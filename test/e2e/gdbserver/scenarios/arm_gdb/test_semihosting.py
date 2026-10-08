# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Semihosting scenarios exercised through arm-none-eabi-gdb."""

import re
import time

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB
from stream import TCPStreamClient

from ._workflows import _CONSOLE_MESSAGE, _assert_spin_running, run_single_client_workflow


@pytest.mark.gdbserver_external_gdb
def test_semihosting_breakpoint_stops_when_semihosting_is_disabled(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that pyOCD does not silently consume a firmware semihosting request when
    semihosting service is intentionally disabled.

    Test method:
    1. Start pyOCD with its default disabled-semihosting configuration and connect
       the selected Arm GDB.
    2. Synchronize at the recurring breakpoint and submit the semihost-console
       mailbox command.
    3. Continue until the firmware executes its ``BKPT 0xAB`` semihosting instruction.
    4. Record PC at that stop and require GDB to expose a non-zero semihost stop.
    5. Continue from the literal breakpoint, wait for mailbox command completion,
       and detach normally.

    Expected result:
    GDB observes the unserviced semihosting breakpoint, can continue past it, and
    the firmware reports completion instead of hanging.

    Failure indicates:
    Disabled-semihosting stop classification, literal-BKPT continuation, or target
    state recovery is broken.
    """
    run_single_client_workflow("semihost-disabled", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_is_forwarded_to_telnet(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that pyOCD services a target semihosting console request and forwards its
    bytes to the configured telnet endpoint while Arm GDB controls execution.

    Test method:
    1. Start pyOCD with semihosting enabled and connect a collector to its telnet port.
    2. Launch Arm GDB and synchronize at the recurring firmware breakpoint.
    3. Submit the semihost-console mailbox command and continue execution.
    4. Let pyOCD recognize ``BKPT 0xAB``, perform the host write, and resume the target.
    5. Wait for the command-completion breakpoint and detach GDB.
    6. Read the telnet stream until the exact expected firmware message is present.

    Expected result:
    The command completes without a debugger-visible semihost stop and the telnet
    collector receives the complete expected message.

    Failure indicates:
    Semihost request decoding, target resume after service, console routing, stream
    collection, or standard-GDB execution control is broken.
    """
    run_single_client_workflow("semihost-console", gdbserver_gdb, gdbserver_server, stream_port="telnet_port", stream_expected=_CONSOLE_MESSAGE)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_survives_no_client_connect_and_disconnect(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that semihosting console output remains complete before Arm GDB connects,
    while one Arm GDB client controls execution, and after it detaches.

    Test method:
    1. Connect one telnet collector and use a short Arm GDB session only to queue a
       console command while the target is stopped at its synchronization breakpoint.
    2. Detach that session before execution and require the first complete console
       message while pyOCD has no GDB client.
    3. Launch one Arm GDB client, run a second console command to completion, and
       require exactly two complete messages on the original telnet connection.
    4. Use a final Arm GDB session to queue a third command while halted, detach it
       before execution, and require exactly three complete messages.
    5. Reconnect a verifier, read the target console-call counter, and require three
       completed calls, proving no phase duplicated or lost its message.

    Expected result:
    The original telnet stream receives one exact message in each lifecycle phase and
    the target reports exactly three console operations.

    Failure indicates:
    GDB connection lifecycle, semihosting servicing, target resume, telnet routing,
    or console-message integrity is broken.
    """
    with gdbserver_server.connect_stream(gdbserver_server.configuration.telnet_port, "arm-gdb-semihosting-client-lifecycle.bin") as console:
        _queue_semihosting_console_and_detach(gdbserver_gdb, gdbserver_server, "before-client")
        captured = _wait_for_console_messages(console, 1)
        assert captured.count(_CONSOLE_MESSAGE) == 1

        _complete_semihosting_console_with_client(gdbserver_gdb, gdbserver_server)
        captured = _wait_for_console_messages(console, 2)
        assert captured.count(_CONSOLE_MESSAGE) == 2

        _queue_semihosting_console_and_detach(gdbserver_gdb, gdbserver_server, "after-client-disconnect")
        captured = _wait_for_console_messages(console, 3)
        assert captured.count(_CONSOLE_MESSAGE) == 3

    output = gdbserver_gdb.run(
        gdbserver_server,
        (
            "break gdbserver_test_firmware_breakpoint_site",
            "continue",
            "printf \"GDB-E2E console-calls=%u\\n\", "
            "gdbserver_test_firmware_mailbox.semihosting_console_calls",
            "delete breakpoints",
            "detach",
        ),
        artifact_name="semihosting-client-lifecycle-verify")
    # Extract the console-operation count reported by the test firmware.
    console_calls = re.search(r"GDB-E2E console-calls=(\d+)", output)
    assert console_calls is not None, output
    assert int(console_calls.group(1)) == 3


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_completes_after_single_step(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that a debugger single-step immediately before a semihosting operation
    does not leave pyOCD in a state where the request is never serviced.

    Test method:
    1. Start semihosting-enabled pyOCD, connect the telnet collector, and launch GDB.
    2. Synchronize and install a breakpoint at
       ``gdbserver_test_firmware_semihosting_write`` before submitting the command.
    3. Continue to that function and execute one machine instruction with ``stepi``.
    4. Remove the temporary breakpoint and continue toward the target's ``BKPT 0xAB``.
    5. Require pyOCD to service the request, resume, and reach mailbox completion.
    6. Detach GDB and require the exact expected message on the telnet stream.

    Expected result:
    The pre-request step completes, semihosting is still recognized and serviced,
    and the firmware command and telnet output both complete.

    Failure indicates:
    Single-step finalization leaves stale run/halt state that blocks semihosting
    service or the following resume path.
    """
    run_single_client_workflow("semihost-console-step", gdbserver_gdb, gdbserver_server, stream_port="telnet_port", stream_expected=_CONSOLE_MESSAGE)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
@pytest.mark.parametrize(
    "workflow",
    ("semihost-step-literal-continue", "semihost-step-literal-step", "semihost-continue-literal-step"),
    ids=("step-continue", "step-step", "continue-step"),
)
def test_semihosting_bkpt_followed_by_literal_bkpt(
        workflow: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that step or continue services a semihosting BKPT at PC and that
    step or continue skips an adjacent ordinary BKPT at PC.

    Test method:
    1. Write executable Thumb code into the firmware RAM window: load SYS_TIME,
       NOP, BKPT 0xAB, BKPT 0, NOP, and BX LR.
    2. Queue the RAM execution command and stop at the NOP before BKPT 0xAB.
    3. Step the NOP, then step or continue from the unexecuted BKPT 0xAB.
       Require the semihosting result to replace the operation in R0.
    4. If stepped, PC is at the unexecuted BKPT 0; step over it or continue
       past it. If continued, the target executes BKPT 0 and stops there;
       step over it.
    5. Require the mailbox command to complete after the ordinary BKPT.

    Expected result:
    Each command processes the BKPT at PC once and reaches the expected next
    PC or the mailbox completion breakpoint.

    Failure indicates:
    Semihosting was not serviced, the ordinary BKPT was retriggered, or
    stepping or continuing from a BKPT at PC failed.
    """
    run_single_client_workflow(workflow, gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
@pytest.mark.parametrize("remote_mode", ("remote", "extended-remote"), ids=("remote", "extended-remote"))
@pytest.mark.parametrize("non_stop", (False, True), ids=("all-stop", "non-stop"))
def test_two_gdb_clients_keep_mixed_bkpt_stop_with_one_run_owner(
        remote_mode: str,
        non_stop: bool,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that an observer GDB can read while another GDB owns execution and
    that the owner still receives a literal BKPT after an adjacent semihost BKPT.

    Test method:
    1. Connect an MI controller and a separate GDB observer in the selected
       remote and stop modes, then synchronize at the firmware breakpoint.
    2. Start the firmware SPIN command through the controller. Require the
       observer to read its advancing iteration counter while the owner runs.
    3. Interrupt and release SPIN through the controller, then program RAM with
       SYS_TIME, BKPT 0xAB, BKPT 0, NOP, and BX LR.
    4. Run that RAM command while both clients remain connected. Require the
       controller to stop at the literal BKPT with a semihost result in R0 and
       an incomplete mailbox command.
    5. Continue from the literal BKPT and require command completion.

    Expected result: The observer reads a running target without taking run
    ownership; the owner sees the literal stop and completes in all four modes.
    Failure indicates: Cross-client reads, semihost resume, literal-BKPT stop
    delivery, run ownership, or recovery after a breakpoint is broken.
    """
    with gdbserver_gdb.start_mi(
            gdbserver_server, "mixed-bkpt-owner", non_stop=non_stop,
            remote_mode=remote_mode) as controller, gdbserver_gdb.start(
            gdbserver_server, "mixed-bkpt-observer", non_stop=non_stop,
            remote_mode=remote_mode) as observer:
        controller.console("break gdbserver_test_firmware_breakpoint_site")
        controller.continue_execution()
        assert 'reason="breakpoint-hit"' in controller.wait_for_stop()

        spin_sequence = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.command_sequence") + 1
        controller.console("set var gdbserver_test_firmware_mailbox.spin_release_sequence = 0")
        controller.console("set var gdbserver_test_firmware_mailbox.command = 8")
        controller.console("set var gdbserver_test_firmware_mailbox.command_sequence = %d" % spin_sequence)
        controller.continue_execution()
        assert _assert_spin_running(observer) != 0

        interrupted = controller.interrupt()
        expected_signal = "0" if non_stop else "SIGINT"
        assert 'signal-name="%s"' % expected_signal in interrupted, interrupted
        controller.console("set var gdbserver_test_firmware_mailbox.spin_release_sequence = %d" % spin_sequence)
        controller.continue_execution()
        assert 'reason="breakpoint-hit"' in controller.wait_for_stop()
        assert controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") == spin_sequence

        for offset, opcode in ((0, 0x2011), (2, 0x2100), (4, 0xbf00), (6, 0xbeab),
                               (8, 0xbe00), (10, 0xbf00), (12, 0x4770)):
            controller.console(
                "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window[%d] = 0x%04x"
                % (offset, opcode))
        address_output = controller.console(
            "printf \"GDB-E2E mixed-base=0x%x\\n\", &gdbserver_test_firmware_mailbox.ram_window[0]")
        address = re.search(r"GDB-E2E mixed-base=0x([0-9a-f]+)", address_output)
        assert address is not None, address_output
        base = int(address.group(1), 16)

        ram_sequence = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.command_sequence") + 1
        controller.console("set var gdbserver_test_firmware_mailbox.command_argument = 0")
        controller.console("set var gdbserver_test_firmware_mailbox.command = 14")
        controller.console("set var gdbserver_test_firmware_mailbox.command_sequence = %d" % ram_sequence)
        controller.continue_execution()
        stopped = controller.wait_for_stop()
        assert '*stopped,' in stopped, stopped
        stop_output = controller.console(
            "printf \"GDB-E2E mixed-stop=0x%x result=%u completed=%u\\n\", "
            "$pc, $r0, gdbserver_test_firmware_mailbox.completed_sequence")
        stop = re.search(r"GDB-E2E mixed-stop=0x([0-9a-f]+) result=(\d+) completed=(\d+)", stop_output)
        assert stop is not None, stop_output
        assert int(stop.group(1), 16) == base + 8, stop_output
        assert int(stop.group(2)) != 17, stop_output
        assert int(stop.group(3)) != ram_sequence, stop_output

        controller.continue_execution()
        assert 'reason="breakpoint-hit"' in controller.wait_for_stop()
        assert controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") == ram_sequence

        observer.detach()
        controller.console("delete breakpoints")
        controller.detach()


def _queue_semihosting_console_and_detach(gdb: ExternalGDB,
                                          server: PyOCDGDBServer,
                                          artifact_name: str) -> None:
    """Use one Arm GDB client to queue a console command, then detach before execution."""
    output = gdb.run(
        server,
        (
            "break gdbserver_test_firmware_breakpoint_site",
            "continue",
            "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1",
            "set var gdbserver_test_firmware_mailbox.command_argument = 0",
            "set var gdbserver_test_firmware_mailbox.command = 3",
            "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence",
            "printf \"GDB-E2E queued=%u\\n\", $gdb_e2e_sequence",
            "delete breakpoints",
            "detach",
        ),
        artifact_name="semihosting-client-lifecycle-" + artifact_name)
    # Confirm that GDB printed the sequence used to queue this command.
    assert re.search(r"GDB-E2E queued=\d+", output), output


def _complete_semihosting_console_with_client(gdb: ExternalGDB,
                                               server: PyOCDGDBServer) -> None:
    """Run one console command to completion while the sole Arm GDB client remains connected."""
    output = gdb.run(
        server,
        (
            "break gdbserver_test_firmware_breakpoint_site",
            "continue",
            "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1",
            "set var gdbserver_test_firmware_mailbox.command_argument = 0",
            "set var gdbserver_test_firmware_mailbox.command = 3",
            "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence",
            "continue",
            "continue",
            "printf \"GDB-E2E completed=%u expected=%u console-calls=%u\\n\", "
            "gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence, "
            "gdbserver_test_firmware_mailbox.semihosting_console_calls",
            "delete breakpoints",
            "detach",
        ),
        artifact_name="semihosting-client-lifecycle-connected")
    # Extract completed and expected sequences plus the console-operation count.
    completed = re.search(r"GDB-E2E completed=(\d+) expected=(\d+) console-calls=(\d+)", output)
    assert completed is not None, output
    assert completed.group(1) == completed.group(2), output
    assert int(completed.group(3)) == 2


def _wait_for_console_messages(stream: TCPStreamClient, count: int,
                               timeout: float = 5.0) -> bytes:
    """Collect exactly the requested number of complete console messages by a deadline."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        captured = stream.received
        if captured.count(_CONSOLE_MESSAGE) >= count:
            return captured
        stream.read_available(timeout=min(0.200, max(0.001, deadline - time.monotonic())))
    raise AssertionError("received %d of %d semihosting console messages within %.1f seconds" % (stream.received.count(_CONSOLE_MESSAGE), count, timeout))
