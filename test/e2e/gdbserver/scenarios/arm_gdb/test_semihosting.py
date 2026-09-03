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

from ._workflows import _CONSOLE_MESSAGE, run_single_client_workflow


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
    run_single_client_workflow(
        "semihost-console", gdbserver_gdb, gdbserver_server,
        stream_port="telnet_port", stream_expected=_CONSOLE_MESSAGE)


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
    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.telnet_port,
            "arm-gdb-semihosting-client-lifecycle.bin") as console:
        _queue_semihosting_console_and_detach(
            gdbserver_gdb, gdbserver_server, "before-client")
        captured = _wait_for_console_messages(console, 1)
        assert captured.count(_CONSOLE_MESSAGE) == 1

        _complete_semihosting_console_with_client(gdbserver_gdb, gdbserver_server)
        captured = _wait_for_console_messages(console, 2)
        assert captured.count(_CONSOLE_MESSAGE) == 2

        _queue_semihosting_console_and_detach(
            gdbserver_gdb, gdbserver_server, "after-client-disconnect")
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
    console_calls = re.search(r"GDB-E2E console-calls=(\\d+)", output)
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
    2. Synchronize, submit the semihost-console command, and install a breakpoint at
       ``gdbserver_test_firmware_semihosting_write``.
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
    run_single_client_workflow(
        "semihost-console-step", gdbserver_gdb, gdbserver_server,
        stream_port="telnet_port", stream_expected=_CONSOLE_MESSAGE)


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
    assert re.search(r"GDB-E2E queued=\\d+", output), output


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
    completed = re.search(r"GDB-E2E completed=(\\d+) expected=(\\d+) console-calls=(\\d+)", output)
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
    raise AssertionError(
        "received %d of %d semihosting console messages within %.1f seconds" %
        (stream.received.count(_CONSOLE_MESSAGE), count, timeout))
