# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Shared arm-none-eabi-gdb workflows for gdbserver scenarios."""

from __future__ import annotations

import re
import time
from typing import Callable, Optional, Sequence

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB, ExternalGDBMISession, ExternalGDBSession


_CONSOLE_MESSAGE = b"pyOCD semihosting test firmware message\n"


def run_single_client_workflow(
        workflow: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer,
        *,
        stream_port: str | None = None,
        stream_expected: bytes | None = None,
        stream_input: bytes | None = None,
        stream_validator: Optional[Callable[[bytes], None]] = None,
        artifact_name: str | None = None) -> str:
    """Run one standard-GDB workflow and verify its observable result."""
    if stream_port is None:
        output = gdbserver_gdb.run(
            gdbserver_server, _commands_for_workflow(workflow), timeout=45.0,
            artifact_name=artifact_name)
    else:
        port = getattr(gdbserver_server.configuration, stream_port)
        assert stream_expected is not None
        with gdbserver_server.connect_stream(
                port, "arm-gdb-%s.bin" % _artifact_name(workflow)) as stream:
            if stream_input is not None:
                stream.send(stream_input)
            output = gdbserver_gdb.run(
                gdbserver_server, _commands_for_workflow(workflow), timeout=45.0,
                artifact_name=artifact_name)
            captured = stream.read_until(stream_expected)
            if stream_validator is not None:
                stream_validator(captured)
    _assert_workflow_output(workflow, output)
    return output


def run_multi_client_workflow(
        workflow: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Run one multi-client standard-GDB workflow."""
    _run_multi_client_workflow(workflow, gdbserver_gdb, gdbserver_server)


def _commands_for_workflow(workflow: str) -> Sequence[str]:
    """Return standard-GDB commands for one supported mirror workflow."""
    if workflow == "hardware-breakpoint":
        return (
            "hbreak gdbserver_test_firmware_breakpoint_site",
            "continue",
            "printf \"GDB-E2E first-break=0x%x\\n\", $pc",
            "delete 1",
            "hbreak gdbserver_test_firmware_breakpoint_site",
            "continue",
            "printf \"GDB-E2E second-break=0x%x\\n\", $pc",
            "info registers pc",
            "delete breakpoints",
            "detach",
        )
    if workflow == "software-breakpoint":
        return _test_firmware_command_workflow(
            14,
            (
                "break *&gdbserver_test_firmware_mailbox.ram_window",
                "continue",
                "printf \"GDB-E2E pc-before=0x%x\\n\", $pc",
                "stepi",
                "printf \"GDB-E2E pc-after=0x%x\\n\", $pc",
                "delete 2",
            ),
            pre_command=(
                "set {unsigned short}&gdbserver_test_firmware_mailbox.ram_window = 0x4770",
            ))
    if workflow == "literal-bkpt":
        return _test_firmware_command_workflow(
            4,
            (
                "printf \"GDB-E2E pc-before=0x%x\\n\", $pc",
                "stepi",
                "printf \"GDB-E2E pc-after=0x%x\\n\", $pc",
            ))
    if workflow == "single-step":
        return _test_firmware_command_workflow(
            9,
            (
                "break gdbserver_test_firmware_step_sequence",
                "continue",
                "printf \"GDB-E2E pc-before=0x%x\\n\", $pc",
                "stepi",
                "printf \"GDB-E2E pc-after=0x%x\\n\", $pc",
                "delete 2",
            ))
    if workflow == "hardware-step-over":
        return _test_firmware_command_workflow(
            9,
            (
                "hbreak gdbserver_test_firmware_step_sequence",
                "continue",
                "printf \"GDB-E2E pc-before=0x%x\\n\", $pc",
                "stepi",
                "printf \"GDB-E2E pc-after=0x%x\\n\", $pc",
                "delete 2",
            ))
    if workflow.startswith("watch-"):
        command = 12 if workflow.endswith("read") else 13
        watch = {
            "watch-write": "watch gdbserver_test_firmware_mailbox.watchpoint_value",
            "watch-read": "rwatch gdbserver_test_firmware_mailbox.watchpoint_value",
            "watch-access-read": "awatch gdbserver_test_firmware_mailbox.watchpoint_value",
            "watch-access-write": "awatch gdbserver_test_firmware_mailbox.watchpoint_value",
        }[workflow]
        return _watchpoint_workflow(command, watch)
    if workflow == "hardfault":
        return (
            "break gdbserver_test_firmware_breakpoint_site",
            "continue",
            "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1",
            "set var gdbserver_test_firmware_mailbox.command = 6",
            "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence",
            "continue",
            "bt",
            "monitor reset",
            "info registers pc",
            "detach",
        )
    if workflow == "rtt-command":
        return _test_firmware_command_workflow(
            1,
            (),
            before_detach=(
                "printf \"GDB-E2E rtt-sequence=%u\\n\", "
                "gdbserver_test_firmware_mailbox.rtt_sequence",
            ))
    if workflow == "rtt-input-command":
        return _test_firmware_command_workflow(
            1,
            (),
            before_detach=(
                "printf \"GDB-E2E rtt-sequence=%u input-bytes=%u input-checksum=%u\\n\", "
                "gdbserver_test_firmware_mailbox.rtt_sequence, "
                "gdbserver_test_firmware_mailbox.rtt_input_bytes, "
                "gdbserver_test_firmware_mailbox.rtt_input_checksum",
            ))
    if workflow == "rtt-burst-command":
        return _test_firmware_command_workflow(
            10,
            (),
            argument=32,
            before_detach=(
                "printf \"GDB-E2E rtt-burst-sequence=%u dropped=%u\\n\", "
                "gdbserver_test_firmware_mailbox.rtt_burst_sequence, "
                "gdbserver_test_firmware_mailbox.rtt_burst_dropped_bytes",
            ))
    if workflow == "semihost-console":
        return _test_firmware_command_workflow(3, ())
    if workflow == "semihost-disabled":
        return _test_firmware_command_workflow(
            3,
            (
                "printf \"GDB-E2E semihost-stop=0x%x\\n\", $pc",
            ))
    if workflow == "semihost-console-step":
        return _test_firmware_command_workflow(
            3,
            (
                "break gdbserver_test_firmware_semihosting_write",
                "continue",
                "stepi",
                "delete 2",
            ))
    raise ValueError("unknown arm-none-eabi-gdb workflow: %s" % workflow)


def _run_multi_client_workflow(workflow: str, gdb: ExternalGDB,
                               server: PyOCDGDBServer) -> None:
    """Run a multi-client workflow with MI execution control and GDB observers."""
    if workflow == "nonpersistent-server":
        with gdb.start(server, "nonpersistent") as client:
            client.execute("info files")
            client.detach()
        assert server.wait_until_stopped(timeout=5.0)
        return

    if workflow == "one-client-non-stop":
        with gdb.start_mi(server, "controller", non_stop=True) as controller:
            _mi_synchronize(controller)
            _mi_start_spin(controller, synchronize=False, wait_for_progress=True)
            _mi_stop_spin(controller)
            _mi_release_spin(controller)
        return

    if workflow == "ctrl-c":
        with gdb.start_mi(server, "controller") as controller:
            _mi_start_confirmed_spin(gdb, server, controller, "ctrl-c-observer")
            _mi_stop_spin(controller)
            _mi_release_spin(controller)
        return

    if workflow == "mailbox-spin":
        with gdb.start_mi(server, "controller") as controller:
            _mi_synchronize(controller)
            assert controller.evaluate_unsigned(
                "gdbserver_test_firmware_mailbox.magic") == 0x47444253
            assert controller.evaluate_unsigned(
                "gdbserver_test_firmware_mailbox.abi_version") == 4
            register_output = controller.console("info registers r0 pc")
            assert re.search(r"\br0\s+0x[0-9a-f]+", register_output, re.IGNORECASE)
            assert re.search(r"\bpc\s+0x[0-9a-f]+", register_output, re.IGNORECASE)
            _mi_start_confirmed_spin(
                gdb, server, controller, "mailbox-spin-observer", synchronize=False)
            _mi_stop_spin(controller)
            _mi_release_spin(controller)
        return

    if workflow == "monitor-reset-reconnect":
        controller = gdb.start_mi(server, "before-reset")
        try:
            _mi_synchronize(controller)
            before_epoch = controller.evaluate_unsigned(
                "gdbserver_test_firmware_mailbox.boot_epoch")
            controller.console("monitor reset")
            controller.detach()
        finally:
            controller.close()
        assert server.is_running
        with gdb.start_mi(server, "after-reset") as reconnected:
            _mi_synchronize(reconnected)
            after_epoch = reconnected.evaluate_unsigned(
                "gdbserver_test_firmware_mailbox.boot_epoch")
            assert after_epoch == ((before_epoch + 1) & 0xffffffff)
        return

    if workflow in ("two-client-all-stop", "two-client-read", "two-client-non-stop"):
        non_stop = workflow == "two-client-non-stop"
        with gdb.start_mi(server, "controller", non_stop=non_stop) as controller, \
                gdb.start(server, "observer", non_stop=non_stop) as observer:
            _mi_synchronize(controller)
            _mi_start_spin(controller, synchronize=False)
            _assert_spin_running(observer)
            _mi_stop_spin(controller)
            register_output = observer.execute("info registers pc")
            assert re.search(r"\bpc\s+0x[0-9a-f]+", register_output, re.IGNORECASE)
            _mi_release_spin(controller)
        return

    if workflow == "observer-disconnect":
        with gdb.start_mi(server, "controller") as controller:
            observer = gdb.start(server, "observer")
            try:
                _mi_start_spin(controller)
                _assert_spin_running(observer)
                observer.detach()
            finally:
                observer.close()
            time.sleep(0.100)
            _mi_stop_spin(controller)
            _mi_release_spin(controller)
        return

    if workflow in ("reconnect-graceful", "reconnect-abrupt"):
        controller = gdb.start_mi(server, "controller")
        try:
            _mi_start_confirmed_spin(gdb, server, controller, "reconnect-observer")
            if workflow == "reconnect-graceful":
                _mi_stop_spin(controller)
                controller.detach()
            else:
                controller.terminate()
        finally:
            controller.close()
        time.sleep(0.200)
        assert server.is_running
        with gdb.start_mi(server, "reconnected") as reconnected:
            _assert_mi_spin_running(reconnected)
            _mi_release_spin(reconnected, set_completion_breakpoint=True)
        return

    if workflow == "reconnect-cycles":
        client = gdb.start_mi(server, "client-0")
        try:
            _mi_start_confirmed_spin(gdb, server, client, "cycle-observer-0")
            for index, disconnect in enumerate(("graceful", "abrupt", "graceful"), start=1):
                if disconnect == "graceful":
                    _mi_stop_spin(client)
                    client.detach()
                else:
                    client.terminate()
                client.close()
                assert server.is_running
                client = gdb.start_mi(server, "client-%d" % index)
                _assert_mi_spin_running(client)
                _mi_continue_confirmed_spin(
                    gdb, server, client, "cycle-observer-%d" % index)
            _mi_stop_spin(client)
            _mi_release_spin(client, set_completion_breakpoint=True)
        finally:
            client.close()
        return

    raise ValueError("unknown arm-none-eabi-gdb multi-client workflow: %s" % workflow)


def _mi_synchronize(controller: ExternalGDBMISession) -> None:
    """Place GDB/MI in a known stopped state at the test firmware breakpoint."""
    controller.console("break gdbserver_test_firmware_breakpoint_site")
    controller.continue_execution()
    controller.wait_for_stop()


def _mi_start_spin(controller: ExternalGDBMISession,
                   synchronize: bool = True,
                   wait_for_progress: bool = False) -> None:
    """Request SPIN, optionally prove target-side progress, then leave it running."""
    if synchronize:
        _mi_synchronize(controller)
    controller.console(
        "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1")
    controller.console("set var gdbserver_test_firmware_mailbox.command = 8")
    controller.console(
        "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence")
    controller.continue_execution()
    if wait_for_progress:
        _wait_for_mi_spin_progress(controller)


def _mi_start_confirmed_spin(gdb: ExternalGDB, server: PyOCDGDBServer,
                             controller: ExternalGDBMISession, observer_name: str,
                             *, synchronize: bool = True) -> None:
    """Synchronize, start SPIN, and prove target-side progress through an observer."""
    if synchronize:
        _mi_synchronize(controller)
    with gdb.start(server, observer_name) as observer:
        _mi_start_spin(controller, synchronize=False)
        _assert_spin_running(observer)
        observer.detach()


def _mi_continue_confirmed_spin(gdb: ExternalGDB, server: PyOCDGDBServer,
                                controller: ExternalGDBMISession,
                                observer_name: str) -> None:
    """Resume SPIN and use an observer to require a fresh target-side advance."""
    with gdb.start(server, observer_name) as observer:
        initial_iterations = _read_spin_iterations(observer)
        assert initial_iterations != 0
        controller.continue_execution()
        _assert_spin_advanced(observer, initial_iterations)
        observer.detach()


def _wait_for_mi_spin_progress(controller: ExternalGDBMISession,
                                timeout: float = 2.0) -> None:
    """Wait until a running SPIN command has executed on the target."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if controller.evaluate_unsigned(
                "gdbserver_test_firmware_mailbox.spin_iterations") != 0:
            return
        time.sleep(0.010)
    raise AssertionError("SPIN command did not make target-side progress")


def _mi_stop_spin(controller: ExternalGDBMISession) -> None:
    """Interrupt a running SPIN through GDB/MI and verify it made progress."""
    controller.interrupt()
    assert controller.evaluate_unsigned(
        "gdbserver_test_firmware_mailbox.spin_iterations") != 0



def _mi_release_spin(controller: ExternalGDBMISession,
                     set_completion_breakpoint: bool = False) -> None:
    """Release a stopped SPIN and prove its target-resident sequence completed."""
    if set_completion_breakpoint:
        controller.console("break gdbserver_test_firmware_breakpoint_site")
    controller.console(
        "set var gdbserver_test_firmware_mailbox.spin_release_sequence = "
        "gdbserver_test_firmware_mailbox.command_sequence")
    controller.continue_execution()
    controller.wait_for_stop()
    completed = controller.evaluate_unsigned(
        "gdbserver_test_firmware_mailbox.completed_sequence")
    expected = controller.evaluate_unsigned(
        "gdbserver_test_firmware_mailbox.command_sequence")
    assert completed == expected


def _assert_mi_spin_running(client: ExternalGDBMISession,
                            timeout: float = 2.0) -> None:
    """Poll a reconnected MI client until it sees target-side SPIN progress."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if client.evaluate_unsigned(
                "gdbserver_test_firmware_mailbox.spin_iterations") != 0:
            return
        time.sleep(0.010)
    raise AssertionError("reconnected client did not observe SPIN progress")


def _read_spin_iterations(client: ExternalGDBSession) -> int:
    """Read the target-resident SPIN iteration counter through an observer."""
    output = client.execute(
        "printf \"GDB-E2E spin-iterations=%u\\n\", "
        "gdbserver_test_firmware_mailbox.spin_iterations")
    match = re.search(r"GDB-E2E spin-iterations=(\d+)", output)
    assert match is not None, output
    return int(match.group(1))


def _assert_spin_running(client: ExternalGDBSession, timeout: float = 2.0) -> None:
    """Poll through an observer until the target has entered its SPIN command."""
    deadline = time.monotonic() + timeout
    iterations = 0
    while time.monotonic() < deadline:
        iterations = _read_spin_iterations(client)
        if iterations != 0:
            return
        time.sleep(0.010)
    raise AssertionError("SPIN command did not make target-side progress")


def _assert_spin_advanced(client: ExternalGDBSession, initial_iterations: int,
                          timeout: float = 2.0) -> None:
    """Require a SPIN counter value different from a stopped observer snapshot."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _read_spin_iterations(client) != initial_iterations:
            return
        time.sleep(0.010)
    raise AssertionError("SPIN command did not make fresh target-side progress")


def _stop_spin(client: ExternalGDBSession) -> None:
    """Interrupt a running GDB continue request and verify that the target is stopped."""
    client.interrupt()
    output = client.execute("info registers pc")
    assert re.search(r"\bpc\s+0x[0-9a-f]+", output, re.IGNORECASE), output


def _release_spin(client: ExternalGDBSession) -> None:
    """Release SPIN through GDB, then prove the mailbox command completed."""
    client.execute(
        "set var gdbserver_test_firmware_mailbox.spin_release_sequence = $gdb_e2e_sequence")
    client.continue_execution()
    time.sleep(0.100)
    _stop_spin(client)
    output = client.execute(
        "printf \"GDB-E2E completed=%u expected=%u\\n\", "
        "gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence")
    completed = re.search(r"GDB-E2E completed=(\d+) expected=(\d+)", output)
    assert completed is not None, output
    assert completed.group(1) == completed.group(2), output


def _test_firmware_command_workflow(command: int, after_start: Sequence[str],
                               argument: int = 0,
                               pre_command: Sequence[str] = (),
                               before_detach: Sequence[str] = ()) -> Sequence[str]:
    """Execute one test firmware mailbox command from GDB and prove it completed.

    The first ``continue`` synchronizes at breakpoint 1 before a mailbox
    command is written. ``pre_command`` prepares test firmware state before the
    command becomes executable. Breakpoint 1 is then retained as the
    post-command completion stop. Workflows that add a temporary breakpoint
    must remove only that breakpoint before this helper's final ``continue``.
    """
    return (
        "break gdbserver_test_firmware_breakpoint_site",
        "continue",
        *pre_command,
        "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1",
        "set var gdbserver_test_firmware_mailbox.command_argument = %d" % argument,
        "set var gdbserver_test_firmware_mailbox.command = %d" % command,
        "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence",
        "continue",
        *after_start,
        "continue",
        "printf \"GDB-E2E completed=%u expected=%u\\n\", "
        "gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence",
        *before_detach,
        "delete breakpoints",
        "detach",
    )


def _watchpoint_workflow(command: int, watch: str) -> Sequence[str]:
    """Execute a mailbox command while its target memory access is watched.

    Standard GDB steps over its recurring synchronization breakpoint before it
    programs a new watchpoint. Remove that breakpoint and explicitly complete
    the step-over before the mailbox command is made executable. The watched
    command then runs without a competing breakpoint until the DWT stop. Once
    the watchpoint is removed, restore the synchronization breakpoint solely
    to observe command completion.
    """
    return (
        "break gdbserver_test_firmware_breakpoint_site",
        "continue",
        "delete 1",
        "stepi",
        "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1",
        "set var gdbserver_test_firmware_mailbox.command_argument = 0",
        "set var gdbserver_test_firmware_mailbox.command = %d" % command,
        "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence",
        watch,
        "continue",
        "printf \"GDB-E2E watch-stop-completed=%u expected=%u\\n\", "
        "gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence",
        "info registers pc",
        "delete 2",
        "hbreak gdbserver_test_firmware_breakpoint_site",
        "continue",
        "printf \"GDB-E2E completed=%u expected=%u\\n\", "
        "gdbserver_test_firmware_mailbox.completed_sequence, $gdb_e2e_sequence",
        "delete breakpoints",
        "detach",
    )


def _assert_workflow_output(workflow: str, output: str) -> None:
    """Check the observable standard-GDB result for one workflow."""
    if workflow == "hardware-breakpoint":
        assert "Hardware assisted breakpoint" in output
        assert "gdbserver_test_firmware_breakpoint_site" in output
        assert re.search(r"\bpc\s+0x[0-9a-f]+", output, re.IGNORECASE)
        stops = re.findall(r"GDB-E2E (?:first|second)-break=0x([0-9a-f]+)", output)
        assert len(stops) == 2, output
        assert int(stops[0], 16) != 0, output
        assert stops[0] == stops[1], output
        return
    if workflow == "hardfault":
        assert "HardFault_Handler" in output
        assert re.search(r"\bpc\s+0x[0-9a-f]+", output, re.IGNORECASE)
        return
    completed = re.search(r"GDB-E2E completed=(\d+) expected=(\d+)", output)
    assert completed is not None, output
    assert completed.group(1) == completed.group(2), output
    if workflow in ("software-breakpoint", "literal-bkpt", "single-step", "hardware-step-over"):
        program_counters = re.findall(r"GDB-E2E pc-(?:before|after)=0x([0-9a-f]+)", output)
        assert len(program_counters) == 2, output
        assert program_counters[0] != program_counters[1], output
    if workflow.startswith("watch-"):
        stopped = re.search(
            r"GDB-E2E watch-stop-completed=(\d+) expected=(\d+)", output)
        assert stopped is not None, output
        assert stopped.group(1) != stopped.group(2), output
        assert re.search(r"(?i)watchpoint", output), output
    if workflow == "semihost-disabled":
        semihost_stop = re.search(r"GDB-E2E semihost-stop=0x([0-9a-f]+)", output)
        assert semihost_stop is not None, output
        assert int(semihost_stop.group(1), 16) != 0, output
    if workflow == "rtt-input-command":
        input_state = re.search(
            r"GDB-E2E rtt-sequence=(\d+) input-bytes=(\d+) input-checksum=(\d+)",
            output)
        assert input_state is not None, output
        assert int(input_state.group(2)) > 0, output
        assert int(input_state.group(3)) > 0, output
    if workflow == "rtt-burst-command":
        burst_state = re.search(
            r"GDB-E2E rtt-burst-sequence=(\d+) dropped=(\d+)", output)
        assert burst_state is not None, output
        assert int(burst_state.group(1)) == 32, output
        assert int(burst_state.group(2)) == 0, output


def _artifact_name(raw_scenario: str) -> str:
    """Convert a raw scenario identity into a safe stream artifact stem."""
    return re.sub(r"[^a-z0-9]+", "-", raw_scenario.lower()).strip("-")
