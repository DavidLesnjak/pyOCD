# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Arm-GDB multi-client read-only observation scenarios."""

import time

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import _assert_spin_running, run_multi_client_workflow


@pytest.mark.gdbserver_external_gdb
def test_two_clients_can_read_the_test_firmware(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that two real Arm GDB processes can share one pyOCD target while one owns execution.
    Test method:
    1. Start an asynchronous controller GDB and a separate observer GDB before the test operation.
    2. Synchronize the controller, queue SPIN through GDB assignments, and continue asynchronously.
    3. Read the live spin counter through the observer and require non-zero progress.
    4. Interrupt through the controller and read pc through the observer while the target is stopped.
    5. Release SPIN through the controller, continue to the synchronization breakpoint, and require exact completion.
    Expected result: The observer reads shared target state without taking execution ownership and SPIN completes normally.
    Failure indicates: Multiple external-GDB sessions cannot safely observe and control the same target.
    """
    run_multi_client_workflow("two-client-read", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.parametrize("remote_mode", ("remote", "extended-remote"), ids=("remote", "extended-remote"))
def test_non_stop_second_gdb_cannot_start_an_owned_run(
        remote_mode: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that a second non-stop GDB client cannot take run ownership while the
    first client's SPIN command is executing.

    Test method:
    1. Connect two non-stop Arm GDB processes in the selected remote mode.
    2. Synchronize the controller, submit SPIN, and prove target-side progress
       through the observer.
    3. Request continue through the observer and require GDB's error for the
       server's rejected execution request.
    4. Interrupt through the original controller, release SPIN, resume, and
       require the exact mailbox command to complete.

    Expected result:
    The observer's continue is rejected while the first client owns the run;
    the original controller can still stop and complete that run.

    Failure indicates:
    Non-stop ownership, cross-client state, GDB error reporting, or owner cleanup
    is broken.
    """
    with gdbserver_gdb.start_mi(
            gdbserver_server, "run-owner", non_stop=True,
            remote_mode=remote_mode) as controller, gdbserver_gdb.start_mi(
            gdbserver_server, "run-observer", non_stop=True,
            remote_mode=remote_mode) as observer:
        controller.console("break gdbserver_test_firmware_breakpoint_site")
        controller.continue_execution()
        assert 'reason="breakpoint-hit"' in controller.wait_for_stop()

        sequence = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.command_sequence") + 1
        controller.console("set var gdbserver_test_firmware_mailbox.command = 8")
        controller.console("set var gdbserver_test_firmware_mailbox.command_sequence = %d" % sequence)
        controller.continue_execution()

        deadline = time.monotonic() + 2.0
        iterations = 0
        while time.monotonic() < deadline:
            iterations = observer.evaluate_unsigned("gdbserver_test_firmware_mailbox.spin_iterations")
            if iterations != 0:
                break
            time.sleep(0.010)
        assert iterations != 0

        rejected = observer.command("-exec-continue", expected_result="error")
        assert "E01" in rejected, rejected

        stopped = controller.interrupt()
        assert 'signal-name="0"' in stopped, stopped
        controller.console("set var gdbserver_test_firmware_mailbox.spin_release_sequence = %d" % sequence)
        controller.continue_execution()
        assert 'reason="breakpoint-hit"' in controller.wait_for_stop()
        assert controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") == sequence

        observer.detach()
        controller.console("delete breakpoints")
        controller.detach()


@pytest.mark.gdbserver_external_gdb
@pytest.mark.parametrize("remote_mode", ("remote", "extended-remote"), ids=("remote", "extended-remote"))
@pytest.mark.parametrize("non_stop", (False, True), ids=("all-stop", "non-stop"))
def test_gdb_client_connect_during_an_active_run_reports_the_stop_to_owner(
        remote_mode: str,
        non_stop: bool,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that a late GDB attachment halts a confirmed active run and reports
    the stop to the original owner in both run-control modes.

    Test method:
    1. Leave the server clientless, then connect a controller and a witness GDB.
    2. Start a SPIN command through the controller and prove progress through
       the witness before it detaches.
    3. Connect a new GDB while the controller still owns the active run.
    4. Require the original controller's stop event and an incomplete SPIN
       command, then release and complete that command through the controller.

    Expected result:
    The late attachment causes one owner-visible stop; it does not lose the
    running mailbox command, and the owner completes it afterward.

    Failure indicates:
    Late-attach halting, stop delivery, run ownership, or resume after an
    attachment-induced stop is broken.
    """
    time.sleep(0.250)
    with gdbserver_gdb.start_mi(
            gdbserver_server, "late-run-owner", non_stop=non_stop,
            remote_mode=remote_mode) as controller:
        assert controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.heartbeat") != 0
        with gdbserver_gdb.start(
                gdbserver_server, "late-run-witness", non_stop=non_stop,
                remote_mode=remote_mode) as witness:
            controller.console("break gdbserver_test_firmware_breakpoint_site")
            controller.continue_execution()
            assert 'reason="breakpoint-hit"' in controller.wait_for_stop()

            sequence = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.command_sequence") + 1
            controller.console("set var gdbserver_test_firmware_mailbox.command = 8")
            controller.console("set var gdbserver_test_firmware_mailbox.command_sequence = %d" % sequence)
            controller.continue_execution()
            assert _assert_spin_running(witness) != 0
            witness.detach()

        with gdbserver_gdb.start_mi(
                gdbserver_server, "late-run-observer", non_stop=non_stop,
                remote_mode=remote_mode) as late_observer:
            stopped = controller.wait_for_stop()
            assert '*stopped,' in stopped, stopped
            assert late_observer.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") != sequence

            controller.console("set var gdbserver_test_firmware_mailbox.spin_release_sequence = %d" % sequence)
            controller.continue_execution()
            assert 'reason="breakpoint-hit"' in controller.wait_for_stop()
            assert controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") == sequence
            late_observer.detach()

        controller.console("delete breakpoints")
        controller.detach()
