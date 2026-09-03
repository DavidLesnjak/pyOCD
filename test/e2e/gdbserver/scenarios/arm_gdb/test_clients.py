# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Multi-client scenarios exercised through arm-none-eabi-gdb."""

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_multi_client_workflow


@pytest.mark.gdbserver_external_gdb
def test_two_clients_all_stop_can_observe_and_release_spin(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that two standard Arm GDB clients can share an all-stop pyOCD server
    without losing control of a running SPIN command.

    Test method:
    1. Start one asynchronous GDB/MI controller and one independent console-mode
       GDB observer, both connected to the same pyOCD gdbserver.
    2. Synchronize the controller at the recurring test-firmware breakpoint and
       submit a SPIN mailbox command without waiting for it to complete.
    3. Poll the SPIN counters through the observer until they prove target-side
       execution; this confirms that both clients see the same live target.
    4. Interrupt execution through the controller and wait for its GDB stop event.
    5. Read the program counter through the observer while the target is halted.
    6. Set the mailbox release value, resume through the controller, and wait for
       the command-completion breakpoint before both GDB clients detach.

    Expected result:
    The observer sees an active SPIN and can read registers after the controller
    stops it; the controller then releases and completes the original command.

    Failure indicates:
    All-stop ownership, cross-client state propagation, mailbox execution, or
    cleanup of simultaneous standard-GDB connections is broken.
    """
    run_multi_client_workflow("two-client-all-stop", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_two_clients_non_stop_receive_stop_notification(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that two standard GDB clients using non-stop mode remain synchronized
    when the controller interrupts a running command.

    Test method:
    1. Start a GDB/MI controller and a console-mode GDB observer with non-stop
       negotiation enabled on both connections.
    2. Synchronize at the recurring breakpoint, then have the controller submit
       a SPIN command and leave the target running asynchronously.
    3. Poll the SPIN counters through the observer until they prove target-side
       execution.
    4. Interrupt through the controller and wait for GDB/MI to report the stop.
    5. Read the halted program counter through the observer, proving that it has
       processed the shared target-state transition.
    6. Release the SPIN, resume, and wait for the command-completion breakpoint.

    Expected result:
    Both non-stop clients remain usable across the run-to-stop transition and the
    command completes after the controller releases it.

    Failure indicates:
    Non-stop negotiation, asynchronous stop propagation, multi-client register
    access, or controller ownership is inconsistent.
    """
    run_multi_client_workflow("two-client-non-stop", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_one_client_non_stop_continues_and_receives_stop_notifications(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify the basic asynchronous run, interrupt, and resume lifecycle through one
    real GDB client in non-stop mode.

    Test method:
    1. Start one non-stop GDB/MI session and synchronize it at the recurring
       test-firmware breakpoint.
    2. Write a new SPIN command sequence into the mailbox and continue execution
       without blocking the host-side GDB driver.
    3. Poll mailbox counters through GDB until they prove the SPIN is executing.
    4. issue GDB/MI interrupt and wait for the matching asynchronous stop record.
    5. Write the release sequence, install the completion breakpoint, continue,
       and wait until the firmware reports that exact command as complete.

    Expected result:
    GDB receives the interrupt stop, retains control of the session, and observes
    completion after the same command is released.

    Failure indicates:
    GDB/MI asynchronous execution, pyOCD non-stop state handling, interrupt
    delivery, or resume-after-stop is broken.
    """
    run_multi_client_workflow("one-client-non-stop", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_controller_keeps_spin_after_observer_disconnect(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that disconnecting a secondary GDB observer does not terminate or take
    ownership away from the controller's running SPIN command.

    Test method:
    1. Connect an asynchronous GDB/MI controller and a second console GDB observer.
    2. Use the controller to submit a SPIN command and leave the target running.
    3. Poll advancing SPIN counters through the observer, then detach only that
       observer.
    4. Allow pyOCD time to process that detach and require the server to remain alive.
    5. Interrupt the target through the original controller and wait for its stop.
    6. Release the SPIN and require command completion before closing the controller.

    Expected result:
    The observer detaches cleanly while the controller continues to own, stop,
    release, and complete the already-running command.

    Failure indicates:
    Client detach cleanup incorrectly changes shared run state, drops controller
    ownership, or terminates the persistent gdbserver.
    """
    run_multi_client_workflow("observer-disconnect", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.parametrize("disconnect", ("graceful", "abrupt"))
def test_persistent_server_reconnects_after_last_client_disconnect(
        disconnect: str,
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that a persistent pyOCD gdbserver accepts a new standard-GDB controller
    after its last client disconnects either cleanly or by process termination.

    Test method:
    1. Start an asynchronous GDB/MI controller and synchronize it at the recurring
       firmware breakpoint.
    2. Attach a temporary observer, then submit the SPIN command through the
       stopped controller.
    3. Poll target-side SPIN progress through the observer, then detach it so the
       controller remains the only client under test.
    4. For the ``graceful`` variant, interrupt and detach through GDB; for the
       ``abrupt`` variant, terminate GDB while the confirmed SPIN is running.
    5. Close the first host process and wait briefly for pyOCD to clean its state.
    6. Require the persistent gdbserver process to remain alive.
    7. Connect a new GDB/MI process and verify through mailbox counters that the
       original SPIN command is still active.
    8. Stop, release, and complete that command through the replacement client.

    Expected result:
    Both disconnect variants leave the server reconnectable, and the replacement
    GDB can recover and complete the command started by the original client.

    Failure indicates:
    Last-client cleanup, abrupt transport-loss recovery, persistent-server
    lifecycle, or GDB reconnection state is broken.
    """
    run_multi_client_workflow(
        "reconnect-" + disconnect, gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
def test_persistent_server_survives_repeated_reconnect_cycles(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Detect connection-state leakage across several graceful and abrupt standard-GDB
    disconnects from one persistent pyOCD server.

    Test method:
    1. Start the first GDB/MI client, synchronize it at the recurring breakpoint,
       then attach a temporary observer.
    2. Submit SPIN, use the observer to confirm it has begun executing, and detach
       the observer.
    3. Disconnect the controller gracefully, reconnect, and verify that SPIN remains
       active.
    4. Before each later resume, connect a temporary observer and require fresh
       target-side SPIN progress after the resume.
    5. Terminate the next GDB abruptly, reconnect again, and verify the same SPIN.
    6. Perform one more graceful disconnect, then connect a final GDB client.
    7. Verify the command once more, interrupt it, write its release sequence, and
       wait for the command-completion breakpoint.
    8. Close the final GDB and require all intermediate sessions to clean up.

    Expected result:
    Every replacement GDB connects successfully, observes the original running
    command, and the final client completes it without restarting pyOCD.

    Failure indicates:
    Repeated reconnects leak server/client state, corrupt execution ownership, or
    leave stale GDB protocol state after a transport loss.
    """
    run_multi_client_workflow("reconnect-cycles", gdbserver_gdb, gdbserver_server)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(persist=False)
def test_nonpersistent_server_exits_after_last_client_detaches(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify the intentional opposite of persistent mode: pyOCD exits after its only
    standard-GDB client performs a clean detach.

    Test method:
    1. Start pyOCD with persistence disabled through the scenario marker.
    2. Connect one console-mode Arm GDB client to the server.
    3. Execute ``info files`` to prove that GDB completed target and symbol setup.
    4. Send GDB's normal detach operation and close the client process.
    5. Wait a bounded interval for the pyOCD gdbserver process to terminate.

    Expected result:
    The client can query the target, detach cleanly, and pyOCD exits within the
    timeout because no GDB clients remain.

    Failure indicates:
    Non-persistent lifecycle handling ignores final detach, or the client/server
    connection did not reach a cleanly detachable state.
    """
    run_multi_client_workflow("nonpersistent-server", gdbserver_gdb, gdbserver_server)
