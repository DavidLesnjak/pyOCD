# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""GDB client ownership, lifecycle, and reconnection scenarios."""

import time

import pytest

from mailbox import (
    FixtureMailboxClient,
    MailboxCommand,
    MailboxSpinState,
    resolve_elf_symbol,
)
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient, RSPError, RSPTimeoutError


def test_two_clients_all_stop_can_observe_and_release_spin(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that one debugger can run the test firmware while a second debugger observes it safely in all-stop mode.
    Test method:
    1. Connect controller and observer RSP clients before execution and bind both to the same ready mailbox.
    2. Queue SPIN through the controller and send an all-stop continue request without waiting for its reply.
    3. Poll running mailbox state and read target RAM through the observer while the controller owns execution.
    4. Interrupt the controller, require T02, and only then read the stopped core register block through the observer.
    5. Write the exact spin release sequence, continue, and use the observer to wait for command completion.
    6. Interrupt again and require released state; on failure, perform bounded spin cleanup.
    Expected result: The observer reads running memory, reads registers only after the stop, and the controller releases it.
    Failure indicates: Multi-client all-stop observation or controller ownership is broken.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    with gdbserver_server.connect_rsp() as controller, gdbserver_server.connect_rsp() as observer:
        controller_mailbox = FixtureMailboxClient(controller, mailbox_address)
        observer_mailbox = FixtureMailboxClient(observer, mailbox_address)
        sequence = None
        completed = None
        try:
            controller_mailbox.wait_until_ready()
            sequence = controller_mailbox.request(MailboxCommand.SPIN)
            controller.send_packet(b"c")
            running = observer_mailbox.wait_for(
                lambda mailbox: (mailbox.command_sequence == sequence and
                                 mailbox.spin_state == MailboxSpinState.RUNNING),
                description="fixture spin command to start")

            assert running.spin_iterations != 0
            assert observer.read_memory(mailbox_address, 16) != b""

            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            assert len(observer.read_registers()) >= 16 * 4

            controller_mailbox.release_spin(sequence)
            controller.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(sequence)

            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            assert completed.spin_state == MailboxSpinState.RELEASED
        finally:
            if sequence is not None and completed is None:
                _recover_all_stop_spin(controller, controller_mailbox, sequence)


def test_two_clients_non_stop_receive_stop_notification(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that two debuggers remain usable when the server permits target execution and debugger requests concurrently.
    Test method:
    1. Connect two clients, verify QNonStop advertisement, and enable non-stop mode independently on each connection.
    2. Queue SPIN and resume with vCont;c, then observe the running mailbox through the second client.
    3. While execution remains active, query state and read memory through the observer. Send g and accept
       hexadecimal data or x placeholders, because live register values can be unavailable while the core runs.
    4. Stop with vCont;t and require a percent Stop:T notification on the controlling connection.
    5. Read concrete register bytes through the now-stopped observer, then acknowledge the stop with vStopped
       and require that no stale or duplicate notification follows.
    6. Release SPIN, resume, wait for completion, stop again, and repeat the notification and stale-event checks.
    7. If any assertion fails, make a bounded non-stop release and resume attempt.
    Expected result: Both clients remain usable, the running register response is well-formed, and the stopped
    observer receives concrete registers before completion.
    Failure indicates: Non-stop negotiation, concurrent RSP access, stop notification delivery, or register
    availability handling fails.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    with gdbserver_server.connect_rsp() as controller, gdbserver_server.connect_rsp() as observer:
        controller_mailbox = FixtureMailboxClient(controller, mailbox_address)
        observer_mailbox = FixtureMailboxClient(observer, mailbox_address)
        sequence = None
        completed = None
        try:
            assert b"QNonStop+" in controller.command(b"qSupported:multiprocess+")
            assert b"QNonStop+" in observer.command(b"qSupported:multiprocess+")
            assert controller.command(b"QNonStop:1") == b"OK"
            assert observer.command(b"QNonStop:1") == b"OK"

            controller_mailbox.wait_until_ready()
            sequence = controller_mailbox.request(MailboxCommand.SPIN)
            assert controller.command(b"vCont;c") == b"OK"
            observer_mailbox.wait_for(
                lambda mailbox: (mailbox.command_sequence == sequence and
                                 mailbox.spin_state == MailboxSpinState.RUNNING),
                description="fixture non-stop spin command to start")

            assert observer.command(b"?") == b"OK"
            assert observer.read_memory(mailbox_address, 16) != b""
            register_reply = observer.command(b"g")
            assert len(register_reply) >= 16 * 4 * 2
            assert all(value in b"0123456789abcdefx" for value in register_reply.lower())

            assert controller.command(b"vCont;t") == b"OK"
            notification = controller.receive_packet_with_type(timeout=5.0)
            assert notification.packet_type == "%"
            assert notification.payload.startswith(b"Stop:T")
            assert len(observer.read_registers()) >= 16 * 4
            assert controller.command(b"vStopped") == b"OK"
            with pytest.raises(RSPTimeoutError):
                controller.receive_packet_with_type(timeout=0.100)

            controller_mailbox.release_spin(sequence)
            assert controller.command(b"vCont;c") == b"OK"
            completed = observer_mailbox.wait_for_completion(sequence)

            assert controller.command(b"vCont;t") == b"OK"
            notification = controller.receive_packet_with_type(timeout=5.0)
            assert notification.packet_type == "%"
            assert notification.payload.startswith(b"Stop:T")
            assert controller.command(b"vStopped") == b"OK"
            with pytest.raises(RSPTimeoutError):
                controller.receive_packet_with_type(timeout=0.100)
            assert completed.spin_state == MailboxSpinState.RELEASED
        finally:
            if sequence is not None and completed is None:
                _recover_non_stop_spin(controller, controller_mailbox, sequence)


def test_one_client_non_stop_continues_and_receives_stop_notifications(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that one debugger can run, interrupt, inspect, and complete the test firmware in non-stop mode.
    Test method:
    1. Connect one client, verify QNonStop support, and switch the connection into non-stop mode.
    2. Queue SPIN, resume with vCont;c, and prove through mailbox counters that the command is executing.
    3. Stop with vCont;t and require one percent Stop:T notification followed by successful vStopped acknowledgement.
    4. Require a quiet receive deadline after vStopped so stale or duplicate stop notifications fail the test.
    5. Release the command, continue, wait for exact completion, and perform the same stop-notification checks again.
    Expected result: The client receives the expected stop notification and completes the mailbox command.
    Failure indicates: Single-client non-stop execution or stop notification is incorrect.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    with gdbserver_server.connect_rsp() as client:
        mailbox = FixtureMailboxClient(client, mailbox_address)
        sequence = None
        completed = None
        try:
            assert b"QNonStop+" in client.command(b"qSupported:multiprocess+")
            assert client.command(b"QNonStop:1") == b"OK"

            mailbox.wait_until_ready()
            sequence = mailbox.request(MailboxCommand.SPIN)
            assert client.command(b"vCont;c") == b"OK"
            running = mailbox.wait_for(
                lambda state: (state.command_sequence == sequence and
                               state.spin_state == MailboxSpinState.RUNNING),
                description="fixture one-client non-stop spin command to start")
            assert running.spin_iterations != 0
            assert client.command(b"?") == b"OK"

            assert client.command(b"vCont;t") == b"OK"
            notification = client.receive_packet_with_type(timeout=5.0)
            assert notification.packet_type == "%"
            assert notification.payload.startswith(b"Stop:T")
            assert len(client.read_registers()) >= 16 * 4
            assert client.command(b"vStopped") == b"OK"
            with pytest.raises(RSPTimeoutError):
                client.receive_packet_with_type(timeout=0.100)

            mailbox.release_spin(sequence)
            assert client.command(b"vCont;c") == b"OK"
            completed = mailbox.wait_for_completion(sequence)

            assert client.command(b"vCont;t") == b"OK"
            notification = client.receive_packet_with_type(timeout=5.0)
            assert notification.packet_type == "%"
            assert notification.payload.startswith(b"Stop:T")
            assert client.command(b"vStopped") == b"OK"
            with pytest.raises(RSPTimeoutError):
                client.receive_packet_with_type(timeout=0.100)
            assert completed.spin_state == MailboxSpinState.RELEASED
        finally:
            if sequence is not None and completed is None:
                _recover_non_stop_spin(client, mailbox, sequence)


def test_controller_keeps_spin_after_observer_disconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that disconnecting a passive observer does not disrupt another debugger that is running the target.
    Test method:
    1. Connect controller and observer clients before execution and prepare mailbox views for both.
    2. Queue SPIN, continue with the controller, and use the observer to prove that the command is running.
    3. Abruptly close only the observer connection while the controller has an outstanding continue.
    4. Interrupt the controller and require T02, then write the release sequence and resume.
    5. Interrupt once more and verify exact mailbox completion and released state through the surviving controller.
    Expected result: The controller keeps control and the test firmware completes after the observer disappears.
    Failure indicates: A passive client disconnect disturbs another client's target session.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    with gdbserver_server.connect_rsp() as controller:
        observer = gdbserver_server.connect_rsp()
        controller_mailbox = FixtureMailboxClient(controller, mailbox_address)
        observer_mailbox = FixtureMailboxClient(observer, mailbox_address)
        sequence = None
        completed = None
        try:
            controller_mailbox.wait_until_ready()
            sequence = controller_mailbox.request(MailboxCommand.SPIN)
            controller.send_packet(b"c")
            observer_mailbox.wait_for(
                lambda mailbox: (mailbox.command_sequence == sequence and
                                 mailbox.spin_state == MailboxSpinState.RUNNING),
                description="fixture spin command before observer disconnect")

            observer.close()
            time.sleep(0.100)

            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            controller_mailbox.release_spin(sequence)
            controller.send_packet(b"c")
            time.sleep(0.100)
            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            completed = controller_mailbox.wait_for_completion(sequence)
            assert completed.spin_state == MailboxSpinState.RELEASED
        finally:
            observer.close()
            if sequence is not None and completed is None:
                _recover_all_stop_spin(controller, controller_mailbox, sequence)


@pytest.mark.parametrize("disconnect", ("graceful", "abrupt"))
def test_persistent_server_reconnects_after_last_client_disconnect(
        gdbserver_server: PyOCDGDBServer, disconnect: str) -> None:
    """
    Purpose: Check that a persistent server remains available when its final debugger disconnects normally or abruptly.
    Variants: graceful RSP detach and abrupt TCP disconnect.
    Test method:
    1. Connect the sole controller, queue SPIN, continue, and allow the target to enter the running loop.
    2. For the graceful variant, interrupt and consume T02 before D detach; for the abrupt variant, close TCP while running.
    3. Wait for final-client cleanup and require that persistent gdbserver remains alive.
    4. Connect a replacement RSP client, which halts the target, and prove that the original SPIN sequence is still active.
    5. Release SPIN, continue, interrupt, and require exact completion through the replacement client.
    Expected result: The persistent server remains alive and the new client can control the target.
    Failure indicates: Last-client cleanup terminates or wedges persistent gdbserver.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    controller = gdbserver_server.connect_rsp()
    sequence = None
    try:
        mailbox = FixtureMailboxClient(controller, mailbox_address)
        mailbox.wait_until_ready()
        sequence = mailbox.request(MailboxCommand.SPIN)
        controller.send_packet(b"c")
        # The all-stop controller is now blocked awaiting its stop reply. Let
        # SPIN execute before disconnecting; the reconnect below halts it for
        # the mailbox inspection.
        time.sleep(0.100)

        if disconnect == "graceful":
            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            controller.detach()
        else:
            controller.close()
    finally:
        controller.close()

    # The disconnect handler resumes the last client's target before the next
    # connection halts it for inspection.
    time.sleep(0.200)
    assert gdbserver_server.is_running

    with gdbserver_server.connect_rsp() as reconnected:
        mailbox = FixtureMailboxClient(reconnected, mailbox_address)
        running = mailbox.wait_for(
            lambda state: (state.command_sequence == sequence and
                           state.spin_state == MailboxSpinState.RUNNING),
            description="fixture spin command after reconnect")
        assert running.spin_iterations != 0

        mailbox.release_spin(sequence)
        reconnected.send_packet(b"c")
        time.sleep(0.100)
        reconnected.interrupt()
        assert reconnected.receive_packet(timeout=5.0).startswith(b"T02")
        assert mailbox.wait_for_completion(sequence).spin_state == MailboxSpinState.RELEASED


def test_persistent_server_survives_repeated_reconnect_cycles(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that repeated normal and abrupt reconnects do not accumulate stale state in a persistent server.
    Test method:
    1. Start one SPIN command and leave the initial all-stop continue outstanding.
    2. Cycle through graceful, abrupt, and graceful client loss, interrupting before each graceful detach when required.
    3. After every disconnect, require that persistent gdbserver stays alive and accepts a replacement client.
    4. Read SPIN progress after each reconnect and require iterations never to move backwards.
    5. Attach a final observer, release the original command, continue, and verify completion and T02 cleanup.
    Expected result: Every reconnection succeeds and later target control remains functional.
    Failure indicates: Connection lifecycle cleanup accumulates stale state or kills the server.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    client = gdbserver_server.connect_rsp()
    mailbox = FixtureMailboxClient(client, mailbox_address)
    sequence = None
    completed = None
    try:
        mailbox.wait_until_ready()
        sequence = mailbox.request(MailboxCommand.SPIN)
        client.send_packet(b"c")
        # An all-stop client cannot issue mailbox reads while its continue is
        # outstanding. The first reconnect synchronously halts SPIN before
        # inspecting it below.
        time.sleep(0.100)
        previous_iterations = 0
        continue_pending = True

        for disconnect in ("graceful", "abrupt", "graceful"):
            if disconnect == "graceful":
                if continue_pending:
                    client.interrupt()
                    assert client.receive_packet(timeout=5.0).startswith(b"T02")
                    continue_pending = False
                client.detach()
            client.close()
            assert gdbserver_server.is_running

            client = gdbserver_server.connect_rsp()
            mailbox = FixtureMailboxClient(client, mailbox_address)
            reconnected = mailbox.wait_for(
                lambda state: (state.command_sequence == sequence and
                               state.spin_state == MailboxSpinState.RUNNING),
                description="fixture spin command after %s reconnect" % disconnect)
            assert reconnected.spin_iterations >= previous_iterations
            previous_iterations = reconnected.spin_iterations

        with gdbserver_server.connect_rsp() as observer:
            observer_mailbox = FixtureMailboxClient(observer, mailbox_address)
            mailbox.release_spin(sequence)
            client.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(sequence)
            client.interrupt()
            assert client.receive_packet(timeout=5.0).startswith(b"T02")
            assert completed.spin_state == MailboxSpinState.RELEASED
    finally:
        if sequence is not None and completed is None:
            _recover_all_stop_spin(client, mailbox, sequence)
        client.close()


@pytest.mark.gdbserver_config(extra_arguments=("-vv",))
def test_server_recovers_after_dispatched_single_step_client_disconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a client loss immediately after a step request does not leave the server or target unusable.
    Test method:
    1. Connect controller and observer clients, queue STEP, and install a hardware breakpoint at its known function entry.
    2. Continue to T05, verify the PC range, and remove the breakpoint before dispatching the raw s packet.
    3. Wait for pyOCD's verbose step-dispatch record so closing the controller cannot race ahead of command acceptance.
    4. Close the controller without consuming its stop reply and poll PC through the observer until the instruction advances.
    5. Require persistent gdbserver to accept a replacement client that sees the same stopped PC.
    6. Continue through the replacement and verify the original STEP result through the still-attached observer.
    Expected result: The server remains alive, PC is readable, and a later client completes the test-firmware command.
    Failure indicates: An in-flight step leaves gdbserver or the target session wedged.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    step_argument = 0x12345678
    controller = gdbserver_server.connect_rsp()
    observer = gdbserver_server.connect_rsp()
    breakpoint_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_step_sequence") & ~1
    insert_packet = _breakpoint_packet(b"Z1", breakpoint_address)
    remove_packet = _breakpoint_packet(b"z1", breakpoint_address)
    breakpoint_inserted = False
    try:
        controller_mailbox = FixtureMailboxClient(controller, mailbox_address)
        observer_mailbox = FixtureMailboxClient(observer, mailbox_address)
        controller_mailbox.wait_until_ready()
        sequence = controller_mailbox.request(
            MailboxCommand.STEP, argument=step_argument)
        assert controller.command(insert_packet) == b"OK"
        breakpoint_inserted = True
        controller.send_packet(b"c")
        assert controller.receive_packet(timeout=5.0).startswith(b"T05")
        program_counter_before = _program_counter(controller)
        assert breakpoint_address <= program_counter_before < breakpoint_address + 16
        assert controller.command(remove_packet) == b"OK"
        breakpoint_inserted = False

        # send_packet() waits only for the transport acknowledgement. Require
        # the server's verbose dispatch record before closing, so this is a
        # client loss after a real step dispatch rather than a packet-I/O queue
        # race. The controller never consumes the step stop reply. The observer
        # remains attached so the disconnect cannot implicitly resume the
        # target before its post-step PC is checked.
        controller.send_packet(b"s")
        gdbserver_server.wait_for_log("Command: Step")
        controller.close()
        stepped_program_counter = _wait_for_program_counter_change(
            observer, program_counter_before)
        assert stepped_program_counter != program_counter_before

        assert gdbserver_server.is_running
        with gdbserver_server.connect_rsp() as reconnected:
            mailbox = FixtureMailboxClient(reconnected, mailbox_address)
            assert _program_counter(reconnected) == stepped_program_counter
            reconnected.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(sequence)

        assert completed.step_result == _expected_fixture_step_result(step_argument)
    finally:
        if breakpoint_inserted:
            try:
                observer.command(remove_packet, timeout=1.0)
            except RSPError:
                pass
        controller.close()
        observer.close()

@pytest.mark.gdbserver_config(persist=False)
def test_nonpersistent_server_exits_after_last_client_detaches(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a nonpersistent server exits after its final debugger has explicitly detached.
    Test method:
    1. Start an isolated gdbserver without the persist option.
    2. Connect one RSP client and verify that the target mailbox is initialized.
    3. Send the standard D detach request and close the client context.
    4. Wait for a bounded deadline and require the owned gdbserver process to terminate.
    Expected result: The server shuts down within the bounded timeout after final detach.
    Failure indicates: Nonpersistent session lifecycle does not honor final-client detach.
    """
    with gdbserver_server.connect_rsp() as client:
        mailbox = FixtureMailboxClient(client, _mailbox_address(gdbserver_server))
        mailbox.wait_until_ready()
        client.detach()

    assert gdbserver_server.wait_until_stopped(timeout=5.0)


def _mailbox_address(gdbserver_server: PyOCDGDBServer) -> int:
    return resolve_elf_symbol(gdbserver_server.configuration.firmware, "gdbserver_test_firmware_mailbox")


def _expected_fixture_step_result(value: int) -> int:
    value ^= 0xA5A5A5A5
    value = (value + 0x10203040) & 0xffffffff
    return ((value << 3) | (value >> 29)) & 0xffffffff


def _breakpoint_packet(kind: bytes, address: int) -> bytes:
    """Encode a two-byte breakpoint insertion or removal packet."""
    return kind + (",%x,2" % address).encode("ascii")


def _program_counter(client: RSPClient) -> int:
    """Extract the Cortex-M PC from the standard GDB register block."""
    registers = client.read_registers()
    program_counter_offset = 15 * 4
    assert len(registers) >= program_counter_offset + 4
    return int.from_bytes(
        registers[program_counter_offset:program_counter_offset + 4],
        byteorder="little")


def _wait_for_program_counter_change(client: RSPClient, previous: int,
                                     timeout: float = 5.0) -> int:
    """Wait until a stopped target shows that its queued step has executed."""
    deadline = time.monotonic() + timeout
    current = _program_counter(client)
    while current == previous and time.monotonic() < deadline:
        time.sleep(0.050)
        current = _program_counter(client)
    assert current != previous, "single step did not change PC within %.1f seconds" % timeout
    return current


def _recover_all_stop_spin(client: RSPClient, mailbox: FixtureMailboxClient,
                           sequence: int) -> None:
    """Best-effort cleanup for a failed all-stop spin scenario."""
    try:
        client.interrupt(timeout=1.0)
        client.receive_packet(timeout=2.0)
    except RSPError:
        pass
    try:
        mailbox.release_spin(sequence, timeout=1.0)
        client.send_packet(b"c", timeout=1.0)
    except RSPError:
        pass


def _recover_non_stop_spin(client: RSPClient, mailbox: FixtureMailboxClient,
                           sequence: int) -> None:
    """Best-effort cleanup for a failed non-stop spin scenario."""
    try:
        if client.command(b"vCont;t", timeout=2.0) == b"OK":
            notification = client.receive_packet_with_type(timeout=2.0)
            if notification.packet_type == "%":
                client.command(b"vStopped", timeout=2.0)
    except RSPError:
        pass
    try:
        mailbox.release_spin(sequence, timeout=1.0)
        client.command(b"vCont;c", timeout=1.0)
    except RSPError:
        pass
