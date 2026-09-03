# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Semihosting console and GDB File-I/O scenarios for B-U585I-IOT02A."""

from __future__ import annotations

from pathlib import Path
import time

import pytest

from mailbox import FixtureMailboxClient, MailboxCommand, resolve_elf_symbol
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient
from stream import TCPStreamClient


_CONSOLE_MESSAGE = b"pyOCD semihosting test firmware message\n"
_FILE_NAME = b"gdbserver_test_firmware.bin"
_FILE_MESSAGE = b"pyOCD GDB file-I/O test firmware\n"
_GDB_FILE_DESCRIPTOR = 7
_TARGET_FILE_DESCRIPTOR = _GDB_FILE_DESCRIPTOR + 4


@pytest.mark.gdbserver_config(enable_semihosting=False)
def test_semihosting_breakpoint_stops_when_semihosting_is_disabled(
        gdbserver_server: PyOCDGDBServer,
        request: pytest.FixtureRequest) -> None:
    """
    Purpose: Check that a program request for host services becomes an ordinary breakpoint stop when semihosting is disabled.
    Test method:
    1. Require a server configuration with semihosting disabled and connect controller and observer clients.
    2. Record the mailbox, queue SEMIHOSTING_WRITE, and continue the controller.
    3. Require T05 at the firmware-owned BKPT 0xAB instead of transparent host servicing.
    4. Verify the console call was reached but the command is still incomplete.
    5. Continue past the literal breakpoint, wait for completion, and require exactly one console call.
    Expected result: The RSP client receives T05 rather than a forwarded console request.
    Failure indicates: Disabled semihosting is intercepted, ignored, or reported with the wrong stop behavior.
    """
    if request.config.getoption("--gdbserver-semihosting"):
        pytest.skip("disabled-semihosting scenario cannot run with --gdbserver-semihosting")

    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
            controller.send_packet(b"c")
            assert controller.receive_packet(timeout=5.0).startswith(b"T05")

            controller.send_packet(b"c")
            completed = mailbox.wait_for_completion(command_sequence)
            assert completed.semihosting_console_calls == 1
            _interrupt_and_expect_stop(controller)


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_is_forwarded_to_telnet(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a test-firmware console message reaches the host through the semihosting output stream.
    Test method:
    1. Start pyOCD with semihosting enabled and connect the telnet console before execution.
    2. Connect controller and observer RSP clients and wait for mailbox readiness.
    3. Queue SEMIHOSTING_WRITE and continue with the controller.
    4. Require the exact console byte string on telnet and exact mailbox command completion.
    5. Verify one console call and interrupt the normally running target with T02.
    Expected result: The exact test-firmware console message arrives and the command completes.
    Failure indicates: Semihosting console forwarding or target resume after servicing fails.
    """
    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.telnet_port,
            "semihosting-console.bin") as console:
        with gdbserver_server.connect_rsp() as controller:
            with gdbserver_server.connect_rsp() as observer:
                mailbox = _mailbox(gdbserver_server, observer)
                command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
                controller.send_packet(b"c")
                assert _CONSOLE_MESSAGE in console.read_until(_CONSOLE_MESSAGE)
                completed = mailbox.wait_for_completion(command_sequence)
                assert completed.semihosting_console_calls == 1
                _interrupt_and_expect_stop(controller)


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_is_serviced_after_monitor_continue(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that semihosting remains transparent when execution is started by a monitor command.
    Test method:
    1. Connect telnet, controller, and observer clients with semihosting enabled.
    2. Queue SEMIHOSTING_WRITE while the target is halted.
    3. Resume with the pyOCD monitor continue command instead of an RSP c packet.
    4. Require the exact telnet output and mailbox completion after the immediate semihosting halt is serviced.
    5. Issue monitor halt in finally cleanup so a failed assertion does not leave the target running.
    Expected result: The console text arrives and the test firmware continues after its semihosting breakpoint.
    Failure indicates: Monitor-command state reconciliation leaves an immediate semihosting halt unserviced.
    """
    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.telnet_port,
            "semihosting-monitor-continue.bin") as console:
        with gdbserver_server.connect_rsp() as controller:
            with gdbserver_server.connect_rsp() as observer:
                mailbox = _mailbox(gdbserver_server, observer)
                command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
                try:
                    controller.monitor("continue")
                    assert _CONSOLE_MESSAGE in console.read_until(_CONSOLE_MESSAGE)
                    completed = mailbox.wait_for_completion(command_sequence)
                    assert completed.semihosting_console_calls == 1
                finally:
                    controller.monitor("halt")


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_completes_after_single_step(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that stepping one instruction does not prevent the test firmware's later console message from reaching the host.
    Test method:
    1. Resolve the semihosting console function and connect telnet, controller, and observer clients.
    2. Queue SEMIHOSTING_WRITE, insert Z1 at the function entry, and continue to T05 in its expected PC window.
    3. Prove the console operation has not executed, remove Z1, and single-step one ordinary instruction.
    4. Require T05 at a changed PC while the mailbox command remains incomplete.
    5. Continue, capture the exact console text, verify one completed call, and interrupt cleanly.
    6. Remove the breakpoint in finally cleanup if normal removal was not reached.
    Expected result: Stepping does not suppress the semihosting request and expected output is forwarded.
    Failure indicates: Step processing corrupts or bypasses subsequent semihosting service.
    """
    breakpoint_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_semihosting_write") & ~1
    insert_packet = _breakpoint_packet(b"Z1", breakpoint_address)
    remove_packet = _breakpoint_packet(b"z1", breakpoint_address)
    breakpoint_inserted = False

    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.telnet_port,
            "semihosting-console-after-step.bin") as console:
        with gdbserver_server.connect_rsp() as controller:
            with gdbserver_server.connect_rsp() as observer:
                mailbox = _mailbox(gdbserver_server, observer)
                before = mailbox.read()
                command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
                try:
                    assert controller.command(insert_packet) == b"OK"
                    breakpoint_inserted = True
                    controller.send_packet(b"c")
                    program_counter_before = _expect_sigtrap_at_function_entry(
                        controller, breakpoint_address)

                    stopped = mailbox.read()
                    assert stopped.completed_sequence != command_sequence
                    assert stopped.semihosting_console_calls == before.semihosting_console_calls

                    assert controller.command(remove_packet) == b"OK"
                    breakpoint_inserted = False
                    controller.send_packet(b"s")
                    assert controller.receive_packet(timeout=5.0).startswith(b"T05")
                    assert _program_counter(controller) != program_counter_before

                    controller.send_packet(b"c")
                    assert _CONSOLE_MESSAGE in console.read_until(_CONSOLE_MESSAGE)
                    completed = mailbox.wait_for_completion(command_sequence)
                    assert completed.semihosting_console_calls == (
                        before.semihosting_console_calls + 1)
                    _interrupt_and_expect_stop(controller)
                finally:
                    if breakpoint_inserted:
                        assert controller.command(remove_packet) == b"OK"


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_handles_several_requests_in_one_run(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that several console messages can be serviced in sequence without restarting the server or reconnecting the stream.
    Test method:
    1. Connect one telnet stream plus controller and observer RSP clients.
    2. Record the initial console-call counter and keep the controller running after the first request.
    3. Queue three distinct mailbox sequences for SEMIHOSTING_WRITE without restarting pyOCD or telnet.
    4. Wait for each exact sequence to complete through the observer.
    5. Capture until three complete messages arrive and require exactly three copies and three new calls.
    6. Interrupt the controller with T02 after the final request.
    Expected result: Each request yields its expected text and all commands complete.
    Failure indicates: Repeated semihosting requests lose output, deadlock, or require server restart.
    """
    request_count = 3
    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.telnet_port,
            "semihosting-console-sequence.bin") as console:
        with gdbserver_server.connect_rsp() as controller:
            with gdbserver_server.connect_rsp() as observer:
                mailbox = _mailbox(gdbserver_server, observer)
                before = mailbox.read()
                command_sequences = []
                completed = None
                for request_index in range(request_count):
                    command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
                    command_sequences.append(command_sequence)
                    if request_index == 0:
                        controller.send_packet(b"c")
                    completed = mailbox.wait_for_completion(command_sequence)

                captured = _wait_for_console_messages(console, request_count)
                assert captured.count(_CONSOLE_MESSAGE) == request_count
                assert completed is not None
                assert completed.completed_sequence == command_sequences[-1]
                assert completed.semihosting_console_calls == (
                    before.semihosting_console_calls + request_count)
                _interrupt_and_expect_stop(controller)


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_is_serviced_after_final_gdb_detach(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that the console stream continues to service the running test firmware after the final debugger detaches.
    Test method:
    1. Connect telnet and the sole RSP controller with semihosting enabled.
    2. Queue SEMIHOSTING_WRITE while halted, then detach and close the final GDB/RSP client.
    3. Let persistent gdbserver resume and service the BKPT with no GDB client attached.
    4. Require the exact console text on the original telnet connection.
    5. Reconnect a verifier and require exact mailbox completion and one console call.
    Expected result: The stream receives expected text while persistent gdbserver has no GDB client.
    Failure indicates: Final-client detach disables semihosting service or target progress.
    """
    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.telnet_port,
            "semihosting-no-client.bin") as console:
        with gdbserver_server.connect_rsp() as controller:
            mailbox = _mailbox(gdbserver_server, controller)
            command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
            controller.detach()

        assert _CONSOLE_MESSAGE in console.read_until(_CONSOLE_MESSAGE)
        with gdbserver_server.connect_rsp() as verifier:
            mailbox = _mailbox(gdbserver_server, verifier)
            completed = mailbox.wait_for_completion(command_sequence)
            assert completed.semihosting_console_calls == 1


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_survives_no_client_connect_and_disconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Verify that semihosting console output remains complete across the full GDB-client lifecycle.
    Test method:
    1. Connect one telnet collector and use a short-lived RSP setup client to queue SEMIHOSTING_WRITE while halted.
    2. Detach that setup client before the target executes the command, then require the first exact console message with no GDB client connected.
    3. Connect one RSP controller, confirm the first command completed, queue a second SEMIHOSTING_WRITE, and continue it while that one client remains connected.
    4. Require exactly two complete console messages, interrupt the controller, and confirm the target recorded two completed console calls.
    5. Queue a third SEMIHOSTING_WRITE while halted, detach the controller before it executes, and require exactly three complete console messages.
    6. Reconnect a verifier and require the third completion plus exactly three console calls, proving each lifecycle phase produced one message without duplication or loss.
    Expected result: One complete console message is delivered before a client connection, while one client is connected, and after final detach.
    Failure indicates: Client attachment or final detach disrupts semihosting service, target resume, console routing, or message integrity.
    """
    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.telnet_port,
            "semihosting-client-lifecycle.bin") as console:
        with gdbserver_server.connect_rsp() as setup:
            mailbox = _mailbox(gdbserver_server, setup)
            before = mailbox.read()
            no_client_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
            setup.detach()

        captured = _wait_for_console_messages(console, 1)
        assert captured.count(_CONSOLE_MESSAGE) == 1

        with gdbserver_server.connect_rsp() as controller:
            mailbox = _mailbox(gdbserver_server, controller)
            no_client_completed = mailbox.wait_for_completion(no_client_sequence)
            assert no_client_completed.semihosting_console_calls == (
                before.semihosting_console_calls + 1)

            connected_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
            controller.send_packet(b"c")
            captured = _wait_for_console_messages(console, 2)
            assert captured.count(_CONSOLE_MESSAGE) == 2
            _interrupt_and_expect_stop(controller)
            connected_completed = mailbox.wait_for_completion(connected_sequence)
            assert connected_completed.semihosting_console_calls == (
                before.semihosting_console_calls + 2)

            disconnected_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
            controller.detach()

        captured = _wait_for_console_messages(console, 3)
        assert captured.count(_CONSOLE_MESSAGE) == 3

        with gdbserver_server.connect_rsp() as verifier:
            mailbox = _mailbox(gdbserver_server, verifier)
            disconnected_completed = mailbox.wait_for_completion(disconnected_sequence)
            assert disconnected_completed.semihosting_console_calls == (
                before.semihosting_console_calls + 3)


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_console_works_after_rsp_reset_and_reconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that console output still reaches the host after the debugger resets the board and reconnects.
    Test method:
    1. Connect the initial controller, record the boot epoch, and send the extended-remote reset sequence.
    2. Close the controller and require persistent gdbserver to remain alive.
    3. Reconnect controller and observer clients, resume initialization, and wait for the exact next boot epoch.
    4. Require the reset console counter to be zero and attach a new telnet stream.
    5. Queue SEMIHOSTING_WRITE, capture exactly one message, verify completion, and interrupt cleanly.
    Expected result: The post-reset test-firmware command completes and forwards its expected console text.
    Failure indicates: Reset leaves semihosting transport or reconnect state unusable.
    """
    mailbox_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_mailbox")
    controller = gdbserver_server.connect_rsp()
    try:
        before = FixtureMailboxClient(controller, mailbox_address).wait_until_ready()
        expected_epoch = (before.boot_epoch + 1) & 0xffffffff
        controller.extended_reset()
    finally:
        controller.close()

    assert gdbserver_server.is_running
    with gdbserver_server.connect_rsp() as reconnected:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = FixtureMailboxClient(observer, mailbox_address)
            reconnected.send_packet(b"c")
            after = mailbox.wait_for_reset(expected_epoch)
            assert after.semihosting_console_calls == 0

            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.telnet_port,
                    "semihosting-console-after-reset.bin") as console:
                command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
                captured = _wait_for_console_messages(console, 1)
                completed = mailbox.wait_for_completion(command_sequence)
                assert captured.count(_CONSOLE_MESSAGE) == 1
                assert completed.semihosting_console_calls == 1
            _interrupt_and_expect_stop(reconnected)


@pytest.mark.gdbserver_config(enable_semihosting=True, semihost_use_syscalls=True)
def test_gdb_file_syscalls_round_trip_to_active_client(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that the test firmware can ask the connected debugger to create, write, and close a host file.
    Test method:
    1. Start syscall-mode semihosting and connect controller and observer clients.
    2. Confirm non-stop is unavailable for this File-I/O mode and queue SEMIHOSTING_FILE_WRITE.
    3. Continue and receive Fopen; validate the target filename, mode, and permissions through observer memory reads.
    4. Reply with a synthetic descriptor, receive Fwrite, validate its descriptor, length, and exact target bytes, then capture them.
    5. Reply with the written count, validate Fclose, and return success.
    6. Require three successful target calls, zero errno, exact artifact bytes, and clean interruption.
    Expected result: File-I/O replies, test-firmware result fields, and captured artifact content all match expectations.
    Failure indicates: File-I/O packet translation, target memory arguments, or host-file results are incorrect.
    """
    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            artifact_path = (
                gdbserver_server.configuration.artifacts.directory /
                "gdb-file-io-output.bin")
            assert b"QNonStop+" not in controller.command(b"qSupported:multiprocess+")
            assert controller.command_response(b"QNonStop:1") == b"E01"

            command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_FILE_WRITE)
            controller.send_packet(b"c")
            _serve_file_syscalls(controller, observer, artifact_path)

            completed = mailbox.wait_for_completion(command_sequence)
            assert completed.semihosting_file_calls == 3
            assert completed.semihosting_open_result_signed == _TARGET_FILE_DESCRIPTOR
            assert completed.semihosting_write_remaining_signed == 0
            assert completed.semihosting_close_result_signed == 0
            assert completed.semihosting_errno == 0
            assert artifact_path.read_bytes() == _FILE_MESSAGE
            _interrupt_and_expect_stop(controller)


@pytest.mark.gdbserver_config(enable_semihosting=True, semihost_use_syscalls=True)
def test_gdb_file_syscalls_complete_after_single_step(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that stepping at the entry to a GDB File-I/O operation does not prevent its later syscall exchange.
    Test method:
    1. Connect controller and observer clients and resolve the semihosting file-operation function from the ELF.
    2. Queue SEMIHOSTING_FILE_WRITE and install a hardware breakpoint at that function entry.
    3. Continue to the breakpoint, verify SIGTRAP and its PC range, then remove the breakpoint.
    4. Single-step one ordinary instruction and verify that the PC advances while the command remains incomplete.
    5. Continue and service the ordered Fopen, Fwrite, and Fclose packets, validating their target arguments.
    6. Verify the mailbox return values and captured file bytes, then interrupt the normally running target.
    Expected result: The step advances, all three syscalls succeed, and the captured file exactly matches the test payload.
    Failure indicates: A preceding single-step loses semihosting state, corrupts File-I/O packets, or prevents target resume.
    """
    breakpoint_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_semihosting_file_write") & ~1
    insert_packet = _breakpoint_packet(b"Z1", breakpoint_address)
    remove_packet = _breakpoint_packet(b"z1", breakpoint_address)
    breakpoint_inserted = False

    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            artifact_path = (
                gdbserver_server.configuration.artifacts.directory /
                "gdb-file-io-after-step.bin")
            try:
                command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_FILE_WRITE)
                assert controller.command(insert_packet) == b"OK"
                breakpoint_inserted = True
                controller.send_packet(b"c")
                program_counter_before = _expect_sigtrap_at_function_entry(
                    controller, breakpoint_address)
                assert controller.command(remove_packet) == b"OK"
                breakpoint_inserted = False

                controller.send_packet(b"s")
                assert controller.receive_packet(timeout=5.0).startswith(b"T05")
                assert _program_counter(controller) != program_counter_before
                assert mailbox.read().completed_sequence != command_sequence

                controller.send_packet(b"c")
                _serve_file_syscalls(controller, observer, artifact_path)
                completed = mailbox.wait_for_completion(command_sequence)
                assert completed.semihosting_file_calls == 3
                assert completed.semihosting_open_result_signed == _TARGET_FILE_DESCRIPTOR
                assert completed.semihosting_write_remaining_signed == 0
                assert completed.semihosting_close_result_signed == 0
                assert completed.semihosting_errno == 0
                assert artifact_path.read_bytes() == _FILE_MESSAGE
                _interrupt_and_expect_stop(controller)
            finally:
                if breakpoint_inserted:
                    assert controller.command(remove_packet) == b"OK"


@pytest.mark.gdbserver_config(
    enable_semihosting=True,
    semihost_use_syscalls=True,
    extra_arguments=("-vv",))
def test_gdb_file_syscalls_fail_without_an_active_client(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a host-file request fails promptly and safely when no debugger is connected to handle it.
    Test method:
    1. Start syscall-mode semihosting with verbose logging and connect the sole RSP client.
    2. Queue SEMIHOSTING_FILE_WRITE while halted, then detach the final client so the target resumes without a handler.
    3. Require pyOCD's explicit no-client skip diagnostic within a bounded deadline.
    4. Reconnect a verifier and wait for the mailbox command to complete rather than deadlock.
    5. Require one failed open result and a non-zero target errno.
    Expected result: The target receives a connection error and gdbserver remains responsive.
    Failure indicates: Unowned File-I/O blocks indefinitely or leaves persistent gdbserver unusable.
    """
    with gdbserver_server.connect_rsp() as controller:
        mailbox = _mailbox(gdbserver_server, controller)
        command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_FILE_WRITE)
        controller.detach()

    assert "Skipping GDB syscall because no client is available" in gdbserver_server.wait_for_log(
        "Skipping GDB syscall because no client is available")
    with gdbserver_server.connect_rsp() as verifier:
        mailbox = _mailbox(gdbserver_server, verifier)
        completed = mailbox.wait_for_completion(command_sequence)
        assert completed.semihosting_file_calls == 1
        assert completed.semihosting_open_result_signed == -1
        assert completed.semihosting_errno != 0


@pytest.mark.gdbserver_config(enable_semihosting=True, semihost_use_syscalls=True)
def test_gdb_file_syscall_recovers_when_active_client_disconnects(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that loss of the debugger during a host-file request returns a clear error and leaves the server usable.
    Test method:
    1. Start syscall-mode semihosting and connect controller and observer clients.
    2. Queue SEMIHOSTING_FILE_WRITE, continue, and receive the first Fopen request on the active controller.
    3. Validate that the packet is an open operation, then abruptly close the client without replying.
    4. Use the observer to require command completion with a failed open result and non-zero errno.
    5. Require the server log to identify that the connection closed during the syscall.
    Expected result: The target receives ENOTCONN and a new client can still use gdbserver.
    Failure indicates: Mid-request client loss wedges File-I/O or the server session.
    """
    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            command_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_FILE_WRITE)
            controller.send_packet(b"c")
            request = controller.receive_packet(timeout=5.0)
            assert request.startswith(b"Fopen,")
            controller.close()

            completed = mailbox.wait_for_completion(command_sequence)
            assert completed.semihosting_file_calls == 1
            assert completed.semihosting_open_result_signed == -1
            assert completed.semihosting_errno != 0

    assert "Connection closed during syscall" in gdbserver_server.wait_for_log(
        "Connection closed during syscall")


def _mailbox(server: PyOCDGDBServer, client: RSPClient) -> FixtureMailboxClient:
    """Construct a ready mailbox client for a manually managed RSP connection."""
    address = resolve_elf_symbol(server.configuration.firmware, "gdbserver_test_firmware_mailbox")
    mailbox = FixtureMailboxClient(client, address)
    mailbox.wait_until_ready()
    return mailbox


def _serve_file_syscalls(controller: RSPClient, observer: RSPClient,
                         artifact_path: Path) -> None:
    """Validate, emulate, and record the fixture's ordered GDB ``F`` packets."""
    open_request = controller.receive_packet(timeout=5.0)
    open_fields = _syscall_fields(open_request, b"open", 4)
    filename_address, filename_length = _pointer_and_length(open_fields[1])
    assert observer.read_memory(filename_address, filename_length) == _FILE_NAME + b"\0"
    assert int(open_fields[2], 16) == 0x601
    assert int(open_fields[3], 16) == 0x1FF
    with artifact_path.open("xb") as output:
        controller.send_packet(("F%x,0" % _GDB_FILE_DESCRIPTOR).encode("ascii"))

        write_request = controller.receive_packet(timeout=5.0)
        write_fields = _syscall_fields(write_request, b"write", 4)
        assert int(write_fields[1], 16) == _GDB_FILE_DESCRIPTOR
        write_address = int(write_fields[2], 16)
        write_length = int(write_fields[3], 16)
        assert write_length == len(_FILE_MESSAGE)
        file_data = observer.read_memory(write_address, write_length)
        assert file_data == _FILE_MESSAGE
        output.write(file_data)
        controller.send_packet(("F%x,0" % write_length).encode("ascii"))

        close_request = controller.receive_packet(timeout=5.0)
        close_fields = _syscall_fields(close_request, b"close", 2)
        assert int(close_fields[1], 16) == _GDB_FILE_DESCRIPTOR
        controller.send_packet(b"F0,0")


def _syscall_fields(packet: bytes, operation: bytes, count: int) -> list[bytes]:
    """Split an expected GDB File-I/O request into its comma-separated fields."""
    expected_prefix = b"F" + operation + b","
    assert packet.startswith(expected_prefix), "unexpected GDB File-I/O request: %r" % packet
    fields = packet[1:].split(b",")
    assert len(fields) == count, "malformed GDB File-I/O request: %r" % packet
    assert fields[0] == operation
    return fields


def _pointer_and_length(value: bytes) -> tuple[int, int]:
    """Decode a GDB File-I/O ``address/length`` argument."""
    address, length = value.split(b"/", 1)
    return int(address, 16), int(length, 16)


def _wait_for_console_messages(stream: TCPStreamClient, count: int,
                               timeout: float = 5.0) -> bytes:
    """Collect a specific number of complete fixture console messages by a deadline."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        captured = stream.received
        if captured.count(_CONSOLE_MESSAGE) >= count:
            return captured
        stream.read_available(timeout=min(0.200, max(0.001, deadline - time.monotonic())))
    raise AssertionError(
        "received %d of %d semihosting console messages within %.1f seconds" %
        (stream.received.count(_CONSOLE_MESSAGE), count, timeout))


def _interrupt_and_expect_stop(client: RSPClient) -> None:
    """Stop an outstanding all-stop continue request after its mailbox command completes."""
    client.interrupt()
    assert client.receive_packet(timeout=5.0).startswith(b"T02")


def _breakpoint_packet(kind: bytes, address: int) -> bytes:
    """Encode a two-byte RSP breakpoint insertion or removal request."""
    return kind + (",%x,2" % address).encode("ascii")


def _expect_sigtrap_at_function_entry(client: RSPClient, address: int) -> int:
    """Require a hardware-breakpoint stop at a nearby fixture function entry."""
    assert client.receive_packet(timeout=5.0).startswith(b"T05")
    program_counter = _program_counter(client)
    assert address <= program_counter < address + 64
    return program_counter


def _program_counter(client: RSPClient) -> int:
    """Read the Cortex-M program counter from the standard RSP register block."""
    registers = client.read_registers()
    program_counter_offset = 15 * 4
    assert len(registers) >= program_counter_offset + 4
    return int.from_bytes(
        registers[program_counter_offset:program_counter_offset + 4],
        byteorder="little") & ~1
