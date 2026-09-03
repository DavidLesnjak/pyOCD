# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""RTT discovery, transport, and input scenarios for B-U585I-IOT02A."""

from __future__ import annotations

import time

import pytest

from mailbox import FixtureMailboxClient, MailboxCommand, resolve_elf_symbol
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient
from stream import TCPStreamClient


_FRAME_CHECK_XOR = 0xA5A5A5A5
_BURST_FRAME_COUNT = 32


@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_symbol_discovery_serves_initial_frame_without_gdb_client(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that the board's RTT output is available as soon as the server starts, without a debugger connection.
    Test method:
    1. Start pyOCD with symbol-based RTT configuration and verify no explicit control-block address was supplied.
    2. Do not create any RSP or GDB connection; attach only a TCP client to RTT channel 0.
    3. Wait for the startup frame emitted during test firmware initialization.
    4. Decode every complete RTT line, validate its checksum, and require sequence 1 exactly once in order.
    Expected result: Channel 0 reports the test firmware's expected initial RTT message.
    Failure indicates: RTT discovery or no-client streaming depends incorrectly on an RSP connection.
    """
    assert gdbserver_server.configuration.rtt_mode == "symbol"
    assert gdbserver_server.configuration.rtt_control_block_address is None

    # Do not create an RSP connection in this scenario. The first fixture frame
    # is emitted during startup, so receiving it proves that RTT discovery and
    # polling are independent of a connected debugger.
    with gdbserver_server.connect_stream(
            gdbserver_server.configuration.rtt_port,
            "rtt-no-gdb.bin") as stream:
        captured = _wait_for_rtt_sequence(stream, 1)
        sequences = _low_rate_frame_sequences(captured)
        assert sequences == sorted(sequences)
        assert sequences.count(1) == 1


@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_symbol_discovery_transfers_output_and_input(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that ordinary RTT text can travel reliably from the board to the host and back again.
    Test method:
    1. Connect controller, observer, and channel-0 RTT clients while using symbol discovery.
    2. Record mailbox counters, queue RTT_WRITE, continue, and wait for exact command completion.
    3. Decode the emitted sequence frame and require one new message with no increase in dropped bytes.
    4. Send a fixed byte string down the RTT socket while the target continues running.
    5. Poll until the mailbox reports the exact input byte count and additive checksum.
    6. Require the input-response RTT sequence frame, unchanged drop count, and a clean T02 interrupt.
    Expected result: Both directions transfer the framed content without corruption.
    Failure indicates: RTT upload or down-channel handling is lost, altered, or stalled.
    """
    assert gdbserver_server.configuration.rtt_mode == "symbol"
    assert gdbserver_server.configuration.rtt_control_block_address is None

    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.rtt_port,
                    "rtt-symbol.bin") as stream:
                before = mailbox.read()
                command_sequence = mailbox.request(MailboxCommand.RTT_WRITE)
                controller.send_packet(b"c")
                completed = mailbox.wait_for_completion(command_sequence)

                captured = _wait_for_rtt_sequence(stream, completed.rtt_sequence)
                assert completed.rtt_messages == before.rtt_messages + 1
                assert completed.rtt_sequence == before.rtt_sequence + 1
                assert completed.rtt_dropped_bytes == before.rtt_dropped_bytes
                _assert_ordered_complete_frame_range(
                    captured,
                    completed.rtt_sequence,
                    completed.rtt_sequence)

                down_data = b"pyocd-rtt-input-0123456789"
                expected_bytes = completed.rtt_input_bytes + len(down_data)
                expected_checksum = (completed.rtt_input_checksum + sum(down_data)) & 0xffffffff
                stream.send(down_data)
                input_received = mailbox.wait_for(
                    lambda snapshot: (
                        snapshot.rtt_input_bytes >= expected_bytes and
                        snapshot.rtt_input_checksum == expected_checksum),
                    description="RTT down-channel input")
                assert input_received.rtt_input_bytes == expected_bytes
                assert input_received.rtt_input_checksum == expected_checksum
                captured = _wait_for_rtt_sequence(stream, input_received.rtt_sequence)
                assert input_received.rtt_messages >= completed.rtt_messages + 1
                assert input_received.rtt_sequence >= completed.rtt_sequence + 1
                assert input_received.rtt_dropped_bytes == before.rtt_dropped_bytes
                _assert_ordered_complete_frame_range(
                    captured,
                    completed.rtt_sequence + 1,
                    input_received.rtt_sequence)
                controller.interrupt()
                assert controller.receive_packet(timeout=5.0).startswith(b"T02")


@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_burst_channel_preserves_high_rate_framed_output(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a fast burst of RTT messages arrives complete, in order, and without duplicates.
    Test method:
    1. Connect controller and observer clients plus the dedicated channel-1 RTT burst stream.
    2. Record the initial sequence, message, and dropped-byte counters.
    3. Queue RTT_BURST with a count of 32 and continue the target.
    4. Wait for mailbox completion and collect through the final expected burst frame.
    5. Decode checksums and require the exact consecutive sequence range with no missing, duplicate, or reordered frame.
    6. Require 32 new messages, zero new dropped bytes, and a clean T02 interrupt.
    Expected result: All frames arrive once and in their expected order.
    Failure indicates: High-rate RTT buffering loses, duplicates, reorders, or corrupts frames.
    """
    assert gdbserver_server.configuration.rtt_mode == "symbol"
    assert gdbserver_server.configuration.rtt_burst_port != 0
    assert (gdbserver_server.configuration.rtt_burst_port !=
            gdbserver_server.configuration.rtt_port)

    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.rtt_burst_port,
                    "rtt-burst.bin") as stream:
                before = mailbox.read()
                command_sequence = mailbox.request(
                    MailboxCommand.RTT_BURST,
                    argument=_BURST_FRAME_COUNT)
                controller.send_packet(b"c")
                completed = mailbox.wait_for_completion(command_sequence)

                captured = _wait_for_rtt_burst_sequence(
                    stream, completed.rtt_burst_sequence)
                first_burst_sequence = before.rtt_burst_sequence + 1
                assert completed.rtt_burst_messages == (
                    before.rtt_burst_messages + _BURST_FRAME_COUNT)
                assert completed.rtt_burst_sequence == (
                    before.rtt_burst_sequence + _BURST_FRAME_COUNT)
                assert completed.rtt_burst_dropped_bytes == (
                    before.rtt_burst_dropped_bytes)
                _assert_ordered_complete_burst_frame_range(
                    captured,
                    first_burst_sequence,
                    completed.rtt_burst_sequence)
                controller.interrupt()
                assert controller.receive_packet(timeout=5.0).startswith(b"T02")


@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_output_is_drained_after_target_halt(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that RTT bytes already emitted by the test firmware remain available after execution is halted.
    Test method:
    1. Start symbol-based RTT and connect controller, observer, and channel-0 stream clients.
    2. Record the current RTT counters and queue one RTT_WRITE mailbox command.
    3. Continue the controller and wait through the observer until the command completes.
    4. Interrupt the controller before reading any RTT bytes and require the SIGINT stop reply.
    5. Drain the stream after the halt and validate the exact sequence and checksum of the queued frame.
    Expected result: The completed frame is delivered once after halt and the firmware reports no dropped RTT bytes.
    Failure indicates: Halting the target discards buffered RTT output or prevents the service thread from draining it.
    """
    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.rtt_port,
                    "rtt-after-halt.bin") as stream:
                before = mailbox.read()
                command_sequence = mailbox.request(MailboxCommand.RTT_WRITE)
                controller.send_packet(b"c")
                completed = mailbox.wait_for_completion(command_sequence)

                controller.interrupt()
                assert controller.receive_packet(timeout=5.0).startswith(b"T02")

                captured = _wait_for_rtt_sequence(stream, completed.rtt_sequence)
                assert completed.rtt_sequence == before.rtt_sequence + 1
                assert completed.rtt_dropped_bytes == before.rtt_dropped_bytes
                _assert_ordered_complete_frame_range(
                    captured, completed.rtt_sequence, completed.rtt_sequence)


@pytest.mark.gdbserver_config(rtt_mode="address")
def test_rtt_explicit_control_block_address_reconnects_stream(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that RTT continues to work after its TCP client reconnects when the control block address is configured explicitly.
    Test method:
    1. Resolve _SEGGER_RTT from the ELF and require the runner's explicit control-block address to match it.
    2. Connect controller and observer clients and attach the first channel-0 TCP stream.
    3. Queue RTT_WRITE, continue, validate the exact next frame and drop counters, then close the first stream.
    4. Attach a replacement TCP stream while the same target session remains active.
    5. Queue a second RTT_WRITE and require the following sequence frame with unchanged drop count.
    6. Interrupt the controller and require T02 after both stream lifecycles complete.
    Expected result: Both TCP clients receive the expected framed RTT traffic.
    Failure indicates: Explicit control-block addressing or RTT client lifecycle is broken.
    """
    expected_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "_SEGGER_RTT")
    assert gdbserver_server.configuration.rtt_mode == "address"
    assert gdbserver_server.configuration.rtt_control_block_address == expected_address

    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.rtt_port,
                    "rtt-address-first.bin") as stream:
                before = mailbox.read()
                command_sequence = mailbox.request(MailboxCommand.RTT_WRITE)
                controller.send_packet(b"c")
                completed = mailbox.wait_for_completion(command_sequence)
                captured = _wait_for_rtt_sequence(stream, completed.rtt_sequence)
                assert completed.rtt_messages == before.rtt_messages + 1
                assert completed.rtt_sequence == before.rtt_sequence + 1
                assert completed.rtt_dropped_bytes == before.rtt_dropped_bytes
                _assert_ordered_complete_frame_range(
                    captured,
                    completed.rtt_sequence,
                    completed.rtt_sequence)

            # The RTT worker accepts only one TCP client at a time. Closing the
            # first connection must not stop the server or lose the next frame.
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.rtt_port,
                    "rtt-address-reconnected.bin") as stream:
                before = mailbox.read()
                command_sequence = mailbox.request(MailboxCommand.RTT_WRITE)
                completed = mailbox.wait_for_completion(command_sequence)
                captured = _wait_for_rtt_sequence(stream, completed.rtt_sequence)
                assert completed.rtt_messages == before.rtt_messages + 1
                assert completed.rtt_sequence == before.rtt_sequence + 1
                assert completed.rtt_dropped_bytes == before.rtt_dropped_bytes
                _assert_ordered_complete_frame_range(
                    captured,
                    completed.rtt_sequence,
                    completed.rtt_sequence)

            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")


@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_active_rtt_stream_survives_final_gdb_disconnect_and_reconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that disconnecting and reconnecting GDB does not close an independently active RTT stream.
    Test method:
    1. Connect one RSP controller and one channel-0 RTT stream and consume the startup frame.
    2. Queue RTT_WRITE, detach the only GDB/RSP client, and leave the RTT socket connected.
    3. Require the queued frame while persistent gdbserver runs with no GDB client and verify the server remains alive.
    4. Connect a replacement RSP client, wait for prior completion, and verify exact counters and no drops.
    5. Queue another RTT_WRITE, resume with the replacement client, and require the next frame on the original RTT socket.
    6. Complete and interrupt through the replacement client without reconnecting RTT.
    Expected result: The original RTT stream remains usable before and after RSP reconnection.
    Failure indicates: GDB connection lifecycle improperly tears down an independent RTT stream.
    """
    mailbox_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_mailbox")
    controller = gdbserver_server.connect_rsp()
    try:
        mailbox = FixtureMailboxClient(controller, mailbox_address)
        mailbox.wait_until_ready()
        with gdbserver_server.connect_stream(
                gdbserver_server.configuration.rtt_port,
                "rtt-last-gdb-client.bin") as stream:
            _wait_for_rtt_sequence(stream, 1)

            # A newly connected all-stop RSP client has already halted the
            # target. Publish a command in that stopped state, then close the
            # sole client. Its disconnect is what resumes the target, so the
            # frame below must be produced after the final GDB disconnect
            # while this RTT connection stays open.
            before_disconnect = mailbox.read()
            command_sequence = mailbox.request(MailboxCommand.RTT_WRITE)
            expected_sequence = before_disconnect.rtt_sequence + 1
            stream_offset = len(stream.received)
            controller.close()

            captured = _wait_for_new_rtt_sequence(
                stream, expected_sequence, stream_offset)
            _assert_ordered_complete_frame_range(
                captured, expected_sequence, expected_sequence)
            assert gdbserver_server.is_running

            # Attach a new final client without replacing the active RTT TCP
            # connection. It must observe the command completed while no RSP
            # client was connected, then produce another frame on that same
            # stream.
            with gdbserver_server.connect_rsp() as reconnected:
                mailbox = FixtureMailboxClient(reconnected, mailbox_address)
                completed = mailbox.wait_for_completion(command_sequence)
                assert completed.rtt_messages == before_disconnect.rtt_messages + 1
                assert completed.rtt_sequence == expected_sequence
                assert completed.rtt_dropped_bytes == before_disconnect.rtt_dropped_bytes

                before_reconnected_write = mailbox.read()
                reconnected_sequence = mailbox.request(MailboxCommand.RTT_WRITE)
                expected_reconnected_sequence = before_reconnected_write.rtt_sequence + 1
                stream_offset = len(stream.received)
                reconnected.send_packet(b"c")
                captured = _wait_for_new_rtt_sequence(
                    stream, expected_reconnected_sequence, stream_offset)
                _interrupt_and_expect_sigint(reconnected)
                completed = mailbox.wait_for_completion(reconnected_sequence)
                assert completed.rtt_sequence == expected_reconnected_sequence
                assert completed.rtt_dropped_bytes == (
                    before_reconnected_write.rtt_dropped_bytes)
                _assert_ordered_complete_frame_range(
                    captured,
                    expected_reconnected_sequence,
                    expected_reconnected_sequence)
    finally:
        controller.close()


@pytest.mark.gdbserver_config(rtt_mode="address")
def test_active_rtt_stream_rediscovers_after_target_reset_and_gdb_reconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that RTT output resumes on its original TCP connection after a board reset and debugger reconnect.
    Test method:
    1. Use explicit RTT addressing and connect one controller plus a channel-0 RTT stream.
    2. Consume the initial frame, record the boot epoch, and queue SYSTEM_RESET.
    3. Continue, close the only RSP connection, and keep the original RTT socket open across target reset.
    4. Require a new sequence-1 startup frame and prove persistent gdbserver remains alive.
    5. Reconnect RSP and wait for the next reset-ready epoch with cleared command and RTT state.
    6. Queue RTT_WRITE, continue, and require sequence 2 on the original socket before clean interruption.
    Expected result: RTT resumes on the original stream after reset without manual reconnection.
    Failure indicates: Target reset leaves RTT discovery or its active connection unusable.
    """
    mailbox_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_mailbox")
    controller = gdbserver_server.connect_rsp()
    try:
        mailbox = FixtureMailboxClient(controller, mailbox_address)
        before = mailbox.wait_until_ready()
        with gdbserver_server.connect_stream(
                gdbserver_server.configuration.rtt_port,
                "rtt-active-reset.bin") as stream:
            _wait_for_rtt_sequence(stream, 1)
            stream_offset = len(stream.received)
            reset_sequence = mailbox.request(MailboxCommand.SYSTEM_RESET)
            controller.send_packet(b"c")
            controller.close()

            # The fixture restarts its low-rate frame numbering at one. Seeing
            # a new sequence-one frame on this same socket proves pyOCD found
            # the reinitialized RTT control block without replacing the TCP
            # consumer.
            captured = _wait_for_new_rtt_sequence(stream, 1, stream_offset)
            assert _low_rate_frame_sequences(captured).count(1) == 1
            assert gdbserver_server.is_running

            with gdbserver_server.connect_rsp() as reconnected:
                mailbox = FixtureMailboxClient(reconnected, mailbox_address)
                after = mailbox.wait_for_reset(
                    (before.boot_epoch + 1) & 0xffffffff)
                assert after.command_sequence == 0
                assert after.completed_sequence == 0
                assert after.rtt_sequence == 1
                assert reset_sequence != after.command_sequence

                command_sequence = mailbox.request(MailboxCommand.RTT_WRITE)
                stream_offset = len(stream.received)
                expected_sequence = after.rtt_sequence + 1
                reconnected.send_packet(b"c")
                captured = _wait_for_new_rtt_sequence(
                    stream, expected_sequence, stream_offset)
                _interrupt_and_expect_sigint(reconnected)
                completed = mailbox.wait_for_completion(command_sequence)
                assert completed.rtt_sequence == expected_sequence
                _assert_ordered_complete_frame_range(
                    captured, completed.rtt_sequence, completed.rtt_sequence)
    finally:
        controller.close()


def _mailbox(server: PyOCDGDBServer, client: RSPClient) -> FixtureMailboxClient:
    """Construct a ready mailbox client for a manually managed RSP connection."""
    address = resolve_elf_symbol(server.configuration.firmware, "gdbserver_test_firmware_mailbox")
    mailbox = FixtureMailboxClient(client, address)
    mailbox.wait_until_ready()
    return mailbox


def _interrupt_and_expect_sigint(client: RSPClient) -> None:
    """Stop an outstanding all-stop continue request before inspecting mailbox memory."""
    client.interrupt()
    assert client.receive_packet(timeout=5.0).startswith(b"T02")


def _wait_for_rtt_sequence(stream: TCPStreamClient, sequence: int,
                            timeout: float = 5.0) -> bytes:
    """Collect RTT data until the requested complete fixture frame arrives."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        captured = stream.received
        if sequence in _low_rate_frame_sequences(captured):
            return captured
        stream.read_available(timeout=min(0.200, max(0.001, deadline - time.monotonic())))
    raise AssertionError("RTT frame %d did not arrive within %.1f seconds" % (sequence, timeout))


def _wait_for_new_rtt_sequence(stream: TCPStreamClient, sequence: int,
                               start_offset: int, timeout: float = 5.0) -> bytes:
    """Collect stream bytes added after ``start_offset`` until a frame arrives."""
    if start_offset < 0:
        raise ValueError("RTT stream start offset must not be negative")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        captured = stream.received
        new_captured = captured[start_offset:]
        if sequence in _low_rate_frame_sequences(new_captured):
            return new_captured
        stream.read_available(timeout=min(0.200, max(0.001, deadline - time.monotonic())))
    raise AssertionError(
        "new RTT frame %d did not arrive within %.1f seconds" % (sequence, timeout))


def _wait_for_rtt_burst_sequence(stream: TCPStreamClient, sequence: int,
                                  timeout: float = 5.0) -> bytes:
    """Collect channel-1 data until the requested complete burst frame arrives."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        captured = stream.received
        if sequence in _burst_frame_sequences(captured):
            return captured
        stream.read_available(timeout=min(0.200, max(0.001, deadline - time.monotonic())))
    raise AssertionError(
        "RTT burst frame %d did not arrive within %.1f seconds" % (sequence, timeout))


def _assert_ordered_complete_frame_range(captured: bytes, first: int, last: int) -> None:
    """Require an exact, in-order, and duplicate-free RTT sequence range."""
    expected = list(range(first, last + 1))
    actual = [
        sequence
        for sequence in _low_rate_frame_sequences(captured)
        if first <= sequence <= last
    ]
    assert actual == expected, "RTT frames were lost, duplicated, or reordered: %r" % actual


def _assert_ordered_complete_burst_frame_range(
        captured: bytes, first: int, last: int) -> None:
    """Require an exact, in-order, duplicate-free channel-1 sequence range."""
    expected = list(range(first, last + 1))
    actual = [
        sequence
        for sequence in _burst_frame_sequences(captured)
        if first <= sequence <= last
    ]
    assert actual == expected, (
        "RTT burst frames were lost, duplicated, or reordered: %r" % actual)


def _frame_sequences(captured: bytes, prefix: bytes) -> list[int]:
    """Validate and return complete prefixed fixture frame numbers in wire order."""
    sequences: list[int] = []
    # TCP may split a fixture frame anywhere. Ignore its unfinished tail until
    # a later read supplies the newline rather than treating it as malformed.
    for raw_line in captured.split(b"\n")[:-1]:
        line = raw_line.rstrip(b"\r")
        if not line.startswith(prefix):
            continue
        fields = line.split(b":")
        assert len(fields) == 3, "malformed RTT fixture frame: %r" % line
        try:
            sequence = int(fields[1], 16)
            checksum = int(fields[2], 16)
        except ValueError as error:
            raise AssertionError("malformed RTT fixture frame: %r" % line) from error
        assert checksum == (sequence ^ _FRAME_CHECK_XOR), "bad RTT fixture frame: %r" % line
        sequences.append(sequence)
    return sequences


def _low_rate_frame_sequences(captured: bytes) -> list[int]:
    """Return sequence numbers carried by the low-rate channel-0 frames."""
    return _frame_sequences(captured, b"RTT:")


def _burst_frame_sequences(captured: bytes) -> list[int]:
    """Return sequence numbers carried by the high-rate channel-1 frames."""
    return _frame_sequences(captured, b"RTTB:")
