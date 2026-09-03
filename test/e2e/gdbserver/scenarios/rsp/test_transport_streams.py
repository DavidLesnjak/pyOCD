# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Continuous RTT and semihosting stream scenarios for client lifecycle changes."""

from __future__ import annotations

from contextlib import ExitStack
import time

import pytest

from mailbox import FixtureMailbox, FixtureMailboxClient, MailboxCommand, resolve_elf_symbol
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient
from stream import TCPStreamClient


_FRAME_CHECK_XOR = 0xA5A5A5A5
_STREAM_MESSAGE_COUNT = 128
_PHASE_MESSAGE_COUNT = 16


@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_stream_survives_no_client_connect_and_disconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Verify continuous RTT output remains lossless across no-client, one-client, and final-detach phases.
    Test method:
    1. Connect an RTT collector and use a setup RSP client only to queue a 128-frame RTT stream while halted.
    2. Detach setup before execution and require the collector to receive the first stream frames with no GDB client attached.
    3. Connect one RSP controller, resume the active stream, require further frames, and interrupt it after that connected phase.
    4. Detach the controller, let the stream finish with no GDB client, and reconnect only to inspect the completed mailbox state.
    5. Require all 128 numbered and checksummed RTT frames exactly once in order, zero RTT dropped bytes, and matching target counters.
    Expected result: RTT delivers the complete continuous stream without corruption, gaps, duplicates, or drops across client lifecycle changes.
    Failure indicates: RTT polling, stream forwarding, target resume, RSP lifecycle handling, or RTT-buffer preservation is broken.
    """
    _run_transport_stream_lifecycle(
        gdbserver_server,
        MailboxCommand.TRANSPORT_STREAM_RTT,
        use_rtt=True,
        use_semihosting=False)


@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_stream_survives_no_client_connect_and_disconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Verify continuous semihosting console output remains lossless across no-client, one-client, and final-detach phases.
    Test method:
    1. Connect a telnet collector and use a setup RSP client only to queue a 128-frame semihosting stream while halted.
    2. Detach setup before execution and require the first console frames while no GDB client is attached.
    3. Connect one RSP controller, resume the active stream, require further console frames, and interrupt it after that connected phase.
    4. Detach the controller, let the stream finish with no GDB client, and reconnect only to inspect completion counters.
    5. Require all 128 numbered and checksummed console frames exactly once in order, zero semihosting failures, and matching target counters.
    Expected result: pyOCD services every semihosting request and forwards every complete frame across each client lifecycle phase.
    Failure indicates: Repeated semihosting service, target resume, telnet forwarding, or detach handling loses or duplicates console output.
    """
    _run_transport_stream_lifecycle(
        gdbserver_server,
        MailboxCommand.TRANSPORT_STREAM_SEMIHOSTING,
        use_rtt=False,
        use_semihosting=True)


@pytest.mark.gdbserver_config(rtt_mode="symbol", enable_semihosting=True)
def test_combined_transport_stream_survives_no_client_connect_and_disconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Verify concurrent RTT and semihosting streams remain independently lossless across client lifecycle changes.
    Test method:
    1. Connect RTT and telnet collectors, then use a setup RSP client only to queue a 128-frame combined stream while halted.
    2. Detach setup before execution and require both collectors to receive initial matching frames with no GDB client attached.
    3. Connect one RSP controller, resume the active combined stream, require further matching frames on both collectors, and interrupt it.
    4. Detach the controller, require both streams to finish while no GDB client is attached, then reconnect only for mailbox verification.
    5. Require each collector to contain sequences 1 through 128 exactly once with valid checksums, zero RTT drops, zero semihosting failures, and matching counters.
    Expected result: Both transports continue together without one starving, corrupting, dropping, or duplicating the other during client transitions.
    Failure indicates: Concurrent RTT and semihosting servicing, stream polling, target resume, or RSP lifecycle state is not robust.
    """
    _run_transport_stream_lifecycle(
        gdbserver_server,
        MailboxCommand.TRANSPORT_STREAM_BOTH,
        use_rtt=True,
        use_semihosting=True)


def _run_transport_stream_lifecycle(server: PyOCDGDBServer, command: MailboxCommand,
                                    *, use_rtt: bool, use_semihosting: bool) -> None:
    """Run a numbered target stream through no-client, one-client, and final-detach phases."""
    with ExitStack() as stack:
        streams: list[tuple[bytes, TCPStreamClient]] = []
        if use_rtt:
            streams.append((b"RTTS", stack.enter_context(server.connect_stream(
                server.configuration.rtt_port, "transport-stream-rtt.bin"))))
        if use_semihosting:
            streams.append((b"SEMS", stack.enter_context(server.connect_stream(
                server.configuration.telnet_port, "transport-stream-semihosting.bin"))))

        with server.connect_rsp() as setup:
            mailbox = _mailbox(server, setup)
            before = mailbox.read()
            command_sequence = mailbox.request(command, argument=_STREAM_MESSAGE_COUNT)
            setup.detach()

        initial_sequence = before.transport_stream_sequence + _PHASE_MESSAGE_COUNT
        _wait_for_stream_sequence(streams, initial_sequence)

        with server.connect_rsp() as controller:
            mailbox = _mailbox(server, controller)
            before_connected = mailbox.read()
            assert before_connected.transport_stream_sequence >= initial_sequence
            connected_sequence = before_connected.transport_stream_sequence + _PHASE_MESSAGE_COUNT
            final_sequence = before.transport_stream_sequence + _STREAM_MESSAGE_COUNT
            assert connected_sequence < final_sequence

            controller.send_packet(b"c")
            _wait_for_stream_sequence(streams, connected_sequence)
            _interrupt_and_expect_sigint(controller)
            after_connected = mailbox.read()
            assert after_connected.transport_stream_sequence >= connected_sequence
            assert after_connected.transport_stream_sequence < final_sequence
            controller.detach()

        _wait_for_stream_sequence(streams, final_sequence)
        time.sleep(0.100)
        with server.connect_rsp() as verifier:
            mailbox = _mailbox(server, verifier)
            completed = mailbox.wait_for_completion(command_sequence)
            _assert_completed_stream(
                completed, final_sequence, use_rtt=use_rtt, use_semihosting=use_semihosting)

        for prefix, stream in streams:
            _assert_exact_stream_frames(stream.received, prefix, before.transport_stream_sequence + 1,
                                        final_sequence)


def _mailbox(server: PyOCDGDBServer, client: RSPClient) -> FixtureMailboxClient:
    """Construct a ready mailbox client for one manually managed RSP connection."""
    address = resolve_elf_symbol(server.configuration.firmware, "gdbserver_test_firmware_mailbox")
    mailbox = FixtureMailboxClient(client, address)
    mailbox.wait_until_ready()
    return mailbox


def _wait_for_stream_sequence(streams: list[tuple[bytes, TCPStreamClient]], sequence: int,
                              timeout: float = 20.0) -> None:
    """Pump every active transport until each stream contains the requested frame sequence."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all(sequence in _stream_sequences(stream.received, prefix) for prefix, stream in streams):
            return
        remaining = max(0.001, deadline - time.monotonic())
        for _, stream in streams:
            stream.read_available(timeout=min(0.020, remaining))
    raise AssertionError("transport stream frame %d did not arrive on every stream" % sequence)


def _assert_completed_stream(completed: FixtureMailbox, final_sequence: int,
                             *, use_rtt: bool, use_semihosting: bool) -> None:
    """Require target counters to agree with the requested stream modes and frame count."""
    assert completed.transport_stream_sequence == final_sequence
    assert completed.transport_stream_rtt_messages == (
        _STREAM_MESSAGE_COUNT if use_rtt else 0)
    assert completed.transport_stream_rtt_dropped_bytes == 0
    assert completed.transport_stream_semihosting_messages == (
        _STREAM_MESSAGE_COUNT if use_semihosting else 0)
    assert completed.transport_stream_semihosting_failures == 0


def _interrupt_and_expect_sigint(client: RSPClient) -> None:
    """Stop an active all-stop stream before detaching the sole RSP controller."""
    client.interrupt()
    assert client.receive_packet(timeout=5.0).startswith(b"T02")


def _assert_exact_stream_frames(captured: bytes, prefix: bytes, first: int, last: int) -> None:
    """Require every numbered, checksummed frame in the requested inclusive sequence range."""
    expected = list(range(first, last + 1))
    actual = _stream_sequences(captured, prefix)
    assert actual == expected


def _stream_sequences(captured: bytes, prefix: bytes) -> list[int]:
    """Parse and validate complete target frames for one transport prefix."""
    sequences = []
    for line in captured.splitlines():
        if not line.startswith(prefix + b":"):
            continue
        fields = line.split(b":")
        assert len(fields) == 3, "malformed transport stream frame: %r" % line
        sequence = int(fields[1], 16)
        checksum = int(fields[2], 16)
        assert checksum == ((sequence ^ _FRAME_CHECK_XOR) & 0xffffffff)
        sequences.append(sequence)
    return sequences
