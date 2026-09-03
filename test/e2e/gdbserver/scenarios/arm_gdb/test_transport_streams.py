# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Continuous RTT and semihosting stream scenarios exercised through arm-none-eabi-gdb."""

from __future__ import annotations

from contextlib import ExitStack
import re
import time

import pytest

from mailbox import MailboxCommand
from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB, ExternalGDBSession
from stream import TCPStreamClient


_FRAME_CHECK_XOR = 0xA5A5A5A5
_STREAM_MESSAGE_COUNT = 128
_PHASE_MESSAGE_COUNT = 16


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_stream_survives_no_client_connect_and_disconnect(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify continuous RTT output remains lossless before Arm GDB connects, while one
    Arm GDB client controls the target, and after that client detaches.

    Test method:
    1. Connect an RTT collector and use an initial Arm GDB session only to queue a
       128-frame RTT stream while the target is halted.
    2. Detach before execution and require initial frames while pyOCD has no GDB
       client attached.
    3. Launch one Arm GDB client, resume the active stream, require further frames,
       interrupt it, and detach.
    4. Require the stream to finish with no GDB client, then reconnect only to read
       the target counters.
    5. Require all 128 numbered, checksummed RTT frames exactly once, zero drops,
       and matching target counters.

    Expected result:
    RTT forwards a complete continuous stream without gaps, duplicates, corruption,
    or drops across Arm GDB lifecycle changes.

    Failure indicates:
    RTT polling, target resume, external-GDB lifecycle handling, or RTT buffering is
    broken.
    """
    _run_transport_stream_lifecycle(
        gdbserver_gdb,
        gdbserver_server,
        MailboxCommand.TRANSPORT_STREAM_RTT,
        use_rtt=True,
        use_semihosting=False)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_semihosting=True)
def test_semihosting_stream_survives_no_client_connect_and_disconnect(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify continuous semihosting console output remains lossless before Arm GDB
    connects, while one client controls the target, and after it detaches.

    Test method:
    1. Connect a telnet collector and use an initial Arm GDB session only to queue a
       128-frame semihosting stream while the target is halted.
    2. Detach before execution and require initial console frames with no GDB client.
    3. Launch one Arm GDB client, resume the active stream, require further frames,
       interrupt it, and detach.
    4. Require the stream to finish with no GDB client, then reconnect only to read
       the target counters.
    5. Require all 128 numbered, checksummed console frames exactly once, zero
       semihosting failures, and matching target counters.

    Expected result:
    pyOCD services and forwards every semihosting request across each Arm GDB client
    lifecycle phase without a lost or duplicated frame.

    Failure indicates:
    Repeated semihosting service, target resume, telnet forwarding, or GDB detach
    handling is broken.
    """
    _run_transport_stream_lifecycle(
        gdbserver_gdb,
        gdbserver_server,
        MailboxCommand.TRANSPORT_STREAM_SEMIHOSTING,
        use_rtt=False,
        use_semihosting=True)


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(rtt_mode="symbol", enable_semihosting=True)
def test_combined_transport_stream_survives_no_client_connect_and_disconnect(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify concurrent RTT and semihosting streams remain independently lossless
    before Arm GDB connects, while one client controls execution, and after detach.

    Test method:
    1. Connect RTT and telnet collectors, then use an initial Arm GDB session only to
       queue a 128-frame combined stream while the target is halted.
    2. Detach before execution and require matching initial frames on both collectors
       while no GDB client is attached.
    3. Launch one Arm GDB client, resume the active stream, require further matching
       frames on both collectors, interrupt it, and detach.
    4. Require both streams to finish with no GDB client, then reconnect only to read
       the target counters.
    5. Require sequences 1 through 128 exactly once on both streams, valid checksums,
       zero RTT drops, zero semihosting failures, and matching target counters.

    Expected result:
    RTT and semihosting continue together without either transport starving,
    corrupting, dropping, or duplicating the other through Arm GDB lifecycle changes.

    Failure indicates:
    Concurrent transport servicing, RTT polling, semihosting handling, target resume,
    or external-GDB lifecycle state is not robust.
    """
    _run_transport_stream_lifecycle(
        gdbserver_gdb,
        gdbserver_server,
        MailboxCommand.TRANSPORT_STREAM_BOTH,
        use_rtt=True,
        use_semihosting=True)


def _run_transport_stream_lifecycle(gdb: ExternalGDB, server: PyOCDGDBServer,
                                    command: MailboxCommand, *, use_rtt: bool,
                                    use_semihosting: bool) -> None:
    """Run a numbered target stream through no-client, one-client, and final-detach phases."""
    with ExitStack() as stack:
        streams: list[tuple[bytes, TCPStreamClient]] = []
        if use_rtt:
            streams.append((b"RTTS", stack.enter_context(server.connect_stream(
                server.configuration.rtt_port, "arm-gdb-transport-stream-rtt.bin"))))
        if use_semihosting:
            streams.append((b"SEMS", stack.enter_context(server.connect_stream(
                server.configuration.telnet_port, "arm-gdb-transport-stream-semihosting.bin"))))

        with gdb.start(server, "transport-stream-setup") as setup:
            before_sequence = _queue_transport_stream(setup, command)
            setup.detach()

        initial_sequence = before_sequence + _PHASE_MESSAGE_COUNT
        _wait_for_stream_sequence(streams, initial_sequence)

        with gdb.start(server, "transport-stream-controller") as controller:
            before_connected = _read_transport_stream_state(controller)
            assert before_connected[0] >= initial_sequence
            connected_sequence = before_connected[0] + _PHASE_MESSAGE_COUNT
            final_sequence = before_sequence + _STREAM_MESSAGE_COUNT
            assert connected_sequence < final_sequence

            controller.continue_execution()
            _wait_for_stream_sequence(streams, connected_sequence)
            controller.interrupt()
            after_connected = _read_transport_stream_state(controller)
            assert after_connected[0] >= connected_sequence
            assert after_connected[0] < final_sequence
            controller.detach()

        _wait_for_stream_sequence(streams, final_sequence)
        time.sleep(0.100)
        with gdb.start(server, "transport-stream-verifier") as verifier:
            completed = _read_transport_stream_state(verifier)
            _assert_completed_stream(
                completed, final_sequence, use_rtt=use_rtt, use_semihosting=use_semihosting)
            verifier.detach()

        for prefix, stream in streams:
            _assert_exact_stream_frames(stream.received, prefix, before_sequence + 1, final_sequence)


def _queue_transport_stream(client: ExternalGDBSession, command: MailboxCommand) -> int:
    """Synchronize Arm GDB, publish one stream command, and return its first sequence number."""
    client.execute("break gdbserver_test_firmware_breakpoint_site")
    client.execute("continue", timeout=15.0)
    before = _read_transport_stream_state(client)
    client.execute(
        "set $gdb_e2e_sequence = gdbserver_test_firmware_mailbox.command_sequence + 1")
    client.execute("set var gdbserver_test_firmware_mailbox.command_argument = %d" %
                   _STREAM_MESSAGE_COUNT)
    client.execute("set var gdbserver_test_firmware_mailbox.command = %d" % int(command))
    client.execute(
        "set var gdbserver_test_firmware_mailbox.command_sequence = $gdb_e2e_sequence")
    client.execute("delete breakpoints")
    return before[0]


def _read_transport_stream_state(client: ExternalGDBSession) -> tuple[int, int, int, int, int]:
    """Read target transport-stream counters through a stopped Arm GDB session."""
    output = client.execute(
        "printf \"GDB-E2E stream=%u rtt=%u dropped=%u semihosting=%u failures=%u\\n\", "
        "gdbserver_test_firmware_mailbox.transport_stream_sequence, "
        "gdbserver_test_firmware_mailbox.transport_stream_rtt_messages, "
        "gdbserver_test_firmware_mailbox.transport_stream_rtt_dropped_bytes, "
        "gdbserver_test_firmware_mailbox.transport_stream_semihosting_messages, "
        "gdbserver_test_firmware_mailbox.transport_stream_semihosting_failures")
    match = re.search(
        r"GDB-E2E stream=(\d+) rtt=(\d+) dropped=(\d+) semihosting=(\d+) failures=(\d+)",
        output)
    assert match is not None, output
    return tuple(int(value) for value in match.groups())


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


def _assert_completed_stream(completed: tuple[int, int, int, int, int], final_sequence: int,
                             *, use_rtt: bool, use_semihosting: bool) -> None:
    """Require target counters to agree with the requested stream modes and frame count."""
    sequence, rtt_messages, rtt_dropped, semihosting_messages, semihosting_failures = completed
    assert sequence == final_sequence
    assert rtt_messages == (_STREAM_MESSAGE_COUNT if use_rtt else 0)
    assert rtt_dropped == 0
    assert semihosting_messages == (_STREAM_MESSAGE_COUNT if use_semihosting else 0)
    assert semihosting_failures == 0


def _assert_exact_stream_frames(captured: bytes, prefix: bytes, first: int, last: int) -> None:
    """Require every numbered, checksummed frame in the requested inclusive sequence range."""
    assert _stream_sequences(captured, prefix) == list(range(first, last + 1))


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
