# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Opt-in SWV/ITM capture scenario for B-U585I-IOT02A."""

from __future__ import annotations

import time

import pytest

from mailbox import FixtureMailboxClient, MailboxCommand, resolve_elf_symbol
from pyocd.trace.events import TraceEvent, TraceITMEvent
from pyocd.trace.sink import TraceEventSink
from pyocd.trace.swo import SWOParser
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient
from stream import TCPStreamClient


_CONSOLE_MESSAGE = b"pyOCD semihosting test firmware message\n"
_FRAME_CHECK_XOR = 0xA5A5A5A5


@pytest.mark.gdbserver_config(enable_semihosting=True, enable_swv=True)
def test_swv_raw_stream_captures_test_firmware_itm_data_with_semihosting(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that trace output and debugger-hosted console output can both work during one target run.
    Test method:
    1. Start pyOCD with SWV and its required semihosting service enabled.
    2. Connect controller and observer clients, then attach both raw SWV and telnet collectors before execution.
    3. Queue SEMIHOSTING_WRITE, continue, and require exact console bytes plus mailbox completion.
    4. Queue ITM_WRITE while still running and wait for its exact sequence-numbered mailbox result.
    5. Decode raw SWO packets into port-0 ITM bytes and require the matching sequence-and-checksum frame.
    6. Verify one new ITM message and one new console call, then interrupt with T02.
    Expected result: The raw stream contains expected port-0 ITM data while telnet receives console text.
    Failure indicates: Trace configuration conflicts with semihosting or loses test-firmware output.
    Skip: --gdbserver-swv and semihosting support are not both enabled.
    """
    assert gdbserver_server.configuration.enable_swv
    assert gdbserver_server.configuration.enable_semihosting
    assert gdbserver_server.configuration.swv_raw_port != 0

    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.telnet_port,
                    "swv-semihosting-console.bin") as console:
                with gdbserver_server.connect_stream(
                        gdbserver_server.configuration.swv_raw_port,
                        "swv-raw.bin") as raw_stream:
                    before = mailbox.read()
                    console_sequence = mailbox.request(MailboxCommand.SEMIHOSTING_WRITE)
                    controller.send_packet(b"c")
                    assert _CONSOLE_MESSAGE in console.read_until(_CONSOLE_MESSAGE)
                    console_completed = mailbox.wait_for_completion(console_sequence)
                    assert console_completed.semihosting_console_calls == (
                        before.semihosting_console_calls + 1)

                    itm_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
                    completed = mailbox.wait_for_completion(itm_sequence)
                    expected_frame = _fixture_itm_frame(completed.itm_sequence)
                    decoded_itm = _wait_for_itm_frame(raw_stream, expected_frame)
                    assert completed.itm_messages == before.itm_messages + 1
                    assert completed.itm_sequence == before.itm_sequence + 1
                    assert expected_frame in decoded_itm

                controller.interrupt()
                assert controller.receive_packet(timeout=5.0).startswith(b"T02")


@pytest.mark.gdbserver_config(enable_semihosting=True, enable_swv=True)
def test_swv_raw_stream_attaches_after_target_execution_begins(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a trace viewer can connect after the program is already running and still receive later output.
    Test method:
    1. Connect controller and observer clients but deliberately leave the raw SWV port unconnected.
    2. Continue the target and prove through mailbox loop count that execution began before the consumer existed.
    3. Attach the raw SWV TCP consumer while the target remains running.
    4. Queue ITM_WRITE and wait for the exact mailbox sequence and message count.
    5. Decode the expected sequence-and-checksum frame from the late consumer and interrupt with T02.
    Expected result: The late-attached stream captures the subsequent expected ITM message.
    Failure indicates: SWV capture requires connection before target execution or misses new trace data.
    Skip: --gdbserver-swv is not enabled.
    """
    assert gdbserver_server.configuration.enable_swv
    assert gdbserver_server.configuration.swv_raw_port != 0

    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            before_run = mailbox.read()
            controller.send_packet(b"c")
            running = mailbox.wait_for(
                lambda state: state.heartbeat != before_run.heartbeat,
                description="fixture execution before raw SWV client attachment")
            assert running.loop_count != before_run.loop_count

            # The trace consumer is intentionally connected only after the
            # target has demonstrated progress. The ITM command is submitted
            # afterwards, so no fixture output is intentionally lost before
            # this consumer is ready.
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.swv_raw_port,
                    "swv-raw-late-client.bin") as raw_stream:
                before_itm = mailbox.read()
                command_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
                completed = mailbox.wait_for_completion(command_sequence)
                expected_frame = _fixture_itm_frame(completed.itm_sequence)
                decoded_itm = _wait_for_itm_frame(raw_stream, expected_frame)

                assert completed.itm_messages == before_itm.itm_messages + 1
                assert completed.itm_sequence == before_itm.itm_sequence + 1
                assert expected_frame in decoded_itm

            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")


@pytest.mark.gdbserver_config(enable_semihosting=True, enable_swv=True)
def test_swv_raw_stream_drains_after_halt_and_controller_reconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that trace data is not lost when execution pauses and the debugger later reconnects.
    Test method:
    1. Connect controller, observer, and one raw SWV consumer and record ITM counters.
    2. Queue ITM_WRITE and continue, but do not read the raw socket before command completion.
    3. Interrupt with T02 and only then drain and decode the already-emitted frame.
    4. Close the controller while retaining the observer and original raw SWV socket.
    5. Connect a replacement controller, queue another ITM_WRITE, and require the next frame on the same stream.
    6. Verify consecutive target counters, additional raw bytes, and a final clean interrupt.
    Expected result: Both expected trace frames arrive on the original SWV stream.
    Failure indicates: Halt or RSP reconnect discards buffered trace or closes raw SWV.
    Skip: --gdbserver-swv is not enabled.
    """
    assert gdbserver_server.configuration.enable_swv
    assert gdbserver_server.configuration.swv_raw_port != 0

    controller = gdbserver_server.connect_rsp()
    observer = gdbserver_server.connect_rsp()
    try:
        mailbox = _mailbox(gdbserver_server, observer)
        with gdbserver_server.connect_stream(
                gdbserver_server.configuration.swv_raw_port,
                "swv-raw-halt-reconnect.bin") as raw_stream:
            before_halt = mailbox.read()
            halted_command_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
            controller.send_packet(b"c")
            halted_completed = mailbox.wait_for_completion(halted_command_sequence)
            halted_frame = _fixture_itm_frame(halted_completed.itm_sequence)

            # Do not read from the raw socket before the stop. The frame was
            # emitted while running, so finding it now verifies that pyOCD
            # continues to drain trace data after a deliberate halt.
            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            drained_itm = _wait_for_itm_frame(raw_stream, halted_frame)
            assert halted_completed.itm_messages == before_halt.itm_messages + 1
            assert halted_completed.itm_sequence == before_halt.itm_sequence + 1
            assert halted_frame in drained_itm

            # Retain the same raw trace socket while a controlling RSP client
            # disconnects and a replacement client resumes the fixture.
            controller.close()
            assert gdbserver_server.is_running
            with gdbserver_server.connect_rsp() as reconnected:
                before_reconnected = mailbox.read()
                reconnected_command_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
                stream_length_before_reconnect = len(raw_stream.received)
                reconnected.send_packet(b"c")
                reconnected_completed = mailbox.wait_for_completion(
                    reconnected_command_sequence)
                reconnected_frame = _fixture_itm_frame(
                    reconnected_completed.itm_sequence)
                decoded_itm = _wait_for_itm_frame(raw_stream, reconnected_frame)

                assert reconnected_completed.itm_messages == (
                    before_reconnected.itm_messages + 1)
                assert reconnected_completed.itm_sequence == (
                    before_reconnected.itm_sequence + 1)
                assert len(raw_stream.received) > stream_length_before_reconnect
                assert reconnected_frame in decoded_itm

                reconnected.interrupt()
                assert reconnected.receive_packet(timeout=5.0).startswith(b"T02")
    finally:
        controller.close()
        observer.close()


@pytest.mark.gdbserver_config(enable_semihosting=True, enable_swv=True)
def test_swv_raw_stream_captures_itm_without_a_gdb_client(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that pyOCD keeps collecting and forwarding ITM data after the final GDB client detaches.
    Test method:
    1. Connect one RSP controller and the raw SWV stream, then locate the initialized mailbox.
    2. Queue an ITM_WRITE command while the controller still has the target halted.
    3. Detach the only RSP client so persistent gdbserver resumes the target with no GDB client present.
    4. Decode the raw stream and wait for the exact sequence-numbered ITM frame.
    5. Reconnect a verifier, halt the target, and confirm that the queued mailbox command completed.
    Expected result: The ITM frame is valid and the command completes while no GDB client is attached.
    Failure indicates: SWV servicing incorrectly depends on an active GDB client or final detach closes the trace stream.
    Skip: --gdbserver-swv is not enabled.
    """
    controller = gdbserver_server.connect_rsp()
    try:
        mailbox = _mailbox(gdbserver_server, controller)
        with gdbserver_server.connect_stream(
                gdbserver_server.configuration.swv_raw_port,
                "swv-raw-no-gdb.bin") as raw_stream:
            before = mailbox.read()
            command_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
            expected_frame = _fixture_itm_frame(before.itm_sequence + 1)
            controller.detach()
            controller.close()

            decoded_itm = _wait_for_itm_frame(raw_stream, expected_frame)
            assert expected_frame in decoded_itm
            assert gdbserver_server.is_running

            with gdbserver_server.connect_rsp() as verifier:
                mailbox = _mailbox(gdbserver_server, verifier)
                completed = mailbox.wait_for_completion(command_sequence)
                assert completed.itm_sequence == before.itm_sequence + 1
    finally:
        controller.close()


@pytest.mark.gdbserver_config(enable_semihosting=True, enable_swv=True)
def test_swv_raw_consumer_disconnects_and_reconnects(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that closing one raw SWV consumer does not prevent a later consumer from receiving new ITM data.
    Test method:
    1. Connect controller and observer RSP clients and attach the first raw SWV consumer.
    2. Queue one ITM_WRITE command, continue, and validate its exact frame on the first consumer.
    3. Halt the target and close the first raw stream connection.
    4. Attach a second raw SWV consumer, queue another ITM_WRITE command, and continue again.
    5. Validate that the second consumer receives the next sequence-numbered frame, then halt cleanly.
    Expected result: Both consumers receive their own valid frame and the second sequence follows the first.
    Failure indicates: SWV consumer cleanup terminates the server endpoint or leaves stale decoder state behind.
    Skip: --gdbserver-swv is not enabled.
    """
    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.swv_raw_port,
                    "swv-raw-consumer-1.bin") as first_stream:
                first_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
                controller.send_packet(b"c")
                first_completed = mailbox.wait_for_completion(first_sequence)
                first_frame = _fixture_itm_frame(first_completed.itm_sequence)
                assert first_frame in _wait_for_itm_frame(first_stream, first_frame)
                controller.interrupt()
                assert controller.receive_packet(timeout=5.0).startswith(b"T02")

            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.swv_raw_port,
                    "swv-raw-consumer-2.bin") as second_stream:
                second_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
                controller.send_packet(b"c")
                second_completed = mailbox.wait_for_completion(second_sequence)
                second_frame = _fixture_itm_frame(second_completed.itm_sequence)
                assert second_frame in _wait_for_itm_frame(second_stream, second_frame)
                assert second_completed.itm_sequence == first_completed.itm_sequence + 1
                controller.interrupt()
                assert controller.receive_packet(timeout=5.0).startswith(b"T02")


@pytest.mark.gdbserver_config(
    enable_semihosting=True,
    enable_swv=True,
    swv_clock=1500000)
def test_swv_incorrect_clock_does_not_decode_a_valid_itm_frame(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a deliberately incorrect SWO baud rate is not mistaken for valid test firmware trace data.
    Test method:
    1. Start SWV with a 1.5 MHz decoder clock while the test firmware emits at its configured 2 MHz rate.
    2. Connect controller, observer, and raw SWV clients and record the next expected ITM frame.
    3. Queue ITM_WRITE, continue until the mailbox command completes, and halt the target.
    4. Collect raw bytes for a bounded interval and decode all bytes as port-0 ITM events.
    5. Assert that the exact sequence-and-checksum frame is absent from the incorrectly decoded stream.
    Expected result: The mailbox command completes, but the wrong clock never produces the exact valid ITM frame.
    Failure indicates: The negative clock test cannot distinguish invalid trace configuration from valid SWV output.
    Skip: --gdbserver-swv is not enabled.
    """
    assert gdbserver_server.configuration.swv_clock == 1500000
    with gdbserver_server.connect_rsp() as controller:
        with gdbserver_server.connect_rsp() as observer:
            mailbox = _mailbox(gdbserver_server, observer)
            with gdbserver_server.connect_stream(
                    gdbserver_server.configuration.swv_raw_port,
                    "swv-raw-wrong-clock.bin") as raw_stream:
                before = mailbox.read()
                command_sequence = mailbox.request(MailboxCommand.ITM_WRITE)
                expected_frame = _fixture_itm_frame(before.itm_sequence + 1)
                controller.send_packet(b"c")
                completed = mailbox.wait_for_completion(command_sequence)
                controller.interrupt()
                assert controller.receive_packet(timeout=5.0).startswith(b"T02")
                assert completed.itm_sequence == before.itm_sequence + 1

                _collect_swv_for(raw_stream, timeout=1.0)
                assert expected_frame not in _decode_itm_port_zero(raw_stream.received)


def _mailbox(server: PyOCDGDBServer, client: RSPClient) -> FixtureMailboxClient:
    """Construct a ready mailbox client for a manually managed RSP connection."""
    address = resolve_elf_symbol(server.configuration.firmware, "gdbserver_test_firmware_mailbox")
    mailbox = FixtureMailboxClient(client, address)
    mailbox.wait_until_ready()
    return mailbox


def _wait_for_itm_frame(stream: TCPStreamClient, expected_frame: bytes,
                        timeout: float = 5.0) -> bytes:
    """Decode the raw SWO stream until it contains one complete fixture frame."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        decoded = _decode_itm_port_zero(stream.received)
        if expected_frame in decoded:
            return decoded
        stream.read_available(timeout=min(0.200, max(0.001, deadline - time.monotonic())))
    raise AssertionError(
        "SWV raw stream did not decode the expected ITM frame within %.1f seconds: %r" %
        (timeout, expected_frame))


def _collect_swv_for(stream: TCPStreamClient, timeout: float) -> bytes:
    """Collect all raw SWV bytes available during a bounded interval."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stream.read_available(timeout=min(0.100, max(0.001, deadline - time.monotonic())))
    return stream.received


def _fixture_itm_frame(sequence: int) -> bytes:
    """Return the framed port-zero ITM message written by the fixture."""
    checksum = (sequence ^ _FRAME_CHECK_XOR) & 0xffffffff
    return ("ITM:%08X:%08X\n" % (sequence, checksum)).encode("ascii")


def _decode_itm_port_zero(raw_data: bytes) -> bytes:
    """Decode port-zero instrumentation bytes from a captured raw SWO stream."""
    collector = _PortZeroITMCollector()
    parser = SWOParser(_TraceCore(), collector)
    parser.parse(raw_data)
    # The parser keeps untimestamped instrumentation events pending. An
    # overflow packet flushes them through its public parser interface without
    # changing the recorded raw capture.
    parser.parse(b"\x70")
    return collector.data


class _TraceCore:
    """Provide the one core API SWOParser may need for non-ITM packets."""

    def exception_number_to_name(self, exception_number: int) -> None:
        """Ignore names for unrelated hardware trace packets in this raw capture."""
        del exception_number
        return None


class _PortZeroITMCollector(TraceEventSink):
    """Collect decoded port-zero ITM payload bytes in stream order."""

    def __init__(self) -> None:
        self._data = bytearray()

    @property
    def data(self) -> bytes:
        """Return the collected payload bytes."""
        return bytes(self._data)

    def receive(self, event: TraceEvent) -> None:
        """Keep only port-zero instrumentation events."""
        if isinstance(event, TraceITMEvent) and event.port == 0:
            self._data.extend(event.data.to_bytes(event.width, byteorder="little"))
