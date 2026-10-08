# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Trace capture and flush exercised through arm-none-eabi-gdb."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
import time
from typing import Iterator

import pytest

from mailbox import MailboxCommand, resolve_elf_symbol
from pyocd.trace.swo import SWOParser
from pyocd.trace.swv import SWVEventSink
from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB, _configuration_for_test


_FRAME_CHECK_XOR = 0xA5A5A5A5


@pytest.fixture
def _trace_file_server(request: pytest.FixtureRequest) -> Iterator[tuple[PyOCDGDBServer, Path]]:
    """Start one SWV server with its raw output in the scenario's artifact directory."""
    configuration = _configuration_for_test(request)
    trace_file = configuration.artifacts.directory / "arm-gdb-trace.raw"
    configuration.session_options = {
        **configuration.session_options,
        "swv_raw_file": str(trace_file),
    }
    with PyOCDGDBServer(configuration) as server:
        yield server, trace_file


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_swv=True)
@pytest.mark.parametrize("non_stop", (False, True), ids=("all-stop", "non-stop"))
def test_trace_file_captures_and_flushes_each_gdb_run(
        non_stop: bool,
        gdbserver_gdb: ExternalGDB,
        _trace_file_server: tuple[PyOCDGDBServer, Path]) -> None:
    """Purpose:
    Verify that trace from each GDB-controlled run is available in the raw SWV
    file as soon as GDB reports the following breakpoint stop, in both stop modes.

    Test method:
    1. Start SWV with a raw file sink, connect Arm GDB/MI in the selected stop
       mode, and synchronize at the fixture's recurring breakpoint.
    2. Queue one ITM_WRITE through GDB, continue to the command-completion
       hardware breakpoint, and read the trace file only after the stop.
    3. Check the target's completion and ITM counters and decode the exact
       sequence-numbered ITM frame from the file.
    4. Queue a second ITM_WRITE, continue from the same breakpoint, and require
       both frames exactly once in the file after the second stop.

    Expected result:
    Each run adds one valid ITM frame, readable immediately after its stop.

    Failure indicates:
    Trace capture did not open or reopen the file, trace flush did not publish
    buffered bytes at the stop, or SWV data was lost.

    Skip: --gdbserver-swv is not enabled; enabled runs also require explicit
    system and SWO clocks.
    """
    server, trace_file = _trace_file_server
    assert server.configuration.enable_swv

    with gdbserver_gdb.start_mi(server, "trace-capture-flush", non_stop=non_stop) as client:
        client.console("break gdbserver_test_firmware_breakpoint_site")
        client.continue_execution()
        synchronized = client.wait_for_stop(timeout=15.0)
        assert 'reason="breakpoint-hit"' in synchronized, synchronized
        client.console("delete breakpoints")
        client.console("hbreak gdbserver_test_firmware_command_completion_site")

        initial_itm_sequence = client.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_sequence")
        initial_itm_messages = client.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_messages")

        for run_index in range(2):
            command_sequence = client.evaluate_unsigned("gdbserver_test_firmware_mailbox.command_sequence") + 1
            client.console("set var gdbserver_test_firmware_mailbox.command = %d" % int(MailboxCommand.ITM_WRITE))
            client.console("set var gdbserver_test_firmware_mailbox.command_sequence = %d" % command_sequence)
            client.continue_execution()
            stopped = client.wait_for_stop(timeout=15.0)
            assert 'reason="breakpoint-hit"' in stopped, stopped

            assert client.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") == command_sequence
            assert client.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_sequence") == initial_itm_sequence + run_index + 1
            assert client.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_messages") == initial_itm_messages + run_index + 1
            assert trace_file.is_file(), "trace capture did not create the raw SWV file"

            decoded = _decode_itm_port_zero(trace_file.read_bytes())
            for sequence in range(initial_itm_sequence + 1, initial_itm_sequence + run_index + 2):
                frame = _fixture_itm_frame(sequence)
                assert decoded.count(frame) == 1, (frame, decoded)

        client.console("delete breakpoints")
        client.detach()


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(enable_swv=True)
def test_trace_file_flushes_clientless_breakpoint_before_gdb_reconnect(
        gdbserver_gdb: ExternalGDB,
        _trace_file_server: tuple[PyOCDGDBServer, Path]) -> None:
    """Purpose:
    Verify that a run started after the final GDB disconnect still captures SWV
    and that the service thread flushes its trace at a clientless breakpoint.

    Test method:
    1. Connect Arm GDB, synchronize with the firmware, and use ``monitor break``
       to install a pyOCD-owned breakpoint at command completion.
    2. Queue ITM_WRITE while halted, then terminate the only GDB process so the
       server resumes the target after its socket closes.
    3. Require the exact ITM frame in the raw trace file before any GDB client
       reconnects.
    4. Reconnect after the file is flushed, require the completion PC and target
       counters, remove the monitor breakpoint, and detach.

    Expected result:
    The clientless run produces one valid frame, and the service thread makes it
    readable at the command-completion halt before GDB reconnects.

    Failure indicates:
    Final-disconnect resume, clientless state polling, trace capture or flush,
    or pyOCD-owned breakpoint handling is broken.

    Skip: --gdbserver-swv is not enabled; enabled runs also require explicit
    system and SWO clocks.
    """
    server, trace_file = _trace_file_server
    completion_address = resolve_elf_symbol(
        server.configuration.firmware, "gdbserver_test_firmware_command_completion_site") & ~1

    with gdbserver_gdb.start_mi(server, "trace-clientless-controller") as controller:
        controller.console("break gdbserver_test_firmware_breakpoint_site")
        controller.continue_execution()
        synchronized = controller.wait_for_stop(timeout=15.0)
        assert 'reason="breakpoint-hit"' in synchronized, synchronized
        controller.console("delete breakpoints")

        installed = controller.console("monitor break 0x%08x" % completion_address)
        assert "Set breakpoint at 0x%08x" % completion_address in installed, installed
        initial_itm_sequence = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_sequence")
        initial_itm_messages = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_messages")
        command_sequence = controller.evaluate_unsigned("gdbserver_test_firmware_mailbox.command_sequence") + 1
        controller.console("set var gdbserver_test_firmware_mailbox.command = %d" % int(MailboxCommand.ITM_WRITE))
        controller.console("set var gdbserver_test_firmware_mailbox.command_sequence = %d" % command_sequence)
        controller.terminate()

    expected_frame = _fixture_itm_frame(initial_itm_sequence + 1)
    _wait_for_trace_frame(trace_file, expected_frame)
    assert server.is_running

    with gdbserver_gdb.start_mi(server, "trace-clientless-verifier") as verifier:
        assert verifier.evaluate_unsigned("(unsigned int)$pc") & ~1 == completion_address
        assert verifier.evaluate_unsigned("gdbserver_test_firmware_mailbox.completed_sequence") == command_sequence
        assert verifier.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_sequence") == initial_itm_sequence + 1
        assert verifier.evaluate_unsigned("gdbserver_test_firmware_mailbox.itm_messages") == initial_itm_messages + 1
        removed = verifier.console("monitor rmbreak 0x%08x" % completion_address)
        assert "Removed breakpoint at 0x%08x" % completion_address in removed, removed
        verifier.detach()


def _fixture_itm_frame(sequence: int) -> bytes:
    """Return the exact port-zero ITM frame emitted by the test firmware."""
    checksum = (sequence ^ _FRAME_CHECK_XOR) & 0xffffffff
    return ("ITM:%08X:%08X\n" % (sequence, checksum)).encode("ascii")


def _decode_itm_port_zero(raw_data: bytes) -> bytes:
    """Decode port-zero text from the raw SWO file, including its final event."""
    output = StringIO()
    parser = SWOParser(_TraceCore(), SWVEventSink(output))
    parser.parse(raw_data)
    parser.parse(b"\x70")
    return output.getvalue().encode("latin-1")


def _wait_for_trace_frame(trace_file: Path, expected_frame: bytes, timeout: float = 5.0) -> None:
    """Wait for a short clientless ITM frame to become readable after flush."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if trace_file.is_file():
            decoded = _decode_itm_port_zero(trace_file.read_bytes())
            if decoded.count(expected_frame) == 1:
                return
        time.sleep(0.020)
    raise AssertionError("clientless trace frame was not flushed before GDB reconnect: %r" % expected_frame)


class _TraceCore:
    """Provide the core API the SWO parser may need for unrelated packets."""

    def exception_number_to_name(self, exception_number: int) -> None:
        del exception_number
        return None
