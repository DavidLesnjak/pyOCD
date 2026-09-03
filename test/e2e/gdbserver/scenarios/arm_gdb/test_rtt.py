# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""RTT scenarios exercised through arm-none-eabi-gdb."""

import re

import pytest

from pyocd_server import PyOCDGDBServer
from pytest_plugin import ExternalGDB

from ._workflows import run_single_client_workflow


_FRAME_CHECK_XOR = 0xA5A5A5A5
_RTT_INPUT = b"arm-gdb-rtt-input"


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_symbol_discovery_transfers_output_and_input(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify bidirectional RTT data transfer while pyOCD discovers the SEGGER control
    block from the firmware ELF symbol and a real GDB controls execution.

    Test method:
    1. Start pyOCD in RTT symbol-discovery mode and connect a host TCP stream to its
       primary RTT channel before launching GDB.
    2. Send ``arm-gdb-rtt-input`` through that stream into the target down-buffer.
    3. Connect Arm GDB, synchronize with the mailbox firmware, and submit one RTT
       output command.
    4. Continue to completion and print the target's output sequence, consumed input
       byte count, and input checksum through GDB before detaching.
    5. Read the host RTT stream through frame 3 and validate frames 1, 2, and 3 for
       exact order, uniqueness, and the firmware's XOR checksum.
    6. Compare the target-reported input byte count and checksum with the exact bytes
       sent by the host.

    Expected result:
    Symbol discovery starts RTT, all three output frames arrive intact and ordered,
    and the firmware consumes every input byte with the expected checksum.

    Failure indicates:
    RTT symbol lookup, polling, TCP forwarding, target up/down-buffer handling,
    command execution, or stream integrity is broken.
    """
    output = run_single_client_workflow(
        "rtt-input-command", gdbserver_gdb, gdbserver_server,
        stream_port="rtt_port",
        stream_expected=_rtt_frame(3),
        stream_input=_RTT_INPUT,
        stream_validator=lambda captured: _assert_frame_range(captured, b"RTT:", 1, 3))
    input_state = re.search(r"input-bytes=(\d+) input-checksum=(\d+)", output)
    assert input_state is not None, output
    assert int(input_state.group(1)) == len(_RTT_INPUT), output
    assert int(input_state.group(2)) == sum(_RTT_INPUT), output


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(rtt_mode="symbol")
def test_rtt_burst_channel_preserves_high_rate_framed_output(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify that the secondary RTT channel preserves a bounded high-rate burst while
    standard GDB controls the target.

    Test method:
    1. Start RTT by ELF-symbol discovery and connect a host stream to the dedicated
       burst-channel TCP port.
    2. Connect Arm GDB, synchronize at the recurring breakpoint, and submit an RTT
       burst command requesting exactly 32 frames.
    3. Continue until the mailbox reports that command complete.
    4. Print the target's final burst sequence and dropped-byte count through GDB.
    5. Read through frame 32 and parse every captured ``RTTB`` frame.
    6. Require sequences 1 through 32 exactly once, in order, with valid checksums,
       and require the firmware drop counter to remain zero.

    Expected result:
    The host receives all 32 valid burst frames in sequence and neither the target
    nor the collector reports loss.

    Failure indicates:
    RTT burst buffering, channel selection, polling throughput, TCP collection, or
    target-side overflow accounting is broken.
    """
    run_single_client_workflow(
        "rtt-burst-command", gdbserver_gdb, gdbserver_server,
        stream_port="rtt_burst_port",
        stream_expected=_rtt_burst_frame(32),
        stream_validator=lambda captured: _assert_frame_range(captured, b"RTTB:", 1, 32))


@pytest.mark.gdbserver_external_gdb
@pytest.mark.gdbserver_config(rtt_mode="address")
def test_rtt_explicit_control_block_address_reconnects_stream(
        gdbserver_gdb: ExternalGDB,
        gdbserver_server: PyOCDGDBServer) -> None:
    """Purpose:
    Verify explicit-address RTT configuration and stream recovery across two
    independent host-stream and Arm GDB connections.

    Test method:
    1. Start pyOCD with the RTT control-block address resolved from the firmware
       symbol and connect the first host stream.
    2. Run a first Arm GDB session, submit one RTT command, and validate startup
       frame 1 followed by command frame 2 before closing both clients.
    3. Connect a new host stream to the same RTT TCP port.
    4. Run a separate Arm GDB process, resynchronize without restarting pyOCD, and
       submit a second RTT command.
    5. Read and validate frame 3 from the replacement stream, including checksum and
       sequence continuity, then detach the second GDB.
    6. Save each GDB run under a distinct artifact name so reconnect diagnostics are
       not overwritten.

    Expected result:
    Explicit-address RTT serves frames before and after stream/GDB reconnection, and
    the target sequence advances continuously from 1 through 3.

    Failure indicates:
    Explicit RTT address setup, server-side stream cleanup, later TCP acceptance,
    persistent target state, or external-GDB reconnect handling is broken.
    """
    run_single_client_workflow(
        "rtt-command", gdbserver_gdb, gdbserver_server,
        stream_port="rtt_port",
        stream_expected=_rtt_frame(2),
        stream_validator=lambda captured: _assert_frame_range(captured, b"RTT:", 1, 2),
        artifact_name="before-rtt-reconnect")
    run_single_client_workflow(
        "rtt-command", gdbserver_gdb, gdbserver_server,
        stream_port="rtt_port",
        stream_expected=_rtt_frame(3),
        stream_validator=lambda captured: _assert_frame_range(captured, b"RTT:", 3, 3),
        artifact_name="after-rtt-reconnect")


def _rtt_frame(sequence: int) -> bytes:
    """Build one low-rate frame emitted by the test firmware."""
    return _frame(b"RTT:", sequence)


def _rtt_burst_frame(sequence: int) -> bytes:
    """Build one high-rate frame emitted by the test firmware."""
    return _frame(b"RTTB:", sequence)


def _frame(prefix: bytes, sequence: int) -> bytes:
    checksum = (sequence ^ _FRAME_CHECK_XOR) & 0xffffffff
    return prefix + ("%08X:%08X\n" % (sequence, checksum)).encode("ascii")


def _assert_frame_range(captured: bytes, prefix: bytes, first: int, last: int) -> None:
    """Require complete, valid, ordered, and duplicate-free RTT frames."""
    sequences: list[int] = []
    for line in captured.splitlines():
        if not line.startswith(prefix):
            continue
        fields = line.split(b":")
        assert len(fields) == 3, "malformed RTT frame: %r" % line
        sequence = int(fields[1], 16)
        checksum = int(fields[2], 16)
        assert checksum == (sequence ^ _FRAME_CHECK_XOR), "bad RTT checksum: %r" % line
        if first <= sequence <= last:
            sequences.append(sequence)
    assert sequences == list(range(first, last + 1)), (
        "RTT frames were lost, duplicated, or reordered: %r" % sequences)
