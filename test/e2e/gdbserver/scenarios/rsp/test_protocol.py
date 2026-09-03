# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""RSP query, memory, and register scenarios for the B-U585I-IOT02A fixture."""

import pytest

from mailbox import FixtureMailboxClient, resolve_elf_symbol
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient


def test_queries_memory_and_register_write_protocol(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check the basic debugger protocol promises: target information, memory access, register access, and clear errors for invalid requests.
    Test method:
    1. Save the test-owned RAM bytes and r0 value so every destructive protocol check can be reversed.
    2. Query qSupported, qC, thread liveness, vCont actions, and the current stop reply.
    3. Round-trip an ASCII M write and an escaped binary X write through the mailbox RAM window.
    4. Change r0 with P0 and verify the value through the complete g register block.
    5. Resolve and read a known immutable flash pattern from the selected ELF image.
    6. Transfer and validate target, memory-map, and thread XML, then require E00 for an unknown feature annex.
    7. Send an invalid monitor command and require a textual error without losing the session.
    8. Restore RAM and r0 in finally cleanup, negotiate no-ack mode, and prove qC still returns QC1.
    Expected result: Advertised features work, valid data round-trips, invalid requests return stated errors,
    and qC returns QC1 before and after no-ack negotiation.
    Failure indicates: An advertised protocol feature is malformed, inaccessible, unsafe, or inconsistent.
    """
    ram_window_address = fixture_mailbox.ram_window_address
    original_window = raw_rsp_client.read_memory(ram_window_address, 17)
    original_register_zero = raw_rsp_client.read_registers()[:4]
    assert len(original_register_zero) == 4

    try:
        supported = raw_rsp_client.command(b"qSupported:PacketSize=4000")
        assert b"QStartNoAckMode+" in supported
        assert b"QNonStop+" in supported
        assert b"qXfer:features:read+" in supported
        assert b"qXfer:memory-map:read+" in supported
        assert raw_rsp_client.command(b"qC") == b"QC1"
        assert raw_rsp_client.command(b"T1") == b"OK"
        assert raw_rsp_client.command_response(b"T2") == b"E00"
        assert raw_rsp_client.command(b"vCont?") == b"vCont;c;C;s;S;r;t"
        assert raw_rsp_client.command(b"?").startswith(b"T")

        raw_rsp_client.write_memory(ram_window_address, b"M-write-safe-test")
        assert (raw_rsp_client.read_memory(ram_window_address, 17) ==
                b"M-write-safe-test")
        raw_rsp_client.write_memory_binary(ram_window_address, b"#$}*")
        assert raw_rsp_client.read_memory(ram_window_address, 4) == b"#$}*"

        changed_register_zero = bytes(
            value ^ 0xA5 for value in original_register_zero)
        raw_rsp_client.write_register(0, changed_register_zero)
        assert raw_rsp_client.read_registers()[:4] == changed_register_zero

        flash_window_address = resolve_elf_symbol(
            gdbserver_server.configuration.firmware,
            "gdbserver_test_firmware_flash_window")
        assert (raw_rsp_client.read_memory(flash_window_address, 16) ==
                bytes(range(0, 256, 17)))

        target_xml = raw_rsp_client.read_xfer("features", "target.xml")
        memory_map_xml = raw_rsp_client.read_xfer("memory-map", "")
        threads_xml = raw_rsp_client.read_xfer("threads", "")
        assert b"<target>" in target_xml
        assert b'name="r0"' in target_xml
        assert b"<memory-map>" in memory_map_xml
        assert b"type=\"flash\"" in memory_map_xml
        assert b"<threads>" in threads_xml
        assert raw_rsp_client.command_response(
            b"qXfer:features:read:not-target.xml:0,10") == b"E00"

        monitor_output = raw_rsp_client.monitor("this-command-does-not-exist")
        assert "Error:" in monitor_output
    finally:
        raw_rsp_client.write_memory(ram_window_address, original_window)
        raw_rsp_client.write_register(0, original_register_zero)

    raw_rsp_client.enable_no_ack_mode()
    assert raw_rsp_client.command(b"qC") == b"QC1"


@pytest.mark.xfail(
    strict=True,
    reason=("pyOCD currently forwards the p register number as bytes instead "
            "of parsing it"))
def test_single_register_read_is_an_explicit_pyocd_regression(
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Guard against a regression where reading one CPU register through the debugger protocol returns the wrong value.
    Test method:
    1. Read r0 alone with the RSP p0 request.
    2. Read the complete register block with g and extract its first four bytes.
    3. Compare the two little-endian values exactly so packet parsing differences cannot be hidden.
    Expected result: This is currently a strict expected failure because p0 is known to be broken.
    Failure indicates: An unexpected pass means the regression was fixed and this test must be converted to normal.
    """
    assert (raw_rsp_client.read_register(0) ==
            raw_rsp_client.read_registers()[:4])
