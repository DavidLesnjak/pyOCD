# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Initial hardware-breakpoint scenario for the B-U585I-IOT02A."""

from mailbox import resolve_elf_symbol
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient


def test_hardware_breakpoint_stops_the_test_firmware(gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that the debugger can pause the running test firmware at a chosen instruction without changing its code.
    Test method:
    1. Resolve the test firmware breakpoint-site address from the selected ELF and clear its Thumb bit.
    2. Connect one raw-RSP client and insert a two-byte hardware breakpoint with Z1.
    3. Continue execution and wait for a bounded T05 SIGTRAP stop reply.
    4. Remove the same breakpoint with z1 and require pyOCD to acknowledge the cleanup.
    Expected result: Z1 and z1 return OK and continue returns a T05 SIGTRAP stop packet.
    Failure indicates: Hardware-breakpoint insertion, stop delivery, or removal is incorrect.
    """
    breakpoint_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_breakpoint_site") & ~1
    insert_packet = ("Z1,%x,2" % breakpoint_address).encode("ascii")
    remove_packet = ("z1,%x,2" % breakpoint_address).encode("ascii")

    with gdbserver_server.connect_rsp() as client:
        assert client.command(insert_packet) == b"OK"
        client.send_packet(b"c")
        assert client.receive_packet(timeout=5.0).startswith(b"T05")
        assert client.command(remove_packet) == b"OK"
