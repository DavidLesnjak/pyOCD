# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Hardware-breakpoint capacity scenario for the B-U585I-IOT02A fixture."""

from __future__ import annotations

import pytest

from mailbox import FixtureMailboxClient, MailboxCommand, resolve_elf_symbol
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient, RSPError


_FPB_CONTROL_ADDRESS = 0xE0002000
_BREAKPOINT_CATALOG_SYMBOLS = tuple(
    "gdbserver_test_firmware_breakpoint_catalog_%02d" % index
    for index in range(24))


def test_hardware_breakpoint_capacity_reports_exhaustion_and_recovers(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check that the debugger reports the board's finite hardware-breakpoint capacity and frees every slot again.
    Test method:
    1. Read FPB_CTRL directly and derive the number of hardware breakpoint comparators advertised by the core.
    2. Resolve the dedicated test firmware breakpoint catalog and queue the command that executes every catalog entry.
    3. Insert one Z1 breakpoint per catalog address until pyOCD rejects the first request beyond capacity.
    4. Require the accepted count to equal FPB_CTRL and the exhaustion response to be E01.
    5. Continue, require T05, and verify that PC lies at the first catalog function rather than an unrelated stop.
    6. Remove every accepted breakpoint, resume the catalog command, and verify exact mailbox completion.
    7. On any failure, make a bounded best-effort attempt to remove every still-tracked breakpoint.
    Expected result: Exactly the reported slot count installs, the next request returns E01, the stop is
    T05 at the first catalog entry, and the command completes after cleanup.
    Failure indicates: FPB capacity accounting, exhaustion signaling, breakpoint location, or cleanup fails.
    Skip: The target reports no hardware breakpoints or the firmware does not expose enough distinct code sites.
    """
    breakpoint_count = _reported_hardware_breakpoint_count(raw_rsp_client)
    if breakpoint_count == 0:
        pytest.skip("target reports no hardware breakpoint comparators")
    if breakpoint_count >= len(_BREAKPOINT_CATALOG_SYMBOLS):
        pytest.skip(
            "fixture has %d catalog locations but target reports %d hardware breakpoints" %
            (len(_BREAKPOINT_CATALOG_SYMBOLS), breakpoint_count))

    breakpoint_addresses = [
        resolve_elf_symbol(gdbserver_server.configuration.firmware, symbol) & ~1
        for symbol in _BREAKPOINT_CATALOG_SYMBOLS
    ]
    installed: list[int] = []

    with gdbserver_server.connect_rsp() as observer:
        observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
        command_sequence = fixture_mailbox.request(MailboxCommand.BREAKPOINT_CATALOG)
        try:
            exhaustion_response = None
            for address in breakpoint_addresses:
                response = raw_rsp_client.command_response(
                    _breakpoint_packet(b"Z1", address))
                if response == b"OK":
                    installed.append(address)
                    continue
                exhaustion_response = response
                break

            assert len(installed) == breakpoint_count
            assert exhaustion_response == b"E01"

            raw_rsp_client.send_packet(b"c")
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T05")
            program_counter = _program_counter(raw_rsp_client)
            assert breakpoint_addresses[0] <= program_counter < breakpoint_addresses[0] + 16

            _remove_breakpoints(raw_rsp_client, installed)
            raw_rsp_client.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(command_sequence)
            assert completed.completed_sequence == command_sequence
        finally:
            _remove_breakpoints(raw_rsp_client, installed, best_effort=True)


def _reported_hardware_breakpoint_count(client: RSPClient) -> int:
    """Read the target FPB comparator count from its standard control register."""
    control = int.from_bytes(
        client.read_memory(_FPB_CONTROL_ADDRESS, 4), byteorder="little")
    return ((control >> 8) & 0x70) | ((control >> 4) & 0xF)


def _breakpoint_packet(kind: bytes, address: int) -> bytes:
    """Encode a two-byte hardware-breakpoint insertion or removal packet."""
    return kind + (",%x,2" % address).encode("ascii")


def _remove_breakpoints(client: RSPClient, installed: list[int],
                        best_effort: bool = False) -> None:
    """Remove every tracked breakpoint, retaining unremoved entries on failure."""
    while installed:
        address = installed[-1]
        try:
            response = client.command_response(_breakpoint_packet(b"z1", address), timeout=2.0)
            assert response == b"OK"
        except (AssertionError, RSPError):
            if best_effort:
                return
            raise
        installed.pop()


def _program_counter(client: RSPClient) -> int:
    """Extract the Cortex-M PC from the standard GDB register block."""
    registers = client.read_registers()
    program_counter_offset = 15 * 4
    assert len(registers) >= program_counter_offset + 4
    return int.from_bytes(
        registers[program_counter_offset:program_counter_offset + 4],
        byteorder="little")
