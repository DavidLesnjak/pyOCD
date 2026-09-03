# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Driver for the deterministic gdbserver fixture RAM mailbox."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
import struct
import time
from typing import TYPE_CHECKING, Callable

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

if TYPE_CHECKING:
    from rsp import RSPClient


FIXTURE_MAGIC = 0x47444253
FIXTURE_ABI_VERSION = 1
MAILBOX_HEADER_FORMAT = "<46I"
MAILBOX_HEADER_SIZE = struct.calcsize(MAILBOX_HEADER_FORMAT)
MAILBOX_RAM_WINDOW_SIZE = 256
MAILBOX_SIZE = MAILBOX_HEADER_SIZE + MAILBOX_RAM_WINDOW_SIZE

COMMAND_OFFSET = 5 * 4
COMMAND_SEQUENCE_OFFSET = 6 * 4
COMMAND_ARGUMENT_OFFSET = 9 * 4
SPIN_RELEASE_SEQUENCE_OFFSET = 36 * 4
WATCHPOINT_VALUE_OFFSET = 38 * 4
RAM_WINDOW_OFFSET = MAILBOX_HEADER_SIZE


class MailboxCommand(IntEnum):
    """Commands defined by ``gdbserver_test_firmware_command_t``."""

    NONE = 0
    RTT_WRITE = 1
    ITM_WRITE = 2
    SEMIHOSTING_WRITE = 3
    LITERAL_BKPT = 4
    WFI = 5
    HARDFAULT = 6
    SYSTEM_RESET = 7
    SPIN = 8
    STEP = 9
    RTT_BURST = 10
    SEMIHOSTING_FILE_WRITE = 11
    WATCHPOINT_READ = 12
    WATCHPOINT_WRITE = 13
    RAM_EXECUTE = 14
    BREAKPOINT_CATALOG = 15
    TRANSPORT_STREAM_RTT = 16
    TRANSPORT_STREAM_SEMIHOSTING = 17
    TRANSPORT_STREAM_BOTH = 18


class MailboxResult(IntEnum):
    """Results defined by ``gdbserver_test_firmware_result_t``."""

    IDLE = 0
    IN_PROGRESS = 1
    COMPLETE = 2


class MailboxCommandState(IntEnum):
    """Execution states defined by ``gdbserver_test_firmware_command_state_t``."""

    IDLE = 0
    EXECUTING = 1
    WAITING = 2
    COMPLETE = 3


class MailboxSpinState(IntEnum):
    """States defined by ``gdbserver_test_firmware_spin_state_t``."""

    IDLE = 0
    RUNNING = 1
    RELEASED = 2


class MailboxWFIState(IntEnum):
    """States defined by ``gdbserver_test_firmware_wfi_state_t``."""

    IDLE = 0
    PREPARED = 1
    ENTERED = 2
    RESUMED = 3


class FixtureMailboxError(RuntimeError):
    """Base error for interactions with the fixture mailbox."""


class FixtureMailboxTimeoutError(FixtureMailboxError):
    """Raised when the fixture does not reach an expected mailbox state."""


@dataclass(frozen=True)
class FixtureMailbox:
    """Decoded representation of ``gdbserver_test_firmware_mailbox_t``."""

    magic: int
    abi_version: int
    boot_epoch: int
    heartbeat: int
    loop_count: int
    command: int
    command_sequence: int
    completed_sequence: int
    result: int
    command_argument: int
    command_state: int
    rtt_messages: int
    rtt_sequence: int
    rtt_input_bytes: int
    rtt_input_checksum: int
    rtt_dropped_bytes: int
    rtt_burst_messages: int
    rtt_burst_sequence: int
    rtt_burst_dropped_bytes: int
    itm_messages: int
    itm_sequence: int
    semihosting_console_calls: int
    semihosting_file_calls: int
    semihosting_open_result: int
    semihosting_write_remaining: int
    semihosting_close_result: int
    semihosting_errno: int
    literal_bkpt_calls: int
    wfi_calls: int
    wfi_state: int
    wfi_wake_count: int
    wfi_wake_irq: int
    hardfault_calls: int
    system_reset_calls: int
    spin_iterations: int
    spin_state: int
    spin_release_sequence: int
    step_result: int
    watchpoint_value: int
    watchpoint_reads: int
    watchpoint_writes: int
    transport_stream_sequence: int
    transport_stream_rtt_messages: int
    transport_stream_rtt_dropped_bytes: int
    transport_stream_semihosting_messages: int
    transport_stream_semihosting_failures: int
    ram_window: bytes

    @classmethod
    def from_bytes(cls, data: bytes) -> "FixtureMailbox":
        """Decode an exact mailbox image read from target memory."""
        if len(data) != MAILBOX_SIZE:
            raise FixtureMailboxError(
                "mailbox must be %d bytes, got %d" % (MAILBOX_SIZE, len(data)))
        return cls(*struct.unpack_from(MAILBOX_HEADER_FORMAT, data), data[MAILBOX_HEADER_SIZE:])

    @property
    def is_ready(self) -> bool:
        """Whether the mailbox belongs to the expected fixture ABI."""
        return self.magic == FIXTURE_MAGIC and self.abi_version == FIXTURE_ABI_VERSION

    def is_reset_ready(self, expected_boot_epoch: int) -> bool:
        """Whether an expected reset generation has published its idle mailbox state."""
        return (
            self.is_ready and
            self.boot_epoch == expected_boot_epoch and
            self.command == MailboxCommand.NONE and
            self.command_sequence == 0 and
            self.completed_sequence == 0 and
            self.result == MailboxResult.IDLE and
            self.command_state == MailboxCommandState.IDLE and
            self.spin_release_sequence == 0)

    @property
    def semihosting_open_result_signed(self) -> int:
        """The signed return value from the most recent SYS_OPEN request."""
        return _signed_32(self.semihosting_open_result)

    @property
    def semihosting_write_remaining_signed(self) -> int:
        """The signed return value from the most recent SYS_WRITE request."""
        return _signed_32(self.semihosting_write_remaining)

    @property
    def semihosting_close_result_signed(self) -> int:
        """The signed return value from the most recent SYS_CLOSE request."""
        return _signed_32(self.semihosting_close_result)


class FixtureMailboxClient:
    """Issue ordered fixture commands through a connected RSP client."""

    def __init__(self, rsp_client: "RSPClient", address: int) -> None:
        self._rsp_client = rsp_client
        self.address = address

    @property
    def ram_window_address(self) -> int:
        """Address of the fixture-owned RAM window reserved for safe test data."""
        return self.address + RAM_WINDOW_OFFSET

    def read(self, timeout: float = 5.0) -> FixtureMailbox:
        """Read and decode the complete mailbox."""
        return FixtureMailbox.from_bytes(self._rsp_client.read_memory(self.address, MAILBOX_SIZE, timeout))

    def wait_until_ready(self, timeout: float = 5.0, poll_interval: float = 0.050) -> FixtureMailbox:
        """Wait for the fully published fixture ABI after flashing or initial startup."""
        deadline = time.monotonic() + timeout
        last_mailbox = None
        while time.monotonic() < deadline:
            last_mailbox = self.read(timeout=self._remaining_timeout(deadline))
            if last_mailbox.is_ready:
                return last_mailbox
            time.sleep(min(poll_interval, self._remaining_timeout(deadline)))

        if last_mailbox is None:
            raise FixtureMailboxTimeoutError("could not read the fixture mailbox")
        raise FixtureMailboxTimeoutError(
            "fixture mailbox did not initialize: magic=0x%08x abi=%d" %
            (last_mailbox.magic, last_mailbox.abi_version))

    def wait_for_reset(self, expected_boot_epoch: int, timeout: float = 5.0,
                       poll_interval: float = 0.050) -> FixtureMailbox:
        """Wait for a reset to publish its expected generation and idle command state."""
        if not 0 <= expected_boot_epoch <= 0xffffffff:
            raise ValueError("expected boot epoch must be an unsigned 32-bit value")
        return self.wait_for(
            lambda mailbox: mailbox.is_reset_ready(expected_boot_epoch),
            description="fixture reset to boot epoch %d" % expected_boot_epoch,
            timeout=timeout,
            poll_interval=poll_interval)

    def request(self, command: MailboxCommand, argument: int = 0,
                timeout: float = 5.0) -> int:
        """Request one command and return its sequence number.

        The argument and command are written before the sequence number so that
        firmware only observes the request after its complete payload is ready.
        """
        mailbox = self.wait_until_ready(timeout=timeout)
        sequence = (mailbox.command_sequence + 1) & 0xffffffff
        self._rsp_client.write_memory(
            self.address + COMMAND_ARGUMENT_OFFSET,
            struct.pack("<I", argument & 0xffffffff),
            timeout=timeout)
        self._rsp_client.write_memory(
            self.address + COMMAND_OFFSET,
            struct.pack("<I", int(command)),
            timeout=timeout)
        self._rsp_client.write_memory(
            self.address + COMMAND_SEQUENCE_OFFSET,
            struct.pack("<I", sequence),
            timeout=timeout)
        return sequence

    def issue(self, command: MailboxCommand, argument: int = 0,
              timeout: float = 5.0) -> FixtureMailbox:
        """Request one non-disruptive command and wait for completion.

        Use :meth:`request` for commands that deliberately stop, fault, sleep,
        or reset the target; those cannot acknowledge in the normal way. The
        target must already be running for this method to complete.
        """
        sequence = self.request(command, argument=argument, timeout=timeout)
        return self.wait_for_completion(sequence, timeout=timeout)

    def release_spin(self, sequence: int, timeout: float = 5.0) -> None:
        """Release a host-controlled spin command while the target is halted."""
        self._rsp_client.write_memory(
            self.address + SPIN_RELEASE_SEQUENCE_OFFSET,
            struct.pack("<I", sequence & 0xffffffff),
            timeout=timeout)

    def wait_for(self, predicate: Callable[[FixtureMailbox], bool], *,
                 description: str, timeout: float = 5.0,
                 poll_interval: float = 0.050) -> FixtureMailbox:
        """Wait until a caller-defined mailbox predicate becomes true."""
        deadline = time.monotonic() + timeout
        last_mailbox = None
        while time.monotonic() < deadline:
            last_mailbox = self.read(timeout=self._remaining_timeout(deadline))
            if predicate(last_mailbox):
                return last_mailbox
            time.sleep(min(poll_interval, self._remaining_timeout(deadline)))

        if last_mailbox is None:
            raise FixtureMailboxTimeoutError("could not read the fixture mailbox")
        raise FixtureMailboxTimeoutError(
            "%s did not occur within %.1f seconds" % (description, timeout))

    def wait_for_completion(self, sequence: int, timeout: float = 5.0,
                            poll_interval: float = 0.050) -> FixtureMailbox:
        """Wait for the specified command sequence to report completion."""
        deadline = time.monotonic() + timeout
        last_mailbox = None
        while time.monotonic() < deadline:
            last_mailbox = self.read(timeout=self._remaining_timeout(deadline))
            if (last_mailbox.completed_sequence == sequence and
                    last_mailbox.result == MailboxResult.COMPLETE):
                return last_mailbox
            time.sleep(min(poll_interval, self._remaining_timeout(deadline)))

        completed_sequence = None if last_mailbox is None else last_mailbox.completed_sequence
        result = None if last_mailbox is None else last_mailbox.result
        raise FixtureMailboxTimeoutError(
            "command sequence %d did not complete (completed=%s result=%s)" %
            (sequence, completed_sequence, result))

    @staticmethod
    def _remaining_timeout(deadline: float) -> float:
        return max(0.001, deadline - time.monotonic())


def resolve_elf_symbol(elf_path: Path, symbol_name: str) -> int:
    """Return a non-zero symbol address from an ELF/AXF fixture image."""
    with elf_path.open("rb") as elf_file:
        elf = ELFFile(elf_file)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol.name == symbol_name:
                    address = int(symbol.entry.st_value)
                    if address == 0:
                        raise FixtureMailboxError("ELF symbol %s has no address" % symbol_name)
                    return address
    raise FixtureMailboxError("ELF symbol %s was not found in %s" % (symbol_name, elf_path))


def _signed_32(value: int) -> int:
    return value if value < 0x80000000 else value - 0x100000000
