# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Deterministic command-completion synchronization for raw-RSP scenarios."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator

from mailbox import FixtureMailbox, FixtureMailboxClient, resolve_elf_symbol
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient


def wait_for_command_completion(server: PyOCDGDBServer, client: RSPClient,
                                mailbox: FixtureMailboxClient,
                                command_sequence: int) -> FixtureMailbox:
    """Check a command's completion after the RSP client has stopped the target.

    Output can be forwarded before the target returns from an RTT or semihosting
    operation and publishes its mailbox completion state. Connecting an all-stop
    RSP client halts the target, so its mailbox can be read safely. If that read
    finds an incomplete command, resume only to a hardware breakpoint placed after
    the completion-state write rather than treating received output as completion.
    """
    completed = mailbox.read()
    if completed.completed_sequence == command_sequence:
        return completed

    breakpoint_address = resolve_elf_symbol(server.configuration.firmware, "gdbserver_test_firmware_command_completion_site") & ~1
    insert_packet = b"Z1,%x,2" % breakpoint_address
    remove_packet = b"z1,%x,2" % breakpoint_address
    breakpoint_inserted = False
    try:
        assert client.command(insert_packet) == b"OK"
        breakpoint_inserted = True
        client.send_packet(b"c")
        assert client.receive_packet(timeout=5.0).startswith(b"T05")
        return mailbox.wait_for_completion(command_sequence)
    finally:
        if breakpoint_inserted:
            assert client.command(remove_packet) == b"OK"


@contextmanager
def command_completion_breakpoint(server: PyOCDGDBServer,
                                  client: RSPClient) -> Iterator[None]:
    """Stop a resumed command at the mailbox completion site.

    Enter this context while the all-stop client has halted the target. The caller
    may then resume it and wait for its side-channel output. Before leaving the
    context, it must consume the hardware-breakpoint stop reply with
    :func:`wait_for_resumed_command_completion`.
    """
    breakpoint_address = resolve_elf_symbol(server.configuration.firmware, "gdbserver_test_firmware_command_completion_site") & ~1
    insert_packet = b"Z1,%x,2" % breakpoint_address
    remove_packet = b"z1,%x,2" % breakpoint_address
    assert client.command(insert_packet) == b"OK"
    try:
        yield
    finally:
        assert client.command(remove_packet) == b"OK"


def wait_for_resumed_command_completion(client: RSPClient,
                                        mailbox: FixtureMailboxClient,
                                        command_sequence: int) -> FixtureMailbox:
    """Wait for a preinstalled completion breakpoint, then read the stopped target."""
    assert client.receive_packet(timeout=5.0).startswith(b"T05")
    return mailbox.wait_for_completion(command_sequence)
