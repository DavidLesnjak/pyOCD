# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Host- and target-initiated reset scenarios for the fixture."""

import time

from mailbox import (
    MAILBOX_HEADER_SIZE,
    FixtureMailboxClient,
    MailboxCommand,
    MailboxResult,
    resolve_elf_symbol,
)
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient


def test_extended_remote_reset_reinitializes_test_firmware(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a debugger-requested reset returns the test firmware to its known initial state.
    Test method:
    1. Connect one RSP client, wait for mailbox readiness, and calculate the next retained boot epoch.
    2. Replace bytes in the test-owned RAM window with a sentinel and verify that the write reached target RAM.
    3. Enter extended-remote mode, send the reply-less R0 reset request, and synchronize on its stop reply.
    4. Resume briefly, interrupt with Ctrl-C, and wait for the complete reset-ready mailbox generation.
    5. Require the incremented boot epoch, idle command state, and restored initial RAM contents.
    Expected result: Boot epoch increments, command/result fields return to initial values, and RAM is restored.
    Failure indicates: RSP reset leaves stale test-firmware state or does not restart target initialization.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    with gdbserver_server.connect_rsp() as client:
        mailbox = FixtureMailboxClient(client, mailbox_address)
        before = mailbox.wait_until_ready()
        original_window = client.read_memory(mailbox_address + MAILBOX_HEADER_SIZE, 16)
        sentinel = bytes(value ^ 0xA5 for value in original_window)
        client.write_memory(mailbox_address + MAILBOX_HEADER_SIZE, sentinel)
        assert client.read_memory(mailbox_address + MAILBOX_HEADER_SIZE, len(sentinel)) == sentinel

        client.extended_reset()
        _resume_and_interrupt(client)

        after = mailbox.wait_for_reset((before.boot_epoch + 1) & 0xffffffff)
        assert client.read_memory(mailbox_address + MAILBOX_HEADER_SIZE, len(original_window)) == original_window


def test_target_reset_survives_disconnect_and_reconnect(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that debugging remains usable when a reset closes the current connection and the debugger reconnects.
    Test method:
    1. Connect the initial controller, record the current boot epoch, and queue the target-side SYSTEM_RESET command.
    2. Continue and allow the test firmware to execute NVIC_SystemReset while the all-stop request is outstanding.
    3. Abruptly close the controller and verify that persistent gdbserver remains alive without clients.
    4. Reconnect a new RSP client and wait for the exact next boot epoch and fully idle mailbox state.
    5. Prove the pre-reset command sequence was discarded, then resume and interrupt to verify continued control.
    Expected result: Persistent gdbserver stays alive, the new client observes a new boot epoch and clean mailbox.
    Failure indicates: Reset, no-client execution, or reconnect recovery leaves the target/server unusable.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    controller = gdbserver_server.connect_rsp()
    try:
        mailbox = FixtureMailboxClient(controller, mailbox_address)
        before = mailbox.wait_until_ready()
        expected_epoch = (before.boot_epoch + 1) & 0xffffffff
        sequence = mailbox.request(MailboxCommand.SYSTEM_RESET)
        controller.send_packet(b"c")

        # The acknowledgement only confirms packet receipt. Give the target a
        # short interval to execute NVIC_SystemReset before dropping the client.
        time.sleep(0.100)
    finally:
        controller.close()

    time.sleep(0.200)
    assert gdbserver_server.is_running

    with gdbserver_server.connect_rsp() as reconnected:
        mailbox = FixtureMailboxClient(reconnected, mailbox_address)
        after = mailbox.wait_for_reset(expected_epoch)

        assert after.command_sequence == 0
        assert after.completed_sequence == 0
        assert after.result == MailboxResult.IDLE
        assert after.system_reset_calls == 0
        assert sequence != after.command_sequence

        _resume_and_interrupt(reconnected)


def _mailbox_address(gdbserver_server: PyOCDGDBServer) -> int:
    return resolve_elf_symbol(gdbserver_server.configuration.firmware, "gdbserver_test_firmware_mailbox")


def _resume_and_interrupt(client: RSPClient) -> None:
    """Run a halted target long enough for initialization, then leave it halted."""
    client.send_packet(b"c")
    time.sleep(0.100)
    client.interrupt()
    assert client.receive_packet(timeout=5.0).startswith(b"T02")
