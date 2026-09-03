# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Initial single-client mailbox and RSP access scenario for the B-U585I-IOT02A."""

import time

from mailbox import (
    MAILBOX_HEADER_SIZE,
    FixtureMailbox,
    FixtureMailboxClient,
    MailboxCommand,
    MailboxSpinState,
)
from rsp import RSPClient


def test_mailbox_memory_registers_and_spin(fixture_mailbox: FixtureMailboxClient,
                                           raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Establish that the basic board-debug connection can read memory and registers, stop a running program, and resume it.
    Test method:
    1. Read the initialized mailbox and save the original bytes from its test-owned RAM window.
    2. Write a transformed pattern through RSP, verify it exactly, restore the original bytes, and read all core registers.
    3. Queue SPIN and continue long enough for the test firmware to enter its host-controlled loop.
    4. Send Ctrl-C and require a T02 stop reply while the SPIN command is still active.
    5. Write the matching release sequence, continue, interrupt again, and wait for exact command completion.
    6. Verify released state, non-zero spin progress, and a heartbeat change proving normal execution resumed.
    Expected result: RAM and registers are readable, both deliberate stops are T02, the spin completes,
    and the test-firmware heartbeat advances.
    Failure indicates: Basic RSP memory/register access, interrupt handling, or mailbox execution is broken.
    """
    initial = fixture_mailbox.read()
    original_window = raw_rsp_client.read_memory(
        fixture_mailbox.address + MAILBOX_HEADER_SIZE,
        16)
    test_window = bytes((value ^ 0xa5) for value in original_window)

    raw_rsp_client.write_memory(fixture_mailbox.address + MAILBOX_HEADER_SIZE, test_window)
    assert raw_rsp_client.read_memory(
        fixture_mailbox.address + MAILBOX_HEADER_SIZE,
        len(test_window)) == test_window
    raw_rsp_client.write_memory(fixture_mailbox.address + MAILBOX_HEADER_SIZE, original_window)
    assert len(raw_rsp_client.read_registers()) >= 16 * 4

    command_sequence = fixture_mailbox.request(MailboxCommand.SPIN)
    raw_rsp_client.send_packet(b"c")
    time.sleep(0.100)
    raw_rsp_client.interrupt()
    assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T02")

    fixture_mailbox.release_spin(command_sequence)
    raw_rsp_client.send_packet(b"c")
    time.sleep(0.100)
    raw_rsp_client.interrupt()
    assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T02")
    completed = fixture_mailbox.wait_for_completion(command_sequence)
    assert completed.completed_sequence == completed.command_sequence
    assert completed.spin_state == MailboxSpinState.RELEASED
    assert completed.spin_iterations != 0
    assert _wait_for_heartbeat_change(fixture_mailbox, initial.heartbeat).heartbeat != initial.heartbeat


def _wait_for_heartbeat_change(mailbox_client: FixtureMailboxClient,
                               initial_heartbeat: int,
                               timeout: float = 2.0) -> FixtureMailbox:
    deadline = time.monotonic() + timeout
    last_mailbox = mailbox_client.read()
    while time.monotonic() < deadline:
        if last_mailbox.heartbeat != initial_heartbeat:
            return last_mailbox
        time.sleep(0.050)
        last_mailbox = mailbox_client.read()
    raise AssertionError("fixture heartbeat did not change within %.1f seconds" % timeout)
