# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Initial two-client RSP observer scenario for the B-U585I-IOT02A."""

from mailbox import (
    FixtureMailboxClient,
    MailboxCommand,
    MailboxSpinState,
    resolve_elf_symbol,
)
from pyocd_server import PyOCDGDBServer


def test_two_clients_can_read_the_test_firmware(gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that one debugger can control the test firmware while another safely observes its shared status.
    Test method:
    1. Resolve the mailbox symbol and connect separate controller and observer RSP clients before execution starts.
    2. Validate mailbox readiness through the controller and read the same RAM through the observer.
    3. Queue SPIN, continue with the controller, and poll through the observer until SPIN reports running.
    4. Interrupt the controller and require a T02 stop before modifying the spin release sequence.
    5. Release SPIN, continue again, and use the observer to wait for the exact command sequence to complete.
    6. Interrupt a second time and prove that the mailbox stayed valid and observable throughout the run.
    Expected result: The observer sees running and completed state, both interrupts return T02, and the
    mailbox remains valid.
    Failure indicates: A second client cannot safely observe controller-owned target activity.
    """
    mailbox_address = resolve_elf_symbol(
        gdbserver_server.configuration.firmware,
        "gdbserver_test_firmware_mailbox")
    with gdbserver_server.connect_rsp() as controller, gdbserver_server.connect_rsp() as observer:
        controller_mailbox = FixtureMailboxClient(controller, mailbox_address)
        observer_mailbox = FixtureMailboxClient(observer, mailbox_address)
        before = controller_mailbox.wait_until_ready()
        observed_before = observer.read_memory(mailbox_address, 16)

        command_sequence = controller_mailbox.request(MailboxCommand.SPIN)
        controller.send_packet(b"c")
        observer_mailbox.wait_for(
            lambda mailbox: (mailbox.command_sequence == command_sequence and
                             mailbox.spin_state == MailboxSpinState.RUNNING),
            description="fixture spin command to start")
        controller.interrupt()
        assert controller.receive_packet(timeout=5.0).startswith(b"T02")
        controller_mailbox.release_spin(command_sequence)
        controller.send_packet(b"c")
        completed = observer_mailbox.wait_for_completion(command_sequence)
        controller.interrupt()
        assert controller.receive_packet(timeout=5.0).startswith(b"T02")
        observed_after = observer.read_memory(mailbox_address, 16)

    assert completed.completed_sequence == completed.command_sequence
    assert completed.spin_state == MailboxSpinState.RELEASED
    assert observed_before != b""
    assert observed_after != b""
    assert before.magic == completed.magic
