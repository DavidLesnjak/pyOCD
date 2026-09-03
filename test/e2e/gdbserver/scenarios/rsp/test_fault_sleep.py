# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Low-power and fault-control scenarios for the hardware fixture."""

import struct
import time

import pytest

from mailbox import (
    FixtureMailboxError,
    FixtureMailboxClient,
    MailboxCommand,
    MailboxWFIState,
    resolve_elf_symbol,
)
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient, RSPError


_NVIC_SET_PENDING_BASE = 0xE000E200


def test_wfi_wakes_from_host_pended_nvic_interrupt(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that the test firmware enters low-power wait and wakes only when the debugger triggers its advertised interrupt.
    Test method:
    1. Connect one controller, wait for mailbox readiness, and queue the WFI command.
    2. Continue, wait briefly, interrupt, and require that the mailbox reached its ENTERED state.
    3. Read the exact wake IRQ published by the test firmware and validate its NVIC range.
    4. Write the corresponding NVIC set-pending bit through RSP and resume execution.
    5. Interrupt after wakeup and require the same IRQ, RESUMED state, and exactly one new wake count.
    6. If the scenario fails mid-wait, pend the advertised IRQ and resume as bounded recovery.
    Expected result: WFI enters first, resumes after the exact IRQ is pended, and increments wake count once.
    Failure indicates: Low-power debug control, NVIC access, target wakeup, or cleanup is incorrect.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    with gdbserver_server.connect_rsp() as controller:
        controller_mailbox = FixtureMailboxClient(controller, mailbox_address)
        sequence = None
        completed = None
        try:
            before = controller_mailbox.wait_until_ready()
            sequence = controller_mailbox.request(MailboxCommand.WFI)
            controller.send_packet(b"c")
            time.sleep(0.100)
            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            sleeping = controller_mailbox.wait_for(
                lambda state: (state.command_sequence == sequence and
                               state.wfi_state == MailboxWFIState.ENTERED),
                description="fixture WFI entry")

            wake_irq = sleeping.wfi_wake_irq
            assert wake_irq < 128

            _pend_fixture_wake_irq(controller, wake_irq)
            controller.send_packet(b"c")
            time.sleep(0.100)
            controller.interrupt()
            assert controller.receive_packet(timeout=5.0).startswith(b"T02")
            completed = controller_mailbox.wait_for_completion(sequence)
            assert completed.wfi_state == MailboxWFIState.RESUMED
            assert completed.wfi_wake_irq == wake_irq
            assert completed.wfi_wake_count == before.wfi_wake_count + 1
        finally:
            if sequence is not None and completed is None:
                _recover_wfi(controller, controller_mailbox)


@pytest.mark.gdbserver_config(vector_catch="h")
def test_hardfault_vector_catch_and_reset_recovery(
        gdbserver_server: PyOCDGDBServer) -> None:
    """
    Purpose: Check that a deliberate processor fault is reported to the debugger and that the board can be reset afterwards.
    Test method:
    1. Start gdbserver with HardFault vector catch and record the ready mailbox and next boot epoch.
    2. Queue the deliberate HARDFAULT command and continue execution.
    3. Require a T0b stop and a one-count HardFault marker while the command remains incomplete.
    4. Send the extended-remote reset sequence, resume briefly, and interrupt the recovered target.
    5. Wait for the exact new boot epoch and require that the reset mailbox cleared the fault counter.
    6. If normal recovery fails, make one bounded best-effort reset and resume attempt.
    Expected result: The fault reports T0b, the HardFault marker increments, and reset advances boot epoch and clears it.
    Failure indicates: Fault classification, vector catch, or recovery after a fault is incorrect.
    """
    mailbox_address = _mailbox_address(gdbserver_server)
    with gdbserver_server.connect_rsp() as client:
        mailbox = FixtureMailboxClient(client, mailbox_address)
        before = mailbox.wait_until_ready()
        expected_epoch = (before.boot_epoch + 1) & 0xffffffff
        reset_complete = False
        try:
            sequence = mailbox.request(MailboxCommand.HARDFAULT)
            client.send_packet(b"c")
            assert client.receive_packet(timeout=5.0).startswith(b"T0b")

            faulted = mailbox.wait_for(
                lambda state: state.hardfault_calls == before.hardfault_calls + 1,
                description="fixture HardFault marker")
            assert faulted.completed_sequence != sequence

            client.extended_reset()
            _resume_and_interrupt(client)
            recovered = mailbox.wait_for_reset(expected_epoch)
            assert recovered.hardfault_calls == 0
            reset_complete = True
        finally:
            if not reset_complete:
                _recover_hardfault(client)


def _mailbox_address(gdbserver_server: PyOCDGDBServer) -> int:
    return resolve_elf_symbol(gdbserver_server.configuration.firmware, "gdbserver_test_firmware_mailbox")


def _pend_fixture_wake_irq(client: RSPClient, wake_irq: int) -> None:
    """Set the NVIC pending bit that the fixture publishes for its WFI wait."""
    register_address = _NVIC_SET_PENDING_BASE + ((wake_irq // 32) * 4)
    pending_bit = 1 << (wake_irq % 32)
    client.write_memory(register_address, struct.pack("<I", pending_bit))


def _resume_and_interrupt(client: RSPClient) -> None:
    """Run a halted target briefly, then leave it halted for mailbox inspection."""
    client.send_packet(b"c")
    time.sleep(0.100)
    client.interrupt()
    assert client.receive_packet(timeout=5.0).startswith(b"T02")


def _recover_wfi(controller: RSPClient, mailbox: FixtureMailboxClient) -> None:
    """Best-effort wake and resume if the WFI scenario fails mid-command."""
    try:
        controller.interrupt(timeout=1.0)
        controller.receive_packet(timeout=2.0)
    except (FixtureMailboxError, RSPError):
        pass
    try:
        _pend_fixture_wake_irq(controller, mailbox.read(timeout=1.0).wfi_wake_irq)
        controller.send_packet(b"c", timeout=1.0)
    except RSPError:
        pass


def _recover_hardfault(client: RSPClient) -> None:
    """Best-effort reset if the expected vector-catch recovery path fails."""
    try:
        client.extended_reset(timeout=2.0)
        client.send_packet(b"c", timeout=2.0)
        time.sleep(0.100)
        client.interrupt(timeout=2.0)
        client.receive_packet(timeout=2.0)
    except RSPError:
        pass
