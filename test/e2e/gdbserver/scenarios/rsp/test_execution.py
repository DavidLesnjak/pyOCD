# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Breakpoint, execution-control, single-step, and watchpoint scenarios."""

import pytest

from mailbox import (
    WATCHPOINT_VALUE_OFFSET,
    FixtureMailboxClient,
    MailboxCommand,
    MailboxSpinState,
    resolve_elf_symbol,
)
from pyocd_server import PyOCDGDBServer
from rsp import RSPClient


_RANGE_STEP_CODE = b"\x00\xbf" * 6
_RANGE_STEP_BKPT = b"\x00\xbe"
_RANGE_STEP_BREAKPOINT_OFFSET = 4
_RANGE_STEP_END_OFFSET = 10
_LITERAL_FLOW_CODE = b"\x00\xbf\x00\xbf\x00\xbe\x00\xbf\x01\xbe\x00\xbf"
_LITERAL_FLOW_FIRST_BKPT_OFFSET = 4
_LITERAL_FLOW_SECOND_BKPT_OFFSET = 8


def test_software_breakpoint_executes_test_firmware_owned_ram_code(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check that a temporary code patch can pause test-firmware-owned RAM code and that the original instructions are restored.
    Test method:
    1. Save the original test-owned RAM bytes and replace them with a two-byte Thumb return instruction.
    2. Queue RAM_EXECUTE, insert Z0 at the RAM address, continue to T05, and require the stopped PC at Z0.
    3. Verify pyOCD's filtered view of the original instruction, remove Z0, then single-step and require PC progress.
    4. Continue the first command to completion, halt, and verify the physical RAM bytes were restored.
    5. Queue a second RAM_EXECUTE command, reinstall Z0, stop again, remove it, and complete the second execution.
    6. Restore the caller's original RAM contents in finally cleanup even if any breakpoint operation fails.
    Expected result: Each operation succeeds, execution advances, and the original RAM contents are restored.
    Failure indicates: Software breakpoint patching, step behavior, or executable-RAM cleanup is incorrect.
    """
    ram_code_address = fixture_mailbox.ram_window_address
    original_ram_code = raw_rsp_client.read_memory(ram_code_address, 2)
    fixture_ram_code = b"\x70\x47"
    insert_packet = _breakpoint_packet(b"Z0", ram_code_address)
    remove_packet = _breakpoint_packet(b"z0", ram_code_address)
    breakpoint_inserted = False

    try:
        with gdbserver_server.connect_rsp() as observer:
            observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
            raw_rsp_client.write_memory_binary(ram_code_address, fixture_ram_code)
            assert raw_rsp_client.read_memory(ram_code_address, 2) == fixture_ram_code

            first_command_sequence = fixture_mailbox.request(MailboxCommand.RAM_EXECUTE)
            assert raw_rsp_client.command(insert_packet) == b"OK"
            breakpoint_inserted = True
            raw_rsp_client.send_packet(b"c")
            program_counter_before = _expect_sigtrap_at_address(
                raw_rsp_client, ram_code_address)

            # GDB removes a managed software breakpoint before asking the stub
            # to single-step its original instruction. Until execution starts,
            # the debugger view must continue to filter the physical BKPT.
            assert raw_rsp_client.read_memory(ram_code_address, 2) == fixture_ram_code
            assert raw_rsp_client.command(remove_packet) == b"OK"
            breakpoint_inserted = False
            raw_rsp_client.send_packet(b"s")
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T05")
            assert _program_counter(raw_rsp_client) != program_counter_before
            assert raw_rsp_client.read_memory(ram_code_address, 2) == fixture_ram_code

            # The step flushed the queued Z0 removal before executing the original
            # ``bx lr``. With no live software breakpoint, the memory read below
            # now observes the physical fixture bytes.
            raw_rsp_client.send_packet(b"c")
            first_completed = observer_mailbox.wait_for_completion(first_command_sequence)
            _interrupt_and_expect_sigint(raw_rsp_client)
            assert raw_rsp_client.read_memory(ram_code_address, 2) == fixture_ram_code

            second_command_sequence = fixture_mailbox.request(MailboxCommand.RAM_EXECUTE)
            assert raw_rsp_client.command(insert_packet) == b"OK"
            breakpoint_inserted = True
            raw_rsp_client.send_packet(b"c")
            _expect_sigtrap_at_address(raw_rsp_client, ram_code_address)
            assert raw_rsp_client.command(remove_packet) == b"OK"
            breakpoint_inserted = False

            raw_rsp_client.send_packet(b"c")
            second_completed = observer_mailbox.wait_for_completion(second_command_sequence)
            _interrupt_and_expect_sigint(raw_rsp_client)
            assert raw_rsp_client.read_memory(ram_code_address, 2) == fixture_ram_code
    finally:
        try:
            if breakpoint_inserted:
                assert raw_rsp_client.command(remove_packet) == b"OK"
        finally:
            raw_rsp_client.write_memory(ram_code_address, original_ram_code)

    assert first_completed.completed_sequence == first_command_sequence
    assert second_completed.completed_sequence == second_command_sequence


def test_hardware_breakpoint_stops_and_allows_execution_to_resume(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check that removing a breakpoint while stopped lets the test firmware continue instead of leaving it paused or damaged.
    Test method:
    1. Resolve the repeatedly executed breakpoint-site symbol and save its original instruction bytes.
    2. Connect an observer, record heartbeat state, and insert a hardware Z1 breakpoint through the controller.
    3. Continue to T05 and require PC to equal the resolved function-entry address.
    4. Remove Z1 and verify that reading code still returns the unchanged original instruction.
    5. Continue without a breakpoint, observe heartbeat progress from the second client, and interrupt with T02.
    Expected result: The loop breakpoint stops once and the test firmware resumes after its removal.
    Failure indicates: Hardware breakpoint cleanup leaves target execution blocked or corrupt.
    """
    breakpoint_address = resolve_elf_symbol(gdbserver_server.configuration.firmware, "gdbserver_test_firmware_breakpoint_site") & ~1
    breakpoint_code = raw_rsp_client.read_memory(breakpoint_address, 2)
    insert_packet = _breakpoint_packet(b"Z1", breakpoint_address)
    remove_packet = _breakpoint_packet(b"z1", breakpoint_address)
    breakpoint_inserted = False

    try:
        with gdbserver_server.connect_rsp() as observer:
            observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
            before = fixture_mailbox.read()
            assert raw_rsp_client.command(insert_packet) == b"OK"
            breakpoint_inserted = True
            assert raw_rsp_client.read_memory(breakpoint_address, 2) == breakpoint_code
            raw_rsp_client.send_packet(b"c")
            _expect_sigtrap_at_address(raw_rsp_client, breakpoint_address)
            assert raw_rsp_client.command(remove_packet) == b"OK"
            breakpoint_inserted = False
            assert raw_rsp_client.read_memory(breakpoint_address, 2) == breakpoint_code

            raw_rsp_client.send_packet(b"c")
            resumed = observer_mailbox.wait_for(
                lambda mailbox: mailbox.heartbeat != before.heartbeat,
                description=("fixture heartbeat after hardware breakpoint "
                             "removal"))
            _interrupt_and_expect_sigint(raw_rsp_client)
    finally:
        if breakpoint_inserted:
            assert raw_rsp_client.command(remove_packet) == b"OK"

    assert resumed.loop_count != before.loop_count


@pytest.mark.parametrize("non_stop", (False, True), ids=("all-stop", "non-stop"))
def test_range_step_stops_at_installed_hardware_breakpoint(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient,
        non_stop: bool) -> None:
    """
    Purpose: Check that target-assisted range stepping stops at an installed hardware breakpoint inside its requested address interval.
    Variants: all-stop direct replies and non-stop asynchronous stop notifications.
    Test method:
    1. Resolve the fixed six-NOP range-step sequence in executable target flash and verify its exact instruction bytes.
    2. Define A at the sequence start, X at its third instruction, and B at its sixth instruction, making the RSP interval [A,B).
    3. Save PC, set PC to A, install Z1 at X, and send vCont;rA,B while the target is halted.
    4. Require a T05 stop with PC exactly X, proving the unrelated hardware-breakpoint event terminated the range step before B.
    5. Remove Z1, range-step again from X to B, and require T05 with PC exactly B.
    6. Verify flash bytes remained unchanged and restore the original PC in finally cleanup.
    Expected result: The first range step stops exactly at hardware breakpoint X and the second reaches exclusive endpoint B.
    Failure indicates: Range stepping ignores an FPB event, reports the wrong PC, or cannot resume after breakpoint removal.
    """
    _run_range_step_breakpoint_scenario(
        fixture_mailbox, gdbserver_server, raw_rsp_client,
        breakpoint_kind=b"Z1", non_stop=non_stop)


@pytest.mark.parametrize("non_stop", (False, True), ids=("all-stop", "non-stop"))
def test_range_step_stops_at_installed_software_breakpoint(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient,
        non_stop: bool) -> None:
    """
    Purpose: Check that target-assisted range stepping stops at a managed software breakpoint inside its requested address interval.
    Variants: all-stop direct replies and non-stop asynchronous stop notifications.
    Test method:
    1. Save the executable mailbox RAM window and replace its first twelve bytes with six Thumb NOP instructions.
    2. Define A at the sequence start, X at its third instruction, and B at its sixth instruction, making the RSP interval [A,B).
    3. Save PC, set PC to A, install Z0 at X, and send vCont;rA,B while the target is halted.
    4. Require a T05 stop with PC exactly X and verify debugger reads still expose the original NOP rather than the inserted BKPT patch.
    5. Remove Z0, range-step again from X to B, and require T05 with PC exactly B and all NOP bytes restored.
    6. Restore the original RAM bytes and PC in finally cleanup.
    Expected result: The first range step stops exactly at software breakpoint X and the second reaches exclusive endpoint B.
    Failure indicates: Range stepping misses a managed Z0 patch, reports the wrong PC, or leaves executable RAM modified.
    """
    _run_range_step_breakpoint_scenario(
        fixture_mailbox, gdbserver_server, raw_rsp_client,
        breakpoint_kind=b"Z0", non_stop=non_stop)


@pytest.mark.parametrize("non_stop", (False, True), ids=("all-stop", "non-stop"))
def test_range_step_stops_at_literal_bkpt_instruction(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient,
        non_stop: bool) -> None:
    """
    Purpose: Check that target-assisted range stepping stops for an unmanaged BKPT instruction located inside its requested interval.
    Variants: all-stop direct replies and non-stop asynchronous stop notifications.
    Test method:
    1. Save the executable mailbox RAM window and write six Thumb instructions with a literal BKPT at the third instruction.
    2. Define A at the sequence start, X at the BKPT instruction, and B at the sixth instruction, making the RSP interval [A,B).
    3. Save PC, set PC to A, and send vCont;rA,B without installing a debugger-managed breakpoint.
    4. Require T05 with PC exactly X, proving the instruction is reported before pyOCD consumes it.
    5. Range-step again from X to B and require T05 exactly at B without stopping on the same BKPT twice.
    6. Verify the literal instruction remained intact and restore the original RAM bytes and PC in finally cleanup.
    Expected result: The literal BKPT terminates the first range step inside the interval and execution then reaches B without retriggering.
    Failure indicates: Range stepping ignores the BKPT debug event, advances to B silently, or repeatedly stops at the same instruction.
    """
    _run_range_step_breakpoint_scenario(
        fixture_mailbox, gdbserver_server, raw_rsp_client,
        breakpoint_kind=None, non_stop=non_stop)


@pytest.mark.parametrize(
    ("non_stop", "execution_packet", "single_step"),
    (
        (False, b"c", False),
        (False, b"vCont;c", False),
        (False, b"s", True),
        (False, b"vCont;s", True),
        (True, b"vCont;c", False),
        (True, b"vCont;s", True),
    ),
    ids=(
        "all-stop-c",
        "all-stop-vCont-c",
        "all-stop-s",
        "all-stop-vCont-s",
        "non-stop-vCont-c",
        "non-stop-vCont-s",
    ),
)
def test_literal_bkpt_execution_boundary_preserves_stop_address(
        fixture_mailbox: FixtureMailboxClient,
        raw_rsp_client: RSPClient,
        non_stop: bool,
        execution_packet: bytes,
        single_step: bool) -> None:
    """
    Purpose: Check exact PC behavior when continue or step starts from an unmanaged literal BKPT.
    Variants: all-stop c, vCont;c, s, and vCont;s plus non-stop vCont;c and vCont;s.
    Test method:
    1. Save PC and executable mailbox RAM, then write NOPs with literal BKPT instructions at distinct X and Y addresses.
    2. Continue from the sequence start and require T05 at X with PC still pointing to the first BKPT bytes.
    3. Repeat all-stop stop and register queries, or leave the non-stop notification pending, and prove PC remains X.
    4. Acknowledge non-stop if needed, issue the variant's execution request from X, and require T05 at Y.
    5. For step variants, continue once more and require a second stop at Y, proving the step reached but did not consume its BKPT.
    6. Acknowledge every non-stop event and restore the original RAM and PC in finally cleanup.
    Expected result: Stops report the triggering BKPT address, while only a later execution request consumes that instruction.
    Failure indicates: Observation moves PC, execution retriggers X, or stepping silently consumes the following BKPT at Y.
    """
    start = fixture_mailbox.ram_window_address
    first_breakpoint = start + _LITERAL_FLOW_FIRST_BKPT_OFFSET
    second_breakpoint = start + _LITERAL_FLOW_SECOND_BKPT_OFFSET
    original_pc = _program_counter(raw_rsp_client)
    original_ram = raw_rsp_client.read_memory(start, len(_LITERAL_FLOW_CODE))

    try:
        if non_stop:
            _enable_non_stop(raw_rsp_client)
        raw_rsp_client.write_memory_binary(start, _LITERAL_FLOW_CODE)
        raw_rsp_client.write_register(15, start.to_bytes(4, byteorder="little"))

        initial_resume = b"vCont;c" if non_stop else b"c"
        assert _execute_to_sigtrap(
            raw_rsp_client, initial_resume, non_stop=non_stop) == first_breakpoint
        assert raw_rsp_client.read_memory(
            first_breakpoint, len(_RANGE_STEP_BKPT)) == _RANGE_STEP_BKPT

        if non_stop:
            assert _program_counter(raw_rsp_client) & ~1 == first_breakpoint
            assert raw_rsp_client.command(b"vStopped") == b"OK"
        else:
            assert raw_rsp_client.command(b"?").startswith(b"T05")
            assert _program_counter(raw_rsp_client) & ~1 == first_breakpoint
            assert len(raw_rsp_client.read_registers()) >= 16 * 4
            assert _program_counter(raw_rsp_client) & ~1 == first_breakpoint

        assert _execute_to_sigtrap(
            raw_rsp_client, execution_packet,
            non_stop=non_stop) == second_breakpoint
        if non_stop:
            assert raw_rsp_client.command(b"vStopped") == b"OK"

        if single_step:
            final_resume = b"vCont;c" if non_stop else b"c"
            assert _execute_to_sigtrap(
                raw_rsp_client, final_resume,
                non_stop=non_stop) == second_breakpoint
            if non_stop:
                assert raw_rsp_client.command(b"vStopped") == b"OK"
    finally:
        raw_rsp_client.write_memory(start, original_ram)
        raw_rsp_client.write_register(15, original_pc.to_bytes(4, byteorder="little"))


@pytest.mark.parametrize(
    ("non_stop", "step_packet"),
    (
        (False, b"s"),
        (False, b"vCont;s"),
        (True, b"vCont;s"),
    ),
    ids=("all-stop-s", "all-stop-vCont-s", "non-stop-vCont-s"),
)
def test_literal_bkpt_can_be_single_stepped_then_completes_after_continue(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient,
        non_stop: bool,
        step_packet: bytes) -> None:
    """
    Purpose: Check that execution can advance past a breakpoint instruction already present in the test-firmware code.
    Variants: legacy all-stop s, all-stop vCont;s, and non-stop vCont;s.
    Test method:
    1. Connect an observer, record the literal-BKPT call count, and queue the LITERAL_BKPT command.
    2. Continue to the firmware-owned BKPT instruction and require T05 with PC still pointing at its BKPT bytes.
    3. In all-stop mode, repeat the stop query and prove it does not change PC.
    4. Send the variant's step request and require a second T05 at a different PC.
    5. Prove the mailbox command is still incomplete immediately after the single instruction.
    6. Continue through the epilogue, wait for exact completion, stop, and require one new BKPT call.
    Expected result: The trap stops as expected, one step advances execution, and the command finishes.
    Failure indicates: Literal breakpoint handling or post-step resume is incorrect.
    """
    with gdbserver_server.connect_rsp() as observer:
        observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
        if non_stop:
            _enable_non_stop(raw_rsp_client)
        before = fixture_mailbox.read()
        command_sequence = fixture_mailbox.request(MailboxCommand.LITERAL_BKPT)
        if non_stop:
            assert raw_rsp_client.command(b"vCont;c") == b"OK"
            _expect_non_stop_sigtrap(raw_rsp_client)
        else:
            raw_rsp_client.send_packet(b"c")
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T05")

        stopped = observer_mailbox.read()
        assert stopped.literal_bkpt_calls == before.literal_bkpt_calls + 1
        assert stopped.completed_sequence != command_sequence

        # Observation leaves PC at the instruction. The execution boundary of
        # the following step consumes the BKPT before stepping the epilogue.
        program_counter_before = _program_counter(raw_rsp_client) & ~1
        assert raw_rsp_client.read_memory(
            program_counter_before, len(_RANGE_STEP_BKPT)) == _RANGE_STEP_BKPT
        if non_stop:
            assert raw_rsp_client.command(b"vStopped") == b"OK"
            assert raw_rsp_client.command(step_packet) == b"OK"
            _expect_non_stop_sigtrap(raw_rsp_client)
        else:
            assert raw_rsp_client.command(b"?").startswith(b"T05")
            assert _program_counter(raw_rsp_client) & ~1 == program_counter_before
            raw_rsp_client.send_packet(step_packet)
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T05")
        assert _program_counter(raw_rsp_client) & ~1 != program_counter_before
        assert observer_mailbox.read().completed_sequence != command_sequence
        if non_stop:
            assert raw_rsp_client.command(b"vStopped") == b"OK"

        if non_stop:
            assert raw_rsp_client.command(b"vCont;c") == b"OK"
            completed = observer_mailbox.wait_for_completion(command_sequence)
            assert raw_rsp_client.command(b"vCont;t") == b"OK"
            _expect_non_stop_stop(raw_rsp_client, b"T00")
            assert raw_rsp_client.command(b"vStopped") == b"OK"
        else:
            raw_rsp_client.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(command_sequence)
            _interrupt_and_expect_sigint(raw_rsp_client)

    assert completed.literal_bkpt_calls == before.literal_bkpt_calls + 1


def test_ctrl_c_halts_a_host_released_spin_command(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check that a normal debugger interrupt pauses a deliberately running test-firmware command, which can then complete.
    Test method:
    1. Connect an observer, queue SPIN, and continue with the controller.
    2. Poll through the observer until SPIN is running and has accumulated non-zero iterations.
    3. Send the out-of-band Ctrl-C byte and require a T02 stop while the command remains incomplete.
    4. Write the matching release sequence while halted and continue the controller.
    5. Wait for completion through the observer, interrupt again, and verify released state and monotonic progress.
    Expected result: Ctrl-C reports T02 and the released command reaches its completed result.
    Failure indicates: Interrupt delivery, target halt state, or resumed command execution is wrong.
    """
    with gdbserver_server.connect_rsp() as observer:
        observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
        command_sequence = fixture_mailbox.request(MailboxCommand.SPIN)
        raw_rsp_client.send_packet(b"c")
        spinning = observer_mailbox.wait_for(
            lambda mailbox: mailbox.spin_state == MailboxSpinState.RUNNING,
            description=("fixture spin command to enter its "
                         "host-controlled loop"))
        assert spinning.spin_iterations != 0

        _interrupt_and_expect_sigint(raw_rsp_client)
        halted = fixture_mailbox.read()
        assert halted.completed_sequence != command_sequence
        assert halted.spin_state == MailboxSpinState.RUNNING

        fixture_mailbox.release_spin(command_sequence)
        raw_rsp_client.send_packet(b"c")
        completed = observer_mailbox.wait_for_completion(command_sequence)
        _interrupt_and_expect_sigint(raw_rsp_client)

    assert completed.spin_state == MailboxSpinState.RELEASED
    assert completed.spin_release_sequence == command_sequence
    assert completed.spin_iterations >= spinning.spin_iterations


@pytest.mark.parametrize("resume_packet", [b"c", b"vCont;c"])
def test_ctrl_c_after_a_breakpoint_stop_interrupts_only_the_next_resume(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient,
        resume_packet: bytes) -> None:
    """
    Purpose: Verify a late Ctrl-C after a reported breakpoint is queued for exactly one resume.
    Test method:
    1. Insert a hardware breakpoint at the loop entry, resume, and consume T05 at that exact PC.
    2. Remove the breakpoint and send Ctrl-C while the target is already stopped.
    3. Require a normal qC response without an unsolicited second stop reply.
    4. Resume without another Ctrl-C and require T02 from the queued interrupt.
    5. Resume again, prove new heartbeat progress through an observer, and interrupt normally.
    Expected result: The original T05 remains valid and the late interrupt stops only the next resume.
    Failure indicates: A late interrupt is lost, produces an extra stop reply, or survives more than one resume.
    """
    breakpoint_address = resolve_elf_symbol(gdbserver_server.configuration.firmware, "gdbserver_test_firmware_breakpoint_site") & ~1
    insert_packet = _breakpoint_packet(b"Z1", breakpoint_address)
    remove_packet = _breakpoint_packet(b"z1", breakpoint_address)
    breakpoint_inserted = False

    with gdbserver_server.connect_rsp() as observer:
        observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
        try:
            assert raw_rsp_client.command(insert_packet) == b"OK"
            breakpoint_inserted = True
            raw_rsp_client.send_packet(resume_packet)
            _expect_sigtrap_at_address(raw_rsp_client, breakpoint_address)
            assert raw_rsp_client.command(remove_packet) == b"OK"
            breakpoint_inserted = False

            raw_rsp_client.interrupt()
            assert raw_rsp_client.command(b"qC").startswith(b"QC")
            raw_rsp_client.send_packet(resume_packet)
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T02")

            before = fixture_mailbox.read()
            raw_rsp_client.send_packet(resume_packet)
            observer_mailbox.wait_for(
                lambda mailbox: mailbox.heartbeat != before.heartbeat,
                description="fixture progress after the queued interrupt was consumed")
            _interrupt_and_expect_sigint(raw_rsp_client)
        finally:
            if breakpoint_inserted:
                assert raw_rsp_client.command(remove_packet) == b"OK"


def test_single_step_is_rejected_while_another_client_is_running(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check that a second debugger cannot take control and single-step while another debugger owns running execution.
    Test method:
    1. Connect controller and observer clients, queue SPIN, and continue through the controller.
    2. Wait through the observer until the controller-owned SPIN is actively executing.
    3. Send raw s from the observer while the controller still owns the running target.
    4. Require the explicit E01 rejection instead of a second execution-control operation.
    5. Interrupt the controller, release SPIN, resume, and verify normal command completion.
    Expected result: The second client's request is rejected with E01 and the controller completes normally.
    Failure indicates: Concurrent execution ownership is not enforced safely.
    """
    with gdbserver_server.connect_rsp() as observer:
        observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
        command_sequence = fixture_mailbox.request(MailboxCommand.SPIN)
        completed = None
        try:
            raw_rsp_client.send_packet(b"c")
            observer_mailbox.wait_for(
                lambda mailbox: (
                    mailbox.command_sequence == command_sequence and
                    mailbox.spin_state == MailboxSpinState.RUNNING),
                description="fixture spin command before conflicting RSP step")

            assert observer.command_response(b"s") == b"E01"

            _interrupt_and_expect_sigint(raw_rsp_client)
            fixture_mailbox.release_spin(command_sequence)
            raw_rsp_client.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(command_sequence)
            _interrupt_and_expect_sigint(raw_rsp_client)
        finally:
            if completed is None:
                try:
                    fixture_mailbox.release_spin(command_sequence, timeout=1.0)
                    raw_rsp_client.send_packet(b"c", timeout=1.0)
                except Exception:
                    pass

    assert completed.spin_state == MailboxSpinState.RELEASED


def test_single_step_from_a_known_function_entry(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check that one instruction can be executed from a known function entry and leaves the target controllable.
    Test method:
    1. Resolve the deterministic step function, save its first instruction, and queue STEP with a fixed argument.
    2. Insert Z1 at the function entry and continue to a T05 stop at that exact address.
    3. Remove Z1, verify the code bytes are unchanged, and record the entry PC.
    4. Send one raw s request and require T05 at a different PC after exactly one instruction.
    5. Continue to mailbox completion, interrupt, and compare the target result with the host's exact computation.
    Expected result: PC advances from the function entry and execution remains controllable through completion.
    Failure indicates: Symbol-address breakpointing or single-step execution is incorrect.
    """
    step_argument = 0x12345678
    breakpoint_address = resolve_elf_symbol(gdbserver_server.configuration.firmware, "gdbserver_test_firmware_step_sequence") & ~1
    breakpoint_code = raw_rsp_client.read_memory(breakpoint_address, 2)
    insert_packet = _breakpoint_packet(b"Z1", breakpoint_address)
    remove_packet = _breakpoint_packet(b"z1", breakpoint_address)
    breakpoint_inserted = False

    try:
        with gdbserver_server.connect_rsp() as observer:
            observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
            command_sequence = fixture_mailbox.request(MailboxCommand.STEP, argument=step_argument)
            assert raw_rsp_client.command(insert_packet) == b"OK"
            breakpoint_inserted = True
            assert raw_rsp_client.read_memory(breakpoint_address, 2) == breakpoint_code
            raw_rsp_client.send_packet(b"c")
            program_counter_before = _expect_sigtrap_at_address(raw_rsp_client, breakpoint_address)
            assert raw_rsp_client.command(remove_packet) == b"OK"
            breakpoint_inserted = False
            assert raw_rsp_client.read_memory(breakpoint_address, 2) == breakpoint_code

            raw_rsp_client.send_packet(b"s")
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T05")
            assert _program_counter(raw_rsp_client) != program_counter_before

            raw_rsp_client.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(command_sequence)
            _interrupt_and_expect_sigint(raw_rsp_client)
    finally:
        if breakpoint_inserted:
            assert raw_rsp_client.command(remove_packet) == b"OK"

    assert completed.step_result == _fixture_step_result(step_argument)


@pytest.mark.skip(reason="raw RSP hardware-breakpoint step-over is not supported; use the external-GDB mirror")
def test_single_step_over_installed_hardware_breakpoint(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient) -> None:
    """
    Purpose: Check that single-stepping at an active hardware breakpoint makes progress instead of repeatedly stopping at the same instruction.
    Test method:
    1. Resolve the deterministic step function, save its instruction bytes, and queue STEP with a fixed argument.
    2. Insert Z1 and continue to T05 at the function entry while leaving the hardware breakpoint installed.
    3. Send one raw s request from the active breakpoint and require T05 at a later instruction in the same function.
    4. Remove Z1, verify unchanged code, continue to completion, and interrupt normally.
    5. Compare the target's step result with the deterministic host calculation.
    Expected result: PC changes from the breakpoint address and the test firmware later completes.
    Failure indicates: Step-over handling repeatedly re-triggers or leaves the target unusable.
    Skip: Raw-RSP step-over at an installed hardware breakpoint is disabled; the Arm GDB scenario covers this behavior.
    """
    step_argument = 0x89ABCDEF
    breakpoint_address = resolve_elf_symbol(gdbserver_server.configuration.firmware, "gdbserver_test_firmware_step_sequence") & ~1
    breakpoint_code = raw_rsp_client.read_memory(breakpoint_address, 2)
    insert_packet = _breakpoint_packet(b"Z1", breakpoint_address)
    remove_packet = _breakpoint_packet(b"z1", breakpoint_address)
    breakpoint_inserted = False

    try:
        with gdbserver_server.connect_rsp() as observer:
            observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
            command_sequence = fixture_mailbox.request(MailboxCommand.STEP, argument=step_argument)
            assert raw_rsp_client.command(insert_packet) == b"OK"
            breakpoint_inserted = True
            assert raw_rsp_client.read_memory(breakpoint_address, 2) == breakpoint_code
            raw_rsp_client.send_packet(b"c")
            program_counter_before = _expect_sigtrap_at_address(raw_rsp_client, breakpoint_address)

            raw_rsp_client.send_packet(b"s")
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T05")
            program_counter_after = _program_counter(raw_rsp_client) & ~1
            assert program_counter_after != program_counter_before
            assert breakpoint_address < program_counter_after < breakpoint_address + 16

            assert raw_rsp_client.command(remove_packet) == b"OK"
            breakpoint_inserted = False
            assert raw_rsp_client.read_memory(breakpoint_address, 2) == breakpoint_code
            raw_rsp_client.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(command_sequence)
            _interrupt_and_expect_sigint(raw_rsp_client)
    finally:
        if breakpoint_inserted:
            assert raw_rsp_client.command(remove_packet) == b"OK"

    assert completed.step_result == _fixture_step_result(step_argument)


@pytest.mark.parametrize(
    ("watchpoint_kind", "fixture_command"),
    (
        (2, MailboxCommand.WATCHPOINT_WRITE),
        (3, MailboxCommand.WATCHPOINT_READ),
        (4, MailboxCommand.WATCHPOINT_READ),
        (4, MailboxCommand.WATCHPOINT_WRITE),
    ),
    ids=("write", "read", "access-read", "access-write"))
def test_watchpoints_stop_for_each_supported_access_type(
        fixture_mailbox: FixtureMailboxClient,
        gdbserver_server: PyOCDGDBServer,
        raw_rsp_client: RSPClient,
        watchpoint_kind: int,
        fixture_command: MailboxCommand) -> None:
    """
    Purpose: Check that the debugger can pause when the test firmware reads or writes a chosen memory location.
    Variants: write (Z2), read (Z3), access-read (Z4), and access-write (Z4).
    Test method:
    1. Select Z2, Z3, or Z4 from the parameter and point it at the mailbox watchpoint field.
    2. Connect an observer, record read/write counters, and insert the selected watchpoint.
    3. For Z2 and Z3, first run the opposite access to completion and prove it does not stop; Z4 has no non-matching access.
    4. Queue the matching target access, continue, and require a T05 stop before mailbox command completion.
    5. Remove the exact watchpoint and resume the interrupted access sequence.
    6. Wait for completion through the observer, interrupt, and require exact read/write counter changes for both phases.
    7. Remove the watchpoint in finally cleanup if the normal removal path did not complete.
    Expected result: Each variant reports the matching watchpoint type and cleanly resumes.
    Failure indicates: Watchpoint programming, stop reporting, removal, or resume is incorrect.
    """
    watchpoint_address = fixture_mailbox.address + WATCHPOINT_VALUE_OFFSET
    insert_packet = _watchpoint_packet(b"Z", watchpoint_kind, watchpoint_address)
    remove_packet = _watchpoint_packet(b"z", watchpoint_kind, watchpoint_address)
    watchpoint_inserted = False

    try:
        with gdbserver_server.connect_rsp() as observer:
            observer_mailbox = FixtureMailboxClient(observer, fixture_mailbox.address)
            before = fixture_mailbox.read()
            assert raw_rsp_client.command(insert_packet) == b"OK"
            watchpoint_inserted = True

            nonmatching_command = None
            if watchpoint_kind == 2:
                nonmatching_command = MailboxCommand.WATCHPOINT_READ
            elif watchpoint_kind == 3:
                nonmatching_command = MailboxCommand.WATCHPOINT_WRITE
            if nonmatching_command is not None:
                nonmatching_sequence = fixture_mailbox.request(nonmatching_command)
                raw_rsp_client.send_packet(b"c")
                nonmatching_completed = observer_mailbox.wait_for_completion(nonmatching_sequence)
                _interrupt_and_expect_sigint(raw_rsp_client)
                assert nonmatching_completed.completed_sequence == nonmatching_sequence

            command_sequence = fixture_mailbox.request(fixture_command)
            raw_rsp_client.send_packet(b"c")
            assert raw_rsp_client.receive_packet(timeout=5.0).startswith(b"T05")
            assert observer_mailbox.read().completed_sequence != command_sequence
            assert raw_rsp_client.command(remove_packet) == b"OK"
            watchpoint_inserted = False

            raw_rsp_client.send_packet(b"c")
            completed = observer_mailbox.wait_for_completion(command_sequence)
            _interrupt_and_expect_sigint(raw_rsp_client)
    finally:
        if watchpoint_inserted:
            assert raw_rsp_client.command(remove_packet) == b"OK"

    expected_reads = int(fixture_command == MailboxCommand.WATCHPOINT_READ)
    expected_writes = int(fixture_command == MailboxCommand.WATCHPOINT_WRITE)
    if watchpoint_kind == 2:
        expected_reads += 1
    elif watchpoint_kind == 3:
        expected_writes += 1
    assert completed.watchpoint_reads == before.watchpoint_reads + expected_reads
    assert completed.watchpoint_writes == before.watchpoint_writes + expected_writes


def _breakpoint_packet(kind: bytes, address: int) -> bytes:
    """Encode a two-byte breakpoint insertion or removal packet."""
    return kind + (",%x,2" % address).encode("ascii")


def _enable_non_stop(client: RSPClient) -> None:
    """Negotiate RSP non-stop mode for one client."""
    assert b"QNonStop+" in client.command(b"qSupported:multiprocess+")
    assert client.command(b"QNonStop:1") == b"OK"


def _expect_non_stop_stop(client: RSPClient, signal: bytes) -> None:
    """Require one non-stop stop notification with the exact signal."""
    notification = client.receive_packet_with_type(timeout=5.0)
    assert notification.packet_type == "%"
    assert notification.payload.startswith(b"Stop:" + signal)


def _expect_non_stop_sigtrap(client: RSPClient) -> None:
    """Require one non-stop SIGTRAP notification."""
    _expect_non_stop_stop(client, b"T05")


def _execute_to_sigtrap(client: RSPClient, packet: bytes, *,
                        non_stop: bool) -> int:
    """Execute one RSP action and return its SIGTRAP program counter."""
    if non_stop:
        assert client.command(packet) == b"OK"
        _expect_non_stop_sigtrap(client)
    else:
        client.send_packet(packet)
        assert client.receive_packet(timeout=5.0).startswith(b"T05")
    return _program_counter(client) & ~1


def _watchpoint_packet(operation: bytes, kind: int, address: int) -> bytes:
    """Encode a four-byte watchpoint insertion or removal packet."""
    return (operation + str(kind).encode("ascii") +
            (",%x,4" % address).encode("ascii"))


def _run_range_step_breakpoint_scenario(
        fixture_mailbox: FixtureMailboxClient,
        server: PyOCDGDBServer,
        client: RSPClient,
        breakpoint_kind: bytes | None,
        non_stop: bool) -> None:
    """Exercise one breakpoint source inside a deterministic RSP range step."""
    if breakpoint_kind not in (None, b"Z0", b"Z1"):
        raise ValueError("unsupported range-step breakpoint kind: %r" % breakpoint_kind)

    uses_flash = breakpoint_kind == b"Z1"
    start = (
        resolve_elf_symbol(server.configuration.firmware, "gdbserver_test_firmware_range_step_code") & ~1
        if uses_flash else fixture_mailbox.ram_window_address)
    breakpoint_address = start + _RANGE_STEP_BREAKPOINT_OFFSET
    end = start + _RANGE_STEP_END_OFFSET
    test_code = bytearray(_RANGE_STEP_CODE)
    if breakpoint_kind is None:
        test_code[_RANGE_STEP_BREAKPOINT_OFFSET:
                  _RANGE_STEP_BREAKPOINT_OFFSET + 2] = _RANGE_STEP_BKPT
    expected_code = bytes(test_code)
    original_pc = _program_counter(client)
    original_ram = None if uses_flash else client.read_memory(start, len(expected_code))
    remove_packet = None
    breakpoint_inserted = False

    try:
        if non_stop:
            _enable_non_stop(client)
        if original_ram is not None:
            client.write_memory_binary(start, expected_code)
        assert client.read_memory(start, len(expected_code)) == expected_code
        client.write_register(15, start.to_bytes(4, byteorder="little"))
        assert _program_counter(client) & ~1 == start

        if breakpoint_kind is not None:
            insert_packet = _breakpoint_packet(breakpoint_kind, breakpoint_address)
            remove_packet = _breakpoint_packet(b"z" + breakpoint_kind[1:], breakpoint_address)
            assert client.command(insert_packet) == b"OK"
            breakpoint_inserted = True

        stopped_pc = _range_step(client, start, end, non_stop=non_stop)
        assert stopped_pc == breakpoint_address
        assert start <= stopped_pc < end
        assert client.read_memory(start, len(expected_code)) == expected_code

        if remove_packet is not None:
            assert client.command(remove_packet) == b"OK"
            breakpoint_inserted = False

        assert _range_step(client, stopped_pc, end, non_stop=non_stop) == end
        assert client.read_memory(start, len(expected_code)) == expected_code
    finally:
        if breakpoint_inserted and remove_packet is not None:
            assert client.command(remove_packet) == b"OK"
        if original_ram is not None:
            client.write_memory(start, original_ram)
        client.write_register(15, original_pc.to_bytes(4, byteorder="little"))


def _range_step(client: RSPClient, start: int, end: int, *,
                non_stop: bool) -> int:
    """Issue one RSP range step and return its stopped program counter."""
    packet = ("vCont;r%x,%x" % (start, end)).encode("ascii")
    if non_stop:
        assert client.command(packet) == b"OK"
        _expect_non_stop_sigtrap(client)
        stopped_pc = _program_counter(client) & ~1
        assert client.command(b"vStopped") == b"OK"
        return stopped_pc

    client.send_packet(packet)
    assert client.receive_packet(timeout=5.0).startswith(b"T05")
    return _program_counter(client) & ~1


def _interrupt_and_expect_sigint(client: RSPClient) -> None:
    """Stop an intentionally running fixture and require the Ctrl-C response."""
    client.interrupt()
    assert client.receive_packet(timeout=5.0).startswith(b"T02")


def _expect_sigtrap_at_address(client: RSPClient, address: int) -> int:
    """Require SIGTRAP at the exact address and return its PC."""
    assert client.receive_packet(timeout=5.0).startswith(b"T05")
    program_counter = _program_counter(client) & ~1
    assert program_counter == address
    return program_counter


def _program_counter(client: RSPClient) -> int:
    """Extract the Cortex-M PC from the standard GDB register block."""
    registers = client.read_registers()
    program_counter_offset = 15 * 4
    assert len(registers) >= program_counter_offset + 4
    return int.from_bytes(registers[program_counter_offset:program_counter_offset + 4], byteorder="little")


def _fixture_step_result(value: int) -> int:
    """Match the fixture's deliberately simple no-inline step computation."""
    result = ((value ^ 0xA5A5A5A5) + 0x10203040) & 0xFFFFFFFF
    return ((result << 3) | (result >> 29)) & 0xFFFFFFFF
