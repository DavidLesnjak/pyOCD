# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Cortex-M breakpoint instruction handling tests."""

from unittest.mock import Mock

from pyocd.coresight.cortex_m import CortexM


def test_step_over_breakpoint_instruction_advances_pc_without_clearing_cause():
    core = Mock(spec=CortexM)
    core._run_token = 0
    core.read_memory.return_value = CortexM.DFSR_BKPT
    core.read_core_register.return_value = 0x1000
    core.find_breakpoint.return_value = None
    core.read16.return_value = 0xbe00

    assert CortexM.step_over_breakpoint_instruction(core, 0x1000)

    core.read_memory.assert_called_once_with(CortexM.DFSR)
    core.write_core_register.assert_called_once_with('pc', 0x1002)
    assert core._run_token == 1
    core.read32.assert_not_called()
    core.write32.assert_not_called()
    core.write_memory.assert_not_called()
    core.clear_debug_cause_bits.assert_not_called()


def test_step_over_breakpoint_instruction_does_not_skip_new_bkpt():
    core = Mock(spec=CortexM)
    core._run_token = 0
    core.read_memory.return_value = CortexM.DFSR_BKPT
    core.read_core_register.return_value = 0x1002

    assert not CortexM.step_over_breakpoint_instruction(core, 0x1000)

    core.read_memory.assert_called_once_with(CortexM.DFSR)
    core.find_breakpoint.assert_not_called()
    core.read16.assert_not_called()
    core.write_core_register.assert_not_called()
    assert core._run_token == 0
