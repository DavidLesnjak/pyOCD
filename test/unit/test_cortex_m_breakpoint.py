# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Cortex-M breakpoint instruction handling tests."""

from unittest.mock import Mock

from pyocd.coresight.cortex_m import CortexM


def test_skip_breakpoint_instruction_clears_sticky_bkpt_cause():
    core = Mock(spec=CortexM)
    core.read32.return_value = CortexM.DFSR_BKPT
    core.read_core_register.return_value = 0x1000
    core.find_breakpoint.return_value = None
    core.read16.return_value = 0xbe00

    assert CortexM.skip_breakpoint_instruction(core)

    core.write_core_register.assert_called_once_with('pc', 0x1002)
    core.write32.assert_called_once_with(CortexM.DFSR, CortexM.DFSR_BKPT)
