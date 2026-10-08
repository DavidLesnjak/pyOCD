# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Cortex-M breakpoint instruction handling tests."""

from unittest.mock import Mock

import pytest

from pyocd.core import exceptions
from pyocd.coresight.cortex_m import CortexM


def test_skip_breakpoint_instruction_advances_pc_without_clearing_cause():
    core = Mock(spec=CortexM)
    core.read_core_register.return_value = 0x1000
    core.read16.return_value = 0xbe00

    assert CortexM.skip_breakpoint_instruction(core)

    core.read_core_register.assert_called_once_with('pc')
    core.find_breakpoint.assert_not_called()
    core.read16.assert_called_once_with(0x1000)
    core.read_memory.assert_not_called()
    core.write_core_register.assert_called_once_with('pc', 0x1002)
    core.read32.assert_not_called()
    core.write32.assert_not_called()
    core.write_memory.assert_not_called()
    core.clear_debug_cause_bits.assert_not_called()


def test_skip_breakpoint_instruction_propagates_core_register_error():
    core = Mock(spec=CortexM)
    error = exceptions.CoreRegisterAccessError("core is running")
    core.read_core_register.side_effect = error

    with pytest.raises(exceptions.CoreRegisterAccessError) as raised:
        CortexM.skip_breakpoint_instruction(core)

    assert raised.value is error
    core.read_core_register.assert_called_once_with('pc')
    core.read16.assert_not_called()
    core.write_core_register.assert_not_called()
