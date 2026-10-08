# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest.mock import Mock

import pytest

from pyocd.core.target import Target
from pyocd.coresight.cortex_m import CortexM
from pyocd.gdbserver.gdbserver import GDBServer


@pytest.mark.parametrize("instruction, exclude_semihosting_breakpoint, skipped", [
    (0xbeab, True, False),
    (0xbeab, False, True),
    (0xbe00, True, True),
    (0xbf00, False, False),
])
def test_skip_breakpoint_instruction(instruction, exclude_semihosting_breakpoint, skipped):
    core = Mock()
    core._run_token = 0
    core.read_core_register.return_value = 0x1000
    core.find_breakpoint.return_value = None
    core.read16.return_value = instruction

    assert CortexM.skip_breakpoint_instruction(core, exclude_semihosting_breakpoint) is skipped

    if skipped:
        core.write_core_register.assert_called_once_with('pc', 0x1002)
        assert core._run_token == 1
    else:
        core.write_core_register.assert_not_called()
        assert core._run_token == 0


def test_step_skips_starting_breakpoint_without_physical_step():
    server = Mock()
    server.target.skip_breakpoint_instruction.return_value = True
    server.target.read_core_register.return_value = 0x1002
    server._read_target_state.return_value = Target.State.HALTED
    server.enable_semihosting = True
    client = Mock()

    GDBServer._execute_step(server, client)

    server.target.skip_breakpoint_instruction.assert_called_once_with(exclude_semihosting_breakpoint=True)
    server.target.step.assert_not_called()


def test_resume_skips_starting_breakpoint_before_running():
    server = Mock()
    server._is_halted = True
    server._read_target_state.return_value = Target.State.HALTED
    server.enable_semihosting = True
    calls = []
    server.target.skip_breakpoint_instruction.side_effect = lambda **kwargs: calls.append('skip')
    server.trace_capture.side_effect = lambda: calls.append('capture')
    server.target.resume.side_effect = lambda: calls.append('resume')

    GDBServer._resume_target(server)

    assert calls == ['skip', 'capture', 'resume']
    server._read_target_state.assert_called_once_with()
    server.target.skip_breakpoint_instruction.assert_called_once_with(exclude_semihosting_breakpoint=True)
    assert server._is_halted is False


def test_range_step_reports_breakpoint_after_semihosting():
    server = Mock()
    server.target.skip_breakpoint_instruction.return_value = False
    server.target.read_core_register.return_value = 0x1002
    server._read_target_state.return_value = Target.State.HALTED
    server._handle_semihosting.side_effect = [True, False]
    server.enable_semihosting = True
    server.step_into_interrupt = False
    client = Mock()
    client.is_connection_closed = False
    client.shutdown_event.is_set.return_value = False
    client.is_interrupted.return_value = False

    GDBServer._execute_step(server, client, 0x1000, 0x1010)

    assert server.target.step.call_count == 2
    server.target.skip_breakpoint_instruction.assert_called_once_with(exclude_semihosting_breakpoint=True)
