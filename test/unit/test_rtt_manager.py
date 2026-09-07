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

import logging
from unittest.mock import Mock

from pyocd.utility.rtt_manager import RTTConfig, RTTManager


def _make_manager(control_block=None):
    session = Mock()
    core = Mock()
    session.board.target.cores = {0: core}

    rtt_config = Mock(spec=RTTConfig)
    rtt_config.has_rtt_config = True
    rtt_config.channels = ((0, "server", 1234, None),)
    rtt_config.control_block = control_block

    return RTTManager(session=session, core=0, rtt_config=rtt_config), session


def test_start_server_accepts_missing_rtt_configuration():
    session = Mock()
    manager = RTTManager(session=session, rtt_config=None)

    assert manager.start_server() is None


def test_start_server_retries_control_block_detection_after_one_warning(caplog):
    manager, _ = _make_manager(control_block=(0x20000000, None, False))
    rtt_server = Mock()
    manager._start_rtt_server = Mock(side_effect=(None, rtt_server))

    with caplog.at_level(logging.WARNING, logger="pyocd.utility.rtt_manager"):
        assert manager.start_server() is None
        assert manager.start_server() is rtt_server

    assert manager._start_rtt_server.call_count == 2
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "failed to find RTT control block with specified address 0x20000000" in warnings[0].message


def test_start_server_logs_symbol_lookup_exception_once(caplog):
    manager, session = _make_manager()
    session.board.target.get_output.side_effect = RuntimeError("test symbol lookup failure")

    with caplog.at_level(logging.WARNING, logger="pyocd.utility.rtt_manager"):
        assert manager.start_server() is None
        assert manager.start_server() is None

    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "failed to get _SEGGER_RTT symbol address from ELF" in warnings[0].message
