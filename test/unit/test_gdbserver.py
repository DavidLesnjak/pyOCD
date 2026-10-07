# pyOCD debugger
# Copyright (c) 2021 Chris Reed
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

import errno
import logging
import socket
import threading
from itertools import permutations
from unittest.mock import Mock, patch

from pyocd.core import exceptions
from pyocd.core.target import Target
from pyocd.coresight.cortex_m import CortexM
from pyocd.gdbserver import signals
from pyocd.gdbserver.gdbserver import (
    _ClientLogFilter,
    GDBClientSession,
    GDBServer,
    escape,
    unescape,
)
from pyocd.gdbserver.packet_io import (
    ConnectionClosedException,
    GDBServerPacketIOThread,
    checksum,
)
from pyocd.gdbserver.syscall import GDBSyscallIOHandler


def _make_state_server(initial_state=Target.State.RUNNING):
    server = object.__new__(GDBServer)
    server.lock = threading.RLock()
    server._is_halted = initial_state == Target.State.HALTED
    server._pc_before_run = None
    server._active_run_client = None
    server._cleanup_lock = threading.RLock()
    server._did_cleanup = False
    server._semihosting_client = None
    server.enable_semihosting = False
    server.semihost_use_syscalls = False
    server.semihost = Mock()
    server.semihost.check_and_handle_semihost_request.return_value = False
    server.rtt_server = None
    server._rtt_manager = None
    server.target = Mock()
    server.target.get_state.return_value = initial_state
    server.target.step_over_breakpoint_instruction.return_value = False
    server.step_into_interrupt = False
    server.thread_provider = None
    server.target.get_halt_reason.return_value = Target.HaltReason.DEBUG
    server.target_context = Mock()
    server.trace_capture = Mock()
    server.trace_flush = Mock()
    server.core = 0
    server.shutdown_event = threading.Event()
    server.session = Mock()
    server.session.log_tracebacks = False
    return server


def _make_client(index):
    client = Mock()
    client.index = index
    client.is_attached_to_target = True
    client.is_connection_closed = False
    client.is_socket_connected = True
    client.shutdown_event = threading.Event()
    client._awaiting_vstopped = False
    client.non_stop = False
    client.is_interrupted.return_value = False
    client.wait_for_interrupt.return_value = False
    return client


def _configure_client_lifecycle(server, clients, persist=False):
    server.client_sessions_lock = threading.Lock()
    server.client_sessions = list(clients)
    server._semihosting_client = None
    server.thread_provider = Mock()
    server.did_init_thread_providers = True
    server.first_run_after_reset_or_flash = False
    server.persist = persist
    server.trace_capture = Mock()


def _make_halt_server(instruction=0xbe00, managed_breakpoint=None):
    server = _make_state_server(Target.State.HALTED)
    server.enable_semihosting = True
    server.target_context = Mock()
    server.target_context.core = Mock(spec=CortexM)
    server.target_context.core.find_breakpoint.return_value = managed_breakpoint
    server.target.step_over_breakpoint_instruction.return_value = (
            managed_breakpoint is None and (instruction & 0xff00) == 0xbe00)
    server.target_context.read32.return_value = CortexM.DFSR_BKPT
    server.target_context.read_core_register.return_value = 0x1000
    server.target_context.read16.return_value = instruction
    server._handle_semihosting = Mock(return_value=False)
    return server


def _configure_semihost_bkpt(server):
    server.target_context.core = Mock(spec=CortexM)
    server.target_context.core.find_breakpoint.return_value = None
    server.target.step_over_breakpoint_instruction.return_value = True
    server.target_context.read32.return_value = CortexM.DFSR_BKPT
    server.target_context.read_core_register.return_value = 0x1000
    server.target_context.read16.return_value = 0xbeab

# escaped chars: '#$}*'
# escaped by prefixing with '}' and xor'ing the char with 0x20
#
# '#' (0x23) -> '}\x03'
# '$' (0x24) -> '}\x04'
# '}' (0x7d) -> '}]'
# '*' (0x2a) -> '}\x0a'

class TestGdbServerEscaping:
    def test_escape_transparent(self):
        """Verify that escaping leaves ordinary bytes unchanged."""
        assert escape(b"hello") == b"hello"

    def test_escape_individual(self):
        """Verify that escaping encodes each reserved RSP character inside text."""
        assert escape(b"hello#foo") == b"hello}\x03foo"
        assert escape(b"hello$foo") == b"hello}\x04foo"
        assert escape(b"hello}foo") == b"hello}]foo"
        assert escape(b"hello*foo") == b"hello}\x0afoo"

    def test_escape_single(self):
        """Verify that escaping encodes a single reserved RSP character."""
        assert escape(b"#") == b"}\x03"
        assert escape(b"$") == b"}\x04"
        assert escape(b"}") == b"}]"
        assert escape(b"*") == b"}\x0a"

    def test_escape_combined(self):
        """Verify that escaping handles adjacent and repeated reserved characters."""
        assert escape(b"#$}*") == b"}\x03}\x04}]}\x0a"
        assert escape(b'}}}') == b"}]}]}]"

    def test_unescape_transparent(self):
        """Verify that unescaping leaves ordinary bytes unchanged."""
        assert unescape(b"bytes") == list(b"bytes")

    def test_unescape_individual(self):
        """Verify that unescaping decodes each reserved RSP character inside text."""
        assert unescape(b"hello}\x03foo") == list(b"hello#foo")
        assert unescape(b"hello}\x04foo") == list(b"hello$foo")
        assert unescape(b"hello}]foo") == list(b"hello}foo")
        assert unescape(b"hello}\x0afoo") == list(b"hello*foo")

    def test_unescape_single(self):
        """Verify that unescaping decodes a single escaped RSP character."""
        assert unescape(b"}\x03") == [b'#'[0]]
        assert unescape(b"}\x04") == [b'$'[0]]
        assert unescape(b"}]") == [b'}'[0]]
        assert unescape(b"}\x0a") == [b'*'[0]]

    def test_unescape_combined(self):
        """Verify that unescaping handles adjacent and repeated escaped characters."""
        assert unescape(b"}\x03}\x04}]}\x0a") == list(b"#$}*")
        assert unescape(b"}]}]}]") == list(b"}}}")


class TestClientLogFilter:
    def test_explicit_client_index_precedes_thread_index(self):
        """Verify an explicitly supplied client index identifies cross-thread log records."""
        log_filter = _ClientLogFilter()
        log_filter.set_client(1)
        record = logging.LogRecord("test", logging.DEBUG, __file__, 1, "message %s", ("value",), None)
        record.client_index = 2

        assert log_filter.filter(record)
        assert record.getMessage() == "Client 2: message value"

    def test_thread_client_index_is_fallback(self):
        """Verify ordinary client-thread records retain their implicit client index."""
        log_filter = _ClientLogFilter()
        log_filter.set_client(1)
        record = logging.LogRecord("test", logging.DEBUG, __file__, 1, "message", (), None)

        assert log_filter.filter(record)
        assert record.getMessage() == "Client 1: message"


class TestGdbServerHaltFinalization:
    def test_repeated_halt_observation_leaves_literal_bkpt_at_address(self):
        """Verify repeated observations leave an embedded BKPT visible at its address."""
        server = _make_halt_server()
        server._is_halted = False
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()
            if not server._is_halted:
                server._read_and_process_target_state()

        server.target_context.write_core_register.assert_not_called()
        server.target_context.write32.assert_not_called()
        server._handle_semihosting.assert_called_once_with(client=None)
        server.target.step_over_breakpoint_instruction.assert_not_called()

    def test_disabled_semihosting_still_processes_breakpoint_after_run(self):
        """A stopped BKPT can be skipped even when semihosting is disabled."""
        server = _make_halt_server()
        server.enable_semihosting = False
        server._is_halted = False
        server._pc_before_run = 0x1000
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        server._handle_semihosting.assert_not_called()
        server.target.step_over_breakpoint_instruction.assert_called_once_with(pc=0x1000)
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_disabled_semihosting_leaves_observed_halt_visible(self):
        """A halted target remains halted when semihosting is disabled."""
        server = _make_halt_server()
        server.enable_semihosting = False
        server._handle_semihosting.return_value = True
        server._is_halted = False

        with server.lock:
            server._read_and_process_target_state()

        server._handle_semihosting.assert_not_called()
        server.target.resume.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_literal_bkpt_is_processed_for_each_resume(self):
        """Each new run saves a PC for the following BKPT halt."""
        server = _make_halt_server()
        server.target.read_core_register.return_value = 0x1000
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            for _ in range(2):
                server._resume_target()
                server._read_and_process_target_state()

        assert server.target.step_over_breakpoint_instruction.call_count == 2
        server.target.step_over_breakpoint_instruction.assert_called_with(pc=0x1000)
        assert server.target.resume.call_count == 4
        assert not server._is_halted

    def test_managed_breakpoint_is_not_advanced(self):
        """A rejected breakpoint remains visible and ends the run."""
        server = _make_halt_server(managed_breakpoint=Mock())
        server._is_halted = False
        server._pc_before_run = 0x1000
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        server._handle_semihosting.assert_called_once_with(client=None)
        server.target.step_over_breakpoint_instruction.assert_called_once_with(pc=0x1000)
        server.target.resume.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_rejected_breakpoint_step_over_leaves_pc_unchanged(self):
        """A failed BKPT skip does not resume the target."""
        server = _make_halt_server()
        server._is_halted = False
        server._pc_before_run = 0x1000
        server.target.step_over_breakpoint_instruction.return_value = False
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        server.target.step_over_breakpoint_instruction.assert_called_once_with(pc=0x1000)
        server.target.resume.assert_not_called()
        assert server._is_halted

    def test_non_bkpt_instruction_is_not_advanced(self):
        """An ordinary halt is reported when the core rejects BKPT step-over."""
        server = _make_halt_server(instruction=0x46c0)
        server._is_halted = False
        server._pc_before_run = 0x1000
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        server.target.step_over_breakpoint_instruction.assert_called_once_with(pc=0x1000)
        server.target.resume.assert_not_called()
        server.trace_flush.assert_called_once_with()

    def test_semihosting_precedes_literal_bkpt_handling(self):
        """A handled semihost request resumes without a generic BKPT skip."""
        server = _make_halt_server(instruction=0xbeab)
        server._is_halted = False
        server._pc_before_run = 0x1000
        server._handle_semihosting.return_value = True
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        server._handle_semihosting.assert_called_once_with(client=None)
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_pending_interrupt_does_not_block_semihosting(self):
        """Verify a pending raw Ctrl-C does not prevent transparent semihosting."""
        server = _make_halt_server(instruction=0xbeab)
        server._handle_semihosting.return_value = True
        server._is_halted = False
        client = _make_client(1)
        client.is_interrupted.return_value = True

        with server.lock:
            server._read_and_process_target_state(client=client)

        server._handle_semihosting.assert_called_once_with(client=client)
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.target_context.write_core_register.assert_not_called()
        server.target_context.write32.assert_not_called()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_interrupt_during_semihosting_resumes_consumed_request(self):
        """Verify an interrupt received during semihosting acts on a distinct execution interval."""
        server = _make_halt_server(instruction=0xbeab)
        server._is_halted = False
        client = _make_client(1)

        def _handle_semihosting(*, client):
            client.is_interrupted.return_value = True
            return True

        server._handle_semihosting.side_effect = _handle_semihosting

        with server.lock:
            server._read_and_process_target_state(client=client)

        server._handle_semihosting.assert_called_once_with(client=client)
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.target_context.write32.assert_not_called()
        server.target.resume.assert_called_once_with()
        assert client.is_interrupted()
        assert not server._is_halted

    def test_unhandled_semihosting_bkpt_is_advanced_only_after_run(self):
        """A BKPT without a saved run PC remains visible."""
        server = _make_halt_server(instruction=0xbeab)
        server._is_halted = False
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        server._handle_semihosting.assert_called_once_with(client=None)
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.target.resume.assert_not_called()
        assert server._is_halted

    def test_non_stop_continue_advances_literal_bkpt_after_resume(self):
        """A non-stop continue reports OK, then skips a BKPT at its starting PC."""
        server = _make_halt_server()
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.target.read_core_register.return_value = 0x1000
        server.target.get_state.return_value = Target.State.HALTED
        events = []
        server.target.step_over_breakpoint_instruction.side_effect = (
                lambda pc: events.append(('advance', pc)) or True)
        server.target.resume.side_effect = lambda: events.append('resume')
        client = _make_client(1)
        client.non_stop = True

        assert server.v_cont(client, b'Cont;c') == b'OK'
        with server.lock:
            server._read_and_process_target_state(client=client)

        assert events == ['resume', ('advance', 0x1000), 'resume']
        assert server._pc_before_run is None
        assert not server._is_halted

    def test_step_consumes_literal_bkpt_after_physical_step(self):
        """A single step executes and consumes a BKPT without stepping the next instruction."""
        server = _make_halt_server()
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        pc = [0x1000]
        events = []
        server.target.read_core_register.side_effect = lambda _register: pc[0]
        server.target.step.side_effect = lambda *_args, **_kwargs: events.append("step")

        def _step_over(pc_before_step):
            assert pc_before_step == pc[0] == 0x1000
            events.append("advance")
            pc[0] += 2
            return True

        server.target.step_over_breakpoint_instruction.side_effect = _step_over
        client = _make_client(1)

        assert server.step(client, b's') == b'T05thread:1;'

        assert events == ["step", "advance"]
        assert pc[0] == 0x1002
        server.target.step.assert_called_once()
        server.target.step_over_breakpoint_instruction.assert_called_once_with(0x1000)
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_step_semihost_failure_after_physical_step_preserves_halt(self):
        """A semihost error after stepping leaves the cached halt intact."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        semihost_error = exceptions.TransferError('test semihost check failure')
        server.semihost.check_and_handle_semihost_request.side_effect = semihost_error
        client = _make_client(1)

        try:
            server.step(client, b's')
        except exceptions.TransferError as error:
            assert error is semihost_error
        else:
            assert False, 'expected semihost check to fail'

        server.target.step.assert_called_once()
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_not_called()
        assert server._is_halted
        assert server._active_run_client is None

    def test_step_semihost_failure_leaves_run_ownership_released(self):
        """A post-step handler exception releases the client's run ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        semihost_error = exceptions.TransferError('test post-step semihost failure')
        server._handle_semihosting = Mock(side_effect=semihost_error)
        client = _make_client(1)

        try:
            server.step(client, b's')
        except exceptions.TransferError as error:
            assert error is semihost_error
        else:
            assert False, 'expected post-step semihost check to fail'

        server.target.step.assert_called_once()
        server._handle_semihosting.assert_called_once_with(client=client)
        server.target.get_state.assert_called_once_with()
        server.trace_flush.assert_not_called()
        assert server._is_halted
        assert server._active_run_client is None

    def test_state_processing_finalizes_literal_bkpt_without_resuming(self):
        """Verify clientless halt servicing leaves an unmanaged literal BKPT visible."""
        server = _make_halt_server()
        server._is_halted = False
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        server.target_context.write_core_register.assert_not_called()
        server.target_context.write32.assert_not_called()
        server.target.resume.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted


class TestGdbServerRuntimeService:
    def test_constructor_uses_supplied_running_state(self):
        """A supplied run state avoids a target read during construction."""
        for target_running in (False, True):
            session = Mock()
            session.options.get.side_effect = lambda name: {
                'gdbserver_port': 0,
                'vector_catch': 'none',
            }.get(name, False)
            session.board.target.cores = {0: session.board.target}
            session.board.target.get_state.side_effect = AssertionError("unexpected state read")

            with patch('pyocd.gdbserver.gdbserver.ListenerSocket'), \
                    patch('pyocd.gdbserver.gdbserver.RTTConfig') as rtt_config, \
                    patch('pyocd.gdbserver.gdbserver.StdioHandler'), \
                    patch('pyocd.gdbserver.gdbserver.semihost.SemihostAgent'), \
                    patch.object(GDBServer, '_init_remote_commands'), \
                    patch.object(GDBServer, '_run_service_thread') as service:
                rtt_config.return_value.channels = None
                server = GDBServer(session, core=0, target_running=target_running)
                server._service_thread.join(1.0)

            assert server._is_halted is not target_running
            server.target.get_state.assert_not_called()
            service.assert_called_once_with()

    def test_constructor_uses_shared_rtt_configuration(self):
        """A launcher-provided RTT configuration is reused without parsing it again."""
        session = Mock()
        session.options.get.side_effect = lambda name: {
            'gdbserver_port': 0,
            'vector_catch': 'none',
        }.get(name, False)
        session.board.target.cores = {0: session.board.target}
        rtt_config = Mock(channels=((1, 'systemview', None, None),))
        systemview_config = Mock()

        with patch('pyocd.gdbserver.gdbserver.ListenerSocket'), \
                patch('pyocd.gdbserver.gdbserver.RTTConfig') as make_rtt_config, \
                patch('pyocd.gdbserver.gdbserver.RTTManager') as make_rtt_manager, \
                patch('pyocd.gdbserver.gdbserver.StdioHandler'), \
                patch('pyocd.gdbserver.gdbserver.semihost.SemihostAgent'), \
                patch.object(GDBServer, '_init_remote_commands'), \
                patch.object(GDBServer, '_run_service_thread'):
            server = GDBServer(session, core=0, target_running=False,
                               rtt_config=rtt_config, systemview_config=systemview_config)
            server._service_thread.join(1.0)

        make_rtt_config.assert_not_called()
        make_rtt_manager.assert_called_once_with(session=session, core=0,
                                                  rtt_config=rtt_config, systemview_config=systemview_config)

    def test_only_one_client_can_have_an_active_run(self):
        """Ownership is exclusive, and releasing it does not acknowledge a pending stop."""
        server = _make_state_server()
        first_client = _make_client(1)
        second_client = _make_client(2)

        assert server._claim_active_run_client(first_client)
        with patch('pyocd.gdbserver.gdbserver.LOG.warning') as warning_log:
            assert not server._claim_active_run_client(second_client)
        warning_log.assert_called_once_with("Cannot start execution while client %d has an active run",
                first_client.index)
        assert server._active_run_client is first_client

        server._release_active_run_client(second_client)
        assert server._active_run_client is first_client

        first_client._awaiting_vstopped = True
        server._release_active_run_client(first_client)
        assert server._active_run_client is None
        assert first_client._awaiting_vstopped
        assert server._claim_active_run_client(second_client)

    def test_repeated_claim_is_rejected_until_release(self):
        """An owner must finish its current run before claiming another one."""
        server = _make_state_server(Target.State.HALTED)
        client = _make_client(1)

        assert server._claim_active_run_client(client)
        assert not server._claim_active_run_client(client)
        assert server._active_run_client is client
        server._release_active_run_client(client)
        assert server._claim_active_run_client(client)

    def test_resume_target_records_pc_without_reading_state(self):
        """Resume uses the current PC without a separate target state read."""
        server = _make_state_server(Target.State.HALTED)
        server.target.read_core_register.return_value = 0x1000

        server._resume_target()

        server.target.read_core_register.assert_called_once_with('pc')
        server.target.get_state.assert_not_called()
        assert server._pc_before_run == 0x1000
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_resume_target_continues_after_pc_transfer_error(self):
        """A failed PC read does not prevent the requested resume."""
        server = _make_state_server(Target.State.HALTED)
        server._pc_before_run = 0x1000
        server.target.read_core_register.side_effect = exceptions.TransferError("PC unavailable")

        server._resume_target()

        server.target.read_core_register.assert_called_once_with('pc')
        server.target.get_state.assert_not_called()
        assert server._pc_before_run is None
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_service_loop_tracks_sleeping_then_halted_without_clients(self):
        """Verify that background polling tracks sleep and halt states without clients."""
        server = _make_state_server()
        server._STATE_INTERVAL = 0
        states = iter((Target.State.SLEEPING, Target.State.HALTED))

        def _get_state():
            state = next(states)
            if state == Target.State.HALTED:
                server.shutdown_event.set()
            return state

        server.target.get_state.side_effect = _get_state

        server._run_service_thread()

        assert server._is_halted
        server.trace_flush.assert_called_once_with()

    def test_service_loop_retries_after_failed_state_read(self, caplog):
        """A failed state read does not prevent a later halt from being processed."""
        server = _make_state_server()
        server._STATE_INTERVAL = 0
        server.session.options.get.return_value = 1.0
        call_count = 0

        def _get_state():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Target.State.RUNNING
            if call_count == 2:
                raise exceptions.TransferError("test transfer error")
            server.shutdown_event.set()
            return Target.State.HALTED

        server.target.get_state.side_effect = _get_state

        with caplog.at_level(logging.DEBUG):
            server._run_service_thread()

        assert call_count == 3
        assert server._is_halted
        assert "Target status read succeeded after transfer error" in caplog.text
        assert "exceeded the retry timeout" not in caplog.text

    def test_service_loop_logs_expired_retry_and_keeps_polling(self, caplog):
        """An expired retry window is logged, then polling continues."""
        server = _make_state_server()
        server._STATE_INTERVAL = 0
        server.session.options.get.return_value = 1.0
        call_count = 0

        def _get_state():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Target.State.RUNNING
            if call_count == 3:
                server.shutdown_event.set()
            raise exceptions.TransferError("test persistent transfer error")

        server.target.get_state.side_effect = _get_state

        with patch('pyocd.utility.timeout.time', side_effect=(0.0, 2.0, 2.1)):
            with caplog.at_level(logging.DEBUG):
                server._run_service_thread()

        assert call_count == 3
        assert caplog.text.count("exceeded the retry timeout; continuing service") == 1
        assert not server._is_halted

    def test_service_loop_skips_state_reads_while_cached_halted(self):
        """RTT keeps running without target state reads after a known halt."""
        server = _make_state_server(Target.State.HALTED)
        server._STATE_INTERVAL = 0
        server._RTT_INTERVAL = 0
        server.rtt_server = Mock(running=True)
        polls = []

        def _poll():
            polls.append(server._is_halted)
            if len(polls) == 2:
                server.shutdown_event.set()

        server.rtt_server.poll.side_effect = _poll

        server._run_service_thread()

        assert polls == [True, True]
        server.target.get_state.assert_not_called()
        assert server._is_halted
        server.trace_flush.assert_not_called()

    def test_service_thread_stops_without_main_server_thread(self):
        """Verify that the service thread can stop before the main server thread starts."""
        server = _make_state_server()
        server._service_thread = threading.Thread(target=server.shutdown_event.wait)
        server._service_thread.start()

        server._stop_service_thread()

        assert server.shutdown_event.is_set()
        assert server._service_thread is None

    def test_only_active_client_receives_stop_notification(self):
        """Verify that only the client owning the run receives its stop notification."""
        server = _make_state_server(Target.State.HALTED)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        active_client = _make_client(1)
        passive_client = _make_client(2)
        active_client.non_stop = True
        passive_client.non_stop = True
        server._active_run_client = active_client
        payload = b'Stop:T05thread:1;'

        server.service_non_stop_client(passive_client)
        server.service_non_stop_client(active_client)
        server.service_non_stop_client(active_client)

        passive_client.send.assert_not_called()
        active_client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        server.get_t_response.assert_called_once_with(active_client, forceSignal=None)
        assert active_client._awaiting_vstopped
        assert server._active_run_client is active_client

        server.v_command(active_client, b'Stopped')
        server.service_non_stop_client(active_client)
        active_client.send.assert_called_once()
        assert server._active_run_client is None

    def test_vstopped_completes_active_run(self):
        """Verify that vStopped acknowledges a pending stop and completes the run."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(return_value=b'$OK#9a')
        client = _make_client(1)
        client._awaiting_vstopped = True
        server._active_run_client = client

        response = server.v_command(client, b'Stopped')

        assert response == b'$OK#9a'
        assert not client._awaiting_vstopped
        assert server._active_run_client is None

    def test_unsolicited_vstopped_does_not_end_active_run(self):
        """Verify that vStopped without a pending notification does not end a run."""
        server = _make_state_server()
        server.create_rsp_packet = Mock(return_value=b'$OK#9a')
        client = _make_client(1)
        server._active_run_client = client

        response = server.v_command(client, b'Stopped')

        assert response == b'$OK#9a'
        assert server._active_run_client is client

    def test_stop_query_keeps_active_run_until_vstopped(self):
        """Verify that a stop query reports the halt but keeps ownership.
        Ownership is released only after the client acknowledges it with vStopped."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(return_value=b'$T05#b9')
        server.get_t_response = Mock(return_value=b'T05')
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client

        response = server.stop_reason_query(client)

        assert response == b'$T05#b9'
        assert client._awaiting_vstopped
        assert server._active_run_client is client

    def test_legacy_continue_is_unsupported_for_non_stop(self):
        """Legacy c/C must not resume or disturb pending non-stop ownership."""
        server = _make_state_server(Target.State.HALTED)
        server._resume = Mock()
        client = _make_client(1)
        client.non_stop = True

        for owner in (None, client):
            server._active_run_client = owner
            client._awaiting_vstopped = owner is client
            for command in (b'c', b'C05'):
                assert server.resume(client, command) == b'$#00'
                assert server._active_run_client is owner
                assert client._awaiting_vstopped == (owner is client)

        server._resume.assert_not_called()

    def test_all_stop_resume_clears_active_client(self):
        """Verify that an all-stop resume releases run ownership when it finishes."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.session.options.get.return_value = 0.1
        server.get_t_response = Mock(return_value=b'T05')
        server.target_context.read_core_register.return_value = 0x1000
        client = _make_client(1)

        def _wait(_timeout):
            assert server._active_run_client is client
            return False

        client.wait_for_interrupt.side_effect = _wait
        with server.lock:
            response = server.resume(client, None)

        assert response == b'$T05#b9'
        assert server._active_run_client is None

    def test_stop_query_failure_allows_stop_notification_retry(self):
        """A failed synchronous stop reply must leave the stop available for notification."""
        server = _make_state_server(Target.State.HALTED)
        server.COMMANDS = {b'?': (server.stop_reason_query, 0)}
        server.get_t_response = Mock(side_effect=(exceptions.TransferError("test stop reply failure"), b'T05'))
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client

        assert server.handle_message(client, b'$?#00') == server.create_rsp_packet(b'E01')
        assert not client._awaiting_vstopped
        assert server._active_run_client is client
        client.send.assert_not_called()

        server.service_non_stop_client(client)
        payload = b'Stop:T05'
        client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert client._awaiting_vstopped
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == server.create_rsp_packet(b'OK')
        assert not client._awaiting_vstopped
        assert server._active_run_client is None

    def test_stop_query_retains_cached_halt_after_external_state_change(self):
        """The stop query uses the cached halt until the server starts another run."""
        for state in (Target.State.RUNNING, Target.State.SLEEPING, Target.State.RESET, Target.State.LOCKUP):
            server = _make_state_server(Target.State.HALTED)
            server.get_t_response = Mock(return_value=b'T05')
            client = _make_client(1)
            client.non_stop = True
            server._active_run_client = client
            server.service_non_stop_client(client)

            # A monitor command may restart the target before vStopped arrives.
            server.target.get_state.return_value = state
            with server.lock:
                server._read_and_process_target_state(client=client)

            assert server.stop_reason_query(client) == server.create_rsp_packet(b'T05')
            assert client._awaiting_vstopped
            assert server._active_run_client is client
            assert server._is_halted

    def test_failed_stop_notification_keeps_active_client(self):
        """A send exception does not complete the pending stop sequence."""
        server = _make_state_server(Target.State.HALTED)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.send.side_effect = RuntimeError("test send failure")
        server._active_run_client = client

        try:
            server._send_stop_notification(client)
        except RuntimeError:
            pass
        else:
            assert False, "expected stop notification to fail"

        assert client._awaiting_vstopped
        assert server._active_run_client is client

    def test_void_stop_notification_send_keeps_active_client(self):
        """A send without a status result still begins the vStopped sequence."""
        server = _make_state_server(Target.State.HALTED)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.send.return_value = None
        server._active_run_client = client

        server.service_non_stop_client(client)
        client.send.assert_called_once_with(b'%Stop:T05thread:1;#' + checksum(b'Stop:T05thread:1;'))
        assert client._awaiting_vstopped
        assert server._active_run_client is client

    def test_non_stop_continue_selects_active_client(self):
        """Verify that non-stop continue assigns ownership before resuming the target."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.non_stop = True

        response = server.v_cont(client, b'Cont;c')

        assert response == b'OK'
        assert server._active_run_client is client
        server.target.resume.assert_called_once_with()
        server.target.get_state.assert_not_called()

    def test_non_stop_execution_actions_for_active_client_are_ignored(self):
        """Verify resume actions do not execute again while the thread is protocol-running."""
        for notification_pending in (False, True):
            state = Target.State.HALTED if notification_pending else Target.State.RUNNING
            server = _make_state_server(state)
            server.is_threading_enabled = Mock(return_value=False)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            client = _make_client(1)
            client.non_stop = True
            client._awaiting_vstopped = notification_pending
            server._active_run_client = client

            for action in (b'Cont;c', b'Cont;C02', b'Cont;s', b'Cont;S02', b'Cont;r1000,1010'):
                assert server.v_cont(client, action) == b'OK'

            server.target.resume.assert_not_called()
            server.target.step.assert_not_called()
            assert server._active_run_client is client
            assert client._awaiting_vstopped is notification_pending

    def test_non_stop_continue_services_semihost_halt_without_restarting_trace(self):
        """A semihost halt is serviced after the continue reply without another capture."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.target.get_state.return_value = Target.State.HALTED
        server.target.read_core_register.return_value = 0x1000
        server.is_threading_enabled = Mock(return_value=False)
        client = _make_client(1)
        client.non_stop = True
        events = []
        server.semihost.check_and_handle_semihost_request.side_effect = lambda: events.append('semihost') or True
        server.target.resume.side_effect = lambda: events.append('resume')
        server.create_rsp_packet = Mock(side_effect=lambda value: events.append(('reply', value)) or value)

        assert server.v_cont(client, b'Cont;c') == b'OK'
        with server.lock:
            server._read_and_process_target_state(client=client)

        assert events == ['resume', ('reply', b'OK'), 'semihost', 'resume']
        server.target.get_state.assert_called_once_with()
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.trace_flush.assert_not_called()
        server.trace_capture.assert_called_once_with()
        assert not server._is_halted
        assert server._active_run_client is client

    def test_all_stop_fresh_continue_returns_natural_stop(self):
        """Verify that fresh all-stop continue reports a naturally observed target halt."""
        server = _make_state_server(Target.State.HALTED)
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        server.target.get_state.return_value = Target.State.HALTED
        server.target_context = Mock()
        server.target_context.read_core_register.return_value = 0x1000
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.is_interrupted.return_value = False

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T05thread:1;'
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted
        assert server._active_run_client is None

    def test_all_stop_continue_uses_halt_cached_by_another_client(self):
        """An attached client can halt the run without another state read."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.session.options.get.return_value = 0.1
        server.target_context.read_core_register.return_value = 0x1000
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)

        def _halt_for_other_client(_timeout):
            server._halt_target()
            return False

        client.wait_for_interrupt.side_effect = _halt_for_other_client

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T05thread:1;'
        server.target.get_state.assert_not_called()
        server.target.halt.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted
        assert server._active_run_client is None

    def test_all_stop_late_ctrl_c_remains_queued(self):
        """Verify Ctrl-C received after halt detection is not consumed by the completed run."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        server.target_context.read_core_register.return_value = 0x1000
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)

        def _read_halted_state():
            client.is_interrupted.return_value = True
            return Target.State.HALTED

        server.target.get_state.side_effect = _read_halted_state

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T05thread:1;'
        server.get_t_response.assert_called_once_with(client)
        client.interrupt_clear.assert_not_called()
        assert client.is_interrupted()

    def test_all_stop_fresh_run_exits_when_connection_closes(self):
        """Verify that a new all-stop run exits cleanly when its client disconnects."""
        server = _make_state_server(Target.State.HALTED)
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        client = _make_client(1)
        client.is_interrupted.return_value = False

        def _close_connection(_timeout):
            server.target.get_state.return_value = Target.State.RUNNING
            client.is_connection_closed = True
            return False

        client.wait_for_interrupt.side_effect = _close_connection

        with server.lock:
            response = server.resume(client, None)

        assert response is None
        assert server._active_run_client is None
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_all_stop_close_during_unhandled_semihost_bkpt_sends_no_response(self):
        """Verify a disconnected client receives no response for the later semihost halt."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = True
        server._semihosting_client = None
        server.semihost = Mock()
        server.session.options.get.return_value = 0.1
        server.get_t_response = Mock()
        client = _make_client(1)
        client.is_interrupted.return_value = False
        checks = []

        def _observe_halt(_timeout):
            server.target.get_state.return_value = Target.State.HALTED
            return False

        def _close_during_semihost_check():
            checks.append(True)
            client.is_connection_closed = True
            return False

        client.wait_for_interrupt.side_effect = _observe_halt
        server.semihost.check_and_handle_semihost_request.side_effect = _close_during_semihost_check

        with server.lock:
            response = server.resume(client, None)

        assert response is None
        assert checks == [True]
        server.get_t_response.assert_not_called()

    def test_all_stop_step_from_halted_reports_stop_and_releases_run(self):
        """Verify that all-stop step reports its stop and then releases ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.trace_capture = Mock()
        server.step_into_interrupt = False
        server.target.get_state.return_value = Target.State.HALTED
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.is_interrupted.return_value = False

        response = server.step(client, b's')

        assert response == b'T05thread:1;'
        server.trace_capture.assert_called_once_with()
        server.target.step.assert_called_once()
        assert server.target.step.call_args.args[:3] == (True, 0, 0)
        assert callable(server.target.step.call_args.kwargs['hook_cb'])
        server.trace_flush.assert_called_once_with()
        assert server._is_halted
        assert server._active_run_client is None

    def test_legacy_step_keeps_direct_reply_for_non_stop_client(self):
        """Legacy s retains its direct stop reply even after non-stop negotiation."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.COMMANDS = {b's': (server.step, 1)}
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False

        assert server.handle_message(client, b'$s#73') == b'T05thread:1;'

        client.send.assert_not_called()
        assert not client._awaiting_vstopped
        assert server._active_run_client is None
        server.target.step.assert_called_once()

    def test_all_stop_vcont_signal_step_sends_direct_reply(self):
        """An all-stop vCont;S step sends a direct stop reply."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)

        assert server.v_cont(client, b'Cont;S05') == b'T05thread:1;'

        server.target.step.assert_called_once()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        client.send.assert_not_called()
        assert server._active_run_client is None

    def test_non_stop_step_sends_stop_notification_until_vstopped(self):
        """Verify that non-stop step keeps ownership until vStopped acknowledges its stop."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False
        payload = b'Stop:T05thread:1;'

        response = server.v_cont(client, b'Cont;s')

        assert response is None
        server.target.step.assert_called_once()
        assert client.send.call_count == 2
        assert client.send.call_args_list[0].args == (b'OK',)
        assert client.send.call_args_list[1].args == (b'%' + payload + b'#' + checksum(payload),)
        assert client._awaiting_vstopped
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == b'OK'
        assert not client._awaiting_vstopped
        assert server._active_run_client is None

    def test_non_stop_step_does_not_duplicate_pending_query_stop(self):
        """A step must not send another stop while a query stop awaits vStopped."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.non_stop = True

        assert server.stop_reason_query(client) == b'T05thread:1;'
        assert client._awaiting_vstopped
        assert server._active_run_client is None

        assert server.v_cont(client, b'Cont;s') is None
        server.service_non_stop_client(client)

        server.target.step.assert_called_once()
        server.get_t_response.assert_called_once_with(client)
        client.send.assert_called_once_with(b'OK')
        assert server._active_run_client is client

    def test_non_stop_range_step_forwards_bounds(self):
        """Verify a non-stop range step forwards its bounds to the physical target step."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.non_stop = True

        assert server.v_cont(client, b'Cont;r1000,1010') is None

        server.target.step.assert_called_once()
        assert server.target.step.call_args.args[:3] == (True, 0x1000, 0x1010)
        assert callable(server.target.step.call_args.kwargs['hook_cb'])
        assert client._awaiting_vstopped

    def test_ctrl_c_during_step_reports_sigint_without_second_halt(self):
        """A completed physical step reports the pending interrupt in either stop mode."""
        for non_stop in (False, True):
            server = _make_state_server(Target.State.HALTED)
            server.is_threading_enabled = Mock(return_value=False)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            server.get_t_response = Mock(return_value=b'T02thread:1;')
            client = _make_client(1)
            client.non_stop = non_stop
            server.target.step.side_effect = lambda *_args, **_kwargs: setattr(
                    client.is_interrupted, 'return_value', True)

            response = server.v_cont(client, b'Cont;s') if non_stop else server.step(client, b's')

            if non_stop:
                assert response is None
                assert server._active_run_client is client
                payload = b'Stop:T02thread:1;'
                assert client.send.call_args_list[1].args == (
                        b'%' + payload + b'#' + checksum(payload),)
                assert client._awaiting_vstopped
            else:
                assert response == b'T02thread:1;'
                assert server._active_run_client is None

            server.target.step.assert_called_once()
            server.target.halt.assert_not_called()
            client.interrupt_clear.assert_called_once_with()
            server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)

    def test_queued_all_stop_ctrl_c_reports_sigint_after_step(self):
        """A pending interrupt is consumed by the step reply."""
        server = _make_halt_server()
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T02thread:1;')
        server.target.read_core_register.return_value = 0x1000
        client = _make_client(1)
        client.is_interrupted.return_value = True

        assert server.step(client, b's') == b'T02thread:1;'

        server.target.step_over_breakpoint_instruction.assert_called_once_with(0x1000)
        server.target.step.assert_called_once()
        server.target.resume.assert_not_called()
        server.target.halt.assert_not_called()
        client.interrupt_clear.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)

    def test_stop_request_classifies_preexisting_debug_halt_without_processing_bkpt(self):
        """Verify a preexisting DEBUG halt is classified without processing its BKPT instruction."""
        server = _make_halt_server(instruction=0xbeab)
        server._handle_semihosting.return_value = True
        server._is_halted = False
        server.target.get_state.return_value = Target.State.HALTED
        client = _make_client(1)
        server._active_run_client = client

        with server.lock:
            result = server._request_stop(client)

        assert result is True
        server.trace_flush.assert_called_once_with()
        server._handle_semihosting.assert_not_called()
        server.target_context.read32.assert_not_called()
        server.target_context.write_core_register.assert_not_called()
        server.target_context.write32.assert_not_called()
        server.target.resume.assert_not_called()
        server.target.halt.assert_called_once_with()
        server.target.get_halt_reason.assert_called_once_with()
        assert server._is_halted

    def test_requested_debug_halt_does_not_process_bkpt_at_current_pc(self):
        """Verify a DEBUG halt before an unexecuted BKPT is classified without consuming it."""
        server = _make_halt_server()
        server._is_halted = False
        server.target.get_state.return_value = Target.State.HALTED
        server.target.get_halt_reason.return_value = Target.HaltReason.DEBUG
        client = _make_client(1)
        server._active_run_client = client

        with server.lock:
            result = server._request_stop(client)

        assert result is True
        server.target.halt.assert_called_once_with()
        server._handle_semihosting.assert_not_called()
        server.target_context.read32.assert_not_called()
        server.target_context.write_core_register.assert_not_called()
        server.target_context.write32.assert_not_called()
        server.target.resume.assert_not_called()
        assert server._is_halted

    def test_requested_halt_preserves_breakpoint_cause(self):
        """Verify a breakpoint winning the halt-request race is not reported as the request."""
        server = _make_halt_server()
        server._is_halted = False
        server.target.get_state.return_value = Target.State.HALTED
        server.target.get_halt_reason.return_value = Target.HaltReason.BREAKPOINT
        client = _make_client(1)

        with server.lock:
            server._active_run_client = client
            result = server._request_stop(client)

        assert result is False
        server.target.halt.assert_called_once_with()
        server._handle_semihosting.assert_not_called()
        server.target_context.read32.assert_not_called()
        server.target_context.write_core_register.assert_not_called()
        server.target_context.write32.assert_not_called()
        server.target.resume.assert_not_called()
        assert server._is_halted

    def test_request_stop_does_not_assume_unreadable_reason_was_requested(self):
        """An absent halt reason cannot establish that the request caused the stop."""
        server = _make_state_server(Target.State.RUNNING)
        server.target.get_halt_reason.return_value = None
        client = _make_client(1)

        with server.lock:
            result = server._request_stop(client)

        assert result is False
        server.target.halt.assert_called_once_with()
        server.target.get_halt_reason.assert_called_once_with()
        server.target.get_state.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_request_stop_propagates_non_transfer_halt_reason_error(self):
        """A non-transfer halt-reason error remains fatal after the halt succeeds."""
        server = _make_state_server(Target.State.RUNNING)
        halt_error = exceptions.TargetError("halt reason unavailable")
        server.target.get_halt_reason.side_effect = halt_error
        client = _make_client(1)

        try:
            with server.lock:
                server._request_stop(client)
        except exceptions.TargetError as error:
            assert error is halt_error
        else:
            assert False, "expected halt-reason error to propagate"

        server.target.halt.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_non_stop_service_handles_raw_ctrl_c_without_queueing(self):
        """Verify raw Ctrl-C immediately stops the current non-stop execution interval."""
        server = _make_state_server(Target.State.RUNNING)
        server.target.get_state.return_value = Target.State.HALTED
        server.get_t_response = Mock(return_value=b'T02thread:1;')
        client = _make_client(1)
        client.is_interrupted.return_value = True
        client.interrupt_clear.side_effect = lambda: setattr(client.is_interrupted, 'return_value', False)
        server._active_run_client = client

        server.service_non_stop_client(client)

        client.interrupt_clear.assert_called_once_with()
        server.target.halt.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)
        payload = b'Stop:T02thread:1;'
        client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert client._awaiting_vstopped

    def test_non_stop_raw_ctrl_c_halt_error_sends_sigint_notification(self):
        """A failed halt reports SIGINT without reading target stop details."""
        server = _make_state_server(Target.State.RUNNING)
        server.get_t_response = Mock()
        server.target.halt.side_effect = exceptions.TransferError("test halt failure")
        client = _make_client(1)
        client.is_interrupted.return_value = True
        client.interrupt_clear.side_effect = lambda: setattr(client.is_interrupted, 'return_value', False)
        server._active_run_client = client

        server.service_non_stop_client(client)
        server.service_non_stop_client(client)

        payload = b'Stop:S02'
        client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        server.target.halt.assert_called_once_with()
        server.target.get_halt_reason.assert_not_called()
        server.get_t_response.assert_not_called()
        server.trace_flush.assert_not_called()
        client.interrupt_clear.assert_called_once_with()
        assert not client.is_interrupted()
        assert not server._is_halted
        assert client._awaiting_vstopped
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == server.create_rsp_packet(b'OK')
        assert not client._awaiting_vstopped
        assert server._active_run_client is None

    def test_non_stop_raw_ctrl_c_halt_reason_error_sends_sigint_notification(self):
        """A failed halt-reason read uses the fallback after a successful halt."""
        server = _make_state_server(Target.State.RUNNING)
        server.get_t_response = Mock()
        server.target.get_halt_reason.side_effect = exceptions.TransferError("test halt reason failure")
        client = _make_client(1)
        client.is_interrupted.return_value = True
        client.interrupt_clear.side_effect = lambda: setattr(client.is_interrupted, 'return_value', False)
        server._active_run_client = client

        server.service_non_stop_client(client)

        payload = b'Stop:S02'
        client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        server.target.halt.assert_called_once_with()
        server.target.get_halt_reason.assert_called_once_with()
        server.get_t_response.assert_not_called()
        server.trace_flush.assert_called_once_with()
        client.interrupt_clear.assert_called_once_with()
        assert server._is_halted
        assert client._awaiting_vstopped
        assert server._active_run_client is client

    def test_non_stop_service_does_not_queue_ctrl_c_after_breakpoint(self):
        """Verify a breakpoint wins the race and consumes raw Ctrl-C without a later interrupt."""
        server = _make_state_server(Target.State.RUNNING)
        server.target.get_state.return_value = Target.State.HALTED
        server.target.get_halt_reason.return_value = Target.HaltReason.BREAKPOINT
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.is_interrupted.return_value = True
        client.interrupt_clear.side_effect = lambda: setattr(client.is_interrupted, 'return_value', False)
        server._active_run_client = client

        server.service_non_stop_client(client)

        client.interrupt_clear.assert_called_once_with()
        server.target.halt.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=None)
        payload = b'Stop:T05thread:1;'
        client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert not client.is_interrupted()

    def test_non_stop_raw_ctrl_c_after_polled_halt_does_not_flush_again(self):
        """A queued interrupt leaves a previously observed breakpoint halt intact."""
        server = _make_state_server(Target.State.RUNNING)
        server.target.get_state.return_value = Target.State.HALTED
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.is_interrupted.return_value = True
        server._active_run_client = client

        with server.lock:
            server._read_and_process_target_state(client=client)
        server.service_non_stop_client(client)

        server.trace_flush.assert_called_once_with()
        server.target.halt.assert_not_called()
        server.target.get_halt_reason.assert_not_called()
        client.interrupt_clear.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=None)
        payload = b'Stop:T05thread:1;'
        client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert client._awaiting_vstopped

    def test_non_stop_continue_notifies_after_service_halt(self):
        """Verify the complete non-stop continue and stop-notification flow.
        The service detects the halt, sends %Stop, and vStopped releases ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.COMMANDS = {b'v': (server.v_command, 2)}
        server.target_context = Mock()
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server.create_rsp_packet = Mock(side_effect=lambda value: b'$' + value + b'#' + checksum(value))
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.notify_client_detached = Mock()
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io._closed = False
        packet_io.receive.side_effect = (
            b'$vCont;c#00',
            b'$vStopped#00',
            ConnectionClosedException(),
        )
        sent_packets = []

        def _send(packet):
            sent_packets.append(packet)
            if len(sent_packets) == 1:
                server.target.get_state.return_value = Target.State.HALTED
                with server.lock:
                    server._read_and_process_target_state()

        packet_io.send.side_effect = _send
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.non_stop = True
        client.is_attached_to_target = True
        payload = b'Stop:T05thread:1;'

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            client.start_packet_io()
            client.run()

        assert sent_packets == [
            b'$OK#' + checksum(b'OK'),
            b'%' + payload + b'#' + checksum(payload),
            b'$OK#' + checksum(b'OK'),
        ]
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=None)
        assert not client._awaiting_vstopped
        assert server._active_run_client is None

    def test_vctrlc_is_unsupported(self):
        """Verify vCtrlC is unsupported in both all-stop and non-stop modes."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        for non_stop in (False, True):
            client = _make_client(1)
            client.non_stop = non_stop

            assert server.v_command(client, b'CtrlC') == b''

            client.set_interrupt.assert_not_called()

    def test_step_uses_cached_halt_after_failed_state_read(self):
        """A failed poll leaves the cached halt available for a later step."""
        for non_stop in (False, True):
            server = _make_state_server(Target.State.HALTED)
            poll_error = exceptions.TransferError("test state read failure")
            server.target.get_state.side_effect = (poll_error, Target.State.HALTED)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            server.get_t_response = Mock(return_value=b'T05thread:1;')
            if non_stop:
                server.is_threading_enabled = Mock(return_value=False)
            client = _make_client(1)
            client.non_stop = non_stop

            try:
                with server.lock:
                    server._read_and_process_target_state(client=client)
            except exceptions.TransferError as error:
                assert error is poll_error
            else:
                assert False, "expected state read to fail"
            assert server._is_halted

            response = server.v_cont(client, b'Cont;s') if non_stop else server.step(client, b's')

            if non_stop:
                assert response is None
            else:
                assert response == b'T05thread:1;'
            server.target.step.assert_called_once()
            assert server._is_halted

    def test_busy_step_logs_current_owner(self):
        """A rejected step identifies the client that already owns execution."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(3)
        server._active_run_client = _make_client(2)

        with patch('pyocd.gdbserver.gdbserver.LOG.warning') as warning_log:
            assert server.step(client, b's') == b'E01'

        warning_log.assert_called_once_with("Cannot start execution while client %d has an active run", 2)

    def test_failed_non_stop_continue_clears_active_client(self):
        """Verify that a failed non-stop resume releases its run ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server.target.resume.side_effect = exceptions.TargetError("test resume failure")
        client = _make_client(1)
        client.non_stop = True

        try:
            server.v_cont(client, b'Cont;c')
        except exceptions.TargetError:
            pass
        else:
            assert False, "expected target resume to fail"

        assert server._active_run_client is None

    def test_non_stop_step_notification_failure_is_retried_without_error_response(self):
        """Verify that building a step stop notification can be retried.
        Since OK was already sent, the failure must not produce a second error reply."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.COMMANDS = {b'v': (server.v_command, 2)}
        notification_error = exceptions.TargetError("test stop response failure")
        server.get_t_response = Mock(side_effect=notification_error)
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False

        with patch('pyocd.gdbserver.gdbserver.LOG.error') as error_log:
            response = server.handle_message(client, b'$vCont;s#00')

        assert response is None
        server.target.step.assert_called_once()
        error_log.assert_called_once_with("Error sending step stop notification: %s", notification_error,
                exc_info=server.session.log_tracebacks)
        client.send.assert_called_once_with(b'OK')
        assert server._active_run_client is client
        assert not client._awaiting_vstopped

        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.service_non_stop_client(client)
        assert client._awaiting_vstopped

    def test_non_stop_step_notification_send_failure_does_not_send_error_response(self):
        """A send failure after OK leaves the stop pending without sending E01."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.COMMANDS = {b'v': (server.v_command, 2)}
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False
        client.send.side_effect = [None, RuntimeError("test send failure")]

        response = server.handle_message(client, b'$vCont;s#00')

        assert response is None
        server.target.step.assert_called_once()
        assert client.send.call_count == 2
        assert client.send.call_args_list[0].args == (b'OK',)
        assert server._active_run_client is client
        assert client._awaiting_vstopped

    def test_non_stop_stop_rejects_unowned_execution(self):
        """A non-stop stop request cannot halt an execution interval it does not own."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.non_stop = True

        assert server.v_cont(client, b'Cont;t') == b'E01'

        server.target.halt.assert_not_called()
        server.trace_flush.assert_not_called()
        client.send.assert_not_called()
        assert server._active_run_client is None

    def test_non_stop_stop_halts_owned_non_halted_states(self):
        """An owner can request a halt from any cached non-halted state."""
        for state in (Target.State.RUNNING, Target.State.SLEEPING, Target.State.RESET, Target.State.LOCKUP):
            server = _make_state_server(state)
            server.is_threading_enabled = Mock(return_value=False)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            server.get_t_response = Mock(return_value=b'T00thread:1;')
            client = _make_client(1)
            client.non_stop = True
            server._active_run_client = client

            assert server.v_cont(client, b'Cont;t') is None

            server.target.halt.assert_called_once_with()
            server.trace_flush.assert_called_once_with()
            assert client._awaiting_vstopped
            assert server._active_run_client is client
            assert server._is_halted

    def test_non_stop_stop_preserves_breakpoint_that_wins_halt_request(self):
        """Verify vCont;t reports a competing breakpoint as T05 rather than T00."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.target.get_state.return_value = Target.State.HALTED
        server.target.get_halt_reason.return_value = Target.HaltReason.BREAKPOINT
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client
        payload = b'Stop:T05thread:1;'

        assert server.v_cont(client, b'Cont;t') is None

        assert client.send.call_args_list[0].args == (b'OK',)
        assert client.send.call_args_list[1].args == (
                b'%' + payload + b'#' + checksum(payload),)
        server.get_t_response.assert_called_once_with(client, forceSignal=None)
        assert client._awaiting_vstopped
        assert server._active_run_client is client

    def test_non_stop_stop_ignores_already_halted_target(self):
        """Verify that vCont;t does nothing when the target is already halted."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._halt_target = Mock()
        server._send_stop_notification = Mock()
        client = _make_client(1)
        client.non_stop = True

        response = server.v_cont(client, b'Cont;t')

        assert response == b'OK'
        server._halt_target.assert_not_called()
        server.trace_flush.assert_not_called()
        server._send_stop_notification.assert_not_called()
        client.send.assert_not_called()

    def test_non_stop_stop_ignores_pending_stop(self):
        """A pending stop sequence must not produce another vCont;t notification."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.non_stop = True
        client._awaiting_vstopped = True
        server._active_run_client = client

        assert server.v_cont(client, b'Cont;t') == b'OK'

        server.target.halt.assert_not_called()
        server.trace_flush.assert_not_called()
        client.send.assert_not_called()
        assert server._active_run_client is client

    def test_failed_non_stop_stop_sends_only_error_response(self):
        """Verify handling when vCont;t cannot halt the target.
        It returns only E01 and preserves ownership so a later real halt can be reported."""
        server = _make_state_server()
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._halt_target = Mock(side_effect=exceptions.TargetError("test halt failure"))
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client

        response = server.v_cont(client, b'Cont;t')

        assert response == b'E01'
        client.send.assert_not_called()
        assert server._active_run_client is client

    def test_non_stop_stop_notification_failure_does_not_send_error_response(self):
        """A send failure after vCont;t OK leaves the stop pending without E01."""
        server = _make_state_server()
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server._halt_target = Mock(side_effect=lambda: setattr(server.target.get_state, 'return_value', Target.State.HALTED))
        client = _make_client(1)
        client.non_stop = True
        notification_error = RuntimeError("test send failure")
        client.send.side_effect = [None, notification_error]
        server._active_run_client = client

        with patch('pyocd.gdbserver.gdbserver.LOG.error') as error_log:
            response = server.v_cont(client, b'Cont;t')

        assert response is None
        error_log.assert_called_once_with("Error sending stop notification: %s", notification_error,
                exc_info=server.session.log_tracebacks)
        assert client.send.call_count == 2
        assert client.send.call_args_list[0].args == (b'OK',)
        assert client._awaiting_vstopped
        assert server._active_run_client is client

    def test_non_stop_idle_waits_for_interrupt(self):
        """Verify that an idle non-stop client waits briefly and wakes directly for Ctrl-C."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.notify_client_detached = Mock()
        server.service_non_stop_client = Mock()
        server.target_context = Mock()
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = Mock()
        packet_io._closed = False
        packet_io.receive.side_effect = (None, ConnectionClosedException())
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.non_stop = True
        client.is_attached_to_target = True

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            client.start_packet_io()
            client.run()

        packet_io.interrupt_event.wait.assert_called_once_with(0.01)

    def test_non_stop_raw_ctrl_c_halts_current_run(self):
        """Verify a raw Ctrl-C halts non-stop execution without creating queued state."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.get_t_response = Mock(return_value=b'T02thread:1;')
        server.notify_client_detached = Mock()
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.interrupt_event.set()
        packet_io._closed = False
        packet_io.receive.side_effect = ConnectionClosedException()
        server.target_context = Mock()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.non_stop = True
        client.is_attached_to_target = True
        server._active_run_client = client

        server.target.halt.side_effect = lambda: setattr(server.target.get_state, 'return_value', Target.State.HALTED)

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            client.start_packet_io()
            client.run()

        server.target.halt.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)
        payload = b'Stop:T02thread:1;'
        packet_io.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert server._active_run_client is client
        assert client._awaiting_vstopped
        assert not packet_io.interrupt_event.is_set()

    def test_all_stop_ctrl_c_halts_current_run(self):
        """Verify that all-stop Ctrl-C halts the run and returns a SIGINT stop reply."""
        server = _make_state_server(Target.State.HALTED)
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        server.get_t_response = Mock(return_value=b'T02thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.is_interrupted.return_value = True
        client.wait_for_interrupt.return_value = True
        server.target.resume.side_effect = lambda: setattr(server.target.get_state, 'return_value', Target.State.RUNNING)

        server.target.halt.side_effect = lambda: setattr(server.target.get_state, 'return_value', Target.State.HALTED)

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T02thread:1;'
        server.target.resume.assert_called_once_with()
        server.target.halt.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        client.interrupt_clear.assert_called_once_with()
        client.wait_for_interrupt.assert_called_once_with(0.01)
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)
        assert server._active_run_client is None

    def test_all_stop_ctrl_c_halt_error_keeps_cached_running_state(self):
        """A failed halt still completes the Ctrl-C reply without assuming a halt."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        halt_error = exceptions.TransferError("test halt failure")
        server.target.halt.side_effect = halt_error
        client = _make_client(1)
        client.is_interrupted.return_value = True

        with server.lock:
            response = server.resume(client, None)

        assert response == b'S02'
        server.target.resume.assert_called_once_with()
        server.target.halt.assert_called_once_with()
        server.target.get_state.assert_not_called()
        assert not server._is_halted
        assert server._active_run_client is None
        server.trace_flush.assert_not_called()
        client.interrupt_clear.assert_called_once_with()

    def test_all_stop_ctrl_c_is_consumed_when_target_was_already_halted(self):
        """Verify Ctrl-C is consumed when a breakpoint preceded the physical halt request."""
        server = _make_state_server(Target.State.HALTED)
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        server.target.get_halt_reason.return_value = Target.HaltReason.BREAKPOINT
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.is_interrupted.return_value = True
        client.wait_for_interrupt.return_value = True

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T05thread:1;'
        server.target.halt.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=None)
        client.interrupt_clear.assert_called_once_with()

    def test_all_stop_queues_ctrl_c_until_the_next_continue(self):
        """Verify a Ctrl-C received while stopped interrupts the following continue."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.COMMANDS = {b'v': (server.v_command, 2)}
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        server.get_t_response = Mock(return_value=b'T02thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.notify_client_detached = Mock()
        server.target.resume.side_effect = lambda: setattr(server.target.get_state, 'return_value', Target.State.RUNNING)
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.interrupt_event.set()
        packet_io._closed = False
        packet_io.receive.side_effect = (
            b'$vCont;c#00',
            ConnectionClosedException(),
        )
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.is_attached_to_target = True

        def _halt_target():
            server.target.get_state.return_value = Target.State.HALTED
            server._is_halted = True

        server._halt_target = Mock(side_effect=_halt_target)

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            client.start_packet_io()
            client.run()

        server.target.resume.assert_called_once_with()
        server._halt_target.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)
        packet_io.send.assert_called_once_with(b'T02thread:1;')
        assert not packet_io.interrupt_event.is_set()
        assert server._active_run_client is None

    def test_passive_client_cannot_control_active_run(self):
        """Verify that a passive client cannot control another client's active run."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._resume_target = Mock()
        server._halt_target = Mock()
        active_client = _make_client(1)
        passive_client = _make_client(2)
        server._active_run_client = active_client

        assert server.resume(passive_client, None) == b'E01'
        assert server.step(passive_client, b's') == b'E01'

        passive_client.non_stop = True
        assert server.v_cont(passive_client, b'Cont;c') == b'E01'
        assert server.v_cont(passive_client, b'Cont;s') == b'E01'
        assert server.v_cont(passive_client, b'Cont;t') == b'E01'

        assert server._active_run_client is active_client
        server._resume_target.assert_not_called()
        server.target.step.assert_not_called()
        server._halt_target.assert_not_called()

    def test_passive_non_stop_ctrl_c_does_not_halt_active_run(self):
        """Verify that Ctrl-C from a passive client does not halt the active run."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.notify_client_detached = Mock()
        server.target_context = Mock()
        server._halt_target = Mock()
        active_client = _make_client(1)
        server._active_run_client = active_client
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.interrupt_event.set()
        packet_io._closed = False
        packet_io.receive.side_effect = ConnectionClosedException()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            passive_client = GDBClientSession(server, connected_socket, 2)
        passive_client.non_stop = True
        passive_client.is_attached_to_target = True

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            passive_client.start_packet_io()
            passive_client.run()

        server._halt_target.assert_not_called()
        packet_io.send.assert_not_called()
        assert not packet_io.interrupt_event.is_set()
        assert server._active_run_client is active_client

    def test_passive_read_commands_do_not_change_owner(self):
        """Verify that passive memory and register reads preserve the run owner."""
        server = _make_state_server(Target.State.RUNNING)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.target_context = Mock()
        server.target_context.read_memory_block8.return_value = [0x12, 0x34]
        active_client = _make_client(1)
        passive_client = _make_client(2)
        passive_client.target_facade.get_register.return_value = b'78563412'
        server._active_run_client = active_client

        assert server.get_memory(passive_client, b'20000000,2#00') == b'1234'
        assert server.read_register(passive_client, 0) == b'78563412'

        server.target_context.read_memory_block8.assert_called_once_with(0x20000000, 2)
        server.target_context.flush.assert_called_once_with()
        passive_client.target_facade.get_register.assert_called_once_with(0)
        assert server._active_run_client is active_client

    def test_active_disconnect_releases_run_for_passive_client(self):
        """Disconnect clears ownership while another attached client remains."""
        server = _make_state_server(Target.State.RUNNING)
        active_client = _make_client(1)
        passive_client = _make_client(2)
        active_client.non_stop = True
        active_client.is_socket_connected = False
        passive_client.non_stop = True
        server._active_run_client = active_client
        _configure_client_lifecycle(server, [active_client, passive_client], persist=True)

        server.notify_client_detached(active_client)

        assert active_client not in server.client_sessions
        assert not active_client.is_attached_to_target
        assert server._active_run_client is None
        server.target.get_state.assert_not_called()
        server.target.resume.assert_not_called()

    def test_passive_disconnect_preserves_active_run_and_pending_stop(self):
        """Verify that disconnecting a passive client does not affect the active one.
        Existing run ownership and any pending stop notification must remain unchanged."""
        for state, pending in ((Target.State.RUNNING, False), (Target.State.HALTED, True)):
            server = _make_state_server(state)
            active_client = _make_client(1)
            passive_client = _make_client(2)
            active_client._awaiting_vstopped = pending
            passive_client.is_socket_connected = False
            server._active_run_client = active_client
            _configure_client_lifecycle(server, [active_client, passive_client], persist=True)

            server.notify_client_detached(passive_client)

            assert passive_client not in server.client_sessions
            assert server._active_run_client is active_client
            assert active_client._awaiting_vstopped is pending
            server.target.get_state.assert_not_called()
            server.target.resume.assert_not_called()

    def test_active_pending_disconnect_allows_passive_client_to_continue(self):
        """Verify disconnect cleanup while the active client has a pending stop.
        Its ownership is cleared so a remaining client can start a new run."""
        server = _make_state_server(Target.State.HALTED)
        active_client = _make_client(1)
        passive_client = _make_client(2)
        active_client.is_socket_connected = False
        active_client._awaiting_vstopped = True
        passive_client.non_stop = True
        server._active_run_client = active_client
        _configure_client_lifecycle(server, [active_client, passive_client], persist=True)

        server.notify_client_detached(active_client)

        assert active_client not in server.client_sessions
        assert not active_client._awaiting_vstopped
        assert server._active_run_client is None
        server.target.resume.assert_not_called()

        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        assert server.v_cont(passive_client, b'Cont;c') == b'OK'
        assert server._active_run_client is passive_client
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_last_client_disconnect_resumes_target_and_honours_persist(self):
        """Verify cleanup after the final client disconnects.
        The target resumes, while only a non-persistent server requests shutdown."""
        for persist in (False, True):
            server = _make_state_server(Target.State.HALTED)
            client = _make_client(1)
            client.is_socket_connected = False
            client._awaiting_vstopped = True
            server._active_run_client = client
            _configure_client_lifecycle(server, [client], persist=persist)

            server.notify_client_detached(client)

            assert client not in server.client_sessions
            assert not client.is_attached_to_target
            assert not client._awaiting_vstopped
            assert server._active_run_client is None
            server.trace_capture.assert_called_once_with()
            server.target.resume.assert_called_once_with()
            server.target.get_state.assert_not_called()
            assert not server._is_halted
            assert server.shutdown_event.is_set() is (not persist)

    def test_last_client_disconnect_resumes_for_service_thread_bkpt_handling(self):
        """Final detach starts a run; later polling handles any BKPT at its saved PC."""
        server = _make_halt_server()
        client = _make_client(1)
        client.is_socket_connected = False
        _configure_client_lifecycle(server, [client], persist=True)
        server._active_run_client = client
        server.target.read_core_register.return_value = 0x1000

        server.notify_client_detached(client)

        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.target.resume.assert_called_once_with()
        assert server._pc_before_run == 0x1000
        assert not server._is_halted

    def test_non_stop_stop_query_while_not_halted_returns_ok(self):
        """Verify a non-stop stop query returns OK for every non-halted target state."""
        for state in (Target.State.RUNNING, Target.State.SLEEPING, Target.State.RESET, Target.State.LOCKUP):
            server = _make_state_server(state)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            server.get_t_response = Mock()
            client = _make_client(1)
            client.non_stop = True
            server._active_run_client = client

            assert server.stop_reason_query(client) == b'OK'
            server.get_t_response.assert_not_called()
            assert not client._awaiting_vstopped
            assert server._active_run_client is client

    def test_stop_query_uses_cached_state_after_failed_read(self):
        """A failed state read leaves the non-stop stop query using its cached state."""
        for cached_state in (Target.State.RUNNING, Target.State.HALTED):
            server = _make_state_server(cached_state)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            server.get_t_response = Mock(return_value=b'T05')
            poll_error = exceptions.TransferError("state read failure")
            server.target.get_state.side_effect = poll_error
            client = _make_client(1)
            client.non_stop = True
            server._active_run_client = client

            try:
                with server.lock:
                    server._read_and_process_target_state(client=client)
            except exceptions.TransferError as error:
                assert error is poll_error
            else:
                assert False, "expected state read to fail"

            expected = b'T05' if cached_state == Target.State.HALTED else b'OK'
            assert server.stop_reason_query(client) == expected
            assert server._is_halted == (cached_state == Target.State.HALTED)
            assert client._awaiting_vstopped == (cached_state == Target.State.HALTED)
            assert server._active_run_client is client
            server.target.get_state.assert_called_once_with()

    def test_stop_query_while_running_allows_notification_after_poll_recovers(self):
        """A running-state query leaves the later observed halt for notification."""
        server = _make_state_server(Target.State.RUNNING)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05')
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client
        poll_error = exceptions.TransferError("test state read failure")
        server.target.get_state.side_effect = poll_error

        try:
            with server.lock:
                server._read_and_process_target_state(client=client)
        except exceptions.TransferError as error:
            assert error is poll_error
        else:
            assert False, "expected state read to fail"

        assert server.stop_reason_query(client) == b'OK'
        assert not server._is_halted
        assert server._active_run_client is client
        assert not client._awaiting_vstopped
        server.get_t_response.assert_not_called()
        assert server.target.get_state.call_count == 1
        client.send.assert_not_called()

        server.target.get_state.side_effect = None
        server.target.get_state.return_value = Target.State.HALTED
        with server.lock:
            server._read_and_process_target_state(client=client)
        server.service_non_stop_client(client)

        payload = b'Stop:T05'
        client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert client._awaiting_vstopped
        assert server._active_run_client is client

    def test_stop_query_without_run_ownership_waits_for_vstopped(self):
        """A non-stop query starts a stop sequence without taking another client's ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05')
        client = _make_client(2)
        client.non_stop = True

        for owner in (None, _make_client(1)):
            server._active_run_client = owner

            assert server.stop_reason_query(client) == b'T05'
            assert client._awaiting_vstopped
            assert server._active_run_client is owner

            assert server.v_command(client, b'Stopped') == b'OK'
            assert not client._awaiting_vstopped
            assert server._active_run_client is owner

    def test_vstopped_from_passive_client_does_not_complete_active_stop(self):
        """Verify that passive vStopped cannot acknowledge another client's stop."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        active_client = _make_client(1)
        passive_client = _make_client(2)
        active_client._awaiting_vstopped = True
        server._active_run_client = active_client

        assert server.v_command(passive_client, b'Stopped') == b'OK'
        assert active_client._awaiting_vstopped
        assert server._active_run_client is active_client

        assert server.v_command(active_client, b'Stopped') == b'OK'
        assert not active_client._awaiting_vstopped
        assert server._active_run_client is None

    def test_all_stop_vcont_stop_is_ignored(self):
        """Verify that all-stop vCont;t is ignored without halting the target."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._halt_target = Mock()
        client = _make_client(1)
        client.non_stop = False

        assert server.v_cont(client, b'Cont;t') == b''
        server._halt_target.assert_not_called()
        assert server._active_run_client is None

    def test_active_non_stop_vcont_stop_completes_with_vstopped(self):
        """Verify that non-stop vCont;t keeps ownership until vStopped arrives."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T00thread:1;')

        server.target.halt.side_effect = lambda: setattr(server.target.get_state, 'return_value', Target.State.HALTED)
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client
        payload = b'Stop:T00thread:1;'

        assert server.v_cont(client, b'Cont;t') is None
        assert client.send.call_args_list[0].args == (b'OK',)
        assert client.send.call_args_list[1].args == (b'%' + payload + b'#' + checksum(payload),)
        assert client._awaiting_vstopped
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == b'OK'
        assert server._active_run_client is None
        assert server._is_halted
        server.trace_flush.assert_called_once_with()

    def test_non_stop_vcont_stop_sends_fallback_after_halt_error(self):
        """A transfer error during halt sends a manual stop notification."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock()
        server.target.halt.side_effect = exceptions.TransferError("test halt failure")
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client

        assert server.v_cont(client, b'Cont;t') is None

        payload = b'Stop:S00'
        assert [call.args for call in client.send.call_args_list] == [
            (b'OK',), (b'%' + payload + b'#' + checksum(payload),)
        ]
        server.target.halt.assert_called_once_with()
        server.target.get_halt_reason.assert_not_called()
        server.get_t_response.assert_not_called()
        server.trace_flush.assert_not_called()
        assert not server._is_halted
        assert client._awaiting_vstopped
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == b'OK'
        assert server._active_run_client is None

    def test_non_stop_vcont_stop_sends_fallback_after_halt_reason_error(self):
        """An unreadable halt reason sends a manual stop notification."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock()
        server.target.get_halt_reason.side_effect = exceptions.TransferError("test cause read failure")
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client

        assert server.v_cont(client, b'Cont;t') is None

        payload = b'Stop:S00'
        assert [call.args for call in client.send.call_args_list] == [
            (b'OK',), (b'%' + payload + b'#' + checksum(payload),)
        ]
        server.target.halt.assert_called_once_with()
        server.target.get_halt_reason.assert_called_once_with()
        server.target.get_state.assert_not_called()
        server.get_t_response.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted
        assert client._awaiting_vstopped
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == b'OK'
        assert server._active_run_client is None

    def test_non_stop_vcont_stop_continues_after_trace_flush_failure(self):
        """A trace flush error does not prevent a successful stop response."""
        server = _make_state_server(Target.State.RUNNING)
        server.board = Mock()
        server.board.target.trace_enabled = True
        server.board.target.trace_flush.side_effect = exceptions.TransferError("test trace flush failure")
        server.trace_flush = lambda: GDBServer.trace_flush(server)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T00thread:1;')
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client

        assert server.v_cont(client, b'Cont;t') is None

        payload = b'Stop:T00thread:1;'
        assert [call.args for call in client.send.call_args_list] == [
            (b'OK',), (b'%' + payload + b'#' + checksum(payload),)
        ]
        server.target.halt.assert_called_once_with()
        server.target.get_state.assert_not_called()
        server.board.target.trace_flush.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=0)
        assert server._is_halted
        assert client._awaiting_vstopped
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == b'OK'
        assert server._active_run_client is None

    def test_service_loop_tracks_non_halted_states_and_halt(self):
        """Verify that service polling continues through non-halted states.
        It must eventually publish HALTED and flush trace exactly once."""
        server = _make_state_server(Target.State.RUNNING)
        server._STATE_INTERVAL = 0
        states = iter((Target.State.RESET, Target.State.LOCKUP, Target.State.RUNNING, Target.State.HALTED))

        def _get_state():
            state = next(states)
            if state == Target.State.HALTED:
                server.shutdown_event.set()
            return state

        server.target.get_state.side_effect = _get_state

        service_thread = threading.Thread(target=server._run_service_thread)
        service_thread.start()
        service_thread.join(1.0)
        if service_thread.is_alive():
            server.shutdown_event.set()
            service_thread.join(1.0)

        assert not service_thread.is_alive()
        assert server.target.get_state.call_count == 4
        assert server._is_halted
        server.trace_flush.assert_called_once_with()

    def test_all_stop_remote_eof_releases_active_run(self):
        """Verify the full remote-EOF path during an all-stop continue.
        Packet I/O detects EOF, resume exits without a reply, and client cleanup runs."""
        run_started = threading.Event()

        class ControlledSocket:
            def __init__(self):
                self._read_count = 0
                self.closed = False
                self.writes = []

            def set_timeout(self, timeout):
                pass

            def read(self):
                self._read_count += 1
                if self._read_count == 1:
                    return b'$c#63'
                run_started.wait(1.0)
                return b''

            def write(self, data):
                self.writes.append(data)
                return len(data)

            def close(self):
                self.closed = True

        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.COMMANDS = {b'c': (server.resume, 1)}
        server.target_context = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.2
        server.target.get_state.return_value = Target.State.RUNNING
        connected_socket = ControlledSocket()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        _configure_client_lifecycle(server, [client], persist=True)
        client.is_attached_to_target = True

        def _resume_target():
            assert server._active_run_client is client
            run_started.set()

        server.target.resume.side_effect = _resume_target

        client.start_packet_io()
        client.start()
        client.join(3.0)
        try:
            assert not client.is_alive()
            assert run_started.is_set()
            assert server._active_run_client is None
            assert not client.is_attached_to_target
            assert client not in server.client_sessions
            assert connected_socket.closed
            assert connected_socket.writes == [b'+']
        finally:
            run_started.set()
            server.shutdown_event.set()
            if client.is_alive():
                client.stop()
            if client._packet_io is not None:
                client._packet_io.stop()
            client.join(1.0)
        assert not client.is_alive()
        assert client._packet_io is not None
        assert not client._packet_io.is_alive()

    def test_packet_io_start_failure_preserves_target_before_attach(self):
        """A packet-I/O startup failure closes the socket without touching the target."""
        for state in (Target.State.RUNNING, Target.State.HALTED):
            server = _make_state_server(state)
            server.port = 3333
            server.client_last_index = 0
            server.listen_socket = Mock()
            server._cleanup = Mock()
            _configure_client_lifecycle(server, [], persist=True)
            connected_socket = Mock()
            server.listen_socket.accept.return_value = connected_socket

            def _fail_packet_io(_socket, _index):
                assert server.client_sessions == []
                server.target.halt.assert_not_called()
                server.shutdown_event.set()
                raise RuntimeError("test packet-I/O failure")

            with patch('pyocd.gdbserver.gdbserver.threading.Timer'), \
                    patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()), \
                    patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', side_effect=_fail_packet_io):
                server.run()

            connected_socket.close.assert_called_once_with()
            assert server.client_sessions == []
            assert server._active_run_client is None
            assert server._semihosting_client is None
            assert server._is_halted == (state == Target.State.HALTED)
            server.target.get_state.assert_not_called()
            server.target.halt.assert_not_called()
            server.target.resume.assert_not_called()
            server.trace_capture.assert_not_called()
            server.trace_flush.assert_not_called()

    def test_shutdown_during_packet_io_start_closes_client_before_attach(self):
        """A server shutdown during packet-I/O startup closes the new connection before attachment."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.client_last_index = 0
        server.listen_socket = Mock()
        server._cleanup = Mock()
        _configure_client_lifecycle(server, [], persist=True)
        connected_socket = Mock()
        server.listen_socket.accept.return_value = connected_socket
        packet_io = Mock()

        def _start_packet_io(_socket, _index):
            server.shutdown_event.set()
            return packet_io

        with patch('pyocd.gdbserver.gdbserver.threading.Timer'), \
                patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()), \
                patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', side_effect=_start_packet_io):
            server.run()

        packet_io.stop.assert_called_once_with()
        connected_socket.close.assert_called_once_with()
        assert server.client_sessions == []
        server.target.get_state.assert_not_called()
        server.target.halt.assert_not_called()
        server.target.resume.assert_not_called()

    def test_stop_wakes_idle_all_stop_client(self):
        """Verify that stopping an idle all-stop client wakes its blocking receive.
        The client and packet-I/O threads both exit and release the connection."""
        receive_started = threading.Event()

        class IdleSocket:
            def __init__(self):
                self.closed = False

            def set_timeout(self, timeout):
                pass

            def read(self):
                threading.Event().wait(0.005)
                if self.closed:
                    return b''
                raise socket.timeout()

            def write(self, data):
                return len(data)

            def close(self):
                self.closed = True

        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.target_context = Mock()
        server.target.get_state.return_value = Target.State.RUNNING
        connected_socket = IdleSocket()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        _configure_client_lifecycle(server, [client], persist=True)
        client.is_attached_to_target = True
        original_receive = client.receive

        def _receive(block=True):
            receive_started.set()
            return original_receive(block)

        client.receive = _receive
        client.start_packet_io()
        client.start()
        try:
            assert receive_started.wait(1.0)
            client.stop(timeout=2.0)

            assert not client.is_alive()
            assert client._packet_io is not None
            assert not client._packet_io.is_alive()
            assert connected_socket.closed
            assert not client.is_socket_connected
            assert not client.is_attached_to_target
            assert client not in server.client_sessions
        finally:
            server.shutdown_event.set()
            client.cleanup()
            if client.is_alive():
                client.join(1.0)

    def test_new_client_is_attached_before_previous_client_detaches(self):
        """Verify that registration publishes a new attachment before its thread starts.
        A simultaneous old-client detach must not resume the target between clients."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.listen_socket = Mock()
        server.client_last_index = 1
        server._halt_target = Mock()
        server.target.get_state.return_value = Target.State.HALTED
        server._cleanup = Mock()
        old_client = _make_client(1)
        old_client.is_socket_connected = False
        _configure_client_lifecycle(server, [old_client], persist=True)
        connected_socket = Mock()
        connected_socket.get_remote_address.return_value = 'new-client'
        server.listen_socket.accept.return_value = connected_socket
        new_client = Mock()
        new_client.is_attached_to_target = False
        new_client.is_socket_connected = True
        new_client.is_connection_closed = False

        def _start_new_client():
            assert new_client.is_attached_to_target is True
            server.notify_client_detached(old_client)
            server.shutdown_event.set()

        new_client.start.side_effect = _start_new_client

        with patch('pyocd.gdbserver.gdbserver.threading.Timer') as timer_class, \
                patch('pyocd.gdbserver.gdbserver.GDBClientSession', return_value=new_client):
            server.run()

        assert new_client.is_attached_to_target is True
        assert server.client_sessions == [new_client]
        assert not old_client.is_attached_to_target
        server.target.resume.assert_not_called()
        server.trace_capture.assert_not_called()
        timer_class.return_value.start.assert_called_once_with()
        server._cleanup.assert_called_once_with()

    def test_client_start_failure_preserves_initial_halt(self):
        """Verify failed client startup is rolled back without resuming an initial halt.
        Cleanup and detachment still run when the client's stop method also fails."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.listen_socket = Mock()
        server.client_sessions = []
        server.client_sessions_lock = threading.Lock()
        server.client_last_index = 0
        server.persist = True
        server.thread_provider = Mock()
        server.did_init_thread_providers = True
        server.first_run_after_reset_or_flash = False
        server.trace_capture = Mock()
        server._halt_target = Mock()
        server.target.get_state.return_value = Target.State.HALTED
        server._cleanup = Mock()
        connected_socket = Mock()
        connected_socket.get_remote_address.return_value = 'failed-client'
        server.listen_socket.accept.return_value = connected_socket
        client = Mock()
        client.is_attached_to_target = False
        client.is_socket_connected = True
        client.is_connection_closed = False
        client.stop.side_effect = RuntimeError("test stop failure")

        def _fail_start():
            server.shutdown_event.set()
            raise RuntimeError("test start failure")

        def _cleanup_client():
            client.is_socket_connected = False

        client.start.side_effect = _fail_start
        client.cleanup.side_effect = _cleanup_client

        with patch('pyocd.gdbserver.gdbserver.threading.Timer'), \
                patch('pyocd.gdbserver.gdbserver.GDBClientSession', return_value=client):
            server.run()

        client.stop.assert_called_once_with()
        client.cleanup.assert_called_once_with()
        assert not client.is_attached_to_target
        assert client not in server.client_sessions
        server.target.resume.assert_not_called()
        server.trace_capture.assert_not_called()
        server._cleanup.assert_called_once_with()

    def test_stop_before_main_thread_start_cleans_resources_once(self):
        """Verify that stop cleans an initialized server whose main thread never started.
        Repeated calls do not stop or close any resource more than once."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.is_alive = Mock(return_value=False)
        client = _make_client(1)
        _configure_client_lifecycle(server, [client], persist=True)
        service_thread = Mock()
        service_thread.is_alive.side_effect = (True, False)
        server._service_thread = service_thread
        server.rtt_server = Mock()
        rtt_server = server.rtt_server
        semihost = server.semihost
        server.stdio_handler = Mock()
        stdio_handler = server.stdio_handler
        server.listen_socket = Mock()

        server.stop(wait=False)
        server.stop(wait=False)

        client.stop.assert_called_once_with()
        client.cleanup.assert_called_once_with()
        service_thread.join.assert_called_once_with(1.0)
        rtt_server.stop.assert_called_once_with()
        semihost.cleanup.assert_called_once_with()
        stdio_handler.shutdown.assert_called_once_with()
        server.listen_socket.close.assert_called_once_with()
        assert server.client_sessions == []
        assert server._service_thread is None
        assert server.rtt_server is None
        assert server.semihost is None
        assert server.stdio_handler is None

    def test_concurrent_cleanup_waits_for_cleanup_to_finish(self):
        """Verify a second cleanup call waits for the active cleanup to complete.
        Resources are still retired only once."""
        cleanup_started = threading.Event()
        allow_cleanup = threading.Event()
        second_started = threading.Event()
        second_finished = threading.Event()
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server._cleanup_client_sessions = Mock()
        server._stop_service_thread = Mock()
        server.rtt_server = None
        server.semihost = None
        server.stdio_handler = None
        server.listen_socket = Mock()

        def _block_cleanup():
            cleanup_started.set()
            assert allow_cleanup.wait(1.0)

        def _second_cleanup():
            second_started.set()
            server._cleanup()
            second_finished.set()

        server._cleanup_client_sessions.side_effect = _block_cleanup
        first_thread = threading.Thread(target=server._cleanup)
        second_thread = threading.Thread(target=_second_cleanup)
        first_thread.start()
        try:
            assert cleanup_started.wait(1.0)
            second_thread.start()
            assert second_started.wait(1.0)
            assert not second_finished.wait(0.05)
            allow_cleanup.set()
            first_thread.join(1.0)
            second_thread.join(1.0)
        finally:
            allow_cleanup.set()
            first_thread.join(1.0)
            if second_thread.ident is not None:
                second_thread.join(1.0)

        assert not first_thread.is_alive()
        assert not second_thread.is_alive()
        assert second_finished.is_set()
        server._cleanup_client_sessions.assert_called_once_with()
        server._stop_service_thread.assert_called_once_with()
        server.listen_socket.close.assert_called_once_with()

    def test_cleanup_continues_after_resource_failures(self):
        """Verify that one cleanup failure does not strand later resources.
        All clients and runtime services are attempted and references are retired."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        failed_client = _make_client(1)
        failed_client.stop.side_effect = RuntimeError("test client stop failure")
        failed_client.cleanup.side_effect = RuntimeError("test client cleanup failure")
        remaining_client = _make_client(2)
        _configure_client_lifecycle(server, [failed_client, remaining_client], persist=True)
        server._stop_service_thread = Mock(side_effect=RuntimeError("test service failure"))
        server.rtt_server = Mock()
        rtt_server = server.rtt_server
        rtt_server.stop.side_effect = RuntimeError("test RTT failure")
        server.semihost.cleanup.side_effect = RuntimeError("test semihosting failure")
        semihost = server.semihost
        server.stdio_handler = Mock()
        stdio_handler = server.stdio_handler
        stdio_handler.shutdown.side_effect = RuntimeError("test stdio failure")
        server.listen_socket = Mock()
        server.listen_socket.close.side_effect = RuntimeError("test listener failure")

        server._cleanup()

        failed_client.stop.assert_called_once_with()
        failed_client.cleanup.assert_called_once_with()
        remaining_client.stop.assert_called_once_with()
        remaining_client.cleanup.assert_called_once_with()
        server._stop_service_thread.assert_called_once_with()
        rtt_server.stop.assert_called_once_with()
        semihost.cleanup.assert_called_once_with()
        stdio_handler.shutdown.assert_called_once_with()
        server.listen_socket.close.assert_called_once_with()
        assert server.client_sessions == []
        assert server.rtt_server is None
        assert server.semihost is None
        assert server.stdio_handler is None

    def test_server_accepts_multiple_clients_before_first_run(self):
        """Verify that the server accepts and starts multiple clients before execution.
        Each client receives a unique index and the target is checked as halted."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.listen_socket = Mock()
        server.client_sessions = []
        server.client_sessions_lock = threading.Lock()
        server.client_last_index = 0
        server._halt_target = Mock()
        server._cleanup = Mock()
        first_socket = Mock()
        second_socket = Mock()
        first_socket.get_remote_address.return_value = 'first'
        second_socket.get_remote_address.return_value = 'second'
        accept_count = 0

        def _accept(_timeout):
            nonlocal accept_count
            accept_count += 1
            if accept_count == 1:
                return first_socket
            return second_socket

        server.listen_socket.accept.side_effect = _accept
        first_client = Mock()
        first_client.is_connection_closed = False
        second_client = Mock()
        second_client.is_connection_closed = False
        second_client.start.side_effect = server.shutdown_event.set

        with patch('pyocd.gdbserver.gdbserver.threading.Timer') as timer_class, \
                patch('pyocd.gdbserver.gdbserver.GDBClientSession', side_effect=(first_client, second_client)) as client_class:
            server.run()

        assert client_class.call_args_list[0].args == (server, first_socket, 1)
        assert client_class.call_args_list[1].args == (server, second_socket, 2)
        assert server.client_sessions == [first_client, second_client]
        first_client.start.assert_called_once_with()
        second_client.start.assert_called_once_with()
        assert server._halt_target.call_count == 2
        server.trace_flush.assert_not_called()
        timer_class.return_value.start.assert_called_once_with()
        server._cleanup.assert_called_once_with()


class TestGdbServerStateAndServiceRegressions:
    def test_trace_stays_open_across_semihosting_pauses(self):
        """Capture precedes resume and only the final non-semihost halt flushes it."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.semihost.check_and_handle_semihost_request.side_effect = (True, True, False)
        server.target.step_over_breakpoint_instruction.return_value = False
        server.target.get_state.return_value = Target.State.HALTED
        events = []
        server.trace_capture.side_effect = lambda: events.append('capture')
        server.trace_flush.side_effect = lambda: events.append('flush')

        def _resume():
            assert not server._is_halted
            events.append('resume')

        server.target.resume.side_effect = _resume
        with server.lock:
            server._resume_target()
            for _ in range(2):
                server._read_and_process_target_state()
                assert not server._is_halted
                server.trace_flush.assert_not_called()
            server._read_and_process_target_state()

        assert server._is_halted
        assert events == ['capture', 'resume', 'resume', 'resume', 'flush']

    def test_semihost_error_on_polled_halt_is_not_retried(self):
        """A failed semihost request is not repeated on the next halted poll."""
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True
        server.target.get_state.return_value = Target.State.HALTED
        semihost_error = exceptions.TransferError("test partial semihost request")
        server.semihost.check_and_handle_semihost_request.side_effect = semihost_error

        with server.lock:
            try:
                server._read_and_process_target_state()
            except exceptions.TransferError as error:
                assert error is semihost_error
            else:
                assert False, "expected semihost request to fail"

        assert server._is_halted
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.trace_flush.assert_not_called()

        with server.lock:
            if not server._is_halted:
                server._read_and_process_target_state()

        assert server._is_halted
        server.target.get_state.assert_called_once_with()
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.target.resume.assert_not_called()
        server.trace_flush.assert_not_called()

    def test_all_stop_stop_reply_error_does_not_flush_polled_halt_again(self):
        """A stop-reply error does not request another halt after polling flushed it."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.session.options.get.return_value = 1.0
        server.target.get_state.return_value = Target.State.HALTED
        server.target_context.read_core_register.side_effect = exceptions.TargetError("PC unavailable")
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.target_facade.get_signal_value.return_value = signals.SIGTRAP

        with server.lock:
            response = server.resume(client, None)

        assert response == b'S05'
        server.target.halt.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted
        assert server._active_run_client is None

    def test_all_stop_continue_retries_state_read_without_resuming_twice(self):
        """Transient state faults start one timeout and preserve the running command."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.session.options.get.return_value = 1.0
        server.target.get_state.side_effect = (
            exceptions.TransferError("first read failed"),
            exceptions.TransferError("second read failed"),
            Target.State.HALTED,
        )
        server.target_context.read_core_register.return_value = 0x1000
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        retry_timeout = Mock(is_running=False, did_time_out=False)
        retry_timeout.check.return_value = True
        retry_timeout.start.side_effect = lambda: setattr(retry_timeout, 'is_running', True)

        with patch('pyocd.gdbserver.gdbserver.Timeout', return_value=retry_timeout):
            with server.lock:
                response = server.resume(client, None)

        assert response == b'T05thread:1;'
        server.target.resume.assert_called_once_with()
        assert server.target.get_state.call_count == 3
        retry_timeout.start.assert_called_once_with()
        retry_timeout.clear.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_step_services_semihost_bkpt_after_physical_step(self):
        """A single step services the semihost request produced by that step."""
        server = _make_state_server(Target.State.HALTED)
        _configure_semihost_bkpt(server)
        server.enable_semihosting = True
        pc = [0x1000]
        events = []
        server.target.read_core_register.side_effect = lambda _register: pc[0]
        server.target.step.side_effect = lambda *_args, **_kwargs: events.append("step")

        def _handle_semihost_request():
            events.append("semihost")
            pc[0] += 2
            return True

        server.semihost.check_and_handle_semihost_request.side_effect = _handle_semihost_request
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)

        assert server.step(client, b's') == b'T05thread:1;'

        assert events == ["step", "semihost"]
        assert pc[0] == 0x1002
        server.target.step.assert_called_once()
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_polling_flushes_observed_halt_once(self):
        """Polling flushes a new halt without capturing observed execution."""
        cases = (
            (False, Target.State.HALTED, 1),
            (True, Target.State.SLEEPING, 0),
            (False, Target.State.SLEEPING, 0),
            (True, Target.State.HALTED, 0),
        )

        for was_halted, observed_state, flush_count in cases:
            initial_state = Target.State.HALTED if was_halted else Target.State.RUNNING
            server = _make_state_server(initial_state)
            server.trace_capture = Mock()
            server.target.get_state.return_value = observed_state

            with server.lock:
                if not server._is_halted:
                    server._read_and_process_target_state()
                # The service loop stops polling after a confirmed halt.
                if not server._is_halted:
                    server._read_and_process_target_state()
            assert server._is_halted == (was_halted or observed_state == Target.State.HALTED)
            server.trace_capture.assert_not_called()
            assert server.trace_flush.call_count == flush_count

    def test_failed_state_read_preserves_cached_halt(self):
        """The cache changes only after a successful state observation."""
        cases = (
            (Target.State.RUNNING, Target.State.HALTED),
        )
        for initial_state, observed_state in cases:
            server = _make_state_server(initial_state)
            poll_error = exceptions.TransferError("test state read failure")
            server.target.get_state.side_effect = (poll_error, observed_state)

            try:
                with server.lock:
                    server._read_and_process_target_state()
            except exceptions.TransferError as error:
                assert error is poll_error
            else:
                assert False, "expected state read to fail"

            assert server._is_halted == (initial_state == Target.State.HALTED)
            server.trace_flush.assert_not_called()

            with server.lock:
                server._read_and_process_target_state()

            assert server._is_halted == (observed_state == Target.State.HALTED)
            if observed_state == Target.State.HALTED:
                server.trace_flush.assert_called_once_with()
            else:
                server.trace_flush.assert_not_called()

    def test_trace_flush_error_does_not_reprocess_observed_halt(self):
        """A successful halt read is cached before trace flush is attempted."""
        server = _make_state_server(Target.State.RUNNING)
        server.target.get_state.return_value = Target.State.HALTED
        flush_error = exceptions.TransferError("test trace flush failure")
        server.trace_flush.side_effect = flush_error

        try:
            with server.lock:
                server._read_and_process_target_state()
        except exceptions.TransferError as error:
            assert error is flush_error
        else:
            assert False, "expected trace flush to fail"

        assert server._is_halted

        with server.lock:
            if not server._is_halted:
                server._read_and_process_target_state()

        assert server._is_halted
        server.target.get_state.assert_called_once_with()
        server.trace_flush.assert_called_once_with()

    def test_restart_error_leaves_halt_for_service_polling(self):
        """A failed reset leaves the cached state until a later poll observes the halt."""
        server = _make_state_server(Target.State.RUNNING)
        server.trace_capture = Mock()
        server.target.reset_and_halt.side_effect = RuntimeError("test reset failure")
        server.target.get_state.return_value = Target.State.HALTED
        client = _make_client(1)
        client.is_attached_to_target = False

        server.restart(client, None)

        assert client.is_attached_to_target
        assert not server._is_halted
        server.target.get_state.assert_not_called()
        server.trace_flush.assert_not_called()

        with server.lock:
            server._read_and_process_target_state()

        assert server._is_halted
        server.trace_flush.assert_called_once_with()

    def test_successful_restart_marks_halted_without_state_read(self):
        """A successful reset and halt updates the cache from the command result."""
        server = _make_state_server(Target.State.RUNNING)
        client = _make_client(1)

        server.restart(client, None)

        server.target.reset_and_halt.assert_called_once_with()
        server.target.get_state.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_restart_post_reset_then_continue_captures_once(self):
        """Reset-and-halt leaves capture for the next physical continue."""
        server = _make_state_server(Target.State.HALTED)
        server.target.reset_and_halt.side_effect = lambda: server.event_handler(Mock(event=Target.Event.POST_RESET))
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.non_stop = True

        server.restart(client, None)

        assert server._is_halted
        server.target.reset_and_halt.assert_called_once_with()
        server.target.get_state.assert_not_called()
        server.trace_capture.assert_not_called()

        assert server.v_cont(client, b'Cont;c') == b'OK'

        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted

        server.target.get_state.return_value = Target.State.RUNNING
        with server.lock:
            server._read_and_process_target_state()

        server.trace_capture.assert_called_once_with()
        server.target.get_state.assert_called_once_with()

    def test_restart_marks_halted_before_failing_trace_flush(self):
        """A trace flush error after reset cannot leave the cached state running."""
        server = _make_state_server(Target.State.RUNNING)
        server.board = Mock()
        server.board.target.trace_enabled = True
        halted_during_flush = []

        def _fail_flush():
            halted_during_flush.append(server._is_halted)
            raise exceptions.TransferError("test trace flush failure")

        server.board.target.trace_flush.side_effect = _fail_flush
        server.trace_flush = lambda: GDBServer.trace_flush(server)
        client = _make_client(1)

        server.restart(client, None)

        server.target.reset_and_halt.assert_called_once_with()
        server.target.get_state.assert_not_called()
        server.board.target.trace_flush.assert_called_once_with()
        assert halted_during_flush == [True]
        assert server._is_halted

    def test_flash_failure_releases_loader_without_reading_target(self):
        """A failed commit discards the loader without changing cached halt state."""
        server = _make_state_server(Target.State.RUNNING)
        server.board = Mock()
        server.board.target.selected_core = server.core
        server.flash_loader = Mock()
        flash_error = RuntimeError("test flash failure")
        server.flash_loader.commit.side_effect = flash_error
        server.target.get_state.return_value = Target.State.HALTED

        try:
            server.flash_op(b'FlashDone')
        except RuntimeError as error:
            assert error is flash_error
        else:
            assert False, "expected flash programming to fail"

        assert server.flash_loader is None
        assert not server._is_halted
        server.target.get_state.assert_not_called()
        server.trace_capture.assert_not_called()
        server.trace_flush.assert_not_called()

    def test_flash_done_preserves_cached_halt_and_marks_next_run(self):
        """FlashDone leaves physical state observation to the normal run paths."""
        for initial_state in (Target.State.RUNNING, Target.State.HALTED):
            server = _make_state_server(initial_state)
            server.board = Mock()
            server.board.target.selected_core = server.core
            server.flash_loader = Mock()
            flash_loader = server.flash_loader
            server.thread_provider = Mock()
            server.target.get_state.side_effect = exceptions.TransferError("state is unavailable")
            server.create_rsp_packet = Mock(side_effect=lambda value: value)

            assert server.flash_op(b'FlashDone') == b'OK'

            flash_loader.commit.assert_called_once_with()
            assert server.flash_loader is None
            assert server._is_halted == (initial_state == Target.State.HALTED)
            assert server.first_run_after_reset_or_flash
            assert not server.thread_provider.read_from_target
            server.target.get_state.assert_not_called()
            server.trace_capture.assert_not_called()
            server.trace_flush.assert_not_called()

    def test_flash_done_leaves_new_halt_for_service_poll(self):
        """Polling publishes a halt observed after FlashDone."""
        server = _make_state_server(Target.State.RUNNING)
        server.board = Mock()
        server.board.target.selected_core = server.core
        server.flash_loader = Mock()
        server.target.get_state.return_value = Target.State.HALTED
        server.create_rsp_packet = Mock(side_effect=lambda value: value)

        assert server.flash_op(b'FlashDone') == b'OK'
        assert not server._is_halted
        server.target.get_state.assert_not_called()

        with server.lock:
            server._read_and_process_target_state()

        assert server._is_halted
        server.target.get_state.assert_called_once_with()
        server.trace_flush.assert_called_once_with()

    def test_post_reset_publishes_not_halted_without_reading_target(self):
        """Verify POST_RESET immediately publishes not-halted without a target read.
        The final state is left for the command path or service polling to observe."""
        server = _make_state_server(Target.State.HALTED)
        server.first_run_after_reset_or_flash = False
        server.thread_provider = Mock()
        notification = Mock(event=Target.Event.POST_RESET)

        server.event_handler(notification)

        assert not server._is_halted
        assert server.first_run_after_reset_or_flash
        assert not server.thread_provider.read_from_target
        server.target.get_state.assert_not_called()

    def test_post_reset_non_halted_poll_updates_cache_after_read_retry(self):
        """A failed read leaves cache unchanged until running or sleeping is observed."""
        for observed_state in (Target.State.RUNNING, Target.State.SLEEPING):
            server = _make_state_server(Target.State.HALTED)
            server.event_handler(Mock(event=Target.Event.POST_RESET))
            assert not server._is_halted
            server.trace_capture.assert_not_called()
            server.target.get_state.assert_not_called()
            state_error = exceptions.TransferError("test post-reset state read failure")
            server.target.get_state.side_effect = (state_error, observed_state, observed_state)

            try:
                with server.lock:
                    server._read_and_process_target_state()
            except exceptions.TransferError as error:
                assert error is state_error
            else:
                assert False, "expected post-reset state read to fail"

            assert not server._is_halted
            server.trace_capture.assert_not_called()

            with server.lock:
                server._read_and_process_target_state()

            assert not server._is_halted
            server.trace_capture.assert_not_called()

            with server.lock:
                server._read_and_process_target_state()

            assert not server._is_halted
            assert server.target.get_state.call_count == 3
            server.trace_capture.assert_not_called()
            server.trace_flush.assert_not_called()
            server.target.resume.assert_not_called()

    def test_post_reset_halted_poll_processes_new_halt_once(self):
        """A new halt after reset checks semihosting and flushes once."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.event_handler(Mock(event=Target.Event.POST_RESET))
        server.trace_capture.assert_not_called()
        server.target.get_state.return_value = Target.State.HALTED

        with server.lock:
            server._read_and_process_target_state()

        assert server._is_halted
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        server.trace_capture.assert_not_called()
        server.target.resume.assert_not_called()

        with server.lock:
            if not server._is_halted:
                server._read_and_process_target_state()

        assert server._is_halted
        server.target.get_state.assert_called_once_with()
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        server.trace_capture.assert_not_called()

    def test_post_reset_semihost_halt_resumes_without_new_capture(self):
        """A handled semihost halt resumes without a new trace capture."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.event_handler(Mock(event=Target.Event.POST_RESET))
        server.trace_capture.assert_not_called()
        server.target.get_state.return_value = Target.State.HALTED
        events = []
        server.semihost.check_and_handle_semihost_request.side_effect = lambda **_kwargs: events.append('semihost') or True
        server.target.resume.side_effect = lambda: events.append('resume')

        with server.lock:
            server._read_and_process_target_state()

        assert events == ['semihost', 'resume']
        assert not server._is_halted
        server.trace_capture.assert_not_called()
        server.target.resume.assert_called_once_with()
        server.trace_flush.assert_not_called()

        server.target.get_state.return_value = Target.State.RUNNING
        with server.lock:
            server._read_and_process_target_state()

        assert not server._is_halted
        assert server.target.get_state.call_count == 2
        server.trace_capture.assert_not_called()

    def test_reset_query_has_no_trace_or_halt_state_side_effects(self):
        """A status query leaves run and trace transitions to execution and polling."""
        server = _make_state_server(Target.State.HALTED)
        server.trace_capture = Mock()
        server.target.get_state.return_value = Target.State.RESET

        assert server.is_target_in_reset()

        assert server._is_halted
        server.trace_capture.assert_not_called()
        server.trace_flush.assert_not_called()

    def test_halt_target_sets_halted_without_state_read(self):
        """A successful halt updates cached state without verifying the physical state."""
        server = _make_state_server(Target.State.RUNNING)

        server._halt_target()

        server.target.halt.assert_called_once_with()
        server.target.get_state.assert_not_called()
        assert server._is_halted
        server.trace_flush.assert_called_once_with()

    def test_halt_target_error_preserves_cache_without_state_read(self):
        """A failed halt preserves cached state and lets a later poll recover it."""
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True
        server._handle_semihosting = Mock(return_value=False)
        halt_error = exceptions.TransferError("test halt failure")
        server.target.halt.side_effect = halt_error
        server.target.get_state.return_value = Target.State.HALTED

        try:
            server._halt_target()
        except exceptions.TransferError as error:
            assert error is halt_error
        else:
            assert False, "expected physical halt to fail"

        server.target.get_state.assert_not_called()
        assert not server._is_halted
        server.trace_flush.assert_not_called()

        with server.lock:
            server._read_and_process_target_state()

        assert server._is_halted
        server.target.get_state.assert_called_once_with()
        server._handle_semihosting.assert_called_once_with(client=None)
        server.trace_flush.assert_called_once_with()

    def test_step_error_keeps_cached_halt_after_state_read(self):
        """A failed physical step propagates without repeating the step."""
        server = _make_state_server(Target.State.HALTED)
        step_error = exceptions.TransferError('test step failure')
        server.target.step.side_effect = step_error
        client = _make_client(1)

        try:
            server.step(client, b's')
        except exceptions.TransferError as error:
            assert error is step_error
        else:
            assert False, 'expected physical step to fail'

        server.target.step.assert_called_once()
        server.target.get_state.assert_called_once_with()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_not_called()
        assert server._is_halted
        assert server._active_run_client is None

    def test_single_step_processes_resulting_semihosting_halt(self):
        """A physical step services a semihost request produced by that step."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.target.read_core_register.side_effect = (0x1000, 0x1002)
        server._handle_semihosting = Mock(return_value=True)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)

        assert server.step(client, b's') == b'T05thread:1;'

        server.target.step.assert_called_once()
        server._handle_semihosting.assert_called_once_with(client=client)
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_called_once_with()

    def test_range_step_continues_after_semihosting_inside_range(self):
        """A range step continues after a semihost request until the next normal halt."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.enable_semihosting = True
        server._handle_semihosting = Mock(side_effect=(True, False))
        server.target.read_core_register.side_effect = (0x0ffe, 0x1000)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)

        assert server.v_cont(client, b'Cont;r1000,1010') == b'T05thread:1;'

        assert server.target.step.call_count == 2
        assert server._handle_semihosting.call_count == 2
        assert server.target.read_core_register.call_count == 2
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_called_once_with()

    def test_range_step_stops_at_unhandled_halt(self):
        """A breakpoint inside a range is reported instead of stepped past."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        pc = [0x1000]

        def _read_pc(_register):
            return pc[0]

        def _stop_at_breakpoint(*_args, **_kwargs):
            assert pc[0] == 0x1000
            pc[0] = 0x1004

        server.target.read_core_register.side_effect = _read_pc
        server.target.step.side_effect = _stop_at_breakpoint
        server._handle_semihosting = Mock(return_value=False)
        client = _make_client(1)

        server._execute_step(client, 0x1000, 0x1010)

        assert pc[0] == 0x1004
        server.target.step.assert_called_once()
        server._handle_semihosting.assert_called_once_with(client=client)
        server.target.step_over_breakpoint_instruction.assert_called_once_with(0x1000)

    def test_step_consumes_first_literal_bkpt(self):
        """A BKPT executed by a step is consumed even after a DEBUG halt."""
        server = _make_state_server(Target.State.HALTED)
        pc = [0x1004]
        step_pcs = []
        server.target.read_core_register.side_effect = lambda _register: pc[0]
        server.target.step.side_effect = lambda *_args, **_kwargs: step_pcs.append(pc[0])

        def _step_over(pc_before_step):
            assert pc_before_step == pc[0]
            pc[0] += 2
            return True

        server.target.step_over_breakpoint_instruction.side_effect = _step_over
        client = _make_client(1)

        server._execute_step(client)

        assert step_pcs == [0x1004]
        assert pc[0] == 0x1006
        server.target.step.assert_called_once()
        server.target.step_over_breakpoint_instruction.assert_called_once_with(0x1004)
        server.target.get_halt_reason.assert_not_called()

    def test_range_step_stops_at_second_literal_bkpt(self):
        """A range step consumes its first BKPT but leaves the next one visible."""
        server = _make_state_server(Target.State.HALTED)
        pc = [0x1004]
        step_pcs = []
        server.target.read_core_register.side_effect = lambda _register: pc[0]
        server.target.step.side_effect = lambda *_args, **_kwargs: step_pcs.append(pc[0])

        def _step_over(pc_before_step):
            assert pc_before_step == 0x1004
            pc[0] = 0x1006
            return True

        server.target.step_over_breakpoint_instruction.side_effect = _step_over
        client = _make_client(1)

        server._execute_step(client, 0x1004, 0x1010)

        assert step_pcs == [0x1004, 0x1006]
        assert pc[0] == 0x1006
        server.target.step_over_breakpoint_instruction.assert_called_once_with(0x1004)
        server.target.get_halt_reason.assert_not_called()

    def test_range_step_disconnect_during_semihosting_stays_halted(self):
        """Client loss during semihosting stops a range step after its current physical halt."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.enable_semihosting = True
        server.target.read_core_register.side_effect = (0x1000, 0x1006)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)

        def _handle_semihosting(client=None):
            client.is_connection_closed = True
            return True

        server._handle_semihosting = Mock(side_effect=_handle_semihosting)

        assert server.v_cont(client, b'Cont;r1000,1010') == b'T05thread:1;'

        server.target.step.assert_called_once()
        assert server.target.step.call_args.args[:3] == (True, 0x1000, 0x1010)
        assert callable(server.target.step.call_args.kwargs['hook_cb'])
        server._handle_semihosting.assert_called_once_with(client=client)
        server.target.resume.assert_not_called()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted
        assert server._active_run_client is None

    def test_semihost_resume_error_is_reconciled_by_later_state_poll(self):
        """A failed semihost resume leaves the next state for normal polling."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.thread_provider = None
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._handle_semihosting = Mock(return_value=True)
        resume_error = exceptions.TransferError("test late semihost resume failure")
        server.target.resume.side_effect = (None, resume_error)
        server.target.get_state.side_effect = (Target.State.HALTED, Target.State.RUNNING)
        client = _make_client(1)
        client.is_interrupted.return_value = False
        retry_timeout = Mock()
        retry_timeout.check.side_effect = (True, False)
        retry_timeout.is_running = False
        retry_timeout.did_time_out = False

        def _observe_semihost_halt(_timeout):
            server.target.get_state.return_value = Target.State.HALTED
            return False

        client.wait_for_interrupt.side_effect = _observe_semihost_halt

        with patch('pyocd.gdbserver.gdbserver.Timeout', return_value=retry_timeout):
            with server.lock:
                response = server.resume(client, None)

        assert response == b''
        assert server.target.resume.call_count == 2
        server.target.get_state.assert_called_once_with()
        retry_timeout.start.assert_called_once_with()
        assert not server._is_halted
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_not_called()

        with server.lock:
            server._read_and_process_target_state()

        assert server.target.get_state.call_count == 2
        assert not server._is_halted
        server.trace_flush.assert_not_called()

    def test_all_stop_continue_resumes_after_gdb_syscall_semihosting(self):
        """Verify all-stop continue services GDB File-I/O and resumes transparently.
        A later normal halt is the only stop reported to the controlling client."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.semihost_use_syscalls = True
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.thread_provider = None
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.target_context.read_core_register.return_value = 0x1000
        client = _make_client(1)
        client.is_interrupted.return_value = False
        client.receive.return_value = b'$F0,0#00'
        halt_count = 0

        def _handle_semihosting(client=None):
            nonlocal halt_count
            halt_count += 1
            if halt_count == 1:
                return GDBServer._handle_semihosting(server, client=client)
            return False

        def _handle_semihost_request():
            assert server._semihosting_client is client
            assert server.syscall('close,1') == (0, 0)
            return True

        def _observe_halt(_timeout):
            server.target.get_state.return_value = Target.State.HALTED
            return False

        server._handle_semihosting = Mock(side_effect=_handle_semihosting)
        server.semihost.check_and_handle_semihost_request.side_effect = _handle_semihost_request
        client.wait_for_interrupt.side_effect = _observe_halt
        retry_timeout = Mock()
        retry_timeout.check.return_value = True
        retry_timeout.did_time_out = False

        with patch('pyocd.gdbserver.gdbserver.Timeout', return_value=retry_timeout), \
                patch('pyocd.gdbserver.gdbserver.threading.current_thread', return_value=client):
            with server.lock:
                response = server.resume(client, None)

        assert response == b'T05thread:1;'
        assert halt_count == 2
        assert server.target.resume.call_count == 2
        assert client.wait_for_interrupt.call_count == 2
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        client.send.assert_called_once_with(b'Fclose,1')
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._semihosting_client is None
        assert server._active_run_client is None

    def test_service_loop_defers_halt_to_active_all_stop_client(self):
        """The all-stop client polls and classifies its own halts for GDB File-I/O."""
        server = _make_state_server(Target.State.RUNNING)
        server._STATE_INTERVAL = 0
        client = _make_client(1)
        server._active_run_client = client
        server._handle_semihosting = Mock()
        server.target.get_state.return_value = Target.State.RUNNING
        shutdown_event = Mock()
        shutdown_event.is_set.side_effect = (False, True)
        server.shutdown_event = shutdown_event

        server._run_service_thread()

        assert not server._is_halted
        server.target.get_state.assert_not_called()
        server._handle_semihosting.assert_not_called()
        server.trace_flush.assert_not_called()

    def test_service_loop_transparently_resumes_non_stop_semihosting(self):
        """Verify semihosting remains transparent to an active non-stop client.
        The service thread handles the request and preserves run ownership."""
        server = _make_state_server(Target.State.RUNNING)
        server._STATE_INTERVAL = 0
        _configure_semihost_bkpt(server)
        server.enable_semihosting = True
        server.trace_capture = Mock()
        server.target.get_state.return_value = Target.State.HALTED
        server.semihost.check_and_handle_semihost_request.return_value = True
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client
        server.target.resume.side_effect = server.shutdown_event.set

        server._run_service_thread()

        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted
        assert server._active_run_client is client
        client.send.assert_not_called()

    def test_service_loop_processes_semihosting_with_pending_raw_interrupt(self):
        """Verify a pending raw Ctrl-C does not block transparent semihosting."""
        server = _make_state_server(Target.State.RUNNING)
        server._STATE_INTERVAL = 0
        _configure_semihost_bkpt(server)
        server.enable_semihosting = True
        server.target.get_state.return_value = Target.State.HALTED
        server.semihost.check_and_handle_semihost_request.return_value = True
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = True
        server._active_run_client = client
        server.target.resume.side_effect = server.shutdown_event.set

        server._run_service_thread()

        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.target_context.write_core_register.assert_not_called()
        server.target_context.write32.assert_not_called()
        server.target.resume.assert_called_once_with()
        assert not server._is_halted
        assert client.is_interrupted()

    def test_service_loop_handles_unprocessed_halted_semihost_request(self):
        """Verify polling services an unprocessed semihosting halt.
        The request is handled once and target execution resumes without a client."""
        server = _make_state_server(Target.State.HALTED)
        _configure_semihost_bkpt(server)
        server.enable_semihosting = True
        server.trace_capture = Mock()
        server.target.get_state.return_value = Target.State.HALTED
        server.semihost.check_and_handle_semihost_request.return_value = True
        server._STATE_INTERVAL = 0
        server.target.resume.side_effect = server.shutdown_event.set
        server._is_halted = False

        server._run_service_thread()

        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        server.trace_capture.assert_not_called()
        server.trace_flush.assert_not_called()
        assert not server._is_halted

    def test_semihost_handler_keeps_lock_for_target_access(self):
        """Only the packet exchange, not semihost target access, releases the server lock."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.semihost_use_syscalls = True
        client = _make_client(1)
        server._active_run_client = client
        peer_started = threading.Event()
        peer_acquired = threading.Event()

        def _acquire_from_peer():
            peer_started.set()
            with server.lock:
                peer_acquired.set()

        peer = threading.Thread(target=_acquire_from_peer)

        def _handle_request():
            peer.start()
            assert peer_started.wait(1.0)
            assert not peer_acquired.wait(0.05)
            return True

        server.semihost.check_and_handle_semihost_request.side_effect = _handle_request
        with patch('pyocd.gdbserver.gdbserver.threading.current_thread', return_value=client):
            with server.lock:
                assert server._handle_semihosting(client)
                assert not peer_acquired.is_set()

        peer.join(1.0)
        assert peer_acquired.is_set()
        assert server._semihosting_client is None

    def test_semihost_file_io_client_is_cleared_after_error(self):
        """Verify a failed GDB File-I/O request cannot leave a stale client.
        The server lock stays held and temporary ownership is always cleared."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.semihost_use_syscalls = True
        client = _make_client(1)
        server._active_run_client = client
        semihost_error = exceptions.TransferError("test semihost failure")
        server.semihost.check_and_handle_semihost_request.side_effect = semihost_error

        with patch('pyocd.gdbserver.gdbserver.threading.current_thread', return_value=client):
            with server.lock:
                try:
                    server._handle_semihosting(client)
                except exceptions.TransferError as error:
                    assert error is semihost_error
                else:
                    assert False, "expected semihosting to fail"

        assert server._semihosting_client is None

    def test_start_rtt_publishes_server_and_configures_channels(self):
        """Verify automatic RTT discovery publishes and configures its server.
        Channel setup receives the GDB server's shared stdio handler."""
        server = _make_state_server(Target.State.HALTED)
        server.stdio_handler = Mock()
        server._rtt_manager = Mock()
        rtt_server = Mock()
        server._rtt_manager.start_server.return_value = rtt_server

        server._start_rtt()

        assert server.rtt_server is rtt_server
        server._rtt_manager.configure_channels.assert_called_once_with(stdio_handler=server.stdio_handler)

    def test_start_rtt_stops_server_if_shutdown_wins_race(self):
        """Verify RTT discovered during shutdown is stopped immediately.
        It must not be published or have channels configured after shutdown."""
        server = _make_state_server(Target.State.HALTED)
        server.stdio_handler = Mock()
        server._rtt_manager = Mock()
        rtt_server = Mock()
        server._rtt_manager.start_server.return_value = rtt_server
        server.shutdown_event.set()

        server._start_rtt()

        rtt_server.stop.assert_called_once_with()
        assert server.rtt_server is None
        server._rtt_manager.configure_channels.assert_not_called()

    def test_service_loop_retries_rtt_discovery_then_polls(self):
        """Verify failed RTT discovery is retried and the result is polled.
        This works while the target is halted and no GDB client is connected."""
        server = _make_state_server(Target.State.HALTED)
        server.stdio_handler = Mock()
        server._rtt_manager = Mock()
        rtt_server = Mock()
        rtt_server.running = True
        server._rtt_manager.start_server.side_effect = (
                exceptions.RTTError("test RTT discovery failure"), rtt_server)
        rtt_server.poll.side_effect = server.shutdown_event.set
        server._RTT_DISCOVERY_INTERVAL = 0
        server._RTT_INTERVAL = 0

        server._run_service_thread()

        assert server._rtt_manager.start_server.call_count == 2
        server._rtt_manager.configure_channels.assert_called_once_with(stdio_handler=server.stdio_handler)
        rtt_server.poll.assert_called_once_with()

    def test_service_loop_schedules_intervals_in_any_order(self):
        """Running RTT polling and missing-server discovery follow their own intervals."""
        for intervals in (*permutations((0.125, 0.25, 0.5)), (0.25, 0.25, 0.25)):
            for has_rtt_server in (False, True):
                server = _make_state_server(Target.State.RUNNING)
                server._RTT_INTERVAL, server._RTT_DISCOVERY_INTERVAL, server._STATE_INTERVAL = intervals
                server._rtt_manager = Mock()
                server.shutdown_event = Mock()
                start_time = 100.0
                end_time = start_time + 1.0
                now = start_time
                calls = {'rtt': [], 'discovery': [], 'state': []}

                if has_rtt_server:
                    server.rtt_server = Mock(running=True)
                    server.rtt_server.poll.side_effect = lambda: calls['rtt'].append(now)

                def _wait(timeout):
                    nonlocal now
                    assert timeout >= 0.0
                    assert server.shutdown_event.wait.call_count <= 16, "service clock did not advance"
                    now += timeout
                    return now >= end_time

                def _get_state():
                    calls['state'].append(now)
                    return Target.State.RUNNING

                server.shutdown_event.is_set.side_effect = lambda: now >= end_time
                server.shutdown_event.wait.side_effect = _wait
                server._start_rtt = Mock(side_effect=lambda: calls['discovery'].append(now))
                server.target.get_state.side_effect = _get_state

                with patch('pyocd.gdbserver.gdbserver.time.monotonic', side_effect=lambda: now):
                    server._run_service_thread()

                rtt_interval, discovery_interval, state_interval = intervals
                expected_rtt = [start_time + i * rtt_interval for i in range(int(1.0 / rtt_interval))]
                expected_discovery = [start_time + i * discovery_interval for i in range(int(1.0 / discovery_interval))]
                expected_state = [start_time + i * state_interval for i in range(int(1.0 / state_interval))]
                assert calls['rtt'] == (expected_rtt if has_rtt_server else []), intervals
                assert calls['discovery'] == ([] if has_rtt_server else expected_discovery), intervals
                assert calls['state'] == expected_state, intervals

    def test_service_loop_checks_inactive_rtt_at_discovery_interval(self):
        """Inactive RTT uses the discovery interval; running RTT uses the poll interval."""
        for has_manager, running, expected_wait in (
                (False, None, 0.25),
                (True, False, 0.25),
                (True, True, 0.125)):
            server = _make_state_server(Target.State.HALTED)
            server._rtt_manager = Mock() if has_manager else None
            if running is not None:
                server.rtt_server = Mock(running=running)
            server._RTT_DISCOVERY_INTERVAL = 0.25
            server._RTT_INTERVAL = 0.125
            server._STATE_INTERVAL = 0.5
            server.shutdown_event = Mock()
            server.shutdown_event.is_set.side_effect = (False, True)

            with patch('pyocd.gdbserver.gdbserver.time.monotonic', return_value=100.0):
                server._run_service_thread()

            server.shutdown_event.wait.assert_called_once_with(expected_wait)
            if server._rtt_manager is not None:
                server._rtt_manager.start_server.assert_not_called()
            if server.rtt_server is not None:
                assert server.rtt_server.poll.call_count == int(running)

    def test_service_loop_drops_discovery_deadline_after_rtt_starts(self):
        """Successful discovery hands scheduling over to RTT polling."""
        server = _make_state_server(Target.State.HALTED)
        server._rtt_manager = Mock()
        server.stdio_handler = Mock()
        rtt_server = Mock(running=True)
        server._rtt_manager.start_server.return_value = rtt_server
        server._RTT_DISCOVERY_INTERVAL = 0
        server._RTT_INTERVAL = 0.125
        server._STATE_INTERVAL = 0.25
        server.shutdown_event = Mock()
        server.shutdown_event.is_set.side_effect = (False, False, True)

        with patch('pyocd.gdbserver.gdbserver.time.monotonic', return_value=100.0):
            server._run_service_thread()

        server._rtt_manager.start_server.assert_called_once_with()
        rtt_server.poll.assert_called_once_with()
        server.shutdown_event.wait.assert_called_once_with(0.125)

    def test_service_loop_continues_after_rtt_failure(self):
        """Verify a temporary RTT polling error does not stop runtime service.
        The next due poll is attempted and can complete normally."""
        server = _make_state_server(Target.State.HALTED)
        rtt_server = Mock()
        rtt_server.running = True
        server.rtt_server = rtt_server
        server._RTT_INTERVAL = 0
        poll_count = 0

        def _poll():
            nonlocal poll_count
            poll_count += 1
            if poll_count == 1:
                raise exceptions.TransferError("test RTT poll failure")
            server.shutdown_event.set()

        rtt_server.poll.side_effect = _poll

        server._run_service_thread()

        assert poll_count == 2

    def test_service_loop_polls_rtt_before_target_state(self):
        """Verify RTT receives priority when both service deadlines are due.
        Delaying halt detection briefly protects the target's small RTT buffers."""
        server = _make_state_server(Target.State.RUNNING)
        server._RTT_INTERVAL = 0
        server._STATE_INTERVAL = 0
        rtt_server = Mock()
        rtt_server.running = True
        server.rtt_server = rtt_server
        service_order = []
        rtt_server.poll.side_effect = lambda: service_order.append("rtt")

        def _get_state():
            service_order.append("state")
            if service_order.count("state") == 2:
                server.shutdown_event.set()
            return Target.State.RUNNING

        server.target.get_state.side_effect = _get_state

        server._run_service_thread()

        assert service_order == ["rtt", "state", "rtt", "state"]

    def test_non_stop_resume_failure_is_reconciled_by_later_state_poll(self):
        """A failed non-stop resume releases ownership before polling observes the halt."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._handle_semihosting = Mock(return_value=False)
        resume_error = exceptions.TransferError("test resume failure")
        server.target.resume.side_effect = resume_error
        server.target.get_state.return_value = Target.State.HALTED
        client = _make_client(1)
        client.non_stop = True

        try:
            server.v_cont(client, b'Cont;c')
        except exceptions.TransferError as error:
            assert error is resume_error
        else:
            assert False, "expected resume to fail"

        assert server._active_run_client is None
        assert not server._is_halted
        server.target.get_state.assert_not_called()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_not_called()

        with server.lock:
            server._read_and_process_target_state()

        assert server._is_halted
        server.target.get_state.assert_called_once_with()
        server._handle_semihosting.assert_called_once_with(client=None)
        server.trace_flush.assert_called_once_with()

    def test_resume_failure_followed_by_poll_failure_keeps_polling_enabled(self):
        """A failed recovery poll leaves the next scheduled state read available."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        resume_error = exceptions.TransferError("test resume failure")
        poll_error = exceptions.TransferError("test poll failure")
        server.target.resume.side_effect = resume_error
        server.target.get_state.side_effect = (poll_error, Target.State.RUNNING)
        client = _make_client(1)
        client.non_stop = True

        try:
            server.v_cont(client, b'Cont;c')
        except exceptions.TransferError as error:
            assert error is resume_error
        else:
            assert False, "expected resume to fail"

        assert not server._is_halted
        assert server._active_run_client is None
        server.target.get_state.assert_not_called()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_not_called()

        try:
            with server.lock:
                server._read_and_process_target_state()
        except exceptions.TransferError as error:
            assert error is poll_error
        else:
            assert False, "expected state poll to fail"

        assert not server._is_halted
        server.target.get_state.assert_called_once_with()

        with server.lock:
            server._read_and_process_target_state()

        assert not server._is_halted
        assert server.target.get_state.call_count == 2

    def test_non_stop_resume_error_is_reconciled_when_poll_observes_running(self):
        """A later running-state poll leaves the cache running without a trace flush."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        resume_error = exceptions.TransferError("test late resume failure")
        server.target.resume.side_effect = resume_error
        server.target.get_state.return_value = Target.State.RUNNING
        client = _make_client(1)
        client.non_stop = True

        try:
            server.v_cont(client, b'Cont;c')
        except exceptions.TransferError as error:
            assert error is resume_error
        else:
            assert False, "expected resume to fail"

        assert server._active_run_client is None
        assert not server._is_halted
        server.target.get_state.assert_not_called()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_not_called()

        with server.lock:
            server._read_and_process_target_state()

        assert not server._is_halted
        server.target.get_state.assert_called_once_with()
        server.trace_flush.assert_not_called()

    def test_detach_resume_failure_is_reconciled_by_later_state_poll(self):
        """A failed final-detach resume leaves polling to observe the halt."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.trace_capture = Mock()
        server._handle_semihosting = Mock(return_value=False)
        client = _make_client(1)
        client.is_socket_connected = False
        _configure_client_lifecycle(server, [client], persist=True)
        resume_error = exceptions.TransferError("test resume failure")
        server.target.resume.side_effect = resume_error

        server.notify_client_detached(client)

        assert not server._is_halted
        server.target.get_state.assert_not_called()
        server.trace_capture.assert_called_once_with()
        server.trace_flush.assert_not_called()

        with server.lock:
            server._read_and_process_target_state()

        assert server._is_halted
        server.target.get_state.assert_called_once_with()
        server._handle_semihosting.assert_called_once_with(client=None)
        server.trace_flush.assert_called_once_with()

    def test_client_start_failure_restores_execution_for_existing_client(self):
        """Verify failed client startup restores execution owned by an existing client."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.listen_socket = Mock()
        existing_client = _make_client(1)
        _configure_client_lifecycle(server, [existing_client], persist=True)
        server._active_run_client = existing_client
        server.client_last_index = 1
        server._cleanup = Mock()
        connected_socket = Mock()
        connected_socket.get_remote_address.return_value = 'failed-client'
        server.listen_socket.accept.return_value = connected_socket
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 2)
        packet_io = Mock()
        packet_io._closed = False
        startup_order = []

        def _halt_target():
            startup_order.append('halt')

        def _fail_start():
            startup_order.append('client')
            server.shutdown_event.set()
            raise RuntimeError("test start failure")

        def _start_packet_io(_socket, _index):
            startup_order.append('packet-io')
            return packet_io

        server.target.halt.side_effect = _halt_target
        client.start = Mock(side_effect=_fail_start)

        with patch('pyocd.gdbserver.gdbserver.threading.Timer'), \
                patch('pyocd.gdbserver.gdbserver.GDBClientSession', return_value=client), \
                patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', side_effect=_start_packet_io):
            server.run()

        assert startup_order == ['packet-io', 'halt', 'client']
        packet_io.stop.assert_called_once_with()
        connected_socket.close.assert_called_once_with()
        assert not client.is_attached_to_target
        assert client not in server.client_sessions
        assert server.client_sessions == [existing_client]
        assert existing_client.is_attached_to_target
        assert server._active_run_client is existing_client
        server.target.resume.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        server.trace_capture.assert_called_once_with()
        assert not server._is_halted

    def test_repeated_detach_does_not_resume_target_twice(self):
        """Verify duplicate cleanup notifications are idempotent.
        Only the first detach of the final attached client may resume target."""
        server = _make_state_server(Target.State.HALTED)
        server.trace_capture = Mock()
        client = _make_client(1)
        client.is_socket_connected = False
        _configure_client_lifecycle(server, [client], persist=True)

        server.notify_client_detached(client)
        server.notify_client_detached(client)

        server.target.resume.assert_called_once_with()
        server.target.get_state.assert_not_called()
        server.trace_capture.assert_called_once_with()

    def test_client_thread_stop_defers_socket_cleanup(self):
        """Verify a client stopping itself leaves packet I/O available for its reply.
        Final cleanup remains the run method's responsibility."""
        server = _make_state_server(Target.State.HALTED)
        connected_socket = Mock()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client._packet_io = Mock()

        with patch('pyocd.gdbserver.gdbserver.threading.current_thread', return_value=client):
            client.stop()

        assert client.shutdown_event.is_set()
        client._packet_io.stop.assert_not_called()
        connected_socket.close.assert_not_called()

        client.cleanup()
        client._packet_io.stop.assert_called_once_with()
        connected_socket.close.assert_called_once_with()

    def test_cleanup_error_log_uses_explicit_client_index(self):
        """Verify cleanup logging identifies the client when another thread performs cleanup."""
        server = _make_state_server(Target.State.HALTED)
        connected_socket = Mock()
        error = RuntimeError("test cleanup failure")
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 4)
        client._packet_io = Mock()
        client._packet_io.stop.side_effect = error

        with patch('pyocd.gdbserver.gdbserver.LOG.debug') as debug_log:
            client.cleanup()

        debug_log.assert_called_once_with("Error stopping packet I/O or closing socket: %s", error,
                exc_info=False, extra={'client_index': 4})
        connected_socket.close.assert_called_once_with()


class TestGdbServerSyscalls:
    def test_syscall_without_client_returns_not_connected(self):
        """Verify that a GDB syscall is skipped when no client can service it.
        The target receives a normal failure result instead of raising an exception."""
        server = _make_state_server(Target.State.HALTED)
        operation = 'open,1000/4,0,1ff'

        with patch('pyocd.gdbserver.gdbserver.LOG.debug') as debug_log:
            result = server.syscall(operation)

        assert result == (-1, errno.ENOTCONN)
        debug_log.assert_any_call("Skipping GDB syscall because no client is available: %s", operation)

    def test_syscall_with_active_client_preserves_gdb_file_io(self):
        """Verify an active all-stop client still services GDB File-I/O.
        The request is sent over RSP and its result and errno are returned."""
        server = _make_state_server(Target.State.HALTED)
        client = _make_client(1)
        client.is_interrupted.return_value = False
        client.receive.return_value = b'$F3,0#00'
        server._semihosting_client = client

        with server.lock:
            result = server.syscall('write,1,1000,3')

        assert result == (3, 0)
        client.send.assert_called_once_with(server.create_rsp_packet(b'Fwrite,1,1000,3'))

    def test_syscall_services_gdb_memory_packets_while_waiting(self):
        """GDB can read semihost arguments before returning the File-I/O result."""
        server = _make_state_server(Target.State.HALTED)
        client = _make_client(1)
        server._semihosting_client = client
        server.COMMANDS = {b'm': (server.get_memory, 2)}
        server.target_context.read_memory_block8.return_value = [0xab]
        client.receive.side_effect = (b'$m1000,1#00', b'$F0,0#00')

        with server.lock:
            result = server.syscall('open,1000/1,0,1ff')

        assert result == (0, 0)
        assert client.send.call_args_list[0].args == (server.create_rsp_packet(b'Fopen,1000/1,0,1ff'),)
        assert client.send.call_args_list[1].args == (server.create_rsp_packet(b'ab'),)
        server.target_context.read_memory_block8.assert_called_once_with(0x1000, 1)

    def test_syscall_wait_allows_rtt_and_client_queries(self):
        """File-I/O waits let RTT polling and other clients read target state."""
        server = _make_state_server(Target.State.HALTED)
        owner = _make_client(1)
        observer = _make_client(2)
        server._semihosting_client = owner
        server._active_run_client = owner
        server.rtt_server = Mock()
        rtt_polled = threading.Event()
        server.rtt_server.poll.side_effect = rtt_polled.set
        server.COMMANDS = {
                b'm': (server.get_memory, 2),
                b'q': (server.handle_query, 2),
                }
        server.target_context.read_memory_block8.return_value = [0xab]
        waiting = threading.Event()
        finish = threading.Event()
        results = []
        errors = []

        def _receive(_block):
            waiting.set()
            assert finish.wait(2.0)
            return b'$F0,0#00'

        def _run_syscall():
            try:
                with server.lock:
                    results.append(server.syscall('close,1'))
            except BaseException as error:
                errors.append(error)

        owner.receive.side_effect = _receive
        worker = threading.Thread(target=_run_syscall)
        service = threading.Thread(target=server._run_service_thread)
        worker.start()
        try:
            assert waiting.wait(1.0)
            service.start()
            assert rtt_polled.wait(1.0)
            assert server.handle_message(observer, b'$m1000,1#00') == server.create_rsp_packet(b'ab')
            assert server.handle_message(observer, b'$qOffsets#00') == server.create_rsp_packet(b'Text=0;Data=0;Bss=0')
        finally:
            server.shutdown_event.set()
            finish.set()
            if service.ident is not None:
                service.join(2.0)
            worker.join(2.0)

        assert not service.is_alive()
        assert not worker.is_alive()
        assert errors == []
        assert results == [(0, 0)]
        server.rtt_server.poll.assert_called()

    def test_syscall_void_send_waits_for_file_io_reply(self):
        """A void send result does not prevent receiving a File-I/O reply."""
        server = _make_state_server(Target.State.HALTED)
        client = _make_client(1)
        client.send.return_value = None
        client.receive.return_value = b'$F0,0#00'
        server._semihosting_client = client

        with server.lock:
            result = server.syscall('write,1,1000,3')

        assert result == (0, 0)
        client.send.assert_called_once_with(server.create_rsp_packet(b'Fwrite,1,1000,3'))
        client.receive.assert_called_once_with(False)

    def test_syscall_disconnect_during_request_returns_not_connected(self):
        """Verify connection loss while awaiting File-I/O reports ENOTCONN.
        The closed client is marked unavailable for subsequent operations."""
        server = _make_state_server(Target.State.HALTED)
        client = _make_client(1)
        client.is_interrupted.return_value = False
        client.receive.side_effect = ConnectionClosedException()
        server._semihosting_client = client

        with server.lock:
            result = server.syscall('write,1,1000,3')

        assert result == (-1, errno.ENOTCONN)
        assert not client.is_socket_connected

    def test_syscall_client_shutdown_during_send_returns_not_connected(self):
        """Verify shutdown racing with a File-I/O send reports ENOTCONN.
        This covers disconnect after validation but before the receive loop."""
        server = _make_state_server(Target.State.HALTED)
        client = _make_client(1)
        client.is_interrupted.return_value = False
        client.send.side_effect = lambda _packet: client.shutdown_event.set()
        server._semihosting_client = client

        with server.lock:
            result = server.syscall('write,1,1000,3')

        assert result == (-1, errno.ENOTCONN)

    def test_service_resumes_after_skipped_syscall(self):
        """Verify that client-independent semihosting continues after a skipped syscall.
        The service thread reports failure to the target and resumes its execution."""
        server = _make_state_server(Target.State.RUNNING)
        _configure_semihost_bkpt(server)
        server.enable_semihosting = True
        server.semihost_use_syscalls = True
        server.target.get_state.return_value = Target.State.HALTED
        server._STATE_INTERVAL = 0

        def _handle_request():
            assert server.syscall('open,1000/4,0,1ff') == (-1, errno.ENOTCONN)
            return True

        server.semihost.check_and_handle_semihost_request.side_effect = _handle_request
        server.target.resume.side_effect = server.shutdown_event.set

        server._run_service_thread()

        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_failed_syscall_read_and_write_report_all_bytes_unprocessed(self):
        """Verify conversion of failed GDB read and write results to semihost results.
        A failed operation reports that the complete buffer remains unprocessed."""
        server = Mock()
        server.syscall.return_value = (-1, errno.ENOTCONN)
        handler = GDBSyscallIOHandler(server)

        assert handler.write(4, 0x1000, 16) == 16
        assert handler.read(4, 0x1000, 16) == 16
        assert handler.errno == errno.ENOTCONN

    def test_successful_syscall_read_and_write_report_remaining_bytes(self):
        """Verify GDB byte counts are converted to semihost remaining counts.
        Partial transfer returns the remainder and a complete transfer returns zero."""
        server = Mock()
        server.syscall.side_effect = ((12, 0), (16, 0))
        handler = GDBSyscallIOHandler(server)

        assert handler.write(4, 0x1000, 16) == 4
        assert handler.read(4, 0x1000, 16) == 0
        assert handler.errno == 0

    def test_syscall_semihosting_disables_non_stop_negotiation(self):
        """Verify syscall semihosting neither advertises nor accepts non-stop mode.
        Synchronous GDB File-I/O requires an all-stop client."""
        server = _make_state_server(Target.State.HALTED)
        server.semihost_use_syscalls = True
        server.packet_size = 2048
        client = _make_client(1)
        client.target_facade.get_memory_map_xml.return_value = None

        supported = server.handle_query(client, b'Supported:multiprocess+#00')
        non_stop_response = server.handle_general_set(client, b'NonStop:1#00')

        assert b'QNonStop+' not in supported
        assert non_stop_response == server.create_rsp_packet(b'E01')
        assert not client.non_stop


class TestGdbServerPacketIO:
    def test_remote_close_marks_packet_io_closed(self):
        """Verify that remote EOF closes the connection and wakes receivers."""
        connected_socket = Mock()
        connected_socket.read.return_value = b''

        packet_io = GDBServerPacketIOThread(connected_socket, 1)
        packet_io.join(1.0)

        assert not packet_io.is_alive()
        assert packet_io._closed
        try:
            packet_io.receive(block=False)
        except ConnectionClosedException:
            pass
        else:
            assert False, "expected receive to report a closed connection"

    def test_write_packet_completes_partial_socket_writes(self):
        """Verify that partial socket writes are retried until all data is sent."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._closed = False
        packet_io._socket = Mock()
        packet_io.send_acks = False
        written = bytearray()
        sizes = iter((2, 1, 100))

        def _partial_write(data):
            count = min(next(sizes), len(data))
            written.extend(data[:count])
            return count

        packet_io._socket.write.side_effect = _partial_write

        packet_io._write_packet(b'abcdef')
        assert written == b'abcdef'
        assert packet_io._socket.write.call_args_list[0].args == (b'abcdef',)
        assert packet_io._socket.write.call_args_list[1].args == (b'cdef',)
        assert packet_io._socket.write.call_args_list[2].args == (b'def',)
        assert not packet_io._closed

    def test_packet_send_tracks_ack_without_returning_status(self):
        """Sending a packet writes it and records the expected RSP ACK."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._closed = False
        packet_io._socket = Mock()
        packet_io._socket.write.return_value = len(b'$OK#9a')
        packet_io.drop_reply = False
        packet_io._last_packet = b''
        packet_io.send_acks = True
        packet_io._expecting_ack = False

        assert packet_io.send(b'$OK#9a') is None

        packet_io._socket.write.assert_called_once_with(b'$OK#9a')
        assert packet_io._last_packet == b'$OK#9a'
        assert packet_io._expecting_ack

    def test_packet_send_when_closed_does_not_write(self):
        """A closed connection silently discards outgoing packets."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._closed = True
        packet_io._socket = Mock()

        assert packet_io.send(b'$OK#9a') is None
        packet_io._socket.write.assert_not_called()

    def test_dropped_reply_does_not_write_or_close(self):
        """An intentional drop does not write to the socket or close it."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._closed = False
        packet_io._socket = Mock()
        packet_io.drop_reply = True

        assert packet_io.send(b'$OK#9a') is None
        assert not packet_io.drop_reply
        assert not packet_io._closed
        packet_io._socket.write.assert_not_called()

    def test_packet_send_reset_marks_connection_closed(self):
        """A connection reset during send marks packet I/O closed."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._closed = False
        packet_io._socket = Mock()
        packet_io._socket.write.side_effect = ConnectionResetError("test reset")
        packet_io.drop_reply = False
        packet_io._last_packet = b''
        packet_io.send_acks = True
        packet_io._expecting_ack = False

        assert packet_io.send(b'$OK#9a') is None

        assert packet_io._closed
        assert packet_io._last_packet == b'$OK#9a'
        assert packet_io._expecting_ack

    def test_packet_receive_reset_marks_connection_closed(self):
        """A connection reset during receive closes packet I/O."""
        connected_socket = Mock()
        connected_socket.read.side_effect = ConnectionResetError("test reset")

        packet_io = GDBServerPacketIOThread(connected_socket, 1)
        packet_io.join(1.0)

        assert not packet_io.is_alive()
        assert packet_io._closed
        try:
            packet_io.receive(block=False)
        except ConnectionClosedException:
            pass
        else:
            assert False, "expected receive to report a closed connection"

    def test_receive_timeout_is_retryable(self):
        """Verify that a receive timeout is retried without closing immediately."""
        connected_socket = Mock()
        connected_socket.read.side_effect = [socket.timeout(), b'']

        packet_io = GDBServerPacketIOThread(connected_socket, 1)
        try:
            packet_io.join(1.0)

            assert connected_socket.read.call_count == 2
            assert not packet_io.is_alive()
            assert packet_io._closed
        finally:
            packet_io.stop()

    def test_send_timeout_propagates(self):
        """A send timeout is propagated by the restored packet I/O implementation."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._closed = False
        packet_io._socket = Mock()
        packet_io._socket.write.side_effect = socket.timeout("test send timeout")
        packet_io.send_acks = False

        try:
            packet_io._write_packet(b'$OK#9a')
        except socket.timeout:
            pass
        else:
            assert False, "expected send timeout to propagate"
        assert not packet_io._closed


class TestGdbServerSimplifiedRunControl:
    def _run_one_service_poll(self, server, state):
        server.target.get_state.return_value = state
        server.rtt_server = Mock(running=True)
        server.rtt_server.poll.side_effect = server.shutdown_event.set
        server._run_service_thread()

    def test_initial_cached_halt_is_reported_to_later_client(self):
        """A later client receives the existing stop without replaying semihosting."""
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.rtt_server = Mock(running=True)
        server.rtt_server.poll.side_effect = server.shutdown_event.set

        server._run_service_thread()

        assert server._is_halted
        server.target.get_state.assert_not_called()
        server.semihost.check_and_handle_semihost_request.assert_not_called()
        server.target.resume.assert_not_called()
        server.rtt_server.poll.assert_called_once_with()

        server.shutdown_event.clear()
        server.port = 3333
        server.listen_socket = Mock()
        server.client_sessions = []
        server.client_sessions_lock = threading.Lock()
        server.client_last_index = 0
        server._cleanup = Mock()
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        stop_replies = []

        def _start_client():
            stop_replies.append(server.stop_reason_query(client))
            server.shutdown_event.set()

        client.start.side_effect = _start_client
        with patch('pyocd.gdbserver.gdbserver.threading.Timer'), \
                patch('pyocd.gdbserver.gdbserver.GDBClientSession', return_value=client):
            server.run()

        assert stop_replies == [server.create_rsp_packet(b'T05thread:1;')]
        server.get_t_response.assert_called_once_with(client)
        server.target.halt.assert_called_once_with()
        server.semihost.check_and_handle_semihost_request.assert_not_called()
        server.target.resume.assert_not_called()
    def test_initial_running_target_is_polled_without_semihosting(self):
        """An already running target is not serviced as an initial halt."""
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True

        self._run_one_service_poll(server, Target.State.RUNNING)

        assert not server._is_halted
        assert server._active_run_client is None
        server.target.get_state.assert_called_once_with()
        server.semihost.check_and_handle_semihost_request.assert_not_called()
        server.target.resume.assert_not_called()
        server.trace_capture.assert_not_called()

    def test_polled_semihost_error_preserves_halt_and_continues_service(self):
        """A failed request at an observed halt leaves the target halted and RTT active."""
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True
        semihost_error = exceptions.TransferError("test semihost failure")
        server._handle_semihosting = Mock(side_effect=semihost_error)

        self._run_one_service_poll(server, Target.State.HALTED)

        assert server._is_halted
        server._handle_semihosting.assert_called_once_with(client=None)
        server.target.get_state.assert_called_once_with()
        server.rtt_server.poll.assert_called_once_with()
        server.trace_capture.assert_not_called()
        server.trace_flush.assert_not_called()
        server.target.resume.assert_not_called()

    def test_unexpected_polled_semihost_error_does_not_stop_service(self):
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True
        server._handle_semihosting = Mock(side_effect=ValueError("test semihost failure"))

        self._run_one_service_poll(server, Target.State.HALTED)

        server._handle_semihosting.assert_called_once_with(client=None)
        server.target.get_state.assert_called_once_with()
        server.rtt_server.poll.assert_called_once_with()
        server.target.resume.assert_not_called()
        assert server._is_halted

    def test_shutdown_before_initial_service_skips_semihosting(self):
        server = _make_state_server(Target.State.HALTED)
        server.enable_semihosting = True
        server.shutdown_event.set()

        server._run_service_thread()

        server.semihost.check_and_handle_semihost_request.assert_not_called()
        server.target.resume.assert_not_called()
        server.target.get_state.assert_not_called()

    def test_polled_semihost_resume_error_allows_next_halt_to_be_processed(self):
        """A failed resume can be followed by another observed halt."""
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True
        server._handle_semihosting = Mock(side_effect=(True, False))
        server.target.resume.side_effect = exceptions.TransferError("test resume failure")
        server.session.options.get.return_value = 1.0
        server._STATE_INTERVAL = 0
        read_count = 0

        def _get_state():
            nonlocal read_count
            read_count += 1
            if read_count == 2:
                server.shutdown_event.set()
            return Target.State.HALTED

        server.target.get_state.side_effect = _get_state

        server._run_service_thread()

        assert read_count == 2
        assert server._handle_semihosting.call_count == 2
        server.target.resume.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._is_halted

    def test_disabled_semihosting_does_not_service_initial_halt(self):
        """Startup keeps an initial halt when semihosting is disabled."""
        server = _make_state_server(Target.State.HALTED)
        server._handle_semihosting = Mock(return_value=True)

        self._run_one_service_poll(server, Target.State.HALTED)

        server._handle_semihosting.assert_not_called()
        server.target.resume.assert_not_called()
        server.target.get_state.assert_not_called()
        assert server._is_halted
        server.trace_capture.assert_not_called()
        server.trace_flush.assert_not_called()

    def test_disabled_semihosting_stops_after_physical_step(self):
        """A step halt remains visible when semihosting is disabled."""
        server = _make_state_server(Target.State.HALTED)
        server.target.read_core_register.return_value = 0x1000
        server._handle_semihosting = Mock(return_value=True)
        client = _make_client(1)

        server._execute_step(client)

        server.target.step.assert_called_once()
        server._handle_semihosting.assert_not_called()

    def test_initial_ordinary_breakpoint_remains_visible_without_a_client(self):
        server = _make_halt_server()

        self._run_one_service_poll(server, Target.State.HALTED)

        assert server._is_halted
        server._handle_semihosting.assert_not_called()
        server.target.resume.assert_not_called()
        server.target.get_state.assert_not_called()
        server.target.step_over_breakpoint_instruction.assert_not_called()
        server.trace_flush.assert_not_called()

    def test_consumed_breakpoint_at_range_end_does_not_execute_outside_range(self):
        for non_stop in (False, True):
            server = _make_halt_server()
            server.is_threading_enabled = Mock(return_value=False)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            server.get_t_response = Mock(return_value=b'T05thread:1;')
            server.target.read_core_register.side_effect = (0x1000, 0x1002)
            client = _make_client(1)
            client.non_stop = non_stop

            response = server.v_cont(client, b'Cont;r1000,1002')

            server.target.step.assert_called_once()
            server.target.step_over_breakpoint_instruction.assert_called_once_with(0x1000)
            assert server._is_halted
            if non_stop:
                assert response is None
                assert server._active_run_client is client
                assert client._awaiting_vstopped
                server.v_command(client, b'Stopped#00')
            else:
                assert response == b'T05thread:1;'
            assert server._active_run_client is None

    def test_successful_semihost_resume_updates_cached_halt(self):
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True
        server.target.get_state.return_value = Target.State.HALTED
        server._handle_semihosting = Mock(return_value=True)

        with server.lock:
            server._read_and_process_target_state()

        server.target.resume.assert_called_once_with()
        assert not server._is_halted

    def test_notification_error_still_allows_disconnect_cleanup(self):
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.get_t_response = Mock(side_effect=exceptions.TransferError("test stop response failure"))
        server.notify_client_detached = Mock(wraps=server.notify_client_detached)
        # Bound the loop even if a notification error incorrectly prevents receiving packets.
        server.shutdown_event = Mock()
        server.shutdown_event.is_set.side_effect = (False, False, True)
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.receive.side_effect = ConnectionClosedException()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, Mock(), 1)
        client._packet_io = packet_io
        client.non_stop = True
        client.is_attached_to_target = True
        server._active_run_client = client
        _configure_client_lifecycle(server, [client], persist=True)

        client.run()

        server.get_t_response.assert_called_once_with(client, forceSignal=None)
        packet_io.receive.assert_called_once_with(False)
        packet_io.stop.assert_called_once_with()
        server.notify_client_detached.assert_called_once_with(client)
        assert not client._awaiting_vstopped
        assert server._active_run_client is None
