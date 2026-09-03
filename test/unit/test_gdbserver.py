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
import socket
import threading
from unittest.mock import Mock, patch

from pyocd.core import exceptions
from pyocd.core.target import Target
from pyocd.gdbserver import signals
from pyocd.gdbserver.gdbserver import (
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
    server._state_cond = threading.Condition(server.lock)
    server._target_state = initial_state
    server._poll_error = None
    server._active_run_client = None
    server._semihosting_client = None
    server.enable_semihosting = False
    server.semihost_use_syscalls = False
    server.semihost = Mock()
    server.semihost.check_and_handle_semihost_request.return_value = False
    server.rtt_server = None
    server._rtt_manager = None
    server.target = Mock()
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
    client._stop_notification_pending = False
    client.non_stop = False
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


class TestGdbServerRuntimeService:
    def test_only_one_client_can_have_an_active_run(self):
        """Verify that only one client can own a run until that run ends."""
        server = _make_state_server()
        first_client = _make_client(1)
        second_client = _make_client(2)

        assert server._begin_run(first_client)
        assert not server._begin_run(second_client)
        assert server._active_run_client is first_client

        server._end_run(second_client)
        assert server._active_run_client is first_client

        server._end_run(first_client)
        assert server._active_run_client is None
        assert server._begin_run(second_client)

    def test_detached_or_disconnected_client_cannot_begin_run(self):
        """Verify that detached or disconnected clients cannot start a run."""
        for is_attached, is_closed in ((False, False), (True, True)):
            server = _make_state_server(Target.State.HALTED)
            client = _make_client(1)
            client.is_attached_to_target = is_attached
            client.is_connection_closed = is_closed

            assert not server._begin_run(client)
            assert server._active_run_client is None

    def test_service_state_tracks_sleeping_then_halted_without_clients(self):
        """Verify that background polling tracks sleep and halt states without clients."""
        server = _make_state_server()
        server.target.get_state.side_effect = [Target.State.SLEEPING, Target.State.HALTED]

        with server.lock:
            server._service_state()
            server._service_state()

        state, error = server._get_state()
        assert state == Target.State.HALTED
        assert error is None
        server.trace_flush.assert_called_once_with()

    def test_service_loop_retries_after_poll_error(self):
        """Verify that background polling retries after a transfer error.
        A later successful poll must clear the error and publish the halted state."""
        server = _make_state_server()
        server._STATE_INTERVAL = 0
        call_count = 0

        def _get_state():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise exceptions.TransferError("test transfer error")
            server.shutdown_event.set()
            return Target.State.HALTED

        server.target.get_state.side_effect = _get_state

        server._run_service_loop()

        state, error = server._get_state()
        assert call_count == 2
        assert state == Target.State.HALTED
        assert error is None

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
        server._active_run_client = active_client
        payload = b'Stop:T05thread:1;'

        assert not server._try_send_stop_notification(passive_client)
        assert server._try_send_stop_notification(active_client)
        assert not server._try_send_stop_notification(active_client)

        passive_client.send.assert_not_called()
        active_client.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert active_client._stop_notification_pending
        assert server._active_run_client is active_client

    def test_detached_or_disconnected_client_does_not_receive_stop_notification(self):
        """Verify that detached or disconnected clients receive no stop notification."""
        for is_attached, is_closed in ((False, False), (True, True)):
            server = _make_state_server(Target.State.HALTED)
            server.get_t_response = Mock(return_value=b'T05thread:1;')
            client = _make_client(1)
            client.is_attached_to_target = is_attached
            client.is_connection_closed = is_closed
            server._active_run_client = client

            assert not server._try_send_stop_notification(client)
            client.send.assert_not_called()
            assert not client._stop_notification_pending

    def test_vstopped_completes_active_run(self):
        """Verify that vStopped acknowledges a pending stop and completes the run."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(return_value=b'$OK#9a')
        client = _make_client(1)
        client._stop_notification_pending = True
        server._active_run_client = client

        response = server.v_command(client, b'Stopped')

        assert response == b'$OK#9a'
        assert not client._stop_notification_pending
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
        assert client._stop_notification_pending
        assert server._active_run_client is client

    def test_all_stop_resume_clears_active_client(self):
        """Verify that an all-stop resume releases run ownership when it finishes."""
        server = _make_state_server(Target.State.HALTED)
        server._resume = Mock(return_value=b'$T05#b9')
        client = _make_client(1)

        response = server.resume(client, None)

        assert response == b'$T05#b9'
        assert server._active_run_client is None

    def test_failed_stop_notification_clears_active_client(self):
        """Verify that a failed stop notification clears pending state and ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.send.side_effect = RuntimeError("test send failure")
        server._active_run_client = client

        try:
            server._try_send_stop_notification(client)
        except RuntimeError:
            pass
        else:
            assert False, "expected stop notification to fail"

        assert not client._stop_notification_pending
        assert server._active_run_client is None

    def test_non_stop_continue_selects_active_client(self):
        """Verify that non-stop continue assigns ownership before resuming the target."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server._mark_running = Mock()
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.non_stop = True

        response = server.v_cont(client, b'Cont;c')

        assert response == b'OK'
        assert server._active_run_client is client
        server.target.resume.assert_called_once_with()

    def test_non_stop_continue_adopts_unowned_execution(self):
        """Verify that a non-stop client adopts an already running unowned target."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server._mark_running = Mock()
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.non_stop = True

        response = server.v_cont(client, b'Cont;c')

        assert response == b'OK'
        assert server._active_run_client is client
        server.trace_capture.assert_not_called()
        server.target.resume.assert_not_called()
        server._mark_running.assert_not_called()

    def test_all_stop_continue_adopts_execution_until_connection_closes(self):
        """Verify that all-stop continue adopts execution and exits when its client closes."""
        server = _make_state_server(Target.State.RUNNING)
        server.trace_capture = Mock()
        server._mark_running = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        client = _make_client(1)
        client.is_interrupted.return_value = False

        def _close_connection(_timeout):
            client.is_connection_closed = True
            return False

        server._wait_while_running = Mock(side_effect=_close_connection)

        with server.lock:
            response = server.resume(client, None)

        assert response is None
        assert server._active_run_client is None
        server.trace_capture.assert_not_called()
        server.target.resume.assert_not_called()
        server._mark_running.assert_not_called()

    def test_all_stop_continue_adopts_execution_until_target_halts(self):
        """Verify that all-stop continue adopts execution and reports its later halt."""
        server = _make_state_server(Target.State.RUNNING)
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = False
        server.session.options.get.return_value = 0.1
        server.target_context = Mock()
        server.target_context.read_core_register.return_value = 0x1000
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.is_interrupted.return_value = False

        def _observe_halt(_timeout):
            server._set_state(Target.State.HALTED)
            return True

        server._wait_while_running = Mock(side_effect=_observe_halt)

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T05thread:1;'
        assert server._active_run_client is None
        server.trace_capture.assert_not_called()
        server.target.resume.assert_not_called()

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

        def _observe_halt(_timeout):
            with server.lock:
                server._service_state()
            return True

        server._wait_while_running = Mock(side_effect=_observe_halt)

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T05thread:1;'
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        assert server._get_state() == (Target.State.HALTED, None)
        assert server._active_run_client is None

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
            client.is_connection_closed = True
            return False

        server._wait_while_running = Mock(side_effect=_close_connection)

        with server.lock:
            response = server.resume(client, None)

        assert response is None
        assert server._active_run_client is None
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        state, error = server._get_state()
        assert state == Target.State.RUNNING
        assert error is None

    def test_all_stop_close_during_non_semihost_halt_sends_no_response(self):
        """Verify that disconnect during a normal halt suppresses the stop reply.
        Semihost checking still runs, but no register access is done for the dead client."""
        server = _make_state_server(Target.State.RUNNING)
        server.trace_capture = Mock()
        server.first_run_after_reset_or_flash = False
        server.rtt_server = None
        server.enable_semihosting = True
        server._semihosting_client = None
        server.semihost = Mock()
        server.session.options.get.return_value = 0.1
        server.target_context = Mock()
        server.get_t_response = Mock()
        client = _make_client(1)
        client.is_interrupted.return_value = False

        def _observe_halt(_timeout):
            server._set_state(Target.State.HALTED)
            return True

        def _close_during_semihost_check():
            client.is_connection_closed = True
            return False

        server._wait_while_running = Mock(side_effect=_observe_halt)
        server.semihost.check_and_handle_semihost_request.side_effect = _close_during_semihost_check

        with server.lock:
            response = server.resume(client, None)

        assert response is None
        server.semihost.check_and_handle_semihost_request.assert_called_once_with()
        server.get_t_response.assert_not_called()
        server.target_context.read_core_register.assert_not_called()

    def test_step_rejects_unowned_execution(self):
        """Verify that all-stop step is rejected while an unowned target is executing."""
        server = _make_state_server(Target.State.RUNNING)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._step = Mock()
        client = _make_client(1)

        response = server.step(client, None)

        assert response == b'E01'
        assert server._active_run_client is None
        server._step.assert_not_called()

    def test_non_stop_step_rejects_unowned_execution(self):
        """Verify that non-stop step is rejected while an unowned target is executing."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._step_target = Mock()
        client = _make_client(1)
        client.non_stop = True

        response = server.v_cont(client, b'Cont;s')

        assert response == b'E01'
        assert server._active_run_client is None
        server._step_target.assert_not_called()

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

        response = server.step(client, None)

        assert response == b'T05thread:1;'
        server.trace_capture.assert_called_once_with()
        server.target.step.assert_called_once()
        assert server.target.step.call_args.args[:3] == (True, 0, 0)
        assert callable(server.target.step.call_args.kwargs['hook_cb'])
        server.trace_flush.assert_called_once_with()
        assert server._get_state() == (Target.State.HALTED, None)
        assert server._active_run_client is None

    def test_non_stop_step_sends_stop_notification_until_vstopped(self):
        """Verify that non-stop step keeps ownership until vStopped acknowledges its stop."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._step_target = Mock(return_value=Target.State.HALTED)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False
        payload = b'Stop:T05thread:1;'

        response = server.v_cont(client, b'Cont;s')

        assert response is None
        assert client.send.call_count == 2
        assert client.send.call_args_list[0].args == (b'OK',)
        assert client.send.call_args_list[1].args == (b'%' + payload + b'#' + checksum(payload),)
        assert client._stop_notification_pending
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == b'OK'
        assert not client._stop_notification_pending
        assert server._active_run_client is None

    def test_non_stop_range_step_forwards_bounds(self):
        """Verify that non-stop range-step forwards its start and end addresses."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._step_target = Mock(return_value=Target.State.HALTED)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False

        assert server.v_cont(client, b'Cont;r1000,1010') is None

        assert server._step_target.call_args.args[:2] == (0x1000, 0x1010)
        assert server._step_target.call_args.kwargs['hook_cb'] is client.is_interrupted
        assert client._stop_notification_pending

    def test_ctrl_c_during_step_forces_sigint_in_both_modes(self):
        """Verify that Ctrl-C during step reports SIGINT in all-stop and non-stop modes."""
        all_stop_server = _make_state_server(Target.State.HALTED)
        all_stop_server.create_rsp_packet = Mock(side_effect=lambda value: value)
        all_stop_server._step_target = Mock(return_value=Target.State.HALTED)
        all_stop_server.get_t_response = Mock(return_value=b'T02thread:1;')
        all_stop_client = _make_client(1)
        all_stop_client.is_interrupted.return_value = True

        assert all_stop_server.step(all_stop_client, None) == b'T02thread:1;'
        all_stop_client.interrupt_clear.assert_called_once_with()
        all_stop_server.get_t_response.assert_called_once_with(
                all_stop_client, forceSignal=signals.SIGINT)
        assert all_stop_server._active_run_client is None

        non_stop_server = _make_state_server(Target.State.HALTED)
        non_stop_server.is_threading_enabled = Mock(return_value=False)
        non_stop_server.create_rsp_packet = Mock(side_effect=lambda value: value)
        non_stop_server._step_target = Mock(return_value=Target.State.HALTED)
        non_stop_server.get_t_response = Mock(return_value=b'T02thread:1;')
        non_stop_client = _make_client(1)
        non_stop_client.non_stop = True
        non_stop_client.is_interrupted.return_value = True
        payload = b'Stop:T02thread:1;'

        assert non_stop_server.v_cont(non_stop_client, b'Cont;s') is None
        non_stop_client.interrupt_clear.assert_called_once_with()
        non_stop_server.get_t_response.assert_called_once_with(
                non_stop_client, forceSignal=signals.SIGINT)
        assert non_stop_client.send.call_args_list[1].args == (
                b'%' + payload + b'#' + checksum(payload),)
        assert non_stop_client._stop_notification_pending
        assert non_stop_server._active_run_client is non_stop_client

    def test_non_stop_continue_notifies_after_service_halt(self):
        """Verify the complete non-stop continue and stop-notification flow.
        The service detects the halt, sends %Stop, and vStopped releases ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.COMMANDS = {b'v': (server.v_command, 2)}
        server.target_context = Mock()
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server.create_rsp_packet = Mock(side_effect=lambda value:
                b'$' + value + b'#' + checksum(value))
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server.notify_client_detached = Mock()
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.is_connection_closed = False
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
                    server._service_state()

        packet_io.send.side_effect = _send
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.non_stop = True
        payload = b'Stop:T05thread:1;'

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
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
        assert not client._stop_notification_pending
        assert server._active_run_client is None

    def test_non_stop_continue_adopts_sleeping_and_reset(self):
        """Verify that non-stop continue adopts targets already sleeping or resetting."""
        for state in (Target.State.SLEEPING, Target.State.RESET):
            server = _make_state_server(state)
            server.is_threading_enabled = Mock(return_value=False)
            server.trace_capture = Mock()
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            client = _make_client(1)
            client.non_stop = True

            assert server.v_cont(client, b'Cont;c') == b'OK'
            assert server._active_run_client is client
            server.trace_capture.assert_not_called()
            server.target.resume.assert_not_called()
            assert server._get_state() == (state, None)

    def test_all_stop_continue_adopts_sleeping_and_reset(self):
        """Verify that all-stop continue adopts targets already sleeping or resetting."""
        for state in (Target.State.SLEEPING, Target.State.RESET):
            server = _make_state_server(state)
            server.trace_capture = Mock()
            server.first_run_after_reset_or_flash = False
            server.rtt_server = None
            server.enable_semihosting = False
            server.session.options.get.return_value = 0.1
            client = _make_client(1)
            client.is_interrupted.return_value = False

            def _close_connection(_timeout):
                client.is_connection_closed = True
                return False

            server._wait_while_running = Mock(side_effect=_close_connection)

            with server.lock:
                assert server.resume(client, None) is None

            server.trace_capture.assert_not_called()
            server.target.resume.assert_not_called()
            assert server._get_state() == (state, None)
            assert server._active_run_client is None

    def test_step_rejects_sleeping_and_reset_in_both_modes(self):
        """Verify that both modes reject step while the target sleeps or resets."""
        for state in (Target.State.SLEEPING, Target.State.RESET):
            all_stop_server = _make_state_server(state)
            all_stop_server.create_rsp_packet = Mock(side_effect=lambda value: value)
            all_stop_server._step = Mock()
            all_stop_client = _make_client(1)

            assert all_stop_server.step(all_stop_client, None) == b'E01'
            all_stop_server._step.assert_not_called()
            assert all_stop_server._active_run_client is None

            non_stop_server = _make_state_server(state)
            non_stop_server.is_threading_enabled = Mock(return_value=False)
            non_stop_server.create_rsp_packet = Mock(side_effect=lambda value: value)
            non_stop_server._step_target = Mock()
            non_stop_client = _make_client(1)
            non_stop_client.non_stop = True

            assert non_stop_server.v_cont(non_stop_client, b'Cont;s') == b'E01'
            non_stop_server._step_target.assert_not_called()
            assert non_stop_server._active_run_client is None

    def test_failed_non_stop_continue_clears_active_client(self):
        """Verify that a failed non-stop resume releases its run ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.trace_capture = Mock()
        server._mark_running = Mock()
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
        server._step_target = Mock(return_value=Target.State.HALTED)
        server.get_t_response = Mock(side_effect=exceptions.TargetError("test stop response failure"))
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False

        response = server.handle_message(client, b'$vCont;s#00')

        assert response is None
        client.send.assert_called_once_with(b'OK')
        assert server._active_run_client is client
        assert not client._stop_notification_pending

        server.get_t_response = Mock(return_value=b'T05thread:1;')
        assert server._try_send_stop_notification(client)
        assert client._stop_notification_pending

    def test_non_stop_step_notification_send_failure_does_not_send_error_response(self):
        """Verify handling when sending a step stop notification fails.
        Since OK was already sent, no E01 reply is allowed and ownership is cleared."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.COMMANDS = {b'v': (server.v_command, 2)}
        server._step_target = Mock(return_value=Target.State.HALTED)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        client = _make_client(1)
        client.non_stop = True
        client.is_interrupted.return_value = False
        client.send.side_effect = [None, RuntimeError("test send failure")]

        response = server.handle_message(client, b'$vCont;s#00')

        assert response is None
        assert client.send.call_count == 2
        assert client.send.call_args_list[0].args == (b'OK',)
        assert server._active_run_client is None
        assert not client._stop_notification_pending

    def test_non_stop_stop_claims_unowned_execution_before_halting(self):
        """Verify that vCont;t claims unowned execution before halting the target."""
        server = _make_state_server()
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        client = _make_client(1)
        client.non_stop = True
        events = []
        server._halt_target = Mock(side_effect=lambda: events.append('halt') or Target.State.HALTED)
        server.trace_flush = Mock(side_effect=lambda: events.append('flush'))
        client.send = Mock(side_effect=lambda packet: events.append(('send', packet)))
        server._try_send_stop_notification = Mock(side_effect=lambda *args, **kwargs:
                events.append('notify') or True)

        response = server.v_cont(client, b'Cont;t')

        assert response is None
        assert events == ['halt', 'flush', ('send', b'OK'), 'notify']
        assert server._active_run_client is client
        server._try_send_stop_notification.assert_called_once_with(client, forceSignal=0)

    def test_non_stop_stop_claims_sleeping_and_reset(self):
        """Verify that vCont;t adopts and halts sleeping and resetting targets."""
        for state in (Target.State.SLEEPING, Target.State.RESET):
            server = _make_state_server(state)
            server.is_threading_enabled = Mock(return_value=False)
            server.create_rsp_packet = Mock(side_effect=lambda value: value)
            server.get_t_response = Mock(return_value=b'T00thread:1;')
            client = _make_client(1)
            client.non_stop = True

            def _halt_target():
                assert server._active_run_client is client
                server._set_state(Target.State.HALTED)
                return Target.State.HALTED

            server._halt_target = Mock(side_effect=_halt_target)

            assert server.v_cont(client, b'Cont;t') is None
            server._halt_target.assert_called_once_with()
            server.trace_flush.assert_called_once_with()
            assert client._stop_notification_pending
            assert server._active_run_client is client
            assert server._get_state() == (Target.State.HALTED, None)

    def test_non_stop_stop_ignores_already_halted_target(self):
        """Verify that vCont;t does nothing when the target is already halted."""
        server = _make_state_server(Target.State.HALTED)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._halt_target = Mock()
        server._try_send_stop_notification = Mock()
        client = _make_client(1)
        client.non_stop = True

        response = server.v_cont(client, b'Cont;t')

        assert response == b'OK'
        server._halt_target.assert_not_called()
        server.trace_flush.assert_not_called()
        server._try_send_stop_notification.assert_not_called()
        client.send.assert_not_called()

    def test_failed_non_stop_stop_sends_only_error_response(self):
        """Verify handling when vCont;t cannot halt the target.
        It returns only E01 and preserves ownership so a later real halt can be reported."""
        server = _make_state_server()
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._halt_target = Mock(side_effect=exceptions.TargetError("test halt failure"))
        client = _make_client(1)
        client.non_stop = True

        response = server.v_cont(client, b'Cont;t')

        assert response == b'E01'
        client.send.assert_not_called()
        assert server._active_run_client is client

    def test_non_stop_stop_notification_failure_does_not_send_error_response(self):
        """Verify that a failed vCont;t notification does not send E01 after OK."""
        server = _make_state_server()
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05thread:1;')
        server._halt_target = Mock(return_value=Target.State.HALTED)
        client = _make_client(1)
        client.non_stop = True
        client.send.side_effect = [None, RuntimeError("test send failure")]
        server._active_run_client = client

        response = server.v_cont(client, b'Cont;t')

        assert response is None
        assert client.send.call_count == 2
        assert client.send.call_args_list[0].args == (b'OK',)
        assert not client._stop_notification_pending
        assert server._active_run_client is None

    def test_non_stop_ctrl_c_claims_unowned_execution(self):
        """Verify that non-stop Ctrl-C claims unowned execution before halting it."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.get_t_response = Mock(return_value=b'T02thread:1;')
        server.notify_client_detached = Mock()
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.interrupt_event.set()
        packet_io.is_connection_closed = False
        packet_io.receive.side_effect = ConnectionClosedException()
        server.target_context = Mock()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.non_stop = True

        def _halt_target():
            assert server._active_run_client is client
            server._set_state(Target.State.HALTED)
            return Target.State.HALTED

        server._halt_target = Mock(side_effect=_halt_target)

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            client.run()

        server._halt_target.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)
        payload = b'Stop:T02thread:1;'
        packet_io.send.assert_called_once_with(b'%' + payload + b'#' + checksum(payload))
        assert server._active_run_client is client
        assert client._stop_notification_pending
        assert not packet_io.interrupt_event.is_set()

    def test_non_stop_ctrl_c_failure_clears_interrupt(self):
        """Verify handling when a non-stop Ctrl-C cannot halt the target.
        The interrupt is consumed after one attempt so the client loop does not spin."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.notify_client_detached = Mock()
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.interrupt_event.set()
        packet_io.is_connection_closed = False
        packet_io.receive.side_effect = ConnectionClosedException()
        server.target_context = Mock()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.non_stop = True

        def _fail_halt():
            assert server._active_run_client is client
            if server._halt_target.call_count > 1:
                server.shutdown_event.set()
            raise exceptions.TargetError("test halt failure")

        server._halt_target = Mock(side_effect=_fail_halt)

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            client.run()

        server._halt_target.assert_called_once_with()
        assert not packet_io.interrupt_event.is_set()
        assert server._active_run_client is client

    def test_active_non_stop_ctrl_c_halts_current_run(self):
        """Verify that Ctrl-C from the active non-stop client halts its current run."""
        server = _make_state_server(Target.State.RUNNING)
        server.port = 3333
        server.get_t_response = Mock(return_value=b'T02thread:1;')
        server.notify_client_detached = Mock()
        server.target_context = Mock()
        server._begin_run = Mock()
        connected_socket = Mock()
        packet_io = Mock()
        packet_io.interrupt_event = threading.Event()
        packet_io.interrupt_event.set()
        packet_io.is_connection_closed = False
        packet_io.receive.side_effect = ConnectionClosedException()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            client = GDBClientSession(server, connected_socket, 1)
        client.non_stop = True
        server._active_run_client = client

        def _halt_target():
            server._set_state(Target.State.HALTED)
            return Target.State.HALTED

        server._halt_target = Mock(side_effect=_halt_target)

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
            client.run()

        server._begin_run.assert_not_called()
        server._halt_target.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)
        assert client._stop_notification_pending
        assert server._active_run_client is client

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
        server._wait_while_running = Mock(return_value=False)

        def _halt_target():
            server._set_state(Target.State.HALTED)
            return Target.State.HALTED

        server._halt_target = Mock(side_effect=_halt_target)

        with server.lock:
            response = server.resume(client, None)

        assert response == b'T02thread:1;'
        server.target.resume.assert_called_once_with()
        server._halt_target.assert_called_once_with()
        server.trace_flush.assert_called_once_with()
        client.interrupt_clear.assert_called_once_with()
        server.get_t_response.assert_called_once_with(client, forceSignal=signals.SIGINT)
        assert server._active_run_client is None

    def test_passive_client_cannot_control_active_run(self):
        """Verify that a passive client cannot control another client's active run."""
        server = _make_state_server(Target.State.RUNNING)
        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server._resume = Mock()
        server._step = Mock()
        server._step_target = Mock()
        server._halt_target = Mock()
        active_client = _make_client(1)
        passive_client = _make_client(2)
        server._active_run_client = active_client

        assert server.resume(passive_client, None) == b'E01'
        assert server.step(passive_client, None) == b'E01'

        passive_client.non_stop = True
        assert server.v_cont(passive_client, b'Cont;c') == b'E01'
        assert server.v_cont(passive_client, b'Cont;s') == b'E01'
        assert server.v_cont(passive_client, b'Cont;t') == b'E01'

        assert server._active_run_client is active_client
        server._resume.assert_not_called()
        server._step.assert_not_called()
        server._step_target.assert_not_called()
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
        packet_io.is_connection_closed = False
        packet_io.receive.side_effect = ConnectionClosedException()
        with patch('pyocd.gdbserver.gdbserver.GDBDebugContextFacade', return_value=Mock()):
            passive_client = GDBClientSession(server, connected_socket, 2)
        passive_client.non_stop = True

        with patch('pyocd.gdbserver.gdbserver.GDBServerPacketIOThread', return_value=packet_io):
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

    def test_active_disconnect_leaves_running_target_for_passive_client_to_adopt(self):
        """Verify that disconnecting the active client leaves execution unowned.
        A remaining client can adopt it without physically resuming the target again."""
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

        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        assert server.v_cont(passive_client, b'Cont;c') == b'OK'
        assert server._active_run_client is passive_client
        server.target.resume.assert_not_called()
        server.trace_capture.assert_not_called()

    def test_passive_disconnect_preserves_active_run_and_pending_stop(self):
        """Verify that disconnecting a passive client does not affect the active one.
        Existing run ownership and any pending stop notification must remain unchanged."""
        for state, pending in ((Target.State.RUNNING, False), (Target.State.HALTED, True)):
            server = _make_state_server(state)
            active_client = _make_client(1)
            passive_client = _make_client(2)
            active_client._stop_notification_pending = pending
            passive_client.is_socket_connected = False
            server._active_run_client = active_client
            _configure_client_lifecycle(server, [active_client, passive_client], persist=True)

            server.notify_client_detached(passive_client)

            assert passive_client not in server.client_sessions
            assert server._active_run_client is active_client
            assert active_client._stop_notification_pending is pending
            server.target.get_state.assert_not_called()
            server.target.resume.assert_not_called()

    def test_active_pending_disconnect_allows_passive_client_to_continue(self):
        """Verify disconnect cleanup while the active client has a pending stop.
        Its ownership is cleared so a remaining client can start a new run."""
        server = _make_state_server(Target.State.HALTED)
        active_client = _make_client(1)
        passive_client = _make_client(2)
        active_client.is_socket_connected = False
        active_client._stop_notification_pending = True
        passive_client.non_stop = True
        server._active_run_client = active_client
        _configure_client_lifecycle(server, [active_client, passive_client], persist=True)

        server.notify_client_detached(active_client)

        assert active_client not in server.client_sessions
        assert not active_client._stop_notification_pending
        assert server._active_run_client is None
        server.target.resume.assert_not_called()

        server.is_threading_enabled = Mock(return_value=False)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        assert server.v_cont(passive_client, b'Cont;c') == b'OK'
        assert server._active_run_client is passive_client
        server.trace_capture.assert_called_once_with()
        server.target.resume.assert_called_once_with()
        assert server._get_state() == (Target.State.RUNNING, None)

    def test_last_client_disconnect_resumes_target_and_honours_persist(self):
        """Verify cleanup after the final client disconnects.
        The target resumes, while only a non-persistent server requests shutdown."""
        for persist in (False, True):
            server = _make_state_server(Target.State.HALTED)
            client = _make_client(1)
            client.is_socket_connected = False
            client._stop_notification_pending = True
            server._active_run_client = client
            _configure_client_lifecycle(server, [client], persist=persist)
            server.target.get_state.side_effect = [Target.State.HALTED, Target.State.RUNNING]

            server.notify_client_detached(client)

            assert client not in server.client_sessions
            assert not client.is_attached_to_target
            assert not client._stop_notification_pending
            assert server._active_run_client is None
            server.trace_capture.assert_called_once_with()
            server.target.resume.assert_called_once_with()
            assert server._get_state() == (Target.State.RUNNING, None)
            assert server.shutdown_event.is_set() is (not persist)

    def test_non_stop_stop_query_while_running_returns_ok(self):
        """Verify that a non-stop stop query while running returns OK without side effects."""
        server = _make_state_server(Target.State.RUNNING)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock()
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client

        assert server.stop_reason_query(client) == b'OK'
        server.get_t_response.assert_not_called()
        assert not client._stop_notification_pending
        assert server._active_run_client is client

    def test_passive_stop_query_does_not_take_stop_ownership(self):
        """Verify that a passive stop query reports the halt without taking ownership."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        server.get_t_response = Mock(return_value=b'T05')
        active_client = _make_client(1)
        passive_client = _make_client(2)
        passive_client.non_stop = True
        server._active_run_client = active_client

        assert server.stop_reason_query(passive_client) == b'T05'
        assert not passive_client._stop_notification_pending
        assert server._active_run_client is active_client

    def test_vstopped_from_passive_client_does_not_complete_active_stop(self):
        """Verify that passive vStopped cannot acknowledge another client's stop."""
        server = _make_state_server(Target.State.HALTED)
        server.create_rsp_packet = Mock(side_effect=lambda value: value)
        active_client = _make_client(1)
        passive_client = _make_client(2)
        active_client._stop_notification_pending = True
        server._active_run_client = active_client

        assert server.v_command(passive_client, b'Stopped') == b'OK'
        assert active_client._stop_notification_pending
        assert server._active_run_client is active_client

        assert server.v_command(active_client, b'Stopped') == b'OK'
        assert not active_client._stop_notification_pending
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

        def _halt_target():
            server._set_state(Target.State.HALTED)
            return Target.State.HALTED

        server._halt_target = Mock(side_effect=_halt_target)
        client = _make_client(1)
        client.non_stop = True
        server._active_run_client = client
        payload = b'Stop:T00thread:1;'

        assert server.v_cont(client, b'Cont;t') is None
        assert client.send.call_args_list[0].args == (b'OK',)
        assert client.send.call_args_list[1].args == (b'%' + payload + b'#' + checksum(payload),)
        assert client._stop_notification_pending
        assert server._active_run_client is client

        assert server.v_command(client, b'Stopped') == b'OK'
        assert server._active_run_client is None
        assert server._get_state() == (Target.State.HALTED, None)
        server.trace_flush.assert_called_once_with()

    def test_service_loop_tracks_reset_running_and_halted(self):
        """Verify that service polling continues through RESET and RUNNING states.
        It must eventually publish HALTED and flush trace exactly once."""
        server = _make_state_server(Target.State.RUNNING)
        server._STATE_INTERVAL = 0
        states = iter((Target.State.RESET, Target.State.RUNNING, Target.State.HALTED))

        def _get_state():
            state = next(states)
            if state == Target.State.HALTED:
                server.shutdown_event.set()
            return state

        server.target.get_state.side_effect = _get_state

        service_thread = threading.Thread(target=server._run_service_loop)
        service_thread.start()
        service_thread.join(1.0)
        if service_thread.is_alive():
            server.shutdown_event.set()
            service_thread.join(1.0)

        assert not service_thread.is_alive()
        assert server.target.get_state.call_count == 3
        assert server._get_state() == (Target.State.HALTED, None)
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

        def _resume_target():
            assert server._active_run_client is client
            run_started.set()

        server.target.resume.side_effect = _resume_target

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

    def test_server_accepts_multiple_clients_before_first_run(self):
        """Verify that the server accepts and starts multiple clients before execution.
        Each client receives a unique index and the target is checked as halted."""
        server = _make_state_server(Target.State.HALTED)
        server.port = 3333
        server.listen_socket = Mock()
        server.client_sessions = []
        server.client_sessions_lock = threading.Lock()
        server.client_last_index = 0
        server._halt_target = Mock(return_value=Target.State.HALTED)
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
        second_client = Mock()
        second_client.start.side_effect = server.shutdown_event.set

        with patch('pyocd.gdbserver.gdbserver.threading.Timer') as timer_class, \
                patch('pyocd.gdbserver.gdbserver.GDBClientSession',
                    side_effect=(first_client, second_client)) as client_class:
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


class TestGdbServerSyscalls:
    def test_syscall_without_client_returns_not_connected(self):
        """Verify that a GDB syscall is skipped when no client can service it.
        The target receives a normal failure result instead of raising an exception."""
        server = _make_state_server(Target.State.HALTED)

        result = server.syscall('open,1000/4,0,1ff')

        assert result == (-1, errno.ENOTCONN)

    def test_service_resumes_after_skipped_syscall(self):
        """Verify that client-independent semihosting continues after a skipped syscall.
        The service thread reports failure to the target and resumes its execution."""
        server = _make_state_server(Target.State.RUNNING)
        server.enable_semihosting = True
        server.semihost_use_syscalls = True
        server.target.get_state.return_value = Target.State.HALTED

        def _handle_request():
            assert server.syscall('open,1000/4,0,1ff') == (-1, errno.ENOTCONN)
            return True

        server.semihost.check_and_handle_semihost_request.side_effect = _handle_request

        with server.lock:
            server._service_state()

        server.target.resume.assert_called_once_with()
        assert server._get_state() == (Target.State.RUNNING, None)

    def test_failed_syscall_read_and_write_report_all_bytes_unprocessed(self):
        """Verify conversion of failed GDB read and write results to semihost results.
        A failed operation reports that the complete buffer remains unprocessed."""
        server = Mock()
        server.syscall.return_value = (-1, errno.ENOTCONN)
        handler = GDBSyscallIOHandler(server)

        assert handler.write(4, 0x1000, 16) == 16
        assert handler.read(4, 0x1000, 16) == 16
        assert handler.errno == errno.ENOTCONN


class TestGdbServerPacketIO:
    def test_remote_close_sets_connection_closed(self):
        """Verify that remote EOF closes the connection and wakes receivers."""
        connected_socket = Mock()
        connected_socket.read.return_value = b''

        packet_io = GDBServerPacketIOThread(connected_socket, 1)
        packet_io.join(1.0)

        assert not packet_io.is_alive()
        assert packet_io.is_connection_closed
        try:
            packet_io.receive(block=False)
        except ConnectionClosedException:
            pass
        else:
            assert False, "expected receive to report a closed connection"

    def test_zero_byte_ack_write_sets_connection_closed(self):
        """Verify that a zero-byte ACK write closes without queuing the packet."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._socket = Mock()
        packet_io._socket.write.return_value = 0
        packet_io._connection_closed_event = threading.Event()
        packet_io._shutdown_event = threading.Event()
        packet_io._receive_queue = Mock()
        packet_io.send_acks = True

        packet_io._handling_incoming_packet(b'$?#3f')

        assert packet_io.is_connection_closed
        packet_io._receive_queue.put.assert_not_called()

    def test_write_data_completes_partial_socket_writes(self):
        """Verify that partial socket writes are retried until all data is sent."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._connection_closed_event = threading.Event()
        packet_io._shutdown_event = threading.Event()
        packet_io._socket = Mock()
        written = bytearray()
        sizes = iter((2, 1, 100))

        def _partial_write(data):
            count = min(next(sizes), len(data))
            written.extend(data[:count])
            return count

        packet_io._socket.write.side_effect = _partial_write

        assert packet_io._write_data(b'abcdef')
        assert written == b'abcdef'
        assert packet_io._socket.write.call_args_list[0].args == (b'abcdef',)
        assert packet_io._socket.write.call_args_list[1].args == (b'cdef',)
        assert packet_io._socket.write.call_args_list[2].args == (b'def',)
        assert not packet_io.is_connection_closed

    def test_packet_send_error_marks_connection_closed(self):
        """Verify that a socket send error marks the connection closed."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._connection_closed_event = threading.Event()
        packet_io._shutdown_event = threading.Event()
        packet_io._socket = Mock()
        packet_io._socket.write.side_effect = BrokenPipeError("test broken pipe")
        packet_io.drop_reply = False
        packet_io._last_packet = b''
        packet_io.send_acks = True
        packet_io._expecting_ack = False

        packet_io.send(b'$OK#9a')

        assert packet_io.is_connection_closed
        assert packet_io._shutdown_event.is_set()
        assert packet_io._last_packet == b'$OK#9a'
        assert not packet_io._expecting_ack

    def test_packet_receive_errors_mark_connection_closed(self):
        """Verify that socket receive errors mark the connection closed."""
        for error in (ConnectionResetError("test reset"), OSError("test receive failure")):
            connected_socket = Mock()
            connected_socket.read.side_effect = error

            packet_io = GDBServerPacketIOThread(connected_socket, 1)
            try:
                packet_io.join(1.0)

                assert not packet_io.is_alive()
                assert packet_io.is_connection_closed
                try:
                    packet_io.receive(block=False)
                except ConnectionClosedException:
                    pass
                else:
                    assert False, "expected receive to report a closed connection"
            finally:
                packet_io.stop()

    def test_receive_timeout_is_retryable(self):
        """Verify that a receive timeout is retried without closing immediately."""
        connected_socket = Mock()
        connected_socket.read.side_effect = [socket.timeout(), b'']

        packet_io = GDBServerPacketIOThread(connected_socket, 1)
        try:
            packet_io.join(1.0)

            assert connected_socket.read.call_count == 2
            assert not packet_io.is_alive()
            assert packet_io.is_connection_closed
        finally:
            packet_io.stop()

    def test_send_timeout_marks_connection_closed(self):
        """Verify that a send timeout marks the connection closed."""
        packet_io = object.__new__(GDBServerPacketIOThread)
        packet_io._connection_closed_event = threading.Event()
        packet_io._shutdown_event = threading.Event()
        packet_io._socket = Mock()
        packet_io._socket.write.side_effect = socket.timeout("test send timeout")

        assert not packet_io._write_data(b'$OK#9a')
        assert packet_io.is_connection_closed
        assert packet_io._shutdown_event.is_set()
