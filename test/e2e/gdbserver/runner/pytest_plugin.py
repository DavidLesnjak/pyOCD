# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Pytest fixtures and command-line options for gdbserver hardware scenarios."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import threading
import time
from typing import Any, Iterator, Sequence

import pytest

from artifacts import RunArtifacts
from mailbox import FixtureMailboxClient, resolve_elf_symbol
from pyocd_server import GDBServerConfiguration, PyOCDGDBServer
from scenario_docs import validate_scenario_docstring
from rsp import RSPClient


_SCENARIO_CONFIGURATION_KEYS = frozenset({
    "enable_semihosting",
    "enable_swv",
    "extra_arguments",
    "persist",
    "reset_run",
    "rtt_mode",
    "semihost_use_syscalls",
    "swv_clock",
    "swv_system_clock",
    "vector_catch",
})


class ExternalGDBError(RuntimeError):
    """Raised when an explicitly selected external GDB process cannot run."""


class ExternalGDBSession:
    """One interactive external GDB process with a separately captured transcript."""

    def __init__(self, process: subprocess.Popen[bytes], output_path: Path) -> None:
        self._process = process
        self._output_path = output_path
        self._output = bytearray()
        self._output_lock = threading.Lock()
        self._output_event = threading.Event()
        self._closed = False
        self._marker_index = 0
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reader.start()

    def __enter__(self) -> "ExternalGDBSession":
        return self

    def __exit__(self, exc_type: object, exc_value: object,
                 traceback: object) -> None:
        self.close()

    @property
    def output(self) -> str:
        """Return all text captured from this GDB process so far."""
        with self._output_lock:
            return self._output.decode("utf-8", errors="replace")

    def execute(self, command: str, timeout: float = 10.0) -> str:
        """Execute one stopped-target GDB command and return its transcript fragment."""
        if not command:
            raise ValueError("external GDB command must not be empty")
        marker = self._next_marker()
        before = self._output_length()
        self._send((command + "\n").encode("utf-8"))
        self._send(("echo " + marker + "\\n\n").encode("utf-8"))
        self._wait_for(marker, timeout)
        return self._output_since(before)

    def continue_execution(self) -> None:
        """Resume the target without waiting for GDB to return to a prompt."""
        self._send(b"continue\n")

    def interrupt(self, timeout: float = 10.0) -> str:
        """Interrupt an outstanding continue and return the resulting transcript fragment."""
        before = self._output_length()
        self._send(b"\x03")
        marker = self._next_marker()
        self._send(("echo " + marker + "\\n\n").encode("utf-8"))
        self._wait_for(marker, timeout)
        return self._output_since(before)

    def detach(self, timeout: float = 10.0) -> str:
        """Detach the GDB client while retaining the server's persistent session."""
        return self.execute("detach", timeout)

    def terminate(self, timeout: float = 10.0) -> None:
        """Abruptly terminate GDB to exercise TCP-disconnect recovery."""
        if self._closed:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=timeout)
        self._closed = True
        self._reader.join(timeout=1.0)

    def close(self) -> None:
        """Gracefully end GDB unless it has already been detached or terminated."""
        if self._closed:
            return
        try:
            self._send(b"quit\n")
            self._process.wait(timeout=5.0)
        except (BrokenPipeError, subprocess.TimeoutExpired):
            self._process.kill()
            self._process.wait(timeout=5.0)
        finally:
            self._closed = True
            self._reader.join(timeout=1.0)

    def _next_marker(self) -> str:
        self._marker_index += 1
        return "GDB-E2E-COMMAND-%d" % self._marker_index

    def _send(self, data: bytes) -> None:
        if self._closed or self._process.stdin is None:
            raise ExternalGDBError("external GDB session is not writable")
        try:
            self._process.stdin.write(data)
            self._process.stdin.flush()
        except BrokenPipeError as error:
            raise ExternalGDBError(
                "external GDB closed unexpectedly; see %s" % self._output_path) from error

    def _read_output(self) -> None:
        assert self._process.stdout is not None
        with self._output_path.open("ab") as output:
            while True:
                data = self._process.stdout.read(1)
                if not data:
                    return
                output.write(data)
                output.flush()
                with self._output_lock:
                    self._output.extend(data)
                self._output_event.set()

    def _wait_for(self, marker: str, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            if marker in self.output:
                return
            if self._process.poll() is not None:
                raise ExternalGDBError(
                    "external GDB exited with code %d; see %s" %
                    (self._process.returncode, self._output_path))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ExternalGDBError(
                    "external GDB did not complete %r; see %s" %
                    (marker, self._output_path))
            self._output_event.wait(min(remaining, 0.100))
            self._output_event.clear()

    def _output_length(self) -> int:
        with self._output_lock:
            return len(self._output)

    def _output_since(self, offset: int) -> str:
        with self._output_lock:
            return self._output[offset:].decode("utf-8", errors="replace")


class ExternalGDBMISession:
    """One asynchronous GDB/MI process with a separately captured transcript."""

    def __init__(self, process: subprocess.Popen[bytes], output_path: Path) -> None:
        self._process = process
        self._output_path = output_path
        self._output = bytearray()
        self._output_lock = threading.Lock()
        self._output_event = threading.Event()
        self._closed = False
        self._token = 0
        self._last_resume_offset = 0
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reader.start()

    def __enter__(self) -> "ExternalGDBMISession":
        return self

    def __exit__(self, exc_type: object, exc_value: object,
                 traceback: object) -> None:
        self.close()

    def command(self, command: str, timeout: float = 10.0,
                expected_result: str = "done") -> str:
        """Run one MI command and return its transcript fragment."""
        if not command:
            raise ValueError("external GDB/MI command must not be empty")
        token = self._next_token()
        before = self._output_length()
        self._send(("%d%s\n" % (token, command)).encode("utf-8"))
        output = self._wait_for_result(token, expected_result, timeout)
        return output[before:]

    def console(self, command: str, timeout: float = 10.0) -> str:
        """Run one ordinary GDB command through the MI console interpreter."""
        return self.command(
            "-interpreter-exec console %s" % _mi_quote(command), timeout)

    def evaluate_unsigned(self, expression: str, timeout: float = 10.0) -> int:
        """Evaluate an unsigned C or GDB convenience-variable expression."""
        output = self.command(
            "-data-evaluate-expression %s" % _mi_quote(expression), timeout)
        value = re.search(r'\^done,value="([0-9]+)"', output)
        if value is None:
            raise ExternalGDBError(
                "external GDB/MI did not return an unsigned value for %r; see %s" %
                (expression, self._output_path))
        return int(value.group(1))

    def continue_execution(self, timeout: float = 10.0) -> None:
        """Resume the target asynchronously through GDB/MI."""
        self._last_resume_offset = self._output_length()
        self.command("-exec-continue", timeout, expected_result="running")

    def interrupt(self, timeout: float = 10.0) -> str:
        """Interrupt a running target through GDB/MI and wait for its stop record."""
        before = self._output_length()
        self.command("-exec-interrupt", timeout)
        return self._wait_for_stop(before, timeout)

    def wait_for_stop(self, timeout: float = 10.0) -> str:
        """Wait for the stop record caused by the most recent resume request."""
        return self._wait_for_stop(self._last_resume_offset, timeout)

    def detach(self, timeout: float = 10.0) -> str:
        """Detach the GDB/MI client while retaining a persistent server session."""
        return self.console("detach", timeout)

    def terminate(self, timeout: float = 10.0) -> None:
        """Abruptly terminate GDB/MI to exercise TCP-disconnect recovery."""
        if self._closed:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=timeout)
        self._closed = True
        self._reader.join(timeout=1.0)

    def close(self) -> None:
        """Gracefully end GDB/MI unless it has already exited."""
        if self._closed:
            return
        try:
            self.command("-gdb-exit", timeout=5.0, expected_result="exit")
            self._process.wait(timeout=5.0)
        except (BrokenPipeError, ExternalGDBError, subprocess.TimeoutExpired):
            if self._process.poll() is None:
                self._process.kill()
                self._process.wait(timeout=5.0)
        finally:
            self._closed = True
            self._reader.join(timeout=1.0)

    def _next_token(self) -> int:
        self._token += 1
        return self._token

    def _send(self, data: bytes) -> None:
        if self._closed or self._process.stdin is None:
            raise ExternalGDBError("external GDB/MI session is not writable")
        try:
            self._process.stdin.write(data)
            self._process.stdin.flush()
        except BrokenPipeError as error:
            raise ExternalGDBError(
                "external GDB/MI closed unexpectedly; see %s" % self._output_path) from error

    def _read_output(self) -> None:
        assert self._process.stdout is not None
        with self._output_path.open("ab") as output:
            while True:
                data = self._process.stdout.read(1)
                if not data:
                    return
                output.write(data)
                output.flush()
                with self._output_lock:
                    self._output.extend(data)
                self._output_event.set()

    def _wait_for_result(self, token: int, expected_result: str,
                         timeout: float) -> str:
        result_pattern = re.compile(r"(?m)^%d\^([a-z]+)(?:,.*)?\r?\n" % token)
        deadline = time.monotonic() + timeout
        while True:
            output = self._output_text()
            result = result_pattern.search(output)
            if result is not None:
                if result.group(1) != expected_result:
                    raise ExternalGDBError(
                        "external GDB/MI command returned %s instead of %s; see %s" %
                        (result.group(1), expected_result, self._output_path))
                return output
            self._wait_for_output(deadline, "MI command %d" % token)

    def _wait_for_stop(self, offset: int, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        while True:
            output = self._output_since(offset)
            if re.search(r"(?m)^\*stopped(?:,.*)?\r?\n", output):
                return output
            self._wait_for_output(deadline, "MI target stop")

    def _wait_for_output(self, deadline: float, description: str) -> None:
        if self._process.poll() is not None:
            raise ExternalGDBError(
                "external GDB/MI exited with code %d; see %s" %
                (self._process.returncode, self._output_path))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ExternalGDBError(
                "external GDB/MI did not complete %s; see %s" %
                (description, self._output_path))
        self._output_event.wait(min(remaining, 0.100))
        self._output_event.clear()

    def _output_length(self) -> int:
        with self._output_lock:
            return len(self._output)

    def _output_text(self) -> str:
        with self._output_lock:
            return self._output.decode("utf-8", errors="replace")

    def _output_since(self, offset: int) -> str:
        with self._output_lock:
            return self._output[offset:].decode("utf-8", errors="replace")


def _mi_quote(value: str) -> str:
    """Encode one MI command argument as a C-style quoted string."""
    return '"%s"' % value.replace("\\", "\\\\").replace('"', '\\"')


def _safe_artifact_name(value: str) -> str:
    """Return a non-empty filename-safe component for an external-GDB artifact."""
    sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
    if not sanitized:
        raise ValueError("external GDB artifact name must contain a filename-safe character")
    return sanitized


class ExternalGDB:
    """Run one explicitly selected GDB executable against a managed server."""

    def __init__(self, executable: str) -> None:
        self._executable = executable

    def run(self, server: PyOCDGDBServer, commands: Sequence[str],
            timeout: float = 30.0, artifact_name: str | None = None) -> str:
        """Load the fixture AXF, connect, run commands, and return GDB output."""
        if timeout <= 0:
            raise ValueError("external GDB timeout must be positive")
        if not all(isinstance(command, str) for command in commands):
            raise TypeError("external GDB commands must be strings")

        version = self._get_version(server.configuration.repository_root, timeout)
        command = [
            self._executable,
            "--nx",
            "--nh",
            "--batch",
            "--quiet",
            "--se=" + str(server.configuration.firmware),
            "--ex", "set pagination off",
            "--ex", "set confirm off",
            "--ex", "target extended-remote 127.0.0.1:%d" %
            server.configuration.gdb_port,
        ]
        for gdb_command in commands:
            command.extend(("--ex", gdb_command))

        artifact_suffix = "" if artifact_name is None else "-" + _safe_artifact_name(artifact_name)
        artifacts = server.configuration.artifacts
        artifacts.write_json("external-gdb%s.json" % artifact_suffix, {
            "command": command,
            "executable": self._executable,
            "firmware": str(server.configuration.firmware),
            "version": version,
        })
        output_path = artifacts.directory / ("external-gdb%s.log" % artifact_suffix)
        with output_path.open("wb") as output:
            output.write(version.encode("utf-8", errors="replace"))
            output.write(b"\n\n")
            try:
                completed = subprocess.run(
                    command,
                    cwd=server.configuration.repository_root,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    check=False)
            except subprocess.TimeoutExpired as error:
                raise ExternalGDBError(
                    "external GDB timed out; see %s" % output_path) from error
            except OSError as error:
                raise ExternalGDBError(
                    "could not run --gdbserver-gdb %r: %s" %
                    (self._executable, error)) from error

        output_text = output_path.read_text(encoding="utf-8", errors="replace")
        if completed.returncode != 0:
            raise ExternalGDBError(
                "external GDB exited with code %d; see %s" %
                (completed.returncode, output_path))
        return output_text

    def start(self, server: PyOCDGDBServer, name: str,
              timeout: float = 15.0, non_stop: bool = False) -> ExternalGDBSession:
        """Start an interactive GDB client for concurrent controller/observer scenarios."""
        if not name:
            raise ValueError("external GDB session name must not be empty")
        version = self._get_version(server.configuration.repository_root, timeout)
        command = [
            self._executable,
            "--nx",
            "--nh",
            "--quiet",
            "--se=" + str(server.configuration.firmware),
            "--ex", "set pagination off",
            "--ex", "set confirm off",
        ]
        if non_stop:
            command.extend(("--ex", "set non-stop on"))
        command.extend((
            "--ex", "target extended-remote 127.0.0.1:%d" %
            server.configuration.gdb_port,
        ))
        artifacts = server.configuration.artifacts
        artifacts.write_json("external-gdb-%s.json" % name, {
            "command": command,
            "executable": self._executable,
            "firmware": str(server.configuration.firmware),
            "version": version,
        })
        output_path = artifacts.directory / ("external-gdb-%s.log" % name)
        output_path.write_text(version + "\n\n", encoding="utf-8")
        try:
            process = subprocess.Popen(
                command,
                cwd=server.configuration.repository_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0)
        except OSError as error:
            raise ExternalGDBError(
                "could not run --gdbserver-gdb %r: %s" %
                (self._executable, error)) from error
        session = ExternalGDBSession(process, output_path)
        try:
            session.execute("echo GDB-E2E-READY\\n", timeout)
        except Exception:
            session.close()
            raise
        return session

    def start_mi(self, server: PyOCDGDBServer, name: str,
                 timeout: float = 15.0,
                 non_stop: bool = False) -> ExternalGDBMISession:
        """Start an asynchronous GDB/MI client for execution-control scenarios."""
        if not name:
            raise ValueError("external GDB/MI session name must not be empty")
        version = self._get_version(server.configuration.repository_root, timeout)
        command = [
            self._executable,
            "--nx",
            "--nh",
            "--quiet",
            "--interpreter=mi2",
        ]
        artifacts = server.configuration.artifacts
        artifacts.write_json("external-gdb-mi-%s.json" % name, {
            "command": command,
            "executable": self._executable,
            "firmware": str(server.configuration.firmware),
            "version": version,
        })
        output_path = artifacts.directory / ("external-gdb-mi-%s.log" % name)
        output_path.write_text(version + "\n\n", encoding="utf-8")
        try:
            process = subprocess.Popen(
                command,
                cwd=server.configuration.repository_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0)
        except OSError as error:
            raise ExternalGDBError(
                "could not run --gdbserver-gdb %r: %s" %
                (self._executable, error)) from error
        session = ExternalGDBMISession(process, output_path)
        try:
            session.command("-gdb-set pagination off", timeout)
            session.command("-gdb-set confirm off", timeout)
            if non_stop:
                session.command("-gdb-set non-stop on", timeout)
            session.command("-gdb-set mi-async on", timeout)
            session.command(
                "-file-exec-and-symbols %s" % _mi_quote(str(server.configuration.firmware)),
                timeout)
            session.command(
                "-target-select extended-remote 127.0.0.1:%d" %
                server.configuration.gdb_port,
                timeout,
                expected_result="connected")
        except Exception:
            session.close()
            raise
        return session

    def _get_version(self, cwd: Path, timeout: float) -> str:
        """Run the explicitly selected executable only to record its version."""
        try:
            completed = subprocess.run(
                (self._executable, "--version"),
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=min(timeout, 10.0),
                check=False)
        except subprocess.TimeoutExpired as error:
            raise ExternalGDBError(
                "external GDB version query timed out for %r" %
                self._executable) from error
        except OSError as error:
            raise ExternalGDBError(
                "could not run --gdbserver-gdb %r: %s" %
                (self._executable, error)) from error
        if completed.returncode != 0:
            raise ExternalGDBError(
                "external GDB version query exited with code %d for %r" %
                (completed.returncode, self._executable))
        return completed.stdout.decode("utf-8", errors="replace").rstrip()


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register opt-in hardware test options."""
    group = parser.getgroup("gdbserver e2e", "pyOCD gdbserver hardware-test options")
    group.addoption(
        "--gdbserver-e2e",
        action="store_true",
        default=False,
        help="enable tests that require an attached dedicated hardware target")
    group.addoption(
        "--gdbserver-probe-uid",
        default=None,
        metavar="UID",
        help="unique identifier of the exclusive debug probe")
    group.addoption(
        "--gdbserver-firmware",
        default=None,
        metavar="AXF",
        help="optional AXF/ELF override; normally derived from the cbuild-run file")
    group.addoption(
        "--gdbserver-cbuild-run",
        default=None,
        metavar="PATH",
        help="generated CMSIS cbuild-run.yml describing the target and debug configuration")
    group.addoption(
        "--gdbserver-mailbox-symbol",
        default="gdbserver_test_firmware_mailbox",
        metavar="SYMBOL",
        help="fixture mailbox ELF symbol")
    group.addoption(
        "--gdbserver-artifacts",
        default=None,
        metavar="DIRECTORY",
        help="directory for generated run artifacts")
    group.addoption(
        "--gdbserver-port",
        type=int,
        default=0,
        metavar="PORT",
        help="GDB server port; 0 allocates an available local port")
    group.addoption(
        "--gdbserver-telnet-port",
        type=int,
        default=0,
        metavar="PORT",
        help="semihosting telnet port; 0 allocates an available local port")
    group.addoption(
        "--gdbserver-extra-arg",
        action="append",
        default=[],
        metavar="ARGUMENT",
        help="extra argument passed unchanged to pyOCD gdbserver; repeat as required")
    group.addoption(
        "--gdbserver-no-program",
        action="store_true",
        default=False,
        help="do not flash the fixture before each scenario")
    group.addoption(
        "--gdbserver-no-reset-run",
        action="store_true",
        default=False,
        help="do not pass --reset-run when starting pyOCD gdbserver")
    group.addoption(
        "--gdbserver-semihosting",
        action="store_true",
        default=False,
        help="enable pyOCD semihosting for the scenario")
    group.addoption(
        "--gdbserver-swv",
        action="store_true",
        default=False,
        help="enable hardware SWV capture scenarios after verifying the board SWO route")
    group.addoption(
        "--gdbserver-gdb",
        default=None,
        metavar="EXECUTABLE",
        help=("explicit GDB executable for external-GDB compatibility scenarios; "
              "no automatic executable discovery is performed"))
    group.addoption(
        "--gdbserver-flash-scratch-address",
        default=None,
        metavar="ADDRESS",
        help="reserved flash address used only by the opt-in gdbserver flash-protocol scenario")
    group.addoption(
        "--gdbserver-flash-scratch-size",
        default=None,
        metavar="BYTES",
        help="size of the reserved flash region used by the flash-protocol scenario")


def pytest_configure(config: pytest.Config) -> None:
    """Register the per-scenario process-configuration marker."""
    config.addinivalue_line(
        "markers",
        "gdbserver_config(**settings): configure one hardware scenario "
        "(persist, reset_run, enable_semihosting, semihost_use_syscalls, "
        "rtt_mode, enable_swv, swv_system_clock, swv_clock, vector_catch, "
        "extra_arguments)")
    config.addinivalue_line(
        "markers",
        "gdbserver_external_gdb: require an explicit --gdbserver-gdb executable")
    config.addinivalue_line(
        "markers",
        "gdbserver_rsp: raw GDB Remote Serial Protocol scenario")
    config.addinivalue_line(
        "markers",
        "gdbserver_arm_gdb: scenario driven by arm-none-eabi-gdb")


def pytest_collection_modifyitems(config: pytest.Config,
                                  items: Sequence[pytest.Item]) -> None:
    """Validate scenarios, mark transport groups, and gate external-GDB cases."""
    skip_external_gdb = None
    if not config.getoption("--gdbserver-gdb"):
        skip_external_gdb = pytest.mark.skip(
            reason=("external GDB scenario disabled; pass --gdbserver-gdb with the "
                    "intended executable"))
    for item in items:
        scenario_parts = item.path.parts
        if "scenarios" in scenario_parts:
            if "rsp" in scenario_parts:
                item.add_marker(pytest.mark.gdbserver_rsp)
                _validate_collected_scenario(item)
            elif "arm_gdb" in scenario_parts:
                item.add_marker(pytest.mark.gdbserver_arm_gdb)
                _validate_collected_scenario(item)
        if (skip_external_gdb is not None and
                item.get_closest_marker("gdbserver_external_gdb") is not None):
            item.add_marker(skip_external_gdb)


def _validate_collected_scenario(item: pytest.Item) -> None:
    """Require structured source documentation on a collected scenario."""
    function = getattr(item, "function", None)
    if function is None:
        return
    try:
        validate_scenario_docstring(function.__doc__, item.nodeid)
    except ValueError as error:
        raise pytest.UsageError(str(error)) from error


@pytest.fixture
def gdbserver_server(request: pytest.FixtureRequest) -> Iterator[PyOCDGDBServer]:
    """Yield a fresh, isolated pyOCD server and fixture image for one test."""
    configuration = _configuration_for_test(request)
    with PyOCDGDBServer(configuration) as server:
        yield server


@pytest.fixture
def raw_rsp_client(gdbserver_server: PyOCDGDBServer) -> Iterator[RSPClient]:
    """Yield a deterministic raw RSP client connected to the test server."""
    with gdbserver_server.connect_rsp() as client:
        yield client


@pytest.fixture
def gdbserver_gdb(request: pytest.FixtureRequest) -> ExternalGDB:
    """Yield the user-selected external GDB helper, or skip without discovery."""
    executable = request.config.getoption("--gdbserver-gdb")
    if not executable:
        pytest.skip(
            "external GDB scenario disabled; pass --gdbserver-gdb with the "
            "intended executable")
    return ExternalGDB(executable)


@pytest.fixture
def fixture_mailbox(gdbserver_server: PyOCDGDBServer,
                    raw_rsp_client: RSPClient,
                    request: pytest.FixtureRequest) -> FixtureMailboxClient:
    """Yield the initialized RAM-mailbox driver for the selected fixture image."""
    symbol_name = request.config.getoption("--gdbserver-mailbox-symbol")
    address = resolve_elf_symbol(gdbserver_server.configuration.firmware, symbol_name)
    mailbox = FixtureMailboxClient(raw_rsp_client, address)
    mailbox.wait_until_ready()
    return mailbox


@pytest.fixture
def gdbserver_flash_scratch(request: pytest.FixtureRequest) -> tuple[int, int]:
    """Return the user-declared isolated flash region for protocol flash tests."""
    address_option = request.config.getoption("--gdbserver-flash-scratch-address")
    size_option = request.config.getoption("--gdbserver-flash-scratch-size")
    if address_option is None or size_option is None:
        pytest.skip(
            "flash-protocol test requires --gdbserver-flash-scratch-address and "
            "--gdbserver-flash-scratch-size for a reserved region")
    try:
        address = int(address_option, 0)
        size = int(size_option, 0)
    except ValueError as error:
        raise pytest.UsageError(
            "flash scratch address and size must be decimal or 0x-prefixed integers") from error
    if address <= 0 or size <= 0:
        raise pytest.UsageError("flash scratch address and size must be positive")
    return address, size


def _configuration_for_test(request: pytest.FixtureRequest) -> GDBServerConfiguration:
    config = request.config
    if not config.getoption("--gdbserver-e2e"):
        pytest.skip("hardware test disabled; pass --gdbserver-e2e to enable it")

    probe_uid = config.getoption("--gdbserver-probe-uid")
    firmware_option = config.getoption("--gdbserver-firmware")
    cbuild_run_option = config.getoption("--gdbserver-cbuild-run")
    if not probe_uid:
        raise pytest.UsageError("--gdbserver-probe-uid is required with --gdbserver-e2e")
    if not cbuild_run_option:
        raise pytest.UsageError("--gdbserver-cbuild-run is required with --gdbserver-e2e")

    settings = _scenario_configuration(request)
    enable_swv = settings.get("enable_swv", False)
    if enable_swv and not config.getoption("--gdbserver-swv"):
        pytest.skip(
            "SWV capture is capability-gated; pass --gdbserver-swv only after verifying "
            "the B-U585I-IOT02A SWO route and probe support")

    artifacts_option = config.getoption("--gdbserver-artifacts")
    artifact_root = (Path(artifacts_option) if artifacts_option else _default_artifact_root())
    artifacts = RunArtifacts.create(artifact_root, Path(cbuild_run_option).stem, request.node.nodeid)
    marker_extra_arguments = settings.get("extra_arguments", ())
    return GDBServerConfiguration(
        probe_uid=probe_uid,
        cbuild_run=Path(cbuild_run_option),
        artifacts=artifacts,
        repository_root=Path(str(config.rootpath)),
        scenario_id=request.node.nodeid,
        firmware=Path(firmware_option) if firmware_option else None,
        gdb_port=config.getoption("--gdbserver-port"),
        telnet_port=config.getoption("--gdbserver-telnet-port"),
        program_firmware=not config.getoption("--gdbserver-no-program"),
        reset_run=settings.get("reset_run", not config.getoption("--gdbserver-no-reset-run")),
        persist=settings.get("persist", True),
        enable_semihosting=(
            config.getoption("--gdbserver-semihosting") or
            settings.get("enable_semihosting", False)),
        semihost_use_syscalls=settings.get("semihost_use_syscalls", False),
        vector_catch=settings.get("vector_catch"),
        rtt_mode=settings.get("rtt_mode"),
        enable_swv=enable_swv,
        swv_system_clock=settings.get("swv_system_clock", 160000000),
        swv_clock=settings.get("swv_clock", 2000000),
        extra_arguments=(
            tuple(config.getoption("--gdbserver-extra-arg")) + marker_extra_arguments))


def _scenario_configuration(request: pytest.FixtureRequest) -> dict[str, Any]:
    marker = request.node.get_closest_marker("gdbserver_config")
    if marker is None:
        return {}
    if marker.args:
        raise pytest.UsageError("gdbserver_config accepts keyword settings only")

    settings = dict(marker.kwargs)
    unsupported = set(settings).difference(_SCENARIO_CONFIGURATION_KEYS)
    if unsupported:
        raise pytest.UsageError(
            "unsupported gdbserver_config setting(s): %s" % ", ".join(sorted(unsupported)))
    for name in ("enable_semihosting", "enable_swv", "persist", "reset_run", "semihost_use_syscalls"):
        if name in settings and not isinstance(settings[name], bool):
            raise pytest.UsageError("gdbserver_config %s must be a boolean" % name)
    if "rtt_mode" in settings and settings["rtt_mode"] not in (None, "symbol", "address"):
        raise pytest.UsageError("gdbserver_config rtt_mode must be 'symbol' or 'address'")
    if "vector_catch" in settings and not isinstance(settings["vector_catch"], str):
        raise pytest.UsageError("gdbserver_config vector_catch must be a string")
    for name in ("swv_system_clock", "swv_clock"):
        if name in settings and (not isinstance(settings[name], int) or settings[name] <= 0):
            raise pytest.UsageError("gdbserver_config %s must be a positive integer" % name)
    if "extra_arguments" in settings:
        extra_arguments = settings["extra_arguments"]
        if isinstance(extra_arguments, str) or not isinstance(extra_arguments, (list, tuple)):
            raise pytest.UsageError("gdbserver_config extra_arguments must be a list or tuple")
        if not all(isinstance(argument, str) for argument in extra_arguments):
            raise pytest.UsageError("gdbserver_config extra_arguments must contain only strings")
        settings["extra_arguments"] = tuple(extra_arguments)
    return settings


def _default_artifact_root() -> Path:
    return Path(__file__).resolve().parents[1] / "artifacts"
