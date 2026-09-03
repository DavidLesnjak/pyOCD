# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Isolated pyOCD gdbserver process control for hardware scenarios."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Mapping, Optional, Sequence

import yaml

from pyocd import __version__ as PYOCD_VERSION

from artifacts import RunArtifacts
from mailbox import resolve_elf_symbol
from rsp import RSPClient, RSPPacket
from stream import TCPStreamClient


class GDBServerError(RuntimeError):
    """Base error for a managed pyOCD gdbserver."""


class GDBServerStartError(GDBServerError):
    """Raised when pyOCD does not start a listening gdbserver by its deadline."""


class FirmwareProgrammingError(GDBServerError):
    """Raised when pyOCD fails to program the selected fixture image."""


@dataclass
class GDBServerConfiguration:
    """All process-level inputs for one isolated gdbserver scenario."""

    probe_uid: str
    cbuild_run: Path
    artifacts: RunArtifacts
    repository_root: Path
    scenario_id: str = "unspecified"
    firmware: Optional[Path] = None
    python_executable: str = sys.executable
    gdb_port: int = 0
    telnet_port: int = 0
    start_timeout: float = 15.0
    program_timeout: float = 60.0
    program_firmware: bool = True
    reset_run: bool = True
    persist: bool = True
    enable_semihosting: bool = False
    semihost_use_syscalls: bool = False
    vector_catch: Optional[str] = None
    rtt_mode: Optional[str] = None
    rtt_port: int = 0
    rtt_burst_port: int = 0
    enable_swv: bool = False
    swv_system_clock: int = 160000000
    swv_clock: int = 2000000
    swv_raw_port: int = 0
    session_options: Mapping[str, object] = field(default_factory=dict)
    extra_arguments: Sequence[str] = field(default_factory=tuple)
    rtt_control_block_address: Optional[int] = field(init=False, default=None)

    def __post_init__(self) -> None:
        self.cbuild_run = self.cbuild_run.resolve()
        self.repository_root = self.repository_root.resolve()
        if not self.cbuild_run.is_file():
            raise ValueError("cbuild-run file does not exist: %s" % self.cbuild_run)
        if self.firmware is None:
            self.firmware = _find_symbol_image(self.cbuild_run)
        else:
            self.firmware = self.firmware.resolve()
        if not self.firmware.is_file():
            raise ValueError("fixture firmware does not exist: %s" % self.firmware)
        if not self.repository_root.is_dir():
            raise ValueError("repository root does not exist: %s" % self.repository_root)
        if not self.scenario_id:
            raise ValueError("scenario_id must not be empty")
        if self.gdb_port == 0:
            self.gdb_port = _find_free_tcp_port()
        if self.telnet_port == 0:
            self.telnet_port = _find_free_tcp_port((self.gdb_port,))
        if self.semihost_use_syscalls:
            self.enable_semihosting = True
        if self.rtt_mode not in (None, "symbol", "address"):
            raise ValueError("rtt_mode must be one of None, 'symbol', or 'address'")
        if self.rtt_mode is not None:
            if self.rtt_port == 0:
                self.rtt_port = _find_free_tcp_port((self.gdb_port, self.telnet_port))
            if self.rtt_burst_port == 0:
                self.rtt_burst_port = _find_free_tcp_port(
                    (self.gdb_port, self.telnet_port, self.rtt_port))
            if self.rtt_mode == "address":
                self.rtt_control_block_address = resolve_elf_symbol(self.firmware, "_SEGGER_RTT")
        if self.enable_swv:
            # pyOCD's SWV worker relies on the semihosting service thread.
            self.enable_semihosting = True
            if self.swv_system_clock <= 0 or self.swv_clock <= 0:
                raise ValueError("SWV clocks must be positive")
            if self.swv_raw_port == 0:
                rtt_ports = ((self.rtt_port, self.rtt_burst_port)
                             if self.rtt_mode is not None else ())
                self.swv_raw_port = _find_free_tcp_port(
                    (self.gdb_port, self.telnet_port) + rtt_ports)

        active_ports = [self.gdb_port, self.telnet_port]
        if self.rtt_mode is not None:
            active_ports.extend((self.rtt_port, self.rtt_burst_port))
        if self.enable_swv:
            active_ports.append(self.swv_raw_port)
        if len(active_ports) != len(set(active_ports)):
            raise ValueError("GDB, telnet, both RTT, and SWV ports must be different")
        if self.rtt_mode is not None and "rtt" in self.session_options:
            raise ValueError("rtt_mode and session_options['rtt'] cannot be combined")


class PyOCDGDBServer:
    """Program a fixture and manage the pyOCD gdbserver process for one test."""

    _READY_MARKER = "PYOCD_GDBSERVER_E2E_READY"

    def __init__(self, configuration: GDBServerConfiguration) -> None:
        self.configuration = configuration
        self._process: Optional[subprocess.Popen] = None
        self._server_log = None
        self._rsp_connection_count = 0

    def __enter__(self) -> "PyOCDGDBServer":
        if self.configuration.program_firmware:
            self.program_firmware()
        self.start()
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.stop()

    @property
    def is_running(self) -> bool:
        """Whether the gdbserver process is still running."""
        return self._process is not None and self._process.poll() is None

    def program_firmware(self) -> None:
        """Flash the exact fixture image with the current checkout's pyOCD."""
        command = self._base_command() + [
            "load",
            "--no-config",
            "--project", str(self.configuration.cbuild_run.parent),
            "--cbuild-run", str(self.configuration.cbuild_run),
        ]
        command.extend(["--uid", self.configuration.probe_uid])
        output_path = self.configuration.artifacts.directory / "program.log"
        with output_path.open("wb") as output:
            try:
                completed = subprocess.run(
                    command,
                    cwd=self.configuration.repository_root,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=self.configuration.program_timeout,
                    check=False)
            except subprocess.TimeoutExpired as error:
                raise FirmwareProgrammingError(
                    "fixture programming timed out; see %s" % output_path) from error

        if completed.returncode != 0:
            raise FirmwareProgrammingError(
                "fixture programming failed with exit code %d; see %s" %
                (completed.returncode, output_path))

    def start(self) -> None:
        """Start pyOCD gdbserver from this repository and wait for its ready marker."""
        if self.is_running:
            raise GDBServerError("gdbserver is already running")

        command = self._gdbserver_command()
        log_path = self.configuration.artifacts.directory / "gdbserver.log"
        self._server_log = log_path.open("wb")
        self._process = subprocess.Popen(
            command,
            cwd=self.configuration.repository_root,
            stdout=self._server_log,
            stderr=subprocess.STDOUT)
        self._write_run_metadata(command)

        try:
            self._wait_for_ready_marker(log_path)
        except Exception:
            self.stop()
            raise

    def stop(self) -> None:
        """Terminate the owned server process and close its artifact log."""
        process = self._process
        self._process = None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)
        if self._server_log is not None:
            self._server_log.close()
            self._server_log = None

    def connect_rsp(self, timeout: float = 5.0) -> RSPClient:
        """Open a raw RSP client after pyOCD has attached it to the target."""
        if not self.is_running:
            raise GDBServerError("cannot connect to a stopped gdbserver")
        self._rsp_connection_count += 1
        connection_id = self._rsp_connection_count
        client = RSPClient.connect(
            "127.0.0.1",
            self.configuration.gdb_port,
            timeout=timeout,
            packet_observer=lambda packet: self._record_rsp_packet(
                connection_id, packet))
        try:
            # A TCP connect completes before gdbserver's accept loop has necessarily
            # created the corresponding client session. Client creation halts the
            # target, so do not let a scenario start execution until that work has
            # completed. qSupported is a side-effect-free RSP request that
            # confirms it without depending on a target-specific thread ID.
            if b"PacketSize=" not in client.command(
                    b"qSupported:PacketSize=4000", timeout=timeout):
                raise GDBServerError("gdbserver returned an invalid qSupported response")
        except Exception:
            client.close()
            raise
        return client

    def connect_stream(self, port: int, artifact_name: str,
                       timeout: float = 5.0) -> TCPStreamClient:
        """Connect to and capture a gdbserver side-channel TCP stream."""
        if not self.is_running:
            raise GDBServerError("cannot connect to a stopped gdbserver")
        return TCPStreamClient.connect(
            "127.0.0.1",
            port,
            timeout=timeout,
            data_observer=lambda data: self._record_stream_data(artifact_name, data))

    def wait_for_log(self, text: str, timeout: float = 5.0) -> str:
        """Wait until the server log contains a known diagnostic or trace record."""
        log_path = self.configuration.artifacts.directory / "gdbserver.log"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            log = self._read_log(log_path)
            if text in log:
                return log
            if not self.is_running:
                raise GDBServerError("gdbserver stopped while waiting for log text: %s" % text)
            time.sleep(0.050)
        raise GDBServerError("gdbserver log did not contain %r within %.1f seconds" % (text, timeout))

    def wait_until_stopped(self, timeout: float = 5.0) -> bool:
        """Wait for a non-persistent server process to exit."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.is_running:
                return True
            time.sleep(0.050)
        return not self.is_running

    def _base_command(self) -> list[str]:
        return [self.configuration.python_executable, "-u", "-m", "pyocd"]

    def _gdbserver_command(self) -> list[str]:
        command = self._base_command() + [
            "gdbserver",
            "--no-config",
            "--project", str(self.configuration.cbuild_run.parent),
            "--cbuild-run", str(self.configuration.cbuild_run),
            "--uid", self.configuration.probe_uid,
            "--port", str(self.configuration.gdb_port),
            "--telnet-port", str(self.configuration.telnet_port),
            "--elf", str(self.configuration.firmware),
        ]
        if self.configuration.persist:
            command.append("--persist")
        if self.configuration.enable_semihosting:
            command.append("--semihosting")
        if self.configuration.vector_catch is not None:
            command.extend(["--vector-catch", self.configuration.vector_catch])
        if self.configuration.reset_run:
            command.append("--reset-run")
        for name, value in self._session_option_arguments():
            command.extend(["-O", name + "=" + value])
        command.extend(self.configuration.extra_arguments)
        command.extend(["--command", "echo " + self._READY_MARKER])
        return command

    def _session_option_arguments(self) -> Sequence[tuple[str, str]]:
        options = dict(self.configuration.session_options)
        if self.configuration.semihost_use_syscalls:
            options["semihost_use_syscalls"] = True
        elif self.configuration.enable_semihosting:
            # cbuild-run defaults STDIO to off unless the runner explicitly enables it.
            options.setdefault("stdio_mode", "server")
        if self.configuration.rtt_mode is not None:
            rtt_configuration: dict[str, object] = {
                "channel": [
                    {"number": 0, "mode": "server", "port": self.configuration.rtt_port},
                    {"number": 1, "mode": "server", "port": self.configuration.rtt_burst_port},
                ],
            }
            if self.configuration.rtt_control_block_address is not None:
                rtt_configuration["control-block"] = {
                    "address": self.configuration.rtt_control_block_address,
                }
            options["rtt"] = [rtt_configuration]
        if self.configuration.enable_swv:
            options.update({
                "enable_swv": True,
                "swv_system_clock": self.configuration.swv_system_clock,
                "swv_clock": self.configuration.swv_clock,
                "swv_raw_port": self.configuration.swv_raw_port,
            })

        return tuple((name, _format_session_option(value)) for name, value in options.items())

    def _wait_for_ready_marker(self, log_path: Path) -> None:
        deadline = time.monotonic() + self.configuration.start_timeout
        while time.monotonic() < deadline:
            if self._process is None:
                raise GDBServerStartError("gdbserver process was not created")
            if self._process.poll() is not None:
                raise GDBServerStartError(
                    "gdbserver exited with code %d; see %s" %
                    (self._process.returncode, log_path))
            if self._READY_MARKER in self._read_log(log_path):
                return
            time.sleep(0.050)

        raise GDBServerStartError(
            "gdbserver did not become ready within %.1f seconds; see %s" %
            (self.configuration.start_timeout, log_path))

    def _write_run_metadata(self, command: Sequence[str]) -> None:
        self.configuration.artifacts.write_json("run.json", {
            "firmware": str(self.configuration.firmware),
            "firmware_sha256": _file_sha256(self.configuration.firmware),
            "cbuild_run": str(self.configuration.cbuild_run),
            "cbuild_run_sha256": _file_sha256(self.configuration.cbuild_run),
            "cbuild_target_type": _cbuild_target_type(self.configuration.cbuild_run),
            "effective_session_options": dict(self._session_option_arguments()),
            "enable_semihosting": self.configuration.enable_semihosting,
            "enable_swv": self.configuration.enable_swv,
            "gdb_port": self.configuration.gdb_port,
            "persist": self.configuration.persist,
            "probe_uid": self.configuration.probe_uid,
            "pyocd_command": list(command),
            "pyocd_git_commit": _repository_git_commit(
                self.configuration.repository_root),
            "pyocd_version": PYOCD_VERSION,
            "python_executable": self.configuration.python_executable,
            "random_seed": None,
            "reset_run": self.configuration.reset_run,
            "rtt_control_block_address": self.configuration.rtt_control_block_address,
            "rtt_mode": self.configuration.rtt_mode,
            "rtt_burst_port": (
                self.configuration.rtt_burst_port if self.configuration.rtt_mode else None),
            "rtt_port": self.configuration.rtt_port if self.configuration.rtt_mode else None,
            "semihost_use_syscalls": self.configuration.semihost_use_syscalls,
            "scenario_id": self.configuration.scenario_id,
            "session_options": dict(self.configuration.session_options),
            "swv_clock": self.configuration.swv_clock if self.configuration.enable_swv else None,
            "swv_raw_port": self.configuration.swv_raw_port if self.configuration.enable_swv else None,
            "swv_system_clock": self.configuration.swv_system_clock if self.configuration.enable_swv else None,
            "telnet_port": self.configuration.telnet_port,
        })

    def _record_rsp_packet(self, connection_id: int, packet: RSPPacket) -> None:
        self.configuration.artifacts.append_json_line("rsp.jsonl", {
            "connection_id": connection_id,
            "direction": packet.direction,
            "packet_type": packet.packet_type,
            "payload_hex": packet.payload.hex(),
            "timestamp_monotonic": packet.timestamp,
        })

    def _record_stream_data(self, artifact_name: str, data: bytes) -> None:
        self.configuration.artifacts.append_bytes(artifact_name, data)

    @staticmethod
    def _read_log(log_path: Path) -> str:
        try:
            return log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""


def _find_free_tcp_port(excluded: Sequence[int] = ()) -> int:
    """Find a locally available TCP port that differs from current endpoints."""
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as socket_handle:
            socket_handle.bind(("127.0.0.1", 0))
            port = int(socket_handle.getsockname()[1])
        if port not in excluded:
            return port


def _format_session_option(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if value is None:
        return "null"
    return yaml.safe_dump(
        value,
        default_flow_style=True,
        sort_keys=False,
        width=1000000).strip()


def _file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as firmware:
        for block in iter(lambda: firmware.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _repository_git_commit(repository_root: Path) -> Optional[str]:
    """Return the checked-out pyOCD revision when Git metadata is available."""
    try:
        completed = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=repository_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3.0,
            check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    commit = completed.stdout.decode("ascii", errors="ignore").strip()
    return commit or None


def _find_symbol_image(cbuild_run: Path) -> Path:
    data = _read_cbuild_run(cbuild_run)
    for output in data.get("output", []):
        if output.get("type") == "elf" and "symbols" in output.get("load", ""):
            return (cbuild_run.parent / output["file"]).resolve()
    raise ValueError("cbuild-run file has no ELF output with symbols: %s" % cbuild_run)


def _cbuild_target_type(cbuild_run: Path) -> Optional[str]:
    return _read_cbuild_run(cbuild_run).get("target-type")


def _read_cbuild_run(cbuild_run: Path) -> dict:
    with cbuild_run.open("r", encoding="utf-8") as input_file:
        document = yaml.safe_load(input_file)
    if not isinstance(document, dict) or not isinstance(document.get("cbuild-run"), dict):
        raise ValueError("invalid cbuild-run file: %s" % cbuild_run)
    return document["cbuild-run"]
