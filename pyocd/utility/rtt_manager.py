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

from typing import Optional, Tuple, List, Union
import os
import logging
from pathlib import Path
from dataclasses import dataclass

from ..core import exceptions
from ..core.session import Session
from ..debug.elf.elf import ELFBinaryFile
from .stdio import StdioHandler
from .rtt_server import RTTLogFilter, RTTServer, RTTChanStdioWorker, RTTChanTCPWorker, RTTChanSysViewFileWorker, RTTChanSysViewTCPWorker, RTTChanFileWorker
from .systemview import SystemViewConfig

LOG = logging.getLogger(__name__)
LOG.addFilter(RTTLogFilter())

@dataclass
class RTTConfig:
    """@brief Data class representing RTT configuration for a specific core."""

    # type aliases scoped to the class
    RTTControlBlock = Optional[Tuple[Optional[int], Optional[int], bool]]                 # (address, size, auto-detect)
    RTTChannel      = Optional[Tuple[int, str, Optional[Union[int, str]], Optional[str]]] # (number, mode, port/file-out, file-in)
    RTTChannelList  = Optional[Tuple[RTTChannel, ...]]

    _session: Session
    _target: str
    _core: int
    has_rtt_config: bool = False
    control_block: RTTControlBlock = None
    channels: RTTChannelList = None
    num_systemview_channels: int = 0

    def __post_init__(self):
        self._rtt_configuration()

    # Helper methods
    def _add_channel(self, ch_list: List["RTTConfig.RTTChannel"],
                     number: int,
                     mode: str,
                     port: Optional[int] = None,
                     file_out: Optional[str] = None,
                     file_in: Optional[str] = None) -> None:

        SUPPORTED_MODES = {'stdio', 'server', 'systemview', 'systemview-server', 'file'}

        if number is None:
            # Warn about missing channel number
            LOG.warning("Channel configuration missing channel number; channel disabled", extra={'core_number': self._core})
            return
        if ch_list and any(number == ch[0] for ch in ch_list):
            LOG.warning("Already configured; skipping duplicate", extra={'core_number': self._core, 'rtt_channel': number})
            return
        if mode is None:
            # Warn about missing channel mode
            LOG.warning("Configuration missing mode; channel disabled", extra={'core_number': self._core, 'rtt_channel': number})
            return
        if mode not in SUPPORTED_MODES:
            # Warn about unsupported channel mode
            LOG.warning("Unsupported mode %r; channel disabled",
                        mode, extra={'core_number': self._core, 'rtt_channel': number})
            return
        # Server mode or SystemView server mode requires a port number
        if mode in {'server', 'systemview-server'}:
            if port is None:
                LOG.warning("Configuration missing port for %s mode; channel disabled", mode, extra={'core_number': self._core, 'rtt_channel': number})
                return
            conflict = next((ch for ch in ch_list if ch[1] in {'server', 'systemview-server'} and ch[2] == port), None)
            if conflict is not None:
                LOG.warning("Port %d is already in use for %s mode on channel %d; channel disabled",
                             port, conflict[1], conflict[0], extra={'core_number': self._core, 'rtt_channel': number})
                return
        else:
            port = None
        if mode == 'systemview':
            # Count the number of SystemView channels
            self.num_systemview_channels += 1

        if mode == 'file':
            if file_out is None or file_in is None:
                # If file not provided, set default: <target>_core<X>_ch<Y>
                file_root = f"{self._session.board.target_type}"
                if len(self._session.board.target.cores) > 1:
                    file_root += f"_core{self._core}"
                file_root += f"_ch{number}"
                file_out = file_out or f"{file_root}.out"
                file_in = file_in or f"{file_root}.in"

            # Check if the folder exists for output file
            if file_out is not None:
                dir_out = os.path.dirname(file_out)
                if dir_out and not os.path.exists(dir_out):
                    LOG.warning("Directory for file-out %r for %s mode does not exist; channel out disabled", dir_out, mode, extra={'core_number': self._core, 'rtt_channel': number})
                    file_out = None

            if file_in and not os.path.exists(file_in):
                LOG.warning("File-in %r for %s mode does not exist; channel in disabled", file_in, mode, extra={'core_number': self._core, 'rtt_channel': number})
                file_in = None

        else:
            file_out = None
            file_in = None

        ch_list.append((number, mode, port or file_out or None, file_in))

    def _rtt_configuration(self) -> None:
        rtt_config_list = self._session.options.get('rtt') or []
        if not rtt_config_list:
            return

        self.has_rtt_config = True

        rtt_config_by_pname = {cfg.get('pname'): cfg for cfg in rtt_config_list}
        proc_name = self._target.node_name if self._target.node_name else None

        # Core-specific configuration
        pname_config = rtt_config_by_pname.get(proc_name)

        # Global configuration (applies to all cores, but core-specific config takes precedence)
        global_config = rtt_config_by_pname.get(None)

        cb_g = global_config.get('control-block') if global_config else None
        cb_l = pname_config.get('control-block') if pname_config else None

        # Merge local and global configurations: local values take precedence unless explicitly None
        if cb_g is None and cb_l is None:
            rtt_cb = None
        else:
            address = cb_l.get('address') if (cb_l and cb_l.get('address') is not None) else (cb_g.get('address') if cb_g else None)
            size = cb_l.get('size') if (cb_l and cb_l.get('size') is not None) else (cb_g.get('size') if cb_g else None)
            auto_detect = cb_l.get('auto-detect') if (cb_l and cb_l.get('auto-detect') is not None) else (cb_g.get('auto-detect', None) if cb_g else None)
            if address is not None or auto_detect is not None:
                rtt_cb = (address, size, auto_detect)
            else:
                rtt_cb = None

        self.control_block = rtt_cb

        ch_g = global_config.get('channel') if global_config else None
        ch_l = pname_config.get('channel') if pname_config else None

        rtt_ch: List["RTTConfig.RTTChannel"] = []
        if ch_l is not None:
            for ch in ch_l:
                self._add_channel(rtt_ch, ch.get('number'), ch.get('mode'), ch.get('port') or ch.get('file-out'), ch.get('file-in'))
        if ch_g is not None:
            for ch in ch_g:
                if ch_l is not None and any(ch.get('number') == local_ch.get('number') for local_ch in ch_l):
                    # Skip global channel configuration if a local channel with the same number exists
                    LOG.debug("Core-specific configuration used; skipping global channel configuration",
                              extra={'core_number': self._core, 'rtt_channel': ch.get('number')})
                else:
                    self._add_channel(rtt_ch, ch.get('number'), ch.get('mode'), ch.get('port') or ch.get('file-out'), ch.get('file-in'))

        # Sort channels by channel number if any were added
        if rtt_ch:
            rtt_ch.sort(key=lambda x: x[0])
            self.channels = tuple(rtt_ch)
        else:
            self.channels = None

class RTTManager:
    """@brief Helper class to configure and start RTT server."""

    def __init__(self, session: Session, core: Optional[int] = None, rtt_config: RTTConfig = None, systemview_config: SystemViewConfig = None):
        self._session = session
        self._board = session.board
        if core is None:
            self._core = 0
            self._target = self._board.target
        else:
            self._core = core
            self._target = self._board.target.cores[core]
        self._warning_logged = False

        # RTT configuration
        self._rtt_config = rtt_config

        # SystemView configuration
        self._systemview = systemview_config

        self._rtt_server: Optional[RTTServer] = None

        self._rtt_symbol_address = None
        if self._rtt_config is not None and self._rtt_config.control_block is None:
            # No RTT control block configuration
            # Auto-detect via symbol "_SEGGER_RTT" lookup in the ELF file
            self._rtt_symbol_address = self._find_segger_rtt_symbol()

    def _log_warning_once(self, message: str, *args) -> None:
        """@brief Log only the first warning passed to this helper."""
        if self._warning_logged:
            return

        LOG.warning(message, *args, extra={'core_number': self._core})
        self._warning_logged = True

    def _start_rtt_server(self, address: Optional[int], size: Optional[int]) -> Optional[RTTServer]:
        """@brief Create and start RTT server with the given address and size.
            If address is None, auto-detect will be attempted."""

        try:
            server = RTTServer(self._target, address, size, b'SEGGER RTT', core_number=self._core)
            server.start()
            LOG.debug("Started", extra={'core_number': self._core})
            return server
        except exceptions.RTTError:
            return None

    def _find_segger_rtt_symbol(self) -> Optional[int]:
        """@brief Attempt to find the address of the _SEGGER_RTT symbol in the ELF file for the current core."""

        try:
            get_output = getattr(self._board.target, 'get_output', None)
            if not callable(get_output):
                return None
            symbol_files = get_output(load='symbol')
            if not symbol_files:
                return None

            # Iterate through all outputs
            for f, (_, _, pname) in symbol_files.items():
                # Skip if pname is specified and does not match the current core's name
                if pname is not None and pname != self._target.node_name:
                    continue
                elf = ELFBinaryFile(f)
                symbol_info = elf.symbol_decoder.get_symbol_for_name('_SEGGER_RTT')
                if symbol_info:
                    return symbol_info.address
            return None
        except Exception as e:
            LOG.debug("Failed to get _SEGGER_RTT symbol address from ELF: %s", e, extra={'core_number': self._core})
            return None

    def start_server(self) -> Optional[RTTServer]:
        """@brief Create and start RTT server."""

        if self._rtt_config is None or not self._rtt_config.has_rtt_config:
            LOG.debug("No RTT configuration; RTT disabled", extra={'core_number': self._core})
            return None

        if self._rtt_config.channels is None:
            LOG.warning("No channels configured; RTT disabled", extra={'core_number': self._core})
            return None

        if self._rtt_server is not None:
            LOG.warning("Already running; start_server() call ignored", extra={'core_number': self._core})
            return self._rtt_server

        # Get RTT control block configuration for this core
        rtt_cb = self._rtt_config.control_block

        if rtt_cb is not None:
            address, size, auto_detect = rtt_cb
            if address is None and auto_detect is False:
                self._log_warning_once("Control block configuration is missing address while auto-detect is disabled; RTT disabled")
                return None
            if address is not None:
                self._rtt_server = self._start_rtt_server(address, size)
                if self._rtt_server is not None:
                    if size:
                        LOG.debug("Control block found via memory scan (addr=0x%08x, size=0x%x)", address, size, extra={'core_number': self._core})
                    else:
                        LOG.debug("Control block found at specified address (addr=0x%08x)", address, extra={'core_number': self._core})
                    return self._rtt_server
                else:
                    if size:
                        self._log_warning_once("Failed to find control block via memory scan (addr=0x%08x, size=0x%x)", address, size)
                    else:
                        self._log_warning_once("Failed to find control block at specified address (addr=0x%08x)", address)
            if auto_detect:
                # Fallback: auto-detect via memory scan in default memory region if no address specified
                self._rtt_server = self._start_rtt_server(None, None)
                if self._rtt_server is not None:
                    LOG.debug("Control block found via auto-detect memory scan in default memory region", extra={'core_number': self._core})
                    return self._rtt_server
                else:
                    self._log_warning_once("Failed to find control block via auto-detect memory scan")
            return None
        else:
            address = self._rtt_symbol_address
            if address is None:
                self._log_warning_once("No _SEGGER_RTT symbol available; cannot auto-detect control block")
                return None
            self._rtt_server = self._start_rtt_server(address, None)
            if self._rtt_server is not None:
                LOG.debug("Control block found via _SEGGER_RTT symbol lookup (addr=0x%08x)", address, extra={'core_number': self._core})
                return self._rtt_server

            self._log_warning_once("Failed to find control block at _SEGGER_RTT symbol address (addr=0x%08x)", address)
            return None

    def configure_channels(self, stdio_handler: Optional[StdioHandler] = None):
        """@brief Configure RTT channels."""

        if self._rtt_server is None:
            LOG.warning("Not started; cannot configure channels", extra={'core_number': self._core})
            return

        stdio_enabled = False

        for number, mode, port_or_file_out, file_in in self._rtt_config.channels:
            if self._rtt_server.is_channel_idx_valid(number) is False:
                LOG.warning("Channel index is out of range; skipping configuration", extra={'core_number': self._core, 'rtt_channel': number})
                continue
            if self._rtt_server.is_channel_configured(number):
                LOG.warning("Already configured; skipping configuration", extra={'core_number': self._core, 'rtt_channel': number})
                continue
            # STDIO mode
            if mode == 'stdio':
                if stdio_handler is None:
                    LOG.warning("StdioHandler is not provided; skipping configuration", extra={'core_number': self._core, 'rtt_channel': number})
                    continue
                if stdio_enabled:
                    LOG.warning("Stdio mode is already enabled; skipping configuration", extra={'core_number': self._core, 'rtt_channel': number})
                    continue
                try:
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanStdioWorker(channel=number, stdio=stdio_handler))
                    LOG.info("Configured (mode=%s)", mode, extra={'core_number': self._core, 'rtt_channel': number})
                    stdio_enabled = True
                except exceptions.RTTError as e:
                    LOG.error("Failed to enable stdio mode: %s", e, extra={'core_number': self._core, 'rtt_channel': number})
            # Server mode
            elif mode == 'server':
                try:
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanTCPWorker(port_or_file_out, listen=True))
                    LOG.info("Configured (mode=%s, port=%d)", mode, port_or_file_out, extra={'core_number': self._core, 'rtt_channel': number})
                except exceptions.RTTError as e:
                    LOG.error("Failed to enable server mode: %s", e, extra={'core_number': self._core, 'rtt_channel': number})
            # SystemView mode
            elif mode == 'systemview':
                try:
                    fname_root = self._systemview.file.rsplit('.', 1)[0]
                    fname = f'{fname_root}.core{self._core}.ch{number}.bin'
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanSysViewFileWorker(rtt_server=self._rtt_server, channel=number, file_out=fname, auto_start=self._systemview.auto_start, auto_stop=self._systemview.auto_stop))
                    LOG.info("Configured (mode=%s)", mode, extra={'core_number': self._core, 'rtt_channel': number})
                except (IOError, exceptions.RTTError) as e:
                    LOG.error("Failed to enable systemview mode: %s", e, extra={'core_number': self._core, 'rtt_channel': number})
            # SystemView server mode
            elif mode == 'systemview-server':
                try:
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanSysViewTCPWorker(port_or_file_out, listen=True, core_number=self._core, channel=number))
                    LOG.info("Configured (mode=%s, port=%d)", mode, port_or_file_out, extra={'core_number': self._core, 'rtt_channel': number})
                except exceptions.RTTError as e:
                    LOG.error("Failed to enable systemview-server mode: %s", e, extra={'core_number': self._core, 'rtt_channel': number})
            # File mode
            elif mode == 'file':
                try:
                    self._rtt_server.add_channel_worker(number, lambda: RTTChanFileWorker(channel=number, file_out=port_or_file_out, file_in=file_in))
                    file_out_str = f", file-out={port_or_file_out}" if port_or_file_out else ""
                    file_in_str = f", file-in={file_in}" if file_in else ""
                    LOG.info("Configured (mode=%s%s%s)", mode, file_out_str, file_in_str, extra={'core_number': self._core, 'rtt_channel': number})
                except (IOError, exceptions.RTTError) as e:
                    LOG.error("Failed to enable file mode: %s", e, extra={'core_number': self._core, 'rtt_channel': number})
            else:
                LOG.warning("Unsupported mode %r; skipping configuration", mode, extra={'core_number': self._core, 'rtt_channel': number})
