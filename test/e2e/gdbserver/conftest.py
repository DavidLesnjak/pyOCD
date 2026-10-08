# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Make the reusable gdbserver hardware-test fixtures available to scenarios."""

from pathlib import Path
import sys

_runner_directory = Path(__file__).resolve().parent / "runner"
if str(_runner_directory) not in sys.path:
    sys.path.insert(0, str(_runner_directory))

pytest_plugins = ("pytest_plugin",)
