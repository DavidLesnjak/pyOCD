# pyOCD debugger
# Copyright (c) 2026 Arm Limited
# SPDX-License-Identifier: Apache-2.0

"""Artifact storage for deterministic gdbserver hardware-test runs."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Mapping


class RunArtifacts:
    """Own the artifact directory for one scenario attempt."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    @classmethod
    def create(cls, root: Path, target_name: str, scenario_id: str) -> "RunArtifacts":
        """Create a unique directory for a target scenario attempt."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        target_part = cls._safe_path_component(target_name)
        scenario_part = cls._safe_path_component(scenario_id)
        directory = root / target_part / (timestamp + "-" + scenario_part)
        directory.mkdir(parents=True, exist_ok=False)
        return cls(directory)

    def write_json(self, filename: str, value: Mapping[str, Any]) -> Path:
        """Write a formatted UTF-8 JSON artifact and return its path."""
        path = self._path_for(filename)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def append_json_line(self, filename: str, value: Mapping[str, Any]) -> Path:
        """Append one structured event to a UTF-8 JSON-lines artifact."""
        path = self._path_for(filename)
        with path.open("a", encoding="utf-8", newline="\n") as output:
            output.write(json.dumps(value, sort_keys=True) + "\n")
        return path

    def append_bytes(self, filename: str, data: bytes) -> Path:
        """Append raw stream data to a binary artifact."""
        path = self._path_for(filename)
        with path.open("ab") as output:
            output.write(data)
        return path

    def _path_for(self, filename: str) -> Path:
        path = self.directory / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    @staticmethod
    def _safe_path_component(value: str) -> str:
        sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")
        return sanitized or "unnamed"
