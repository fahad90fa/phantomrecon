from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ScanState:
    target: str
    scan_id: str
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    completed_modules: list[str] = field(default_factory=list)
    pending_paths: list[str] = field(default_factory=list)
    scanned_paths: list[str] = field(default_factory=list)
    findings_count: int = 0
    discovered_paths_count: int = 0
    total_requests: int = 0
    partial_results: dict[str, Any] = field(default_factory=dict)


class StateManager:
    def __init__(self, state_dir: str = ".") -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._current_state: Optional[ScanState] = None

    def _state_file(self, scan_id: str) -> Path:
        return self.state_dir / f".phantomrecon_state_{scan_id}.json"

    def create_state(self, target: str, scan_id: str) -> ScanState:
        state = ScanState(target=target, scan_id=scan_id)
        self._current_state = state
        self.save(state)
        return state

    def save(self, state: ScanState) -> None:
        state.updated_at = time.time()
        path = self._state_file(state.scan_id)
        try:
            with open(path, "w") as f:
                json.dump(asdict(state), f, indent=2)
        except Exception:
            pass

    def load(self, scan_id: str) -> Optional[ScanState]:
        path = self._state_file(scan_id)
        if not path.exists():
            return None
        try:
            with open(path) as f:
                data = json.load(f)
            state = ScanState(**data)
            self._current_state = state
            return state
        except Exception:
            return None

    def find_resumable(self, target: str) -> Optional[ScanState]:
        for state_file in self.state_dir.glob(".phantomrecon_state_*.json"):
            try:
                with open(state_file) as f:
                    data = json.load(f)
                if data.get("target") == target:
                    age = time.time() - data.get("updated_at", 0)
                    if age < 86400:
                        return ScanState(**data)
            except Exception:
                continue
        return None

    def mark_module_done(self, state: ScanState, module_name: str) -> None:
        if module_name not in state.completed_modules:
            state.completed_modules.append(module_name)
        self.save(state)

    def is_module_done(self, state: ScanState, module_name: str) -> bool:
        return module_name in state.completed_modules

    def add_scanned_path(self, state: ScanState, path: str) -> None:
        if path not in state.scanned_paths:
            state.scanned_paths.append(path)
        if path in state.pending_paths:
            state.pending_paths.remove(path)

    def update_stats(self, state: ScanState, requests: int = 0, findings: int = 0, paths: int = 0) -> None:
        state.total_requests += requests
        state.findings_count += findings
        state.discovered_paths_count += paths
        self.save(state)

    def cleanup(self, state: ScanState) -> None:
        path = self._state_file(state.scan_id)
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass

    def list_states(self) -> list[dict[str, Any]]:
        states = []
        for state_file in self.state_dir.glob(".phantomrecon_state_*.json"):
            try:
                with open(state_file) as f:
                    data = json.load(f)
                states.append({
                    "scan_id": data.get("scan_id"),
                    "target": data.get("target"),
                    "started_at": data.get("started_at"),
                    "updated_at": data.get("updated_at"),
                    "completed_modules": data.get("completed_modules", []),
                    "findings_count": data.get("findings_count", 0),
                    "total_requests": data.get("total_requests", 0),
                })
            except Exception:
                continue
        return sorted(states, key=lambda x: x.get("updated_at", 0), reverse=True)
