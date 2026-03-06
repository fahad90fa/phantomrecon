from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_SIGNATURES_DIR = Path(__file__).parent


def load_signatures(name: str) -> Any:
    path = _SIGNATURES_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"Signature database not found: {path}")
    with open(path) as f:
        return json.load(f)


def list_databases() -> list[str]:
    return [p.stem for p in _SIGNATURES_DIR.glob("*.json")]
