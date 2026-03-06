from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from ..http_client import HttpClient
from ..models import Finding, ScanConfig


class BasePlugin(ABC):
    name: str = "base"
    version: str = "1.0.0"
    description: str = ""
    author: str = ""

    def __init__(self, config: ScanConfig, client: Optional[HttpClient] = None) -> None:
        self.config = config
        self.client = client
        self._enabled: bool = True

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> list[Finding]:
        ...

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    def get_metadata(self) -> dict[str, str]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
        }
