from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
from typing import Any, Callable, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen


INTERACTSH_SERVERS = [
    "oast.pro", "oast.live", "oast.site", "oast.online",
    "oast.fun", "oast.me", "interact.sh",
]


class InteractshInteraction:
    def __init__(self, raw: dict) -> None:
        self.protocol = raw.get("protocol", "")
        self.unique_id = raw.get("unique-id", "")
        self.remote_address = raw.get("remote-address", "")
        self.timestamp = raw.get("timestamp", "")
        self.raw_request = raw.get("raw-request", "")
        self.raw_response = raw.get("raw-response", "")
        self.q_type = raw.get("q-type", "")
        self.raw = raw

    def __repr__(self) -> str:
        return f"<Interaction protocol={self.protocol} from={self.remote_address}>"


class InteractshClient:
    def __init__(
        self,
        server: Optional[str] = None,
        token: Optional[str] = None,
        callback: Optional[Callable] = None,
        poll_interval: int = 5,
    ) -> None:
        self.server = server or INTERACTSH_SERVERS[0]
        self.token = token
        self.callback = callback
        self.poll_interval = poll_interval
        self._correlation_id: Optional[str] = None
        self._secret_key: Optional[str] = None
        self._encoded_id: Optional[str] = None
        self._registered = False
        self._polling = False
        self._interactions: list[InteractshInteraction] = []
        self._poll_task: Optional[asyncio.Task] = None

    @property
    def url(self) -> Optional[str]:
        if self._encoded_id:
            return f"{self._encoded_id}.{self.server}"
        return None

    async def start(self) -> bool:
        try:
            self._correlation_id = secrets.token_hex(16)
            self._secret_key = secrets.token_hex(32)
            self._encoded_id = self._correlation_id[:20]

            payload = {
                "public-key": base64.b64encode(self._secret_key.encode()).decode(),
                "secret-key": self._secret_key,
                "correlation-id": self._correlation_id,
            }

            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = self.token

            url = f"https://{self.server}/register"
            data = json.dumps(payload).encode()
            req = Request(url, data=data, headers=headers, method="POST")

            loop = asyncio.get_event_loop()
            try:
                await loop.run_in_executor(None, lambda: urlopen(req, timeout=10).read())
                self._registered = True
            except Exception:
                self._registered = True

            self._polling = True
            self._poll_task = asyncio.create_task(self._poll_loop())
            return True

        except Exception as e:
            self._registered = False
            return False

    async def stop(self) -> None:
        self._polling = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass

        if self._registered and self._correlation_id:
            try:
                url = f"https://{self.server}/deregister"
                payload = {"correlation-id": self._correlation_id}
                data = json.dumps(payload).encode()
                headers = {"Content-Type": "application/json"}
                if self.token:
                    headers["Authorization"] = self.token
                req = Request(url, data=data, headers=headers, method="POST")
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(None, lambda: urlopen(req, timeout=5).read())
            except Exception:
                pass

    async def _poll_loop(self) -> None:
        while self._polling:
            try:
                await asyncio.sleep(self.poll_interval)
                interactions = await self._poll()
                for interaction in interactions:
                    self._interactions.append(interaction)
                    if self.callback:
                        self.callback(interaction)
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _poll(self) -> list[InteractshInteraction]:
        if not self._correlation_id:
            return []
        try:
            url = f"https://{self.server}/poll?id={self._correlation_id}&secret={self._secret_key}"
            headers = {}
            if self.token:
                headers["Authorization"] = self.token
            req = Request(url, headers=headers)
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(None, lambda: urlopen(req, timeout=10).read())
            data = json.loads(raw)
            interactions = []
            for item in data.get("data", []):
                try:
                    decrypted = self._decrypt(item)
                    interactions.append(InteractshInteraction(decrypted))
                except Exception:
                    interactions.append(InteractshInteraction(item if isinstance(item, dict) else {}))
            return interactions
        except Exception:
            return []

    def _decrypt(self, item: Any) -> dict:
        if isinstance(item, dict):
            return item
        try:
            decoded = base64.b64decode(item)
            return json.loads(decoded)
        except Exception:
            return {}

    def get_interactions(self) -> list[InteractshInteraction]:
        return list(self._interactions)

    def clear_interactions(self) -> None:
        self._interactions.clear()

    def has_interaction(self, unique_id: str) -> bool:
        return any(i.unique_id == unique_id or unique_id in i.raw_request
                   for i in self._interactions)

    def generate_payload_url(self, suffix: str = "") -> str:
        uid = secrets.token_hex(4)
        base = self.url or f"phantomrecon.{self.server}"
        return f"{uid}{suffix}.{base}"

    @staticmethod
    def is_available() -> bool:
        try:
            req = Request(f"https://{INTERACTSH_SERVERS[0]}/", method="HEAD")
            urlopen(req, timeout=5).read()
            return True
        except Exception:
            return False
