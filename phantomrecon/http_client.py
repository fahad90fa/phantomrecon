from __future__ import annotations

import asyncio
import random
import time
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientSession, TCPConnector

from .models import HttpResponse, ProxyConfig, ScanConfig
from .useragents import build_browser_headers, get_random_ua


class ProxyManager:
    def __init__(self, proxies: list[str]) -> None:
        self._pool: list[ProxyConfig] = []
        self._index: int = 0
        self._request_count: int = 0
        for p in proxies:
            self._pool.append(self._parse_proxy(p))

    @staticmethod
    def _parse_proxy(proxy_str: str) -> ProxyConfig:
        parsed = urlparse(proxy_str)
        return ProxyConfig(
            url=proxy_str,
            proxy_type=parsed.scheme or "http",
            username=parsed.username,
            password=parsed.password,
        )

    def get_proxy(self) -> Optional[str]:
        healthy = [p for p in self._pool if p.healthy]
        if not healthy:
            return None
        proxy = healthy[self._index % len(healthy)]
        proxy.last_used = time.time()
        self._index = (self._index + 1) % len(healthy)
        return proxy.url

    def mark_failed(self, proxy_url: str) -> None:
        for p in self._pool:
            if p.url == proxy_url:
                p.failures += 1
                if p.failures >= 3:
                    p.healthy = False
                break

    def has_proxies(self) -> bool:
        return bool([p for p in self._pool if p.healthy])


class RateLimiter:
    def __init__(self, rate: int) -> None:
        self._rate = rate
        self._tokens = float(rate)
        self._last_time = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self._rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_time
            self._last_time = now
            self._tokens = min(float(self._rate), self._tokens + elapsed * self._rate)
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


class HttpClient:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.proxy_manager = ProxyManager(config.proxies)
        self.rate_limiter = RateLimiter(config.rate_limit)
        self._session: Optional[ClientSession] = None
        self._request_count: int = 0
        self._current_ua: str = config.user_agent or get_random_ua()

    async def __aenter__(self) -> "HttpClient":
        connector = TCPConnector(
            ssl=False,
            limit=self.config.threads,
            limit_per_host=min(self.config.threads, 30),
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=False,
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._session:
            await self._session.close()
            await asyncio.sleep(0.25)

    def _get_headers(self, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
        if self.config.rotate_ua:
            self._current_ua = get_random_ua()
        headers = build_browser_headers(self._current_ua)
        headers.update(self.config.headers)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _jitter_delay(self) -> float:
        if self.config.delay_max <= 0:
            return 0.0
        base = random.gauss(
            (self.config.delay_min + self.config.delay_max) / 2,
            (self.config.delay_max - self.config.delay_min) / 4,
        )
        return max(self.config.delay_min, min(self.config.delay_max * 2, base))

    async def request(
        self,
        method: str,
        url: str,
        extra_headers: dict[str, str] | None = None,
        data: dict | str | None = None,
        json_data: dict | list | None = None,
        params: dict | None = None,
        allow_redirects: bool = True,
        retries: int | None = None,
    ) -> HttpResponse:
        if self._session is None:
            raise RuntimeError("HttpClient must be used as async context manager")

        await self.rate_limiter.acquire()

        delay = self._jitter_delay()
        if delay > 0:
            await asyncio.sleep(delay)

        max_retries = retries if retries is not None else self.config.retries
        headers = self._get_headers(extra_headers)
        proxy = self.proxy_manager.get_proxy() if self.proxy_manager.has_proxies() else None

        auth = None
        if self.config.auth and self.config.auth_type == "basic":
            auth = aiohttp.BasicAuth(*self.config.auth)

        if self.config.bearer_token:
            headers["Authorization"] = f"Bearer {self.config.bearer_token}"

        if self.config.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.config.cookies.items())
            headers["Cookie"] = cookie_str

        last_error: str = ""
        for attempt in range(max_retries + 1):
            try:
                start = time.monotonic()
                async with self._session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    proxy=proxy,
                    auth=auth,
                    data=data,
                    json=json_data,
                    params=params,
                    allow_redirects=allow_redirects,
                    ssl=False,
                ) as resp:
                    elapsed = time.monotonic() - start
                    body = ""
                    try:
                        body = await resp.text(errors="replace")
                    except Exception:
                        try:
                            raw = await resp.read()
                            body = raw.decode("utf-8", errors="replace")
                        except Exception:
                            body = ""

                    resp_headers = dict(resp.headers)
                    content_type = resp_headers.get("Content-Type", "")
                    content_length = int(resp_headers.get("Content-Length", len(body.encode())))
                    redirect_chain: list[str] = [str(h.url) for h in resp.history]

                    self._request_count += 1
                    return HttpResponse(
                        url=str(resp.url),
                        status_code=resp.status,
                        headers=resp_headers,
                        body=body,
                        redirect_chain=redirect_chain,
                        response_time=elapsed,
                        content_length=content_length,
                        content_type=content_type,
                    )

            except aiohttp.ClientProxyConnectionError:
                if proxy:
                    self.proxy_manager.mark_failed(proxy)
                    proxy = self.proxy_manager.get_proxy()
                last_error = "proxy_error"
                await asyncio.sleep(0.5 * (attempt + 1))
            except (aiohttp.ServerTimeoutError, asyncio.TimeoutError):
                last_error = "timeout"
                await asyncio.sleep(0.5 * (attempt + 1))
            except aiohttp.ClientConnectorError as e:
                last_error = f"connection_error: {e}"
                break
            except Exception as e:
                last_error = str(e)
                if attempt < max_retries:
                    await asyncio.sleep(0.5 * (attempt + 1))

        return HttpResponse(
            url=url,
            status_code=0,
            headers={},
            body="",
            error=last_error,
        )

    async def get(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: object) -> HttpResponse:
        return await self.request("OPTIONS", url, **kwargs)

    @property
    def request_count(self) -> int:
        return self._request_count
