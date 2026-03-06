from __future__ import annotations

import asyncio
from typing import Optional

from ..http_client import HttpClient
from ..models import Finding, ScanConfig, ScanModule, Severity


DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
                     "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"}

ALL_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD",
               "TRACE", "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY",
               "MOVE", "LOCK", "UNLOCK", "SEARCH"]


class HttpMethodTester:
    def __init__(self, config: ScanConfig, client: HttpClient) -> None:
        self.config = config
        self.client = client

    async def test(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        options_resp = await self.client.options(url)
        allowed_methods: set[str] = set()

        if options_resp and options_resp.status_code in (200, 204, 405):
            allow_header = options_resp.headers.get("Allow", "") or options_resp.headers.get("allow", "")
            public_header = options_resp.headers.get("Public", "") or options_resp.headers.get("public", "")
            combined = allow_header + "," + public_header
            for m in combined.split(","):
                m = m.strip().upper()
                if m:
                    allowed_methods.add(m)

        if not allowed_methods:
            results = await asyncio.gather(*[
                self._probe_method(url, method) for method in ALL_METHODS
            ], return_exceptions=True)
            for method, result in zip(ALL_METHODS, results):
                if isinstance(result, bool) and result:
                    allowed_methods.add(method)

        findings.extend(self._analyze_methods(url, allowed_methods, options_resp))
        return findings

    async def _probe_method(self, url: str, method: str) -> bool:
        try:
            resp = await self.client.request(method, url, retries=1)
            if resp and resp.status_code not in (0, 405, 501, 400):
                return True
            return False
        except Exception:
            return False

    def _analyze_methods(self, url: str, allowed: set[str], options_resp: object) -> list[Finding]:
        findings: list[Finding] = []

        dangerous_enabled = allowed & DANGEROUS_METHODS

        if "TRACE" in allowed or "TRACE" in dangerous_enabled:
            findings.append(Finding(
                url=url,
                title="HTTP TRACE Method Enabled (XST Vulnerability)",
                severity=Severity.MEDIUM,
                module=ScanModule.METHODS,
                description="HTTP TRACE method is enabled. This can be used in Cross-Site Tracing (XST) attacks to steal credentials.",
                evidence=f"TRACE method accepted at {url}",
                recommendation="Disable the TRACE method in your web server configuration.",
            ))

        if "PUT" in allowed:
            findings.append(Finding(
                url=url,
                title="HTTP PUT Method Enabled",
                severity=Severity.HIGH,
                module=ScanModule.METHODS,
                description="HTTP PUT method is enabled. This may allow unauthorized file uploads to the server.",
                evidence=f"PUT method accepted at {url}",
                recommendation="Disable PUT method unless explicitly required. Implement proper authentication.",
            ))

        if "DELETE" in allowed:
            findings.append(Finding(
                url=url,
                title="HTTP DELETE Method Enabled",
                severity=Severity.HIGH,
                module=ScanModule.METHODS,
                description="HTTP DELETE method is enabled. This may allow unauthorized deletion of resources.",
                evidence=f"DELETE method accepted at {url}",
                recommendation="Disable DELETE method unless required. Implement proper authorization.",
            ))

        webdav_methods = {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"}
        webdav_enabled = allowed & webdav_methods
        if webdav_enabled:
            findings.append(Finding(
                url=url,
                title="WebDAV Methods Enabled",
                severity=Severity.MEDIUM,
                module=ScanModule.METHODS,
                description=f"WebDAV methods are enabled: {', '.join(sorted(webdav_enabled))}. This increases attack surface.",
                evidence=f"WebDAV methods: {', '.join(sorted(webdav_enabled))}",
                recommendation="Disable WebDAV unless required. Restrict access with authentication.",
            ))

        if not dangerous_enabled and allowed:
            findings.append(Finding(
                url=url,
                title="Allowed HTTP Methods",
                severity=Severity.INFO,
                module=ScanModule.METHODS,
                description=f"Server accepts the following HTTP methods: {', '.join(sorted(allowed))}",
                evidence=f"Allowed: {', '.join(sorted(allowed))}",
                recommendation="Verify only required methods are enabled.",
            ))

        return findings
