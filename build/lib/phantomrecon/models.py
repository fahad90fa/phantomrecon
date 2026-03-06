from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanModule(str, Enum):
    BRUTEFORCE = "bruteforce"
    HEADERS = "headers"
    SSL = "ssl"
    METHODS = "methods"
    FINGERPRINT = "fingerprint"
    DISCLOSURE = "disclosure"
    VULNS = "vulns"
    CRAWLER = "crawler"
    CMS = "cms"
    API = "api"
    VHOST = "vhost"
    WAF = "waf"


@dataclass
class ProxyConfig:
    url: str
    proxy_type: str = "http"
    username: Optional[str] = None
    password: Optional[str] = None
    healthy: bool = True
    failures: int = 0
    last_used: float = 0.0


@dataclass
class ScanConfig:
    target: str
    threads: int = 50
    timeout: int = 10
    retries: int = 3
    delay_min: float = 0.0
    delay_max: float = 0.5
    user_agent: Optional[str] = None
    rotate_ua: bool = True
    proxies: list[str] = field(default_factory=list)
    rotate_proxy_every: int = 10
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    auth: Optional[tuple[str, str]] = None
    auth_type: str = "basic"
    bearer_token: Optional[str] = None
    wordlist: Optional[str] = None
    wordlist_size: str = "medium"
    extensions: list[str] = field(default_factory=list)
    recursive: bool = False
    recursion_depth: int = 3
    follow_redirects: bool = True
    verify_ssl: bool = False
    modules: list[ScanModule] = field(default_factory=list)
    output_dir: str = "."
    output_formats: list[str] = field(default_factory=lambda: ["json", "html"])
    verbosity: int = 1
    rate_limit: int = 0
    scope: list[str] = field(default_factory=list)
    exclude_codes: list[int] = field(default_factory=lambda: [404])
    include_codes: list[int] = field(default_factory=list)
    min_size: int = 0
    max_size: int = 0
    filter_regex: Optional[str] = None
    exclude_regex: Optional[str] = None


@dataclass
class Finding:
    url: str
    title: str
    severity: Severity
    module: ScanModule
    description: str
    evidence: str = ""
    recommendation: str = ""
    cve: Optional[str] = None
    cvss: Optional[float] = None
    extra: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    redirect_chain: list[str] = field(default_factory=list)
    response_time: float = 0.0
    content_length: int = 0
    content_type: str = ""
    error: Optional[str] = None


@dataclass
class DiscoveredPath:
    url: str
    status_code: int
    content_length: int
    content_type: str
    response_time: float
    is_directory: bool = False
    redirect_to: Optional[str] = None
    title: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    target: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    total_requests: int = 0
    findings: list[Finding] = field(default_factory=list)
    discovered_paths: list[DiscoveredPath] = field(default_factory=list)
    technologies: dict[str, Any] = field(default_factory=dict)
    ssl_info: dict[str, Any] = field(default_factory=dict)
    headers_analysis: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_path(self, path: DiscoveredPath) -> None:
        self.discovered_paths.append(path)

    @property
    def duration(self) -> float:
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for f in self.findings:
            result[f.severity.value].append(f)
        return result
