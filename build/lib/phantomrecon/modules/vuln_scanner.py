from __future__ import annotations

import asyncio
import re
from typing import Optional
from urllib.parse import urljoin, urlencode, urlparse, parse_qs, urlencode

from ..http_client import HttpClient
from ..models import Finding, HttpResponse, ScanConfig, ScanModule, Severity


SENSITIVE_PATHS = [
    ".env", ".env.local", ".env.production", ".env.backup", ".env.example",
    ".env.development", ".env.staging",
    ".git/HEAD", ".git/config", ".gitignore", ".git/COMMIT_EDITMSG",
    ".svn/entries", ".svn/wc.db", ".hg/requires", ".bzr/README",
    "wp-config.php", "wp-config.php.bak", "wp-config.bak", "wp-config.old",
    "config.php", "configuration.php", "config.php.bak", "config.bak",
    "settings.py", "settings.php", "web.config", ".htaccess", ".htpasswd",
    "nginx.conf", "httpd.conf", "apache.conf", "php.ini",
    "backup.zip", "backup.tar.gz", "backup.rar", "backup.tar", "backup.sql",
    "dump.sql", "database.sql", "db.sql", "data.sql", "site.zip", "www.zip",
    "error.log", "access.log", "debug.log", "application.log",
    "server.log", "error_log", "access_log",
    "package.json", "composer.json", "Gemfile", "requirements.txt",
    "Pipfile", "go.mod", "cargo.toml", "yarn.lock", "package-lock.json",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".travis.yml", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml",
    ".github/workflows/ci.yml", ".github/workflows/deploy.yml",
    "terraform.tfstate", ".terraform/terraform.tfstate",
    "serverless.yml", "serverless.yaml",
    ".aws/credentials", "aws-credentials.json",
    "phpinfo.php", "info.php", "test.php", "shell.php", "adminer.php",
    "phpmyadmin/index.php", "pma/index.php",
    "server-status", "server-info", "nginx_status",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "actuator/mappings", "actuator/beans", "actuator/configprops",
    "swagger.json", "swagger.yaml", "openapi.json", "openapi.yaml",
    "api-docs", "api/docs", "graphql", "graphiql",
    "README.md", "readme.html", "CHANGELOG.md", "INSTALL.md",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    ".well-known/security.txt", "security.txt",
    "id_rsa", "id_rsa.pub", "id_dsa", ".bash_history", ".zsh_history",
    ".mysql_history", "authorized_keys",
    "wp-json/wp/v2/users", "wp-login.php", "wp-admin/",
    "xmlrpc.php", "wp-cron.php", "wp-content/debug.log",
    "administrator/index.php", "administrator/",
    "configuration.php.bak", "configuration.bak",
]

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare"],
    "AWS WAF": ["awselb", "x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-check-cacheable", "x-akamai"],
    "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo", "x-cdn=incapsula"],
    "F5 BIG-IP": ["bigipserver", "f5-", "x-cnection", "ts="],
    "ModSecurity": ["mod_security", "modsecurity", "naxsi"],
    "Sucuri": ["x-sucuri-id", "sucuri"],
    "Barracuda": ["barra_counter_session", "barracuda"],
    "Fortinet": ["fortigate", "fortiweb"],
    "Citrix": ["ns_af", "netscaler", "citrix"],
    "Nginx WAF": ["naxsi_sig"],
    "Wordfence": ["wordfence"],
    "SiteLock": ["x-sitelock"],
}

SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"Npgsql\.",
    r"ERROR:\s+syntax error at or near",
    r"ORA-[0-9]{4,}",
    r"Microsoft OLE DB Provider for SQL Server",
    r"ODBC SQL Server Driver",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"\[Microsoft\]\[ODBC SQL Server Driver\]",
    r"Unclosed quotation mark",
    r"SQLite.*Exception",
    r"SQLITE_ERROR",
    r"sqlite3\.OperationalError",
    r"You have an error in your SQL syntax",
    r"supplied argument is not a valid MySQL",
    r"Column count doesn't match",
    r"The used SELECT statements have a different number",
    r"Syntax error or access violation",
    r"DBD::mysql::st execute failed",
    r"DB2 SQL error",
    r"Sybase message",
    r"Informix.*Exception",
]

XSS_REFLECTION_TEST = "<script>xss</script>"
LFI_PATHS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "%2fetc%2fpasswd",
]

SSRF_INDICATORS = [
    r"Connection refused",
    r"Failed to connect",
    r"Network is unreachable",
    r"No route to host",
    r"169\.254\.",
    r"10\.\d+\.\d+\.\d+",
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
    r"192\.168\.\d+\.\d+",
    r"127\.\d+\.\d+\.\d+",
]


class VulnScanner:
    def __init__(self, config: ScanConfig, client: HttpClient) -> None:
        self.config = config
        self.client = client
        self._sql_patterns = [re.compile(p, re.IGNORECASE) for p in SQL_ERROR_PATTERNS]
        self._ssrf_patterns = [re.compile(p, re.IGNORECASE) for p in SSRF_INDICATORS]

    async def scan_sensitive_paths(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.config.threads)

        async def check_path(path: str) -> Optional[Finding]:
            async with semaphore:
                url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                resp = await self.client.get(url, allow_redirects=False)
                if resp and resp.status_code in (200, 301, 302, 401, 403):
                    return self._classify_sensitive_path(url, path, resp)
            return None

        results = await asyncio.gather(*[check_path(p) for p in SENSITIVE_PATHS], return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)

        return findings

    def _classify_sensitive_path(self, url: str, path: str, resp: HttpResponse) -> Optional[Finding]:
        path_lower = path.lower()

        if resp.status_code in (401, 403):
            severity = Severity.LOW
            description = f"Sensitive path exists but is protected (HTTP {resp.status_code})."
        elif resp.status_code in (200, 301, 302):
            severity = Severity.HIGH
            description = f"Sensitive path is accessible (HTTP {resp.status_code})."
        else:
            return None

        if any(kw in path_lower for kw in [".env", "credentials", "password", "passwd", "secret", "id_rsa"]):
            severity = Severity.CRITICAL
        elif any(kw in path_lower for kw in ["config", "backup", ".sql", ".bak", ".git", "phpinfo", "shell"]):
            severity = Severity.HIGH
        elif any(kw in path_lower for kw in ["swagger", "api-docs", "graphql", "actuator", "server-status"]):
            severity = Severity.MEDIUM

        snippet = ""
        if resp.status_code == 200 and resp.body:
            snippet = resp.body[:200].strip()

        return Finding(
            url=url,
            title=f"Sensitive File/Path Accessible: {path}",
            severity=severity,
            module=ScanModule.VULNS,
            description=description,
            evidence=snippet or f"HTTP {resp.status_code}",
            recommendation=f"Restrict access to '{path}'. Remove from public webroot if not needed.",
        )

    def detect_waf(self, resp: HttpResponse) -> Optional[str]:
        body_lower = resp.body.lower()
        headers_str = " ".join(f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items())

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in body_lower:
                    return waf_name

        if resp.status_code in (406, 501) and "mod_security" in body_lower:
            return "ModSecurity"

        return None

    async def test_sql_injection(self, url: str, params: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        payloads = ["'", '"', "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND 1=1--", "1; DROP TABLE users--"]

        for param_name, original_value in params.items():
            for payload in payloads:
                test_params = dict(params)
                test_params[param_name] = payload
                test_url = url + "?" + urlencode(test_params)
                resp = await self.client.get(test_url, retries=1)
                if resp and resp.status_code == 200:
                    for pattern in self._sql_patterns:
                        if pattern.search(resp.body):
                            findings.append(Finding(
                                url=test_url,
                                title=f"Potential SQL Injection: Parameter '{param_name}'",
                                severity=Severity.CRITICAL,
                                module=ScanModule.VULNS,
                                description=f"SQL error pattern detected in response when injecting into parameter '{param_name}'.",
                                evidence=f"Payload: {payload}\nMatch: {pattern.pattern[:100]}",
                                recommendation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            ))
                            break

        return findings

    async def test_open_redirect(self, url: str, params: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        redirect_params = ["url", "redirect", "redirect_url", "return", "return_url",
                           "next", "next_url", "target", "destination", "goto", "link", "to"]
        test_url_payload = "https://evil.example.com/redirect"

        for param_name in params:
            if param_name.lower() in redirect_params:
                test_params = dict(params)
                test_params[param_name] = test_url_payload
                test_url_full = url + "?" + urlencode(test_params)
                resp = await self.client.get(test_url_full, allow_redirects=False, retries=1)
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    if "evil.example.com" in location:
                        findings.append(Finding(
                            url=test_url_full,
                            title=f"Open Redirect via Parameter '{param_name}'",
                            severity=Severity.MEDIUM,
                            module=ScanModule.VULNS,
                            description=f"URL parameter '{param_name}' reflects in Location header without validation.",
                            evidence=f"Location: {location}",
                            recommendation="Validate and whitelist allowed redirect destinations.",
                        ))

        return findings

    async def test_host_header_injection(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        test_host = "evil.example.com"

        resp = await self.client.get(url, extra_headers={"Host": test_host}, retries=1)
        if resp and resp.body and test_host in resp.body:
            findings.append(Finding(
                url=url,
                title="Host Header Injection",
                severity=Severity.HIGH,
                module=ScanModule.VULNS,
                description="The Host header value is reflected in the response body, indicating a host header injection vulnerability.",
                evidence=f"Injected: Host: {test_host}\nReflected in response body.",
                recommendation="Validate and whitelist the Host header. Use a web framework that handles this automatically.",
            ))

        return findings

    async def test_clickjacking(self, url: str, resp: HttpResponse) -> list[Finding]:
        findings: list[Finding] = []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        has_csp_frame = "frame-ancestors" in headers.get("content-security-policy", "")
        has_xfo = "x-frame-options" in headers

        if not has_csp_frame and not has_xfo:
            findings.append(Finding(
                url=url,
                title="Clickjacking Vulnerability - Missing Frame Protection",
                severity=Severity.MEDIUM,
                module=ScanModule.VULNS,
                description="The page does not set X-Frame-Options or CSP frame-ancestors, making it susceptible to clickjacking.",
                recommendation="Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors none;'.",
            ))

        return findings

    async def test_lfi(self, url: str, params: dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        lfi_indicators = [
            r"root:.*:0:0:",
            r"\[boot loader\]",
            r"127\.0\.0\.1.*localhost",
            r"# localhost",
            r"<\?php",
        ]
        lfi_patterns = [re.compile(p, re.IGNORECASE) for p in lfi_indicators]

        file_params = [p for p in params if any(kw in p.lower() for kw in
                       ["file", "page", "path", "include", "load", "read", "template", "view", "doc"])]

        for param_name in file_params:
            for payload in LFI_PATHS[:5]:
                test_params = dict(params)
                test_params[param_name] = payload
                test_url = url + "?" + urlencode(test_params)
                resp = await self.client.get(test_url, retries=1)
                if resp and resp.status_code == 200:
                    for pattern in lfi_patterns:
                        if pattern.search(resp.body):
                            findings.append(Finding(
                                url=test_url,
                                title=f"Local File Inclusion (LFI) via '{param_name}'",
                                severity=Severity.CRITICAL,
                                module=ScanModule.VULNS,
                                description=f"File inclusion content detected in response via parameter '{param_name}'.",
                                evidence=f"Payload: {payload}",
                                recommendation="Never pass user-supplied input to file include functions. Use whitelisting.",
                            ))
                            break

        return findings

    async def check_crlf_injection(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        payload = "%0d%0aX-Injected-Header: injected"
        test_url = url + payload
        resp = await self.client.get(test_url, allow_redirects=False, retries=1)
        if resp and "x-injected-header" in {k.lower() for k in resp.headers}:
            findings.append(Finding(
                url=url,
                title="CRLF Injection in URL",
                severity=Severity.HIGH,
                module=ScanModule.VULNS,
                description="CRLF characters in the URL result in header injection.",
                evidence="X-Injected-Header appeared in response.",
                recommendation="Sanitize user-supplied input. Reject or encode CR/LF characters.",
            ))
        return findings
