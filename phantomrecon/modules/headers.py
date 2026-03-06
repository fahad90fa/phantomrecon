from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ..models import Finding, HttpResponse, ScanConfig, ScanModule, Severity


class HeaderAnalyzer:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    def analyze(self, resp: HttpResponse) -> list[Finding]:
        findings: list[Finding] = []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        url = resp.url

        findings.extend(self._check_missing_security_headers(headers, url))
        findings.extend(self._check_server_disclosure(headers, url))
        findings.extend(self._check_cors(headers, url))
        findings.extend(self._check_csp(headers, url))
        findings.extend(self._check_hsts(headers, url))
        findings.extend(self._check_cookies(resp, url))
        findings.extend(self._check_cache(headers, url))
        findings.extend(self._check_content_type(headers, url))
        return findings

    def _check_missing_security_headers(self, headers: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"

        required = {
            "x-content-type-options": (
                "Missing X-Content-Type-Options Header",
                Severity.MEDIUM,
                "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing attacks.",
            ),
            "x-frame-options": (
                "Missing X-Frame-Options Header",
                Severity.MEDIUM,
                "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking.",
            ),
            "referrer-policy": (
                "Missing Referrer-Policy Header",
                Severity.LOW,
                "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer info.",
            ),
            "permissions-policy": (
                "Missing Permissions-Policy Header",
                Severity.LOW,
                "Add a Permissions-Policy header to control browser feature access.",
            ),
            "content-security-policy": (
                "Missing Content-Security-Policy Header",
                Severity.HIGH,
                "Implement a Content-Security-Policy to prevent XSS and data injection attacks.",
            ),
        }

        for header, (title, severity, rec) in required.items():
            if header not in headers:
                findings.append(Finding(
                    url=url,
                    title=title,
                    severity=severity,
                    module=ScanModule.HEADERS,
                    description=f"The response does not include the '{header}' security header.",
                    recommendation=rec,
                ))

        if is_https and "strict-transport-security" not in headers:
            findings.append(Finding(
                url=url,
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity=Severity.HIGH,
                module=ScanModule.HEADERS,
                description="HSTS header not found on HTTPS site.",
                recommendation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'",
            ))

        if "x-xss-protection" in headers:
            val = headers["x-xss-protection"]
            if val.strip() == "0":
                findings.append(Finding(
                    url=url,
                    title="X-XSS-Protection Disabled",
                    severity=Severity.LOW,
                    module=ScanModule.HEADERS,
                    description="X-XSS-Protection is explicitly disabled.",
                    evidence=f"X-XSS-Protection: {val}",
                    recommendation="Remove this header or set to '1; mode=block'. Rely on CSP instead.",
                ))

        return findings

    def _check_server_disclosure(self, headers: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []

        version_pattern = re.compile(r"[\d]+\.[\d]+")

        for header in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
                       "x-generator", "x-drupal-cache", "x-wordpress-cache"):
            if header in headers:
                val = headers[header]
                if version_pattern.search(val):
                    severity = Severity.MEDIUM
                    title = f"Technology Version Disclosure via {header.title()} Header"
                else:
                    severity = Severity.LOW
                    title = f"Technology Disclosure via {header.title()} Header"

                findings.append(Finding(
                    url=url,
                    title=title,
                    severity=severity,
                    module=ScanModule.HEADERS,
                    description=f"Server discloses technology information in the '{header}' header.",
                    evidence=f"{header.title()}: {val}",
                    recommendation=f"Remove or sanitize the '{header}' header to prevent technology fingerprinting.",
                ))

        return findings

    def _check_cors(self, headers: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "").lower()

        if acao == "*":
            if acac == "true":
                findings.append(Finding(
                    url=url,
                    title="CORS Wildcard with Credentials Allowed",
                    severity=Severity.CRITICAL,
                    module=ScanModule.HEADERS,
                    description="CORS is configured with wildcard origin (*) AND credentials allowed. This is a critical misconfiguration.",
                    evidence=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                    recommendation="Never combine wildcard CORS with credentials. Specify exact allowed origins.",
                ))
            else:
                findings.append(Finding(
                    url=url,
                    title="Permissive CORS Policy (Wildcard Origin)",
                    severity=Severity.MEDIUM,
                    module=ScanModule.HEADERS,
                    description="CORS allows requests from any origin.",
                    evidence=f"Access-Control-Allow-Origin: *",
                    recommendation="Restrict CORS to specific trusted origins.",
                ))
        elif acao and acao != "null":
            if acac == "true":
                findings.append(Finding(
                    url=url,
                    title="CORS with Credentials Allowed",
                    severity=Severity.MEDIUM,
                    module=ScanModule.HEADERS,
                    description=f"CORS credentials are allowed for origin: {acao}",
                    evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: true",
                    recommendation="Verify this origin is fully trusted, as credentials (cookies/auth) will be sent cross-origin.",
                ))

        acam = headers.get("access-control-allow-methods", "")
        dangerous_methods = {"DELETE", "PUT", "PATCH", "TRACE", "CONNECT"}
        if acam:
            allowed = {m.strip().upper() for m in acam.split(",")}
            dangerous_allowed = allowed & dangerous_methods
            if dangerous_allowed:
                findings.append(Finding(
                    url=url,
                    title="CORS Allows Dangerous HTTP Methods",
                    severity=Severity.MEDIUM,
                    module=ScanModule.HEADERS,
                    description=f"CORS policy allows potentially dangerous methods: {', '.join(dangerous_allowed)}",
                    evidence=f"Access-Control-Allow-Methods: {acam}",
                    recommendation="Restrict CORS methods to only GET and POST if possible.",
                ))

        return findings

    def _check_csp(self, headers: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []
        csp = headers.get("content-security-policy", "")
        if not csp:
            return findings

        issues: list[str] = []

        if "'unsafe-inline'" in csp:
            issues.append("'unsafe-inline' allows inline script/style execution (XSS risk)")
        if "'unsafe-eval'" in csp:
            issues.append("'unsafe-eval' allows eval() and similar dangerous functions")
        if "http:" in csp and "script-src" in csp:
            issues.append("HTTP sources allowed in script-src (man-in-the-middle risk)")
        if "data:" in csp and "script-src" in csp:
            issues.append("data: URIs allowed in script-src")

        wildcard_pattern = re.compile(r"(?:script-src|default-src|img-src|connect-src|frame-src)\s+[^;]*\*")
        if wildcard_pattern.search(csp):
            issues.append("Wildcard (*) source in directive allows any origin")

        if not any(d in csp for d in ("default-src", "script-src")):
            issues.append("No default-src or script-src directive found")

        if issues:
            findings.append(Finding(
                url=url,
                title="Weak Content-Security-Policy Configuration",
                severity=Severity.MEDIUM,
                module=ScanModule.HEADERS,
                description="CSP is present but contains weaknesses that reduce its effectiveness.",
                evidence=f"CSP: {csp[:500]}\nIssues:\n" + "\n".join(f"  - {i}" for i in issues),
                recommendation="Review CSP directives and eliminate unsafe-inline, unsafe-eval, and wildcards.",
            ))

        return findings

    def _check_hsts(self, headers: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            return findings

        max_age_match = re.search(r"max-age\s*=\s*(\d+)", hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 15768000:
                findings.append(Finding(
                    url=url,
                    title="HSTS max-age Too Short",
                    severity=Severity.LOW,
                    module=ScanModule.HEADERS,
                    description=f"HSTS max-age is {max_age} seconds (< 6 months). Browsers may not enforce HTTPS for long enough.",
                    evidence=f"Strict-Transport-Security: {hsts}",
                    recommendation="Set max-age to at least 31536000 (1 year) with includeSubDomains.",
                ))
        else:
            findings.append(Finding(
                url=url,
                title="HSTS Header Missing max-age",
                severity=Severity.MEDIUM,
                module=ScanModule.HEADERS,
                description="HSTS header present but max-age is missing or malformed.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Ensure HSTS includes a valid max-age directive.",
            ))

        if "includesubdomains" not in hsts.lower():
            findings.append(Finding(
                url=url,
                title="HSTS Missing includeSubDomains",
                severity=Severity.LOW,
                module=ScanModule.HEADERS,
                description="HSTS does not include the 'includeSubDomains' directive.",
                evidence=f"Strict-Transport-Security: {hsts}",
                recommendation="Add 'includeSubDomains' to protect all subdomains.",
            ))

        return findings

    def _check_cookies(self, resp: HttpResponse, url: str) -> list[Finding]:
        findings: list[Finding] = []
        parsed = urlparse(url)
        is_https = parsed.scheme == "https"

        set_cookie_headers: list[str] = []
        for key, val in resp.headers.items():
            if key.lower() == "set-cookie":
                set_cookie_headers.append(val)

        for cookie_str in set_cookie_headers:
            cookie_lower = cookie_str.lower()
            cookie_name = cookie_str.split("=")[0].strip()

            if is_https and "secure" not in cookie_lower:
                findings.append(Finding(
                    url=url,
                    title=f"Cookie Without Secure Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    module=ScanModule.HEADERS,
                    description="Cookie is missing the Secure flag; it may be transmitted over HTTP.",
                    evidence=cookie_str[:200],
                    recommendation="Add the Secure attribute to all cookies on HTTPS sites.",
                ))

            if "httponly" not in cookie_lower:
                findings.append(Finding(
                    url=url,
                    title=f"Cookie Without HttpOnly Flag: {cookie_name}",
                    severity=Severity.MEDIUM,
                    module=ScanModule.HEADERS,
                    description="Cookie is missing the HttpOnly flag; it is accessible via JavaScript (XSS risk).",
                    evidence=cookie_str[:200],
                    recommendation="Add the HttpOnly attribute to prevent JavaScript access to cookies.",
                ))

            if "samesite" not in cookie_lower:
                findings.append(Finding(
                    url=url,
                    title=f"Cookie Without SameSite Attribute: {cookie_name}",
                    severity=Severity.LOW,
                    module=ScanModule.HEADERS,
                    description="Cookie is missing the SameSite attribute (CSRF risk).",
                    evidence=cookie_str[:200],
                    recommendation="Add SameSite=Strict or SameSite=Lax attribute.",
                ))

            if "session" in cookie_name.lower() or "auth" in cookie_name.lower() or "token" in cookie_name.lower():
                if "expires" not in cookie_lower and "max-age" not in cookie_lower:
                    findings.append(Finding(
                        url=url,
                        title=f"Session Cookie Without Expiry: {cookie_name}",
                        severity=Severity.INFO,
                        module=ScanModule.HEADERS,
                        description="Session/auth cookie has no expiry; it will expire at browser close only.",
                        evidence=cookie_str[:200],
                        recommendation="Set explicit expiry for session cookies based on security requirements.",
                    ))

        return findings

    def _check_cache(self, headers: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []
        cache_control = headers.get("cache-control", "")
        pragma = headers.get("pragma", "")

        sensitive_indicators = any(
            kw in url.lower() for kw in
            ["/account", "/profile", "/dashboard", "/admin", "/payment", "/checkout", "/login", "/auth"]
        )

        if sensitive_indicators:
            if "no-store" not in cache_control.lower() and "private" not in cache_control.lower():
                findings.append(Finding(
                    url=url,
                    title="Sensitive Page May Be Cached",
                    severity=Severity.MEDIUM,
                    module=ScanModule.HEADERS,
                    description="Page at sensitive URL path does not have cache-control: no-store or private.",
                    evidence=f"Cache-Control: {cache_control}\nPragma: {pragma}",
                    recommendation="Add 'Cache-Control: no-store, private' to sensitive pages.",
                ))

        return findings

    def _check_content_type(self, headers: dict[str, str], url: str) -> list[Finding]:
        findings: list[Finding] = []
        ct = headers.get("content-type", "")

        if "text/html" in ct and "charset" not in ct.lower():
            findings.append(Finding(
                url=url,
                title="Content-Type Missing Charset",
                severity=Severity.LOW,
                module=ScanModule.HEADERS,
                description="HTML response Content-Type does not specify charset (potential XSS vector).",
                evidence=f"Content-Type: {ct}",
                recommendation="Set 'Content-Type: text/html; charset=UTF-8'.",
            ))

        return findings

    def get_analysis_summary(self, resp: HttpResponse) -> dict[str, Any]:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        summary: dict[str, Any] = {
            "server": headers.get("server", "Not disclosed"),
            "powered_by": headers.get("x-powered-by", "Not disclosed"),
            "hsts": headers.get("strict-transport-security", "Missing"),
            "csp": headers.get("content-security-policy", "Missing")[:100] if headers.get("content-security-policy") else "Missing",
            "x_frame_options": headers.get("x-frame-options", "Missing"),
            "x_content_type_options": headers.get("x-content-type-options", "Missing"),
            "referrer_policy": headers.get("referrer-policy", "Missing"),
            "permissions_policy": headers.get("permissions-policy", "Missing")[:100] if headers.get("permissions-policy") else "Missing",
            "cors_origin": headers.get("access-control-allow-origin", "Not set"),
            "cache_control": headers.get("cache-control", "Not set"),
        }
        return summary
