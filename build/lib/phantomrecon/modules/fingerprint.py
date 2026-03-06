from __future__ import annotations

import re
from typing import Any, Optional

from ..models import Finding, HttpResponse, ScanConfig, ScanModule, Severity


TECH_SIGNATURES: dict[str, dict[str, Any]] = {
    "WordPress": {
        "headers": ["x-powered-by:wordpress"],
        "body": [r"wp-content/", r"wp-includes/", r"WordPress"],
        "cookies": ["wordpress_", "wp-settings-"],
        "meta": [r'generator.*WordPress'],
    },
    "Joomla": {
        "headers": [],
        "body": [r"/components/com_", r"Joomla!", r"/media/jui/"],
        "meta": [r'generator.*Joomla'],
    },
    "Drupal": {
        "headers": ["x-drupal-cache", "x-generator:drupal"],
        "body": [r"/sites/default/files/", r"Drupal.settings", r"/misc/drupal.js"],
        "meta": [r'generator.*Drupal'],
        "cookies": ["SESS", "DrupalVisitor"],
    },
    "Magento": {
        "body": [r"Mage.Cookies", r"/skin/frontend/", r"Magento"],
        "cookies": ["frontend", "adminhtml"],
        "headers": [],
    },
    "Shopify": {
        "body": [r"cdn.shopify.com", r"Shopify.theme"],
        "headers": ["x-shopify-stage", "x-shopid"],
    },
    "Laravel": {
        "body": [r"Laravel"],
        "cookies": ["laravel_session", "XSRF-TOKEN"],
        "headers": [],
    },
    "Django": {
        "body": [r"csrfmiddlewaretoken"],
        "cookies": ["csrftoken", "sessionid"],
        "headers": [],
    },
    "Ruby on Rails": {
        "body": [r"authenticity_token"],
        "headers": ["x-runtime", "x-request-id"],
        "cookies": ["_session_id"],
    },
    "Next.js": {
        "body": [r"__NEXT_DATA__", r"_next/static"],
        "headers": ["x-nextjs-page", "x-powered-by:next.js"],
    },
    "Nuxt.js": {
        "body": [r"__NUXT__", r"_nuxt/"],
        "headers": ["x-powered-by:nuxt.js"],
    },
    "React": {
        "body": [r"__REACT_FIBER__", r"react-app", r'data-reactroot'],
    },
    "Angular": {
        "body": [r"ng-version=", r"angular\.js", r"ng-controller"],
    },
    "Vue.js": {
        "body": [r"__vue__", r"vue\.js", r"v-bind:", r"v-on:"],
    },
    "jQuery": {
        "body": [r"jquery[\.\-][\d]", r"jQuery\.fn\.jquery"],
    },
    "Bootstrap": {
        "body": [r"bootstrap\.min\.css", r"bootstrap\.min\.js", r'class="(?:container|row|col-)'],
    },
    "Apache": {
        "headers": ["server:apache"],
    },
    "Nginx": {
        "headers": ["server:nginx"],
    },
    "IIS": {
        "headers": ["server:microsoft-iis", "x-powered-by:asp.net"],
    },
    "Tomcat": {
        "headers": ["server:apache-tomcat", "server:apache coyote"],
        "body": [r"Apache Tomcat"],
    },
    "LiteSpeed": {
        "headers": ["server:litespeed", "x-powered-by:litespeed"],
    },
    "Caddy": {
        "headers": ["server:caddy"],
    },
    "PHP": {
        "headers": ["x-powered-by:php"],
        "body": [r"\.php"],
    },
    "ASP.NET": {
        "headers": ["x-powered-by:asp.net", "x-aspnet-version", "x-aspnetmvc-version"],
    },
    "Node.js": {
        "headers": ["x-powered-by:express"],
    },
    "Python": {
        "headers": ["x-powered-by:python", "server:werkzeug", "server:gunicorn", "server:uvicorn"],
    },
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server:cloudflare"],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-cache:hit from cloudfront", "via:cloudfront"],
    },
    "Akamai": {
        "headers": ["x-check-cacheable", "x-akamai-transformed"],
    },
    "Fastly": {
        "headers": ["x-served-by", "x-cache:hit", "fastly-restarts"],
    },
    "Varnish": {
        "headers": ["x-varnish", "via:varnish"],
    },
    "Google Analytics": {
        "body": [r"google-analytics\.com/ga\.js", r"gtag\('config'", r"UA-\d{4,10}-\d{1,4}"],
    },
    "Google Tag Manager": {
        "body": [r"googletagmanager\.com"],
    },
    "Stripe": {
        "body": [r"js\.stripe\.com"],
    },
    "Recaptcha": {
        "body": [r"recaptcha\.net", r"google\.com/recaptcha"],
    },
    "Elasticsearch": {
        "body": [r"\"cluster_name\"", r"\"cluster_uuid\"", r"\"number_of_nodes\""],
    },
    "Spring Boot": {
        "body": [r"Whitelabel Error Page", r"Spring Framework", r"org\.springframework"],
        "headers": ["x-application-context"],
    },
    "Symfony": {
        "body": [r"Symfony Component", r"sfFormField"],
        "cookies": ["_sf2_"],
    },
    "CakePHP": {
        "cookies": ["cakephp"],
        "body": [r"CakePHP"],
    },
    "CodeIgniter": {
        "cookies": ["ci_session"],
        "body": [r"CodeIgniter"],
    },
}

DISCLOSURE_PATTERNS: dict[str, dict[str, Any]] = {
    "AWS Access Key": {
        "pattern": r"(?:ASIA|AKIA|AROA|AIDA)[A-Z0-9]{16}",
        "severity": Severity.CRITICAL,
    },
    "AWS Secret Key": {
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": Severity.CRITICAL,
    },
    "GitHub Token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": Severity.CRITICAL,
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": Severity.HIGH,
    },
    "Stripe API Key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,99}",
        "severity": Severity.CRITICAL,
    },
    "Twilio API Key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": Severity.HIGH,
    },
    "SendGrid API Key": {
        "pattern": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "severity": Severity.HIGH,
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z\-]{10,100}",
        "severity": Severity.HIGH,
    },
    "JWT Token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": Severity.HIGH,
    },
    "Private Key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
    },
    "Internal IP Address": {
        "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "severity": Severity.MEDIUM,
    },
    "Email Address": {
        "pattern": r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "severity": Severity.LOW,
    },
    "SQL in HTML Comments": {
        "pattern": r"<!--.*?(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|EXEC|UNION).*?-->",
        "severity": Severity.HIGH,
    },
    "Password in HTML": {
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\",]{4,}['\"]?",
        "severity": Severity.CRITICAL,
    },
    "Stack Trace": {
        "pattern": r"(?:Traceback \(most recent call last\)|at [A-Za-z0-9\.]+\(|Exception in thread|java\.lang\.|System\.Web\.HttpUnhandledException)",
        "severity": Severity.MEDIUM,
    },
    "Directory Listing": {
        "pattern": r"<title>(?:Index of|Directory Listing)",
        "severity": Severity.MEDIUM,
    },
    "Source Map": {
        "pattern": r"//# sourceMappingURL=",
        "severity": Severity.LOW,
    },
}


class Fingerprinter:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._disclosure_compiled = {
            name: re.compile(info["pattern"], re.IGNORECASE | re.DOTALL)
            for name, info in DISCLOSURE_PATTERNS.items()
        }

    def fingerprint(self, resp: HttpResponse) -> dict[str, Any]:
        technologies: dict[str, list[str]] = {}
        headers_str = " ".join(f"{k.lower()}:{v.lower()}" for k, v in resp.headers.items())
        body = resp.body
        cookies_str = resp.headers.get("Set-Cookie", "").lower()

        for tech_name, sigs in TECH_SIGNATURES.items():
            evidence: list[str] = []

            for header_sig in sigs.get("headers", []):
                if header_sig.lower() in headers_str:
                    evidence.append(f"header:{header_sig}")

            for body_sig in sigs.get("body", []):
                if re.search(body_sig, body, re.IGNORECASE):
                    evidence.append(f"body:{body_sig[:40]}")

            for cookie_sig in sigs.get("cookies", []):
                if cookie_sig.lower() in cookies_str:
                    evidence.append(f"cookie:{cookie_sig}")

            for meta_sig in sigs.get("meta", []):
                if re.search(meta_sig, body, re.IGNORECASE):
                    evidence.append(f"meta:{meta_sig[:40]}")

            if evidence:
                technologies[tech_name] = evidence

        return technologies

    def detect_version(self, resp: HttpResponse, tech: str) -> Optional[str]:
        body = resp.body
        headers = resp.headers

        version_patterns: dict[str, list[str]] = {
            "WordPress": [
                r'<meta name="generator" content="WordPress ([0-9.]+)"',
                r"WordPress ([0-9.]+)",
                r"wp-includes/js/wp-embed\.min\.js\?ver=([0-9.]+)",
            ],
            "Joomla": [
                r'<meta name="generator" content="Joomla! ([0-9.]+)"',
            ],
            "Drupal": [
                r'Drupal ([0-9.]+)',
                r'"drupal_settings".*"version":"([0-9.]+)"',
            ],
            "PHP": [
                r"PHP/([0-9.]+)",
            ],
            "Apache": [
                r"Apache/([0-9.]+)",
            ],
            "Nginx": [
                r"nginx/([0-9.]+)",
            ],
            "IIS": [
                r"Microsoft-IIS/([0-9.]+)",
            ],
        }

        server_header = headers.get("Server", "") or headers.get("server", "")
        x_powered = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
        combined = f"{server_header} {x_powered} {body[:50000]}"

        for pattern in version_patterns.get(tech, []):
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def find_disclosure(self, resp: HttpResponse) -> list[Finding]:
        findings: list[Finding] = []
        body = resp.body
        url = resp.url

        for name, pattern in self._disclosure_compiled.items():
            matches = pattern.findall(body)
            if matches:
                severity = DISCLOSURE_PATTERNS[name]["severity"]
                sample = str(matches[0])[:100] if matches else ""

                unique_count = len(set(str(m) for m in matches))

                if name == "Email Address" and unique_count > 20:
                    severity = Severity.MEDIUM

                findings.append(Finding(
                    url=url,
                    title=f"Information Disclosure: {name}",
                    severity=severity,
                    module=ScanModule.DISCLOSURE,
                    description=f"Found {unique_count} instance(s) of '{name}' in the response.",
                    evidence=f"Sample: {sample}",
                    recommendation=self._get_disclosure_recommendation(name),
                ))

        html_comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL)
        sensitive_comment_keywords = [
            "password", "passwd", "secret", "api_key", "apikey", "token",
            "todo", "fixme", "hack", "bug", "temp", "debug", "internal",
            "credentials", "private", "remove", "delete"
        ]
        for comment in html_comments:
            comment_lower = comment.lower()
            for kw in sensitive_comment_keywords:
                if kw in comment_lower and len(comment.strip()) > 5:
                    findings.append(Finding(
                        url=url,
                        title="Sensitive Information in HTML Comment",
                        severity=Severity.MEDIUM,
                        module=ScanModule.DISCLOSURE,
                        description=f"HTML comment contains potentially sensitive keyword: '{kw}'",
                        evidence=comment.strip()[:200],
                        recommendation="Remove sensitive information from HTML comments before production deployment.",
                    ))
                    break

        return findings

    def _get_disclosure_recommendation(self, disclosure_type: str) -> str:
        recs = {
            "AWS Access Key": "Immediately rotate the exposed AWS credentials. Review CloudTrail logs for unauthorized access.",
            "GitHub Token": "Immediately revoke the token on GitHub. Audit recent token activity.",
            "Stripe API Key": "Immediately rotate the Stripe API key in the Stripe dashboard.",
            "Private Key": "Immediately revoke and reissue any certificates associated with this key.",
            "JWT Token": "Invalidate the exposed JWT token. Implement short expiry and proper token storage.",
            "Internal IP Address": "Avoid exposing internal network topology in public-facing responses.",
            "Stack Trace": "Disable detailed error messages in production. Use generic error pages.",
            "Directory Listing": "Disable directory listing in web server configuration.",
            "Password in HTML": "Never embed credentials in HTML. Use environment variables and secrets management.",
        }
        return recs.get(disclosure_type, "Review and remove sensitive information from public responses.")
