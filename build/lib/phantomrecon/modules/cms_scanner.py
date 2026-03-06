from __future__ import annotations

import asyncio
import base64
import json
import re
from typing import Any, Optional
from urllib.parse import urljoin

from ..http_client import HttpClient
from ..models import Finding, ScanConfig, ScanModule, Severity


WP_PLUGINS_COMMON = [
    "akismet", "contact-form-7", "woocommerce", "yoast-seo", "jetpack",
    "wordfence", "elementor", "classic-editor", "really-simple-ssl",
    "wp-super-cache", "w3-total-cache", "all-in-one-seo-pack",
    "updraftplus", "wp-file-manager", "duplicator", "backup-buddy",
    "revslider", "wp-slimstat", "gravityforms", "ninja-forms",
    "all-in-one-wp-migration", "loginizer", "limit-login-attempts-reloaded",
    "wp-mail-smtp", "advanced-custom-fields", "wpforms-lite",
    "mailchimp-for-wp", "google-analytics-for-wordpress", "wp-fastest-cache",
    "autoptimize", "wordpress-seo", "ithemes-security", "sucuri-scanner",
    "timber", "buddypress", "bbpress", "wpcf7", "redirection",
    "ewww-image-optimizer", "imagify", "smush", "shortpixel-image-optimiser",
    "nextgen-gallery", "the-events-calendar", "tribe-events-calendar",
    "easy-digital-downloads", "memberpress", "learndash", "lifterlms",
    "wp-lms", "tutor", "fluentforms", "mailpoet", "newsletter",
    "profile-builder", "user-role-editor", "members", "capability-manager",
    "multisite-toolbar-additions", "polylang", "wpml", "translatepress",
    "cookie-law-info", "gdpr-cookie-compliance", "cookie-notice",
    "complianz-gdpr", "wp-crontrol", "query-monitor", "debug-bar",
    "health-check", "wp-optimize", "hummingbird-performance",
    "asset-cleanup", "flying-scripts", "wp-rocket", "nitropack",
    "imagify", "cloudflare", "cloudinary", "bunnycdn",
]

WP_THEMES_COMMON = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
    "twentytwentyone", "twentytwenty", "twentynineteen", "twentyseventeen",
    "astra", "generatepress", "oceanwp", "hello-elementor", "neve",
    "kadence", "blocksy", "storefront", "enfold", "avada", "divi",
    "flatsome", "betheme", "x", "bridge", "salient", "jupiter",
    "newspaper", "publisher", "jannah", "magazine-pro", "genesis-sample",
]

JOOMLA_COMPONENTS = [
    "com_content", "com_users", "com_contact", "com_weblinks",
    "com_newsfeeds", "com_search", "com_wrapper", "com_mailto",
    "com_banners", "com_tags", "com_finder", "com_ajax",
    "com_config", "com_cpanel", "com_media", "com_menus",
    "com_modules", "com_plugins", "com_templates", "com_languages",
    "com_installer", "com_joomlawire", "com_k2", "com_virtuemart",
    "com_hikashop", "com_akeeba", "com_foxcontact", "com_phocapdf",
    "com_chronoforms", "com_fabrik", "com_eventbooking",
]

DRUPAL_MODULES = [
    "views", "ctools", "token", "pathauto", "admin_menu", "panels",
    "date", "link", "email", "field_group", "imageapi", "imageapi_gd",
    "imagecache", "imagecache_ui", "filefield", "webform", "captcha",
    "recaptcha", "smtp", "mimemail", "rules", "trigger", "actions",
    "node", "user", "comment", "taxonomy", "search", "contact",
    "book", "blog", "aggregator", "forum", "statistics", "poll",
    "profile", "translation", "locale", "content_translation",
    "field_permissions", "acl", "content_access", "role_delegation",
    "backup_migrate", "security_review", "paranoia", "password_policy",
    "login_security", "flood_control", "honeypot", "mollom",
]


class CMSScanner:
    def __init__(self, config: ScanConfig, client: HttpClient) -> None:
        self.config = config
        self.client = client

    async def scan(self, base_url: str, detected_cms: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        cms_names = set(detected_cms.keys())

        tasks = []
        if "WordPress" in cms_names:
            tasks.append(self._scan_wordpress(base_url))
        if "Joomla" in cms_names:
            tasks.append(self._scan_joomla(base_url))
        if "Drupal" in cms_names:
            tasks.append(self._scan_drupal(base_url))

        if not tasks:
            tasks.append(self._scan_generic_cms(base_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                findings.extend(r)

        return findings

    async def _scan_wordpress(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        version_sources = [
            (f"{base}/readme.html", r"Version ([0-9.]+)"),
            (f"{base}/feed/", r"<generator>.*?WordPress.*?([0-9.]+)</generator>"),
            (f"{base}/wp-json/", r'"version"\s*:\s*"([0-9.]+)"'),
            (f"{base}/?p=1", r'<meta name="generator" content="WordPress ([0-9.]+)"'),
        ]

        wp_version: Optional[str] = None
        for url, pattern in version_sources:
            resp = await self.client.get(url, retries=1)
            if resp and resp.status_code == 200:
                match = re.search(pattern, resp.body, re.IGNORECASE)
                if match:
                    wp_version = match.group(1)
                    findings.append(Finding(
                        url=url,
                        title=f"WordPress Version Detected: {wp_version}",
                        severity=Severity.INFO,
                        module=ScanModule.VULNS,
                        description=f"WordPress version {wp_version} detected from {url}.",
                        evidence=f"Pattern match: {pattern}\nVersion: {wp_version}",
                        recommendation="Keep WordPress updated to the latest stable version.",
                    ))
                    break

        user_enum_findings = await self._wp_user_enumeration(base_url)
        findings.extend(user_enum_findings)

        xmlrpc_findings = await self._wp_check_xmlrpc(base_url)
        findings.extend(xmlrpc_findings)

        api_findings = await self._wp_check_rest_api(base_url)
        findings.extend(api_findings)

        cron_findings = await self._wp_check_cron(base_url)
        findings.extend(cron_findings)

        debug_log_url = f"{base}/wp-content/debug.log"
        resp = await self.client.get(debug_log_url, retries=1)
        if resp and resp.status_code == 200 and len(resp.body) > 100:
            findings.append(Finding(
                url=debug_log_url,
                title="WordPress Debug Log Exposed",
                severity=Severity.HIGH,
                module=ScanModule.VULNS,
                description="WordPress debug.log is publicly accessible and may contain sensitive error information.",
                evidence=resp.body[:300],
                recommendation="Delete or restrict access to wp-content/debug.log. Disable WP_DEBUG_LOG in production.",
            ))

        plugin_findings = await self._wp_enumerate_plugins(base_url)
        findings.extend(plugin_findings)

        theme_findings = await self._wp_enumerate_themes(base_url)
        findings.extend(theme_findings)

        return findings

    async def _wp_user_enumeration(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        rest_url = f"{base}/wp-json/wp/v2/users"
        resp = await self.client.get(rest_url, retries=1)
        if resp and resp.status_code == 200:
            try:
                users = json.loads(resp.body)
                if isinstance(users, list) and users:
                    usernames = [u.get("slug", u.get("name", "")) for u in users if isinstance(u, dict)]
                    findings.append(Finding(
                        url=rest_url,
                        title="WordPress User Enumeration via REST API",
                        severity=Severity.HIGH,
                        module=ScanModule.VULNS,
                        description=f"WordPress REST API exposes {len(users)} user(s) without authentication.",
                        evidence=f"Users found: {', '.join(filter(None, usernames[:10]))}",
                        recommendation="Restrict wp-json/wp/v2/users endpoint. Add 'rest_authentication_errors' filter to require auth.",
                    ))
            except json.JSONDecodeError:
                pass

        for i in range(1, 4):
            author_url = f"{base}/?author={i}"
            resp = await self.client.get(author_url, allow_redirects=False, retries=1)
            if resp and resp.status_code in (301, 302):
                location = resp.headers.get("Location", "")
                user_match = re.search(r"/author/([^/]+)/?", location)
                if user_match:
                    username = user_match.group(1)
                    findings.append(Finding(
                        url=author_url,
                        title=f"WordPress User Enumeration via Author Archive: {username}",
                        severity=Severity.MEDIUM,
                        module=ScanModule.VULNS,
                        description=f"WordPress author archive redirect exposes username: '{username}'",
                        evidence=f"Location: {location}",
                        recommendation="Disable author archives or install a user enumeration prevention plugin.",
                    ))
                    break

        return findings

    async def _wp_check_xmlrpc(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        xmlrpc_url = f"{base_url.rstrip('/')}/xmlrpc.php"

        resp = await self.client.get(xmlrpc_url, retries=1)
        if resp and resp.status_code == 200 and "XML-RPC" in resp.body:
            findings.append(Finding(
                url=xmlrpc_url,
                title="WordPress XML-RPC Enabled",
                severity=Severity.MEDIUM,
                module=ScanModule.VULNS,
                description="XML-RPC is enabled. This can be used for brute-force amplification attacks (system.multicall).",
                evidence="xmlrpc.php returned HTTP 200 with XML-RPC response",
                recommendation="Disable XML-RPC unless required: add 'add_filter(\"xmlrpc_enabled\", \"__return_false\");' to functions.php",
            ))

            multicall_payload = """<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName>
<params><param><value><array><data>
<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><array><data><value><string>admin</string></value><value><string>password</string></value></data></array></value>
</data></array></value></member></struct></value>
</data></array></value></param></params></methodCall>"""
            post_resp = await self.client.post(
                xmlrpc_url,
                data=multicall_payload,
                extra_headers={"Content-Type": "text/xml"},
                retries=1,
            )
            if post_resp and post_resp.status_code == 200 and "faultCode" not in post_resp.body:
                findings.append(Finding(
                    url=xmlrpc_url,
                    title="WordPress XML-RPC Multicall Enabled (Brute-Force Risk)",
                    severity=Severity.HIGH,
                    module=ScanModule.VULNS,
                    description="system.multicall is enabled, allowing thousands of login attempts in a single HTTP request.",
                    evidence="system.multicall responded without fault code",
                    recommendation="Disable XML-RPC entirely or use a firewall rule to block multicall.",
                ))

        return findings

    async def _wp_check_rest_api(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        api_url = f"{base}/wp-json/"
        resp = await self.client.get(api_url, retries=1)
        if resp and resp.status_code == 200:
            try:
                data = json.loads(resp.body)
                namespaces = data.get("namespaces", [])
                findings.append(Finding(
                    url=api_url,
                    title="WordPress REST API Exposed",
                    severity=Severity.INFO,
                    module=ScanModule.VULNS,
                    description=f"WordPress REST API is accessible. Namespaces: {', '.join(namespaces[:10])}",
                    evidence=f"API root accessible at {api_url}",
                    recommendation="Restrict REST API to authenticated users if not needed publicly.",
                ))
            except json.JSONDecodeError:
                pass

        return findings

    async def _wp_check_cron(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        cron_url = f"{base_url.rstrip('/')}/wp-cron.php"
        resp = await self.client.get(cron_url, retries=1)
        if resp and resp.status_code == 200:
            findings.append(Finding(
                url=cron_url,
                title="WordPress wp-cron.php Publicly Accessible",
                severity=Severity.LOW,
                module=ScanModule.VULNS,
                description="wp-cron.php is publicly accessible, which can be abused for DoS attacks by triggering resource-intensive cron jobs.",
                evidence="HTTP 200 response from wp-cron.php",
                recommendation="Disable default wp-cron and set up a real cron job. Add 'define(\"DISABLE_WP_CRON\", true);' to wp-config.php",
            ))
        return findings

    async def _wp_enumerate_plugins(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")
        found_plugins: list[str] = []

        semaphore = asyncio.Semaphore(min(self.config.threads, 30))

        async def check_plugin(plugin: str) -> Optional[str]:
            async with semaphore:
                url = f"{base}/wp-content/plugins/{plugin}/readme.txt"
                resp = await self.client.get(url, retries=1)
                if resp and resp.status_code == 200 and len(resp.body) > 50:
                    version = None
                    ver_match = re.search(r"Stable tag:\s*([0-9.]+)", resp.body, re.IGNORECASE)
                    if ver_match:
                        version = ver_match.group(1)
                    return f"{plugin} (v{version})" if version else plugin
                url2 = f"{base}/wp-content/plugins/{plugin}/"
                resp2 = await self.client.get(url2, retries=1)
                if resp2 and resp2.status_code in (200, 403):
                    return plugin
                return None

        results = await asyncio.gather(*[check_plugin(p) for p in WP_PLUGINS_COMMON], return_exceptions=True)
        found_plugins = [r for r in results if isinstance(r, str)]

        if found_plugins:
            findings.append(Finding(
                url=f"{base}/wp-content/plugins/",
                title=f"WordPress Plugins Detected ({len(found_plugins)})",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"Detected {len(found_plugins)} WordPress plugin(s).",
                evidence="Plugins: " + ", ".join(found_plugins[:20]),
                recommendation="Keep all plugins updated. Remove unused plugins. Check each for known vulnerabilities.",
            ))

        return findings

    async def _wp_enumerate_themes(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")
        found_themes: list[str] = []

        semaphore = asyncio.Semaphore(min(self.config.threads, 20))

        async def check_theme(theme: str) -> Optional[str]:
            async with semaphore:
                url = f"{base}/wp-content/themes/{theme}/style.css"
                resp = await self.client.get(url, retries=1)
                if resp and resp.status_code == 200 and "Theme Name" in resp.body:
                    ver_match = re.search(r"Version:\s*([0-9.]+)", resp.body)
                    version = ver_match.group(1) if ver_match else None
                    return f"{theme} (v{version})" if version else theme
                return None

        results = await asyncio.gather(*[check_theme(t) for t in WP_THEMES_COMMON], return_exceptions=True)
        found_themes = [r for r in results if isinstance(r, str)]

        if found_themes:
            findings.append(Finding(
                url=f"{base}/wp-content/themes/",
                title=f"WordPress Themes Detected ({len(found_themes)})",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"Detected {len(found_themes)} WordPress theme(s).",
                evidence="Themes: " + ", ".join(found_themes),
                recommendation="Keep themes updated. Remove inactive themes.",
            ))

        return findings

    async def _scan_joomla(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        version_sources = [
            (f"{base}/administrator/manifests/files/joomla.xml", r"<version>([0-9.]+)</version>"),
            (f"{base}/language/en-GB/en-GB.xml", r"<version>([0-9.]+)</version>"),
            (f"{base}/README.txt", r"Joomla!? ([0-9.]+)"),
        ]

        for url, pattern in version_sources:
            resp = await self.client.get(url, retries=1)
            if resp and resp.status_code == 200:
                match = re.search(pattern, resp.body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    findings.append(Finding(
                        url=url,
                        title=f"Joomla Version Detected: {version}",
                        severity=Severity.MEDIUM,
                        module=ScanModule.VULNS,
                        description=f"Joomla version {version} detected from {url}. Version disclosure aids attackers.",
                        evidence=f"Version: {version}",
                        recommendation="Restrict access to version-disclosing files.",
                    ))
                    break

        config_url = f"{base}/configuration.php.bak"
        resp = await self.client.get(config_url, retries=1)
        if resp and resp.status_code == 200 and "password" in resp.body.lower():
            findings.append(Finding(
                url=config_url,
                title="Joomla Configuration Backup Exposed",
                severity=Severity.CRITICAL,
                module=ScanModule.VULNS,
                description="Joomla configuration backup file is accessible and may contain database credentials.",
                evidence=resp.body[:300],
                recommendation="Delete configuration backup files from web root immediately.",
            ))

        admin_url = f"{base}/administrator/"
        resp = await self.client.get(admin_url, retries=1)
        if resp and resp.status_code == 200:
            findings.append(Finding(
                url=admin_url,
                title="Joomla Admin Panel Accessible",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description="Joomla administrator panel is accessible.",
                evidence=f"HTTP 200 at {admin_url}",
                recommendation="Restrict admin panel access by IP. Enable two-factor authentication.",
            ))

        semaphore = asyncio.Semaphore(20)
        found_components: list[str] = []

        async def check_component(comp: str) -> Optional[str]:
            async with semaphore:
                url = f"{base}/index.php?option={comp}"
                resp = await self.client.get(url, retries=1)
                if resp and resp.status_code == 200 and "404" not in resp.body.lower()[:500]:
                    return comp
                return None

        results = await asyncio.gather(*[check_component(c) for c in JOOMLA_COMPONENTS], return_exceptions=True)
        found_components = [r for r in results if isinstance(r, str)]

        if found_components:
            findings.append(Finding(
                url=base_url,
                title=f"Joomla Components Detected ({len(found_components)})",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"Detected Joomla components: {', '.join(found_components[:10])}",
                evidence=f"Components found: {', '.join(found_components)}",
                recommendation="Audit all installed components for known vulnerabilities.",
            ))

        return findings

    async def _scan_drupal(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        changelog_url = f"{base}/CHANGELOG.txt"
        resp = await self.client.get(changelog_url, retries=1)
        if resp and resp.status_code == 200:
            version_match = re.search(r"Drupal ([0-9.]+),", resp.body)
            if version_match:
                version = version_match.group(1)
                findings.append(Finding(
                    url=changelog_url,
                    title=f"Drupal Version Disclosed via CHANGELOG.txt: {version}",
                    severity=Severity.MEDIUM,
                    module=ScanModule.VULNS,
                    description=f"CHANGELOG.txt is accessible and discloses Drupal version {version}.",
                    evidence=f"Version: {version}",
                    recommendation="Delete or restrict access to CHANGELOG.txt, INSTALL.txt, and similar files.",
                ))

        for check_file in ["INSTALL.txt", "INSTALL.mysql.txt", "UPGRADE.txt", "install.php", "update.php"]:
            url = f"{base}/{check_file}"
            resp = await self.client.get(url, retries=1)
            if resp and resp.status_code == 200:
                findings.append(Finding(
                    url=url,
                    title=f"Drupal Sensitive File Accessible: {check_file}",
                    severity=Severity.MEDIUM,
                    module=ScanModule.VULNS,
                    description=f"Drupal file {check_file} is publicly accessible.",
                    evidence=f"HTTP 200 at {url}",
                    recommendation=f"Remove or restrict access to {check_file}.",
                ))

        for path in ["/sites/default/settings.php", "/sites/default/default.settings.php"]:
            url = f"{base}{path}"
            resp = await self.client.get(url, retries=1)
            if resp and resp.status_code == 200 and "database" in resp.body.lower():
                findings.append(Finding(
                    url=url,
                    title="Drupal Settings File Accessible",
                    severity=Severity.CRITICAL,
                    module=ScanModule.VULNS,
                    description=f"Drupal settings file is accessible and may expose database credentials.",
                    evidence=resp.body[:300],
                    recommendation="Ensure settings.php has proper file permissions (444) and is not readable via web.",
                ))

        nodes_url = f"{base}/node/1"
        resp = await self.client.get(nodes_url, retries=1)
        if resp and resp.status_code == 200:
            admin_match = re.search(r"Submitted by.*?<a[^>]*>([^<]+)</a>", resp.body, re.IGNORECASE)
            if admin_match:
                username = admin_match.group(1)
                findings.append(Finding(
                    url=nodes_url,
                    title=f"Drupal Username Disclosed: {username}",
                    severity=Severity.LOW,
                    module=ScanModule.VULNS,
                    description=f"Username '{username}' disclosed in node authorship.",
                    evidence=f"Found in: {nodes_url}",
                    recommendation="Hide author information or use display names that don't match login names.",
                ))

        semaphore = asyncio.Semaphore(15)
        found_modules: list[str] = []

        async def check_module(mod: str) -> Optional[str]:
            async with semaphore:
                url = f"{base}/modules/{mod}/{mod}.info"
                resp = await self.client.get(url, retries=1)
                if resp and resp.status_code == 200 and "name" in resp.body.lower():
                    return mod
                return None

        results = await asyncio.gather(*[check_module(m) for m in DRUPAL_MODULES[:20]], return_exceptions=True)
        found_modules = [r for r in results if isinstance(r, str)]
        if found_modules:
            findings.append(Finding(
                url=base_url,
                title=f"Drupal Modules Detected ({len(found_modules)})",
                severity=Severity.INFO,
                module=ScanModule.VULNS,
                description=f"Detected Drupal modules: {', '.join(found_modules)}",
                recommendation="Audit all installed modules for known vulnerabilities. Keep updated.",
            ))

        return findings

    async def _scan_generic_cms(self, base_url: str) -> list[Finding]:
        findings: list[Finding] = []
        base = base_url.rstrip("/")

        admin_paths = [
            "/admin", "/admin/", "/administrator/", "/wp-admin/",
            "/backend/", "/manage/", "/dashboard/", "/panel/",
            "/control/", "/portal/", "/cms/", "/siteadmin/",
            "/manager/", "/admin/login", "/admin/index.php",
            "/login", "/signin", "/auth/login",
        ]

        semaphore = asyncio.Semaphore(20)

        async def check_admin(path: str) -> Optional[Finding]:
            async with semaphore:
                url = f"{base}{path}"
                resp = await self.client.get(url, allow_redirects=True, retries=1)
                if resp and resp.status_code in (200, 401, 403):
                    sev = Severity.INFO if resp.status_code in (401, 403) else Severity.MEDIUM
                    return Finding(
                        url=url,
                        title=f"Admin Panel Found: {path}",
                        severity=sev,
                        module=ScanModule.VULNS,
                        description=f"Admin/login panel detected at {path} (HTTP {resp.status_code}).",
                        evidence=f"HTTP {resp.status_code}",
                        recommendation="Restrict admin panel access to trusted IPs. Enable MFA.",
                    )
                return None

        results = await asyncio.gather(*[check_admin(p) for p in admin_paths], return_exceptions=True)
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)

        return findings
