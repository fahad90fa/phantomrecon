from __future__ import annotations

import asyncio
import time
from typing import Callable, Optional
from urllib.parse import urlparse

from .http_client import HttpClient
from .models import ScanConfig, ScanModule, ScanResult
from .modules.api_scanner import APIScanner
from .modules.bruteforce import BruteForcer
from .modules.cms_scanner import CMSScanner
from .modules.crawler import Crawler
from .modules.fingerprint import Fingerprinter
from .modules.headers import HeaderAnalyzer
from .modules.http_methods import HttpMethodTester
from .modules.ssl_scanner import SSLScanner
from .modules.vhost_scanner import VHostScanner
from .modules.vuln_scanner import VulnScanner
from .modules.waf_bypass import WAFBypass


class ScanEngine:
    def __init__(self, config: ScanConfig, ui_callback: Optional[Callable] = None) -> None:
        self.config = config
        self.ui_callback = ui_callback
        self.result = ScanResult(target=config.target)

    def _notify(self, event: str, data: dict) -> None:
        if self.ui_callback:
            self.ui_callback(event, data)

    async def run(self) -> ScanResult:
        self._notify("scan_start", {"target": self.config.target})

        modules = self.config.modules or list(ScanModule)

        async with HttpClient(self.config) as client:
            initial_resp = await client.get(self.config.target)

            if not initial_resp or initial_resp.status_code == 0:
                self.result.errors.append(f"Failed to connect to target: {initial_resp.error if initial_resp else 'unknown'}")
                self._notify("error", {"msg": "Cannot reach target"})
                self.result.end_time = time.time()
                return self.result

            self._notify("initial_response", {
                "status": initial_resp.status_code,
                "server": initial_resp.headers.get("Server", "unknown"),
                "content_type": initial_resp.content_type,
            })

            fingerprinter = Fingerprinter(self.config)

            if ScanModule.FINGERPRINT in modules:
                self._notify("module_start", {"module": "Technology Fingerprinting"})
                technologies = fingerprinter.fingerprint(initial_resp)
                for tech, evidence in technologies.items():
                    version = fingerprinter.detect_version(initial_resp, tech)
                    self.result.technologies[tech] = {
                        "evidence": evidence,
                        "version": version,
                    }
                self._notify("module_done", {
                    "module": "Technology Fingerprinting",
                    "count": len(self.result.technologies),
                })

            if ScanModule.DISCLOSURE in modules:
                self._notify("module_start", {"module": "Information Disclosure"})
                disc_findings = fingerprinter.find_disclosure(initial_resp)
                for f in disc_findings:
                    self.result.add_finding(f)
                self._notify("module_done", {
                    "module": "Information Disclosure",
                    "count": len(disc_findings),
                })

            if ScanModule.HEADERS in modules:
                self._notify("module_start", {"module": "Security Headers"})
                header_analyzer = HeaderAnalyzer(self.config)
                header_findings = header_analyzer.analyze(initial_resp)
                for f in header_findings:
                    self.result.add_finding(f)
                self.result.headers_analysis = header_analyzer.get_analysis_summary(initial_resp)
                self._notify("module_done", {
                    "module": "Security Headers",
                    "count": len(header_findings),
                })

            if ScanModule.SSL in modules:
                self._notify("module_start", {"module": "SSL/TLS Analysis"})
                ssl_scanner = SSLScanner(self.config)
                ssl_findings, ssl_info = await ssl_scanner.scan(self.config.target)
                for f in ssl_findings:
                    self.result.add_finding(f)
                self.result.ssl_info = ssl_info
                self._notify("module_done", {
                    "module": "SSL/TLS Analysis",
                    "count": len(ssl_findings),
                })

            if ScanModule.METHODS in modules:
                self._notify("module_start", {"module": "HTTP Methods"})
                method_tester = HttpMethodTester(self.config, client)
                method_findings = await method_tester.test(self.config.target)
                for f in method_findings:
                    self.result.add_finding(f)
                self._notify("module_done", {
                    "module": "HTTP Methods",
                    "count": len(method_findings),
                })

            if ScanModule.WAF in modules:
                self._notify("module_start", {"module": "WAF Detection & Bypass"})
                waf_bypass = WAFBypass(self.config, client)
                waf_findings = await waf_bypass.scan_with_bypass(self.config.target)
                for f in waf_findings:
                    self.result.add_finding(f)
                detected_waf = waf_bypass.detected_waf
                if detected_waf:
                    self.result.technologies["WAF: " + detected_waf] = {"evidence": "WAF fingerprinting", "version": None}
                self._notify("module_done", {
                    "module": "WAF Detection & Bypass",
                    "count": len(waf_findings),
                })

            if ScanModule.VULNS in modules:
                self._notify("module_start", {"module": "Vulnerability Scanning"})
                vuln_scanner = VulnScanner(self.config, client)

                waf = vuln_scanner.detect_waf(initial_resp)
                if waf:
                    self._notify("waf_detected", {"waf": waf})

                sensitive_findings = await vuln_scanner.scan_sensitive_paths(self.config.target)
                for f in sensitive_findings:
                    self.result.add_finding(f)

                host_findings = await vuln_scanner.test_host_header_injection(self.config.target)
                for f in host_findings:
                    self.result.add_finding(f)

                click_findings = await vuln_scanner.test_clickjacking(self.config.target, initial_resp)
                for f in click_findings:
                    self.result.add_finding(f)

                crlf_findings = await vuln_scanner.check_crlf_injection(self.config.target)
                for f in crlf_findings:
                    self.result.add_finding(f)

                self._notify("module_done", {
                    "module": "Vulnerability Scanning",
                    "count": len(sensitive_findings) + len(host_findings) + len(click_findings),
                })

            if ScanModule.CMS in modules:
                self._notify("module_start", {"module": "CMS Scanning"})
                cms_scanner = CMSScanner(self.config, client)
                cms_findings = await cms_scanner.scan(self.config.target, self.result.technologies)
                for f in cms_findings:
                    self.result.add_finding(f)
                self._notify("module_done", {
                    "module": "CMS Scanning",
                    "count": len(cms_findings),
                })

            if ScanModule.API in modules:
                self._notify("module_start", {"module": "API Scanning"})
                api_scanner = APIScanner(self.config, client)
                api_findings = await api_scanner.scan(self.config.target)
                for f in api_findings:
                    self.result.add_finding(f)
                self._notify("module_done", {
                    "module": "API Scanning",
                    "count": len(api_findings),
                })

            if ScanModule.VHOST in modules:
                self._notify("module_start", {"module": "Virtual Host Scanning"})
                vhost_scanner = VHostScanner(self.config, client)
                vhost_findings = await vhost_scanner.scan(self.config.target)
                for f in vhost_findings:
                    self.result.add_finding(f)
                self._notify("module_done", {
                    "module": "Virtual Host Scanning",
                    "count": len(vhost_findings),
                })

            if ScanModule.CRAWLER in modules:
                self._notify("module_start", {"module": "Web Crawling"})
                crawler = Crawler(self.config, client, self.config.target)
                crawled_paths, extracted_paths = await crawler.crawl(max_pages=500)
                for path in crawled_paths:
                    self.result.add_path(path)
                self._notify("module_done", {
                    "module": "Web Crawling",
                    "count": len(crawled_paths),
                    "extracted_paths": len(extracted_paths),
                })

                if ScanModule.BRUTEFORCE in modules and extracted_paths:
                    self._notify("module_start", {"module": "Brute-Force (crawler seeds)"})
                    for path in list(extracted_paths)[:1000]:
                        from .models import DiscoveredPath
                        resp = await client.get(
                            self.config.target.rstrip("/") + "/" + path.lstrip("/"),
                            allow_redirects=False,
                        )
                        if resp and resp.status_code not in (0, 404, 410):
                            dp = DiscoveredPath(
                                url=self.config.target.rstrip("/") + "/" + path.lstrip("/"),
                                status_code=resp.status_code,
                                content_length=resp.content_length,
                                content_type=resp.content_type,
                                response_time=resp.response_time,
                            )
                            self.result.add_path(dp)

            if ScanModule.BRUTEFORCE in modules:
                self._notify("module_start", {"module": "Directory Brute-Force"})
                done_count = [0]
                total_words = [0]

                def progress_cb(done: int, total: int, url: str, status: int) -> None:
                    done_count[0] = done
                    total_words[0] = total
                    self._notify("bruteforce_progress", {
                        "done": done, "total": total, "url": url, "status": status
                    })

                brute = BruteForcer(self.config, client, progress_callback=progress_cb)
                wordlist_paths = [self.config.wordlist] if self.config.wordlist else None
                discovered = await brute.run(self.config.target, wordlist_paths)
                for path in discovered:
                    self.result.add_path(path)
                self._notify("module_done", {
                    "module": "Directory Brute-Force",
                    "count": len(discovered),
                })

            self.result.total_requests = client.request_count

        self.result.end_time = time.time()
        self._notify("scan_complete", {
            "findings": len(self.result.findings),
            "paths": len(self.result.discovered_paths),
            "duration": self.result.duration,
            "requests": self.result.total_requests,
        })

        return self.result
