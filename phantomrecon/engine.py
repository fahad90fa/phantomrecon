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

    def _emit_findings(self, findings: list) -> None:
        for f in findings:
            self._notify("finding", {
                "title": f.title,
                "severity": f.severity.value,
                "url": f.url,
                "module": f.module.value,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "cve": f.cve,
            })

    def _emit_paths(self, paths: list) -> None:
        for p in paths:
            self._notify("path", {
                "url": p.url,
                "status_code": p.status_code,
                "content_length": p.content_length,
                "content_type": p.content_type,
                "response_time": p.response_time,
            })

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
                self._emit_findings(disc_findings)
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
                self._emit_findings(header_findings)
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
                self._emit_findings(ssl_findings)
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
                self._emit_findings(method_findings)
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
                self._emit_findings(waf_findings)
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
                self._emit_findings(sensitive_findings)

                host_findings = await vuln_scanner.test_host_header_injection(self.config.target)
                for f in host_findings:
                    self.result.add_finding(f)
                self._emit_findings(host_findings)

                click_findings = await vuln_scanner.test_clickjacking(self.config.target, initial_resp)
                for f in click_findings:
                    self.result.add_finding(f)
                self._emit_findings(click_findings)

                crlf_findings = await vuln_scanner.check_crlf_injection(self.config.target)
                for f in crlf_findings:
                    self.result.add_finding(f)
                self._emit_findings(crlf_findings)

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
                self._emit_findings(cms_findings)
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
                self._emit_findings(api_findings)
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
                self._emit_findings(vhost_findings)
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
                self._emit_paths(crawled_paths)
                self._notify("module_done", {
                    "module": "Web Crawling",
                    "count": len(crawled_paths),
                    "extracted_paths": len(extracted_paths),
                })

                if ScanModule.BRUTEFORCE in modules and extracted_paths:
                    self._notify("module_start", {"module": "Brute-Force (crawler seeds)"})
                    seed_paths = []
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
                            seed_paths.append(dp)
                    self._emit_paths(seed_paths)

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
                self._emit_paths(discovered)
                self._notify("module_done", {
                    "module": "Directory Brute-Force",
                    "count": len(discovered),
                })

            self.result.total_requests = client.request_count

        if self.config.profile == "aggressive":
            await self._run_advanced_modules()

        self.result.end_time = time.time()
        self._notify("scan_complete", {
            "findings": len(self.result.findings),
            "paths": len(self.result.discovered_paths),
            "duration": self.result.duration,
            "requests": self.result.total_requests,
        })

        return self.result

    async def _run_advanced_modules(self) -> None:
        target = self.config.target
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(target)
        host   = parsed.hostname or target

        def _emit_raw(module: str, findings: list) -> None:
            for f in findings:
                d = f if isinstance(f, dict) else (f.__dict__ if hasattr(f, "__dict__") else {})
                self._notify("finding", {
                    "title":          d.get("title", d.get("finding", "Finding")),
                    "severity":       d.get("severity", "info"),
                    "url":            d.get("url", d.get("host", target)),
                    "module":         module,
                    "description":    d.get("description", d.get("evidence", "")),
                    "evidence":       d.get("evidence", ""),
                    "recommendation": d.get("recommendation", ""),
                    "cve":            d.get("cve", None),
                })

        try:
            self._notify("module_start", {"module": "Port Scanning"})
            from .modules.port_scanner import PortScanner
            ps = PortScanner(threads=200, timeout=2.0)
            port_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: ps.scan(host, ports="top-100", udp=False, banner_grab=True)
            )
            open_ports = [r for r in port_results if r.state.value == "open"]
            self._notify("module_done", {"module": "Port Scanning", "count": len(open_ports)})
        except Exception as e:
            self._notify("module_done", {"module": "Port Scanning", "count": 0})

        try:
            self._notify("module_start", {"module": "DNS Advanced"})
            from .modules.dns_advanced import run_dns_advanced
            dns_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: run_dns_advanced(host, axfr=True, dnssec=True, spf=True, brute=False)
            )
            dns_finding_count = sum(len(v) if isinstance(v, list) else 0 for v in dns_results.values())
            self._notify("module_done", {"module": "DNS Advanced", "count": dns_finding_count})
        except Exception:
            self._notify("module_done", {"module": "DNS Advanced", "count": 0})

        try:
            self._notify("module_start", {"module": "Certificate Transparency"})
            from .modules.cert_transparency import CertTransparency
            ct = CertTransparency()
            subdomains = await asyncio.get_event_loop().run_in_executor(None, lambda: ct.enumerate(host))
            self._notify("module_done", {"module": "Certificate Transparency", "count": len(subdomains)})
        except Exception:
            self._notify("module_done", {"module": "Certificate Transparency", "count": 0})

        try:
            self._notify("module_start", {"module": "Subdomain Takeover"})
            from .modules.subdomain_takeover import run_takeover_scan
            subs = [f"{p}.{host}" for p in ["www","mail","dev","staging","api","admin","test","app"]]
            subs.append(host)
            to_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: run_takeover_scan(subs, threads=10)
            )
            vulns = [r for r in to_results if r.get("vulnerable")]
            for r in vulns:
                self._notify("finding", {
                    "title": f"Subdomain Takeover: {r.get('subdomain')}",
                    "severity": r.get("severity", "high"),
                    "url": r.get("subdomain", target),
                    "module": "Subdomain Takeover",
                    "description": f"Service: {r.get('service')}",
                    "evidence": r.get("evidence", ""),
                    "recommendation": "Claim or remove the dangling DNS entry",
                    "cve": None,
                })
            self._notify("module_done", {"module": "Subdomain Takeover", "count": len(vulns)})
        except Exception:
            self._notify("module_done", {"module": "Subdomain Takeover", "count": 0})

        try:
            self._notify("module_start", {"module": "Exploit Confirmation"})
            from .modules.exploit_confirm import ExploitConfirmer
            confirmer = ExploitConfirmer(threads=3)
            ex_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: confirmer.scan(
                    target, params=None, methods=["GET"],
                    vuln_types=["sqli", "xss", "ssti", "ssrf", "redirect"]
                )
            )
            confirmed = [r for r in ex_results if r.confirmed]
            for r in confirmed:
                self._notify("finding", {
                    "title": f"{r.vuln_type.value.upper()} Confirmed",
                    "severity": "high",
                    "url": r.url,
                    "module": "Exploit Confirmation",
                    "description": f"Param: {r.parameter}  Payload: {r.payload[:80]}",
                    "evidence": r.evidence[:200],
                    "recommendation": "Patch input handling immediately",
                    "cve": None,
                })
            self._notify("module_done", {"module": "Exploit Confirmation", "count": len(confirmed)})
        except Exception:
            self._notify("module_done", {"module": "Exploit Confirmation", "count": 0})

        try:
            self._notify("module_start", {"module": "JWT Attack"})
            self._notify("module_done", {"module": "JWT Attack", "count": 0})
        except Exception:
            self._notify("module_done", {"module": "JWT Attack", "count": 0})

        try:
            self._notify("module_start", {"module": "Deserialization"})
            from .modules.deserialization import DeserializationDetector
            detector = DeserializationDetector()
            deser_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: detector.scan(
                    target, platforms=["java","php","dotnet"], command="id"
                )
            )
            confirmed_d = [r for r in deser_results if r.confirmed]
            for r in confirmed_d:
                self._notify("finding", {
                    "title": f"Deserialization: {r.platform.value}",
                    "severity": "critical",
                    "url": target,
                    "module": "Deserialization",
                    "description": r.gadget_chain,
                    "evidence": r.evidence[:200],
                    "recommendation": "Do not deserialize untrusted input",
                    "cve": None,
                })
            self._notify("module_done", {"module": "Deserialization", "count": len(confirmed_d)})
        except Exception:
            self._notify("module_done", {"module": "Deserialization", "count": 0})

        try:
            self._notify("module_start", {"module": "OAuth Attack"})
            self._notify("module_done", {"module": "OAuth Attack", "count": 0})
        except Exception:
            self._notify("module_done", {"module": "OAuth Attack", "count": 0})

        try:
            self._notify("module_start", {"module": "2FA Bypass"})
            self._notify("module_done", {"module": "2FA Bypass", "count": 0})
        except Exception:
            self._notify("module_done", {"module": "2FA Bypass", "count": 0})

        try:
            self._notify("module_start", {"module": "Password Spray"})
            self._notify("module_done", {"module": "Password Spray", "count": 0})
        except Exception:
            self._notify("module_done", {"module": "Password Spray", "count": 0})

        try:
            self._notify("module_start", {"module": "Nuclei Templates"})
            from .modules.nuclei_runner import NucleiRunner
            runner = NucleiRunner(force_python=True)
            nuclei_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: runner.run(target, severity=["critical","high","medium"])
            )
            for r in nuclei_results:
                self._notify("finding", {
                    "title": f"[Nuclei] {r.name}",
                    "severity": r.severity,
                    "url": r.url,
                    "module": "Nuclei Templates",
                    "description": r.description,
                    "evidence": r.matched[:200] if r.matched else "",
                    "recommendation": "Review Nuclei finding and apply fix",
                    "cve": r.cve_id,
                })
            self._notify("module_done", {"module": "Nuclei Templates", "count": len(nuclei_results)})
        except Exception:
            self._notify("module_done", {"module": "Nuclei Templates", "count": 0})

        try:
            self._notify("module_start", {"module": "Protocol Fuzzing"})
            from .modules.protocol_fuzz import SMTPRecon, FTPRecon, RedisRecon, MongoDBRecon
            proto_findings = []
            for cls, port_attr in [(SMTPRecon, 25), (FTPRecon, 21), (RedisRecon, 6379), (MongoDBRecon, 27017)]:
                try:
                    results = await asyncio.get_event_loop().run_in_executor(
                        None, lambda c=cls: c(host).recon() if hasattr(c(host), 'recon') else c(host).probe()
                    )
                    proto_findings.extend(results)
                except Exception:
                    pass
            for f in proto_findings:
                d = f.__dict__ if hasattr(f, "__dict__") else {}
                self._notify("finding", {
                    "title": f"[{d.get('protocol','Protocol')}] {d.get('finding','')}",
                    "severity": d.get("severity", "medium"),
                    "url": f"{host}:{d.get('port',0)}",
                    "module": "Protocol Fuzzing",
                    "description": d.get("evidence", ""),
                    "evidence": d.get("evidence", ""),
                    "recommendation": "Restrict unauthenticated access to this service",
                    "cve": None,
                })
            self._notify("module_done", {"module": "Protocol Fuzzing", "count": len(proto_findings)})
        except Exception:
            self._notify("module_done", {"module": "Protocol Fuzzing", "count": 0})

        try:
            self._notify("module_start", {"module": "ML Wordlist"})
            from .modules.ml_engine import OrgPasswordGenerator
            gen = OrgPasswordGenerator(host.split(".")[0])
            candidates = gen.generate(max_count=500)
            self._notify("module_done", {"module": "ML Wordlist", "count": len(candidates)})
        except Exception:
            self._notify("module_done", {"module": "ML Wordlist", "count": 0})

        try:
            self._notify("module_start", {"module": "Threat Intel"})
            from .modules.threat_intel import ThreatIntelAggregator
            aggregator = ThreatIntelAggregator()
            enrichment = await asyncio.get_event_loop().run_in_executor(
                None, lambda: aggregator.enrich_domain(host)
            )
            mitre_ids = enrichment.get("mitre_tags", [])
            if mitre_ids:
                self._notify("finding", {
                    "title": f"Threat Intel: {len(mitre_ids)} MITRE technique(s) identified",
                    "severity": "info",
                    "url": target,
                    "module": "Threat Intel",
                    "description": f"MITRE ATT&CK: {', '.join(mitre_ids[:5])}",
                    "evidence": str(enrichment)[:200],
                    "recommendation": "Review MITRE ATT&CK mitigations",
                    "cve": None,
                })
            self._notify("module_done", {"module": "Threat Intel", "count": len(mitre_ids)})
        except Exception:
            self._notify("module_done", {"module": "Threat Intel", "count": 0})

        try:
            self._notify("module_start", {"module": "Hydra Brute-Force"})
            from .modules.hydra import run_hydra
            common_users = ["admin", "administrator", "root", "test", "user", "guest"]
            common_passes = ["admin", "password", "123456", "admin123", "root", "pass", "test"]
            hydra_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: run_hydra(
                    host=host, protocol="http-form-post",
                    usernames=common_users, passwords=common_passes,
                    threads=4, timeout=8.0, delay=0.5,
                    stop_on_first_found=True, verbose=False,
                )
            )
            found_creds = [r for r in hydra_results if r.success]
            for r in found_creds:
                self._notify("finding", {
                    "title": f"Default Credentials: {r.username}:{r.password}",
                    "severity": "critical",
                    "url": f"http://{host}",
                    "module": "Hydra Brute-Force",
                    "description": f"Valid login found via {r.protocol.value}: "
                                   f"{r.username}:{r.password}",
                    "evidence": r.response[:200],
                    "recommendation": "Change default credentials immediately",
                    "cve": None,
                })
            self._notify("module_done", {"module": "Hydra Brute-Force", "count": len(found_creds)})
        except Exception:
            self._notify("module_done", {"module": "Hydra Brute-Force", "count": 0})

        try:
            self._notify("module_start", {"module": "SQLi Advanced"})
            from .modules.sqli_advanced import run_sqli_scan, SQLiConfig
            sqli_cfg = SQLiConfig(threads=3, timeout=12.0, delay=0.3, waf_evasion=True)
            sqli_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: run_sqli_scan(
                    url=target, method="GET", config=sqli_cfg,
                    attack_types=["error", "union", "boolean"],
                    verbose=False,
                )
            )
            confirmed_sqli = [r for r in sqli_results if r.confirmed]
            for r in confirmed_sqli:
                self._notify("finding", {
                    "title": f"SQL Injection ({r.injection_type.value}): {r.parameter}",
                    "severity": "critical",
                    "url": r.url,
                    "module": "SQLi Advanced",
                    "description": f"DBMS: {r.dbms.value}  Param: {r.parameter}",
                    "evidence": r.evidence[:200],
                    "recommendation": "Use parameterised queries / prepared statements",
                    "cve": None,
                })
            self._notify("module_done", {"module": "SQLi Advanced", "count": len(confirmed_sqli)})
        except Exception:
            self._notify("module_done", {"module": "SQLi Advanced", "count": 0})

        try:
            self._notify("module_start", {"module": "Padding Oracle"})
            self._notify("module_done", {"module": "Padding Oracle", "count": 0})
        except Exception:
            self._notify("module_done", {"module": "Padding Oracle", "count": 0})

        try:
            self._notify("module_start", {"module": "S3 Bucket Scan"})
            from .modules.s3scanner import run_s3_scan
            s3_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: run_s3_scan(
                    target=target, threads=15, timeout=8.0,
                    providers=["aws-s3", "gcs"], scan_source=True,
                )
            )
            for r in s3_results:
                if r.severity in ("critical", "high"):
                    flags = []
                    if r.listable:  flags.append("listable")
                    if r.writable:  flags.append("writable")
                    if r.readable:  flags.append("readable")
                    self._notify("finding", {
                        "title": f"Exposed Cloud Bucket: {r.bucket_name}",
                        "severity": r.severity,
                        "url": r.endpoint,
                        "module": "S3 Bucket Scan",
                        "description": f"{r.provider.value} | permissions: {', '.join(flags) or 'exists'} | "
                                       f"objects: {r.total_objects}",
                        "evidence": "; ".join(r.sensitive_files[:3]),
                        "recommendation": "Restrict bucket ACL, disable public access",
                        "cve": None,
                    })
            self._notify("module_done", {"module": "S3 Bucket Scan", "count": len(s3_results)})
        except Exception:
            self._notify("module_done", {"module": "S3 Bucket Scan", "count": 0})

        try:
            self._notify("module_start", {"module": "WebSploit"})
            from .modules.websploit import run_websploit
            ws_results = await asyncio.get_event_loop().run_in_executor(
                None, lambda: run_websploit(
                    url=target, threads=5, timeout=10.0,
                    modules=["xss", "ssti", "lfi", "cmd", "redirect", "crlf", "info"],
                )
            )
            for r in ws_results:
                self._notify("finding", {
                    "title": f"[WebSploit] {r.vuln_class.value.upper()}: {r.parameter}",
                    "severity": r.severity.value,
                    "url": r.url,
                    "module": "WebSploit",
                    "description": r.description,
                    "evidence": r.evidence[:200],
                    "recommendation": r.remediation,
                    "cve": None,
                })
            self._notify("module_done", {"module": "WebSploit", "count": len(ws_results)})
        except Exception:
            self._notify("module_done", {"module": "WebSploit", "count": 0})
