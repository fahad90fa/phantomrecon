from __future__ import annotations

import asyncio
import socket
import ssl
import datetime
from typing import Any, Optional
from urllib.parse import urlparse

from ..models import Finding, ScanConfig, ScanModule, Severity


class SSLScanner:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config

    async def scan(self, target_url: str) -> tuple[list[Finding], dict[str, Any]]:
        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return [], {"tls_available": False}

        host = parsed.hostname or ""
        port = parsed.port or 443

        findings: list[Finding] = []
        info: dict[str, Any] = {}

        cert_info = await asyncio.get_event_loop().run_in_executor(
            None, self._get_cert_info, host, port
        )
        info.update(cert_info)

        protocol_findings, protocol_info = await self._test_protocols(host, port)
        findings.extend(protocol_findings)
        info.update(protocol_info)

        findings.extend(self._analyze_cert(cert_info, target_url))
        findings.extend(self._check_weak_ciphers(info, target_url))

        info["tls_available"] = True
        return findings, info

    def _get_cert_info(self, host: str, port: int) -> dict[str, Any]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    not_after_str = cert.get("notAfter", "")
                    not_before_str = cert.get("notBefore", "")
                    not_after: Optional[datetime.datetime] = None
                    not_before: Optional[datetime.datetime] = None

                    try:
                        not_after = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        not_before = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                    except Exception:
                        pass

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    san_list: list[str] = []
                    for san_type, san_val in cert.get("subjectAltName", []):
                        san_list.append(f"{san_type}:{san_val}")

                    days_until_expiry = None
                    if not_after:
                        days_until_expiry = (not_after - datetime.datetime.utcnow()).days

                    return {
                        "subject_cn": subject.get("commonName", ""),
                        "issuer_cn": issuer.get("commonName", ""),
                        "issuer_org": issuer.get("organizationName", ""),
                        "not_before": not_before.isoformat() if not_before else "",
                        "not_after": not_after.isoformat() if not_after else "",
                        "days_until_expiry": days_until_expiry,
                        "san": san_list,
                        "cipher_suite": cipher[0] if cipher else "",
                        "cipher_bits": cipher[2] if cipher else 0,
                        "tls_version": version,
                        "serial_number": cert.get("serialNumber", ""),
                        "cert_error": None,
                    }
        except ssl.SSLCertVerificationError as e:
            return {"cert_error": str(e), "tls_version": "unknown"}
        except ssl.SSLError as e:
            return {"cert_error": str(e), "tls_version": "unknown"}
        except Exception as e:
            return {"cert_error": str(e), "tls_version": "unknown"}

    async def _test_protocols(self, host: str, port: int) -> tuple[list[Finding], dict[str, Any]]:
        findings: list[Finding] = []
        info: dict[str, Any] = {"supported_protocols": []}

        protocol_tests = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2 if hasattr(ssl.TLSVersion, "TLSv1_2") else None),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, "TLSv1_3") else None),
        ]

        for proto_name, proto_version in protocol_tests:
            if proto_version is None:
                continue
            supported = await asyncio.get_event_loop().run_in_executor(
                None, self._test_single_protocol, host, port, proto_version
            )
            if supported:
                info["supported_protocols"].append(proto_name)
                if proto_name in ("TLSv1.0", "TLSv1.1"):
                    findings.append(Finding(
                        url=f"https://{host}:{port}",
                        title=f"Deprecated TLS Protocol Supported: {proto_name}",
                        severity=Severity.HIGH,
                        module=ScanModule.SSL,
                        description=f"The server accepts connections using {proto_name}, which is deprecated and vulnerable.",
                        evidence=f"Protocol {proto_name} accepted on {host}:{port}",
                        recommendation=f"Disable {proto_name} and enforce TLS 1.2 minimum (TLS 1.3 preferred).",
                    ))

        return findings, info

    def _test_single_protocol(self, host: str, port: int, version: Any) -> bool:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    def _analyze_cert(self, cert_info: dict[str, Any], url: str) -> list[Finding]:
        findings: list[Finding] = []

        if cert_info.get("cert_error"):
            findings.append(Finding(
                url=url,
                title="SSL Certificate Error",
                severity=Severity.HIGH,
                module=ScanModule.SSL,
                description="SSL certificate validation failed.",
                evidence=str(cert_info["cert_error"]),
                recommendation="Ensure a valid, trusted certificate is installed.",
            ))
            return findings

        days = cert_info.get("days_until_expiry")
        if days is not None:
            if days < 0:
                findings.append(Finding(
                    url=url,
                    title="SSL Certificate Expired",
                    severity=Severity.CRITICAL,
                    module=ScanModule.SSL,
                    description=f"SSL certificate expired {abs(days)} days ago.",
                    evidence=f"Not After: {cert_info.get('not_after', '')}",
                    recommendation="Renew the SSL certificate immediately.",
                ))
            elif days < 14:
                findings.append(Finding(
                    url=url,
                    title="SSL Certificate Expiring Very Soon",
                    severity=Severity.HIGH,
                    module=ScanModule.SSL,
                    description=f"SSL certificate expires in {days} days.",
                    evidence=f"Not After: {cert_info.get('not_after', '')}",
                    recommendation="Renew the SSL certificate immediately.",
                ))
            elif days < 30:
                findings.append(Finding(
                    url=url,
                    title="SSL Certificate Expiring Soon",
                    severity=Severity.MEDIUM,
                    module=ScanModule.SSL,
                    description=f"SSL certificate expires in {days} days.",
                    evidence=f"Not After: {cert_info.get('not_after', '')}",
                    recommendation="Schedule SSL certificate renewal.",
                ))

        issuer_org = cert_info.get("issuer_org", "")
        issuer_cn = cert_info.get("issuer_cn", "")
        self_signed_indicators = ["self", "localhost", cert_info.get("subject_cn", "NOMATCH")]
        if any(ind.lower() in issuer_cn.lower() for ind in self_signed_indicators) and not issuer_org:
            findings.append(Finding(
                url=url,
                title="Self-Signed SSL Certificate",
                severity=Severity.HIGH,
                module=ScanModule.SSL,
                description="The SSL certificate appears to be self-signed, not issued by a trusted CA.",
                evidence=f"Issuer: {issuer_cn}",
                recommendation="Replace with a certificate from a trusted Certificate Authority.",
            ))

        cipher = cert_info.get("cipher_suite", "")
        bits = cert_info.get("cipher_bits", 0)
        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ADH", "AECDH", "MD5"]
        for weak in weak_ciphers:
            if weak in cipher.upper():
                findings.append(Finding(
                    url=url,
                    title=f"Weak Cipher Suite in Use: {cipher}",
                    severity=Severity.HIGH,
                    module=ScanModule.SSL,
                    description=f"Server is using a weak cipher suite ({cipher}) that is considered insecure.",
                    evidence=f"Cipher: {cipher}, Bits: {bits}",
                    recommendation="Configure the server to use only strong cipher suites (AES-GCM, CHACHA20).",
                ))
            break

        if bits and bits < 128:
            findings.append(Finding(
                url=url,
                title=f"Weak Cipher Key Length: {bits} bits",
                severity=Severity.HIGH,
                module=ScanModule.SSL,
                description=f"Cipher suite uses only {bits} bit key length.",
                recommendation="Use cipher suites with at least 128-bit (256-bit preferred) key length.",
            ))

        return findings

    def _check_weak_ciphers(self, info: dict[str, Any], url: str) -> list[Finding]:
        findings: list[Finding] = []
        cipher = info.get("cipher_suite", "")

        forward_secrecy_ciphers = ["ECDHE", "DHE"]
        if cipher and not any(fs in cipher for fs in forward_secrecy_ciphers):
            findings.append(Finding(
                url=url,
                title="No Forward Secrecy Support Detected",
                severity=Severity.MEDIUM,
                module=ScanModule.SSL,
                description="The negotiated cipher suite does not provide forward secrecy.",
                evidence=f"Cipher: {cipher}",
                recommendation="Configure server to prefer ECDHE or DHE cipher suites for forward secrecy.",
            ))

        return findings
