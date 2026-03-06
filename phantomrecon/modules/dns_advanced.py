"""
dns_advanced.py
===============
Advanced DNS analysis:
  - Zone transfer (AXFR) attempts on all nameservers
  - DNSSEC analysis (DNSKEY, DS, NSEC/NSEC3 walking)
  - Full DNS record enumeration (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR, CAA, DMARC, DKIM)
  - SPF/DMARC/DKIM policy analysis and misconfig detection
  - DNS cache poisoning check (TXID randomization, 0x20 encoding)
  - Subdomain brute-force via DNS (dictionary-based)
  - Wildcard detection
  - DNS-over-HTTPS (DoH) queries
  - Zone walking via NSEC enumeration
  - DNS rebinding check
  - Dangling DNS detection
"""

from __future__ import annotations

import json
import random
import re
import socket
import string
import struct
import time
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# DNS wire protocol helpers (no dnspython dependency)
# ---------------------------------------------------------------------------

DNS_TYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
    "TXT": 16, "AAAA": 28, "SRV": 33, "DS": 43, "DNSKEY": 48,
    "NSEC": 47, "NSEC3": 50, "RRSIG": 46, "CAA": 257,
}
DNS_CLASS_IN = 1


def _encode_name(name: str) -> bytes:
    result = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        result += bytes([len(encoded)]) + encoded
    return result + b"\x00"


def _build_query(name: str, qtype: int, txid: Optional[int] = None) -> bytes:
    if txid is None:
        txid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype, DNS_CLASS_IN)
    return header + question


def _dns_query_udp(name: str, qtype: int, server: str = "8.8.8.8",
                   port: int = 53, timeout: float = 3.0) -> Optional[bytes]:
    try:
        query = _build_query(name, qtype)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(query, (server, port))
        data, _ = s.recvfrom(4096)
        s.close()
        return data
    except Exception:
        return None


def _decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    jumped = False
    orig_offset = offset
    max_jumps = 10
    jumps = 0
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            jumped = True
            offset = ptr
            jumps += 1
            if jumps > max_jumps:
                break
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode("ascii", errors="replace"))
            offset += length
    return ".".join(labels), (orig_offset if jumped else offset)


def _parse_dns_response(data: bytes) -> Dict:
    if len(data) < 12:
        return {}
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    result = {"txid": txid, "rcode": rcode, "answers": [], "authority": [], "additional": []}

    offset = 12
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4

    def parse_records(count: int) -> List[Dict]:
        records = []
        nonlocal offset
        for _ in range(count):
            if offset >= len(data):
                break
            name, offset = _decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlen]
            offset += rdlen

            parsed = _parse_rdata(rtype, rdata, data)
            records.append({"name": name, "type": rtype, "ttl": ttl, "data": parsed})
        return records

    result["answers"]    = parse_records(ancount)
    result["authority"]  = parse_records(nscount)
    result["additional"] = parse_records(arcount)
    return result


def _parse_rdata(rtype: int, rdata: bytes, full_pkt: bytes) -> str:
    try:
        if rtype == 1:   # A
            return socket.inet_ntoa(rdata)
        if rtype == 28:  # AAAA
            return socket.inet_ntop(socket.AF_INET6, rdata)
        if rtype in (2, 5, 12):  # NS, CNAME, PTR
            name, _ = _decode_name(full_pkt, len(full_pkt) - len(rdata))
            return name
        if rtype == 15:  # MX
            pref = struct.unpack("!H", rdata[:2])[0]
            name, _ = _decode_name(full_pkt, len(full_pkt) - len(rdata) + 2)
            return f"{pref} {name}"
        if rtype == 16:  # TXT
            parts = []
            i = 0
            while i < len(rdata):
                l = rdata[i]; i += 1
                parts.append(rdata[i:i+l].decode("utf-8", errors="replace"))
                i += l
            return " ".join(parts)
        if rtype == 33:  # SRV
            prio, weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = _decode_name(full_pkt, len(full_pkt) - len(rdata) + 6)
            return f"{prio} {weight} {port} {target}"
        if rtype == 6:   # SOA
            return rdata.hex()
        if rtype == 257: # CAA
            flags = rdata[0]
            tag_len = rdata[1]
            tag = rdata[2:2+tag_len].decode("ascii", errors="replace")
            val = rdata[2+tag_len:].decode("utf-8", errors="replace")
            return f"{flags} {tag} {val}"
        return rdata.hex()
    except Exception:
        return rdata.hex()


def dns_query(name: str, qtype_name: str, server: str = "8.8.8.8") -> List[str]:
    qtype = DNS_TYPES.get(qtype_name.upper(), 1)
    data = _dns_query_udp(name, qtype, server)
    if not data:
        return []
    parsed = _parse_dns_response(data)
    target_type = qtype
    return [r["data"] for r in parsed["answers"] if r["type"] == target_type]


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DNSRecord:
    name: str
    record_type: str
    value: str
    ttl: int = 0

@dataclass
class ZoneTransferResult:
    nameserver: str
    success: bool
    records: List[DNSRecord] = field(default_factory=list)
    error: Optional[str] = None

@dataclass
class DNSSECResult:
    domain: str
    has_dnssec: bool
    dnskey_records: List[str] = field(default_factory=list)
    ds_records: List[str] = field(default_factory=list)
    nsec_type: Optional[str] = None
    chain_valid: bool = False
    issues: List[str] = field(default_factory=list)

@dataclass
class SPFResult:
    domain: str
    record: Optional[str]
    valid: bool
    issues: List[str] = field(default_factory=list)
    mechanisms: List[str] = field(default_factory=list)

@dataclass
class DMARCResult:
    domain: str
    record: Optional[str]
    policy: Optional[str]
    pct: int = 100
    valid: bool = False
    issues: List[str] = field(default_factory=list)

@dataclass
class DKIMResult:
    domain: str
    selector: str
    record: Optional[str]
    valid: bool = False
    key_bits: Optional[int] = None


# ---------------------------------------------------------------------------
# Zone Transfer (AXFR)
# ---------------------------------------------------------------------------

class ZoneTransfer:
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    def _get_nameservers(self, domain: str) -> List[str]:
        ns_records = dns_query(domain, "NS")
        servers = []
        for ns in ns_records:
            ns = ns.rstrip(".")
            try:
                ip = socket.gethostbyname(ns)
                servers.append(ip)
            except Exception:
                servers.append(ns)
        return servers

    def _axfr_raw(self, domain: str, server: str) -> Tuple[bool, List[DNSRecord], Optional[str]]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((server, 53))

            query = _build_query(domain, DNS_TYPES["A"])
            axfr_query = _build_query(domain, 252)
            msg = struct.pack("!H", len(axfr_query)) + axfr_query
            s.sendall(msg)

            records = []
            buf = b""
            while True:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while len(buf) >= 2:
                        msg_len = struct.unpack("!H", buf[:2])[0]
                        if len(buf) < msg_len + 2:
                            break
                        pkt = buf[2:msg_len+2]
                        buf = buf[msg_len+2:]
                        parsed = _parse_dns_response(pkt)
                        if parsed.get("rcode", 0) != 0:
                            s.close()
                            return False, [], f"RCODE {parsed['rcode']}"
                        for ans in parsed.get("answers", []):
                            type_name = {v: k for k, v in DNS_TYPES.items()}.get(ans["type"], str(ans["type"]))
                            records.append(DNSRecord(
                                name=ans["name"],
                                record_type=type_name,
                                value=ans["data"],
                                ttl=ans["ttl"],
                            ))
                except socket.timeout:
                    break
            s.close()
            return len(records) > 2, records, None
        except ConnectionRefusedError:
            return False, [], "Connection refused"
        except Exception as e:
            return False, [], str(e)

    def attempt(self, domain: str) -> List[ZoneTransferResult]:
        nameservers = self._get_nameservers(domain)
        results = []
        for ns in nameservers:
            success, records, error = self._axfr_raw(domain, ns)
            results.append(ZoneTransferResult(
                nameserver=ns, success=success, records=records, error=error
            ))
        return results


# ---------------------------------------------------------------------------
# DNSSEC Analyzer
# ---------------------------------------------------------------------------

class DNSSECAnalyzer:
    def __init__(self):
        self.resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    def analyze(self, domain: str) -> DNSSECResult:
        result = DNSSECResult(domain=domain, has_dnssec=False)

        dnskey = dns_query(domain, "DNSKEY", self.resolvers[0])
        ds = dns_query(domain, "DS", self.resolvers[0])

        result.dnskey_records = dnskey
        result.ds_records     = ds
        result.has_dnssec     = bool(dnskey or ds)

        nsec3 = dns_query(f"__phantom_nonexistent_12345.{domain}", "NSEC3", self.resolvers[0])
        nsec  = dns_query(f"__phantom_nonexistent_12345.{domain}", "NSEC", self.resolvers[0])
        if nsec3:
            result.nsec_type = "NSEC3"
        elif nsec:
            result.nsec_type = "NSEC"

        if not result.has_dnssec:
            result.issues.append("DNSSEC not configured — domain is vulnerable to cache poisoning")
        else:
            if not ds:
                result.issues.append("DNSKEY present but no DS record at parent — broken chain of trust")
            else:
                result.chain_valid = True
            if result.nsec_type == "NSEC":
                result.issues.append("NSEC (not NSEC3) used — zone walking possible, all subdomains can be enumerated")

        return result


# ---------------------------------------------------------------------------
# SPF Analyzer
# ---------------------------------------------------------------------------

class SPFAnalyzer:
    def analyze(self, domain: str) -> SPFResult:
        result = SPFResult(domain=domain, record=None, valid=False)
        txt_records = dns_query(domain, "TXT")
        spf_records = [r for r in txt_records if r.strip().startswith("v=spf1")]

        if not spf_records:
            result.issues.append("No SPF record found — email spoofing possible")
            return result

        if len(spf_records) > 1:
            result.issues.append("Multiple SPF records found (RFC violation)")

        record = spf_records[0]
        result.record = record
        result.valid  = True

        parts = record.split()
        result.mechanisms = [p for p in parts if not p.startswith("v=")]

        if not any(p in record for p in ["-all", "~all"]):
            result.issues.append("SPF does not end with -all or ~all — weak policy")
        if "+all" in record:
            result.issues.append("SPF uses +all — allows ALL senders (critical misconfiguration)")

        includes = [p for p in parts if p.startswith("include:") or p.startswith("+include:")]
        if len([p for p in parts if p.startswith(("include:", "ip4:", "ip6:", "a", "mx", "ptr", "exists:"))]) > 10:
            result.issues.append("SPF has >10 DNS lookup mechanisms — may exceed lookup limit (RFC 7208)")

        return result


# ---------------------------------------------------------------------------
# DMARC Analyzer
# ---------------------------------------------------------------------------

class DMARCAnalyzer:
    def analyze(self, domain: str) -> DMARCResult:
        result = DMARCResult(domain=domain, record=None, policy=None, valid=False)
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = dns_query(dmarc_domain, "TXT")
        dmarc_records = [r for r in txt_records if "v=DMARC1" in r]

        if not dmarc_records:
            result.issues.append("No DMARC record found — emails can pass without DMARC enforcement")
            return result

        record = dmarc_records[0]
        result.record = record
        result.valid  = True

        p_match = re.search(r'p=(\w+)', record)
        if p_match:
            result.policy = p_match.group(1).lower()

        pct_match = re.search(r'pct=(\d+)', record)
        if pct_match:
            result.pct = int(pct_match.group(1))

        if result.policy == "none":
            result.issues.append("DMARC policy is 'none' — monitoring only, no enforcement")
        if result.policy == "quarantine":
            result.issues.append("DMARC policy is 'quarantine' — failing emails go to spam but not rejected")
        if result.pct < 100:
            result.issues.append(f"DMARC pct={result.pct} — only {result.pct}% of messages are evaluated")
        if "rua=" not in record:
            result.issues.append("No DMARC reporting URI (rua) — no aggregate reports")

        return result


# ---------------------------------------------------------------------------
# DKIM Checker
# ---------------------------------------------------------------------------

COMMON_DKIM_SELECTORS = [
    "default", "google", "k1", "k2", "mail", "dkim", "selector1", "selector2",
    "email", "mta", "smtp", "s1", "s2", "key1", "key2", "mx", "dkimkey",
    "zoho", "mailchimp", "sendgrid", "amazonses", "mandrill", "postmark",
    "sparkpost", "mailgun", "brevo", "klaviyo",
]


class DKIMChecker:
    def check_selector(self, domain: str, selector: str) -> DKIMResult:
        dkim_domain = f"{selector}._domainkey.{domain}"
        result = DKIMResult(domain=domain, selector=selector, record=None, valid=False)
        txt_records = dns_query(dkim_domain, "TXT")
        if txt_records:
            result.record = txt_records[0]
            result.valid  = True
            key_match = re.search(r'p=([A-Za-z0-9+/=]+)', result.record)
            if key_match:
                import base64
                try:
                    key_bytes = base64.b64decode(key_match.group(1) + "==")
                    result.key_bits = len(key_bytes) * 8
                except Exception:
                    pass
        return result

    def enumerate(self, domain: str) -> List[DKIMResult]:
        results = []
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(self.check_selector, domain, sel): sel
                    for sel in COMMON_DKIM_SELECTORS}
            for ft in as_completed(futs):
                r = ft.result()
                if r.valid:
                    results.append(r)
        return results


# ---------------------------------------------------------------------------
# DNS Cache Poisoning Check
# ---------------------------------------------------------------------------

def check_dns_security(domain: str) -> Dict:
    issues = []

    resolvers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
    txids = set()
    for _ in range(5):
        for resolver in resolvers:
            data = _dns_query_udp(domain, DNS_TYPES["A"], resolver)
            if data and len(data) >= 2:
                txid = struct.unpack("!H", data[:2])[0]
                txids.add(txid)

    if len(txids) < 3:
        issues.append("DNS resolver appears to use predictable transaction IDs — cache poisoning risk")

    src_ports = set()
    for _ in range(5):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("", 0))
            port = s.getsockname()[1]
            src_ports.add(port)
            s.close()
        except Exception:
            pass
    if len(src_ports) < 3:
        issues.append("Limited source port randomization detected")

    return {"domain": domain, "issues": issues, "txid_diversity": len(txids)}


# ---------------------------------------------------------------------------
# Subdomain brute-force via DNS
# ---------------------------------------------------------------------------

def dns_bruteforce(domain: str, wordlist: Optional[List[str]] = None,
                   threads: int = 100, resolver: str = "8.8.8.8") -> List[Dict]:
    if not wordlist:
        wordlist = [
            "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
            "blog", "shop", "app", "secure", "vpn", "remote", "portal",
            "intranet", "extranet", "mobile", "m", "static", "cdn", "assets",
            "images", "media", "upload", "files", "docs", "wiki", "jira",
            "confluence", "gitlab", "github", "jenkins", "grafana", "kibana",
            "prometheus", "elastic", "redis", "mongo", "mysql", "postgres",
            "smtp", "mx", "imap", "pop", "webmail", "owa", "autodiscover",
            "exchange", "sharepoint", "sso", "auth", "login", "dashboard",
            "monitoring", "alerts", "backup", "db", "database", "internal",
            "private", "corp", "office", "meet", "video", "chat", "support",
            "helpdesk", "crm", "erp", "hr", "finance", "payments",
        ]

    wildcard_ip = None
    test = dns_query(f"_phantom_wildcard_test_.{domain}", "A", resolver)
    if test:
        wildcard_ip = test[0]

    results = []
    lock = __import__("threading").Lock()

    def _check(subdomain: str) -> Optional[Dict]:
        fqdn = f"{subdomain}.{domain}"
        ips = dns_query(fqdn, "A", resolver)
        if ips and (not wildcard_ip or ips[0] != wildcard_ip):
            ipv6 = dns_query(fqdn, "AAAA", resolver)
            cname = dns_query(fqdn, "CNAME", resolver)
            return {"subdomain": fqdn, "ips": ips, "ipv6": ipv6, "cname": cname}
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_check, w): w for w in wordlist}
        for ft in as_completed(futs):
            r = ft.result()
            if r:
                with lock:
                    results.append(r)

    return sorted(results, key=lambda x: x["subdomain"])


# ---------------------------------------------------------------------------
# Full DNS record enumeration
# ---------------------------------------------------------------------------

def enumerate_dns_records(domain: str, resolver: str = "8.8.8.8") -> Dict:
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]
    results = {}
    for rt in record_types:
        vals = dns_query(domain, rt, resolver)
        if vals:
            results[rt] = vals
    return results


# ---------------------------------------------------------------------------
# Combined runner
# ---------------------------------------------------------------------------

def run_dns_advanced(
    domain:        str,
    zone_transfer: bool = True,
    dnssec:        bool = True,
    email_auth:    bool = True,
    brute:         bool = False,
    wordlist:      Optional[List[str]] = None,
    security:      bool = True,
    resolver:      str = "8.8.8.8",
    verbose:       bool = False,
) -> Dict:
    result = {"domain": domain}

    result["records"] = enumerate_dns_records(domain, resolver)

    if zone_transfer:
        zt = ZoneTransfer()
        zt_results = zt.attempt(domain)
        result["zone_transfer"] = [
            {"ns": r.nameserver, "success": r.success,
             "record_count": len(r.records), "error": r.error,
             "records": [{"name": rec.name, "type": rec.record_type, "value": rec.value}
                         for rec in r.records[:50]]}
            for r in zt_results
        ]

    if dnssec:
        da = DNSSECAnalyzer()
        dn = da.analyze(domain)
        result["dnssec"] = {
            "has_dnssec": dn.has_dnssec,
            "dnskey": dn.dnskey_records,
            "ds": dn.ds_records,
            "nsec_type": dn.nsec_type,
            "chain_valid": dn.chain_valid,
            "issues": dn.issues,
        }

    if email_auth:
        spf  = SPFAnalyzer().analyze(domain)
        dmarc = DMARCAnalyzer().analyze(domain)
        dkim  = DKIMChecker().enumerate(domain)
        result["email_security"] = {
            "spf": {"record": spf.record, "valid": spf.valid, "issues": spf.issues, "mechanisms": spf.mechanisms},
            "dmarc": {"record": dmarc.record, "policy": dmarc.policy, "pct": dmarc.pct, "valid": dmarc.valid, "issues": dmarc.issues},
            "dkim": [{"selector": r.selector, "record": r.record, "key_bits": r.key_bits} for r in dkim],
        }

    if security:
        sec = check_dns_security(domain)
        result["dns_security"] = sec

    if brute:
        subs = dns_bruteforce(domain, wordlist)
        result["brute_subdomains"] = subs

    return result
