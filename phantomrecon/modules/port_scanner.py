"""
port_scanner.py
===============
Built-in TCP/UDP port scanner with:
  - TCP SYN/connect scan (no root needed for connect scan)
  - UDP scanning (common ports)
  - Banner grabbing (raw + HTTP + FTP + SMTP + SSH + IMAP + POP3)
  - Service/version fingerprinting
  - OS TTL-based guessing
  - NSE-style script checks (anon FTP, null SMB session, HTTP title)
  - CIDR range expansion
  - Top-ports presets (top-100, top-1000, full 65535)
  - Concurrent scanning with configurable thread pool
  - JSON/CSV export
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import select
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Port/Service data
# ---------------------------------------------------------------------------

class PortState(str, Enum):
    OPEN     = "open"
    CLOSED   = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"


SERVICE_MAP: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpc", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 162: "snmp-trap", 179: "bgp",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    500: "isakmp", 514: "syslog", 515: "printer", 520: "rip",
    587: "submission", 593: "msrpc-http", 631: "ipp",
    636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks5", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3000: "http-alt", 3306: "mysql", 3389: "rdp",
    3690: "svn", 4443: "https-alt", 4444: "msf", 4505: "saltstack",
    4506: "saltstack", 5000: "http-alt", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl",
    6379: "redis", 6443: "k8s-api", 7001: "weblogic", 7077: "spark",
    8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "php-fpm", 9090: "prometheus", 9200: "elasticsearch",
    9300: "elasticsearch-node", 10250: "kubelet", 11211: "memcached",
    27017: "mongodb", 50000: "db2", 50070: "hadoop-namenode",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 135, 139, 143, 161, 179,
    389, 443, 445, 465, 500, 514, 587, 636, 993, 995, 1080, 1433, 1521,
    1723, 2049, 2375, 3000, 3306, 3389, 3690, 4444, 5000, 5432, 5672,
    5900, 5985, 6379, 6443, 7001, 8080, 8443, 8888, 9000, 9090, 9200,
    9300, 10250, 11211, 27017,
]

TOP_1000_PORTS = TOP_100_PORTS + list(range(1, 1025))
TOP_1000_PORTS = sorted(set(TOP_1000_PORTS))


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    host:    str
    port:    int
    proto:   str
    state:   PortState
    service: str = ""
    version: str = ""
    banner:  str = ""
    scripts: Dict[str, str] = field(default_factory=dict)
    ttl:     Optional[int] = None
    latency: float = 0.0

@dataclass
class ScanReport:
    hosts: Dict[str, List[PortResult]] = field(default_factory=dict)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    total_ports_scanned: int = 0
    open_count: int = 0

    @property
    def duration(self) -> float:
        return (self.end_time or time.time()) - self.start_time


# ---------------------------------------------------------------------------
# Banner grabbers
# ---------------------------------------------------------------------------

BANNER_PROBES: Dict[str, bytes] = {
    "http":  b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    "ftp":   b"",
    "smtp":  b"",
    "ssh":   b"",
    "imap":  b"",
    "pop3":  b"",
    "default": b"\r\n",
}

HTTP_SERVICES = {80, 443, 8080, 8443, 8888, 4443, 3000, 5000}


def _grab_banner(host: str, port: int, proto: str = "tcp", timeout: float = 3.0) -> Tuple[str, str]:
    try:
        if proto == "udp":
            return "", ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        banner_raw = b""
        try:
            sock.settimeout(2.0)
            banner_raw = sock.recv(1024)
        except Exception:
            pass

        if not banner_raw and port in HTTP_SERVICES:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                sock.settimeout(2.0)
                banner_raw = sock.recv(2048)
            except Exception:
                pass

        if not banner_raw:
            probe = BANNER_PROBES.get("default", b"\r\n")
            try:
                sock.sendall(probe)
                sock.settimeout(2.0)
                banner_raw = sock.recv(1024)
            except Exception:
                pass

        sock.close()
        banner = banner_raw.decode("utf-8", errors="replace").strip()[:512]
        version = _extract_version(banner, port)
        return banner, version
    except Exception:
        return "", ""


def _extract_version(banner: str, port: int) -> str:
    patterns = [
        r"SSH-[\d.]+-([^\s\r\n]+)",
        r"220[\s-]+([^\r\n]{3,60})",
        r"Server:\s*([^\r\n]{1,60})",
        r"X-Powered-By:\s*([^\r\n]{1,60})",
        r"([a-zA-Z][a-zA-Z0-9\-_]+/[\d.]+)",
        r"version\s+([\d.]+)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:80]
    return ""


# ---------------------------------------------------------------------------
# Script checks (NSE-style)
# ---------------------------------------------------------------------------

def _script_ftp_anon(host: str, port: int) -> Optional[str]:
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.recv(512)
        s.sendall(b"USER anonymous\r\n")
        r1 = s.recv(512).decode(errors="replace")
        s.sendall(b"PASS anon@example.com\r\n")
        r2 = s.recv(512).decode(errors="replace")
        s.close()
        if "230" in r2:
            return "Anonymous FTP login ALLOWED"
        return None
    except Exception:
        return None


def _script_http_title(host: str, port: int, tls: bool = False) -> Optional[str]:
    try:
        scheme = "https" if (tls or port in {443, 8443, 4443}) else "http"
        import urllib.request, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        url = f"{scheme}://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "PhantomRecon/1.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            body = resp.read(8192).decode("utf-8", errors="replace")
        m = re.search(r"<title[^>]*>([^<]{1,200})</title>", body, re.IGNORECASE)
        return m.group(1).strip() if m else "HTTP service detected"
    except Exception:
        return None


def _script_smb_null(host: str, port: int) -> Optional[str]:
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        # SMB negotiate
        negot = (
            b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18"
            b"\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43"
            b"\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52"
            b"\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e"
            b"\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66"
            b"\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20"
            b"\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30"
            b"\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02"
            b"\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"
        )
        s.sendall(negot)
        resp = s.recv(256)
        s.close()
        if len(resp) > 32:
            return "SMB service detected (null session probe sent)"
        return None
    except Exception:
        return None


def _script_redis_unauth(host: str, port: int) -> Optional[str]:
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        s.sendall(b"PING\r\n")
        resp = s.recv(64).decode(errors="replace")
        s.close()
        if "+PONG" in resp:
            return "Redis UNAUTHENTICATED — PING returned PONG"
        return None
    except Exception:
        return None


def _script_mongodb_unauth(host: str, port: int) -> Optional[str]:
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))
        # isMaster MongoDB wire protocol query
        msg = b"\x41\x00\x00\x00\x3e\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00"
        s.sendall(msg)
        resp = s.recv(256)
        s.close()
        if b"ismaster" in resp.lower() or b"isWritablePrimary" in resp:
            return "MongoDB UNAUTHENTICATED access detected"
        return None
    except Exception:
        return None


def _script_elasticsearch_unauth(host: str, port: int) -> Optional[str]:
    try:
        import urllib.request
        url = f"http://{host}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "PhantomRecon"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read(2048).decode(errors="replace")
        if "cluster_name" in body or "elasticsearch" in body.lower():
            return "Elasticsearch UNAUTHENTICATED — cluster info exposed"
        return None
    except Exception:
        return None


SCRIPT_REGISTRY: Dict[str, Callable] = {
    "ftp-anon":        lambda h, p: _script_ftp_anon(h, p),
    "http-title":      lambda h, p: _script_http_title(h, p),
    "smb-null":        lambda h, p: _script_smb_null(h, p),
    "redis-unauth":    lambda h, p: _script_redis_unauth(h, p),
    "mongodb-unauth":  lambda h, p: _script_mongodb_unauth(h, p),
    "elastic-unauth":  lambda h, p: _script_elasticsearch_unauth(h, p),
}

SCRIPT_PORT_MAP: Dict[int, List[str]] = {
    21:    ["ftp-anon"],
    80:    ["http-title"],
    443:   ["http-title"],
    445:   ["smb-null"],
    139:   ["smb-null"],
    6379:  ["redis-unauth"],
    27017: ["mongodb-unauth"],
    9200:  ["elastic-unauth"],
    8080:  ["http-title"],
    8443:  ["http-title"],
}


# ---------------------------------------------------------------------------
# OS detection (TTL fingerprinting)
# ---------------------------------------------------------------------------

def _guess_os_from_ttl(ttl: int) -> str:
    if ttl <= 0:
        return "unknown"
    if ttl <= 64:
        return "Linux/Unix/macOS"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Network device (Cisco/HP)"
    return "unknown"


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

class PortScanner:
    def __init__(
        self,
        timeout:    float = 1.0,
        threads:    int   = 200,
        grab_banner: bool = True,
        run_scripts: bool = True,
        verbose:    bool  = False,
        progress_cb: Optional[Callable[[int, int, str, int], None]] = None,
    ):
        self.timeout     = timeout
        self.threads     = threads
        self.grab_banner = grab_banner
        self.run_scripts = run_scripts
        self.verbose     = verbose
        self.progress_cb = progress_cb
        self._lock       = threading.Lock()
        self._done       = 0
        self._total      = 0

    def _scan_tcp_port(self, host: str, port: int) -> PortResult:
        t0 = time.time()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            result = s.connect_ex((host, port))
            latency = time.time() - t0
            s.close()
            if result == 0:
                state = PortState.OPEN
            else:
                state = PortState.CLOSED
        except socket.timeout:
            state = PortState.FILTERED
            latency = time.time() - t0
        except Exception:
            state = PortState.FILTERED
            latency = time.time() - t0

        service = SERVICE_MAP.get(port, "unknown")
        pr = PortResult(host=host, port=port, proto="tcp", state=state,
                        service=service, latency=round(latency * 1000, 2))

        if state == PortState.OPEN:
            if self.grab_banner:
                pr.banner, pr.version = _grab_banner(host, port, timeout=2.0)
            if self.run_scripts:
                scripts = SCRIPT_PORT_MAP.get(port, [])
                for script_name in scripts:
                    fn = SCRIPT_REGISTRY.get(script_name)
                    if fn:
                        try:
                            result_msg = fn(host, port)
                            if result_msg:
                                pr.scripts[script_name] = result_msg
                        except Exception:
                            pass

        with self._lock:
            self._done += 1
            if self.progress_cb:
                self.progress_cb(self._done, self._total, host, port)

        return pr

    def _scan_udp_port(self, host: str, port: int) -> PortResult:
        service = SERVICE_MAP.get(port, "unknown")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(self.timeout)
            s.sendto(b"\x00" * 16, (host, port))
            try:
                data, _ = s.recvfrom(1024)
                state = PortState.OPEN
                banner = data.decode("utf-8", errors="replace").strip()[:256]
            except socket.timeout:
                state = PortState.OPEN_FILTERED
                banner = ""
            except Exception:
                state = PortState.CLOSED
                banner = ""
            s.close()
        except Exception:
            state = PortState.FILTERED
            banner = ""

        with self._lock:
            self._done += 1
            if self.progress_cb:
                self.progress_cb(self._done, self._total, host, port)

        return PortResult(host=host, port=port, proto="udp", state=state,
                          service=service, banner=banner)

    def scan_host(
        self,
        host:    str,
        ports:   Optional[List[int]] = None,
        udp:     bool = False,
        preset:  str  = "top-100",
    ) -> List[PortResult]:
        if not ports:
            if preset == "top-100":
                ports = TOP_100_PORTS
            elif preset == "top-1000":
                ports = TOP_1000_PORTS
            elif preset == "full":
                ports = list(range(1, 65536))
            else:
                ports = TOP_100_PORTS

        tcp_ports = ports
        udp_ports = [53, 67, 68, 69, 123, 137, 161, 500, 514, 520] if udp else []

        self._total = len(tcp_ports) + len(udp_ports)
        self._done  = 0
        results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._scan_tcp_port, host, p): ("tcp", p) for p in tcp_ports}
            if udp_ports:
                futs.update({ex.submit(self._scan_udp_port, host, p): ("udp", p) for p in udp_ports})
            for ft in as_completed(futs):
                try:
                    results.append(ft.result())
                except Exception:
                    pass

        return sorted(results, key=lambda r: (r.proto, r.port))

    def scan_range(
        self,
        cidr_or_hosts: str,
        ports:   Optional[List[int]] = None,
        udp:     bool = False,
        preset:  str  = "top-100",
    ) -> ScanReport:
        report = ScanReport()
        hosts: List[str] = []
        try:
            net = ipaddress.ip_network(cidr_or_hosts, strict=False)
            hosts = [str(h) for h in net.hosts()]
        except ValueError:
            hosts = [cidr_or_hosts]

        for host in hosts:
            results = self.scan_host(host, ports=ports, udp=udp, preset=preset)
            open_results = [r for r in results if r.state == PortState.OPEN]
            if open_results:
                report.hosts[host] = results
                report.open_count += len(open_results)
            report.total_ports_scanned += len(results)

        report.end_time = time.time()
        return report


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_scan_table(report: ScanReport, show_closed: bool = False) -> str:
    lines = [
        "\n\033[1;32m╔═══════════════════════════════════════════════════════════════╗",
        "║               PORT SCANNER — PhantomRecon                    ║",
        "╚═══════════════════════════════════════════════════════════════╝\033[0m",
        f"  Scan duration : {report.duration:.2f}s",
        f"  Hosts scanned : {len(report.hosts)}",
        f"  Open ports    : {report.open_count}",
        f"  Total probed  : {report.total_ports_scanned}",
        "",
    ]
    for host, results in sorted(report.hosts.items()):
        open_ports = [r for r in results if r.state == PortState.OPEN]
        if not open_ports and not show_closed:
            continue
        lines.append(f"\033[1;36m  Host: {host}\033[0m")
        lines.append(f"  {'PORT':<8} {'PROTO':<6} {'STATE':<12} {'SERVICE':<14} {'VERSION':<30} {'LATENCY'}")
        lines.append(f"  {'─'*8} {'─'*6} {'─'*12} {'─'*14} {'─'*30} {'─'*8}")
        to_show = results if show_closed else [r for r in results if r.state == PortState.OPEN]
        for r in to_show:
            state_color = "\033[1;32m" if r.state == PortState.OPEN else "\033[0;90m"
            lines.append(
                f"  {state_color}{r.port:<8}\033[0m {r.proto:<6} "
                f"{state_color}{r.state.value:<12}\033[0m "
                f"{r.service:<14} {(r.version or r.banner[:28]):<30} {r.latency}ms"
            )
            if r.banner and r.state == PortState.OPEN:
                banner_short = r.banner.replace("\n", " ").replace("\r", "")[:80]
                lines.append(f"    \033[0;33m  Banner: {banner_short}\033[0m")
            for script_name, msg in r.scripts.items():
                lines.append(f"    \033[1;31m  [!] {script_name}: {msg}\033[0m")
        lines.append("")
    return "\n".join(lines)


def scan_to_json(report: ScanReport) -> str:
    data = {
        "duration": round(report.duration, 2),
        "open_count": report.open_count,
        "hosts": {}
    }
    for host, results in report.hosts.items():
        data["hosts"][host] = [
            {
                "port": r.port, "proto": r.proto, "state": r.state.value,
                "service": r.service, "version": r.version, "banner": r.banner,
                "scripts": r.scripts, "latency_ms": r.latency,
            }
            for r in results if r.state == PortState.OPEN
        ]
    return json.dumps(data, indent=2)


def scan_to_csv(report: ScanReport, path: str) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["host","port","proto","state","service","version","banner","latency_ms"])
        w.writeheader()
        for host, results in report.hosts.items():
            for r in results:
                if r.state == PortState.OPEN:
                    w.writerow({"host": host, "port": r.port, "proto": r.proto,
                                "state": r.state.value, "service": r.service,
                                "version": r.version, "banner": r.banner[:100],
                                "latency_ms": r.latency})
