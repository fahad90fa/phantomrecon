"""
network_recon.py
================
Network & Infrastructure Recon:
  - IPv6 scanner (AAAA records, dual-stack detection, link-local enum)
  - BGP/ASN mapper (BGPView API, RIPE, ARIN, APNIC)
  - Cloud asset discovery (S3, Azure Blob, GCP Storage, DigitalOcean Spaces)
  - Network topology mapper (traceroute + TTL fingerprinting)
  - CDN/hosting detection
  - IP geolocation enrichment
  - Reverse DNS mass lookup
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int = 10, headers: Optional[Dict] = None) -> Tuple[int, str]:
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class IPv6Result:
    hostname: str
    ipv6_addresses: List[str] = field(default_factory=list)
    dual_stack: bool = False
    ipv4_address: Optional[str] = None
    link_local: Optional[str] = None
    reachable: bool = False

@dataclass
class ASNResult:
    ip: str
    asn: str
    asn_name: str
    prefix: str
    country: str
    rir: str
    ip_ranges: List[str] = field(default_factory=list)

@dataclass
class CloudAsset:
    url: str
    service: str
    name: str
    accessible: bool
    listing: bool = False
    files: List[str] = field(default_factory=list)
    region: Optional[str] = None

@dataclass
class HopResult:
    hop: int
    ip: Optional[str]
    hostname: Optional[str]
    rtt_ms: List[float] = field(default_factory=list)
    asn: Optional[str] = None
    country: Optional[str] = None
    os_guess: Optional[str] = None

@dataclass
class GeoResult:
    ip: str
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    asn: Optional[str] = None
    timezone: Optional[str] = None
    hosting: bool = False
    cdn: Optional[str] = None


# ---------------------------------------------------------------------------
# IPv6 Scanner
# ---------------------------------------------------------------------------

CDN_CNAME_PATTERNS = [
    (r"cloudfront\.net$",   "AWS CloudFront"),
    (r"fastly\.net$",       "Fastly"),
    (r"akamaiedge\.net$",   "Akamai"),
    (r"akamai\.net$",       "Akamai"),
    (r"cdnjs\.cloudflare\.com$", "Cloudflare"),
    (r"cloudflare\.net$",   "Cloudflare"),
    (r"edgecastcdn\.net$",  "EdgeCast"),
    (r"cdn\.jsdelivr\.net$","jsDelivr"),
    (r"llnwd\.net$",        "Limelight"),
    (r"azureedge\.net$",    "Azure CDN"),
    (r"trafficmanager\.net$","Azure Traffic Manager"),
    (r"amazonaws\.com$",    "AWS"),
    (r"googleusercontent\.com$", "Google Cloud CDN"),
    (r"pantheonsite\.io$",  "Pantheon"),
    (r"stackpathdns\.com$", "StackPath"),
]


class IPv6Scanner:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def _resolve_ipv6(self, hostname: str) -> List[str]:
        addrs = []
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for r in results:
                ip = r[4][0]
                if ip not in addrs:
                    addrs.append(ip)
        except Exception:
            pass
        return addrs

    def _resolve_ipv4(self, hostname: str) -> Optional[str]:
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None

    def _is_reachable(self, ip: str, port: int = 80, timeout: float = 2.0) -> bool:
        try:
            fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.settimeout(timeout)
            r = s.connect_ex((ip, port))
            s.close()
            return r == 0
        except Exception:
            return False

    def _detect_cdn(self, hostname: str) -> Optional[str]:
        try:
            import socket as _s
            cname = str(_s.gethostbyname_ex(hostname)[0])
            for pattern, cdn_name in CDN_CNAME_PATTERNS:
                if re.search(pattern, cname, re.IGNORECASE):
                    return cdn_name
        except Exception:
            pass
        return None

    def scan_host(self, hostname: str) -> IPv6Result:
        result = IPv6Result(hostname=hostname)
        result.ipv6_addresses = self._resolve_ipv6(hostname)
        result.ipv4_address   = self._resolve_ipv4(hostname)
        result.dual_stack     = bool(result.ipv6_addresses and result.ipv4_address)

        for addr in result.ipv6_addresses:
            if addr.startswith("fe80"):
                result.link_local = addr
            if self._is_reachable(addr):
                result.reachable = True
                break

        return result

    def scan_hosts(self, hostnames: List[str]) -> List[IPv6Result]:
        with ThreadPoolExecutor(max_workers=50) as ex:
            futs = {ex.submit(self.scan_host, h): h for h in hostnames}
            return [ft.result() for ft in as_completed(futs)]


# ---------------------------------------------------------------------------
# BGP/ASN Mapper
# ---------------------------------------------------------------------------

class BGPASNMapper:
    BGPVIEW_IP  = "https://api.bgpview.io/ip/{ip}"
    BGPVIEW_ASN = "https://api.bgpview.io/asn/{asn}/prefixes"
    IPINFO      = "https://ipinfo.io/{ip}/json"
    RIPE_WHOIS  = "https://stat.ripe.net/data/network-info/data.json?resource={ip}"

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._cache: Dict[str, ASNResult] = {}

    def lookup_ip(self, ip: str) -> ASNResult:
        if ip in self._cache:
            return self._cache[ip]

        result = ASNResult(ip=ip, asn="", asn_name="", prefix="", country="", rir="")

        # Try BGPView
        status, body = _http_get(self.BGPVIEW_IP.format(ip=ip), timeout=10)
        if status == 200:
            try:
                data = json.loads(body)
                prefixes = data.get("data", {}).get("prefixes", [])
                if prefixes:
                    p = prefixes[0]
                    asn_data = p.get("asn", {})
                    result.asn      = str(asn_data.get("asn", ""))
                    result.asn_name = asn_data.get("name", "")
                    result.prefix   = p.get("prefix", "")
                    result.country  = asn_data.get("country_code", "")
                    result.rir      = data.get("data", {}).get("rir_allocation", {}).get("rir_name", "")
            except Exception:
                pass

        if not result.asn:
            status, body = _http_get(self.IPINFO.format(ip=ip), timeout=10)
            if status == 200:
                try:
                    data = json.loads(body)
                    org = data.get("org", "")
                    if " " in org:
                        parts = org.split(" ", 1)
                        result.asn      = parts[0].lstrip("AS")
                        result.asn_name = parts[1]
                    result.country  = data.get("country", "")
                    result.prefix   = data.get("org", "")
                except Exception:
                    pass

        self._cache[ip] = result
        return result

    def get_asn_prefixes(self, asn: str) -> List[str]:
        asn_clean = str(asn).lstrip("AS").lstrip("as")
        status, body = _http_get(self.BGPVIEW_ASN.format(asn=asn_clean), timeout=15)
        prefixes = []
        if status == 200:
            try:
                data = json.loads(body)
                for p in data.get("data", {}).get("ipv4_prefixes", []):
                    prefixes.append(p.get("prefix", ""))
                for p in data.get("data", {}).get("ipv6_prefixes", []):
                    prefixes.append(p.get("prefix", ""))
            except Exception:
                pass
        return prefixes

    def map_domain(self, domain: str) -> Optional[ASNResult]:
        try:
            ip = socket.gethostbyname(domain)
            result = self.lookup_ip(ip)
            if result.asn:
                result.ip_ranges = self.get_asn_prefixes(result.asn)
            return result
        except Exception:
            return None

    def enumerate_org_ranges(self, org_name: str) -> List[ASNResult]:
        results = []
        url = f"https://api.bgpview.io/search?query_term={urllib.parse.quote(org_name)}"
        status, body = _http_get(url, timeout=15)
        if status == 200:
            try:
                data = json.loads(body)
                for asn_entry in data.get("data", {}).get("asns", [])[:10]:
                    asn = str(asn_entry.get("asn", ""))
                    name = asn_entry.get("name", "")
                    prefixes = self.get_asn_prefixes(asn)
                    r = ASNResult(ip="", asn=asn, asn_name=name, prefix="",
                                  country=asn_entry.get("country_code", ""),
                                  rir="", ip_ranges=prefixes)
                    results.append(r)
            except Exception:
                pass
        return results


# ---------------------------------------------------------------------------
# Cloud Asset Discovery
# ---------------------------------------------------------------------------

CLOUD_PATTERNS = {
    "s3": [
        "{name}.s3.amazonaws.com",
        "{name}.s3-website-us-east-1.amazonaws.com",
        "{name}.s3-website.us-east-1.amazonaws.com",
        "s3.amazonaws.com/{name}",
        "{name}.s3.us-east-1.amazonaws.com",
        "{name}.s3.eu-west-1.amazonaws.com",
        "{name}.s3.ap-southeast-1.amazonaws.com",
    ],
    "azure_blob": [
        "{name}.blob.core.windows.net",
        "{name}.azurewebsites.net",
        "{name}.azurestaticapps.net",
        "{name}.file.core.windows.net",
        "{name}.table.core.windows.net",
        "{name}.queue.core.windows.net",
    ],
    "gcp": [
        "{name}.storage.googleapis.com",
        "storage.googleapis.com/{name}",
        "{name}.appspot.com",
        "{name}.firebaseapp.com",
        "{name}.web.app",
    ],
    "digitalocean": [
        "{name}.nyc3.digitaloceanspaces.com",
        "{name}.sgp1.digitaloceanspaces.com",
        "{name}.ams3.digitaloceanspaces.com",
        "{name}.fra1.digitaloceanspaces.com",
        "{name}.sfo3.digitaloceanspaces.com",
    ],
    "cloudflare_r2": [
        "{name}.r2.cloudflarestorage.com",
    ],
    "alibaba": [
        "{name}.oss-cn-hangzhou.aliyuncs.com",
        "{name}.oss-us-east-1.aliyuncs.com",
    ],
    "backblaze": [
        "{name}.s3.us-west-001.backblazeb2.com",
        "{name}.s3.us-west-002.backblazeb2.com",
    ],
}

BUCKET_LISTING_PATTERNS = [
    r"<ListBucketResult",
    r"<EnumerationResults",
    r'"kind": "storage#objects"',
    r'"items":\s*\[',
    r"<Contents>",
]


class CloudAssetDiscovery:
    def __init__(self, threads: int = 50, verbose: bool = False):
        self.threads = threads
        self.verbose = verbose

    def _generate_names(self, base: str) -> List[str]:
        base = base.lower().replace(" ", "-").replace("_", "-")
        domain_parts = base.split(".")
        names = set()
        names.add(base)
        names.add(domain_parts[0])
        names.add(base.replace(".", "-"))
        names.add(base.replace(".", ""))
        for suffix in ["assets", "static", "media", "files", "uploads", "backup",
                        "data", "images", "cdn", "storage", "public", "private",
                        "dev", "staging", "prod", "production", "test", "logs",
                        "archive", "exports", "downloads", "resources"]:
            names.add(f"{domain_parts[0]}-{suffix}")
            names.add(f"{domain_parts[0]}.{suffix}")
            names.add(f"{suffix}-{domain_parts[0]}")
        return list(names)

    def _check_url(self, url: str, service: str, name: str) -> Optional[CloudAsset]:
        if not url.startswith("http"):
            url = "https://" + url
        try:
            status, body = _http_get(url, timeout=8)
            if status in (0, 400, 404):
                return None
            accessible = status in (200, 301, 302, 403)
            listing = any(re.search(p, body) for p in BUCKET_LISTING_PATTERNS)
            files = []
            if listing:
                files = re.findall(r"<Key>([^<]{1,200})</Key>", body)[:20]
                if not files:
                    files = re.findall(r'"name":\s*"([^"]{1,200})"', body)[:20]

            return CloudAsset(
                url=url, service=service, name=name,
                accessible=accessible, listing=listing, files=files,
            )
        except Exception:
            return None

    def discover(self, target: str) -> List[CloudAsset]:
        names = self._generate_names(target)
        tasks = []
        for name in names:
            for service, patterns in CLOUD_PATTERNS.items():
                for pattern in patterns:
                    url = pattern.format(name=name)
                    tasks.append((url, service, name))

        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futs = {ex.submit(self._check_url, url, svc, name): (url, svc, name)
                    for url, svc, name in tasks}
            for ft in as_completed(futs):
                try:
                    r = ft.result()
                    if r:
                        results.append(r)
                except Exception:
                    pass

        return sorted(results, key=lambda x: (not x.listing, not x.accessible, x.service))


# ---------------------------------------------------------------------------
# Network Topology Mapper (traceroute)
# ---------------------------------------------------------------------------

class TopologyMapper:
    def __init__(self, max_hops: int = 30, verbose: bool = False):
        self.max_hops = max_hops
        self.verbose  = verbose
        self._asn_mapper = BGPASNMapper()
        self._geo_cache: Dict[str, GeoResult] = {}

    def _traceroute_system(self, host: str) -> List[HopResult]:
        hops = []
        try:
            cmd = ["traceroute", "-n", "-m", str(self.max_hops), "-q", "2", "-w", "2", host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            lines = result.stdout.splitlines()
            for line in lines[1:]:
                m = re.match(r'\s*(\d+)\s+([\d.*\s]+)', line)
                if not m:
                    continue
                hop_num = int(m.group(1))
                rest = m.group(2).strip()
                ips_and_rtts = re.findall(r'([\d.]+)\s+([\d.]+)\s*ms', rest)
                ip = None
                rtts = []
                for ipt, rtt in ips_and_rtts:
                    ip = ipt
                    rtts.append(float(rtt))

                if not ip and "*" in rest:
                    hops.append(HopResult(hop=hop_num, ip=None, hostname=None))
                    continue

                hostname = None
                if ip:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = ip

                asn_info = None
                if ip:
                    try:
                        asn_r = self._asn_mapper.lookup_ip(ip)
                        asn_info = f"AS{asn_r.asn} {asn_r.asn_name}" if asn_r.asn else None
                    except Exception:
                        pass

                hops.append(HopResult(hop=hop_num, ip=ip, hostname=hostname,
                                       rtt_ms=rtts, asn=asn_info))
        except FileNotFoundError:
            hops = self._traceroute_python(host)
        except Exception:
            pass
        return hops

    def _traceroute_python(self, host: str) -> List[HopResult]:
        hops = []
        try:
            dest_ip = socket.gethostbyname(host)
        except Exception:
            return hops

        port = 33434
        for ttl in range(1, self.max_hops + 1):
            try:
                recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                recv_sock.settimeout(2)
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                send_sock.settimeout(2)

                t0 = time.time()
                send_sock.sendto(b"PhantomRecon", (dest_ip, port + ttl))

                try:
                    data, addr = recv_sock.recvfrom(512)
                    rtt = (time.time() - t0) * 1000
                    ip = addr[0]
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except Exception:
                        hostname = ip
                    hops.append(HopResult(hop=ttl, ip=ip, hostname=hostname, rtt_ms=[round(rtt, 2)]))
                    if ip == dest_ip:
                        break
                except socket.timeout:
                    hops.append(HopResult(hop=ttl, ip=None, hostname=None))

                send_sock.close()
                recv_sock.close()
                port += 1
            except Exception:
                hops.append(HopResult(hop=ttl, ip=None, hostname=None))

        return hops

    def trace(self, host: str) -> List[HopResult]:
        return self._traceroute_system(host)


# ---------------------------------------------------------------------------
# IP Geolocation
# ---------------------------------------------------------------------------

class IPGeolocator:
    IPAPI_URL  = "https://ip-api.com/json/{ip}?fields=66846719"
    IPINFO_URL = "https://ipinfo.io/{ip}/json"

    HOSTING_ORGS = [
        "amazon", "aws", "google", "azure", "microsoft", "digitalocean",
        "linode", "vultr", "hetzner", "ovh", "cloudflare", "fastly",
        "akamai", "leaseweb", "choopa", "psychz", "serverius",
    ]

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self._cache: Dict[str, GeoResult] = {}

    def lookup(self, ip: str) -> GeoResult:
        if ip in self._cache:
            return self._cache[ip]

        result = GeoResult(ip=ip)

        status, body = _http_get(self.IPAPI_URL.format(ip=ip), timeout=10)
        if status == 200:
            try:
                data = json.loads(body)
                result.city         = data.get("city")
                result.country      = data.get("country")
                result.country_code = data.get("countryCode")
                result.region       = data.get("regionName")
                result.latitude     = data.get("lat")
                result.longitude    = data.get("lon")
                result.isp          = data.get("isp")
                result.org          = data.get("org")
                result.asn          = data.get("as")
                result.timezone     = data.get("timezone")
                org_lower = (result.org or "").lower()
                result.hosting = any(h in org_lower for h in self.HOSTING_ORGS)
            except Exception:
                pass

        self._cache[ip] = result
        return result

    def bulk_lookup(self, ips: List[str]) -> Dict[str, GeoResult]:
        with ThreadPoolExecutor(max_workers=20) as ex:
            futs = {ex.submit(self.lookup, ip): ip for ip in ips}
            return {futs[ft]: ft.result() for ft in as_completed(futs)}


# ---------------------------------------------------------------------------
# Reverse DNS bulk lookup
# ---------------------------------------------------------------------------

def reverse_dns_lookup(ips: List[str], threads: int = 100) -> Dict[str, Optional[str]]:
    def _lookup(ip: str) -> Tuple[str, Optional[str]]:
        try:
            return ip, socket.gethostbyaddr(ip)[0]
        except Exception:
            return ip, None

    results = {}
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(_lookup, ip): ip for ip in ips}
        for ft in as_completed(futs):
            ip, hostname = ft.result()
            results[ip] = hostname
    return results


# ---------------------------------------------------------------------------
# Combined network recon runner
# ---------------------------------------------------------------------------

def run_network_recon(
    target:         str,
    ipv6:           bool = True,
    bgp:            bool = True,
    cloud:          bool = True,
    topology:       bool = True,
    geo:            bool = True,
    org_name:       Optional[str] = None,
    verbose:        bool = False,
) -> Dict:
    result = {"target": target}

    if ipv6:
        scanner = IPv6Scanner(verbose=verbose)
        r = scanner.scan_host(target)
        result["ipv6"] = {
            "addresses": r.ipv6_addresses,
            "dual_stack": r.dual_stack,
            "ipv4": r.ipv4_address,
            "link_local": r.link_local,
            "reachable": r.reachable,
        }

    if bgp:
        mapper = BGPASNMapper(verbose=verbose)
        asn_r = mapper.map_domain(target)
        if asn_r:
            result["asn"] = {
                "ip": asn_r.ip, "asn": asn_r.asn, "name": asn_r.asn_name,
                "prefix": asn_r.prefix, "country": asn_r.country, "rir": asn_r.rir,
                "ip_ranges": asn_r.ip_ranges[:20],
            }
        if org_name:
            org_ranges = mapper.enumerate_org_ranges(org_name)
            result["org_ranges"] = [
                {"asn": r.asn, "name": r.asn_name, "country": r.country,
                 "prefixes": r.ip_ranges[:10]}
                for r in org_ranges
            ]

    if cloud:
        discovery = CloudAssetDiscovery(verbose=verbose)
        assets = discovery.discover(target)
        result["cloud_assets"] = [
            {"url": a.url, "service": a.service, "name": a.name,
             "accessible": a.accessible, "listing": a.listing, "files": a.files[:5]}
            for a in assets
        ]

    if topology:
        mapper_topo = TopologyMapper(verbose=verbose)
        hops = mapper_topo.trace(target)
        result["topology"] = [
            {"hop": h.hop, "ip": h.ip, "hostname": h.hostname,
             "rtt_ms": h.rtt_ms, "asn": h.asn}
            for h in hops
        ]

    if geo:
        try:
            ip = socket.gethostbyname(target)
            geolocator = IPGeolocator(verbose=verbose)
            geo_r = geolocator.lookup(ip)
            result["geo"] = {
                "ip": geo_r.ip, "city": geo_r.city, "country": geo_r.country,
                "region": geo_r.region, "lat": geo_r.latitude, "lon": geo_r.longitude,
                "isp": geo_r.isp, "org": geo_r.org, "asn": geo_r.asn,
                "timezone": geo_r.timezone, "hosting": geo_r.hosting,
            }
        except Exception:
            pass

    return result
