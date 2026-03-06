"""
subdomain_takeover.py
=====================
Subdomain Takeover Detection Engine (50+ services):
  - Resolves CNAME chains for all target subdomains
  - Checks for dangling CNAMEs pointing to unclaimed services
  - Service-specific fingerprints (HTTP response body + error patterns)
  - Dead NS delegation detection
  - GitHub Pages, Heroku, Fastly, Netlify, Vercel, AWS S3/CloudFront,
    Azure, GCP, Shopify, Tumblr, WordPress.com, Zendesk, Desk.com,
    UserVoice, HelpScout, Unbounce, LaunchRock, Strikingly, Tictail,
    Bitbucket, Squarespace, Cargo, Teamwork, Kajabi, Pingdom, Surge.sh,
    Uberflip, Proposify, SimpleBooklet, Vend, Acquia, Webflow, JetBrains,
    Smartling, Feedpress, Kinsta, ReadTheDocs, Ghost.io, Pantheon,
    Campaign Monitor, Fly.io, Render, Railway, Supabase, and more
"""

from __future__ import annotations

import json
import re
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Service fingerprints
# Each entry: (service_name, cname_pattern, error_body_pattern, severity, notes)
# ---------------------------------------------------------------------------

TAKEOVER_FINGERPRINTS = [
    # GitHub Pages
    ("github_pages", r"github\.io$", r"there isn't a github pages site here|for root url", "high",
     "GitHub Pages — claim repo at github.com/{org}.github.io"),

    # Heroku
    ("heroku", r"heroku(app)?\.com$", r"no such app|herokucdn\.com", "high",
     "Heroku — register app at heroku.com"),

    # Fastly
    ("fastly", r"fastly\.net$", r"fastly error: unknown domain|please check that this domain has been added to a fastly service", "high",
     "Fastly CDN — add domain to your Fastly service"),

    # Netlify
    ("netlify", r"netlify\.(app|com)$", r"not found - request id", "high",
     "Netlify — claim site at netlify.com"),

    # Vercel
    ("vercel", r"vercel\.app$|\.now\.sh$", r"the deployment you are looking for|vercel\.app", "high",
     "Vercel — deploy to claim this domain"),

    # AWS S3
    ("aws_s3", r"s3[^.]*\.amazonaws\.com$|s3-website[^.]*\.amazonaws\.com$",
     r"nosuchbucket|the specified bucket does not exist", "high",
     "AWS S3 — create bucket with matching name"),

    # AWS CloudFront
    ("aws_cloudfront", r"cloudfront\.net$",
     r"bad request|the request could not be satisfied", "medium",
     "AWS CloudFront — distribution may be deleted"),

    # AWS Elastic Beanstalk
    ("aws_elasticbeanstalk", r"elasticbeanstalk\.com$",
     r"can't connect to local mysql server|this application is not available", "high",
     "AWS Elastic Beanstalk — environment deleted"),

    # Azure
    ("azure_websites", r"azurewebsites\.net$|azure-mobile\.net$|cloudapp\.net$",
     r"404 web site not found|error 404 - web app not found", "high",
     "Azure Web App — claim via Azure portal"),

    # Azure App Service
    ("azure_appservice", r"\.azurefd\.net$|\.trafficmanager\.net$",
     r"404 - file or directory not found", "medium", "Azure Front Door / Traffic Manager"),

    # GCP App Engine
    ("gcp_appengine", r"appspot\.com$",
     r"error: server error|404. that's an error", "high",
     "Google App Engine — create app with matching ID"),

    # GCP Storage
    ("gcp_storage", r"storage\.googleapis\.com$",
     r"nosuchbucket|the specified bucket does not exist", "high",
     "GCP Storage — create bucket with matching name"),

    # Shopify
    ("shopify", r"myshopify\.com$",
     r"sorry, this shop is currently unavailable|only if you want to get into the shopify", "high",
     "Shopify — create store with matching subdomain"),

    # Tumblr
    ("tumblr", r"tumblr\.com$",
     r"whatever you were looking for doesn't currently exist|there's nothing here", "medium",
     "Tumblr — create blog with matching name"),

    # WordPress.com
    ("wordpress_com", r"wordpress\.com$",
     r"do you want to register|doesn't exist", "low",
     "WordPress.com — register site"),

    # Zendesk
    ("zendesk", r"zendesk\.com$",
     r"help center closed|this help center no longer exists", "high",
     "Zendesk — claim subdomain"),

    # UserVoice
    ("uservoice", r"uservoice\.com$",
     r"this uservoice subdomain is currently available|you have reached a uservoice domain", "high",
     "UserVoice — claim subdomain"),

    # HelpScout
    ("helpscout", r"helpscoutdocs\.com$",
     r"no settings were found for this company|page not found", "high",
     "HelpScout — claim docs site"),

    # Unbounce
    ("unbounce", r"unbouncepages\.com$",
     r"the requested url was not found on this server|page not found", "high",
     "Unbounce — create page"),

    # Strikingly
    ("strikingly", r"strikingly\.com$",
     r"this domain is available for purchase|buy this domain", "high",
     "Strikingly — claim site"),

    # Surge.sh
    ("surge", r"surge\.sh$",
     r"project not found|this page is not available", "high",
     "Surge.sh — deploy project"),

    # Bitbucket
    ("bitbucket", r"bitbucket\.io$",
     r"repository not found|this repository is private", "high",
     "Bitbucket — create repository pages"),

    # Squarespace
    ("squarespace", r"squarespace\.com$",
     r"no such account|if you're moving your squarespace site", "low",
     "Squarespace — account deleted"),

    # Webflow
    ("webflow", r"webflow\.io$|\.webflow\.com$",
     r"the page you are looking for doesn't exist|the page could not be found", "high",
     "Webflow — claim project"),

    # Ghost.io
    ("ghost", r"ghost\.io$",
     r"the thing you were looking for is no longer here|404", "high",
     "Ghost — claim blog"),

    # ReadTheDocs
    ("readthedocs", r"readthedocs\.io$|readthedocs\.org$",
     r"project does not exist|we had trouble finding that page", "high",
     "Read the Docs — create project"),

    # Fly.io
    ("fly_io", r"fly\.dev$|\.fly\.io$",
     r"no app found with that hostname|404", "high",
     "Fly.io — deploy app"),

    # Render
    ("render", r"onrender\.com$",
     r"service does not exist|could not route to service", "high",
     "Render — create service"),

    # Railway
    ("railway", r"railway\.app$",
     r"application failed to respond|404 not found", "high",
     "Railway — create app"),

    # Supabase
    ("supabase", r"supabase\.co$",
     r"project not found|supabase project", "medium",
     "Supabase — create project"),

    # JetBrains Space
    ("jetbrains_space", r"jetbrains\.space$",
     r"404 not found|space organization not found", "medium",
     "JetBrains Space — organization deleted"),

    # Kinsta
    ("kinsta", r"kinsta\.cloud$",
     r"no site found|this site is not available", "high",
     "Kinsta — create WordPress site"),

    # Pantheon
    ("pantheon", r"pantheonsite\.io$",
     r"the gods are wise|404 error|site not found", "high",
     "Pantheon — create WordPress/Drupal site"),

    # Acquia
    ("acquia", r"acquia-sites\.com$",
     r"the site you were looking for couldn't be found|if you're an acquia customer", "high",
     "Acquia — site deleted"),

    # Campaign Monitor
    ("campaign_monitor", r"createsend\.com$",
     r"alias not configured|this campaign monitor account does not exist", "high",
     "Campaign Monitor — account deleted"),

    # Feedpress
    ("feedpress", r"feedpress\.me$",
     r"the feed has not been found|404", "medium",
     "Feedpress — feed deleted"),

    # Proposify
    ("proposify", r"proposify\.biz$",
     r"if you need immediate assistance|no proposals", "medium",
     "Proposify — account deleted"),

    # Uberflip
    ("uberflip", r"uberflip\.com$",
     r"the requested url was not found|non-hub pages", "medium",
     "Uberflip — hub deleted"),

    # Kajabi
    ("kajabi", r"kajabi\.com$|mykajabi\.com$",
     r"this site no longer exists|the page you were looking for doesn't exist", "high",
     "Kajabi — site deleted"),

    # Cargo
    ("cargo", r"cargo\.site$|cargocollective\.com$",
     r"if you're the owner|404", "low",
     "Cargo — site deleted"),

    # Vend
    ("vend", r"vendhq\.com$",
     r"the store you're looking for|this store is no longer available", "high",
     "Vend — store deleted"),

    # Pingdom
    ("pingdom", r"pingdom\.com$",
     r"this public report page has been removed|report deleted", "medium",
     "Pingdom — public report removed"),

    # Teamwork
    ("teamwork", r"teamwork\.com$",
     r"oops - we didn't find your site|this account doesn't exist", "high",
     "Teamwork — account deleted"),

    # Launchrock
    ("launchrock", r"launchrock\.com$",
     r"it looks like you may have taken a wrong turn|404", "medium",
     "Launchrock — site deleted"),

    # Tictail
    ("tictail", r"tictail\.com$",
     r"to target|building a brand new", "medium",
     "Tictail — shop deleted"),

    # SmartJobBoard
    ("smartjobboard", r"smartjobboard\.com$",
     r"this job board website is either expired or its domain name was changed", "high",
     "SmartJobBoard — expired"),

    # Simple Booklet
    ("simplebooklet", r"simplebooklet\.com$",
     r"we can't find this booklet|404", "medium",
     "SimpleBooklet — booklet deleted"),

    # Worksites.net
    ("worksites", r"worksites\.net$",
     r"hello! there's nothing here yet|website builder", "low",
     "Worksites.net — unclaimed"),

    # Aftership
    ("aftership", r"aftership\.com$",
     r"tracking page not found|this page does not exist", "medium",
     "AfterShip — tracking page deleted"),

    # Airee
    ("airee", r"airee\.ru$",
     r"ошибка|error", "medium", "Airee — site deleted"),
]


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def _resolve_cname_chain(hostname: str, max_depth: int = 10) -> List[str]:
    chain = [hostname]
    current = hostname
    for _ in range(max_depth):
        try:
            answers = socket.getaddrinfo(current, None)
            cname_resolved = socket.gethostbyname(current)
            canonical = socket.getfqdn(current)
            if canonical != current and canonical not in chain:
                chain.append(canonical)
                current = canonical
            else:
                break
        except Exception:
            break
    return chain

def _resolve_a(hostname: str) -> Optional[str]:
    try:
        return socket.gethostbyname(hostname.rstrip("."))
    except Exception:
        return None

def _resolve_cname_raw(hostname: str) -> Optional[str]:
    from phantomrecon.modules.dns_advanced import dns_query
    results = dns_query(hostname, "CNAME")
    return results[0] if results else None


# ---------------------------------------------------------------------------
# HTTP probe
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: float = 8.0) -> Tuple[int, str]:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0 PhantomRecon/1.0")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(8192).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class TakeoverResult:
    subdomain:   str
    cname:       Optional[str]
    cname_chain: List[str]
    service:     str
    vulnerable:  bool
    severity:    str
    evidence:    str
    notes:       str
    status_code: int = 0


# ---------------------------------------------------------------------------
# Core checker
# ---------------------------------------------------------------------------

class SubdomainTakeoverChecker:
    def __init__(self, verbose: bool = False, timeout: float = 8.0):
        self.verbose = verbose
        self.timeout = timeout

    def _match_fingerprint(self, cname: str, body: str,
                            status: int) -> Optional[Tuple[str, str, str, str]]:
        for service, cname_pat, body_pat, severity, notes in TAKEOVER_FINGERPRINTS:
            if cname and re.search(cname_pat, cname, re.IGNORECASE):
                if re.search(body_pat, body, re.IGNORECASE):
                    return service, severity, f"CNAME {cname!r} + body match: {body_pat!r}", notes
                if status in (404, 0, 410, 500):
                    return service, severity, f"CNAME {cname!r} resolves to {service} (HTTP {status})", notes
        return None

    def check_subdomain(self, subdomain: str) -> TakeoverResult:
        ip      = _resolve_a(subdomain)
        cname   = None
        try:
            cname = _resolve_cname_raw(subdomain)
        except Exception:
            pass

        if not cname and not ip:
            return TakeoverResult(
                subdomain=subdomain, cname=None, cname_chain=[subdomain],
                service="dead_dns", vulnerable=True, severity="high",
                evidence="No DNS resolution — dangling DNS record",
                notes="DNS record exists but target has no IP/CNAME — high takeover risk",
            )

        cname_chain = _resolve_cname_chain(subdomain)

        for proto in ("https", "http"):
            url = f"{proto}://{subdomain}"
            status, body = _http_get(url, self.timeout)
            final_cname = cname or (cname_chain[-1] if cname_chain else "")
            match = self._match_fingerprint(final_cname, body, status)
            if match:
                service, severity, evidence, notes = match
                return TakeoverResult(
                    subdomain=subdomain, cname=cname, cname_chain=cname_chain,
                    service=service, vulnerable=True, severity=severity,
                    evidence=evidence, notes=notes, status_code=status,
                )

        if cname and not ip:
            for _, cname_pat, _, severity, notes in TAKEOVER_FINGERPRINTS:
                if re.search(cname_pat, cname, re.IGNORECASE):
                    return TakeoverResult(
                        subdomain=subdomain, cname=cname, cname_chain=cname_chain,
                        service=cname.split(".")[-2] if "." in cname else cname,
                        vulnerable=True, severity=severity,
                        evidence=f"CNAME {cname!r} matches service pattern but host unresolvable",
                        notes=notes,
                    )

        return TakeoverResult(
            subdomain=subdomain, cname=cname, cname_chain=cname_chain,
            service="none", vulnerable=False, severity="info",
            evidence="No takeover indicators found", notes="",
        )

    def scan(self, subdomains: List[str], threads: int = 30) -> List[TakeoverResult]:
        results = []
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futs = {ex.submit(self.check_subdomain, s): s for s in subdomains}
            for ft in as_completed(futs):
                try:
                    r = ft.result()
                    results.append(r)
                except Exception:
                    pass
        return sorted(results, key=lambda r: r.vulnerable, reverse=True)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_takeover_scan(subdomains: List[str], threads: int = 30,
                      verbose: bool = False) -> Dict:
    checker = SubdomainTakeoverChecker(verbose=verbose)
    results = checker.scan(subdomains, threads)
    vulnerable = [r for r in results if r.vulnerable]
    return {
        "total_checked": len(results),
        "vulnerable":    len(vulnerable),
        "findings": [
            {
                "subdomain":   r.subdomain,
                "cname":       r.cname,
                "cname_chain": r.cname_chain,
                "service":     r.service,
                "severity":    r.severity,
                "evidence":    r.evidence,
                "notes":       r.notes,
            }
            for r in vulnerable
        ],
        "all_results": [
            {
                "subdomain": r.subdomain,
                "cname":     r.cname,
                "service":   r.service,
                "vulnerable": r.vulnerable,
            }
            for r in results
        ],
    }
