"""PhantomRecon CLI — all subcommands."""

import asyncio
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import click

from . import __version__
from .config import apply_profile_to_config, load_config_file, load_profile, merge_config, write_example_config, PROFILES
from .engine import ScanEngine
from .models import ScanConfig, ScanModule
from .reports.reporter import Reporter
from .state import StateManager
from .ui import TerminalUI


def validate_target(ctx: click.Context, param: click.Parameter, value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urlparse(value)
    if not parsed.netloc:
        raise click.BadParameter(f"Invalid URL: {value}")
    return value.rstrip("/")


HELP_EXAMPLES = """
\033[1;32m╔══════════════════════════════════════════════════════════════════════╗
║          PhantomRecon — Advanced Web Recon & Vuln Assessment         ║
╚══════════════════════════════════════════════════════════════════════╝\033[0m

\033[1;33mCOMMANDS OVERVIEW\033[0m
\033[1;36m── Core ──────────────────────────────────────────────────────────────\033[0m
  scan              Full vulnerability & recon scan against a target
  fuzz              Fuzz URL parameters, headers, and cookies with attack payloads
  dns               DNS recon — records, zone transfer, SPF/DMARC, subdomain enum
  osint             Passive OSINT — Shodan, VirusTotal, crt.sh, Wayback Machine
  diff              Compare two scan JSON reports and show delta
  schedule          Run recurring scans on a timer with webhook/email alerts
  chain             Auto-discover subdomains then scan each one (pipeline mode)
  proxy-check       Test and score a proxy list for speed and anonymity
  history           Browse, search, and manage saved scan history (SQLite)
  profiles          List all available scan profiles
  gen-config        Generate an annotated YAML config file template
  john              Crack password hashes (35+ formats, 12 attack modes)
\033[1;36m── Recon & Discovery ─────────────────────────────────────────────────\033[0m
  cert-transparency Certificate transparency subdomain recon + email harvesting
  port-scan         TCP/UDP port scanner with banner grabbing (no nmap needed)
  network-recon     IPv6, BGP/ASN, cloud assets (S3/Azure/GCP), topology
  dns-adv           Advanced DNS: AXFR, DNSSEC, SPF/DMARC/DKIM, brute-force
  takeover          Subdomain takeover detection (50+ services)
  nuclei-run        Run Nuclei templates (binary or pure-Python fallback)
\033[1;36m── Exploitation & Auth ───────────────────────────────────────────────\033[0m
  exploit-confirm   Auto-confirm: SQLi, XSS, RCE, SSRF, SSTI, traversal, XXE
  jwt               JWT attack suite: alg:none, RS256→HS256, weak secret, kid
  deser             Deserialization payloads: Java, PHP, .NET, Python, Ruby, Node
  oauth             OAuth 2.0/OIDC: state fixation, redirect bypass, scope escalation
  2fa-bypass        2FA bypass: response manip, backup brute, race condition
  spray             Smart password spray with lockout avoidance (Poisson timing)
  payload-gen       Reverse shells (27 langs), web shells, WAF bypass encodings
  protocol-fuzz     GraphQL, WebSocket, SMTP, FTP, SMB, Redis, MongoDB, Kerberos
\033[1;36m── AI / Stealth / Intel ──────────────────────────────────────────────\033[0m
  ml-wordlist       AI Markov + org-specific password candidate generator
  stealth-check     HTTP/2, HTTP/3, entropy scan, polyglot payloads, decoy traffic
  threat-intel      VT, AbuseIPDB, Shodan enrichment + MITRE ATT&CK + HTML report

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;36mQUICK START EXAMPLES\033[0m
\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m

\033[1;32m▶  SCAN — Basic & Profiles\033[0m
  phantomrecon scan https://target.com
  phantomrecon scan https://target.com --profile aggressive
  phantomrecon scan https://target.com --profile ghost
  phantomrecon scan https://target.com --profile balanced
  phantomrecon scan https://target.com --profile shadow

\033[1;32m▶  SCAN — Select Specific Modules\033[0m
  phantomrecon scan https://target.com -m headers -m ssl -m vulns
  phantomrecon scan https://target.com -m fingerprint -m cms
  phantomrecon scan https://target.com -m bruteforce -m crawler
  phantomrecon scan https://target.com -m waf -m api -m vhost

\033[1;32m▶  SCAN — Performance Tuning\033[0m
  phantomrecon scan https://target.com -t 200 --timeout 8
  phantomrecon scan https://target.com --delay-min 0.5 --delay-max 2.0 --rate 30
  phantomrecon scan https://target.com --wordlist-size large --recursive
  phantomrecon scan https://target.com -w /path/to/wordlist.txt -e php,asp,html

\033[1;32m▶  SCAN — Authentication & Headers\033[0m
  phantomrecon scan https://target.com --auth admin:password
  phantomrecon scan https://target.com --bearer eyJhbGciOi...
  phantomrecon scan https://target.com -H "X-API-Key: abc123" -H "Accept: application/json"
  phantomrecon scan https://target.com -c "session=abc123" -c "csrf=xyz"

\033[1;32m▶  SCAN — Proxies\033[0m
  phantomrecon scan https://target.com -p socks5://127.0.0.1:9050
  phantomrecon scan https://target.com -p http://proxy1:8080 -p http://proxy2:8080
  phantomrecon scan https://target.com -p socks5://127.0.0.1:9050 --rotate-proxy-every 10

\033[1;32m▶  SCAN — Output Formats\033[0m
  phantomrecon scan https://target.com -f json -f html -o ./results
  phantomrecon scan https://target.com -f csv -f xml -f sarif -f markdown
  phantomrecon scan https://target.com --save-db

\033[1;32m▶  SCAN — Filtering Results\033[0m
  phantomrecon scan https://target.com --exclude-codes 404,403
  phantomrecon scan https://target.com --include-codes 200,301,302
  phantomrecon scan https://target.com --filter "admin|config|backup"
  phantomrecon scan https://target.com --min-size 100 --max-size 50000

\033[1;32m▶  SCAN — Advanced Flags\033[0m
  phantomrecon scan https://target.com --exploit
  phantomrecon scan https://target.com --screenshot
  phantomrecon scan https://target.com --nuclei-export
  phantomrecon scan https://target.com --interactsh
  phantomrecon scan https://target.com --resume -v
  phantomrecon scan https://target.com --slack-webhook https://hooks.slack.com/...
  phantomrecon scan https://target.com --discord-webhook https://discord.com/api/...

\033[1;32m▶  SCAN — Config File\033[0m
  phantomrecon scan https://target.com --config scan.yaml
  phantomrecon gen-config myscan.yaml        # generate template first

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  FUZZ — Parameter & Header Fuzzing\033[0m
  phantomrecon fuzz https://target.com/search?q=test -T sqli -T xss
  phantomrecon fuzz https://target.com/page -p id -p user -T all
  phantomrecon fuzz https://target.com/api --fuzz-headers -T ssrf
  phantomrecon fuzz https://target.com/login --method POST -p username -p password -T sqli
  phantomrecon fuzz https://target.com/upload --fuzz-cookies -T lfi -T ssti
  phantomrecon fuzz https://target.com/redirect -T redirect -T crlf --nuclei-export
  phantomrecon fuzz https://target.com/cmd -T cmdi -T xxe -o results.json -v

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  DNS — Recon & Subdomain Enumeration\033[0m
  phantomrecon dns example.com
  phantomrecon dns example.com --subdomains
  phantomrecon dns example.com --passive
  phantomrecon dns example.com --subdomains --passive
  phantomrecon dns example.com --subdomains -w /usr/share/wordlists/subdomains.txt
  phantomrecon dns example.com --subdomains -t 100 -o dns_results.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  OSINT — Passive Intelligence Gathering\033[0m
  phantomrecon osint example.com --crt --wayback
  phantomrecon osint example.com --shodan-key YOUR_KEY --vt-key YOUR_KEY
  phantomrecon osint example.com --crt -o osint.json
  phantomrecon osint example.com --github-dork "example.com password"
  SHODAN_API_KEY=xxx phantomrecon osint example.com --shodan-key $SHODAN_API_KEY

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  DIFF — Compare Scan Reports\033[0m
  phantomrecon diff scan_old.json scan_new.json
  phantomrecon diff scan_old.json scan_new.json --html diff_report.html
  phantomrecon diff scan_old.json scan_new.json -o diff.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  SCHEDULE — Recurring Scans\033[0m
  phantomrecon schedule https://target.com --interval 24h
  phantomrecon schedule https://target.com --interval 6h --profile aggressive
  phantomrecon schedule https://target.com --interval 12h --slack-webhook https://hooks.slack.com/...
  phantomrecon schedule https://target.com --interval 1h --email-to sec@company.com --smtp-host smtp.gmail.com

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  CHAIN — Subdomain Pipeline Scan\033[0m
  phantomrecon chain https://target.com
  phantomrecon chain https://target.com --subdomain-passive --max-targets 20
  phantomrecon chain https://target.com --profile ghost --save-db
  phantomrecon chain https://target.com -t 50 -o chain_results/

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  PROXY-CHECK — Validate Proxy List\033[0m
  phantomrecon proxy-check proxies.txt
  phantomrecon proxy-check proxies.txt -o working.txt --min-score 50
  phantomrecon proxy-check proxies.txt -t 50 --timeout 5 --check-url https://httpbin.org/ip

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  HISTORY — Saved Scan Database\033[0m
  phantomrecon history --list
  phantomrecon history --show 3
  phantomrecon history --search "SQL injection"
  phantomrecon history --diff 2 5
  phantomrecon history --delete 1

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  PROFILES & CONFIG\033[0m
  phantomrecon profiles
  phantomrecon gen-config
  phantomrecon gen-config custom.yaml

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  JOHN — Expert Password Hash Cracking (35+ formats · 12 attack modes)\033[0m
  phantomrecon john --hash 5f4dcc3b5aa765d61d8327deb882cf99
  phantomrecon john --hash 5f4dcc3b5aa765d61d8327deb882cf99 --identify
  phantomrecon john --hash 5f4dcc3b5aa765d61d8327deb882cf99 --format md5
  phantomrecon john --hash-file hashes.txt -w /usr/share/wordlists/rockyou.txt
  phantomrecon john --hash-file hashes.txt -w rockyou.txt --rules
  phantomrecon john --hash-file hashes.txt --single
  phantomrecon john --hash-file hashes.txt --incremental --charset alnum --max-length 8
  phantomrecon john --hash-file hashes.txt --incremental --charset freq --min-length 4 --max-length 10
  phantomrecon john --hash-file hashes.txt --mask "?u?l?l?l?d?d"
  phantomrecon john --hash-file hashes.txt --mask "?d?d?d?d?d?d"
  phantomrecon john --hash-file hashes.txt --combinator -w w1.txt --wordlist2 w2.txt
  phantomrecon john --hash-file hashes.txt --prince -w wordlist.txt --prince-chains 3
  phantomrecon john --hash-file hashes.txt --markov --markov-train rockyou.txt --min-length 6 --max-length 10
  phantomrecon john --hash-file hashes.txt --keyboard
  phantomrecon john --hash-file hashes.txt --hybrid-wm -w rockyou.txt --mask "?d?d?d?d"
  phantomrecon john --hash-file hashes.txt --hybrid-mw --mask "?u?l?l" -w rockyou.txt
  phantomrecon john --hash-file hashes.txt --pattern
  phantomrecon john --hash-file hashes.txt --association --words "acme,admin,2024,john"
  phantomrecon john --hash-file hashes.txt -w rockyou.txt --session myjob
  phantomrecon john --hash-file hashes.txt --session myjob --restore
  phantomrecon john --shadow /etc/shadow -w rockyou.txt --rules
  phantomrecon john --hash-file ntlm.txt --format ntlm -w rockyou.txt --rules -t 8
  phantomrecon john --hash "$2b$12$..." --format bcrypt -w rockyou.txt
  phantomrecon john --hash-file hashes.txt --words "company,admin,2024" -t 8 -o cracked.json --show-failed
  phantomrecon john --show
  phantomrecon john --show --pot ~/.phantomrecon/john.pot

\033[1;36mSupported hash formats (35+):\033[0m
  md5  sha1  sha224  sha256  sha384  sha512  sha3_256  sha3_512
  md4  ntlm  lm  mysql323  mysql41  double_md5  half_md5  crc32
  md5crypt  sha256crypt  sha512crypt  bcrypt  blake2b  ripemd160
  whirlpool  sha1_upper  cisco_pix  wordpress  django_pbkdf2  oracle11g
  md5_salt  sha1_salt  sha256_salt  hmac_md5  hmac_sha1  hmac_sha256

\033[1;36mMask charset tokens:\033[0m
  ?l  lowercase a-z    ?u  uppercase A-Z    ?d  digits 0-9
  ?s  special chars    ?a  all printable    ?h  hex lowercase
  ?H  hex uppercase    ?n  newline/cr       ?b  full 8-bit byte

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  CERT-TRANSPARENCY — Subdomain Discovery via crt.sh + Email Harvest\033[0m
  phantomrecon cert-transparency example.com
  phantomrecon cert-transparency example.com --emails
  phantomrecon cert-transparency example.com --emails --hibp-key YOUR_KEY -o ct.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  PORT-SCAN — Built-in TCP/UDP Scanner (no nmap required)\033[0m
  phantomrecon port-scan 192.168.1.1
  phantomrecon port-scan 192.168.1.1 --ports top-1000 --banner
  phantomrecon port-scan 192.168.1.0/24 --ports 80,443,8080,8443 -t 500
  phantomrecon port-scan 10.0.0.1 --ports all --udp --scripts -o scan.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  NETWORK-RECON — IPv6, BGP/ASN, Cloud Assets, Topology\033[0m
  phantomrecon network-recon example.com --asn --geo
  phantomrecon network-recon example.com --cloud
  phantomrecon network-recon example.com --ipv6 --topology
  phantomrecon network-recon example.com --all-modules -o net.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  DNS-ADV — AXFR, DNSSEC, SPF/DMARC/DKIM, Subdomain Brute-force\033[0m
  phantomrecon dns-adv example.com --axfr
  phantomrecon dns-adv example.com --spf --dnssec
  phantomrecon dns-adv example.com --brute -w subdomains.txt
  phantomrecon dns-adv example.com --all-checks -o dns.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  EXPLOIT-CONFIRM — Auto-Confirm SQLi, XSS, RCE, SSRF, SSTI...\033[0m
  phantomrecon exploit-confirm "https://target.com/page?id=1" -T sqli
  phantomrecon exploit-confirm "https://target.com/search" -p q -T xss -T ssti
  phantomrecon exploit-confirm "https://target.com/api" -T ssrf -T rce -o confirmed.json
  phantomrecon exploit-confirm "https://target.com/file" -T traversal -T xxe

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  JWT — Full JWT Attack Suite\033[0m
  phantomrecon jwt eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx --analyze
  phantomrecon jwt <TOKEN> --alg-none
  phantomrecon jwt <TOKEN> --rs256-hs256 --pubkey public.pem
  phantomrecon jwt <TOKEN> --brute -w rockyou.txt
  phantomrecon jwt <TOKEN> --kid-inject
  phantomrecon jwt <TOKEN> --claim "role=admin"
  phantomrecon jwt <TOKEN> --all-attacks -o jwt_results.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  DESER — Deserialization Payload Injection\033[0m
  phantomrecon deser https://target.com/api --platform java --cmd id
  phantomrecon deser https://target.com/login --platform php --param remember_me
  phantomrecon deser https://target.com/api --platform dotnet --header X-Session
  phantomrecon deser https://target.com/api --platform all -o deser.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  OAUTH — OAuth 2.0 / OIDC Attack Suite\033[0m
  phantomrecon oauth https://auth.example.com/oauth/authorize --discovery
  phantomrecon oauth https://auth.example.com/oauth/authorize --client-id abc --state-fixation
  phantomrecon oauth https://auth.example.com/oauth/authorize --redirect-bypass --redirect-uri https://evil.com
  phantomrecon oauth https://auth.example.com/oauth/authorize --all-attacks -o oauth.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  2FA-BYPASS — 2FA Bypass Techniques\033[0m
  phantomrecon 2fa-bypass https://target.com/verify --response-manip
  phantomrecon 2fa-bypass https://target.com/otp --backup-brute --session "sess=abc"
  phantomrecon 2fa-bypass https://target.com/mfa --race
  phantomrecon 2fa-bypass https://target.com/mfa --null-otp --header-bypass
  phantomrecon 2fa-bypass https://target.com/mfa --all-attacks -o 2fa.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  SPRAY — Smart Password Spray with Lockout Avoidance\033[0m
  phantomrecon spray https://target.com/login --users users.txt --passwords common.txt
  phantomrecon spray https://target.com/login --users users.txt --password 'Summer2024!'
  phantomrecon spray https://target.com/api/login --mode json --users u.txt --passwords p.txt
  phantomrecon spray https://target.com/login --enumerate --users users.txt
  phantomrecon spray https://target.com/login --mode basic_auth -u users.txt -p pwds.txt --delay-min 30

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  PAYLOAD-GEN — Reverse Shells, Web Shells & WAF Bypass Encodings\033[0m
  phantomrecon payload-gen --type list
  phantomrecon payload-gen --type revshell --lang bash --lhost 10.0.0.1 --lport 4444
  phantomrecon payload-gen --type revshell --lang python3 --lhost 10.0.0.1 --lport 9001
  phantomrecon payload-gen --type revshell --lang powershell --lhost 10.0.0.1 --lport 443
  phantomrecon payload-gen --type webshell --lang php
  phantomrecon payload-gen --type encode --payload "' OR 1=1--" --encode url
  phantomrecon payload-gen --type encode --payload "<script>alert(1)</script>" --encode base64
  phantomrecon payload-gen --type polyglot

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  TAKEOVER — Subdomain Takeover Detection (50+ Services)\033[0m
  phantomrecon takeover example.com
  phantomrecon takeover subdomains.txt --threads 30
  phantomrecon takeover example.com -w subdomains-top1m.txt -o takeover.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  NUCLEI-RUN — Run Nuclei Templates (built-in Python fallback)\033[0m
  phantomrecon nuclei-run https://target.com
  phantomrecon nuclei-run https://target.com --tags cve --severity critical
  phantomrecon nuclei-run https://target.com --severity high --severity critical
  phantomrecon nuclei-run https://target.com --python-only
  phantomrecon nuclei-run https://target.com -t /path/to/templates/ -o nuclei.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  PROTOCOL-FUZZ — GraphQL, WebSocket, SMTP, SMB, Redis, Kerberos...\033[0m
  phantomrecon protocol-fuzz target.com --graphql --url https://target.com
  phantomrecon protocol-fuzz target.com --websocket --url https://target.com
  phantomrecon protocol-fuzz target.com --smtp --users users.txt
  phantomrecon protocol-fuzz target.com --ftp
  phantomrecon protocol-fuzz target.com --smb
  phantomrecon protocol-fuzz target.com --redis --mongodb --elasticsearch
  phantomrecon protocol-fuzz target.com --kerberos --realm CORP.LOCAL --users users.txt
  phantomrecon protocol-fuzz target.com --all-protocols --url https://target.com -o proto.json

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  ML-WORDLIST — AI-Powered Wordlist Generator (Markov + NLP)\033[0m
  phantomrecon ml-wordlist --train rockyou.txt --count 10000 -o smart.txt
  phantomrecon ml-wordlist --org "Acme Corp" --keywords "acme,admin,corp" -o acme.txt
  phantomrecon ml-wordlist --profile-text about_page.txt --org acme -o profiled.txt
  phantomrecon ml-wordlist --train rockyou.txt --org acme --count 20000 -o combined.txt
  phantomrecon ml-wordlist --train rockyou.txt --order 4 --min-len 8 --max-len 16 -o long.txt

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  STEALTH-CHECK — HTTP/2, HTTP/3, Entropy Scan, Polyglot\033[0m
  phantomrecon stealth-check https://target.com --http2 --http3
  phantomrecon stealth-check https://target.com --entropy-scan
  phantomrecon stealth-check https://target.com --polyglot
  phantomrecon stealth-check https://target.com --all-checks

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  THREAT-INTEL — VirusTotal, AbuseIPDB, Shodan, MITRE ATT&CK Report\033[0m
  phantomrecon threat-intel 1.2.3.4 --vt-key YOUR_KEY --shodan-key YOUR_KEY
  phantomrecon threat-intel example.com --vt-key YOUR_KEY
  phantomrecon threat-intel example.com --findings scan.json --report report.html
  phantomrecon threat-intel example.com --findings scan.json --report-text report.txt
  phantomrecon threat-intel example.com --findings scan.json --diff-baseline baseline.json
  phantomrecon threat-intel example.com --findings scan.json --save-baseline

\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
\033[1;32m▶  SUBCOMMAND HELP\033[0m
  phantomrecon scan --help            phantomrecon fuzz --help
  phantomrecon dns --help             phantomrecon osint --help
  phantomrecon diff --help            phantomrecon schedule --help
  phantomrecon chain --help           phantomrecon proxy-check --help
  phantomrecon history --help         phantomrecon john --help
  phantomrecon cert-transparency -h   phantomrecon port-scan -h
  phantomrecon network-recon -h       phantomrecon dns-adv -h
  phantomrecon exploit-confirm -h     phantomrecon jwt -h
  phantomrecon deser -h               phantomrecon oauth -h
  phantomrecon 2fa-bypass -h          phantomrecon spray -h
  phantomrecon payload-gen -h         phantomrecon takeover -h
  phantomrecon nuclei-run -h          phantomrecon protocol-fuzz -h
  phantomrecon ml-wordlist -h         phantomrecon stealth-check -h
  phantomrecon threat-intel -h
\033[1;33m─────────────────────────────────────────────────────────────────────\033[0m
"""


class _RichGroup(click.Group):
    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        click.echo(HELP_EXAMPLES)


@click.group(cls=_RichGroup, invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx: click.Context) -> None:
    """PhantomRecon - Advanced Web Reconnaissance & Vulnerability Assessment"""
    if ctx.invoked_subcommand is None:
        click.echo(HELP_EXAMPLES)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------
@cli.command(name="scan", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", callback=validate_target, is_eager=True)
@click.option("--profile", default=None,
              type=click.Choice(list(PROFILES.keys()), case_sensitive=False),
              help="Scan profile: ghost/shadow/balanced/aggressive")
@click.option("--config", "config_file", default=None, help="YAML config file path")
@click.option("-t", "--threads", default=None, type=int, help="Concurrent threads (1-1000)")
@click.option("--timeout", default=None, type=int, help="Request timeout (seconds)")
@click.option("--retries", default=None, type=int, help="Request retry count")
@click.option("--delay-min", default=None, type=float, help="Min delay between requests (seconds)")
@click.option("--delay-max", default=None, type=float, help="Max delay between requests (seconds)")
@click.option("--rate", default=None, type=int, help="Max requests/second (0=unlimited)")
@click.option("-w", "--wordlist", default=None, help="Custom wordlist file path")
@click.option("--wordlist-size", default=None,
              type=click.Choice(["micro", "small", "medium", "large"], case_sensitive=False),
              help="Built-in wordlist size")
@click.option("-e", "--extensions", default=None, help="Extensions to fuzz (comma-separated)")
@click.option("--recursive/--no-recursive", default=None, help="Enable recursive directory scanning")
@click.option("--depth", default=None, type=int, help="Max recursion depth")
@click.option("-p", "--proxy", multiple=True, help="Proxy URL (can specify multiple)")
@click.option("--rotate-proxy-every", default=None, type=int, help="Rotate proxy every N requests")
@click.option("-u", "--user-agent", default=None, help="Custom User-Agent string")
@click.option("--no-rotate-ua", is_flag=True, default=False, help="Disable User-Agent rotation")
@click.option("-H", "--header", multiple=True, help="Custom header (Name: Value)")
@click.option("-c", "--cookie", multiple=True, help="Cookies (name=value)")
@click.option("--auth", default=None, help="Basic auth (user:password)")
@click.option("--bearer", default=None, help="Bearer token")
@click.option("--no-follow-redirects", is_flag=True, default=False)
@click.option("--verify-ssl", is_flag=True, default=False)
@click.option("-m", "--module", multiple=True,
              type=click.Choice([m.value for m in ScanModule], case_sensitive=False),
              help="Run specific module(s)")
@click.option("-o", "--output-dir", default=".", show_default=True)
@click.option("-f", "--format", "formats", multiple=True,
              type=click.Choice(["json", "html", "csv", "xml", "markdown", "sarif"], case_sensitive=False))
@click.option("--include-codes", default=None, help="Only show these status codes (comma-separated)")
@click.option("--exclude-codes", default=None, help="Exclude these status codes")
@click.option("--min-size", default=None, type=int)
@click.option("--max-size", default=None, type=int)
@click.option("--filter", "filter_regex", default=None, help="Only show responses matching regex")
@click.option("--exclude", "exclude_regex", default=None, help="Exclude responses matching regex")
@click.option("--resume", is_flag=True, default=False, help="Resume previous interrupted scan")
# New advanced flags
@click.option("--exploit", is_flag=True, default=False, help="Attempt to exploit confirmed vulns (LFI, redirect, SSRF, XXE)")
@click.option("--screenshot", is_flag=True, default=False, help="Headless browser screenshot of every discovered URL")
@click.option("--nuclei-export", is_flag=True, default=False, help="Export findings as Nuclei templates")
@click.option("--slack-webhook", default=None, help="Slack webhook URL for critical/high alerts")
@click.option("--discord-webhook", default=None, help="Discord webhook URL for critical/high alerts")
@click.option("--save-db", is_flag=True, default=False, help="Persist scan results to SQLite history DB")
@click.option("--interactsh", default=None, help="Interactsh server for OOB detection (default: oast.pro)")
@click.option("-v", "--verbose", count=True, help="Verbosity (-v, -vv)")
@click.option("-q", "--quiet", is_flag=True, default=False)
@click.version_option(__version__, "-V", "--version")
def scan(
    target, profile, config_file, threads, timeout, retries,
    delay_min, delay_max, rate, wordlist, wordlist_size, extensions,
    recursive, depth, proxy, rotate_proxy_every, user_agent, no_rotate_ua,
    header, cookie, auth, bearer, no_follow_redirects, verify_ssl, module,
    output_dir, formats, include_codes, exclude_codes, min_size, max_size,
    filter_regex, exclude_regex, resume, exploit, screenshot, nuclei_export,
    slack_webhook, discord_webhook, save_db, interactsh, verbose, quiet,
) -> None:
    """Scan TARGET for vulnerabilities, directories, and misconfigurations."""
    ui = TerminalUI(verbosity=verbose)
    if not quiet:
        ui.banner()

    merged: dict[str, Any] = {}
    if config_file:
        try:
            merged = merge_config(merged, load_config_file(config_file))
        except Exception as e:
            ui.error(f"Failed to load config: {e}")
            sys.exit(1)
    if profile:
        try:
            p = load_profile(profile)
            p.pop("description", None)
            merged = merge_config(merged, p)
        except Exception as e:
            ui.error(f"Failed to load profile: {e}")
            sys.exit(1)

    extra_headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            n, _, v = h.partition(":")
            extra_headers[n.strip()] = v.strip()

    cookies: dict[str, str] = {}
    for c in cookie:
        if "=" in c:
            n, _, v = c.partition("=")
            cookies[n.strip()] = v.strip()

    auth_tuple: Optional[tuple[str, str]] = None
    if auth:
        if ":" not in auth:
            ui.error("--auth must be 'user:password'")
            sys.exit(1)
        u, _, p2 = auth.partition(":")
        auth_tuple = (u, p2)

    ext_list = [e.strip().lstrip(".") for e in extensions.split(",") if e.strip()] if extensions else merged.get("extensions", [])
    raw_inc = include_codes or merged.get("include_codes", "")
    raw_exc = exclude_codes or merged.get("exclude_codes", "404")
    inc_list = [int(x.strip()) for x in str(raw_inc).split(",") if x.strip().isdigit()]
    exc_list = [int(x.strip()) for x in str(raw_exc).split(",") if x.strip().isdigit()] if raw_exc else [404]

    selected_modules: list[ScanModule] = []
    if module:
        selected_modules = [ScanModule(m) for m in module]
    elif merged.get("modules"):
        selected_modules = [ScanModule(m) for m in merged["modules"]]

    formats_list = list(formats) if formats else merged.get("output_formats", ["json", "html"])

    config = ScanConfig(
        target=target,
        threads=max(1, min(threads or merged.get("threads", 50), 1000)),
        timeout=timeout or merged.get("timeout", 10),
        retries=retries or merged.get("retries", 2),
        delay_min=delay_min if delay_min is not None else merged.get("delay_min", 0.0),
        delay_max=delay_max if delay_max is not None else merged.get("delay_max", 0.5),
        rate_limit=rate if rate is not None else merged.get("rate_limit", 0),
        wordlist=wordlist or merged.get("wordlist"),
        wordlist_size=wordlist_size or merged.get("wordlist_size", "medium"),
        extensions=ext_list if isinstance(ext_list, list) else [],
        recursive=recursive if recursive is not None else merged.get("recursive", False),
        recursion_depth=depth or merged.get("recursion_depth", 3),
        proxies=list(proxy) or merged.get("proxies", []),
        rotate_proxy_every=rotate_proxy_every or merged.get("rotate_proxy_every", 10),
        user_agent=user_agent or merged.get("user_agent"),
        rotate_ua=not no_rotate_ua and merged.get("rotate_ua", True),
        headers=extra_headers or merged.get("headers", {}),
        cookies=cookies or merged.get("cookies", {}),
        auth=auth_tuple,
        auth_type="basic",
        bearer_token=bearer or merged.get("bearer"),
        follow_redirects=not no_follow_redirects and merged.get("follow_redirects", True),
        verify_ssl=verify_ssl or merged.get("verify_ssl", False),
        modules=selected_modules,
        output_dir=output_dir,
        output_formats=formats_list,
        verbosity=verbose or merged.get("verbosity", 1),
        include_codes=inc_list,
        exclude_codes=exc_list,
        min_size=min_size if min_size is not None else merged.get("min_size", 0),
        max_size=max_size if max_size is not None else merged.get("max_size", 0),
        filter_regex=filter_regex or merged.get("filter_regex"),
        exclude_regex=exclude_regex or merged.get("exclude_regex"),
    )

    state_manager = StateManager(state_dir=output_dir)
    scan_id = str(uuid.uuid4())[:8]
    if resume:
        existing = state_manager.find_resumable(target)
        if existing:
            scan_id = existing.scan_id
            if not quiet:
                ui.info(f"Resuming scan {scan_id}")
        else:
            if not quiet:
                ui.warning("No resumable scan found, starting fresh.")
    state = state_manager.create_state(target, scan_id)

    if not quiet:
        ui.print_config(target, config)

    notifier = None
    if slack_webhook or discord_webhook:
        from .notifications import NotificationManager
        notifier = NotificationManager(slack_webhook=slack_webhook, discord_webhook=discord_webhook)

    interactsh_client = None
    if interactsh is not None:
        from .modules.interactsh import InteractshClient
        server = interactsh if interactsh else None
        interactsh_client = InteractshClient(server=server)
        if not quiet:
            ui.info(f"Interactsh server: {interactsh_client.server}")

    def ui_callback(event: str, data: dict) -> None:
        if not quiet:
            ui.handle_event(event, data)
        if event == "module_done":
            state_manager.mark_module_done(state, data.get("module", ""))
        if event == "finding" and notifier:
            notifier.notify_finding(data, target)

    engine = ScanEngine(config, ui_callback=ui_callback)

    try:
        result = asyncio.run(engine.run())
    except KeyboardInterrupt:
        ui.warning("Scan interrupted.")
        result = engine.result
        result.end_time = __import__("time").time()

    state_manager.cleanup(state)

    # Post-scan: screenshots
    if screenshot and result.discovered_paths:
        if not quiet:
            ui.info(f"Taking screenshots of {min(50, len(result.discovered_paths))} paths...")
        from .modules.screenshot import ScreenshotModule
        ss_dir = str(Path(output_dir) / "screenshots")
        ss_module = ScreenshotModule(output_dir=ss_dir, threads=3)
        urls = [p.url for p in result.discovered_paths[:50]]
        try:
            asyncio.run(ss_module.screenshot_urls(urls))
            if not quiet:
                ui.info(f"Screenshots saved to {ss_dir}")
        except Exception as e:
            ui.warning(f"Screenshot error: {e}")

    # Post-scan: exploit
    if exploit and result.findings:
        if not quiet:
            ui.info("Running exploit engine on confirmed findings...")
        from .modules.exploit_engine import ExploitEngine
        exploit_engine = ExploitEngine(timeout=10, interactsh_client=interactsh_client)
        exploit_results = asyncio.run(exploit_engine.run_all(result.findings, target))
        for er in exploit_results:
            if er.success:
                finding = er.to_finding()
                result.add_finding(finding)
                if not quiet:
                    ui.info(f"[EXPLOIT] {er.vuln_type} confirmed: {er.url}")

    # Post-scan: nuclei export
    if nuclei_export and result.findings:
        from .modules.fuzz_engine import FuzzEngine
        fuzz_eng = FuzzEngine()
        nuclei_dir = str(Path(output_dir) / "nuclei_templates")
        Path(nuclei_dir).mkdir(parents=True, exist_ok=True)
        count = 0
        for finding in result.findings:
            f_dict = {
                "title": finding.title,
                "severity": finding.severity.value,
                "url": finding.url,
                "description": finding.description,
                "evidence": finding.evidence,
                "vuln_type": finding.module.value,
            }
            templates = fuzz_eng.generate_nuclei_templates([type('FR', (), f_dict)()])
            for tmpl in templates:
                fname = Path(nuclei_dir) / f"{finding.title[:40].replace(' ', '_').lower()}.yaml"
                fname.write_text(tmpl)
                count += 1
        if not quiet:
            ui.info(f"Exported {count} Nuclei templates to {nuclei_dir}")

    # Post-scan: save to DB
    if save_db:
        try:
            from .database import ScanDatabase
            db = ScanDatabase()
            db.save_scan(result)
            if not quiet:
                ui.info("Scan saved to history database (~/.phantomrecon/history.db)")
        except Exception as e:
            ui.warning(f"DB save error: {e}")

    # Notifications
    if notifier:
        summary = {
            "target": target,
            "total_findings": len(result.findings),
            "critical": sum(1 for f in result.findings if f.severity.value == "critical"),
            "high": sum(1 for f in result.findings if f.severity.value == "high"),
            "paths": len(result.discovered_paths),
            "requests": result.total_requests,
            "duration": result.duration,
        }
        notifier.notify_scan_complete(summary)

    if not quiet:
        ui.print_technologies(result)
        ui.print_findings_summary(result)
        ui.print_discovered_paths(result, limit=50)

    reporter = Reporter(output_dir=output_dir)
    saved = reporter.save_all(result, formats_list)
    if not quiet:
        ui.print_report_paths(saved)

    critical_high = sum(1 for f in result.findings if f.severity.value in ("critical", "high"))
    sys.exit(1 if critical_high > 0 else 0)


# ---------------------------------------------------------------------------
# john
# ---------------------------------------------------------------------------
@cli.command(name="john", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", default="")
@click.option("--hash",          "single_hash",   default=None, help="Single hash string to crack")
@click.option("--hash-file",     "hash_file",     default=None, help="File containing hashes (one per line or user:hash format)")
@click.option("--shadow",        "shadow_file",   default=None, help="Linux /etc/shadow file")
@click.option("--format",        "fmt",
              type=click.Choice([
                  "md5","sha1","sha224","sha256","sha384","sha512",
                  "sha3_256","sha3_512","md4","ntlm","lm","mysql323","mysql41",
                  "md5crypt","sha256crypt","sha512crypt","bcrypt",
                  "blake2b","ripemd160","double_md5","sha1_upper",
                  "wordpress","django_pbkdf2","oracle11g",
                  "md5_salt","sha1_salt","sha256_salt",
                  "hmac_md5","hmac_sha1","hmac_sha256",
                  "crc32","cisco_pix","half_md5","whirlpool","auto",
              ], case_sensitive=False),
              default="auto", show_default=True,
              help="Force hash format (auto = detect)")
@click.option("-w","--wordlist",      default=None, help="Primary wordlist for dictionary/combinator/prince attack")
@click.option("--wordlist2",          default=None, help="Second wordlist for combinator attack")
@click.option("--rules",              is_flag=True, default=False,  help="Apply JtR-compatible mangling rules (150+ rules)")
@click.option("--single",             is_flag=True, default=False,  help="Single crack mode (built-in common passwords + rules)")
@click.option("--incremental",        is_flag=True, default=False,  help="Brute-force incremental mode")
@click.option("--charset",            default="all", show_default=True,
              type=click.Choice(["alpha","upper","lower","digits","alnum","hex","ascii","all","lm","freq"], case_sensitive=False),
              help="Character set for incremental mode")
@click.option("--min-length",         default=1,  show_default=True, type=int, help="Min password length (incremental/markov)")
@click.option("--max-length",         default=6,  show_default=True, type=int, help="Max password length (incremental/markov)")
@click.option("--mask",               default=None, help="Mask attack pattern (e.g. ?u?l?l?l?d?d)")
@click.option("--combinator",         is_flag=True, default=False, help="Combinator attack: cross-product of --wordlist x --wordlist2")
@click.option("--prince",             is_flag=True, default=False, help="PRINCE attack: chain-combine elements from wordlist")
@click.option("--prince-chains",      default=2, show_default=True, type=int, help="Max chain length for PRINCE attack")
@click.option("--markov",             is_flag=True, default=False, help="Markov chain statistical password generation")
@click.option("--markov-train",       "markov_train", default=None, help="Train Markov model from this wordlist file")
@click.option("--keyboard",           is_flag=True, default=False, help="Keyboard walk attack (QWERTY/AZERTY/Dvorak patterns)")
@click.option("--hybrid-wm",          "hybrid_wm", is_flag=True, default=False, help="Hybrid attack: wordlist + mask suffix")
@click.option("--hybrid-mw",          "hybrid_mw", is_flag=True, default=False, help="Hybrid attack: mask prefix + wordlist")
@click.option("--pattern",            is_flag=True, default=False, help="Pattern attack: seasonal, year, suffix/prefix combos")
@click.option("--association",        is_flag=True, default=False, help="Association attack using --words as target context")
@click.option("--session",            "session_name", default=None, help="Session name for save/restore (e.g. myjob)")
@click.option("--restore",            is_flag=True, default=False, help="Restore previous cracking session (requires --session)")
@click.option("--show",               is_flag=True, default=False, help="Show all previously cracked hashes from pot file")
@click.option("--show-failed",        is_flag=True, default=False, help="Also display uncracked hashes in output")
@click.option("--identify",           is_flag=True, default=False, help="Identify hash type only (no cracking)")
@click.option("--pot",                "pot_file", default=None, help="Custom pot file path (default: ~/.phantomrecon/john.pot)")
@click.option("-t","--threads",       default=4,  show_default=True, type=int, help="Worker threads")
@click.option("--max-candidates",     default=50_000_000, show_default=True, type=int,
              help="Max candidates per attack mode")
@click.option("--words",              default=None, help="Comma-separated target-context words for association/rule attack")
@click.option("-o","--output",        default=None, help="Save cracked results to JSON file")
@click.option("--no-single",          is_flag=True, default=False, help="Skip built-in single-crack mode")
@click.option("-v","--verbose",       is_flag=True, default=False)
def john_cmd(
    target, single_hash, hash_file, shadow_file, fmt,
    wordlist, wordlist2, rules, single, incremental, charset,
    min_length, max_length, mask,
    combinator, prince, prince_chains,
    markov, markov_train, keyboard,
    hybrid_wm, hybrid_mw, pattern, association,
    session_name, restore,
    show, show_failed, identify, pot_file, threads, max_candidates,
    words, output, no_single, verbose,
) -> None:
    """John the Ripper — expert password hash cracker (35+ formats, 12 attack modes).

    \b
    Supported hash formats (35+):
      md5  sha1  sha224  sha256  sha384  sha512  sha3_256  sha3_512
      md4  ntlm  lm  mysql323  mysql41  double_md5  half_md5  crc32
      md5crypt($1$)  sha256crypt($5$)  sha512crypt($6$)  bcrypt($2b$)
      blake2b  ripemd160  whirlpool  sha1_upper  cisco_pix
      wordpress($P$/$H$)  django_pbkdf2  oracle11g
      md5_salt  sha1_salt  sha256_salt  hmac_md5  hmac_sha1  hmac_sha256

    \b
    Attack modes (12):
      dictionary   -w rockyou.txt
      rules        -w rockyou.txt --rules          (150+ JtR-compatible rules)
      single       --single                         (built-in common passwords)
      incremental  --incremental --charset alnum    (brute-force)
      mask         --mask ?u?l?l?l?d?d             (hashcat-style masks)
      combinator   --combinator -w w1.txt --wordlist2 w2.txt
      prince       --prince -w wordlist.txt         (PRINCE element-chain)
      markov       --markov --markov-train words.txt (statistical generation)
      keyboard     --keyboard                        (QWERTY/AZERTY walks)
      hybrid-wm    --hybrid-wm -w list.txt --mask ?d?d?d
      hybrid-mw    --hybrid-mw --mask ?u?l?l --wordlist list.txt
      pattern      --pattern                         (seasonal/year patterns)
      association  --association --words "company,admin,2024"

    \b
    Mask charset tokens:
      ?l  lowercase a-z    ?u  uppercase A-Z    ?d  digits 0-9
      ?s  special chars    ?a  all printable    ?h  hex lowercase
      ?H  hex uppercase    ?n  newline/cr       ?b  full 8-bit byte

    \b
    Examples:
      phantomrecon john --hash 5f4dcc3b5aa765d61d8327deb882cf99
      phantomrecon john --hash 5f4dcc3b5aa765d61d8327deb882cf99 --format md5
      phantomrecon john --hash 5f4dcc3b5aa765d61d8327deb882cf99 --identify
      phantomrecon john --hash-file hashes.txt -w rockyou.txt
      phantomrecon john --hash-file hashes.txt -w rockyou.txt --rules
      phantomrecon john --hash-file hashes.txt --single
      phantomrecon john --hash-file hashes.txt --incremental --charset alnum --max-length 8
      phantomrecon john --hash-file hashes.txt --mask "?u?l?l?l?d?d"
      phantomrecon john --hash-file hashes.txt --combinator -w w1.txt --wordlist2 w2.txt
      phantomrecon john --hash-file hashes.txt --prince -w wordlist.txt --prince-chains 3
      phantomrecon john --hash-file hashes.txt --markov --markov-train rockyou.txt --min-length 6 --max-length 10
      phantomrecon john --hash-file hashes.txt --keyboard
      phantomrecon john --hash-file hashes.txt --hybrid-wm -w rockyou.txt --mask "?d?d?d?d"
      phantomrecon john --hash-file hashes.txt --hybrid-mw --mask "?u?l?l" -w rockyou.txt
      phantomrecon john --hash-file hashes.txt --pattern
      phantomrecon john --hash-file hashes.txt --association --words "acme,admin,2024,john"
      phantomrecon john --hash-file hashes.txt -w rockyou.txt --session myjob
      phantomrecon john --hash-file hashes.txt --session myjob --restore
      phantomrecon john --shadow /etc/shadow -w rockyou.txt --rules
      phantomrecon john --hash-file ntlm.txt --format ntlm -w rockyou.txt --rules -t 8
      phantomrecon john --show
      phantomrecon john --show --pot ~/.phantomrecon/john.pot
    """
    from .modules.john import (
        HashIdentifier, JohnCracker, HashFormat, FORMAT_ALIASES,
        load_hashes_from_file, load_shadow_file,
        format_results_table, PotFile,
    )

    # ── show pot file ────────────────────────────────────────────────────────
    if show and not single_hash and not hash_file and not shadow_file and not target:
        pot = PotFile(pot_file)
        entries = pot.list_all()
        if not entries:
            click.echo("[*] Pot file is empty. No passwords cracked yet.")
            return
        click.echo(f"\n[+] Cracked passwords in pot file ({len(entries)} entries):\n")
        click.echo(f"  {'HASH':<50} PASSWORD")
        click.echo(f"  {'─'*50} {'─'*30}")
        for h, pwd in entries:
            h_disp = h[:48] + '..' if len(h) > 50 else h
            click.echo(f"  {h_disp:<50} {pwd}")
        return

    # ── collect hashes ───────────────────────────────────────────────────────
    hashes: list[str] = []
    usernames: dict[str, str] = {}

    if single_hash:
        hashes.append(single_hash.strip())

    if target and not target.startswith("http"):
        hashes.append(target.strip())

    if hash_file:
        try:
            loaded = load_hashes_from_file(hash_file)
            hashes.extend(loaded)
            click.echo(f"[*] Loaded {len(loaded)} hashes from {hash_file}")
        except Exception as e:
            click.echo(f"[-] Error reading hash file: {e}", err=True)
            sys.exit(1)

    if shadow_file:
        try:
            entries = load_shadow_file(shadow_file)
            for user, pw_hash in entries:
                hashes.append(pw_hash)
                usernames[pw_hash] = user
            click.echo(f"[*] Loaded {len(entries)} hashes from shadow file: {shadow_file}")
        except Exception as e:
            click.echo(f"[-] Error reading shadow file: {e}", err=True)
            sys.exit(1)

    if not hashes:
        click.echo("[-] No hashes provided. Use --hash, --hash-file, or --shadow", err=True)
        sys.exit(1)

    hashes = list(dict.fromkeys(hashes))

    # ── identify only ────────────────────────────────────────────────────────
    if identify:
        click.echo(f"\n[*] Hash Identification ({len(hashes)} hash{'es' if len(hashes) != 1 else ''}):\n")
        click.echo(f"  {'HASH':<50} POSSIBLE FORMATS")
        click.echo(f"  {'─'*50} {'─'*30}")
        for h in hashes:
            candidates = HashIdentifier.identify(h)
            h_disp = h[:48] + '..' if len(h) > 50 else h
            fmt_names = ', '.join(f.value for f in candidates)
            click.echo(f"  {h_disp:<50} {fmt_names}")
        return

    # ── resolve format ───────────────────────────────────────────────────────
    resolved_fmt: HashFormat | None = None
    if fmt and fmt != "auto":
        resolved_fmt = FORMAT_ALIASES.get(fmt.lower())
        if not resolved_fmt:
            try:
                resolved_fmt = HashFormat(fmt.lower())
            except ValueError:
                click.echo(f"[-] Unknown format: {fmt}", err=True)
                sys.exit(1)

    # ── banner ───────────────────────────────────────────────────────────────
    active_modes = []
    if wordlist and not combinator and not hybrid_wm and not hybrid_mw and not prince:
        active_modes.append("dictionary")
    if rules:                active_modes.append("rules")
    if single or (not wordlist and not incremental and not mask and not combinator
                  and not prince and not markov and not keyboard
                  and not hybrid_wm and not hybrid_mw and not pattern
                  and not association and not no_single):
        active_modes.append("single")
    if incremental:          active_modes.append("incremental")
    if mask:                 active_modes.append("mask")
    if combinator:           active_modes.append("combinator")
    if prince:               active_modes.append("prince")
    if markov:               active_modes.append("markov")
    if keyboard:             active_modes.append("keyboard")
    if hybrid_wm:            active_modes.append("hybrid-wm")
    if hybrid_mw:            active_modes.append("hybrid-mw")
    if pattern:              active_modes.append("pattern")
    if association:          active_modes.append("association")

    click.echo(f"""
\033[1;32m╔══════════════════════════════════════════════════════════════╗
║       JOHN THE RIPPER — PhantomRecon Expert Edition          ║
║            35+ formats · 12 attack modes · 150+ rules        ║
╚══════════════════════════════════════════════════════════════╝\033[0m
  Hashes      : {len(hashes)}
  Format      : {resolved_fmt.value if resolved_fmt else 'auto-detect'}
  Threads     : {threads}
  Attack modes: {', '.join(active_modes) or 'single'}
  Wordlist    : {wordlist or '—'}
  Wordlist2   : {wordlist2 or '—'}
  Rules       : {'yes (150+ JtR rules)' if rules else 'no'}
  Mask        : {mask or '—'}
  Incremental : {'yes (' + charset + ' ' + str(min_length) + '-' + str(max_length) + ')' if incremental else 'no'}
  Markov      : {'yes (train=' + (markov_train or 'built-in') + ' len=' + str(min_length) + '-' + str(max_length) + ')' if markov else 'no'}
  Session     : {session_name or '—'}{' [RESTORE]' if restore else ''}
""")

    for h in hashes:
        auto_fmt = HashIdentifier.identify_best(h)
        user = usernames.get(h, "")
        user_str = f" [{user}]" if user else ""
        click.echo(f"  [*]{user_str} {h[:60]} → {auto_fmt.value}")

    click.echo()

    # ── progress callback ────────────────────────────────────────────────────
    _last_print = [0]

    def _progress(done: int, total: int, attack: str, current: str) -> None:
        now = time.time()
        if now - _last_print[0] > 1.0:
            pct = f"{done/total*100:.1f}%" if total else f"{done}"
            click.echo(f"\r  [{attack}] {pct} — {done:,} tried — last: {current[:30]:<30}", nl=False)
            _last_print[0] = now

    # ── run cracker ──────────────────────────────────────────────────────────
    cracker = JohnCracker(
        hashes=hashes,
        fmt=resolved_fmt,
        pot_file=pot_file,
        threads=threads,
        progress_cb=_progress if verbose else None,
        verbose=verbose,
        session=session_name,
    )

    target_words: list[str] = []
    if words:
        target_words = [w.strip() for w in words.split(',') if w.strip()]

    _auto_single = (
        not wordlist and not incremental and not mask and not combinator
        and not prince and not markov and not keyboard
        and not hybrid_wm and not hybrid_mw and not pattern
        and not association and not no_single
    )

    try:
        results = cracker.run_all(
            wordlist=wordlist,
            wordlist2=wordlist2,
            rules=rules,
            incremental=incremental,
            charset=charset,
            min_len=min_length,
            max_len=max_length,
            mask=mask,
            single=single or _auto_single,
            combinator=combinator,
            prince=prince,
            prince_chains=prince_chains,
            markov=markov,
            markov_train=markov_train,
            markov_min=min_length,
            markov_max=max_length,
            keyboard=keyboard,
            hybrid_wm=hybrid_wm,
            hybrid_mw=hybrid_mw,
            pattern=pattern,
            association=association or bool(target_words),
            association_words=target_words or None,
            max_candidates=max_candidates,
            restore=restore,
        )
    except KeyboardInterrupt:
        cracker.stop()
        click.echo("\n[!] Cracking interrupted.")
        results = cracker.results

    if session_name and cracker._session and results:
        cracker._session.save({'results': results})
        click.echo(f"[*] Session saved: {session_name}")

    if verbose:
        click.echo()

    # ── print results ────────────────────────────────────────────────────────
    cracked = [r for r in results.values() if r.cracked]
    failed  = [r for r in results.values() if not r.cracked]

    click.echo(format_results_table(results, show_failed=show_failed))

    if cracked:
        click.echo(f"\033[1;32m[+] SESSION COMPLETE — {len(cracked)}/{len(hashes)} passwords cracked\033[0m\n")
        for r in cracked:
            user = usernames.get(r.hash_str, "")
            user_str = f"{user}:" if user else ""
            h_disp = r.hash_str[:48] + '..' if len(r.hash_str) > 50 else r.hash_str
            click.echo(f"  \033[1;32m✓\033[0m  {user_str}{h_disp} : \033[1;33m{r.password}\033[0m  [{r.fmt.value}] [{r.attack}]")
    else:
        click.echo(f"\033[1;31m[-] No passwords cracked.\033[0m")
        click.echo("[*] Try: --wordlist rockyou.txt --rules, or --incremental --max-length 8")

    click.echo(f"\n[*] Pot file: {PotFile(pot_file).path}")
    click.echo(f"[*] Stats: {sum(r.attempts for r in results.values()):,} candidates tested\n")

    if output:
        data = []
        for r in results.values():
            data.append({
                "hash": r.hash_str,
                "password": r.password,
                "format": r.fmt.value,
                "cracked": r.cracked,
                "attack": r.attack,
                "attempts": r.attempts,
                "elapsed": round(r.elapsed, 3),
                "username": usernames.get(r.hash_str, ""),
            })
        Path(output).write_text(json.dumps(data, indent=2))
        click.echo(f"[+] Results saved to {output}")

    sys.exit(0 if cracked else 1)


# ---------------------------------------------------------------------------
# fuzz
# ---------------------------------------------------------------------------
@cli.command(name="fuzz", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("--param", "-p", multiple=True, help="Parameter name(s) to fuzz")
@click.option("--method", "-X", default="GET", type=click.Choice(["GET", "POST", "PUT", "PATCH"], case_sensitive=False), show_default=True)
@click.option("--payload-type", "-T", multiple=True,
              type=click.Choice(["sqli", "xss", "lfi", "ssti", "ssrf", "xxe", "redirect", "crlf", "cmdi", "all"], case_sensitive=False),
              help="Payload type(s) to use [default: all]")
@click.option("--fuzz-headers", is_flag=True, default=False, help="Also fuzz common headers")
@click.option("--fuzz-cookies", is_flag=True, default=False, help="Also fuzz cookies")
@click.option("-t", "--threads", default=10, show_default=True, help="Concurrent requests")
@click.option("--timeout", default=10, show_default=True, help="Request timeout (seconds)")
@click.option("--proxy", default=None, help="Proxy URL")
@click.option("--nuclei-export", is_flag=True, default=False, help="Export confirmed findings as Nuclei templates")
@click.option("-o", "--output", default=None, help="Output JSON file for results")
@click.option("-v", "--verbose", is_flag=True, default=False)
def fuzz_cmd(url, param, method, payload_type, fuzz_headers, fuzz_cookies,
             threads, timeout, proxy, nuclei_export, output, verbose) -> None:
    """Fuzz URL parameters, headers, and cookies with attack payloads.

    \b
    Examples:
      phantomrecon fuzz https://target.com/search?q=test -T sqli -T xss
      phantomrecon fuzz https://target.com/page -p id -p user --method GET -T all
      phantomrecon fuzz https://target.com/api --fuzz-headers -T ssrf
    """
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    from .modules.fuzz_engine import FuzzEngine

    types = list(payload_type) if payload_type else ["all"]
    if "all" in types:
        types = ["sqli", "xss", "lfi", "ssti", "ssrf", "xxe", "redirect", "crlf", "cmdi"]

    click.echo(f"[*] Fuzzing: {url}")
    click.echo(f"[*] Payload types: {', '.join(types)}")
    click.echo(f"[*] Method: {method}")

    proxies = [proxy] if proxy else []
    engine = FuzzEngine(threads=threads, timeout=timeout, proxies=proxies)

    async def _run():
        results = []
        params = list(param) if param else None
        if method.upper() in ("GET", ""):
            res = await engine.fuzz_url_params(url, params=params, payload_types=types)
            results.extend(res)
        if method.upper() in ("POST", "PUT", "PATCH"):
            res = await engine.fuzz_post_params(url, method=method.upper(), params=params, payload_types=types)
            results.extend(res)
        if fuzz_headers:
            res = await engine.fuzz_headers(url, payload_types=types)
            results.extend(res)
        if fuzz_cookies:
            res = await engine.fuzz_cookies(url, payload_types=types)
            results.extend(res)
        return results

    results = asyncio.run(_run())
    confirmed = [r for r in results if r.confirmed]

    click.echo(f"\n[+] Total requests: {len(results)}")
    click.echo(f"[+] Confirmed vulnerabilities: {len(confirmed)}")
    for r in confirmed:
        sev_color = {"critical": "\033[91m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m", "info": "\033[97m"}.get(r.severity, "")
        reset = "\033[0m"
        click.echo(f"  {sev_color}[{r.severity.upper()}]{reset} {r.vuln_type} @ {r.url} | param={r.parameter} | payload={r.payload[:60]}")
        if verbose and r.evidence:
            click.echo(f"         evidence: {r.evidence[:200]}")

    if nuclei_export and confirmed:
        templates = engine.generate_nuclei_templates(confirmed)
        out_dir = Path("nuclei_templates")
        out_dir.mkdir(exist_ok=True)
        for i, tmpl in enumerate(templates):
            fname = out_dir / f"finding_{i:03d}.yaml"
            fname.write_text(tmpl)
        click.echo(f"[+] Nuclei templates written to nuclei_templates/")

    if output:
        data = [{"url": r.url, "parameter": r.parameter, "payload": r.payload,
                 "vuln_type": r.vuln_type, "severity": r.severity,
                 "confirmed": r.confirmed, "evidence": r.evidence} for r in confirmed]
        Path(output).write_text(json.dumps(data, indent=2))
        click.echo(f"[+] Results saved to {output}")


# ---------------------------------------------------------------------------
# dns
# ---------------------------------------------------------------------------
@cli.command(name="dns", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("domain")
@click.option("--subdomains", is_flag=True, default=False, help="Brute-force subdomains")
@click.option("--passive", is_flag=True, default=False, help="Passive subdomain recon (crt.sh, HackerTarget)")
@click.option("-w", "--wordlist", default=None, help="Custom subdomain wordlist")
@click.option("-t", "--threads", default=50, show_default=True)
@click.option("--timeout", default=5, show_default=True)
@click.option("-o", "--output", default=None, help="Output JSON file")
def dns_cmd(domain, subdomains, passive, wordlist, threads, timeout, output) -> None:
    """Full DNS reconnaissance: records, zone transfer, SPF/DMARC/DKIM, subdomain discovery.

    \b
    Examples:
      phantomrecon dns example.com
      phantomrecon dns example.com --subdomains --passive
      phantomrecon dns example.com --subdomains -w /usr/share/wordlists/subdomains.txt
    """
    from .modules.subdomain_scanner import DNSRecon, SubdomainScanner

    click.echo(f"[*] DNS recon: {domain}")

    async def _run():
        results: dict[str, Any] = {"domain": domain}

        recon = DNSRecon(domain, timeout=timeout)
        dns_data = await recon.run()
        results["dns_records"] = dns_data
        click.echo(f"\n[+] DNS Records:")
        for rtype, records in dns_data.items():
            if isinstance(records, list) and records:
                click.echo(f"  {rtype}: {', '.join(str(r) for r in records[:5])}")
            elif records and not isinstance(records, list):
                click.echo(f"  {rtype}: {records}")

        if subdomains or passive:
            wl = None
            if wordlist:
                wl = Path(wordlist).read_text().splitlines()
            scanner = SubdomainScanner(
                domain=domain, threads=threads, timeout=timeout,
                wordlist=wl, use_passive=passive,
                callback=lambda r: click.echo(f"  [FOUND] {r.subdomain} -> {r.ip} (HTTP {r.status})")
            )
            sub_results = await scanner.scan(active=subdomains, passive=passive)
            results["subdomains"] = [r.to_dict() for r in sub_results]
            click.echo(f"\n[+] Discovered {len(sub_results)} subdomains")

        return results

    data = asyncio.run(_run())

    if output:
        Path(output).write_text(json.dumps(data, indent=2))
        click.echo(f"\n[+] Results saved to {output}")


# ---------------------------------------------------------------------------
# osint
# ---------------------------------------------------------------------------
@cli.command(name="osint", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--shodan-key", default=None, envvar="SHODAN_API_KEY", help="Shodan API key")
@click.option("--vt-key", default=None, envvar="VT_API_KEY", help="VirusTotal API key")
@click.option("--censys-id", default=None, envvar="CENSYS_API_ID")
@click.option("--censys-secret", default=None, envvar="CENSYS_API_SECRET")
@click.option("--wayback", is_flag=True, default=False, help="Extract URLs from Wayback Machine")
@click.option("--crt", is_flag=True, default=False, help="Certificate transparency lookup (crt.sh)")
@click.option("--github-dork", default=None, help="GitHub dork query for the target")
@click.option("-o", "--output", default=None, help="Output JSON file")
def osint_cmd(target, shodan_key, vt_key, censys_id, censys_secret, wayback, crt, github_dork, output) -> None:
    """Passive OSINT: Shodan, VirusTotal, crt.sh, Wayback Machine, GitHub dorking.

    \b
    Examples:
      phantomrecon osint example.com --crt --wayback
      phantomrecon osint example.com --shodan-key KEY --vt-key KEY
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    click.echo(f"[*] OSINT recon for: {domain}")

    results: dict[str, Any] = {"target": domain}

    if crt:
        click.echo("[*] Querying crt.sh...")
        try:
            from urllib.request import urlopen
            import urllib.parse
            url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
            with urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read())
            domains = sorted(set(e.get("name_value", "") for e in data if e.get("name_value")))
            results["crt_sh"] = domains
            click.echo(f"  [+] crt.sh: {len(domains)} certificates/domains found")
            for d in domains[:20]:
                click.echo(f"    {d}")
        except Exception as e:
            click.echo(f"  [-] crt.sh error: {e}")

    if wayback:
        click.echo("[*] Querying Wayback Machine...")
        try:
            from urllib.request import urlopen
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=1000"
            with urlopen(url, timeout=20) as resp:
                data = json.loads(resp.read())
            urls = [row[0] for row in data[1:] if row]
            results["wayback_urls"] = urls
            click.echo(f"  [+] Wayback Machine: {len(urls)} URLs found")
            for u in urls[:20]:
                click.echo(f"    {u}")
        except Exception as e:
            click.echo(f"  [-] Wayback error: {e}")

    if shodan_key:
        click.echo("[*] Querying Shodan...")
        try:
            from urllib.request import urlopen
            import socket
            ip = socket.gethostbyname(domain)
            url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_key}"
            with urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            results["shodan"] = {"ip": ip, "ports": ports, "vulns": list(vulns), "org": data.get("org", "")}
            click.echo(f"  [+] Shodan: IP={ip}, Ports={ports}, Vulns={list(vulns)[:5]}")
        except Exception as e:
            click.echo(f"  [-] Shodan error: {e}")

    if vt_key:
        click.echo("[*] Querying VirusTotal...")
        try:
            from urllib.request import urlopen, Request as UReq
            req = UReq(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": vt_key}
            )
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            results["virustotal"] = stats
            click.echo(f"  [+] VirusTotal stats: {stats}")
        except Exception as e:
            click.echo(f"  [-] VirusTotal error: {e}")

    if github_dork:
        click.echo(f"[*] GitHub dork: {github_dork} {domain}")
        dork_url = f"https://github.com/search?q={github_dork}+{domain}&type=code"
        results["github_dork_url"] = dork_url
        click.echo(f"  [→] Open in browser: {dork_url}")

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        click.echo(f"\n[+] Results saved to {output}")


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------
@cli.command(name="diff", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("scan_a", metavar="SCAN_A.json")
@click.argument("scan_b", metavar="SCAN_B.json")
@click.option("-o", "--output", default=None, help="Output diff JSON file")
@click.option("--html", "html_out", default=None, help="Output HTML diff report")
def diff_cmd(scan_a, scan_b, output, html_out) -> None:
    """Compare two scan JSON results — show new/fixed/changed findings.

    \b
    Examples:
      phantomrecon diff scan_monday.json scan_friday.json
      phantomrecon diff old.json new.json --html diff_report.html
    """
    try:
        data_a = json.loads(Path(scan_a).read_text())
        data_b = json.loads(Path(scan_b).read_text())
    except Exception as e:
        click.echo(f"[-] Failed to load scan files: {e}", err=True)
        sys.exit(1)

    findings_a = {f"{f['title']}|{f['url']}": f for f in data_a.get("findings", [])}
    findings_b = {f"{f['title']}|{f['url']}": f for f in data_b.get("findings", [])}
    paths_a = set(p["url"] for p in data_a.get("discovered_paths", []))
    paths_b = set(p["url"] for p in data_b.get("discovered_paths", []))

    new_findings = {k: v for k, v in findings_b.items() if k not in findings_a}
    fixed_findings = {k: v for k, v in findings_a.items() if k not in findings_b}
    new_paths = paths_b - paths_a
    removed_paths = paths_a - paths_b

    click.echo(f"\n{'='*60}")
    click.echo(f"DIFF: {scan_a}  →  {scan_b}")
    click.echo(f"{'='*60}")
    click.echo(f"\n\033[91m[NEW FINDINGS] ({len(new_findings)})\033[0m")
    for f in new_findings.values():
        click.echo(f"  + [{f.get('severity','?').upper()}] {f.get('title','')} @ {f.get('url','')}")

    click.echo(f"\n\033[92m[FIXED/RESOLVED] ({len(fixed_findings)})\033[0m")
    for f in fixed_findings.values():
        click.echo(f"  - [{f.get('severity','?').upper()}] {f.get('title','')} @ {f.get('url','')}")

    click.echo(f"\n\033[93m[NEW PATHS] ({len(new_paths)})\033[0m")
    for p in sorted(new_paths)[:30]:
        click.echo(f"  + {p}")

    click.echo(f"\n\033[94m[REMOVED PATHS] ({len(removed_paths)})\033[0m")
    for p in sorted(removed_paths)[:30]:
        click.echo(f"  - {p}")

    diff_data = {
        "scan_a": scan_a,
        "scan_b": scan_b,
        "new_findings": list(new_findings.values()),
        "fixed_findings": list(fixed_findings.values()),
        "new_paths": sorted(new_paths),
        "removed_paths": sorted(removed_paths),
        "summary": {
            "new_findings": len(new_findings),
            "fixed_findings": len(fixed_findings),
            "new_paths": len(new_paths),
            "removed_paths": len(removed_paths),
        }
    }

    if output:
        Path(output).write_text(json.dumps(diff_data, indent=2))
        click.echo(f"\n[+] Diff saved to {output}")

    if html_out:
        _write_diff_html(diff_data, html_out)
        click.echo(f"[+] HTML diff report saved to {html_out}")


def _write_diff_html(diff: dict, path: str) -> None:
    new_rows = "".join(
        f"<tr class='new'><td>{f.get('severity','').upper()}</td><td>{f.get('title','')}</td><td>{f.get('url','')}</td></tr>"
        for f in diff.get("new_findings", [])
    )
    fixed_rows = "".join(
        f"<tr class='fixed'><td>{f.get('severity','').upper()}</td><td>{f.get('title','')}</td><td>{f.get('url','')}</td></tr>"
        for f in diff.get("fixed_findings", [])
    )
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>PhantomRecon Diff</title>
<style>body{{background:#0d0d0d;color:#e0e0e0;font-family:monospace;padding:20px}}
h1{{color:#00ff41}}h2{{color:#00cc33}}
table{{width:100%;border-collapse:collapse;margin:10px 0}}
th{{background:#1a1a1a;color:#00ff41;padding:8px;text-align:left}}
td{{padding:6px 8px;border-bottom:1px solid #222}}
tr.new{{background:#0a2200}}tr.fixed{{background:#002200}}.new td:first-child{{color:#ff4444}}.fixed td:first-child{{color:#44ff44}}</style>
</head><body>
<h1>PhantomRecon — Scan Diff</h1>
<p>{diff.get('scan_a')} → {diff.get('scan_b')}</p>
<h2>New Findings ({diff['summary']['new_findings']})</h2>
<table><tr><th>Severity</th><th>Title</th><th>URL</th></tr>{new_rows}</table>
<h2>Fixed/Resolved ({diff['summary']['fixed_findings']})</h2>
<table><tr><th>Severity</th><th>Title</th><th>URL</th></tr>{fixed_rows}</table>
<h2>New Paths ({diff['summary']['new_paths']})</h2>
<ul>{''.join(f'<li style="color:#00ff41">+ {p}</li>' for p in diff.get('new_paths',[])[:100])}</ul>
<h2>Removed Paths ({diff['summary']['removed_paths']})</h2>
<ul>{''.join(f'<li style="color:#ff4444">- {p}</li>' for p in diff.get('removed_paths',[])[:100])}</ul>
</body></html>"""
    Path(path).write_text(html)


# ---------------------------------------------------------------------------
# schedule
# ---------------------------------------------------------------------------
@cli.command(name="schedule", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target", callback=validate_target, is_eager=True)
@click.option("--interval", "-i", default="24h",
              help="Scan interval: e.g. 1h, 6h, 12h, 24h, 7d [default: 24h]")
@click.option("--profile", default="balanced",
              type=click.Choice(list(PROFILES.keys()), case_sensitive=False))
@click.option("--slack-webhook", default=None, help="Slack webhook for new findings alerts")
@click.option("--discord-webhook", default=None, help="Discord webhook for new findings alerts")
@click.option("--email-to", default=None, help="Email recipient for alerts")
@click.option("--smtp-host", default=None)
@click.option("--smtp-port", default=587, type=int)
@click.option("--smtp-user", default=None)
@click.option("--smtp-pass", default=None)
@click.option("-o", "--output-dir", default="scheduled_scans", show_default=True)
def schedule_cmd(target, interval, profile, slack_webhook, discord_webhook,
                 email_to, smtp_host, smtp_port, smtp_user, smtp_pass, output_dir) -> None:
    """Schedule recurring scans with webhook/email alerts on new findings.

    \b
    Examples:
      phantomrecon schedule https://target.com --interval 12h --slack-webhook URL
      phantomrecon schedule https://target.com --interval 24h --email-to sec@company.com
    """
    import time as time_mod
    import re as re_mod

    m = re_mod.match(r'^(\d+)(h|d|m)$', interval.lower())
    if not m:
        click.echo("[-] Invalid interval format. Use e.g. 1h, 6h, 24h, 7d", err=True)
        sys.exit(1)
    num, unit = int(m.group(1)), m.group(2)
    seconds = num * {"h": 3600, "d": 86400, "m": 60}[unit]

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    notifier = None
    if slack_webhook or discord_webhook or (email_to and smtp_host):
        from .notifications import NotificationManager
        email_cfg = None
        if email_to and smtp_host:
            email_cfg = {"smtp_host": smtp_host, "smtp_port": smtp_port,
                         "smtp_user": smtp_user, "smtp_pass": smtp_pass,
                         "from_addr": smtp_user or "phantomrecon@localhost",
                         "to_addr": email_to}
        notifier = NotificationManager(slack_webhook=slack_webhook, discord_webhook=discord_webhook, email_cfg=email_cfg)

    click.echo(f"[*] Scheduling scans for {target} every {interval}")
    click.echo(f"[*] Output directory: {output_dir}")
    click.echo(f"[*] Press Ctrl+C to stop.")

    last_findings: set = set()
    run_num = 0

    try:
        while True:
            run_num += 1
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            click.echo(f"\n[{ts}] Starting scheduled scan #{run_num}...")

            p_cfg = load_profile(profile)
            p_cfg.pop("description", None)
            config = ScanConfig(
                target=target,
                threads=p_cfg.get("threads", 30),
                wordlist_size=p_cfg.get("wordlist_size", "medium"),
                output_dir=output_dir,
                output_formats=["json"],
            )

            engine = ScanEngine(config)
            result = asyncio.run(engine.run())

            current_findings = set(f"{f.title}|{f.url}" for f in result.findings)
            new_findings = current_findings - last_findings

            click.echo(f"[+] Scan #{run_num} complete: {len(result.findings)} findings ({len(new_findings)} new)")

            if new_findings and notifier:
                for key in new_findings:
                    for f in result.findings:
                        if f"{f.title}|{f.url}" == key:
                            notifier.notify_finding({
                                "title": f.title, "severity": f.severity.value,
                                "url": f.url, "description": f.description,
                            }, target)

            # Save result
            reporter = Reporter(output_dir=output_dir)
            reporter.save_all(result, ["json"])

            from .database import ScanDatabase
            try:
                db = ScanDatabase()
                db.save_scan(result)
            except Exception:
                pass

            last_findings = current_findings
            click.echo(f"[*] Next scan in {interval}. Sleeping...")
            time_mod.sleep(seconds)

    except KeyboardInterrupt:
        click.echo("\n[*] Scheduler stopped.")


# ---------------------------------------------------------------------------
# chain
# ---------------------------------------------------------------------------
@cli.command(name="chain", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("seed_target", callback=validate_target, is_eager=True)
@click.option("--profile", default="balanced",
              type=click.Choice(list(PROFILES.keys()), case_sensitive=False))
@click.option("-t", "--threads", default=30, show_default=True)
@click.option("--max-targets", default=20, show_default=True, help="Max targets to scan")
@click.option("--subdomain-passive", is_flag=True, default=False, help="Discover subdomains via passive recon first")
@click.option("-o", "--output-dir", default="chain_results", show_default=True)
@click.option("--save-db", is_flag=True, default=False)
def chain_cmd(seed_target, profile, threads, max_targets, subdomain_passive, output_dir, save_db) -> None:
    """Pipeline mode: discover subdomains then auto-scan each one.

    \b
    Examples:
      phantomrecon chain https://target.com --subdomain-passive --max-targets 10
      phantomrecon chain https://target.com --profile ghost --save-db
    """
    from urllib.parse import urlparse
    from .modules.subdomain_scanner import SubdomainScanner

    domain = urlparse(seed_target).netloc
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    click.echo(f"[*] Chain scan — seed: {seed_target}")
    click.echo(f"[*] Discovering subdomains of: {domain}")

    async def _discover():
        scanner = SubdomainScanner(domain=domain, threads=threads, timeout=5, use_passive=subdomain_passive)
        return await scanner.scan(active=True, passive=subdomain_passive)

    sub_results = asyncio.run(_discover())
    targets = [seed_target]
    for r in sub_results[:max_targets - 1]:
        if r.status in (200, 301, 302, 403):
            scheme = "https" if r.status != 0 else "http"
            targets.append(f"{scheme}://{r.subdomain}")

    targets = targets[:max_targets]
    click.echo(f"[+] Scanning {len(targets)} targets: {targets}")

    all_results = []
    for i, tgt in enumerate(targets, 1):
        click.echo(f"\n[{i}/{len(targets)}] Scanning: {tgt}")
        p_cfg = load_profile(profile)
        p_cfg.pop("description", None)
        config = ScanConfig(
            target=tgt,
            threads=p_cfg.get("threads", 30),
            wordlist_size=p_cfg.get("wordlist_size", "small"),
            output_dir=output_dir,
            output_formats=["json"],
        )
        engine = ScanEngine(config, ui_callback=lambda e, d: click.echo(f"  [{e}] {d}") if e == "module_done" else None)
        try:
            result = asyncio.run(engine.run())
            all_results.append(result)
            reporter = Reporter(output_dir=output_dir)
            reporter.save_all(result, ["json"])
            click.echo(f"  [+] {len(result.findings)} findings, {len(result.discovered_paths)} paths")

            if save_db:
                try:
                    from .database import ScanDatabase
                    ScanDatabase().save_scan(result)
                except Exception:
                    pass
        except Exception as e:
            click.echo(f"  [-] Error: {e}")

    total_findings = sum(len(r.findings) for r in all_results)
    click.echo(f"\n[+] Chain complete: {len(all_results)} targets, {total_findings} total findings")
    click.echo(f"[+] Results in: {output_dir}/")


# ---------------------------------------------------------------------------
# proxy-check
# ---------------------------------------------------------------------------
@cli.command(name="proxy-check", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("proxy_file", metavar="PROXY_FILE")
@click.option("--check-url", default="https://httpbin.org/ip", show_default=True, help="URL to test proxies against")
@click.option("-t", "--threads", default=20, show_default=True)
@click.option("--timeout", default=10, show_default=True)
@click.option("-o", "--output", default=None, help="Save working proxies to file")
@click.option("--min-score", default=0, type=int, help="Minimum score (0-100) to include proxy")
def proxy_check_cmd(proxy_file, check_url, threads, timeout, output, min_score) -> None:
    """Test and score a proxy list for speed, anonymity level, and geolocation.

    \b
    Examples:
      phantomrecon proxy-check proxies.txt
      phantomrecon proxy-check proxies.txt -o working_proxies.txt --min-score 50
    """
    try:
        proxies = [l.strip() for l in Path(proxy_file).read_text().splitlines() if l.strip() and not l.startswith("#")]
    except Exception as e:
        click.echo(f"[-] Failed to read proxy file: {e}", err=True)
        sys.exit(1)

    click.echo(f"[*] Testing {len(proxies)} proxies against {check_url}")
    click.echo(f"[*] Threads: {threads}, Timeout: {timeout}s")

    import aiohttp

    async def test_proxy(proxy_url: str) -> dict:
        start = __import__("time").time()
        result = {"proxy": proxy_url, "working": False, "speed": 0.0, "score": 0, "ip": "", "anonymity": "unknown", "country": ""}
        try:
            conn = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=conn) as session:
                async with session.get(check_url, proxy=proxy_url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    elapsed = __import__("time").time() - start
                    if resp.status == 200:
                        result["working"] = True
                        result["speed"] = round(elapsed, 2)
                        try:
                            data = await resp.json()
                            result["ip"] = data.get("origin", "")
                        except Exception:
                            pass
                        speed_score = max(0, 50 - int(elapsed * 10))
                        result["score"] = min(100, speed_score + 50)
                        result["anonymity"] = "elite" if "X-Forwarded-For" not in str(resp.headers) else "transparent"
        except Exception:
            pass
        return result

    async def _run():
        sem = asyncio.Semaphore(threads)
        async def guarded(p):
            async with sem:
                return await test_proxy(p)
        return await asyncio.gather(*[guarded(p) for p in proxies])

    results = asyncio.run(_run())
    working = [r for r in results if r["working"] and r["score"] >= min_score]
    working.sort(key=lambda x: x["score"], reverse=True)

    click.echo(f"\n{'─'*70}")
    click.echo(f"{'PROXY':<40} {'SPEED':>8} {'SCORE':>6} {'ANONYMITY':<12} {'IP'}")
    click.echo(f"{'─'*70}")
    for r in working[:50]:
        click.echo(f"{r['proxy']:<40} {r['speed']:>7.2f}s {r['score']:>5}/100 {r['anonymity']:<12} {r['ip']}")

    click.echo(f"\n[+] Working proxies: {len(working)} / {len(proxies)}")

    if output:
        Path(output).write_text("\n".join(r["proxy"] for r in working))
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# history
# ---------------------------------------------------------------------------
@cli.command(name="history", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--list", "list_all", is_flag=True, default=False, help="List all saved scans")
@click.option("--show", default=None, type=int, help="Show details for scan ID")
@click.option("--delete", default=None, type=int, help="Delete scan by ID")
@click.option("--search", default=None, help="Search findings by keyword")
@click.option("--diff", "diff_ids", nargs=2, type=int, default=None, help="Diff two scan IDs")
def history_cmd(list_all, show, delete, search, diff_ids) -> None:
    """Browse, search, and manage saved scan history.

    \b
    Examples:
      phantomrecon history --list
      phantomrecon history --show 3
      phantomrecon history --search "SQL injection"
      phantomrecon history --diff 2 5
    """
    try:
        from .database import ScanDatabase
        db = ScanDatabase()
    except Exception as e:
        click.echo(f"[-] Database error: {e}", err=True)
        sys.exit(1)

    if list_all or (not show and not delete and not search and not diff_ids):
        scans = db.list_scans()
        if not scans:
            click.echo("[*] No scans in history. Run: phantomrecon scan ... --save-db")
            return
        click.echo(f"\n{'ID':>4} {'TARGET':<40} {'DATE':<20} {'FINDINGS':>8} {'PATHS':>6} {'REQ':>6}")
        click.echo("─" * 90)
        for s in scans:
            dt = datetime.fromtimestamp(s.get("start_time", 0)).strftime("%Y-%m-%d %H:%M")
            click.echo(f"{s['id']:>4} {s['target']:<40} {dt:<20} {s.get('finding_count',0):>8} {s.get('path_count',0):>6} {s.get('total_requests',0):>6}")

    if show:
        scan = db.get_scan(show)
        if not scan:
            click.echo(f"[-] Scan ID {show} not found.")
            return
        click.echo(json.dumps(scan, indent=2, default=str))

    if delete:
        db.delete_scan(delete)
        click.echo(f"[+] Scan {delete} deleted.")

    if search:
        findings = db.search_findings(search)
        click.echo(f"\n[+] Search '{search}': {len(findings)} results")
        for f in findings[:50]:
            click.echo(f"  [{f.get('severity','?').upper()}] {f.get('title','')} @ {f.get('url','')}")

    if diff_ids:
        diff = db.diff_scans(diff_ids[0], diff_ids[1])
        click.echo(f"\n[+] Diff scan {diff_ids[0]} vs {diff_ids[1]}:")
        click.echo(f"  New findings: {len(diff.get('new_findings', []))}")
        click.echo(f"  Fixed findings: {len(diff.get('fixed_findings', []))}")
        for f in diff.get("new_findings", []):
            click.echo(f"  + [{f.get('severity','?').upper()}] {f.get('title','')} @ {f.get('url','')}")
        for f in diff.get("fixed_findings", []):
            click.echo(f"  - [{f.get('severity','?').upper()}] {f.get('title','')} @ {f.get('url','')}")


# ---------------------------------------------------------------------------
# profiles / gen-config
# ---------------------------------------------------------------------------
@cli.command(name="profiles", context_settings={"help_option_names": ["-h", "--help"]})
def list_profiles() -> None:
    """List available scan profiles."""
    click.echo("\nAvailable PhantomRecon Scan Profiles:\n")
    for name, data in PROFILES.items():
        click.echo(f"  [{name}]")
        click.echo(f"    {data.get('description', '')}")
        click.echo(f"    Threads: {data.get('threads')}  |  "
                   f"Delay: {data.get('delay_min')}-{data.get('delay_max')}s  |  "
                   f"Wordlist: {data.get('wordlist_size')}")
        mods = data.get("modules", [])
        click.echo(f"    Modules: {', '.join(mods) if mods else 'all'}")
        click.echo()


@cli.command(name="gen-config", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("output", default="phantomrecon.yaml")
def gen_config(output: str) -> None:
    """Generate an example YAML config file."""
    try:
        write_example_config(output)
        click.echo(f"[+] Example config written to: {output}")
    except Exception as e:
        click.echo(f"[-] Failed to write config: {e}", err=True)
        sys.exit(1)



# ---------------------------------------------------------------------------
# cert-transparency
# ---------------------------------------------------------------------------
@cli.command(name="cert-transparency", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("domain")
@click.option("--emails", is_flag=True, default=False, help="Also harvest emails via OSINT")
@click.option("--hibp-key", default=None, help="HaveIBeenPwned API key for email breach check")
@click.option("-o", "--output", default=None, help="Save JSON output to file")
@click.option("-v", "--verbose", is_flag=True, default=False)
def cert_transparency_cmd(domain, emails, hibp_key, output, verbose) -> None:
    """Certificate transparency subdomain discovery + email harvesting.

    \b
    Examples:
      phantomrecon cert-transparency example.com
      phantomrecon cert-transparency example.com --emails
      phantomrecon cert-transparency example.com --emails --hibp-key YOUR_KEY -o results.json
    """
    from .modules.cert_transparency import CertTransparency, EmailHarvester

    click.echo(f"[*] CT subdomain recon: {domain}")
    ct = CertTransparency()
    subdomains = ct.enumerate(domain)
    click.echo(f"[+] Found {len(subdomains)} subdomains")
    for s in subdomains:
        click.echo(f"  {s.domain:<50} [{s.source}]  {s.ip or ''}")

    email_results = []
    if emails:
        click.echo(f"\n[*] Harvesting emails for {domain}...")
        harvester = EmailHarvester(hibp_api_key=hibp_key)
        email_results = harvester.harvest(domain)
        click.echo(f"[+] Found {len(email_results)} emails")
        for e in email_results:
            click.echo(f"  {e.email:<40} [{e.source}] confidence={e.confidence}")

    if output:
        import json as _json
        data = {
            "domain": domain,
            "subdomains": [s.__dict__ for s in subdomains],
            "emails": [e.__dict__ for e in email_results],
        }
        with open(output, "w") as f:
            _json.dump(data, f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# port-scan
# ---------------------------------------------------------------------------
@cli.command(name="port-scan", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--ports", "-p", default="top-100", help="Port range: top-100, top-1000, all, or 80,443,8080 or 1-1024")
@click.option("--udp", is_flag=True, default=False, help="Also scan UDP common ports")
@click.option("--banner", is_flag=True, default=True, show_default=True, help="Grab service banners")
@click.option("--scripts", is_flag=True, default=False, help="Run NSE-style scripts (anon FTP, null SMB, HTTP title)")
@click.option("-t", "--threads", default=200, show_default=True, help="Concurrent scan threads")
@click.option("--timeout", default=2.0, show_default=True, type=float, help="Connection timeout seconds")
@click.option("-o", "--output", default=None, help="Save JSON output to file")
@click.option("-v", "--verbose", is_flag=True, default=False)
def port_scan_cmd(target, ports, udp, banner, scripts, threads, timeout, output, verbose) -> None:
    """Built-in TCP/UDP port scanner with banner grabbing and service detection.

    \b
    Examples:
      phantomrecon port-scan 192.168.1.1
      phantomrecon port-scan 192.168.1.1 --ports top-1000 --banner
      phantomrecon port-scan 192.168.1.0/24 --ports 80,443,8080,8443 -t 500
      phantomrecon port-scan 10.0.0.1 --ports all --udp --scripts -o scan.json
    """
    from .modules.port_scanner import PortScanner

    click.echo(f"[*] Port scanning: {target}  ports={ports}")
    scanner = PortScanner(threads=threads, timeout=timeout)
    results = scanner.scan(target, ports=ports, udp=udp, banner_grab=banner, run_scripts=scripts)
    open_ports = [r for r in results if r.state.value == "open"]
    click.echo(f"[+] {len(open_ports)} open ports found\n")
    click.echo(f"  {'PORT':<10} {'STATE':<12} {'SERVICE':<16} {'BANNER'}")
    click.echo("  " + "─" * 70)
    for r in sorted(open_ports, key=lambda x: x.port):
        banner_s = (r.banner[:40] + "...") if r.banner and len(r.banner) > 40 else (r.banner or "")
        click.echo(f"  {r.port:<10} {r.state.value:<12} {r.service:<16} {banner_s}")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"\n[+] Saved to {output}")


# ---------------------------------------------------------------------------
# network-recon
# ---------------------------------------------------------------------------
@cli.command(name="network-recon", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--ipv6", is_flag=True, default=False, help="IPv6 AAAA record enumeration")
@click.option("--asn", is_flag=True, default=False, help="BGP/ASN lookup for target org")
@click.option("--cloud", is_flag=True, default=False, help="Discover cloud assets (S3, Azure, GCP)")
@click.option("--topology", is_flag=True, default=False, help="Network topology via traceroute")
@click.option("--geo", is_flag=True, default=False, help="IP geolocation enrichment")
@click.option("--all-modules", "all_modules", is_flag=True, default=False, help="Run all modules")
@click.option("-o", "--output", default=None, help="Save JSON output to file")
def network_recon_cmd(target, ipv6, asn, cloud, topology, geo, all_modules, output) -> None:
    """Network & infrastructure recon: IPv6, BGP/ASN, cloud assets, topology.

    \b
    Examples:
      phantomrecon network-recon example.com --asn --geo
      phantomrecon network-recon example.com --cloud
      phantomrecon network-recon example.com --all-modules -o net.json
    """
    from .modules.network_recon import run_network_recon

    if all_modules:
        ipv6 = asn = cloud = topology = geo = True
    click.echo(f"[*] Network recon: {target}")
    results = run_network_recon(target, ipv6=ipv6, asn=asn, cloud=cloud,
                                topology=topology, geo=geo)
    import json as _json
    click.echo(_json.dumps(results, indent=2, default=str))
    if output:
        with open(output, "w") as f:
            _json.dump(results, f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# dns-adv (advanced DNS)
# ---------------------------------------------------------------------------
@cli.command(name="dns-adv", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("domain")
@click.option("--axfr", is_flag=True, default=False, help="Attempt zone transfer (AXFR)")
@click.option("--dnssec", is_flag=True, default=False, help="Analyze DNSSEC chain")
@click.option("--spf", is_flag=True, default=False, help="SPF/DMARC/DKIM analysis")
@click.option("--brute", is_flag=True, default=False, help="Subdomain DNS brute-force")
@click.option("--wordlist", "-w", default=None, help="Wordlist for subdomain brute-force")
@click.option("--all-checks", "all_checks", is_flag=True, default=False, help="Run all DNS checks")
@click.option("-o", "--output", default=None, help="Save JSON output to file")
def dns_adv_cmd(domain, axfr, dnssec, spf, brute, wordlist, all_checks, output) -> None:
    """Advanced DNS analysis: AXFR, DNSSEC, SPF/DMARC/DKIM, subdomain brute-force.

    \b
    Examples:
      phantomrecon dns-adv example.com --axfr
      phantomrecon dns-adv example.com --spf --dnssec
      phantomrecon dns-adv example.com --brute -w subdomains.txt
      phantomrecon dns-adv example.com --all-checks -o dns.json
    """
    from .modules.dns_advanced import run_dns_advanced

    if all_checks:
        axfr = dnssec = spf = brute = True
    click.echo(f"[*] DNS advanced analysis: {domain}")
    results = run_dns_advanced(domain, axfr=axfr, dnssec=dnssec, spf=spf,
                               brute=brute, wordlist=wordlist)
    import json as _json
    click.echo(_json.dumps(results, indent=2, default=str))
    if output:
        with open(output, "w") as f:
            _json.dump(results, f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# exploit-confirm
# ---------------------------------------------------------------------------
@cli.command(name="exploit-confirm", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("--param", "-p", multiple=True, help="Parameter(s) to test")
@click.option("--type", "-T", "vuln_types", multiple=True,
              type=click.Choice(["sqli","xss","rce","ssrf","ssti","traversal","xxe","redirect","all"]),
              help="Vulnerability type(s) to confirm")
@click.option("--method", "-X", default="GET", help="HTTP method")
@click.option("-t", "--threads", default=5, show_default=True)
@click.option("-o", "--output", default=None, help="Save JSON results")
def exploit_confirm_cmd(url, param, vuln_types, method, threads, output) -> None:
    """Auto-confirm exploitation: SQLi, XSS, RCE, SSRF, SSTI, path traversal, XXE.

    \b
    Examples:
      phantomrecon exploit-confirm "https://target.com/page?id=1" -T sqli
      phantomrecon exploit-confirm "https://target.com/search" -p q -T xss -T ssti
      phantomrecon exploit-confirm "https://target.com/api" -T ssrf -T rce -o confirmed.json
    """
    from .modules.exploit_confirm import ExploitConfirmer

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    types = list(vuln_types) if vuln_types else ["all"]
    if "all" in types:
        types = ["sqli","xss","rce","ssrf","ssti","traversal","xxe","redirect"]
    params = list(param) if param else None

    click.echo(f"[*] Exploit confirmation: {url}")
    click.echo(f"[*] Types: {', '.join(types)}")
    confirmer = ExploitConfirmer(threads=threads)
    results = confirmer.scan(url, params=params, methods=[method.upper()], vuln_types=types)
    confirmed = [r for r in results if r.confirmed]
    click.echo(f"[+] {len(confirmed)}/{len(results)} confirmed\n")
    for r in confirmed:
        click.echo(f"  \033[91m[{r.vuln_type.value.upper()}]\033[0m {r.url}")
        click.echo(f"    Param: {r.parameter}  Method: {r.method}")
        click.echo(f"    Payload: {r.payload[:80]}")
        click.echo(f"    Evidence: {r.evidence[:100]}\n")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# jwt
# ---------------------------------------------------------------------------
@cli.command(name="jwt", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("token", default="")
@click.option("--analyze", is_flag=True, default=False, help="Analyze/decode JWT token")
@click.option("--alg-none", "alg_none", is_flag=True, default=False, help="alg:none attack")
@click.option("--rs256-hs256", "rs256_hs256", is_flag=True, default=False, help="RS256→HS256 confusion attack")
@click.option("--pubkey", default=None, help="PEM public key file (for RS256→HS256)")
@click.option("--brute", is_flag=True, default=False, help="Brute-force weak HMAC secret")
@click.option("--wordlist", "-w", default=None, help="Wordlist for brute-force")
@click.option("--kid-inject", "kid_inject", is_flag=True, default=False, help="kid injection attack")
@click.option("--claim", default=None, help="Set custom claim e.g. role=admin")
@click.option("--all-attacks", "all_attacks", is_flag=True, default=False, help="Run all JWT attacks")
@click.option("-o", "--output", default=None, help="Save JSON results")
def jwt_cmd(token, analyze, alg_none, rs256_hs256, pubkey, brute, wordlist,
            kid_inject, claim, all_attacks, output) -> None:
    """JWT attack suite: alg:none, RS256→HS256, weak secret brute, kid injection.

    \b
    Examples:
      phantomrecon jwt eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.xxx --analyze
      phantomrecon jwt <TOKEN> --alg-none
      phantomrecon jwt <TOKEN> --rs256-hs256 --pubkey public.pem
      phantomrecon jwt <TOKEN> --brute -w rockyou.txt
      phantomrecon jwt <TOKEN> --kid-inject
      phantomrecon jwt <TOKEN> --all-attacks -o jwt_results.json
    """
    from .modules.jwt_attack import JWTAnalyzer, AlgNoneAttack, RS256HS256ConfusionAttack
    from .modules.jwt_attack import WeakSecretBruteForce, KIDInjectionAttack, ClaimManipulator

    if not token:
        click.echo("[-] Provide a JWT token as argument", err=True)
        sys.exit(1)
    if all_attacks:
        analyze = alg_none = rs256_hs256 = brute = kid_inject = True

    results = {}
    if analyze or (not any([alg_none, rs256_hs256, brute, kid_inject, claim])):
        info = JWTAnalyzer(token).analyze()
        results["analysis"] = info
        click.echo("\n[JWT Analysis]")
        for k, v in info.items():
            click.echo(f"  {k}: {v}")

    if alg_none:
        forgeries = AlgNoneAttack(token).attack()
        results["alg_none"] = forgeries
        click.echo(f"\n[alg:none] {len(forgeries)} forged tokens generated")
        for t in forgeries[:3]:
            click.echo(f"  {t[:80]}...")

    if brute:
        bf = WeakSecretBruteForce(token)
        found = bf.brute_force(wordlist=wordlist)
        results["brute"] = found
        if found:
            click.echo(f"\n[Brute-force] \033[92mSecret found: {found['secret']}\033[0m")
        else:
            click.echo(f"\n[Brute-force] No weak secret found")

    if kid_inject:
        payloads = KIDInjectionAttack(token).generate()
        results["kid_injection"] = payloads
        click.echo(f"\n[kid injection] {len(payloads)} injection tokens generated")

    if claim:
        k, v = (claim.split("=", 1) + ["true"])[:2]
        manip = ClaimManipulator(token).set_claim(k, v)
        results["claim_manipulation"] = manip
        click.echo(f"\n[Claim] Modified token: {manip[:80]}...")

    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump(results, f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# deser
# ---------------------------------------------------------------------------
@cli.command(name="deser", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("--platform", "-P", default="all",
              type=click.Choice(["java","php","dotnet","python","ruby","nodejs","all"]),
              help="Target platform for deserialization payloads")
@click.option("--cmd", default="id", help="Command to embed in payload")
@click.option("--param", default=None, help="Target parameter (POST body)")
@click.option("--header", default=None, help="Target header (e.g. X-Session)")
@click.option("-o", "--output", default=None)
def deser_cmd(url, platform, cmd, param, header, output) -> None:
    """Insecure deserialization detection: Java, PHP, .NET, Python, Ruby, Node.

    \b
    Examples:
      phantomrecon deser https://target.com/api --platform java --cmd id
      phantomrecon deser https://target.com/login --platform php --param remember_me
      phantomrecon deser https://target.com/api --platform all -o deser.json
    """
    from .modules.deserialization import DeserializationDetector

    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    platforms = ["java","php","dotnet","python","ruby","nodejs"] if platform == "all" else [platform]
    click.echo(f"[*] Deserialization scan: {url}  platforms={', '.join(platforms)}  cmd={cmd}")
    detector = DeserializationDetector()
    results = detector.scan(url, platforms=platforms, command=cmd,
                            parameter=param, header=header)
    confirmed = [r for r in results if r.confirmed]
    click.echo(f"[+] {len(confirmed)} confirmed deserialization vulnerabilities")
    for r in confirmed:
        click.echo(f"  \033[91m[{r.platform.value}]\033[0m {r.gadget_chain} — {r.evidence[:100]}")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# oauth
# ---------------------------------------------------------------------------
@cli.command(name="oauth", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("auth_url")
@click.option("--client-id", "client_id", default=None)
@click.option("--redirect-uri", "redirect_uri", default=None)
@click.option("--discovery", is_flag=True, default=False, help="OIDC well-known discovery")
@click.option("--state-fixation", "state_fixation", is_flag=True, default=False)
@click.option("--redirect-bypass", "redirect_bypass", is_flag=True, default=False)
@click.option("--scope-escalate", "scope_escalate", is_flag=True, default=False)
@click.option("--all-attacks", "all_attacks", is_flag=True, default=False)
@click.option("-o", "--output", default=None)
def oauth_cmd(auth_url, client_id, redirect_uri, discovery, state_fixation,
              redirect_bypass, scope_escalate, all_attacks, output) -> None:
    """OAuth 2.0 / OIDC attack suite: state fixation, redirect bypass, scope escalation.

    \b
    Examples:
      phantomrecon oauth https://auth.example.com/oauth/authorize --discovery
      phantomrecon oauth https://auth.example.com/oauth/authorize --client-id abc --all-attacks
      phantomrecon oauth https://auth.example.com/oauth/authorize --redirect-bypass --redirect-uri https://evil.com
    """
    from .modules.oauth_attack import OAuthAttacker

    if not auth_url.startswith(("http://", "https://")):
        auth_url = "https://" + auth_url
    if all_attacks:
        discovery = state_fixation = redirect_bypass = scope_escalate = True

    attacker = OAuthAttacker(auth_url, client_id=client_id, redirect_uri=redirect_uri)
    results  = attacker.run(discovery=discovery, state_fixation=state_fixation,
                            redirect_bypass=redirect_bypass, scope_escalate=scope_escalate)
    click.echo(f"[+] OAuth findings: {len(results)}")
    for r in results:
        click.echo(f"  [{r.severity.upper()}] {r.title}: {r.evidence[:100]}")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# 2fa-bypass
# ---------------------------------------------------------------------------
@cli.command(name="2fa-bypass", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("--otp-field", "otp_field", default="otp", help="OTP form field name")
@click.option("--session", "session_cookie", default=None, help="Session cookie value")
@click.option("--response-manip", "response_manip", is_flag=True, default=False)
@click.option("--backup-brute", "backup_brute", is_flag=True, default=False)
@click.option("--race", is_flag=True, default=False, help="OTP race condition attack")
@click.option("--null-otp", "null_otp", is_flag=True, default=False)
@click.option("--header-bypass", "header_bypass", is_flag=True, default=False)
@click.option("--all-attacks", "all_attacks", is_flag=True, default=False)
@click.option("-o", "--output", default=None)
def twofa_bypass_cmd(url, otp_field, session_cookie, response_manip, backup_brute,
                     race, null_otp, header_bypass, all_attacks, output) -> None:
    """2FA bypass techniques: response manipulation, backup brute, race condition.

    \b
    Examples:
      phantomrecon 2fa-bypass https://target.com/verify --response-manip
      phantomrecon 2fa-bypass https://target.com/otp --backup-brute --session "sess=abc"
      phantomrecon 2fa-bypass https://target.com/mfa --all-attacks -o 2fa.json
    """
    from .modules.twofa_bypass import TwoFAAttacker

    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if all_attacks:
        response_manip = backup_brute = race = null_otp = header_bypass = True

    attacker = TwoFAAttacker(url, otp_field=otp_field, session_cookie=session_cookie)
    results  = attacker.run(response_manip=response_manip, backup_brute=backup_brute,
                            race=race, null_otp=null_otp, header_bypass=header_bypass)
    click.echo(f"[+] 2FA bypass findings: {len(results)}")
    for r in results:
        click.echo(f"  [{r.severity.upper()}] {r.title}: {r.evidence[:120]}")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# spray
# ---------------------------------------------------------------------------
@cli.command(name="spray", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("--users", "-u", default=None, help="Usernames file (one per line)")
@click.option("--passwords", "-p", default=None, help="Passwords file (one per line)")
@click.option("--user", default=None, help="Single username")
@click.option("--password", default=None, help="Single password")
@click.option("--mode", default="form",
              type=click.Choice(["form","basic_auth","json","oauth2_ropc"]),
              help="Spray mode")
@click.option("--user-field", "user_field", default="username")
@click.option("--pass-field", "pass_field", default="password")
@click.option("--delay-min", "delay_min", default=30.0, show_default=True, type=float)
@click.option("--delay-max", "delay_max", default=60.0, show_default=True, type=float)
@click.option("--max-per-user", "max_per_user", default=3, show_default=True, type=int)
@click.option("--enumerate", is_flag=True, default=False, help="User enumeration mode")
@click.option("-o", "--output", default=None)
def spray_cmd(url, users, passwords, user, password, mode, user_field, pass_field,
              delay_min, delay_max, max_per_user, enumerate, output) -> None:
    """Smart password spray with lockout avoidance (Poisson jitter timing).

    \b
    Examples:
      phantomrecon spray https://target.com/login --users users.txt --passwords common.txt
      phantomrecon spray https://target.com/login --users users.txt --password 'Summer2024!'
      phantomrecon spray https://target.com/api/login --mode json --users users.txt --passwords pwds.txt
      phantomrecon spray https://target.com/login --enumerate --users users.txt
    """
    from .modules.password_spray import PasswordSprayer, SprayConfig, SprayMode, UserEnumerator

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    user_list = []
    if users:
        with open(users) as f:
            user_list = [l.strip() for l in f if l.strip()]
    elif user:
        user_list = [user]
    else:
        click.echo("[-] Provide --users or --user", err=True)
        sys.exit(1)

    if enumerate:
        click.echo(f"[*] User enumeration: {url}")
        enum = UserEnumerator(url, user_field=user_field, pass_field=pass_field)
        found = enum.enumerate(user_list)
        click.echo(f"[+] Valid users found: {len(found)}")
        for u in found:
            click.echo(f"  [+] {u}")
        return

    pass_list = []
    if passwords:
        with open(passwords) as f:
            pass_list = [l.strip() for l in f if l.strip()]
    elif password:
        pass_list = [password]
    else:
        click.echo("[-] Provide --passwords or --password", err=True)
        sys.exit(1)

    config = SprayConfig(
        target_url=url, usernames=user_list, passwords=pass_list,
        mode=SprayMode(mode), user_field=user_field, pass_field=pass_field,
        delay_min=delay_min, delay_max=delay_max, max_per_user=max_per_user,
    )
    click.echo(f"[*] Spraying {len(user_list)} users × {len(pass_list)} passwords against {url}")
    sprayer = PasswordSprayer(config)
    results = sprayer.spray()
    hits = [r for r in results if r.success]
    click.echo(f"[+] {len(hits)} valid credentials found")
    for r in hits:
        click.echo(f"  \033[92m✓\033[0m  {r.username}:{r.password}")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# payload-gen
# ---------------------------------------------------------------------------
@cli.command(name="payload-gen", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--type", "-T", "ptype",
              type=click.Choice(["revshell","webshell","encode","list","polyglot"]),
              default="list", show_default=True)
@click.option("--lang", "-l", default=None, help="Language (bash, python, powershell, php, etc.)")
@click.option("--lhost", default="10.0.0.1", show_default=True, help="Attacker IP for reverse shells")
@click.option("--lport", default=4444, show_default=True, type=int, help="Attacker port")
@click.option("--encode", default=None,
              type=click.Choice(["url","double_url","html","base64","hex","unicode",
                                  "ifs","case","null_byte","comment"]),
              help="WAF bypass encoding")
@click.option("--payload", default=None, help="Payload string to encode (with --encode)")
@click.option("--list-langs", "list_langs", is_flag=True, default=False, help="List available languages")
def payload_gen_cmd(ptype, lang, lhost, lport, encode, payload, list_langs) -> None:
    """Reverse shell / web shell / payload generator with WAF bypass encodings.

    \b
    Examples:
      phantomrecon payload-gen --type list
      phantomrecon payload-gen --type revshell --lang bash --lhost 10.0.0.1 --lport 4444
      phantomrecon payload-gen --type revshell --lang python3 --lhost 10.0.0.1 --lport 9001
      phantomrecon payload-gen --type webshell --lang php
      phantomrecon payload-gen --type encode --payload "' OR 1=1--" --encode url
      phantomrecon payload-gen --type polyglot
    """
    from .modules.payload_gen import PayloadGenerator, REVERSE_SHELLS, WAFBypassEncoder, PolyglotPayloads

    gen = PayloadGenerator(lhost=lhost, lport=lport)

    if list_langs:
        click.echo("[*] Available reverse shell languages:")
        for name in REVERSE_SHELLS.keys():
            click.echo(f"  {name}")
        return

    if ptype == "list":
        click.echo("[*] Available reverse shells:")
        for name, tmpl in REVERSE_SHELLS.items():
            click.echo(f"  [{name}]  {tmpl[:60].format(LHOST=lhost, LPORT=lport)}")
        return

    if ptype == "revshell":
        if lang:
            tmpl = REVERSE_SHELLS.get(lang)
            if not tmpl:
                click.echo(f"[-] Unknown language: {lang}", err=True)
                sys.exit(1)
            click.echo(tmpl.format(LHOST=lhost, LPORT=lport))
        else:
            for name, tmpl in REVERSE_SHELLS.items():
                click.echo(f"[{name}]\n{tmpl.format(LHOST=lhost, LPORT=lport)}\n")

    if ptype == "webshell":
        shells = gen.get_web_shells()
        if lang:
            s = shells.get(lang.lower())
            if s:
                click.echo(s)
            else:
                click.echo(f"[-] No web shell for {lang}")
        else:
            for name, code in shells.items():
                click.echo(f"[{name}]\n{code}\n")

    if ptype == "encode" and payload:
        encoder = WAFBypassEncoder()
        if encode:
            result = encoder.encode(payload, encode)
            click.echo(result)
        else:
            click.echo("[*] All encodings:")
            for enc in ["url","double_url","html","base64","hex","unicode","ifs","case","null_byte","comment"]:
                try:
                    click.echo(f"  [{enc}]  {encoder.encode(payload, enc)}")
                except Exception:
                    pass

    if ptype == "polyglot":
        from .modules.stealth import PolyglotEngine
        engine = PolyglotEngine()
        for p in engine.get_all():
            click.echo(f"[{p['name']}]  contexts={p['contexts']}")
            click.echo(f"  {p['payload']}")
            click.echo()


# ---------------------------------------------------------------------------
# takeover
# ---------------------------------------------------------------------------
@cli.command(name="takeover", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("domain_or_file")
@click.option("--wordlist", "-w", default=None, help="Subdomain wordlist for discovery")
@click.option("-t", "--threads", default=20, show_default=True)
@click.option("-o", "--output", default=None)
def takeover_cmd(domain_or_file, wordlist, threads, output) -> None:
    """Subdomain takeover detection: 50+ services (GitHub Pages, Heroku, S3, Azure, Vercel...).

    \b
    Examples:
      phantomrecon takeover example.com
      phantomrecon takeover subdomains.txt --threads 30
      phantomrecon takeover example.com -w subdomains-top1m.txt -o takeover.json
    """
    from .modules.subdomain_takeover import SubdomainTakeoverChecker, run_takeover_scan
    import os as _os

    subdomains = []
    if _os.path.isfile(domain_or_file):
        with open(domain_or_file) as f:
            subdomains = [l.strip() for l in f if l.strip()]
    else:
        subdomains = [domain_or_file]
        if wordlist:
            with open(wordlist) as f:
                subs = [f"{l.strip()}.{domain_or_file}" for l in f if l.strip()]
                subdomains.extend(subs)

    click.echo(f"[*] Checking {len(subdomains)} subdomains for takeover...")
    results = run_takeover_scan(subdomains, threads=threads)
    vulns = [r for r in results if r.get("vulnerable")]
    click.echo(f"[+] {len(vulns)} vulnerable subdomains found")
    for r in vulns:
        click.echo(f"  \033[91m[{r['severity'].upper()}]\033[0m {r['subdomain']} → {r['service']} — {r['evidence'][:80]}")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump(results, f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# nuclei-run
# ---------------------------------------------------------------------------
@cli.command(name="nuclei-run", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--templates", "-t", multiple=True, help="Template file(s) or directory")
@click.option("--tags", multiple=True, help="Tag filter (cve, rce, sqli, xss, ...)")
@click.option("--severity", multiple=True,
              type=click.Choice(["critical","high","medium","low","info"]),
              help="Severity filter")
@click.option("--rate-limit", "rate_limit", default=150, show_default=True)
@click.option("--python-only", "python_only", is_flag=True, default=False,
              help="Force pure-Python fallback (no nuclei binary)")
@click.option("-o", "--output", default=None)
def nuclei_run_cmd(target, templates, tags, severity, rate_limit, python_only, output) -> None:
    """Run Nuclei templates against a target (or use built-in pure-Python templates).

    \b
    Examples:
      phantomrecon nuclei-run https://target.com
      phantomrecon nuclei-run https://target.com --tags cve --severity critical,high
      phantomrecon nuclei-run https://target.com --python-only
      phantomrecon nuclei-run https://target.com -t /path/to/templates/ -o nuclei.json
    """
    from .modules.nuclei_runner import NucleiRunner

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    runner = NucleiRunner(force_python=python_only)
    results = runner.run(
        target,
        templates=list(templates) or None,
        tags=list(tags) or None,
        severity=list(severity) or None,
        rate_limit=rate_limit,
    )
    click.echo(f"[+] Nuclei found {len(results)} issues")
    for r in results:
        sev_colors = {"critical":"\033[91m","high":"\033[91m","medium":"\033[93m","low":"\033[94m","info":"\033[97m"}
        col = sev_colors.get(r.severity, "")
        click.echo(f"  {col}[{r.severity.upper()}]\033[0m [{r.template_id}] {r.name} — {r.url}")
        if r.extracted:
            click.echo(f"    Extracted: {', '.join(r.extracted[:3])}")
    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# protocol-fuzz
# ---------------------------------------------------------------------------
@cli.command(name="protocol-fuzz", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("host")
@click.option("--url", "target_url", default=None, help="HTTP/HTTPS base URL for GraphQL/WS fuzzing")
@click.option("--graphql", is_flag=True, default=False)
@click.option("--websocket", is_flag=True, default=False)
@click.option("--smtp", is_flag=True, default=False)
@click.option("--ftp", is_flag=True, default=False)
@click.option("--smb", is_flag=True, default=False)
@click.option("--redis", is_flag=True, default=False)
@click.option("--mongodb", is_flag=True, default=False)
@click.option("--elasticsearch", is_flag=True, default=False)
@click.option("--kerberos", is_flag=True, default=False)
@click.option("--realm", default=None, help="Kerberos realm (e.g. CORP.LOCAL)")
@click.option("--users", "-u", default=None, help="Username file for Kerberos/SMTP enum")
@click.option("--all-protocols", "all_protocols", is_flag=True, default=False)
@click.option("-o", "--output", default=None)
def protocol_fuzz_cmd(host, target_url, graphql, websocket, smtp, ftp, smb,
                      redis, mongodb, elasticsearch, kerberos, realm, users,
                      all_protocols, output) -> None:
    """Protocol-level fuzzer: GraphQL, WebSocket, SMTP, FTP, SMB, Redis, MongoDB, Kerberos.

    \b
    Examples:
      phantomrecon protocol-fuzz target.com --graphql --url https://target.com
      phantomrecon protocol-fuzz target.com --smtp --users users.txt
      phantomrecon protocol-fuzz target.com --redis --mongodb --elasticsearch
      phantomrecon protocol-fuzz target.com --smb
      phantomrecon protocol-fuzz target.com --kerberos --realm CORP.LOCAL --users users.txt
      phantomrecon protocol-fuzz target.com --all-protocols --url https://target.com -o proto.json
    """
    from .modules.protocol_fuzz import ProtocolFuzzer

    if all_protocols:
        graphql = websocket = smtp = ftp = smb = redis = mongodb = elasticsearch = True

    user_list = None
    if users:
        with open(users) as f:
            user_list = [l.strip() for l in f if l.strip()]

    ports = {}
    fuzzer = ProtocolFuzzer()

    results = {}
    if graphql or websocket:
        url = target_url or f"https://{host}"
        if graphql:
            from .modules.protocol_fuzz import GraphQLFuzzer
            r = GraphQLFuzzer(url).fuzz()
            results["graphql"] = [x.__dict__ for x in r]
            click.echo(f"[GraphQL] {len(r)} findings")
            for finding in r:
                click.echo(f"  [{finding.severity.upper()}] {finding.finding}: {finding.evidence[:80]}")
        if websocket:
            from .modules.protocol_fuzz import WebSocketFuzzer
            r = WebSocketFuzzer().fuzz_endpoint(host, 80)
            results["websocket"] = [x.__dict__ for x in r]
            click.echo(f"[WebSocket] {len(r)} findings")
    if smtp:
        from .modules.protocol_fuzz import SMTPRecon
        r = SMTPRecon(host).recon(user_list)
        results["smtp"] = [x.__dict__ for x in r]
        click.echo(f"[SMTP] {len(r)} findings")
        for f in r:
            click.echo(f"  [{f.severity.upper()}] {f.finding}: {f.evidence[:80]}")
    if ftp:
        from .modules.protocol_fuzz import FTPRecon
        r = FTPRecon(host).recon()
        results["ftp"] = [x.__dict__ for x in r]
        click.echo(f"[FTP] {len(r)} findings")
        for f in r:
            click.echo(f"  [{f.severity.upper()}] {f.finding}")
    if smb:
        from .modules.protocol_fuzz import SMBRecon
        r = SMBRecon(host).probe()
        results["smb"] = [x.__dict__ for x in r]
        click.echo(f"[SMB] {len(r)} findings")
        for f in r:
            click.echo(f"  [{f.severity.upper()}] {f.finding}: {f.evidence[:80]}")
    if redis:
        from .modules.protocol_fuzz import RedisRecon
        r = RedisRecon(host).probe()
        results["redis"] = [x.__dict__ for x in r]
        click.echo(f"[Redis] {len(r)} findings")
        for f in r:
            click.echo(f"  [{f.severity.upper()}] {f.finding}")
    if mongodb:
        from .modules.protocol_fuzz import MongoDBRecon
        r = MongoDBRecon(host).probe()
        results["mongodb"] = [x.__dict__ for x in r]
        click.echo(f"[MongoDB] {len(r)} findings")
    if elasticsearch:
        from .modules.protocol_fuzz import ElasticsearchRecon
        r = ElasticsearchRecon(host).probe()
        results["elasticsearch"] = [x.__dict__ for x in r]
        click.echo(f"[Elasticsearch] {len(r)} findings")
        for f in r:
            click.echo(f"  [{f.severity.upper()}] {f.finding}")
    if kerberos:
        from .modules.protocol_fuzz import KerberosRecon
        if not realm:
            click.echo("[-] --realm required for Kerberos (e.g. CORP.LOCAL)", err=True)
        else:
            krb = KerberosRecon(host)
            users_k = user_list or ["administrator","admin","user","test","guest"]
            r = krb.enumerate_users(users_k, realm) + krb.check_asrep_roasting(users_k, realm)
            results["kerberos"] = [x.__dict__ for x in r]
            click.echo(f"[Kerberos] {len(r)} findings")
            for f in r:
                click.echo(f"  [{f.severity.upper()}] {f.finding}")

    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump(results, f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# ml-wordlist
# ---------------------------------------------------------------------------
@cli.command(name="ml-wordlist", context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--train", default=None, help="Train Markov model from this wordlist file")
@click.option("--org", default=None, help="Org/company name for org-specific generation")
@click.option("--keywords", default=None, help="Comma-separated target keywords")
@click.option("--profile-text", "profile_text", default=None, help="File containing org text for NLP profiling")
@click.option("--count", default=5000, show_default=True, type=int, help="Number of candidates to generate")
@click.option("--min-len", "min_len", default=6, show_default=True, type=int)
@click.option("--max-len", "max_len", default=14, show_default=True, type=int)
@click.option("--order", default=3, show_default=True, type=int, help="Markov chain order (2-5 recommended)")
@click.option("-o", "--output", default=None, help="Save wordlist to file")
def ml_wordlist_cmd(train, org, keywords, profile_text, count, min_len, max_len, order, output) -> None:
    """AI-powered wordlist generator: Markov n-gram model + org-specific candidates.

    \b
    Examples:
      phantomrecon ml-wordlist --train rockyou.txt --count 10000 -o smart.txt
      phantomrecon ml-wordlist --org "Acme Corp" --keywords "acme,admin,corp" -o acme.txt
      phantomrecon ml-wordlist --profile-text about_page.txt --org acme -o profiled.txt
      phantomrecon ml-wordlist --train rockyou.txt --org acme --count 20000 -o combined.txt
    """
    from .modules.ml_engine import MarkovPasswordModel, OrgPasswordGenerator, NLPTargetProfiler

    candidates = []

    if profile_text:
        with open(profile_text) as f:
            text = f.read()
        profiler = NLPTargetProfiler(text)
        profile  = profiler.profile()
        click.echo(f"[*] NLP profile: {len(profile['keywords'])} keywords, "
                   f"{len(profile['names'])} names, {len(profile['technologies'])} techs")
        if not keywords:
            keywords = ",".join(profile["password_seeds"][:20])

    if org or keywords:
        kw = [k.strip() for k in keywords.split(",")] if keywords else []
        gen = OrgPasswordGenerator(org or "target", keywords=kw)
        org_cands = gen.generate(max_count=count // 2)
        candidates.extend(org_cands)
        click.echo(f"[*] Org-specific: {len(org_cands)} candidates")

    if train:
        model = MarkovPasswordModel(order=order)
        n = model.train_from_file(train)
        click.echo(f"[*] Markov model trained on {n} words (order={order})")
        markov_cands = model.generate(min_len=min_len, max_len=max_len,
                                       count=count - len(candidates))
        candidates.extend(markov_cands)
        click.echo(f"[*] Markov generated: {len(markov_cands)} candidates")

    candidates = list(dict.fromkeys(candidates))[:count]
    click.echo(f"[+] Total unique candidates: {len(candidates)}")

    if output:
        with open(output, "w") as f:
            f.write("\n".join(candidates))
        click.echo(f"[+] Saved to {output}")
    else:
        for c in candidates[:50]:
            click.echo(c)
        if len(candidates) > 50:
            click.echo(f"  ... ({len(candidates)-50} more, use -o to save)")


# ---------------------------------------------------------------------------
# threat-intel
# ---------------------------------------------------------------------------
@cli.command(name="threat-intel", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--vt-key", "vt_key", envvar="VT_API_KEY", default=None, help="VirusTotal API key")
@click.option("--abuse-key", "abuse_key", envvar="ABUSEIPDB_KEY", default=None, help="AbuseIPDB API key")
@click.option("--shodan-key", "shodan_key", envvar="SHODAN_KEY", default=None, help="Shodan API key")
@click.option("--findings", default=None, help="JSON findings file to enrich with MITRE ATT&CK tags")
@click.option("--report", default=None, help="Output HTML report file")
@click.option("--report-text", "report_text", default=None, help="Output text report file")
@click.option("--diff-baseline", "diff_baseline", default=None, help="Baseline JSON for regression diff")
@click.option("--save-baseline", "save_baseline", is_flag=True, default=False, help="Save current findings as new baseline")
@click.option("-o", "--output", default=None, help="Save enriched JSON")
def threat_intel_cmd(target, vt_key, abuse_key, shodan_key, findings,
                     report, report_text, diff_baseline, save_baseline, output) -> None:
    """Threat intel enrichment: VirusTotal, AbuseIPDB, Shodan, MITRE ATT&CK, HTML report.

    \b
    Examples:
      phantomrecon threat-intel 1.2.3.4 --vt-key YOUR_KEY --shodan-key YOUR_KEY
      phantomrecon threat-intel example.com --vt-key YOUR_KEY
      phantomrecon threat-intel example.com --findings scan.json --report report.html
      phantomrecon threat-intel example.com --findings scan.json --diff-baseline baseline.json
      phantomrecon threat-intel example.com --findings scan.json --save-baseline
    """
    import json as _json
    from .modules.threat_intel import ThreatIntelAggregator, ReportGenerator, RegressionScanner, tag_mitre

    aggregator = ThreatIntelAggregator(vt_key=vt_key, abuse_key=abuse_key, shodan_key=shodan_key)

    import re
    is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", target))
    if is_ip:
        click.echo(f"[*] Enriching IP: {target}")
        data = aggregator.enrich_ip(target)
        click.echo(_json.dumps(data, indent=2, default=str))
    else:
        click.echo(f"[*] Enriching domain: {target}")
        data = aggregator.enrich_domain(target)
        click.echo(_json.dumps(data, indent=2, default=str))

    all_findings = []
    if findings:
        with open(findings) as f:
            all_findings = _json.load(f)
        all_findings = aggregator.enrich_findings(all_findings)
        click.echo(f"[*] Enriched {len(all_findings)} findings with MITRE ATT&CK tags")

    if diff_baseline and all_findings:
        scanner = RegressionScanner(diff_baseline)
        diff = scanner.diff(all_findings)
        click.echo(f"\n[REGRESSION DIFF]")
        click.echo(f"  New:      {diff['summary']['new_count']}")
        click.echo(f"  Resolved: {diff['summary']['resolved_count']}")
        click.echo(f"  Unchanged:{diff['summary']['unchanged_count']}")
        for f in diff["new"]:
            click.echo(f"  \033[91m[NEW]\033[0m [{f.get('severity','?').upper()}] {f.get('title','')}")

    if save_baseline and all_findings:
        scanner = RegressionScanner()
        scanner.save_baseline(all_findings)
        click.echo(f"[+] Baseline saved")

    if (report or report_text) and all_findings:
        import datetime
        gen = ReportGenerator(target=target, findings=all_findings)
        if report_text:
            text = gen.generate_text()
            with open(report_text, "w") as f:
                f.write(text)
            click.echo(f"[+] Text report: {report_text}")
        if report:
            html = gen.generate_html(output_path=report)
            click.echo(f"[+] HTML report: {report}")

    if output:
        with open(output, "w") as f:
            _json.dump({"target": target, "enrichment": data, "findings": all_findings}, f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# stealth-check
# ---------------------------------------------------------------------------
@cli.command(name="stealth-check", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("--http2", is_flag=True, default=False, help="Detect HTTP/2 support")
@click.option("--http3", is_flag=True, default=False, help="Detect HTTP/3 (QUIC) via Alt-Svc header")
@click.option("--entropy-scan", "entropy_scan", is_flag=True, default=False, help="Scan page for leaked tokens/keys")
@click.option("--polyglot", is_flag=True, default=False, help="Test polyglot injection payloads")
@click.option("--decoy", is_flag=True, default=False, help="Send decoy traffic")
@click.option("--all-checks", "all_checks", is_flag=True, default=False)
def stealth_check_cmd(url, http2, http3, entropy_scan, polyglot, decoy, all_checks) -> None:
    """Stealth & evasion checks: HTTP/2, HTTP/3, entropy scan, polyglot payloads.

    \b
    Examples:
      phantomrecon stealth-check https://target.com --http2 --http3
      phantomrecon stealth-check https://target.com --entropy-scan
      phantomrecon stealth-check https://target.com --polyglot
      phantomrecon stealth-check https://target.com --all-checks
    """
    from .modules.stealth import TLSFingerprintRandomizer, EntropyScanner, PolyglotEngine, DecoyTrafficGenerator
    from urllib.parse import urlparse

    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    if all_checks:
        http2 = http3 = entropy_scan = polyglot = True

    parsed = urlparse(url)
    host = parsed.hostname

    if http2:
        tls = TLSFingerprintRandomizer()
        supports = tls.detect_http2(host, 443)
        click.echo(f"[HTTP/2]  {'✓ Supported' if supports else '✗ Not supported'}")

    if http3:
        tls = TLSFingerprintRandomizer()
        alt_svc = tls.detect_http3(url)
        if alt_svc:
            click.echo(f"[HTTP/3]  ✓ Detected via Alt-Svc: {alt_svc}")
        else:
            click.echo(f"[HTTP/3]  ✗ Not detected")

    if entropy_scan:
        from .modules.ml_engine import EntropyScanner as ES
        scanner = ES()
        findings = scanner.scan_url(url)
        click.echo(f"[Entropy] {len(findings)} high-entropy tokens found")
        for f in findings:
            click.echo(f"  [{f['severity'].upper()}] {f['type']}: {f['value'][:60]}  entropy={f['entropy']}")

    if polyglot:
        from .modules.stealth import PolyglotEngine as PE
        engine = PE()
        click.echo(f"[Polyglot] Available payloads:")
        for p in engine.get_all():
            click.echo(f"  [{p['name']}]  {p['payload'][:60]}")

    if decoy:
        from .modules.stealth import DecoyTrafficGenerator as DT
        click.echo(f"[Decoy] Sending 5 decoy requests...")
        DT(url).send_decoys(5)
        click.echo(f"[Decoy] Done")


# ---------------------------------------------------------------------------
# hydra  (multi-protocol brute-force)
# ---------------------------------------------------------------------------
@cli.command(name="hydra", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("-p", "--protocol", "protocol", required=True,
              help="Protocol: http-form-post, http-basic, ssh, ftp, smtp, mysql, postgres, redis, smb, etc.")
@click.option("-U", "--userlist", "userlist", default=None, help="File of usernames (one per line)")
@click.option("-P", "--passlist", "passlist", default=None, help="File of passwords (one per line)")
@click.option("-u", "--username", "username", default=None, help="Single username")
@click.option("-p2", "--password", "password", default=None, help="Single password")
@click.option("-C", "--combo", "combo", default=None, help="Combo file (user:pass per line)")
@click.option("--port", default=0, type=int, help="Target port (0 = protocol default)")
@click.option("--form-path", "form_path", default="/login", show_default=True,
              help="Login form URL path (for HTTP form attacks)")
@click.option("--form-user-field", "user_field", default="username", show_default=True)
@click.option("--form-pass-field", "pass_field", default="password", show_default=True)
@click.option("--success-string", "success_str", default=None,
              help="String in response that indicates login success")
@click.option("--fail-string", "fail_str", default=None,
              help="String in response that indicates login failure")
@click.option("-t", "--threads", default=16, show_default=True, type=int)
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--delay", default=0.0, show_default=True, type=float,
              help="Base delay (seconds) between attempts per thread")
@click.option("--lockout-threshold", "lockout_threshold", default=5, show_default=True, type=int,
              help="Back off after N consecutive failures")
@click.option("--proxy", default=None, help="HTTP/SOCKS5 proxy (http://... or socks5://...)")
@click.option("--checkpoint", default=None, help="Save/resume checkpoint file")
@click.option("--stop-on-success", "stop_on_success", is_flag=True, default=True)
@click.option("-v", "--verbose", is_flag=True, default=False)
@click.option("-o", "--output", default=None, help="Save found credentials to file")
def hydra_cmd(target, protocol, userlist, passlist, username, password, combo,
              port, form_path, user_field, pass_field, success_str, fail_str,
              threads, timeout, delay, lockout_threshold, proxy, checkpoint,
              stop_on_success, verbose, output):
    """Multi-protocol brute-force engine (Hydra-equivalent).

    \b
    Examples:
      phantomrecon hydra target.com -p ssh -U users.txt -P rockyou.txt -t 16
      phantomrecon hydra target.com -p http-form-post -u admin -P rockyou.txt --form-path /login
      phantomrecon hydra target.com -p ftp -U users.txt -P passes.txt --timeout 8
      phantomrecon hydra target.com -p mysql -u root -P rockyou.txt --port 3306
      phantomrecon hydra target.com -p redis -u "" -P rockyou.txt
      phantomrecon hydra target.com -p smb -C combos.txt --threads 8 -o found.txt
      phantomrecon hydra target.com -p http-basic -u admin -P rockyou.txt --proxy socks5://127.0.0.1:9050
    """
    from .modules.hydra import run_hydra, Protocol, HydraConfig

    usernames = []
    passwords = []
    combos    = []

    if userlist:
        with open(userlist) as f:
            usernames = [l.strip() for l in f if l.strip()]
    if username:
        usernames = [username]
    if passlist:
        with open(passlist) as f:
            passwords = [l.strip() for l in f if l.strip()]
    if password:
        passwords = [password]
    if combo:
        with open(combo) as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    u, p = line.split(":", 1)
                    combos.append((u, p))

    if not usernames and not combos:
        click.echo("[!] Provide -U/--userlist or -u/--username or -C/--combo")
        return
    if not passwords and not combos:
        click.echo("[!] Provide -P/--passlist or -p2/--password or -C/--combo")
        return

    try:
        proto = Protocol(protocol.lower())
    except ValueError:
        click.echo(f"[!] Unknown protocol '{protocol}'. Valid: " +
                   ", ".join(p.value for p in Protocol))
        return

    click.echo(f"[*] Starting Hydra on {target} | protocol={proto.value} | "
               f"users={len(usernames)} | passes={len(passwords)} | combos={len(combos)}")

    results = run_hydra(
        host=target, protocol=protocol,
        usernames=usernames, passwords=passwords, combos=combos,
        port=port, threads=threads, timeout=timeout, delay=delay,
        lockout_threshold=lockout_threshold, proxy=proxy,
        checkpoint_file=checkpoint, stop_on_first_found=stop_on_success,
        verbose=verbose,
        http_path=form_path, user_field=user_field, pass_field=pass_field,
        success_string=success_str, fail_string=fail_str,
    )

    found = [r for r in results if r.success]
    click.echo(f"\n[+] Found {len(found)} credential(s):")
    lines = []
    for r in found:
        line = f"  [+] {r.protocol.value}://{r.host}:{r.port}  {r.username}:{r.password}"
        click.echo(line)
        lines.append(f"{r.username}:{r.password}")
    if output and lines:
        with open(output, "w") as f:
            f.write("\n".join(lines))
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# sqli-advanced  (expert SQL injection engine)
# ---------------------------------------------------------------------------
@cli.command(name="sqli-advanced", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("-p", "--param", "param", default=None,
              help="Parameter to test (default: test all GET params)")
@click.option("--method", default="GET", show_default=True, type=click.Choice(["GET","POST"], case_sensitive=False))
@click.option("--data", "post_data", default=None, help="POST body (use with --method POST)")
@click.option("--cookie", "cookie", default=None, help="Cookies (name=value; name2=value2)")
@click.option("--dbms", default=None,
              type=click.Choice(["mysql","postgres","mssql","oracle","sqlite"], case_sensitive=False),
              help="Force DBMS (skip detection)")
@click.option("--attack", "attack_type", default=None,
              type=click.Choice(["error","union","blind","time","oob","auth-bypass","all"], case_sensitive=False),
              help="Injection technique (default: auto-detect)")
@click.option("--enumerate", "enumerate", is_flag=True, default=False,
              help="Enumerate databases, tables, columns, data")
@click.option("--dump-table", "dump_table", default=None, help="Table to dump after enumeration")
@click.option("--dump-limit", "dump_limit", default=50, show_default=True, type=int)
@click.option("--os-cmd", "os_cmd", default=None, help="OS command to execute (xp_cmdshell / UDF)")
@click.option("--file-read", "file_read", default=None, help="File path to read via SQLi")
@click.option("--waf-evasion", "waf_evasion", is_flag=True, default=True, show_default=True)
@click.option("--threads", default=4, show_default=True, type=int)
@click.option("--timeout", default=15.0, show_default=True, type=float)
@click.option("--delay", default=0.2, show_default=True, type=float)
@click.option("--proxy", default=None, help="HTTP proxy")
@click.option("-o", "--output", default=None, help="Save results JSON")
@click.option("-v", "--verbose", is_flag=True, default=False)
def sqli_advanced_cmd(url, param, method, post_data, cookie, dbms, attack_type,
                      enumerate, dump_table, dump_limit, os_cmd, file_read,
                      waf_evasion, threads, timeout, delay, proxy, output, verbose):
    """Expert SQL injection engine: error/union/blind/time/OOB/auth-bypass.

    \b
    Examples:
      phantomrecon sqli-advanced "http://target.com/page?id=1"
      phantomrecon sqli-advanced "http://target.com/page?id=1" --attack union --enumerate
      phantomrecon sqli-advanced "http://target.com/page?id=1" --attack time --dbms mysql
      phantomrecon sqli-advanced "http://target.com/login" --method POST --data "user=admin&pass=x" --attack auth-bypass
      phantomrecon sqli-advanced "http://target.com/page?id=1" --enumerate --dump-table users
      phantomrecon sqli-advanced "http://target.com/page?id=1" --os-cmd "whoami" --dbms mssql
      phantomrecon sqli-advanced "http://target.com/page?id=1" --file-read /etc/passwd --dbms mysql
      phantomrecon sqli-advanced "http://target.com/page?id=1" --waf-evasion --proxy http://127.0.0.1:8080
    """
    from .modules.sqli_advanced import run_sqli_scan, SQLiConfig, InjectionType, DBMS

    cookies = {}
    if cookie:
        for pair in cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    params = None
    if param:
        from urllib.parse import urlparse, parse_qsl
        qs = dict(parse_qsl(urlparse(url).query))
        if param in qs:
            params = {param: qs[param]}
        else:
            params = {param: ""}

    cfg = SQLiConfig(
        threads=threads, timeout=timeout, delay=delay,
        waf_evasion=waf_evasion, dump_limit=dump_limit,
    )

    click.echo(f"[*] SQLi scan: {url} | method={method} | waf_evasion={waf_evasion}")

    results = run_sqli_scan(
        url=url, method=method, params=params,
        post_data=post_data, cookies=cookies,
        dbms=dbms, attack_types=[attack_type] if attack_type and attack_type != "all" else None,
        enumerate_db=enumerate, dump_table=dump_table,
        os_command=os_cmd, file_path=file_read,
        config=cfg, proxy=proxy, verbose=verbose,
    )

    confirmed = [r for r in results if r.confirmed]
    click.echo(f"[+] {len(confirmed)} confirmed injection(s):")
    for r in confirmed:
        click.echo(f"  [{r.injection_type.value.upper()}] param='{r.parameter}' "
                   f"dbms={r.dbms.value} payload={r.payload[:60]}")
        if r.databases:
            click.echo(f"    Databases: {r.databases}")
        if r.current_user:
            click.echo(f"    User: {r.current_user}")
        if r.data:
            click.echo(f"    Dumped {len(r.data)} rows")

    if output and results:
        import json as _json
        with open(output, "w") as f:
            _json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# padbuster  (CBC padding oracle)
# ---------------------------------------------------------------------------
@cli.command(name="padbuster", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.argument("ciphertext")
@click.option("--block-size", "block_size", default=16, show_default=True, type=int,
              help="Block size (8 or 16)")
@click.option("--encoding", default="base64",
              type=click.Choice(["base64","base64url","hex","url","raw"], case_sensitive=False))
@click.option("--oracle", "oracle_detection", default="status",
              type=click.Choice(["status","body","error","length"], case_sensitive=False),
              help="Oracle detection method")
@click.option("--error-string", "error_string", default="", help="Error string in body (for oracle=error)")
@click.option("--padding-status", "padding_status", default=500, show_default=True, type=int,
              help="HTTP status code indicating padding error")
@click.option("--cookie-param", "cookie_param", default=None,
              help="Cookie name containing ciphertext (will replace during oracle queries)")
@click.option("--post-param", "post_param", default=None,
              help="POST parameter name containing ciphertext")
@click.option("--encrypt", "plaintext_to_encrypt", default=None,
              help="Plaintext string to encrypt (forge ciphertext)")
@click.option("--threads", default=8, show_default=True, type=int)
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--proxy", default=None)
@click.option("-v", "--verbose", is_flag=True, default=False)
@click.option("-o", "--output", default=None, help="Save result JSON")
def padbuster_cmd(url, ciphertext, block_size, encoding, oracle_detection,
                  error_string, padding_status, cookie_param, post_param,
                  plaintext_to_encrypt, threads, timeout, proxy, verbose, output):
    """CBC Padding Oracle attack: decrypt tokens and forge arbitrary ciphertext.

    \b
    Examples:
      phantomrecon padbuster "http://target.com/auth" "rW12Cx...=" --block-size 16
      phantomrecon padbuster "http://target.com/auth" "rW12Cx...=" --oracle body --error-string "Invalid padding"
      phantomrecon padbuster "http://target.com/auth" "abc123" --encoding hex --block-size 8
      phantomrecon padbuster "http://target.com/auth" "rW12Cx...=" --cookie-param session
      phantomrecon padbuster "http://target.com/auth" "rW12Cx...=" --encrypt "user=admin;role=superuser"
      phantomrecon padbuster "http://target.com/auth" "rW12Cx...=" --threads 16 --proxy http://127.0.0.1:8080
    """
    from .modules.padbuster import run_padbuster, CiphertextEncoding, OracleDetection

    click.echo(f"[*] PadBuster: {url} | block={block_size} | encoding={encoding} | "
               f"oracle={oracle_detection}")

    result = run_padbuster(
        url=url, ciphertext=ciphertext, block_size=block_size,
        encoding=encoding, oracle_detection=oracle_detection,
        error_string=error_string, padding_error_status=padding_status,
        cookie_param=cookie_param, post_param=post_param,
        plaintext_to_encrypt=plaintext_to_encrypt,
        threads=threads, timeout=timeout, proxy=proxy, verbose=verbose,
    )

    if result.success:
        click.echo(f"[+] Decrypted: {result.plaintext_str!r}")
        click.echo(f"[+] Oracle calls: {result.oracle_calls}  elapsed: {result.elapsed:.1f}s")
        if result.encrypted_ciphertext:
            import base64 as _b64
            click.echo(f"[+] Forged ciphertext (base64): "
                       f"{_b64.b64encode(result.encrypted_ciphertext).decode()}")
    else:
        click.echo(f"[-] Failed: {result.error}")
        click.echo(f"    Oracle calls: {result.oracle_calls}")

    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump({
                "success": result.success,
                "plaintext": result.plaintext_str,
                "oracle_calls": result.oracle_calls,
                "elapsed": result.elapsed,
                "error": result.error,
            }, f, indent=2)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# s3scan  (cloud storage bucket scanner)
# ---------------------------------------------------------------------------
@cli.command(name="s3scan", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("target")
@click.option("--words", "extra_words", default=None,
              help="Comma-separated extra keywords for bucket name generation")
@click.option("--buckets", "bucket_file", default=None,
              help="File with explicit bucket names to test (one per line)")
@click.option("--providers", default="aws-s3,azure-blob,gcs",
              show_default=True, help="Comma-separated providers to scan")
@click.option("--no-source", "no_source", is_flag=True, default=False,
              help="Skip extracting bucket names from target page source")
@click.option("--threads", default=20, show_default=True, type=int)
@click.option("--timeout", default=10.0, show_default=True, type=float)
@click.option("--proxy", default=None)
@click.option("--show-objects", "show_objects", is_flag=True, default=False,
              help="Print all enumerated objects (not just sensitive)")
@click.option("-o", "--output", default=None, help="Save results JSON")
@click.option("-v", "--verbose", is_flag=True, default=False)
def s3scan_cmd(target, extra_words, bucket_file, providers, no_source,
               threads, timeout, proxy, show_objects, output, verbose):
    """Cloud bucket scanner: AWS S3, Azure Blob, GCS — find open/misconfigured buckets.

    \b
    Examples:
      phantomrecon s3scan target.com
      phantomrecon s3scan target.com --words "backup,media,static,dev"
      phantomrecon s3scan target.com --providers aws-s3
      phantomrecon s3scan target.com --buckets my_buckets.txt
      phantomrecon s3scan target.com --providers aws-s3,gcs --threads 30 --show-objects
      phantomrecon s3scan target.com -o findings.json
    """
    from .modules.s3scanner import run_s3_scan, S3Scanner

    extra = [w.strip() for w in extra_words.split(",")] if extra_words else None
    prov  = [p.strip() for p in providers.split(",")]

    if bucket_file:
        with open(bucket_file) as f:
            bucket_names = [l.strip() for l in f if l.strip()]
        scanner  = S3Scanner(threads=threads, timeout=timeout, proxy=proxy, verbose=verbose,
                             providers=[__import__("phantomrecon.modules.s3scanner",
                                                    fromlist=["CloudProvider"]).CloudProvider(p)
                                        for p in prov])
        results  = scanner.scan_buckets(bucket_names)
    else:
        results = run_s3_scan(
            target=target, extra_words=extra, threads=threads, timeout=timeout,
            proxy=proxy, providers=prov, verbose=verbose, scan_source=not no_source,
        )

    vuln = [r for r in results if r.severity in ("critical", "high")]
    click.echo(f"[+] {len(results)} bucket(s) found | {len(vuln)} critical/high")

    for r in results:
        sev_color = {"critical": "\033[91m", "high": "\033[93m",
                     "medium": "\033[94m", "low": "\033[92m", "info": "\033[0m"}
        col = sev_color.get(r.severity, "\033[0m")
        flags = []
        if r.listable:  flags.append("LIST")
        if r.readable:  flags.append("READ")
        if r.writable:  flags.append("WRITE")
        if r.deletable: flags.append("DELETE")
        click.echo(f"  {col}[{r.severity.upper()}]\033[0m "
                   f"{r.provider.value} | {r.bucket_name} | "
                   f"{'|'.join(flags) if flags else 'exists'}")
        if r.sensitive_files:
            click.echo(f"    Sensitive files ({len(r.sensitive_files)}):")
            for sf in r.sensitive_files[:5]:
                click.echo(f"      {sf}")
        if show_objects and r.objects:
            click.echo(f"    Objects ({r.total_objects}):")
            for obj in r.objects[:10]:
                click.echo(f"      {obj.key}  ({obj.size} bytes)")

    if output:
        import json as _json
        with open(output, "w") as f:
            _json.dump([{
                "provider": r.provider.value, "bucket": r.bucket_name,
                "endpoint": r.endpoint, "severity": r.severity,
                "listable": r.listable, "readable": r.readable,
                "writable": r.writable, "total_objects": r.total_objects,
                "sensitive_files": r.sensitive_files,
            } for r in results], f, indent=2)
        click.echo(f"[+] Saved to {output}")


# ---------------------------------------------------------------------------
# websploit  (web exploitation framework)
# ---------------------------------------------------------------------------
@cli.command(name="websploit", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("url")
@click.option("--modules", default=None,
              help="Comma-separated modules: xss,ssti,ssrf,lfi,cmd,xxe,redirect,crlf,smuggle,graphql,info")
@click.option("--params", "params_str", default=None,
              help="Comma-separated param=value pairs (e.g. id=1,search=test)")
@click.option("--cookie", "cookie", default=None, help="Cookies (name=value; name2=value2)")
@click.option("--oob-domain", "oob_domain", default="", help="OOB callback domain for SSRF/XXE/RCE")
@click.option("--threads", default=8, show_default=True, type=int)
@click.option("--timeout", default=12.0, show_default=True, type=float)
@click.option("--proxy", default=None)
@click.option("--no-waf-evasion", "no_waf", is_flag=True, default=False)
@click.option("-o", "--output", default=None, help="Save results JSON")
@click.option("-v", "--verbose", is_flag=True, default=False)
def websploit_cmd(url, modules, params_str, cookie, oob_domain, threads, timeout,
                  proxy, no_waf, output, verbose):
    """Expert web exploitation framework: XSS, SSTI, SSRF, LFI, CMDi, XXE, Smuggling, GraphQL.

    \b
    Examples:
      phantomrecon websploit "http://target.com/search?q=test"
      phantomrecon websploit "http://target.com/search?q=test" --modules xss,ssti,lfi
      phantomrecon websploit "http://target.com/" --modules info,graphql
      phantomrecon websploit "http://target.com/page?id=1" --modules ssrf,xxe --oob-domain yourcollab.oast.pro
      phantomrecon websploit "http://target.com/page?file=x" --modules lfi,cmd
      phantomrecon websploit "http://target.com/" --modules smuggle
      phantomrecon websploit "http://target.com/" --cookie "session=abc123" --proxy http://127.0.0.1:8080
      phantomrecon websploit "http://target.com/" --modules xss,ssti,lfi,cmd,xxe -o findings.json
    """
    from .modules.websploit import run_websploit

    params = {}
    if params_str:
        for pair in params_str.split(","):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                params[k.strip()] = v.strip()

    cookies = {}
    if cookie:
        for pair in cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=", 1)
                cookies[k.strip()] = v.strip()

    mod_list = [m.strip() for m in modules.split(",")] if modules else None

    click.echo(f"[*] WebSploit: {url}")
    click.echo(f"    Modules: {', '.join(mod_list) if mod_list else 'all'}")

    results = run_websploit(
        url=url, params=params or None, cookies=cookies or None,
        modules=mod_list, threads=threads, timeout=timeout,
        proxy=proxy, oob_domain=oob_domain, verbose=verbose,
    )

    click.echo(f"\n[+] {len(results)} finding(s):")
    sev_order = {"critical": "\033[91m", "high": "\033[93m",
                 "medium": "\033[94m", "low": "\033[92m", "info": "\033[0m"}
    for r in results:
        col = sev_order.get(r.severity.value, "\033[0m")
        click.echo(f"  {col}[{r.severity.value.upper()}]\033[0m "
                   f"[{r.vuln_class.value}] param={r.parameter!r}")
        click.echo(f"    {r.description}")
        if r.evidence:
            click.echo(f"    Evidence: {r.evidence[:120]}")
        click.echo(f"    Payload: {r.payload[:80]}")

    if output and results:
        import json as _json
        with open(output, "w") as f:
            _json.dump([{
                "vuln_class": r.vuln_class.value,
                "url": r.url,
                "parameter": r.parameter,
                "method": r.method,
                "severity": r.severity.value,
                "cvss": r.cvss,
                "confirmed": r.confirmed,
                "payload": r.payload,
                "evidence": r.evidence,
                "description": r.description,
                "remediation": r.remediation,
            } for r in results], f, indent=2)
        click.echo(f"[+] Saved to {output}")


def run() -> None:
    cli()
