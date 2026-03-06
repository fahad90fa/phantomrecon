# PhantomRecon

PhantomRecon is a **full-spectrum offensive security suite** that blends advanced recon, exploitation, fuzzing, and reporting capabilities in a single cross-platform Python application. It ships with both a **feature-rich CLI** and a **Qt-based GUI** so teams can operate manually command-by-command or run aggressive automated scanning pipelines.

## Core Features
- **Aggressive scanning pipeline** that steps through 31 modules (fingerprinting, CT, DNS, brute force, fuzzing, ML-enabled wordlists, intelligence + reporting) with live GUI feedback.
- **Multi-protocol CLI** covering John the Ripper, Hydra, PadBuster, SQLi Advanced, WebSploit, advanced S3 scanning, nuclei templating, payload generation, SSL/TLS analysis, and more.
- **Defense-grade modules** like TLS/SSL auditing, HTTP/2+HTTP/3 fuzzing, JWT/OAuth/2FA bypass techniques, deserialization detection, and subdomain takeover checks.
- **Expert automation**: built-in engines for hydra-style brute forcing, ML-powered password generation, protocol-specific fuzzing, and threat intel enrichment (VirusTotal, AbuseIPDB, Shodan, MITRE ATT&CK mapping).
- **Reporting & export**: findings stream through a GUI + CLI notification bus and export to CSV/JSON for integration with external trackers.

## Getting Started
### Requirements
- Python 3.13+ (tested on CPython 3.13)
- System packages for Qt6 if running the GUI (PyQt6 is already listed in `requirements.txt`).
- `virtualenv`, `pip`, and access to standard offensive tooling networks (e.g., DNS resolution, HTTP, SSH).

### Installation
```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -m pip install --editable .
```

### Usage
- Run the GUI with `phantomrecon-gui` and select an aggressive scan profile to execute every pipeline stage automatically.
- Use the CLI for targeted tasks. Example:
  ```bash
  phantomrecon hydra target.com -p http-form-post -U users.txt -P rockyou.txt
  phantomrecon sqli-advanced "https://target/page?id=1" --attack union --enumerate
  phantomrecon padbuster http://target.com/auth Am9oblRlc3RTX0== --encrypt "role=admin"
  ```
- Run `phantomrecon --help` to see advanced usage examples covering every module and command.

## Module Highlights
- **Recon & Intelligence**: cert transparency, DNS advanced, subnet enumeration, BGP/ASN mapping, threat intel enrichment, MITRE ATT&CK scoring.
- **Exploitation**: John the Ripper + Hydra modules, SQLi auto-exploitation, padding oracle attacks, deserialization detectors, WebSploit attack library.
- **Cloud & Infrastructure**: S3/GCS/Azure storage scanners, IPv6 recon, port scanning with banner grabbing, protocol fuzzers (SMTP, FTP, Redis, Kerberos, GraphQL, gRPC).
- **Stealth & Automation**: proxy rotation, TLS fingerprint randomization, ML-powered wordlist generator, payload generator with WAF encoding, auto severity scoring.

## Testing
```bash
python -m pytest tests
```

## Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.

## License
Distributed under the [MIT License](./LICENSE).
