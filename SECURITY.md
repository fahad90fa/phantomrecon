# Security Policy

## Reporting a Vulnerability
If you discover a security issue in PhantomRecon, please report it privately by emailing `security@phantomrecon.io` (replace with your actual maintainer email) with the following information:
1. Steps to reproduce (include CLI command or GUI actions).
2. Target environment (OS, Python version, network scope).
3. Proof-of-concept exploit or sample input/output.
4. Severity assessment (critical/high/medium/low).

Expect a response within 72 hours. We may request additional logs or test cases to triage the report.

## Supported Versions
We support the latest release and the previous minor version. Reported issues affecting older versions may require an upgrade to reproduce.

## Security Fix Process
- Once verified, we will coordinate a fix and notify the reporter before public disclosure.
- Fixes are merged into `main` and backported to active release branches when required.
- We maintain a changelog entry per release noting resolved CVEs or security findings.

## Public Disclosure
Do not publicly disclose a vulnerability until it has been patched and we have released an update. Assisting us with coordination helps protect all users.
