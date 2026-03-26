<div align="center">

# Domain Security Toolkit

**Open-source domain security auditing backed by industry standards.**

Run one command against any domain. Get a customer-ready security report.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-235%20passing-brightgreen)](https://github.com/wblv-dev/domain-security-toolkit/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Checks](https://img.shields.io/badge/checks-35%2B-informational)](https://github.com/wblv-dev/domain-security-toolkit)

</div>

---

```
$ domain-audit --domains example.com

[1/7] Auditing 1 domain(s) ...
[2/7] Skipping Cloudflare API checks (no token provided)
[3/7] Running live DNS and HTTP checks ...
  [EMAIL] example.com: SPF=PASS  DMARC=PASS
  [DNSSEC] example.com: PASS
  [WEB] example.com: 4/6 headers
  [SHODAN] example.com: PASS (2 ports, 0 CVEs)
  [OBSERVATORY] example.com: B+ (score: 70)
  [CT] example.com: PASS (12 certs, 5 subdomains)
[4/7] Saving results ...
[7/7] Summary
============================================================
  example.com          SPF:PASS  DMARC:PASS  DNSSEC:PASS  Headers:4/6
```

35+ security checks. No API keys required. Every finding cites the specific NIST, OWASP, NCSC, CISA, or GDPR standard that recommends it.

**Cloudflare integration is optional** — add `--cloudflare-token` to include zone settings. Everything else works against any domain.

---

## Install

**Windows (PowerShell):**

```powershell
git clone https://github.com/wblv-dev/domain-security-toolkit
cd domain-security-toolkit
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install .
```

**macOS / Linux:**

```bash
git clone https://github.com/wblv-dev/domain-security-toolkit
cd domain-security-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

## Run

```bash
domain-audit --domains example.com example.org
```

That's it. No accounts, no API keys, no configuration.

**With Cloudflare** (optional — adds zone security settings):

```bash
domain-audit --domains example.com --cloudflare-token YOUR_CF_TOKEN
```

**With OSINT enrichment** (optional — set any combination):

```bash
export VIRUSTOTAL_KEY="..."      # Domain reputation (free: 500/day)
export OTX_KEY="..."             # Threat intelligence (free: 10K/hr)
export ABUSEIPDB_KEY="..."       # IP reputation (free: 1K/day)
domain-audit --domains example.com
```

### Output

| File | Description |
|------|-------------|
| `audit_report.html` | **Customer-ready dashboard** — charts, findings, remediations, standards references |
| `AUDIT_REPORT.md` | Markdown — Git-friendly |
| `audit_report.csv` | One row per domain |
| `audit_history.db` | SQLite — cumulative history |

---

## What it checks

<table>
<tr><td>

**Email security**
- SPF record + grading
- DMARC policy + grading
- DKIM (10 selectors)
- MTA-STS
- TLSRPT
- BIMI

**DNS security**
- DNSSEC validation
- CAA records
- Dangling CNAMEs
- DNSBL blacklists (6 lists)
- Reverse DNS (FCrDNS)

</td><td>

**Web security**
- X-Frame-Options
- Content-Security-Policy
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- HSTS (HTTP header)
- security.txt (RFC 9116)
- Mozilla Observatory grade

</td><td>

**Infrastructure**
- Domain expiry (RDAP)
- Transfer lock
- Open ports + CVEs (Shodan)
- Certificate Transparency
- Technology fingerprint

**Cloudflare** (optional)
- SSL mode, TLS version
- HSTS, HTTPS redirect
- Security level, headers
- +6 more zone settings

</td></tr>
</table>

Every finding cites the standard that recommends it — the **Checks Reference** tab in the report links to NIST, OWASP, NCSC, CISA, BSI, ENISA, ICO, PCI DSS, and relevant RFCs.

---

## CLI reference

```
domain-audit --domains DOMAIN [DOMAIN ...]   Required: domains to audit
             --cloudflare-token TOKEN         Optional: Cloudflare API token
             --output-dir DIR                 Output directory (default: .)
             --format {html,md,csv}           Output formats (default: all)
             --concurrency N                  Max concurrent domains (default: 20)
             --verbose                        Debug logging
             --log-file FILE                  Log to file
             --no-diff                        Skip previous-run comparison

domain-dashboard                              Launch Datasette data explorer

Exit codes:  0 = pass/warn   1 = error   2 = at least one FAIL
```

---

## Optional API enrichment

All optional. Silent if not set. The tool works fully without any keys.

| Service | Env var | Free tier | What it adds |
|---------|---------|-----------|-------------|
| Shodan | `SHODAN_API_KEY` | 100/month | Detailed port/service data |
| VirusTotal | `VIRUSTOTAL_KEY` | 500/day | Reputation from 70+ engines |
| AlienVault OTX | `OTX_KEY` | 10,000/hr | Threat intelligence |
| AbuseIPDB | `ABUSEIPDB_KEY` | 1,000/day | IP abuse scoring |
| URLhaus | `URLHAUS_KEY` | Fair use | Malware URL checking |
| Google Safe Browsing | `GOOGLE_SAFEBROWSING_KEY` | 10,000+/day | Phishing/malware flagging |

---

## Security & compliance

Every check maps to published standards:

| Standard | Checks covered |
|----------|---------------|
| **NIST SP 800-52** | TLS 1.2+, TLS 1.3 |
| **NIST SP 800-177** | SPF, DKIM, DMARC |
| **PCI DSS v4.0** | TLS 1.2 minimum |
| **CISA BOD 18-01** | HTTPS, HSTS, SPF, DMARC p=reject |
| **OWASP** | All HTTP security headers |
| **NCSC UK** | TLS, email auth, DNSSEC, domain management |
| **GDPR Art. 32** | Encryption in transit |
| **NIS2** | DNSSEC, cryptography policies |
| **BSI TR-02102** | TLS configuration |
| **RFC 9116** | security.txt |

---

## Project structure

```
domain-security-toolkit/
├── README.md
├── LICENSE
├── pyproject.toml
├── domain_audit/               # pip install .
│   ├── cli.py                  # domain-audit command
│   ├── dashboard.py            # domain-dashboard command
│   ├── template.html           # HTML report template
│   ├── checks/                 # One module per check category
│   └── lib/                    # API client, database, reporter, remediation
└── tests/                      # 235 tests
```

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## Contributing

Issues and pull requests welcome.

## License

[MIT](LICENSE)
