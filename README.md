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
[3/7] Running live DNS and HTTP checks ...
  [EMAIL] example.com: SPF=PASS  DMARC=PASS
  [DNSSEC] example.com: PASS
  [WEB] example.com: 4/6 headers
  [SHODAN] example.com: PASS (2 ports, 0 CVEs)
  [OBSERVATORY] example.com: B+ (score: 70)
  [CT] example.com: PASS (12 certs, 5 subdomains)
[7/7] Summary
============================================================
  example.com          SPF:PASS  DMARC:PASS  DNSSEC:PASS  Headers:4/6

  Reports: audit_report.html, AUDIT_REPORT.md, audit_report.csv
```

35+ security checks against any domain. No API keys needed. Every finding backed by NIST, OWASP, NCSC, CISA, or GDPR standards.

---

## Step 1: Prerequisites

You need **Git** and **Python 3.10+** installed.

| | Windows | macOS | Linux |
|---|---------|-------|-------|
| **Git** | [git-scm.com](https://git-scm.com/downloads/win) (reopen PowerShell after) | `brew install git` or `xcode-select --install` | `sudo apt install git` |
| **Python** | Search **"Python"** in Microsoft Store (recommended) | `brew install python` | `sudo apt install python3 python3-pip python3-venv` |

Verify both work:
```
git --version
python --version       # Windows
python3 --version      # macOS/Linux
```

## Step 2: Install the toolkit

**Windows (PowerShell):**
```powershell
git clone https://github.com/wblv-dev/domain-security-toolkit
cd domain-security-toolkit
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install .
```

> **PowerShell error?** If you see "cannot be loaded because running scripts is disabled", run this first:
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
> ```

**macOS / Linux:**
```bash
git clone https://github.com/wblv-dev/domain-security-toolkit
cd domain-security-toolkit
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

## Step 3: Audit your domains

```bash
domain-audit --domains yourdomain.com
```

That's it. No accounts, no API keys, no configuration needed.

**Multiple domains:**
```bash
domain-audit --domains example.com example.org example.co.uk
```

**With Cloudflare zone settings** (optional — need a [Cloudflare API token](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/) with Zone:Read + DNS:Read):
```bash
domain-audit --domains example.com --cloudflare-token YOUR_TOKEN
```

## Step 4: View your report

After the audit runs, open **`audit_report.html`** in any web browser. This is your security report.

| File | What it's for |
|------|--------------|
| **`audit_report.html`** | Open in a browser — interactive dashboard with charts, findings, fix steps. **Send this to customers.** |
| `AUDIT_REPORT.md` | Same content in Markdown — useful for Git repos or documentation. |
| `audit_report.csv` | One row per domain — open in Excel/Sheets for filtering and analysis. |
| `audit_history.db` | SQLite database — accumulates data across runs for trend tracking. |

**Printing / PDF:** Open the HTML file in your browser and press **Ctrl+P** (or **Cmd+P** on Mac) → Save as PDF. The report is print-optimised.

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

Every finding in the report links to the standard that recommends it (NIST, OWASP, NCSC, CISA, GDPR, PCI DSS, and more).

---

## Optional: OSINT enrichment

The tool works fully without any API keys. For deeper threat intelligence, you can set any of these (all have free tiers):

**Windows (PowerShell):**
```powershell
$env:VIRUSTOTAL_KEY="your_key_here"
$env:OTX_KEY="your_key_here"
domain-audit --domains example.com
```

**macOS / Linux:**
```bash
export VIRUSTOTAL_KEY="your_key_here"
export OTX_KEY="your_key_here"
domain-audit --domains example.com
```

| Service | Env var | Free signup | What it adds |
|---------|---------|------------|-------------|
| VirusTotal | `VIRUSTOTAL_KEY` | [virustotal.com](https://www.virustotal.com/gui/join-us) (500/day) | Reputation from 70+ security engines |
| AlienVault OTX | `OTX_KEY` | [otx.alienvault.com](https://otx.alienvault.com/) (10K/hr) | Threat intelligence feeds |
| AbuseIPDB | `ABUSEIPDB_KEY` | [abuseipdb.com](https://www.abuseipdb.com/register) (1K/day) | IP abuse scoring |
| Shodan | `SHODAN_API_KEY` | [shodan.io](https://account.shodan.io/register) (100/month) | Detailed port/service data |
| URLhaus | `URLHAUS_KEY` | [abuse.ch](https://auth.abuse.ch/) | Malware URL checking |
| Google Safe Browsing | `GOOGLE_SAFEBROWSING_KEY` | [developers.google.com](https://developers.google.com/safe-browsing/) | Phishing/malware flagging |

---

## Optional: Cloudflare integration

If your domains use Cloudflare, adding a token unlocks 11 additional zone security checks (SSL mode, TLS version, HSTS, security level, etc.).

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com/)
2. **My Profile** → **API Tokens** → **Create Token**
3. Permissions: **Zone → Zone → Read** and **Zone → DNS → Read**
4. Zone resources: **Include → All zones**

```bash
domain-audit --domains example.com --cloudflare-token YOUR_TOKEN
```

Or set it as an environment variable:
```bash
export CF_API_TOKEN="YOUR_TOKEN"        # macOS/Linux
$env:CF_API_TOKEN="YOUR_TOKEN"          # Windows
domain-audit --domains example.com
```

---

## All CLI options

```
domain-audit --domains DOMAIN [DOMAIN ...]   Domains to audit (required)
             --cloudflare-token TOKEN         Cloudflare API token (optional)
             --output-dir DIR                 Where to save reports (default: current folder)
             --format {html,md,csv}           Which reports to generate (default: all)
             --concurrency N                  Parallel domains (default: 20, lower for slow connections)
             --verbose                        Show detailed debug output
             --log-file FILE                  Save full log to a file
             --no-diff                        Don't compare with previous run

domain-dashboard                              Open interactive data explorer (needs Datasette)
```

**Exit codes** (useful for automation):
- `0` — all checks passed or warned
- `1` — configuration or runtime error
- `2` — at least one check graded FAIL

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `domain-audit: command not found` | Make sure your virtual environment is activated (`.venv\Scripts\Activate.ps1` on Windows, `source .venv/bin/activate` on Mac/Linux) |
| `python: command not found` | Install Python — see Step 1 above |
| `git: command not found` | Install Git — see Step 1 above. Reopen your terminal after installing. |
| `Scripts\Activate.ps1 cannot be loaded` | Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` in PowerShell |
| `pip install .` fails | Make sure you're inside the `domain-security-toolkit` folder and your venv is activated |
| Report looks broken | Make sure you open `audit_report.html` in a modern browser (Chrome, Firefox, Edge) |
| Slow on many domains | Lower concurrency: `domain-audit --domains ... --concurrency 10` |

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
│   └── lib/                    # Reporter, database, remediation, standards
└── tests/                      # 235 tests
```

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

## Contributing

Issues and pull requests welcome.

## License

[MIT](LICENSE)
