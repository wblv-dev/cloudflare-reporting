"""
optional.py — Optional OSINT integrations that require API keys.

Each integration is completely silent if its env var is not set.
No errors, no warnings — just skipped.

Supported:
    SHODAN_API_KEY      — Open ports, services, vulnerabilities
    VIRUSTOTAL_KEY      — Domain reputation and malware associations
"""

import asyncio
import os
from typing import Dict, List, Optional

import aiohttp


# ── Shodan ───────────────────────────────────────────────────────────────────

async def _shodan_lookup(domain: str, api_key: str) -> Optional[dict]:
    """Query Shodan for a domain's IP information."""
    from cloudflare_reporting.lib.concurrency import sem

    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://api.shodan.io/dns/resolve?hostnames={domain}&key={api_key}"
                async with session.get(url) as r:
                    if r.status != 200:
                        return None
                    ips = await r.json()
                    ip = ips.get(domain)
                    if not ip:
                        return None

                # Get host info
                url2 = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                async with session.get(url2) as r2:
                    if r2.status != 200:
                        return {"ip": ip, "ports": [], "vulns": [], "error": f"HTTP {r2.status}"}
                    data = await r2.json()
                    return {
                        "ip": ip,
                        "ports": data.get("ports", []),
                        "vulns": list(data.get("vulns", [])),
                        "org": data.get("org", ""),
                        "os": data.get("os", ""),
                        "isp": data.get("isp", ""),
                    }
    except Exception as e:
        return {"ip": None, "ports": [], "vulns": [], "error": str(e)}


# ── VirusTotal ───────────────────────────────────────────────────────────────

async def _virustotal_lookup(domain: str, api_key: str) -> Optional[dict]:
    """Query VirusTotal for domain reputation."""
    from cloudflare_reporting.lib.concurrency import sem

    try:
        async with sem.http:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {"x-apikey": api_key}
                async with session.get(url, headers=headers) as r:
                    if r.status != 200:
                        return None
                    data = await r.json()
                    attrs = data.get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": attrs.get("reputation", 0),
                        "categories": attrs.get("categories", {}),
                    }
    except Exception:
        return None


# ── Public API ───────────────────────────────────────────────────────────────

async def check_domain(domain: str) -> dict:
    """Run all optional integrations for a domain. Skip if keys not set."""
    result = {"domain": domain, "shodan": None, "virustotal": None}

    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    vt_key = os.environ.get("VIRUSTOTAL_KEY", "")

    tasks = {}
    if shodan_key:
        tasks["shodan"] = _shodan_lookup(domain, shodan_key)
    if vt_key:
        tasks["virustotal"] = _virustotal_lookup(domain, vt_key)

    if not tasks:
        return result  # No keys set, nothing to do

    for name, coro in tasks.items():
        try:
            result[name] = await coro
        except Exception:
            pass

    active = [k for k in ("shodan", "virustotal") if result.get(k)]
    if active:
        print(f"  [OSINT] {domain}: {', '.join(active)}")

    return result


async def check_all(domains: List[str]) -> Dict[str, dict]:
    """Run optional checks. Returns empty dict if no keys set."""
    shodan_key = os.environ.get("SHODAN_API_KEY", "")
    vt_key = os.environ.get("VIRUSTOTAL_KEY", "")

    if not shodan_key and not vt_key:
        return {}  # Silent skip — no keys, no output

    from cloudflare_reporting.lib.concurrency import throttled_gather
    return await throttled_gather(
        {d: check_domain(d) for d in domains}, label="OSINT check"
    )


def has_any_keys() -> bool:
    """Check if any optional integration keys are configured."""
    return bool(os.environ.get("SHODAN_API_KEY", "") or os.environ.get("VIRUSTOTAL_KEY", ""))
