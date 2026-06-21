#!/usr/bin/env python3
"""
build_demo.py — run subfinder-recon against nmap.org and write:
  - web/data/domains/nmap.org.json   (for subdomain-registry + domain.html)
  - web/data/index.json              (subdomain registry index)
Called by .github/workflows/build-demo.yml on a daily cron schedule.
"""

import subprocess
import sys
import json
from pathlib import Path
from datetime import datetime, timezone

DOMAIN       = "nmap.org"
DISPLAY_NAME = "fmfalgun"
DISPLAY_LOC  = "Chennai, India"
SCRIPT       = Path("subfinder-recon.py")
DOMAIN_OUT   = Path(f"web/data/domains/{DOMAIN}.json")
INDEX_OUT    = Path("web/data/index.json")


def run_script():
    print(f"[*] Running subfinder-recon on {DOMAIN} ...")
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "-d", DOMAIN, "-o", str(DOMAIN_OUT), "--no-cache"],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"[!] Script failed:\n{result.stderr}")
        sys.exit(1)
    if not DOMAIN_OUT.exists():
        print(f"[!] Output file not created: {DOMAIN_OUT}")
        sys.exit(1)
    return json.loads(DOMAIN_OUT.read_text())


def enrich_domain_file(data: dict):
    """Add display metadata to the domain file."""
    DOMAIN_OUT.parent.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["display_name"]   = DISPLAY_NAME
    data["display_loc"]    = DISPLAY_LOC
    data["last_refreshed"] = now
    DOMAIN_OUT.write_text(json.dumps(data, indent=2))
    print(f"[+] Written: {DOMAIN_OUT}")
    return data


def update_index(data: dict):
    """Update web/data/index.json with nmap.org entry."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if INDEX_OUT.exists():
        try:
            index = json.loads(INDEX_OUT.read_text())
        except Exception:
            index = {}
    else:
        index = {}

    index.setdefault("total_domains", 0)
    index.setdefault("total_scans", 0)
    index.setdefault("domains", [])

    entry = {
        "domain":          DOMAIN,
        "display_name":    DISPLAY_NAME,
        "display_loc":     DISPLAY_LOC,
        "queried_at":      data.get("queried_at", now),
        "last_refreshed":  now,
        "subdomain_count": data.get("subdomain_count", 0),
        "source_count":    data.get("source_count", 0),
        "unique_ips":      data.get("unique_ips", 0),
        "wildcard_count":  data.get("wildcard_count", 0),
    }

    domains = [d for d in index["domains"] if d["domain"] != DOMAIN]
    domains.append(entry)
    domains.sort(key=lambda x: x["domain"])

    index["domains"]       = domains
    index["total_domains"] = len(domains)
    index["total_scans"]   = len(domains)
    index["generated_at"]  = now

    INDEX_OUT.write_text(json.dumps(index, indent=2))
    print(f"[+] Updated: {INDEX_OUT} ({len(domains)} domains)")


def main():
    data = run_script()

    subs  = data.get("subdomain_count", "?")
    srcs  = data.get("source_count", "?")
    wc    = data.get("wildcard_count", "?")
    print(f"[+] Result: {subs} subdomains, {srcs} sources, {wc} wildcards")

    enrich_domain_file(data)
    update_index(data)
    print("[+] build_demo.py complete")


if __name__ == "__main__":
    main()
