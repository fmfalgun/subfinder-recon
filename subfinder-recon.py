#!/usr/bin/env python3
"""
subfinder-recon.py — Passive subdomain enumeration with local cache + community submit

Usage:
    subfinder-recon.py -d nmap.org                     # query, print, cache
    subfinder-recon.py -d nmap.org -o out.json         # also write JSON to file
    subfinder-recon.py -d nmap.org --no-cache          # bypass cache, always run subfinder
    subfinder-recon.py -d nmap.org --ttl 6             # custom TTL in hours (default 24)
    subfinder-recon.py -d nmap.org -s crtsh,hackertarget  # limit sources
    subfinder-recon.py -d nmap.org --active            # resolve IPs (-active -ip to subfinder)
    subfinder-recon.py --submit -d nmap.org            # also submit to community registry
    subfinder-recon.py --reconfigure                   # re-run setup wizard
"""

import sys
import json
import re
import sqlite3
import argparse
import subprocess
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ─── constants ────────────────────────────────────────────────────────────────

__version__ = "1.0.0"
CONFIG_PATH = Path.home() / ".config" / "subfinder-recon" / "config.json"
GITHUB_ISSUES_URL = "https://api.github.com/repos/fmfalgun/subfinder-recon/issues"
CACHE_DB = "./cache.db"
DEFAULT_TTL_HOURS = 24

# ─── helpers ──────────────────────────────────────────────────────────────────

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def check_subfinder() -> str:
    path = shutil.which("subfinder")
    if not path:
        sys.exit(
            "[!] subfinder not found in PATH.\n"
            "    Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        )
    return path

# ─── cache ────────────────────────────────────────────────────────────────────

CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS subfinder_cache (
    domain      TEXT PRIMARY KEY,
    data        TEXT NOT NULL,
    cached_at   TEXT NOT NULL
);
"""

def get_cache_db() -> sqlite3.Connection:
    db = sqlite3.connect(CACHE_DB)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.executescript(CACHE_SCHEMA)
    db.commit()
    return db

def cache_get(db: sqlite3.Connection, domain: str, ttl_hours: int) -> dict | None:
    """Return cached result if it exists and is within TTL, else None."""
    row = db.execute(
        "SELECT data, cached_at FROM subfinder_cache WHERE domain = ?",
        (domain,)
    ).fetchone()
    if row is None:
        return None
    cached_at = datetime.strptime(row["cached_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - cached_at
    if age > timedelta(hours=ttl_hours):
        return None  # stale
    result = json.loads(row["data"])
    result["cached"] = True
    return result

def cache_put(db: sqlite3.Connection, domain: str, result: dict):
    """Store full result JSON in cache."""
    db.execute(
        """
        INSERT INTO subfinder_cache (domain, data, cached_at)
        VALUES (?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET data=excluded.data, cached_at=excluded.cached_at
        """,
        (domain, json.dumps(result), result["queried_at"])
    )
    db.commit()

# ─── subfinder run ────────────────────────────────────────────────────────────

def run_subfinder(
    domain: str,
    sources: str | None,
    active: bool,
) -> list[dict]:
    """
    Run subfinder with JSONL output (-oJ -cs) to capture per-source attribution.
    Returns list of {"host": str, "sources": [str, ...], "ip": str|None} dicts.
    Falls back to plain-text parsing if JSON mode fails.
    """
    sf = check_subfinder()

    # Build a temp file path without importing tempfile/os — use pathlib + datetime
    tmp_json = str(Path("/tmp") / f"subfinder_{domain.replace('.', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json")

    cmd = [sf, "-d", domain, "-oJ", "-cs", "-o", tmp_json]
    if sources:
        cmd += ["-s", sources]
    if active:
        cmd += ["-active", "-ip"]

    cmd_str = f"subfinder -d {domain}" + (f" -s {sources}" if sources else "") + (" -active -ip" if active else "")
    print(f"[>] {cmd_str}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=False,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        print(f"[!] subfinder timed out for {domain} after 15 minutes")
        return []
    except FileNotFoundError:
        sys.exit("[!] subfinder binary not found")

    results = []
    json_path = Path(tmp_json)

    if json_path.exists() and json_path.stat().st_size > 0:
        with open(json_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # subfinder JSONL: {"host": "sub.example.com", "source": "crtsh"}
                    # or newer:        {"host": "sub.example.com", "sources": ["crtsh"], "ip": "1.2.3.4"}
                    host = obj.get("host", "").strip().lower()
                    if not host:
                        continue

                    # Normalise sources to a list
                    srcs = obj.get("sources") or obj.get("source")
                    if isinstance(srcs, list):
                        src_list = srcs
                    elif isinstance(srcs, str) and srcs:
                        src_list = [srcs]
                    else:
                        src_list = ["subfinder"]

                    ip = obj.get("ip") if active else None

                    results.append({"host": host, "sources": src_list, "ip": ip})
                except json.JSONDecodeError:
                    # plain subdomain line slipped through
                    host = line.strip().lower()
                    if host and "." in host:
                        results.append({"host": host, "sources": ["subfinder"], "ip": None})

        # clean up temp file
        try:
            json_path.unlink()
        except OSError:
            pass

    else:
        # JSON file missing or empty — subfinder may have printed plain lines to stdout
        # (shouldn't normally happen with -oJ, but handle it gracefully)
        print("[!] JSON output file empty or missing; no results captured")
        try:
            json_path.unlink()
        except OSError:
            pass

    if proc.returncode not in (0, 1):
        print(f"[!] subfinder exited with code {proc.returncode}")

    return results

# ─── result builder ───────────────────────────────────────────────────────────

def build_result(domain: str, raw: list[dict], active: bool) -> dict:
    """
    Turn the raw list from run_subfinder() into the canonical output JSON.
    """
    queried_at = now_utc()

    # Deduplicate: one entry per unique host; merge sources across duplicates
    host_map: dict[str, dict] = {}
    for r in raw:
        host = r["host"]
        if host not in host_map:
            host_map[host] = {"name": host, "sources": list(r["sources"]), "ip": r.get("ip")}
        else:
            # merge sources
            existing_srcs = set(host_map[host]["sources"])
            for s in r["sources"]:
                if s not in existing_srcs:
                    host_map[host]["sources"].append(s)
                    existing_srcs.add(s)
            # keep first non-None IP
            if host_map[host]["ip"] is None and r.get("ip"):
                host_map[host]["ip"] = r["ip"]

    subdomains = sorted(host_map.values(), key=lambda x: x["name"])

    # Aggregate sources across all subdomains
    all_sources: set[str] = set()
    for sub in subdomains:
        all_sources.update(sub["sources"])
    sources_list = sorted(all_sources)

    wildcard_count = sum(1 for s in subdomains if s["name"].startswith("*."))
    unique_ips = len({s["ip"] for s in subdomains if s["ip"] is not None})

    return {
        "domain": domain,
        "queried_at": queried_at,
        "cached": False,
        "subdomain_count": len(subdomains),
        "unique_ips": unique_ips,
        "wildcard_count": wildcard_count,
        "source_count": len(sources_list),
        "sources": sources_list,
        "subdomains": subdomains,
    }

# ─── display ──────────────────────────────────────────────────────────────────

def print_result(result: dict, active: bool):
    domain = result["domain"]
    sources_str = ", ".join(result["sources"]) if result["sources"] else "(none)"
    ip_hint = "" if active else "  (use --active to resolve)"

    print(f"\n[subfinder-recon] {domain}")
    print(f"  subdomains : {result['subdomain_count']}")
    print(f"  wildcards  : {result['wildcard_count']}")
    print(f"  unique IPs : {result['unique_ips']}{ip_hint}")
    print(f"  sources    : {sources_str}")
    print()

    for sub in result["subdomains"]:
        name = sub["name"]
        src_tag = "[" + ", ".join(sub["sources"]) + "]" if sub["sources"] else ""
        ip_tag = f"  → {sub['ip']}" if sub.get("ip") else ""
        print(f"  {name:<45} {src_tag}{ip_tag}")

    cached_str = "true" if result.get("cached") else "false"
    print(f"\n  cached: {cached_str} | queried: {result['queried_at']}")

# ─── config / setup wizard ────────────────────────────────────────────────────

def load_config() -> dict | None:
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return None
    return None

def setup_wizard() -> dict:
    print("\n[subfinder-recon] First-time setup for --submit")
    print("  You need a GitHub Personal Access Token with Issues: write permission.")
    print("  Create one at: https://github.com/settings/tokens\n")

    pat = input("  GitHub PAT: ").strip()
    if not pat:
        sys.exit("[!] PAT is required for --submit. Aborted.")

    display_name = input("  Display name (handle or name, shown publicly): ").strip()
    if not display_name:
        display_name = "anonymous"

    display_loc = input("  Location (city/country, shown publicly, optional): ").strip()

    config = {
        "github_pat": pat,
        "display_name": display_name,
        "display_loc": display_loc,
    }

    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2))
    CONFIG_PATH.chmod(0o600)
    print(f"  Config saved to {CONFIG_PATH}\n")
    return config

# ─── submit flow ──────────────────────────────────────────────────────────────

def submit_result(result: dict, config: dict):
    domain = result["domain"]
    display_name = config.get("display_name", "anonymous")
    display_loc = config.get("display_loc", "")
    pat = config.get("github_pat", "")

    loc_part = f" — {display_loc}" if display_loc else ""
    print(f"\n  Domain: {domain} | Listed as: {display_name}{loc_part}")
    print("  This result will be publicly listed on the Subdomain Registry.")
    confirm = input("  Submit? [y/N] ").strip().lower()
    if confirm != "y":
        print("  Submission cancelled.")
        return

    payload = dict(result)
    payload["submitted_by"] = display_name
    payload["submitted_loc"] = display_loc

    issue_body = json.dumps(payload, indent=2)
    issue_title = f"[submission] {domain}"

    post_data = json.dumps({"title": issue_title, "body": issue_body}).encode("utf-8")
    req = Request(
        GITHUB_ISSUES_URL,
        data=post_data,
        headers={
            "Authorization": f"token {pat}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": f"subfinder-recon/{__version__}",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            issue_url = resp_data.get("html_url", "(no URL)")
            print(f"  [+] Submitted: {issue_url}")
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"  [!] HTTP {e.code}: {body[:300]}")
    except URLError as e:
        print(f"  [!] Network error: {e.reason}")

# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description=f"subfinder-recon v{__version__} — passive subdomain enumeration with cache + submit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("-d", "--domain", help="target domain (e.g. nmap.org)")
    ap.add_argument("-o", "--output", help="write JSON result to this file")
    ap.add_argument("--no-cache", action="store_true", help="bypass cache; always run subfinder")
    ap.add_argument("--ttl", type=int, default=DEFAULT_TTL_HOURS, metavar="HOURS",
                    help=f"cache TTL in hours (default: {DEFAULT_TTL_HOURS})")
    ap.add_argument("-s", "--sources", default=None,
                    help="comma-separated sources to pass to subfinder (e.g. crtsh,hackertarget)")
    ap.add_argument("--active", action="store_true",
                    help="resolve subdomains and include IPs (-active -ip passed to subfinder)")
    ap.add_argument("--submit", action="store_true",
                    help="submit result to community subdomain registry after querying")
    ap.add_argument("--reconfigure", action="store_true",
                    help="re-run setup wizard, overwrite saved config")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    # --reconfigure: just re-run wizard
    if args.reconfigure:
        setup_wizard()
        return

    if not args.domain:
        ap.print_help()
        sys.exit(1)

    domain = args.domain.lower().strip().rstrip(".")

    # Open cache DB
    cache_db = get_cache_db()

    result = None

    # Cache lookup (skip if --no-cache)
    if not args.no_cache:
        result = cache_get(cache_db, domain, args.ttl)
        if result:
            print(f"[i] Cache hit for {domain} (TTL {args.ttl}h)")

    # Run subfinder if no cached result
    if result is None:
        raw = run_subfinder(domain=domain, sources=args.sources, active=args.active)
        result = build_result(domain, raw, args.active)
        # Store in cache (even on --no-cache, we write the fresh result)
        cache_put(cache_db, domain, result)

    # Always print summary to stdout
    print_result(result, args.active)

    # Optional JSON file output
    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json.dumps(result, indent=2))
        print(f"[+] JSON written to {out_path}")

    # Submit flow
    if args.submit:
        config = load_config()
        if config is None:
            print("[i] No config found — starting setup wizard.")
            config = setup_wizard()
        submit_result(result, config)

if __name__ == "__main__":
    main()
