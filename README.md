# subfinder-recon

Passive subdomain enumeration via [subfinder](https://github.com/projectdiscovery/subfinder) with per-subdomain source attribution, wildcard detection, SQLite cache, and community [Subdomain Registry](https://fmfalgun.github.io/subfinder-recon/subdomain-registry.html).

## Install

```bash
# Install subfinder binary
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Clone this repo
git clone https://github.com/fmfalgun/subfinder-recon
cd subfinder-recon
```

## Usage

```bash
# Basic query — results cached 24h
python3 subfinder-recon.py -d nmap.org

# Save full JSON output
python3 subfinder-recon.py -d nmap.org -o results.json

# Bypass cache, always run fresh
python3 subfinder-recon.py -d nmap.org --no-cache

# Resolve IPs (--active mode)
python3 subfinder-recon.py -d nmap.org --active

# Specific sources only
python3 subfinder-recon.py -d nmap.org -s crtsh,hackertarget

# Submit to Subdomain Registry (first run prompts for GitHub token)
python3 subfinder-recon.py -d nmap.org --submit

# Reconfigure saved token/handle
python3 subfinder-recon.py --reconfigure
```

## Output schema

```json
{
  "domain":          "nmap.org",
  "queried_at":      "2026-06-21T00:00:00Z",
  "cached":          false,
  "subdomain_count": 5,
  "wildcard_count":  0,
  "unique_ips":      0,
  "source_count":    4,
  "sources":         ["crtsh", "certspotter", "hackertarget", "dnsdumpster"],
  "subdomains": [
    { "name": "scanme.nmap.org", "sources": ["crtsh", "hackertarget"], "ip": null }
  ]
}
```

`unique_ips` is only populated with `--active`. `sources` lists every service that found at least one subdomain.

## Subdomain Registry

Browse community scans at [fmfalgun.github.io/subfinder-recon/subdomain-registry.html](https://fmfalgun.github.io/subfinder-recon/subdomain-registry.html).

Submit with `--submit`. First run prompts for a GitHub Personal Access Token (Issues: write scope only).

## License

MIT
