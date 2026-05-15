# 🗼 WatchTower

**Automated Reconnaissance & OSINT Framework**

WatchTower is a modular, extensible, production-grade Python framework for automated
reconnaissance and OSINT. It wraps industry-standard tools (nmap, sslscan, nuclei,
axiom, spiderfoot, gitleaks, and more) into a single, consistent CLI.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Project Structure](#project-structure)
- [Usage](#usage)
- [Modules](#modules)
- [Adding a New Module](#adding-a-new-module)
- [Tips & Tricks](#tips--tricks)
- [Troubleshooting](#troubleshooting)

---

## Requirements

| Requirement | Notes |
|---|---|
| Python 3.10+ | `python3 --version` |
| pip | `python3 -m pip --version` |
| curl | Pre-installed on most Linux/macOS |
| git | For nmap-converter clone and repo cloning |

**Axiom-scan modules** additionally require:

| Tool | Install |
|---|---|
| [axiom](https://github.com/pry0cc/axiom) | See axiom docs |
| hakrawler | `go install github.com/hakluke/hakrawler@latest` |
| gospider | `go install github.com/jaeles-project/gospider@latest` |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| wafw00f | `pip install wafw00f` |

**Standalone module dependencies:**

| Tool | Install |
|---|---|
| dnsrecon | `sudo apt install dnsrecon` |
| spiderfoot | `pip install spiderfoot` |
| gitleaks | [releases page](https://github.com/gitleaks/gitleaks/releases) |
| asn | Installed automatically on first use |
| jq | `sudo apt install jq` |

---

## Installation

```bash
# Clone or download
git clone https://github.com/yourorg/watchtower.git
cd watchtower

# Install Python dependencies
pip install -r requirements.txt

# Make the main script executable
chmod +x watchtower.py
```

---

## Project Structure

```
watchtower/
├── watchtower.py          ← Main entry point (run this)
├── requirements.txt
├── README.md
└── modules/               ← Helper scripts (do NOT move or rename)
    ├── capture-headers.py
    ├── capture-osint.py
    ├── clone-repos.py
    ├── convert-nmap-to-xml.py
    ├── dnsrecon-merge.py
    ├── parse_domains_subdomains.py
    └── pretty_parse_ssl_alt_names.py
```

> **Important:** All helper scripts must stay inside the `modules/` directory.
> WatchTower resolves them relative to `watchtower.py` at runtime.

---

## Usage

```
python3 watchtower.py -m <MODULE> -i <INPUT_FILE> [OPTIONS]
```

### Options

| Flag | Long | Description |
|---|---|---|
| `-m` | `--module` | Module to run (required) |
| `-i` | `--input` | Input file — domains or URLs, one per line (required) |
| `-f` | `--fleet` | Axiom fleet name (required for axiom modules) |
| `-e` | `--extension` | File extension for `finddocs` (e.g. `pdf`) |
| `-v` | `--verbose` | Print every command being executed |
| | `--version` | Show version and exit |

### Examples

```bash
# Network scan with axiom fleet
python3 watchtower.py -m nmap -i targets.txt -f my_fleet

# Crawl domains
python3 watchtower.py -m spidering -i domains.txt -f osint_fleet

# DNS recon (no fleet needed)
python3 watchtower.py -m dnsrecon -i domains.txt

# Grab response headers
python3 watchtower.py -m getheaders -i urls.txt

# Find PDF documents
python3 watchtower.py -m finddocs -i urls.txt -e pdf

# Verbose mode (see every command)
python3 watchtower.py -m httpx -i domains.txt -f fleet1 -v

# Disable colours (e.g. for CI logs)
NO_COLOR=1 python3 watchtower.py -m dnsrecon -i domains.txt

# Full tracebacks on errors
DEBUG=1 python3 watchtower.py -m sslscan -i domains.txt -f fleet1
```

---

## Modules

### Axiom-scan Modules
> These require `-f <fleet>` and an active axiom fleet.

| Module | Description | Primary Output |
|---|---|---|
| `nmap` | Comprehensive network scan | `nmap-watchtower.xls` |
| `spidering` | Crawl with hakrawler + gospider | `Final-URL-List.txt`, `Final-JavaScript-URL-List.txt` |
| `sslscan` | SSL/TLS misconfiguration scan | `sslscan-result.txt`, `weak-ciphers.txt`, `ssl-tls-status.txt` |
| `secretfinder` | Find secrets in JS files | `JavaScriptSecrets.txt` |
| `subdomains` | Subdomain discovery | `domains-subdomains-final.csv` |
| `whatweb` | Web technology fingerprinting | `whatweboutput.txt` |
| `waf` | WAF detection | `waf-result.txt` |
| `waybackurls` | Historical URLs from Wayback Machine | `waybackurls-results.txt` |
| `httpx` | Live host enumeration | `httpx-results.txt` |
| `nuclei` | Vulnerability scanning | `nuclei-results.txt` |

### Standalone Modules
> These work without axiom.

| Module | Description | Primary Output |
|---|---|---|
| `dnsrecon` | DNS reconnaissance | `final-dnsrecon-result.csv`, `dmarc-dnsrecon-result.csv`, `spf-dnsrecon-result.csv` |
| `getheaders` | Capture HTTP response headers | `response-headers-output.xlsx` |
| `getbody` | Capture HTTP response bodies | `allresponsebody.txt` |
| `spiderfoot` | OSINT — emails, names, phones | `merged.tsv` |
| `formfinder` | Extract web forms | `formfinder/` |
| `asn` | ASN + geolocation lookup | `asn.xlsx` |
| `cve` | CVE lookup via Shodan/ASN | `cve.xlsx` |
| `github` | Find GitHub repos for targets | `github-links-for-gitleaks.txt` |
| `finddocs` | Filter URLs by file extension | `<ext>_files/` |
| `gitleaks` | Secret scanning in git repos | `results/*_gitleaks_report.json` |

---

# Adding a New Module to WatchTower

WatchTower is designed for easy extensibility. Adding a module is always exactly **3 steps** in `watchtower.py`. No other files need to change.

---

## Standalone Module

Use this when the tool runs locally on your machine (no axiom needed).

**1. Add to `MODULE_REGISTRY`:**

```python
MODULE_REGISTRY: dict[str, dict] = {
    # ... existing entries ...
    "mymodule": {
        "desc":  "Short description of what it does",
        "fleet": False,   # False = no axiom fleet needed
        "ext":   False,   # True only if it needs -e extension (like finddocs)
    },
}
```

**2. Write the function:**

```python
def run_mymodule(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    # ... your logic here ...
    success("mymodule complete.")
```

**3. Add to `DISPATCH`:**

```python
DISPATCH: dict[str, callable] = {
    # ... existing entries ...
    "mymodule": lambda a: run_mymodule(a.input, a.verbose),
}
```

**Run it:**

```bash
python3 watchtower.py -m mymodule -i targets.txt
```

---

## Axiom Fleet Module

Use this when the tool needs to be distributed across a fleet of cloud instances.

**1. Add to `MODULE_REGISTRY`:**

```python
MODULE_REGISTRY: dict[str, dict] = {
    # ... existing entries ...
    "mymodule": {
        "desc":  "Short description of what it does",
        "fleet": True,    # True = requires -f fleet
        "ext":   False,
    },
}
```

**2. Write the function:**

```python
def run_mymodule(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "mymodule")    # errors cleanly if -f was not passed
    axiom_scan(input_file, fleet, "mymodule-axiom-flag", "output.txt", verbose=verbose)
    success("mymodule complete.")
```

**3. Add to `DISPATCH`:**

```python
DISPATCH: dict[str, callable] = {
    # ... existing entries ...
    "mymodule": lambda a: run_mymodule(a.input, a.fleet, a.verbose),
}
```

**Run it:**

```bash
python3 watchtower.py -m mymodule -i targets.txt -f my_fleet
```

---

## Dual-Mode Module (Standalone + Axiom)

Use this when you want the same module to work locally **or** via fleet depending
on whether `-f` is passed.

**1. Add to `MODULE_REGISTRY`:**

```python
MODULE_REGISTRY: dict[str, dict] = {
    # ... existing entries ...
    "mymodule": {
        "desc":  "Short description — works standalone or with axiom fleet",
        "fleet": False,   # False = fleet is optional, not required
        "ext":   False,
    },
}
```

**2. Write the function:**

```python
def run_mymodule(input_file: str, fleet: str = "", verbose: bool = False) -> None:
    require_file(input_file)

    if fleet:
        # ── axiom path ────────────────────────────────────────────
        info(f"Using axiom fleet '{fleet}' ...")
        axiom_scan(input_file, fleet, "mymodule-axiom-flag", "output.txt", verbose=verbose)
    else:
        # ── local path ────────────────────────────────────────────
        if not shutil.which("mytool"):
            error("mytool not found. Install with: sudo apt install mytool")
            sys.exit(1)
        run_cmd(f'mytool -i "{input_file}" -o output.txt', verbose=verbose)

    success("mymodule complete.")
```

**3. Add to `DISPATCH`:**

```python
DISPATCH: dict[str, callable] = {
    # ... existing entries ...
    "mymodule": lambda a: run_mymodule(a.input, a.fleet, a.verbose),
}
```

**Run it either way:**

```bash
# Standalone
python3 watchtower.py -m mymodule -i targets.txt

# Axiom fleet
python3 watchtower.py -m mymodule -i targets.txt -f my_fleet
```

---

## Helper Scripts

If your module needs a supporting Python script, place it in `modules/` and call
it with:

```python
run_module_script("my-helper.py", arg1, arg2)
```

The script will be resolved automatically from the `modules/` directory regardless
of where you run WatchTower from.

---

## Quick Reference

| Mode | `fleet` in registry | Function signature | `DISPATCH` lambda |
|---|---|---|---|
| Standalone | `False` | `(input_file, verbose)` | `run_x(a.input, a.verbose)` |
| Axiom only | `True` | `(input_file, fleet, verbose)` | `run_x(a.input, a.fleet, a.verbose)` |
| Dual-mode | `False` | `(input_file, fleet="", verbose)` | `run_x(a.input, a.fleet, a.verbose)` |

Once added, the module automatically appears in `--help`, tab completion, and the
module list — no other changes needed.




---

## Tips & Tricks

- **Tab completion** is available in interactive mode — press `Tab` after `-m` to
  cycle through module names.
- **Input files** should have one domain or URL per line. Lines starting with `#`
  are not stripped automatically — clean your file first.
- **Debug mode:** `DEBUG=1 python3 watchtower.py …` prints a full Python traceback
  on unexpected errors.
- **No-color mode:** `NO_COLOR=1 python3 watchtower.py …` strips all ANSI escapes
  (useful for piping output to files or CI logs).
- **Verbose mode:** `-v` / `--verbose` prints every shell command before it runs.
- **Debug directories:** Most modules save intermediate files to `debug-<module>/`
  for post-analysis.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Module helper 'X' not found` | Ensure `modules/` directory is intact and alongside `watchtower.py` |
| `axiom-scan: command not found` | Install and configure axiom, or use standalone modules |
| `dnsrecon: command not found` | `sudo apt install dnsrecon` |
| `gitleaks: command not found` | Download from [gitleaks releases](https://github.com/gitleaks/gitleaks/releases) |
| Empty output files | Run with `-v` to see exactly what commands ran and if they errored |
| Permission denied on scripts | `chmod +x watchtower.py` |
| Python version error | Upgrade to Python 3.10+: `python3 --version` |

---

## License

MIT — use freely, contribute back.
