# 🗼 WatchTower
**Automated Reconnaissance & OSINT Framework**

WatchTower is a modular Python framework that wraps industry-standard security tools into a single, consistent CLI. Run network scans, subdomain enumeration, SSL analysis, secret finding, CVE lookups, and more — all with structured, timestamped, self-documenting outputs.

---

## Table of Contents
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Output Structure](#output-structure)
- [Adding a New Module](#adding-a-new-module)
- [Tips & Tricks](#tips--tricks)
- [Troubleshooting](#troubleshooting)

---

## How It Works

WatchTower has two kinds of modules:

- **Fleet modules** — distribute work across a cloud fleet of instances using [axiom](https://github.com/pry0cc/axiom). These are for heavy scanning tasks (nmap, nuclei, spidering, etc.) where you want to run across many targets fast. They require `-f fleet_name`.
- **Standalone modules** — run locally on your machine. No cloud needed. Good for DNS recon, OSINT, header grabbing, etc.

Both types produce the same structured output format.

---

## Requirements

**Always required:**
- Python 3.10 or higher
- `curl` — pre-installed on most Linux/macOS systems
- `git` — for cloning repos used by some modules

**For standalone modules** — only install what you actually need:

| Tool | Used by | Install |
|---|---|---|
| `dnsrecon` | `dnsrecon` module | `sudo apt install dnsrecon` |
| `spiderfoot` | `spiderfoot`, `formfinder`, `github` | `pip install spiderfoot` |
| `gitleaks` | `gitleaks` module | [Download binary](https://github.com/gitleaks/gitleaks/releases) |
| `jq` | `spidering` module | `sudo apt install jq` |
| `qsreplace` | `spidering` module | `go install github.com/tomnomnom/qsreplace@latest` |
| `asn` | `asn`, `cve` modules | Auto-installed on first run |

**For fleet modules** — you need axiom set up first. The tools below run on your cloud fleet nodes, not your local machine. WatchTower installs them on the fleet automatically when you run each module:

| Tool | Used by |
|---|---|
| `nmap` | `nmap` |
| `hakrawler` + `gospider` | `spidering` |
| `httpx` | `spidering`, `subdomains`, `httpx` |
| `assetfinder` + `amass` | `subdomains` |
| `nuclei` | `nuclei` |
| `wafw00f` | `waf` |
| `waybackurls` | `waybackurls` |
| `sslscan` | `sslscan` (built from source on fleet, auto) |
| `whatweb` | `whatweb` (apt installed on fleet, auto) |
| `SecretFinder` | `secretfinder` (cloned on fleet, auto) |
| `ffuf` | `ffuf` (go installed on fleet, auto) |

> **Note:** Fleet tools are installed automatically the first time you run that module. You don't need to pre-install anything on fleet nodes.

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/yourorg/watchtower.git
cd watchtower

# 2. Create a Python virtual environment
python3 -m venv venv

# 3. Activate it
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

# 4. Install Python dependencies
pip install xlsxwriter openpyxl

# 5. Make the script executable
chmod +x watchtower.py
```

> **Every time** you open a new terminal to use WatchTower, activate the venv first:
> ```bash
> source venv/bin/activate
> ```

**Then install only the tools you need** from the standalone requirements table above. You don't need to install everything upfront.

**For fleet modules**, install and configure axiom:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pry0cc/axiom/master/interact/axiom-configure)

# Spin up a fleet (5 nodes)
axiom-fleet spawn myfleet -i 5

# Check it's running
axiom-ls
```

---

## Usage

```bash
python3 watchtower.py -m <MODULE> -i <INPUT_FILE> [OPTIONS]
```

| Flag | Description |
|---|---|
| `-m` / `--module` | Module to run **(required)** |
| `-i` / `--input` | Input file — one domain or URL per line **(required)** |
| `-f` / `--fleet` | Axiom fleet name (required for fleet modules) |
| `-e` / `--extension` | File extension for `finddocs` (e.g. `pdf`) |
| `-v` / `--verbose` | Print every command as it runs |
| `--version` | Show version |

**Examples:**

```bash
# Fleet modules (require -f)
python3 watchtower.py -m nmap        -i targets.txt   -f myfleet
python3 watchtower.py -m spidering   -i domains.txt   -f myfleet
python3 watchtower.py -m nuclei      -i urls.txt      -f myfleet
python3 watchtower.py -m ffuf        -i urls.txt      -f myfleet

# Standalone modules (no -f needed)
python3 watchtower.py -m dnsrecon    -i domains.txt
python3 watchtower.py -m getheaders  -i urls.txt
python3 watchtower.py -m asn         -i ips.txt
python3 watchtower.py -m finddocs    -i urls.txt      -e pdf

# Useful flags
python3 watchtower.py -m httpx -i domains.txt -f myfleet -v      # verbose
DEBUG=1 python3 watchtower.py -m sslscan -i domains.txt -f myfleet  # full traceback
NO_COLOR=1 python3 watchtower.py -m dnsrecon -i domains.txt         # no colour
```

---

## Modules

### Fleet Modules
> Require `-f fleet_name` and a running axiom fleet.

| Module | What it does | Key output |
|---|---|---|
| `nmap` | Network scan with interactive options (TCP/UDP, ports, speed, scripts) | Excel with Open Ports, Host Summary, Vulnerabilities sheets |
| `spidering` | Crawl targets with hakrawler + gospider, probe live URLs with httpx | `Final-URL-List.txt`, `Final-JavaScript-URL-List.txt` |
| `sslscan` | Scan SSL/TLS — finds weak ciphers, protocol status, cert alt names | `ssl-tls-status.txt`, `weak-ciphers.txt`, `domains-from-ssl-cert.txt` |
| `secretfinder` | Hunt for API keys, tokens, secrets in JavaScript files | `javascript-secrets.txt` |
| `subdomains` | Enumerate subdomains via assetfinder and/or amass, confirm live with httpx | `live-subdomains.txt`, `subdomains-by-domain.txt`, Excel report |
| `whatweb` | Fingerprint web technologies (CMS, frameworks, server versions) | `whatweb-results.txt` |
| `waf` | Detect WAF protection on targets via wafw00f | `waf-results.txt` |
| `waybackurls` | Pull historical URLs from the Wayback Machine | `waybackurls.txt` |
| `httpx` | Probe a list of hosts and return only live HTTP/HTTPS ones | `httpx-live-hosts.txt` |
| `nuclei` | Run Nuclei vulnerability templates against targets | `nuclei-findings.txt` |
| `ffuf` | Directory/endpoint bruteforcing with interactive wordlist and mode selection | Excel (colour-coded by status) + plain text |

### Standalone Modules
> Run locally, no fleet needed.

| Module | What it does | Key output |
|---|---|---|
| `dnsrecon` | Full DNS recon — A, MX, NS, TXT, SPF, DMARC records | `dnsrecon-all-records.csv`, `spf-records.csv`, `dmarc-records.csv` |
| `getheaders` | Grab HTTP response headers from a list of URLs via curl | `response-headers.xlsx`, `response-headers.txt` |
| `getbody` | Grab HTTP response bodies from a list of URLs via curl | `response-bodies.txt` |
| `spiderfoot` | OSINT collection — emails, names, phone numbers | `spiderfoot-osint.txt` |
| `formfinder` | Discover web forms on target sites | `forms-found.txt` |
| `asn` | ASN lookup, IP block info, geolocation per target | `asn-results.xlsx` |
| `cve` | Pull CVE/vulnerability data for targets via Shodan | `cve-results.xlsx` |
| `github` | Discover public GitHub repos tied to targets | `github-repos.txt`, `github-repos-for-gitleaks.txt` |
| `finddocs` | Filter a URL list by file extension (pdf, docx, xlsx, etc.) | `<ext>-file-urls.txt`, `<ext>-files-by-domain.txt` |
| `gitleaks` | Clone GitHub repos and scan for leaked secrets | JSON reports per repo + `gitleaks-summary.txt` |

---

## Output Structure

All outputs go into `watchtower-results/`. Nothing is ever written to your working directory.

```
watchtower-results/
├── MANIFEST.txt                    ← index of every file produced, with timestamps
├── final/
│   ├── nmap/
│   │   ├── nmap-results-20250516T143022.xlsx
│   │   └── nmap-open-ports-20250516T143022.txt
│   ├── ffuf/
│   │   ├── ffuf-findings-20250516T150012.xlsx
│   │   └── ffuf-findings-20250516T150012.txt
│   └── <module>/...
└── debug/
    └── <module>/                   ← raw tool output and temp files
```

**Every output file is self-documenting.** Plain-text files have a header block at the top:

```
# ════════════════════════════════════════════════════════════════
# WatchTower Reconnaissance Report
# ────────────────────────────────────────────────────────────────
# Module      : nmap
# Description : Comprehensive network scan via Nmap
# Generated   : 2025-05-16 14:30:22
# Operator    : alice @ kali
# Input File  : /home/alice/targets.txt
# Fleet       : myfleet
# Targets (3):
#   192.168.1.1
#   192.168.1.2
#   10.0.0.1
# ════════════════════════════════════════════════════════════════
```

Excel files have a **Report Info** sheet as the first tab with the same information.

---

## Adding a New Module

Adding a module always requires exactly **3 changes** in `watchtower.py`. Nothing else needs to change — once those 3 things are in place, the module automatically appears in `--help`, tab completion, and the module list.

Here's what each piece does:

```
MODULE_REGISTRY  →  tells WatchTower the module exists and what flags it needs
run_<name>()     →  the actual logic: install tools, run the scan, write outputs
DISPATCH         →  connects the module name string to the function
```

---

### Pattern A — Standalone Module

Use this when the tool runs **on your local machine**. No axiom needed.

**1. Add to `MODULE_REGISTRY`:**
```python
MODULE_REGISTRY: dict[str, dict] = {
    # ... existing entries ...
    "mymodule": {
        "desc":  "One-line description shown in --help",
        "fleet": False,   # standalone — no -f flag needed
        "ext":   False,   # set True only if it needs -e <extension> like finddocs
    },
}
```

**2. Write the function:**
```python
# ══════════════════════════════════════════════
# mymodule
# ══════════════════════════════════════════════
def run_mymodule(input_file: str, verbose: bool = False) -> None:
    MODULE = "mymodule"
    require_file(input_file)

    fin = final_dir(MODULE)    # watchtower-results/final/mymodule/  ← analyst outputs go here
    dbg = debug_dir(MODULE)    # watchtower-results/debug/mymodule/  ← raw/temp files go here

    # Check the tool is installed before trying to use it
    if not shutil.which("mytool"):
        error("mytool not found. Install with: sudo apt install mytool")
        sys.exit(1)

    # Run the tool — save raw output into debug/ so it doesn't pollute final/
    raw_out = str(dbg / "mytool-raw.txt")
    run_cmd(f'mytool -i "{input_file}" -o "{raw_out}"', verbose=verbose)

    # Write the final clean output to final/ with a metadata header
    out_txt = fin / f"mymodule-results-{_SESSION['timestamp']}.txt"
    header  = _write_text_header(MODULE, "Description of what this file contains")
    content = open(raw_out, encoding="utf-8", errors="replace").read()

    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(content)

    # Register the file in MANIFEST.txt so it shows up in the session index
    write_manifest_entry(MODULE, str(out_txt), "Short description for the manifest")
    success(f"mymodule complete → {out_txt}")
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

### Pattern B — Fleet Module (axiom-scan)

Use this when the tool **has a native axiom module** and can be distributed with `axiom-scan -m <tool>`. This is the most common fleet pattern.

**1. Add to `MODULE_REGISTRY`:**
```python
"mymodule": {
    "desc":  "One-line description",
    "fleet": True,    # fleet required — user must pass -f
    "ext":   False,
},
```

**2. Write the function:**
```python
def run_mymodule(input_file: str, fleet: str, verbose: bool = False) -> None:
    MODULE = "mymodule"
    require_file(input_file)
    require_fleet(fleet, MODULE)    # exits cleanly with a message if -f was not passed

    fin = final_dir(MODULE)
    dbg = debug_dir(MODULE)

    # Install the tool on all fleet nodes before scanning.
    # The if ! command -v check makes this safe to run every time —
    # it skips silently if the tool is already installed.
    info(f"Ensuring mytool is on fleet '{fleet}' …")
    run_cmd(
        "axiom-exec '"
        "if ! command -v mytool &>/dev/null; then "
        "  echo \"[fleet] installing mytool …\" && "
        "  go install github.com/example/mytool@latest; "   # ← your install command
        "else "
        "  echo \"[fleet] mytool already present\"; "
        "fi'",
        verbose=verbose,
    )

    # axiom-scan splits your input file across fleet nodes and runs the tool in parallel
    raw_out = str(dbg / "mytool-raw.txt")
    axiom_scan(input_file, fleet, "mytool-axiom-flag", raw_out, verbose=verbose)
    #                                     ↑
    #                    this is the -m flag used by axiom-scan
    #                    check axiom's module list for the exact name

    # Write the final output
    out_txt = fin / f"mymodule-results-{_SESSION['timestamp']}.txt"
    header  = _write_text_header(MODULE, "Description of what this file contains")
    content = open(raw_out, encoding="utf-8", errors="replace").read() \
              if os.path.isfile(raw_out) else ""

    with open(out_txt, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(content)

    write_manifest_entry(MODULE, str(out_txt), "mytool findings")
    success(f"mymodule complete → {fin}/")
```

**3. Add to `DISPATCH`:**
```python
"mymodule": lambda a: run_mymodule(a.input, a.fleet, a.verbose),
```

**Run it:**
```bash
python3 watchtower.py -m mymodule -i targets.txt -f myfleet
```

---

### Pattern C — Fleet Module (axiom-exec)

Use this when the tool **does not have a native axiom module**. You build a shell script, push it to fleet nodes, run it remotely, then pull results back. The `ffuf` module uses this pattern.

**2. Write the function** (steps 1 and 3 are identical to Pattern B):
```python
def run_mymodule(input_file: str, fleet: str, verbose: bool = False) -> None:
    MODULE = "mymodule"
    require_file(input_file)
    require_fleet(fleet, MODULE)

    fin = final_dir(MODULE)
    dbg = debug_dir(MODULE)

    # Install on fleet nodes (same idempotent pattern as Pattern B)
    run_cmd(
        "axiom-exec 'if ! command -v mytool &>/dev/null; then "
        "<install command>; fi'",
        verbose=verbose,
    )

    # Build a shell script that runs the tool against each target
    tmp_script = dbg / "run-mytool.sh"
    raw_out    = dbg / "raw-results"
    raw_out.mkdir(parents=True, exist_ok=True)

    with open(tmp_script, "w") as sh:
        sh.write("#!/usr/bin/env bash\nset -euo pipefail\n\n")
        for target in read_lines(input_file):
            safe = re.sub(r"[^\w._-]", "", target)[:100]
            sh.write(f"mytool -target '{target}' -o ~/recon/mytool-{safe}.json\n")

    # Push script → run it on fleet → pull results back locally
    run_cmd("axiom-exec 'mkdir -p ~/recon'", verbose=verbose)
    run_cmd(f'axiom-scp "{tmp_script}" "~/recon/run-mytool.sh"', verbose=verbose)
    run_cmd("axiom-exec 'bash ~/recon/run-mytool.sh'", verbose=verbose)
    run_cmd(f'axiom-scp "~/recon/mytool-*.json" "{raw_out}/"', verbose=verbose)

    # Parse raw_out/*.json and write final outputs
    # ... your parsing logic here ...

    success(f"mymodule complete → {fin}/")
```

---

### Helper Scripts

If your module needs a supporting Python script for parsing or merging results, place it in the `modules/` directory and call it like this:

```python
run_module_script("my-helper.py", arg1, arg2)
```

It will be found automatically regardless of where WatchTower is run from.

---

### Quick Reference

| Pattern | When to use | `fleet` in registry | Function signature |
|---|---|---|---|
| A — Standalone | Tool runs locally | `False` | `(input_file, verbose)` |
| B — axiom-scan | Tool has a native axiom module | `True` | `(input_file, fleet, verbose)` |
| C — axiom-exec | Tool has no axiom module | `True` | `(input_file, fleet, verbose)` |

---

## Project Structure

```
watchtower/
├── watchtower.py          ← Main script — edit this to add modules
├── requirements.txt       ← Python package list (xlsxwriter, openpyxl)
├── README.md
└── modules/               ← Helper scripts — do NOT move or rename these
    ├── capture-headers.py
    ├── capture-osint.py
    ├── clone-repos.py
    ├── convert-nmap-to-xml.py
    ├── dnsrecon-merge.py
    ├── parse_domains_subdomains.py
    └── pretty_parse_ssl_alt_names.py
```

> Helper scripts must stay in `modules/` next to `watchtower.py`. WatchTower resolves them by relative path at runtime.

---

## Tips & Tricks

- **Only install what you need.** If you only use `dnsrecon` and `getheaders`, only install `dnsrecon`. WatchTower will error clearly if a required tool is missing.
- **Tab completion** — press `Tab` after `-m` to cycle through module names.
- **Input file format** — one domain or URL per line. Remove blank lines and comments before running.
- **Verbose mode** (`-v`) prints every shell command before it runs — useful for understanding what's happening.
- **Debug mode** (`DEBUG=1`) prints a full Python traceback on unexpected errors.
- **No-color mode** (`NO_COLOR=1`) strips all colour — useful for logging to files or CI pipelines.
- **Check MANIFEST.txt** after any run — it lists every file produced with timestamps and descriptions, across all sessions.
- **Debug folders** (`watchtower-results/debug/<module>/`) contain raw tool output if you need to check what actually came back from a tool.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Module helper 'X' not found` | Check `modules/` directory is intact and next to `watchtower.py` |
| `axiom-scan: command not found` | Install and configure axiom, or use a standalone module instead |
| `dnsrecon: command not found` | `sudo apt install dnsrecon` |
| `gitleaks: command not found` | Download from [gitleaks releases](https://github.com/gitleaks/gitleaks/releases) |
| `jq: command not found` | `sudo apt install jq` |
| Empty output files | Run with `-v` to see exact commands and any errors |
| `Permission denied` | `chmod +x watchtower.py` |
| Python version error | Upgrade to Python 3.10+: check with `python3 --version` |
| venv not active | Run `source venv/bin/activate` before running WatchTower |

---

## License

MIT — use freely, contribute back.
