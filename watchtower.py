#!/usr/bin/env python3
"""
WatchTower - Automated Reconnaissance & OSINT Framework
Modular, extensible, production-ready recon tooling.
"""

import sys
import os
import re
import subprocess
import argparse
import shutil
import glob
import time
from pathlib import Path

# ─────────────────────────────────────────────
# Ensure we're using Python 3.10+
# ─────────────────────────────────────────────
if sys.version_info < (3, 10):
    print("[-] WatchTower requires Python 3.10 or higher.")
    sys.exit(1)

# ─────────────────────────────────────────────
# Path setup
# ─────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent
MODULES_DIR = BASE_DIR / "modules"
sys.path.insert(0, str(BASE_DIR))

# ─────────────────────────────────────────────
# Dependency bootstrap
# ─────────────────────────────────────────────
def _ensure(package: str, import_name: str | None = None) -> None:
    """Install *package* if not importable under *import_name*."""
    import_name = import_name or package
    try:
        __import__(import_name)
    except ImportError:
        print(f"[~] Installing missing dependency: {package} …")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", package],
            check=True,
        )

_ensure("xlsxwriter")
_ensure("openpyxl")

try:
    import readline
    import rlcompleter  # noqa: F401
    _HAS_READLINE = True
except ImportError:
    _HAS_READLINE = False

# ─────────────────────────────────────────────
# Colour helpers
# ─────────────────────────────────────────────
_NO_COLOR = not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))

def _c(code: str, text: str) -> str:
    return text if _NO_COLOR else f"\033[{code}m{text}\033[0m"

def red(t: str) -> str:    return _c("31", t)
def green(t: str) -> str:  return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def blue(t: str) -> str:   return _c("34", t)
def cyan(t: str) -> str:   return _c("36", t)
def bold(t: str) -> str:   return _c("1",  t)

def info(msg: str) -> None:    print(blue(f"[*] {msg}"))
def success(msg: str) -> None: print(green(f"[+] {msg}"))
def warn(msg: str) -> None:    print(yellow(f"[!] {msg}"))
def error(msg: str) -> None:   print(red(f"[-] {msg}"), file=sys.stderr)

def progress(current: int, total: int, label: str = "") -> None:
    if total == 0:
        return
    pct = current / total * 100
    bar_len = 30
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    suffix = f" {label}" if label else ""
    print(f"\r  {cyan(bar)} {pct:5.1f}%{suffix}", end="", flush=True)
    if current == total:
        print()

# ─────────────────────────────────────────────
# ASCII banner
# ─────────────────────────────────────────────
BANNER = cyan(r"""
 ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗████████╗ ██████╗ ██╗    ██╗███████╗██████╗
 ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║╚══██╔══╝██╔═══██╗██║    ██║██╔════╝██╔══██╗
 ██║ █╗ ██║███████║   ██║   ██║     ███████║   ██║   ██║   ██║██║ █╗ ██║█████╗  ██████╔╝
 ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║   ██║   ██║   ██║██║███╗██║██╔══╝  ██╔══██╗
 ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║   ██║   ╚██████╔╝╚███╔███╔╝███████╗██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝
""") + bold("  Automated Reconnaissance & OSINT Framework  ") + blue("v1.0.0\n")

# ─────────────────────────────────────────────
# Module registry
# ─────────────────────────────────────────────
# Each entry: name -> (description, requires_fleet, requires_ext)
MODULE_REGISTRY: dict[str, dict] = {
    # ── axiom-scan modules ────────────────────
    "nmap":         {"desc": "Comprehensive network scan via Nmap",              "fleet": True,  "ext": False},
    "spidering":    {"desc": "Crawl domains with hakrawler & gospider",          "fleet": True,  "ext": False},
    "sslscan":      {"desc": "Scan SSL/TLS for misconfigurations",               "fleet": True,  "ext": False},
    "secretfinder": {"desc": "Find secrets in JavaScript files",                 "fleet": True,  "ext": False},
    "subdomains":   {"desc": "Discover subdomains via assetfinder/amass",        "fleet": True,  "ext": False},
    "whatweb":      {"desc": "Identify web technologies",                        "fleet": True,  "ext": False},
    "waf":          {"desc": "Detect WAF protections",                           "fleet": True,  "ext": False},
    "waybackurls":  {"desc": "Pull historical URLs from Wayback Machine",        "fleet": True,  "ext": False},
    "httpx":        {"desc": "Enumerate live HTTP/HTTPS servers",                "fleet": True,  "ext": False},
    "nuclei":       {"desc": "Auto-detect vulns via Nuclei templates",           "fleet": True,  "ext": False},
    # ── standalone modules ────────────────────
    "dnsrecon":     {"desc": "DNS reconnaissance",                               "fleet": False, "ext": False},
    "getheaders":   {"desc": "Capture & save HTTP response headers",             "fleet": False, "ext": False},
    "getbody":      {"desc": "Capture & save HTTP response bodies",              "fleet": False, "ext": False},
    "spiderfoot":   {"desc": "Gather emails, names, phones via SpiderFoot",      "fleet": False, "ext": False},
    "formfinder":   {"desc": "Extract web forms via SpiderFoot",                 "fleet": False, "ext": False},
    "asn":          {"desc": "Fetch ASN, IP block, geolocation → Excel",         "fleet": False, "ext": False},
    "cve":          {"desc": "Search CVEs via Shodan/ASN → Excel",               "fleet": False, "ext": False},
    "github":       {"desc": "Find GitHub repos related to targets",             "fleet": False, "ext": False},
    "finddocs":     {"desc": "Extract URLs by file extension",                   "fleet": False, "ext": True },
    "gitleaks":     {"desc": "Scan git repos for secrets",                       "fleet": False, "ext": False},
}

MODULES = list(MODULE_REGISTRY.keys())
AXIOM_MODULES = [k for k, v in MODULE_REGISTRY.items() if v["fleet"]]

# ─────────────────────────────────────────────
# Tab completion
# ─────────────────────────────────────────────
def _setup_completion() -> None:
    if not _HAS_READLINE:
        return
    candidates = MODULES + ["--module", "--input", "--fleet", "--extension",
                             "--output-dir", "--verbose", "--help",
                             "-m", "-i", "-f", "-e", "-o", "-v"]
    def completer(text: str, state: int) -> str | None:
        options = [c for c in candidates if c.startswith(text)]
        return options[state] if state < len(options) else None
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")

# ─────────────────────────────────────────────
# Core utilities (shared across modules)
# ─────────────────────────────────────────────
def require_file(path: str, label: str = "Input file") -> None:
    if not path or not os.path.isfile(path):
        error(f"{label} '{path}' not found.")
        sys.exit(1)

def require_fleet(fleet: str, module: str) -> None:
    if not fleet:
        error(f"Module '{module}' requires --fleet / -f <fleet_name>")
        sys.exit(1)

def require_extension(ext: str, module: str) -> None:
    if not ext:
        error(f"Module '{module}' requires --extension / -e <ext>")
        sys.exit(1)

def require_module_script(name: str) -> Path:
    """Return path to a helper script in modules/ or abort."""
    path = MODULES_DIR / name
    if not path.is_file():
        error(f"Module helper '{name}' not found in {MODULES_DIR}")
        sys.exit(1)
    return path

def run_cmd(cmd: str, *, check: bool = True,
            verbose: bool = False) -> subprocess.CompletedProcess:
    """Run a shell command, streaming output."""
    if verbose:
        info(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if check and result.returncode != 0:
        error(f"Command failed (exit {result.returncode}): {cmd}")
        sys.exit(result.returncode)
    return result

def axiom_scan(input_file: str, fleet: str, module_flag: str,
               output: str, extra: str = "",
               verbose: bool = False) -> None:
    cmd = (f'axiom-scan "{input_file}" --fleet "{fleet}" '
           f'-m {module_flag} -o "{output}"')
    if extra:
        cmd += f" {extra}"
    run_cmd(cmd, verbose=verbose)

def read_lines(path: str) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.strip() for ln in f if ln.strip()]

def mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def move_files(patterns: list[str], dest: str) -> None:
    mkdir(dest)
    for pat in patterns:
        for f in glob.glob(pat):
            try:
                shutil.move(f, dest)
            except shutil.Error:
                pass

def ask(prompt: str, choices: list[str]) -> str:
    print()
    for i, c in enumerate(choices, 1):
        print(f"  {cyan(str(i))}) {c}")
    while True:
        raw = input(f"\n{prompt} [1-{len(choices)}]: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        warn("Invalid choice — try again.")

def yes_no(prompt: str) -> bool:
    ans = input(f"{blue(prompt)} [y/N]: ").strip().lower()
    return ans in ("y", "yes")

def run_module_script(script_name: str, *args: str,
                      check: bool = True) -> subprocess.CompletedProcess:
    """Run a helper from modules/ as a subprocess."""
    script = require_module_script(script_name)
    cmd = [sys.executable, str(script)] + list(args)
    info(f"Running helper: {script_name} {' '.join(args)}")
    result = subprocess.run(cmd)
    if check and result.returncode != 0:
        error(f"Helper '{script_name}' failed (exit {result.returncode})")
        sys.exit(result.returncode)
    return result

# ─────────────────────────────────────────────
# Module implementations
# ─────────────────────────────────────────────

# ── nmap ─────────────────────────────────────
def run_nmap(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "nmap")
    require_module_script("convert-nmap-to-xml.py")

    DEFAULT_TCP = (
        "-p 20,21,22,23,69,3389,5900-5902,512-514,873,53,111,2049,"
        "135,137,138,139,445,161,389,25,110,143,80,8000,8080,8888,"
        "8443,1433,1521,3306,5000,5432,6379,27017-27018"
    )
    DEFAULT_UDP = "53,67,68,69,161,162,123,514,520,137,138,139,5355,5353"

    scan_type = ask("Select scan type", ["TCP Scan", "UDP Scan"])
    tcp_opt = udp_opt = tcp_ports = udp_ports = defeat_icmp = ""

    if scan_type == "TCP Scan":
        tcp_type = ask("Select TCP scan type",
                       ["TCP Connect Scan (-sT)", "SYN Scan (-sS)"])
        tcp_opt = "-sT" if "sT" in tcp_type else "-sS"
        port_choice = ask("Select TCP ports",
                          ["Full port scan (-p-)", "Common ports (default)", "Custom ports"])
        if port_choice.startswith("Full"):
            tcp_ports = "-p-"
        elif port_choice.startswith("Common"):
            tcp_ports = DEFAULT_TCP
        else:
            custom = input("  Enter custom ports (e.g. 80,443): ").strip()
            tcp_ports = f"-p {custom}"
    else:
        udp_opt = "-sU"
        port_choice = ask("Select UDP ports",
                          ["Full port scan (-p-)", "Common UDP ports (default)", "Custom ports"])
        if port_choice.startswith("Full"):
            udp_ports = "-p-"
        elif port_choice.startswith("Common"):
            udp_ports = f"-p {DEFAULT_UDP}"
        else:
            custom = input("  Enter custom ports (e.g. 53,161): ").strip()
            udp_ports = f"-p {custom}"
        defeat_icmp = "--defeat-icmp-ratelimit"

    speed = ask("Select scan speed", ["T3 (Normal)", "T4 (Aggressive)", "T5 (Insane)"])
    speed_flag = f"-T{speed[1]}"
    scripts_flag = "--script=default" if yes_no("Run default scripts?") else ""
    version_flag = "-sV" if yes_no("Enumerate service versions?") else ""

    args = " ".join(filter(None, [
        tcp_ports, udp_ports, "--open", speed_flag,
        scripts_flag, version_flag, tcp_opt, udp_opt, defeat_icmp,
        '--script-args "http.useragent=Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"',
        "--script-timeout 60m", "--host-timeout 60m", "-oA nmapx",
    ]))

    cmd = f'axiom-scan "{input_file}" --fleet "{fleet}" -m nmapx {args}'
    success(f"Nmap command:\n  {yellow(cmd)}")
    run_cmd(cmd, verbose=verbose)

    info("Converting Nmap XML files …")
    run_module_script("convert-nmap-to-xml.py")

    info("Cloning nmap-converter …")
    run_cmd("git clone https://github.com/mrschyte/nmap-converter.git", verbose=verbose)
    run_cmd("cd nmap-converter && sudo pip install --quiet python-libnmap XlsxWriter", verbose=verbose)
    shutil.copy("merged_nmap_output.xml", "nmap-converter/")
    run_cmd("cd nmap-converter && python3 nmap-converter.py -o nmap-watchtower.xls merged_nmap_output.xml", verbose=verbose)
    shutil.copy("nmap-converter/nmap-watchtower.xls", ".")
    shutil.rmtree("nmap-converter", ignore_errors=True)
    success("nmap-watchtower.xls created.")


# ── getheaders ───────────────────────────────
def run_getheaders(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_module_script("capture-headers.py")

    out_dir = "headers"
    mkdir(out_dir)
    urls = read_lines(input_file)
    if not urls:
        error("Input file is empty.")
        sys.exit(1)

    info(f"Fetching headers for {len(urls)} URL(s) …")
    for i, url in enumerate(urls, 1):
        safe = re.sub(r"https?://", "", url).replace("/", "_")
        safe = re.sub(r"[^\w._-]", "", safe)[:200]
        out = os.path.join(out_dir, safe + ".txt")
        result = subprocess.run(
            ["curl", "-L", "-D", out, "-k", "--max-time", "30", url, "-o", "/dev/null"],
            capture_output=True,
        )
        if verbose and result.returncode != 0:
            warn(f"curl failed for {url} (exit {result.returncode})")
        progress(i, len(urls), url)

    all_headers = "allresponseheaders.txt"
    with open(all_headers, "w", encoding="utf-8") as merged:
        for f in sorted(Path(out_dir).iterdir()):
            merged.write(f"Filename: {f.name}\n")
            merged.write(f.read_text(errors="replace"))
            merged.write("\n")

    info("Converting to Excel …")
    run_module_script("capture-headers.py", all_headers)
    success("response-headers-output.xlsx created.")


# ── getbody ──────────────────────────────────
def run_getbody(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    out_dir = "responses"
    mkdir(out_dir)
    urls = read_lines(input_file)
    if not urls:
        error("Input file is empty.")
        sys.exit(1)

    info(f"Fetching response bodies for {len(urls)} URL(s) …")
    for i, url in enumerate(urls, 1):
        safe = re.sub(r"https?://", "", url).replace("/", "_")
        safe = re.sub(r"[^\w._-]", "", safe)[:200]
        out = os.path.join(out_dir, safe + ".txt")
        subprocess.run(
            ["curl", "-o", out, "-k", "--max-time", "30", url],
            capture_output=not verbose,
        )
        progress(i, len(urls), url)

    all_bodies = "allresponsebody.txt"
    with open(all_bodies, "w", encoding="utf-8") as merged:
        for f in sorted(Path(out_dir).iterdir()):
            merged.write(f"Filename: {f.name}\n")
            merged.write(f.read_text(errors="replace"))
            merged.write("\n")
    success(f"Response bodies saved to {all_bodies}")


# ── spidering ────────────────────────────────
def run_spidering(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "spidering")

    lines = read_lines(input_file)
    if not any("://" in ln for ln in lines):
        new_file = "https_input_file.txt"
        warn(f"No scheme detected; writing https:// prefixed copy → {new_file}")
        with open(new_file, "w") as f:
            f.writelines(f"https://{ln}\n" for ln in lines)
        input_file = new_file

    if not shutil.which("jq"):
        info("jq not found — installing …")
        run_cmd("sudo apt-get install -y jq", verbose=verbose)

    axiom_scan(input_file, fleet, "hakrawler", "hakrawler-output-temp.txt", verbose=verbose)
    run_cmd("cat hakrawler-output-temp.txt | jq -r '.URL' > hakrawler-output.txt", verbose=verbose)
    run_cmd(f'grep -Ff "{input_file}" hakrawler-output.txt > temp-urls-hakrawler.txt || true', verbose=verbose)

    axiom_scan(input_file, fleet, "gospider", "spider-output", verbose=verbose)
    run_cmd("cat spider-output/* | awk '{print $3}' | grep http | grep -v '^$' > gospider-output.txt", verbose=verbose)
    run_cmd(f'grep -Ff "{input_file}" gospider-output.txt > temp-urls-gospider.txt || true', verbose=verbose)

    run_cmd("cat temp-urls-hakrawler.txt temp-urls-gospider.txt | sort -u > combinedURLs-hakrawler-gospider.txt", verbose=verbose)

    _create_final_url_list(fleet, verbose)
    _create_final_js_url_list(fleet, verbose)

    move_files([
        "hakrawler-output-temp.txt", "hakrawler-output.txt",
        "temp-urls-hakrawler.txt", "gospider-output.txt",
        "temp-urls-gospider.txt", "combinedURLs-hakrawler-gospider.txt",
        "FinalURLListTemp*.txt", "javascript-files-temp*.txt",
        "https_input_file.txt",
    ], "debug-spidering")
    success("Spidering complete. See Final-URL-List.txt and Final-JavaScript-URL-List.txt")


def _create_final_url_list(fleet: str, verbose: bool = False) -> None:
    combined = "combinedURLs-hakrawler-gospider.txt"
    require_file(combined, "Combined URLs")
    run_cmd(f"cat {combined} | grep -Ev '\\.js$|\\.css$|jquery|css|/js/|js' > FinalURLListTemp1.txt", verbose=verbose)
    axiom_scan("FinalURLListTemp1.txt", fleet, "httpx", "FinalURLListTemp2.txt", verbose=verbose)
    run_cmd("cat FinalURLListTemp2.txt | grep -v -E '404|FAILED|400|401|403' | awk '{print $1}' > FinalURLListTemp3.txt", verbose=verbose)

    if not shutil.which("qsreplace"):
        info("Installing qsreplace …")
        run_cmd("go install github.com/tomnomnom/qsreplace@latest", verbose=verbose)
        os.environ["PATH"] += ":" + os.path.expanduser("~/go/bin")

    run_cmd("cat FinalURLListTemp3.txt | qsreplace -a > Final-URL-List.txt", verbose=verbose)


def _create_final_js_url_list(fleet: str, verbose: bool = False) -> None:
    combined = "combinedURLs-hakrawler-gospider.txt"
    run_cmd(f"cat {combined} | grep -i -E 'jquery|js|css' > javascript-files-temp1.txt", verbose=verbose)
    axiom_scan("javascript-files-temp1.txt", fleet, "httpx", "javascript-files-temp2.txt", verbose=verbose)
    run_cmd("cat javascript-files-temp2.txt | grep -v -E '404|FAILED|400|401|403' | awk '{print $1}' > Final-JavaScript-URL-List.txt", verbose=verbose)


# ── secretfinder ─────────────────────────────
def run_secretfinder(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "secretfinder")
    warn("Output may contain false positives — review carefully.")
    time.sleep(2)

    info(f"Installing SecretFinder on fleet '{fleet}' …")
    time.sleep(3)
    run_cmd("axiom-exec 'cd recon && git clone https://github.com/m4ll0k/SecretFinder.git && cd SecretFinder && pip install -r requirements.txt'", verbose=verbose)
    run_cmd(f'axiom-scan "{input_file}" --fleet "{fleet}" -m secretfinder | tee -a jstemp1.txt', verbose=verbose)

    if not os.path.isfile("jstemp1.txt"):
        error("jstemp1.txt not created — secretfinder may have failed.")
        sys.exit(1)

    with open("jstemp1.txt", encoding="utf-8", errors="replace") as f:
        content = f.read()

    lines, in_block = [], False
    for line in content.splitlines():
        if "[ + ]" in line:
            in_block = True
        if in_block:
            lines.append(line)

    filtered = [
        ln for ln in lines
        if not re.search(r"home|fire|module|runtime|mode|URL: \$url", ln, re.I)
    ]
    with open("JavaScriptSecrets.txt", "w") as f:
        f.write("\n".join(filtered))

    move_files(["jstemp1.txt", "jstemp2.txt", "scan+*"], "debug-secretfinder")
    success("JavaScriptSecrets.txt created.")


# ── sslscan ──────────────────────────────────
def run_sslscan(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "sslscan")
    require_module_script("pretty_parse_ssl_alt_names.py")

    info(f"Installing sslscan on fleet '{fleet}' …")
    time.sleep(3)
    run_cmd("axiom-exec 'git clone https://github.com/rbsec/sslscan.git && cd sslscan && make static && sudo cp sslscan /usr/local/bin/'", verbose=verbose)

    axiom_scan(input_file, fleet, "sslscan", "sslscan-raw.txt", verbose=verbose)

    if not os.path.isfile("sslscan-raw.txt"):
        error("sslscan-raw.txt not created.")
        sys.exit(1)

    ansi_escape = re.compile(r"\x1B\[[0-9;]*[a-zA-Z]")
    raw = open("sslscan-raw.txt", encoding="utf-8", errors="replace").read()
    clean = ansi_escape.sub("", raw)
    with open("sslscan-result.txt", "w") as f:
        f.write(clean)

    if not os.path.getsize("sslscan-result.txt"):
        warn("sslscan-result.txt is empty — nothing to parse.")
        return

    status_lines = [
        ln for ln in clean.splitlines()
        if re.search(r"SSL|TLS", ln, re.I)
        and not re.search(
            r"Accepted|Preferred|SSL Certificate:|TLS Compression|TLS renegotiation|TLS Fallback|heartbleed|SL Certificate:", ln, re.I
        )
    ]
    filtered_status = []
    for ln in status_lines:
        parts = ln.split()
        if len(parts) >= 11 and not re.search(r"openssl|128|192|224|260|RSA|SSL/TLS Protocols:", ln, re.I):
            filtered_status.append(f"{parts[0]} {parts[1]} {parts[10]}")
    with open("ssl-tls-status.txt", "w") as f:
        f.write("\n".join(filtered_status))

    ip = port = ""
    weak: list[str] = []
    for ln in clean.splitlines():
        m = re.match(r"Testing SSL server (.+?) on port (\d+)", ln)
        if m:
            ip, port = m.group(1), m.group(2)
            continue
        if re.search(r"null|rc4|rc2|des|sm4|maga|cnt|md5|sm3", ln, re.I):
            weak.append(f"{ip}:{port} {ln.strip()}")
    with open("weak-ciphers.txt", "w") as f:
        f.write("\n".join(weak))

    run_module_script("pretty_parse_ssl_alt_names.py")

    alt_raw = open("ssl-alt-names.txt", encoding="utf-8", errors="replace").read() \
              if os.path.isfile("ssl-alt-names.txt") else ""
    domains: set[str] = set()
    for m in re.finditer(r"Altnames: (.+)", alt_raw):
        for entry in m.group(1).split(", "):
            d = entry.strip().lstrip("DNS:").strip()
            if d and not d.startswith("*"):
                domains.add(d)
    with open("domain-names-from-ssl-cert.txt", "w") as f:
        f.write("\n".join(sorted(domains)))

    move_files(["scan*", "ssl-alt-names.txt", "ssl-tls-status-temp.txt",
                "domain-names-from-ssl-cert.txt", "sslscan-raw.txt"],
               "debug-sslscan")
    success("SSLScan complete.")


# ── subdomains ───────────────────────────────
def run_subdomains(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "subdomains")
    require_module_script("parse_domains_subdomains.py")

    scan = ask("Select scan depth",
               ["Quick Scan (Assetfinder only)", "Deep Scan (Assetfinder + Amass)"])

    if "Quick" in scan:
        axiom_scan(input_file, fleet, "assetfinder", "assetfinder_output.txt", verbose=verbose)
        axiom_scan("assetfinder_output.txt", fleet, "httpx", "subdomain-httpx-result.txt", verbose=verbose)
        _finalize_subdomains(input_file)
        move_files(["assetfinder_output.txt", "subdomain-httpx-result.txt"], "debug-subdomain")
    else:
        axiom_scan(input_file, fleet, "assetfinder", "assetfinder_output.txt", verbose=verbose)
        axiom_scan(input_file, fleet, "amass", "amass_output.txt", verbose=verbose)
        run_cmd("cat assetfinder_output.txt amass_output.txt | sort -u > merged_unique_subdomains.txt", verbose=verbose)
        axiom_scan("merged_unique_subdomains.txt", fleet, "httpx", "subdomain-httpx-result.txt", verbose=verbose)
        _finalize_subdomains(input_file)
        move_files(["amass_output.txt", "assetfinder_output.txt",
                    "merged_unique_subdomains.txt", "subdomain-httpx-result.txt",
                    "temp_subdomain.txt"], "debug-subdomain")

    run_module_script("parse_domains_subdomains.py")
    move_files(["subdomains_list.txt", "live_subdomains.txt"], "debug-subdomain")
    success("Subdomain enumeration complete.")


def _finalize_subdomains(input_file: str) -> None:
    if not os.path.isfile("subdomain-httpx-result.txt"):
        error("subdomain-httpx-result.txt not found.")
        sys.exit(1)
    lines = read_lines("subdomain-httpx-result.txt")
    cleaned: list[str] = []
    for ln in lines:
        ln = re.sub(r"https?://(www\.)?", "", ln.split()[0]) if ln else ln
        if ln:
            cleaned.append(ln)
    with open("live_subdomains.txt", "w") as f:
        f.write("\n".join(cleaned))

    domains = read_lines(input_file)
    with open("subdomains_list.txt", "w") as out:
        for domain in domains:
            out.write(f"Domain: {domain}\n")
            out.write("Subdomains:\n")
            for sub in cleaned:
                if sub.endswith(f".{domain}"):
                    out.write(f"{sub}\n")
            out.write("\n")


# ── whatweb ──────────────────────────────────
def run_whatweb(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "whatweb")

    info(f"Installing whatweb on fleet '{fleet}' …")
    run_cmd("axiom-exec 'sudo apt install whatweb -y'", verbose=verbose)
    axiom_scan(input_file, fleet, "whatweb", "whatweboutput-temp.txt", verbose=verbose)

    if not os.path.isfile("whatweboutput-temp.txt"):
        error("whatweboutput-temp.txt not created.")
        sys.exit(1)

    ansi = re.compile(r"\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mK]")
    raw = open("whatweboutput-temp.txt", encoding="utf-8", errors="replace").read()
    no_ansi = ansi.sub("", raw)
    formatted = re.sub(r"\]([^\]]*?)$", r"]\1\n", no_ansi, flags=re.MULTILINE)
    with open("whatweboutput.txt", "w") as f:
        f.write(formatted)

    move_files(["whatweboutput-add-newline.txt", "whatweboutput-temp.txt"], "debug-whatweb")
    success("whatweboutput.txt created.")


# ── waf ──────────────────────────────────────
def run_waf(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "waf")

    axiom_scan(input_file, fleet, "wafw00f", "waf-temp.txt", verbose=verbose)

    if not os.path.isfile("waf-temp.txt"):
        error("waf-temp.txt not created.")
        sys.exit(1)

    ansi = re.compile(r"\x1b\[[0-9;]*m")
    with open("waf-temp.txt", encoding="utf-8", errors="replace") as f, \
         open("waf-result.txt", "a") as out:
        for line in f:
            if "site" in line.lower():
                out.write(ansi.sub("", line))

    move_files(["waf-temp.txt"], "debug-waf")
    success("waf-result.txt created.")


# ── spiderfoot ───────────────────────────────
def run_spiderfoot(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    out_dir = "spiderfoot-email-phone-name"
    mkdir(out_dir)
    urls = read_lines(input_file)
    if not urls:
        error("Input file is empty.")
        sys.exit(1)

    info(f"Running SpiderFoot against {len(urls)} target(s) …")
    for i, url in enumerate(urls, 1):
        safe = re.sub(r"[^\w._-]", "", url)[:200]
        out = os.path.join(out_dir, f"{safe}.tsv")
        with open(out, "a") as f:
            f.write(f"URL: {url}\n")
        run_cmd(
            f'spiderfoot -m sfp_spider,sfp_email,sfp_names,sfp_phone '
            f'-s "{url}" -q -F EMAILADDR,HUMAN_NAME,PHONE_NUMBER >> "{out}"',
            check=False, verbose=verbose,
        )
        progress(i, len(urls))

    run_cmd(f"cat {out_dir}/*.tsv | grep -Ev '\\-e' > merged.tsv", check=False, verbose=verbose)
    success("merged.tsv created.")


# ── formfinder ───────────────────────────────
def run_formfinder(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    mkdir("formfinder")
    for url in read_lines(input_file):
        safe = re.sub(r"[^\w._-]", "", url)[:200]
        out = f"formfinder/{safe}.tsv"
        with open(out, "a") as f:
            f.write(f"URL: {url}\n")
        run_cmd(
            f'spiderfoot -m sfp_pageinfo -s "{url}" -q -F URL_FORM >> "{out}"',
            check=False, verbose=verbose,
        )
    success("Form data saved in formfinder/")


# ── dnsrecon ─────────────────────────────────
def run_dnsrecon(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_module_script("dnsrecon-merge.py")

    if not shutil.which("dnsrecon"):
        error("dnsrecon not found. Install with: sudo apt install dnsrecon")
        sys.exit(1)

    domains = read_lines(input_file)
    if not domains:
        error("Input file is empty.")
        sys.exit(1)

    info(f"Running dnsrecon for {len(domains)} domain(s) …")
    for i, domain in enumerate(domains, 1):
        run_cmd(f'dnsrecon -d "{domain}" -t std -c "{domain}_rec.csv"',
                check=False, verbose=verbose)
        progress(i, len(domains), domain)

    run_module_script("dnsrecon-merge.py")

    for grep_cmd, out in [
        ("grep -vi txt merged_output.csv", "final-dnsrecon-result.csv"),
        ("grep -iE 'v=DMARC|p=' merged_output.csv", "dmarc-dnsrecon-result.csv"),
        ("grep -i 'v=spf' merged_output.csv", "spf-dnsrecon-result.csv"),
    ]:
        run_cmd(f"{grep_cmd} > {out}", check=False, verbose=verbose)

    mkdir("recon-data")
    for f in glob.glob("*.csv"):
        if f not in ("final-dnsrecon-result.csv", "dmarc-dnsrecon-result.csv",
                     "spf-dnsrecon-result.csv"):
            shutil.move(f, "recon-data/")
    success("DNS recon complete.")


# ── waybackurls ──────────────────────────────
def run_waybackurls(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "waybackurls")
    axiom_scan(input_file, fleet, "waybackurls", "waybackurls-results.txt", verbose=verbose)
    success("waybackurls-results.txt created.")


# ── httpx ────────────────────────────────────
def run_httpx(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "httpx")
    axiom_scan(input_file, fleet, "httpx", "httpx-results.txt", verbose=verbose)
    success("httpx-results.txt created.")


# ── nuclei ───────────────────────────────────
def run_nuclei(input_file: str, fleet: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_fleet(fleet, "nuclei")
    axiom_scan(input_file, fleet, "nuclei", "nuclei-results.txt", verbose=verbose)
    success("nuclei-results.txt created.")


# ── asn ──────────────────────────────────────
def run_asn(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_module_script("capture-osint.py")

    if not shutil.which("asn"):
        info("Installing asn …")
        run_cmd(
            'sudo sh -c \'curl "https://raw.githubusercontent.com/nitefood/asn/master/asn" '
            '> /usr/bin/asn && chmod 0755 /usr/bin/asn\'',
            verbose=verbose,
        )

    run_module_script("capture-osint.py", input_file)
    success("asn.xlsx created.")


# ── cve ──────────────────────────────────────
def run_cve(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    import xlsxwriter as xlw

    if not shutil.which("asn"):
        info("Installing asn …")
        run_cmd(
            'sudo sh -c \'curl "https://raw.githubusercontent.com/nitefood/asn/master/asn" '
            '> /usr/bin/asn && chmod 0755 /usr/bin/asn\'',
            verbose=verbose,
        )

    domains = read_lines(input_file)
    if not domains:
        error("Input file is empty.")
        sys.exit(1)

    output_file = "cve.xlsx"
    wb = xlw.Workbook(output_file)
    ws = wb.add_worksheet()
    ws.write_row(0, 0, ["Target", "Vulnerabilities"])

    info(f"Fetching CVEs for {len(domains)} domain(s) …")
    for i, domain in enumerate(domains, 1):
        cmd = (
            f"asn -J -n {domain} | jq -r "
            "'.results[].fingerprinting.vulns // [\"No vulnerabilities\"] | @csv' "
            "| sed 's/\"//g'"
        )
        try:
            out = subprocess.check_output(cmd, shell=True, timeout=60).decode().strip()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            out = "Error retrieving data"
        ws.write(i, 0, domain)
        ws.write(i, 1, out)
        progress(i, len(domains), domain)

    wb.close()
    success(f"{output_file} created.")


# ── github ───────────────────────────────────
def run_github(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    mkdir("github")
    for url in read_lines(input_file):
        safe = re.sub(r"[^\w._-]", "", url)[:200]
        out = f"github/{safe}.tsv"
        with open(out, "a") as f:
            f.write(f"URL: {url}\n")
        run_cmd(
            f'spiderfoot -m sfp_spider,sfp_github -s "{url}" -q -F PUBLIC_CODE_REPO >> "{out}"',
            check=False, verbose=verbose,
        )

    run_cmd("cat github/*.tsv > merged-github.txt", check=False, verbose=verbose)
    run_cmd(
        "cat merged-github.txt | grep -ivE '\\-e|sfp_github|source|description' "
        "| sed 's/URL://g' > temp-sorted-github-links.txt",
        check=False, verbose=verbose,
    )
    run_cmd(
        "cat temp-sorted-github-links.txt | grep http | sed 's/^URL: //' "
        "| sort -u | tee github-links-for-gitleaks.txt",
        check=False, verbose=verbose,
    )
    success("github-links-for-gitleaks.txt created.")


# ── finddocs ─────────────────────────────────
def run_finddocs(input_file: str, extension: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_extension(extension, "finddocs")
    from urllib.parse import urlparse

    out_dir = f"{extension}_files"
    urls = [ln for ln in read_lines(input_file) if ln.endswith(f".{extension}")]

    if not urls:
        warn(f"No URLs found with extension .{extension}")
        return

    mkdir(out_dir)
    url_file = os.path.join(out_dir, f"urls.{extension}")
    with open(url_file, "w") as f:
        f.write("\n".join(urls))

    grouped: dict[str, list[str]] = {}
    for u in urls:
        domain = urlparse(u).netloc.lstrip("www.")
        grouped.setdefault(domain, []).append(u)

    grouped_file = os.path.join(out_dir, "grouped_urls.txt")
    with open(grouped_file, "w") as f:
        for domain, links in sorted(grouped.items()):
            f.write(f"\nDomain: {domain}\n")
            for link in links:
                f.write(f"  {link}\n")

    success(f"{len(urls)} URL(s) with .{extension} saved in {out_dir}/")


# ── gitleaks ─────────────────────────────────
def run_gitleaks(input_file: str, verbose: bool = False) -> None:
    require_file(input_file)
    require_module_script("clone-repos.py")

    if not shutil.which("gitleaks"):
        error("gitleaks not found. Install from https://github.com/gitleaks/gitleaks/releases")
        sys.exit(1)

    lines = read_lines(input_file)
    if not any("github.com" in ln for ln in lines):
        error("Input file must contain GitHub URLs (e.g. https://github.com/user/repo).")
        sys.exit(1)

    run_module_script("clone-repos.py", input_file)
    success("Repositories cloned.")

    output_file = "gitleaks_output.txt"
    open(output_file, "w").close()

    cloned = Path("cloned_repos")
    if not cloned.is_dir():
        error("cloned_repos directory not found after cloning.")
        sys.exit(1)

    repos = [d for d in cloned.iterdir() if d.is_dir()]
    info(f"Running gitleaks on {len(repos)} repo(s) …")
    for i, repo in enumerate(repos, 1):
        info(f"  Scanning: {repo.name}")
        subprocess.run(
            ["gitleaks", "detect", "--report-format=json",
             "--report-path=gitleaks_report.json"],
            cwd=repo,
            capture_output=not verbose,
        )
        progress(i, len(repos), repo.name)

    mkdir("results")
    found = 0
    for report in cloned.rglob("gitleaks_report.json"):
        if report.stat().st_size > 3:
            dest = Path("results") / f"{report.parent.name}_gitleaks_report.json"
            shutil.copy(report, dest)
            found += 1

    if found:
        success(f"Gitleaks found findings in {found} repo(s). Reports saved in results/")
    else:
        info("No gitleaks findings detected.")


# ─────────────────────────────────────────────
# Dispatch table
# ─────────────────────────────────────────────
DISPATCH: dict[str, callable] = {
    "nmap":         lambda a: run_nmap(a.input, a.fleet, a.verbose),
    "getheaders":   lambda a: run_getheaders(a.input, a.verbose),
    "getbody":      lambda a: run_getbody(a.input, a.verbose),
    "spidering":    lambda a: run_spidering(a.input, a.fleet, a.verbose),
    "secretfinder": lambda a: run_secretfinder(a.input, a.fleet, a.verbose),
    "sslscan":      lambda a: run_sslscan(a.input, a.fleet, a.verbose),
    "subdomains":   lambda a: run_subdomains(a.input, a.fleet, a.verbose),
    "whatweb":      lambda a: run_whatweb(a.input, a.fleet, a.verbose),
    "waf":          lambda a: run_waf(a.input, a.fleet, a.verbose),
    "spiderfoot":   lambda a: run_spiderfoot(a.input, a.verbose),
    "formfinder":   lambda a: run_formfinder(a.input, a.verbose),
    "dnsrecon":     lambda a: run_dnsrecon(a.input, a.verbose),
    "waybackurls":  lambda a: run_waybackurls(a.input, a.fleet, a.verbose),
    "httpx":        lambda a: run_httpx(a.input, a.fleet, a.verbose),
    "nuclei":       lambda a: run_nuclei(a.input, a.fleet, a.verbose),
    "finddocs":     lambda a: run_finddocs(a.input, a.extension, a.verbose),
    "asn":          lambda a: run_asn(a.input, a.verbose),
    "cve":          lambda a: run_cve(a.input, a.verbose),
    "github":       lambda a: run_github(a.input, a.verbose),
    "gitleaks":     lambda a: run_gitleaks(a.input, a.verbose),
}

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def _epilog() -> str:
    lines = [bold("\nAvailable Modules:"), "", bold("  Requiring axiom-scan:")]
    for m in AXIOM_MODULES:
        lines.append(f"    {cyan(m):<22}  {MODULE_REGISTRY[m]['desc']}")
    lines += ["", bold("  Standalone:")]
    for m in MODULES:
        if m not in AXIOM_MODULES:
            lines.append(f"    {cyan(m):<22}  {MODULE_REGISTRY[m]['desc']}")
    lines += [
        "",
        bold("Examples:"),
        f"  {green('watchtower.py')} -m nmap        -i targets.txt  -f my_fleet",
        f"  {green('watchtower.py')} -m spidering   -i domains.txt  -f osint",
        f"  {green('watchtower.py')} -m dnsrecon    -i domains.txt",
        f"  {green('watchtower.py')} -m getheaders  -i targets.txt",
        f"  {green('watchtower.py')} -m finddocs    -i urls.txt     -e pdf",
        "",
        bold("Notes:"),
        "  • axiom-scan modules require an active axiom fleet (-f).",
        "  • Helper scripts live in modules/ — do not move them.",
        "  • Use NO_COLOR=1 to disable colour output.",
        "  • Use DEBUG=1 for full tracebacks on errors.",
        "  • Use -v / --verbose for detailed command output.",
        "",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="watchtower",
        description=f"{BANNER}\n{bold('Automated Reconnaissance & OSINT Framework')}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog(),
    )
    p.add_argument("-m", "--module",    metavar="MODULE",  required=True,
                   choices=MODULES,
                   help="Module to run (see list below)")
    p.add_argument("-i", "--input",     metavar="FILE",    required=True,
                   help="Input file (domains or URLs, one per line)")
    p.add_argument("-f", "--fleet",     metavar="FLEET",   default="",
                   help="Axiom fleet name (required for axiom-scan modules)")
    p.add_argument("-e", "--extension", metavar="EXT",     default="",
                   help="File extension for 'finddocs' module (e.g. pdf)")
    p.add_argument("-v", "--verbose",   action="store_true",
                   help="Show all commands being executed")
    p.add_argument("--version",         action="version",  version="WatchTower v1.0.0")
    return p


def main() -> None:
    print(BANNER)
    _setup_completion()
    parser = build_parser()
    args = parser.parse_args()

    info(f"Module  : {bold(args.module)}")
    info(f"Input   : {args.input}")
    if args.fleet:
        info(f"Fleet   : {args.fleet}")
    if args.extension:
        info(f"Ext     : {args.extension}")
    if args.verbose:
        info("Verbose : enabled")
    print()

    try:
        DISPATCH[args.module](args)
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user.")
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:
        error(f"Unexpected error in module '{args.module}': {exc}")
        if os.environ.get("DEBUG"):
            import traceback
            traceback.print_exc()
        else:
            info("Run with DEBUG=1 for a full traceback.")
        sys.exit(1)


if __name__ == "__main__":
    main()
