#!/usr/bin/env python3
"""
modules/capture-osint.py
Fetches ASN, geolocation, and network info for each domain in the
input file and writes an Excel spreadsheet 'asn.xlsx'.

Usage:
    python3 modules/capture-osint.py <input_file>
"""

import sys
import subprocess
from pathlib import Path


def _ensure(pkg: str) -> None:
    try:
        __import__(pkg)
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", pkg], check=True)


_ensure("xlsxwriter")
import xlsxwriter  # noqa: E402


def run_asn_lookup(domain: str) -> list[list[str]]:
    """Run ASN lookup for a single domain; return list of data rows."""
    jq_filter = (
        ". as $root |$root.results[] "
        "|[$root.target,.ip,.geolocation.city,.geolocation.region,"
        ".geolocation.country,"
        r'"\(.routing.as_number) (\(.routing.as_name))",'
        r'"\(.net_range) (\(.net_name))"] | @csv'
    )
    cmd = (
        f"asn -J -n {domain} | jq -r '{jq_filter}'"
        " | sed 's/\"//g' | sed 's/,/, /g'"
    )
    try:
        raw = subprocess.check_output(cmd, shell=True, timeout=60).decode().strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return []

    rows: list[list[str]] = []
    for line in raw.splitlines():
        data = line.split(", ")
        geo = ", ".join(data[2:5]) if len(data) >= 5 else ""
        row_data = data[:2] + [geo] + data[5:] if len(data) >= 5 else data
        rows.append(row_data)
    return rows


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python3 capture-osint.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    if not Path(input_file).is_file():
        print(f"[-] Input file not found: {input_file}")
        sys.exit(1)

    with open(input_file, encoding="utf-8", errors="replace") as f:
        domains = [ln.strip() for ln in f if ln.strip()]

    if not domains:
        print("[-] Input file is empty.")
        sys.exit(1)

    wb = xlsxwriter.Workbook("asn.xlsx")
    ws = wb.add_worksheet()
    ws.write_row(0, 0, ["Target", "IP", "Geolocation",
                         "AS Number and Name", "Network Range and Name"])
    row = 1
    total = len(domains)

    for i, domain in enumerate(domains, 1):
        data_rows = run_asn_lookup(domain)
        if not data_rows:
            ws.write(row, 0, domain)
            ws.write(row, 1, "No data retrieved")
            row += 1
        else:
            for data in data_rows:
                for col, val in enumerate(data):
                    ws.write(row, col, val)
                row += 1

        pct = i / total * 100
        print(f"\rProgress: {pct:.1f}% ({i}/{total})", end="", flush=True)

    print()
    wb.close()
    print("[+] asn.xlsx created.")


if __name__ == "__main__":
    main()
