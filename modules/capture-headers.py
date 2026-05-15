#!/usr/bin/env python3
"""
modules/capture-headers.py
Reads allresponseheaders.txt (or a path given as argv[1]) and writes
an Excel file 'response-headers-output.xlsx'.

Usage:
    python3 modules/capture-headers.py <input_file>
"""

import sys
import subprocess
from pathlib import Path


def _ensure(pkg: str) -> None:
    try:
        __import__(pkg)
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", pkg], check=True)


_ensure("openpyxl")
import openpyxl  # noqa: E402


def parse_headers(input_file: str) -> list[list[str]]:
    """Parse allresponseheaders.txt into a list of rows."""
    rows: list[list[str]] = []
    target = status = location = server = x_powered = ""

    with open(input_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Filename:"):
                if target and status:
                    rows.append([target, status, location, server, x_powered])
                target  = line.split(":", 1)[1].strip()
                status  = location = server = x_powered = "NA"
            elif line.upper().startswith("HTTP"):
                parts  = line.split()
                status = parts[1] if len(parts) > 1 else "NA"
            elif line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
            elif line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
            elif line.lower().startswith("x-powered-by:"):
                x_powered = line.split(":", 1)[1].strip()

    if target:
        rows.append([target, status, location, server, x_powered])
    return rows


def write_excel(rows: list[list[str]], output: str = "response-headers-output.xlsx") -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Response Headers"
    ws.append(["Target", "Status Code", "Location", "Server", "X-Powered-By"])
    for row in rows:
        ws.append(row)
    wb.save(output)
    print(f"[+] Excel file saved: {output}")


def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python3 capture-headers.py <input_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    if not Path(input_file).is_file():
        print(f"[-] Input file not found: {input_file}")
        sys.exit(1)

    rows = parse_headers(input_file)
    if not rows:
        print("[!] No header data parsed — output file will be empty.")
    write_excel(rows)


if __name__ == "__main__":
    main()
