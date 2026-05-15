#!/usr/bin/env python3
"""
modules/parse_domains_subdomains.py
Reads subdomains_list.txt (produced by watchtower.py subdomains module)
and writes domains-subdomains-final.csv.

Usage:
    python3 modules/parse_domains_subdomains.py [--input subdomains_list.txt] [--output domains-subdomains-final.csv]
"""

import sys
import csv
import argparse
from pathlib import Path


def parse(input_file: str) -> list[list[str]]:
    """Parse subdomains_list.txt; return list of [domain, sub1, sub2, …] rows."""
    rows: list[list[str]] = []
    current: str | None = None
    subs: list[str] = []

    with open(input_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Domain:"):
                if current is not None:
                    rows.append([current] + subs)
                    subs = []
                current = line.split(":", 1)[1].strip()
            elif line and not line.startswith("Subdomains:"):
                subs.append(line)

    if current is not None:
        rows.append([current] + subs)

    return rows


def write_csv(data: list[list[str]], output_file: str) -> int:
    """Write domain/subdomain pairs to CSV. Returns count of rows written."""
    count = 0
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Domain", "Subdomain"])
        for row in data:
            domain = row[0]
            for sub in row[1:]:
                w.writerow([domain, sub])
                count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse subdomains list to CSV")
    parser.add_argument("--input",  default="subdomains_list.txt",
                        help="Input file (default: subdomains_list.txt)")
    parser.add_argument("--output", default="domains-subdomains-final.csv",
                        help="Output CSV file (default: domains-subdomains-final.csv)")
    args = parser.parse_args()

    if not Path(args.input).is_file():
        print(f"[-] Input file not found: {args.input}")
        sys.exit(1)

    data  = parse(args.input)
    count = write_csv(data, args.output)
    print(f"[+] Written {count} subdomain row(s) to {args.output}")


if __name__ == "__main__":
    main()
