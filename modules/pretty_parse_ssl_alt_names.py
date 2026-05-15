#!/usr/bin/env python3
"""
modules/pretty_parse_ssl_alt_names.py
Reads ssl-alt-names.txt (from sslscan module) and writes
domain_alt_names.txt with a clean, human-readable format.

Usage:
    python3 modules/pretty_parse_ssl_alt_names.py [--input ssl-alt-names.txt] [--output domain_alt_names.txt]
"""

import sys
import re
import argparse
from pathlib import Path


def parse_alt_names(content: str) -> dict[str, list[str]]:
    """Extract domain → alt-names mapping from sslscan output."""
    result: dict[str, list[str]] = {}
    for entry in content.split("Testing SSL server"):
        if not entry.strip():
            continue
        dm = re.search(r"(\S+) on port", entry)
        an = re.search(r"Altnames: (.+)", entry)
        if dm and an:
            domain = dm.group(1)
            alts = [
                a.strip().lstrip("DNS:").strip()
                for a in an.group(1).split(", ")
                if a.strip()
            ]
            result[domain] = alts
    return result


def write_output(result: dict[str, list[str]], output_file: str) -> int:
    """Write pretty-printed alt names. Returns count of domains written."""
    with open(output_file, "w", encoding="utf-8") as f:
        for domain, alts in result.items():
            f.write(f"Domain: {domain}\n")
            f.write("Alternative Names:\n")
            for a in alts:
                f.write(f"  - {a}\n")
            f.write("\n")
    return len(result)


def main() -> None:
    parser = argparse.ArgumentParser(description="Parse SSL alt names")
    parser.add_argument("--input",  default="ssl-alt-names.txt",
                        help="Input sslscan output file (default: ssl-alt-names.txt)")
    parser.add_argument("--output", default="domain_alt_names.txt",
                        help="Output file (default: domain_alt_names.txt)")
    args = parser.parse_args()

    if not Path(args.input).is_file():
        print(f"[!] {args.input} not found — skipping alt-name parse.")
        sys.exit(0)   # Not fatal; sslscan may not have found alt names

    content = Path(args.input).read_text(encoding="utf-8", errors="replace")
    result  = parse_alt_names(content)

    if not result:
        print("[!] No alt names found in input file.")
        sys.exit(0)

    count = write_output(result, args.output)
    print(f"[+] Alt names for {count} domain(s) written to {args.output}")


if __name__ == "__main__":
    main()
