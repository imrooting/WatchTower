#!/usr/bin/env python3
"""
modules/dnsrecon-merge.py
Merges all *_rec.csv files produced by dnsrecon into merged_output.csv.

Run from the directory containing the CSV files (or pass --directory).

Usage:
    python3 modules/dnsrecon-merge.py [--directory .] [--output merged_output.csv]
"""

import sys
import csv
import argparse
from pathlib import Path


def merge_csv(directory: str, output_file: str) -> int:
    """Merge dnsrecon CSV files. Returns count of data rows merged."""
    merged: list[list] = []
    header: list[str] = []

    csv_files = sorted(Path(directory).glob("*_rec.csv"))
    if not csv_files:
        print(f"[!] No *_rec.csv files found in '{directory}'")
        return 0

    for path in csv_files:
        domain = path.stem.split("_")[0]
        try:
            with open(path, newline="", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                file_header = next(reader, None)
                if file_header:
                    header = file_header
                for row in reader:
                    merged.append([domain] + row)
        except OSError as e:
            print(f"[!] Skipping {path}: {e}")

    if not merged:
        print("[!] No data rows found across CSV files.")
        return 0

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Domain"] + header)
        w.writerows(merged)

    return len(merged)


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge dnsrecon CSV files")
    parser.add_argument("--directory", default=".",
                        help="Directory containing *_rec.csv files (default: .)")
    parser.add_argument("--output", default="merged_output.csv",
                        help="Output CSV file (default: merged_output.csv)")
    args = parser.parse_args()

    count = merge_csv(args.directory, args.output)
    if count > 0:
        print(f"[+] Merged {count} rows → {args.output}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
