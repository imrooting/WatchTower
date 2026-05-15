#!/usr/bin/env python3
"""
modules/convert-nmap-to-xml.py
Merges all Nmap XML files from the 'nmapx/' directory into a single
'merged_nmap_output.xml'.

Called automatically by watchtower.py after an axiom-scan nmap run.

Usage:
    python3 modules/convert-nmap-to-xml.py [--directory nmapx] [--output merged_nmap_output.xml]
"""

import sys
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path


def merge_xml(directory: str, output_file: str) -> int:
    """Merge Nmap XML files. Returns count of files merged."""
    xml_files = sorted(Path(directory).glob("*.xml"))
    if not xml_files:
        print(f"[!] No XML files found in '{directory}' — nothing to merge.")
        return 0

    base_tree = ET.parse(xml_files[0])
    base_root = base_tree.getroot()

    for xml_file in xml_files[1:]:
        try:
            for host in ET.parse(xml_file).getroot().findall("host"):
                base_root.append(host)
        except ET.ParseError as e:
            print(f"[!] Skipping malformed XML: {xml_file} — {e}")

    base_tree.write(output_file, encoding="utf-8", xml_declaration=True)
    return len(xml_files)


def main() -> None:
    parser = argparse.ArgumentParser(description="Merge Nmap XML files")
    parser.add_argument("--directory", default="nmapx",
                        help="Directory containing Nmap XML files (default: nmapx)")
    parser.add_argument("--output", default="merged_nmap_output.xml",
                        help="Output merged XML file (default: merged_nmap_output.xml)")
    args = parser.parse_args()

    if not Path(args.directory).is_dir():
        print(f"[-] Directory not found: '{args.directory}'")
        sys.exit(1)

    count = merge_xml(args.directory, args.output)
    if count > 0:
        print(f"[+] Merged {count} file(s) → {args.output}")
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
