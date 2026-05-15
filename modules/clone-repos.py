#!/usr/bin/env python3
"""
modules/clone-repos.py
Clones each GitHub URL in the input file into the output directory.

Usage:
    python3 modules/clone-repos.py <input_file> [<output_dir>]
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


def clone_repos(input_file: str, output_dir: str = "cloned_repos") -> int:
    """Clone repos. Returns count of successfully cloned repos."""
    os.makedirs(output_dir, exist_ok=True)

    with open(input_file, encoding="utf-8", errors="replace") as f:
        urls = [ln.strip() for ln in f if ln.strip()]

    if not urls:
        print("[-] Input file is empty.")
        return 0

    cloned = 0
    for url in urls:
        repo_name = url.rstrip("/").split("/")[-1].removesuffix(".git")
        repo_path = os.path.join(output_dir, repo_name)

        if os.path.exists(repo_path):
            print(f"[~] Already exists, skipping: {repo_name}")
            cloned += 1
            continue

        result = subprocess.run(
            ["git", "clone", "--depth=1", url, repo_path],
            capture_output=False,
        )
        if result.returncode != 0:
            print(f"[-] Failed to clone: {url}")
        else:
            print(f"[+] Cloned: {url} → {repo_path}")
            cloned += 1

    return cloned


def main() -> None:
    if not (2 <= len(sys.argv) <= 3):
        print("Usage: python3 clone-repos.py <input_file> [<output_dir>]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) == 3 else "cloned_repos"

    if not Path(input_file).is_file():
        print(f"[-] Input file not found: {input_file}")
        sys.exit(1)

    count = clone_repos(input_file, output_dir)
    print(f"[+] Done. {count} repository(ies) available in '{output_dir}/'")


if __name__ == "__main__":
    main()
