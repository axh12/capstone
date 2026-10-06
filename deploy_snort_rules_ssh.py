#!/usr/bin/env python3
"""Safely deploy generated Snort rules to pfSense over SSH.

The pfSense custom-rules path and reload command vary by package/interface,
so both are explicit arguments. SSH keys are recommended; no password is
accepted on the command line.
"""
from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rules", required=True, type=Path)
    p.add_argument("--host", required=True)
    p.add_argument("--user", default="root")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--key", help="SSH private key file")
    p.add_argument("--remote-rules", required=True,
                   help="pfSense Snort custom.rules path")
    p.add_argument("--reload", required=True,
                   help="pfSense command that validates/reloads Snort")
    p.add_argument("--insecure-host-key", action="store_true",
                   help="Disable SSH host-key checking (not recommended)")
    args = p.parse_args()

    if not args.rules.is_file():
        p.error(f"rules file not found: {args.rules}")
    text = args.rules.read_text(encoding="utf-8")
    # Refuse legacy source-IP rules; deployment must remain command-specific.
    for line in text.splitlines():
        if re.match(r"\s*(?:alert|drop)\s+tcp\s+\d+\.\d+\.\d+\.\d+\s", line):
            raise SystemExit("Refusing deployment of an IP-specific Snort rule")

    ssh_base = ["ssh", "-p", str(args.port)]
    scp_base = ["scp", "-P", str(args.port)]
    if args.key:
        ssh_base += ["-i", args.key]
        scp_base += ["-i", args.key]
    if args.insecure_host_key:
        ssh_base += ["-o", "StrictHostKeyChecking=no"]
        scp_base += ["-o", "StrictHostKeyChecking=no"]
    target = f"{args.user}@{args.host}"

    with tempfile.NamedTemporaryFile(prefix="capstone-snort-", suffix=".rules", delete=False) as f:
        remote_tmp = f"/tmp/{Path(f.name).name}"
    try:
        run(scp_base + [str(args.rules), f"{target}:{remote_tmp}"])
        install = (
            f"cp {shlex.quote(args.remote_rules)} "
            f"{shlex.quote(args.remote_rules)}.bak 2>/dev/null || true; "
            f"install -m 0644 {shlex.quote(remote_tmp)} {shlex.quote(args.remote_rules)}; "
            f"rm -f {shlex.quote(remote_tmp)}; {args.reload}"
        )
        run(ssh_base + [target, install])
    finally:
        Path(f.name).unlink(missing_ok=True)
    print(f"Deployed {args.rules} to {target}:{args.remote_rules}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
