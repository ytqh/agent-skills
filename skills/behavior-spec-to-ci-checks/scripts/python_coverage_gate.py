#!/usr/bin/env python3
"""
Enforce Python coverage thresholds for selected paths.

This is intended to be run after tests have produced coverage data (e.g. `.coverage`).

Important:
- To enforce *branch* coverage, make sure coverage was collected with branch data enabled:
  - `python -m coverage run --branch -m pytest`
  - or set `branch = True` in `.coveragerc`
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run coverage report with a fail-under threshold.")
    ap.add_argument(
        "--include",
        action="append",
        default=[],
        help="Include pattern for coverage report (repeatable, e.g. 'src/core/*').",
    )
    ap.add_argument(
        "--omit",
        action="append",
        default=[],
        help="Omit pattern for coverage report (repeatable).",
    )
    ap.add_argument("--fail-under", type=float, default=100.0, help="Fail if coverage is below this value.")
    ap.add_argument(
        "--require-branch-data",
        action="store_true",
        help="Fail if coverage output doesn't include branch columns.",
    )
    args = ap.parse_args()

    cmd = [
        sys.executable,
        "-m",
        "coverage",
        "report",
        "--precision=2",
        "--show-missing",
        f"--fail-under={args.fail_under}",
    ]
    if args.include:
        cmd.append("--include=" + ",".join(args.include))
    if args.omit:
        cmd.append("--omit=" + ",".join(args.omit))

    p = _run(cmd)
    out = (p.stdout or "") + (p.stderr or "")
    if p.stdout:
        print(p.stdout.rstrip())
    if p.stderr:
        print(p.stderr.rstrip(), file=sys.stderr)

    if args.require_branch_data:
        # coverage.py report header includes 'Branch'/'BrPart' when branch data is present.
        header_line = ""
        for line in out.splitlines():
            if "Stmts" in line and "Cover" in line:
                header_line = line
                break
        if header_line and "Branch" not in header_line:
            print(
                "ERROR: Coverage report does not include branch columns. "
                "Collect branch data with `coverage run --branch` (or set `branch = True`).",
                file=sys.stderr,
            )
            return 2

    return p.returncode


if __name__ == "__main__":
    raise SystemExit(main())

