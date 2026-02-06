#!/usr/bin/env python3
"""
Lint Gherkin `.feature` specs with gherkin-lint.

Designed for CI usage:
- Lint only changed `.feature` files between two git refs (default).
- Optionally lint all `.feature` files under docs/spec*/.

This script shells out to `npx -y gherkin-lint`.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )


def _require_git_repo() -> None:
    p = _run(["git", "rev-parse", "--is-inside-work-tree"])
    if p.returncode != 0 or p.stdout.strip() != "true":
        raise RuntimeError("Not inside a git repository.")


def _detect_default_base_ref() -> str:
    # Prefer origin's HEAD branch if available.
    p = _run(["git", "remote", "show", "origin"])
    if p.returncode == 0:
        for line in p.stdout.splitlines():
            line = line.strip()
            if line.startswith("HEAD branch:"):
                branch = line.split(":", 1)[1].strip()
                if branch:
                    return f"origin/{branch}"

    # Fallbacks.
    for ref in ("origin/main", "origin/master", "main", "master"):
        p2 = _run(["git", "rev-parse", "--verify", ref])
        if p2.returncode == 0:
            return ref

    raise RuntimeError("Unable to detect a default base ref. Pass --base explicitly.")


def _ensure_gherkin_lintc(repo_root: Path) -> Path:
    cfg = repo_root / ".gherkin-lintc"
    if cfg.exists():
        return cfg

    # Try to copy from the behavior-spec-writing skill if present.
    fallback = Path.home() / ".agents" / "skills" / "behavior-spec-writing" / ".gherkin-lintc"
    if fallback.exists():
        shutil.copyfile(fallback, cfg)
        return cfg

    raise RuntimeError(
        "Missing .gherkin-lintc in repo root and no fallback found at "
        f"{fallback}. Create/copy .gherkin-lintc first."
    )


def _changed_feature_files(base: str, head: str) -> list[str]:
    p = _run(["git", "diff", "--name-only", f"{base}...{head}", "--", "*.feature"])
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"git diff failed for {base}...{head}")
    return [line.strip() for line in p.stdout.splitlines() if line.strip()]


def _all_feature_files(repo_root: Path) -> list[str]:
    candidates: list[Path] = []
    for d in (repo_root / "docs" / "spec", repo_root / "docs" / "specs"):
        if d.is_dir():
            candidates.append(d)

    if not candidates:
        # Last resort: search under docs/.
        docs = repo_root / "docs"
        if docs.is_dir():
            candidates.append(docs)

    files: list[str] = []
    for base in candidates:
        for p in base.rglob("*.feature"):
            if p.is_file():
                files.append(str(p))
    return sorted(set(files))


def main() -> int:
    ap = argparse.ArgumentParser(description="Run gherkin-lint for changed .feature files.")
    ap.add_argument("--base", help="Git base ref/sha (default: auto-detect origin HEAD)")
    ap.add_argument("--head", default="HEAD", help="Git head ref/sha (default: HEAD)")
    ap.add_argument(
        "--all",
        action="store_true",
        help="Lint all .feature files under docs/spec*/ instead of only changed files.",
    )
    args = ap.parse_args()

    if shutil.which("npx") is None:
        print("ERROR: npx not found. Install Node.js (npx) to run gherkin-lint.", file=sys.stderr)
        return 2

    try:
        _require_git_repo()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    repo_root = Path(_run(["git", "rev-parse", "--show-toplevel"]).stdout.strip())
    if not repo_root.exists():
        print("ERROR: Unable to resolve repo root.", file=sys.stderr)
        return 2

    try:
        cfg = _ensure_gherkin_lintc(repo_root)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.all:
        files = _all_feature_files(repo_root)
    else:
        base = args.base or _detect_default_base_ref()
        files = _changed_feature_files(base, args.head)

    if not files:
        print("No .feature files to lint.")
        return 0

    failures = 0
    for f in files:
        print(f"Linting: {f}")
        p = _run(["npx", "-y", "gherkin-lint", "-c", str(cfg), f], cwd=repo_root)
        if p.stdout.strip():
            print(p.stdout.rstrip())
        if p.stderr.strip():
            print(p.stderr.rstrip(), file=sys.stderr)
        if p.returncode != 0:
            failures += 1

    if failures:
        print(f"gherkin-lint failed for {failures} file(s).", file=sys.stderr)
        return 1

    print("gherkin-lint OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

