#!/usr/bin/env python3
"""
Validate spec traceability between Gherkin behavior specs and tests.

Conventions (recommended):
- Each `Scenario` / `Scenario Outline` has exactly one tag with prefix `@spec-`.
- Tests reference the same id as a literal string, e.g. in test name/docstring/comment.

This script can be rolled out incrementally:
- mode=diff-tags (default): only enforce spec ids newly introduced in the PR diff.
- mode=changed-files: enforce all spec ids present in changed `.feature` files.
- mode=all: enforce all spec ids across the repo.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


SPEC_TAG_RE = re.compile(r"@spec-[a-z0-9][a-z0-9-]*")
SPEC_ID_RE = re.compile(r"(?:@)?(spec-[a-z0-9][a-z0-9-]*)")


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


def _repo_root() -> Path:
    p = _run(["git", "rev-parse", "--show-toplevel"])
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "Unable to resolve repo root.")
    root = Path(p.stdout.strip())
    if not root.exists():
        raise RuntimeError("Repo root does not exist on disk.")
    return root


def _detect_default_base_ref() -> str:
    p = _run(["git", "remote", "show", "origin"])
    if p.returncode == 0:
        for line in p.stdout.splitlines():
            line = line.strip()
            if line.startswith("HEAD branch:"):
                branch = line.split(":", 1)[1].strip()
                if branch:
                    return f"origin/{branch}"

    for ref in ("origin/main", "origin/master", "main", "master"):
        p2 = _run(["git", "rev-parse", "--verify", ref])
        if p2.returncode == 0:
            return ref

    raise RuntimeError("Unable to detect a default base ref. Pass --base explicitly.")


def _git_changed_feature_files(base: str, head: str) -> list[str]:
    p = _run(["git", "diff", "--name-only", f"{base}...{head}", "--", "*.feature"])
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"git diff failed for {base}...{head}")
    return [line.strip() for line in p.stdout.splitlines() if line.strip()]


@dataclass(frozen=True)
class SpecIdSource:
    spec_id: str  # normalized without leading '@' (e.g. spec-foo-001)
    file: str | None = None


def _collect_spec_ids_from_diff(base: str, head: str) -> list[SpecIdSource]:
    p = _run(["git", "diff", "--unified=0", f"{base}...{head}", "--", "*.feature"])
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"git diff failed for {base}...{head}")

    current_file: str | None = None
    out: list[SpecIdSource] = []
    for raw in p.stdout.splitlines():
        line = raw.rstrip("\n")
        if line.startswith("+++ "):
            # Example: +++ b/docs/spec/feature-spec/foo.feature
            if line.startswith("+++ b/"):
                current_file = line[len("+++ b/") :].strip()
            else:
                current_file = None
            continue

        # Only added lines; skip file header.
        if not line.startswith("+") or line.startswith("+++"):
            continue

        for m in SPEC_TAG_RE.finditer(line):
            spec_id = m.group(0).lstrip("@")
            out.append(SpecIdSource(spec_id=spec_id, file=current_file))
    return out


def _collect_spec_ids_from_files(files: list[Path]) -> list[SpecIdSource]:
    out: list[SpecIdSource] = []
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in SPEC_TAG_RE.finditer(text):
            spec_id = m.group(0).lstrip("@")
            out.append(SpecIdSource(spec_id=spec_id, file=str(fp)))
    return out


def _find_all_feature_files(root: Path) -> list[Path]:
    bases: list[Path] = []
    for d in (root / "docs" / "spec", root / "docs" / "specs"):
        if d.is_dir():
            bases.append(d)
    if not bases:
        docs = root / "docs"
        if docs.is_dir():
            bases.append(docs)
    out: list[Path] = []
    for base in bases:
        out.extend([p for p in base.rglob("*.feature") if p.is_file()])
    return sorted(set(out))


def _scenario_tag_violations(feature_file: Path) -> list[str]:
    """
    Return a list of violations like:
    - "<file>: Scenario: <name> missing @spec- tag"
    - "<file>: Scenario: <name> has multiple @spec- tags"
    """
    violations: list[str] = []
    pending_tags: list[str] = []
    for raw in feature_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("@"):
            pending_tags.append(line)
            continue

        m = re.match(r"^(Scenario Outline|Scenario)\s*:\s*(.+)$", line)
        if m:
            scenario_name = m.group(2).strip()
            spec_tags: list[str] = []
            for tag_line in pending_tags:
                spec_tags.extend(SPEC_TAG_RE.findall(tag_line))
            if len(spec_tags) == 0:
                violations.append(f"{feature_file}: Scenario '{scenario_name}' missing @spec- tag")
            elif len(spec_tags) > 1:
                violations.append(f"{feature_file}: Scenario '{scenario_name}' has multiple @spec- tags: {spec_tags}")
            pending_tags = []
            continue

        # Any other non-tag line consumes pending tags context.
        pending_tags = []

    return violations


def _duplicate_spec_id_violations(spec_sources: list[SpecIdSource]) -> list[str]:
    by_id: dict[str, list[str]] = {}
    for s in spec_sources:
        by_id.setdefault(s.spec_id, []).append(s.file or "<unknown>")

    violations: list[str] = []
    for spec_id, files in sorted(by_id.items()):
        uniq = sorted(set(files))
        if len(uniq) > 1:
            violations.append(f"Duplicate spec id '{spec_id}' appears in: {', '.join(uniq)}")
    return violations


def _iter_search_files(root: Path, search_dirs: list[Path]) -> list[Path]:
    exclude_dir_names = {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        "__pycache__",
        "htmlcov",
    }
    include_exts = {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs"}

    out: list[Path] = []
    for base in search_dirs:
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_dir() and p.name in exclude_dir_names:
                # rglob won't let us prune; rely on filtering files only.
                continue
            if not p.is_file():
                continue
            if p.suffix not in include_exts:
                continue
            out.append(p)
    return out


def _collect_spec_ids_in_code(search_files: list[Path]) -> set[str]:
    found: set[str] = set()
    for fp in search_files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for m in SPEC_ID_RE.finditer(text):
            found.add(m.group(1))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description="Check spec id traceability against test code.")
    ap.add_argument(
        "--mode",
        choices=("diff-tags", "changed-files", "all"),
        default="diff-tags",
        help="What to enforce (default: diff-tags).",
    )
    ap.add_argument("--base", help="Git base ref/sha (default: auto-detect origin HEAD)")
    ap.add_argument("--head", default="HEAD", help="Git head ref/sha (default: HEAD)")
    ap.add_argument(
        "--require-scenario-tags",
        action="store_true",
        help="Fail if any selected scenario is missing (or has multiple) @spec- tags.",
    )
    ap.add_argument(
        "--enforce-unique-spec-ids",
        action="store_true",
        help="Fail if the same spec id appears in multiple selected feature files.",
    )
    ap.add_argument(
        "--search-dir",
        action="append",
        default=[],
        help="Directory to search for test/code references (repeatable). Default: auto-detect.",
    )
    args = ap.parse_args()

    try:
        _require_git_repo()
        root = _repo_root()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    base = args.base or _detect_default_base_ref()
    head = args.head

    selected_feature_files: list[Path] = []
    spec_sources: list[SpecIdSource] = []

    try:
        if args.mode == "diff-tags":
            changed_paths = _git_changed_feature_files(base, head)
            selected_feature_files = [root / p for p in changed_paths]
            spec_sources = _collect_spec_ids_from_diff(base, head)
        elif args.mode == "changed-files":
            changed_paths = _git_changed_feature_files(base, head)
            selected_feature_files = [root / p for p in changed_paths]
            spec_sources = _collect_spec_ids_from_files(selected_feature_files)
        elif args.mode == "all":
            selected_feature_files = _find_all_feature_files(root)
            spec_sources = _collect_spec_ids_from_files(selected_feature_files)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    selected_feature_files = [p for p in selected_feature_files if p.exists() and p.is_file()]

    if args.require_scenario_tags and selected_feature_files:
        violations: list[str] = []
        for fp in selected_feature_files:
            try:
                violations.extend(_scenario_tag_violations(fp))
            except Exception:
                violations.append(f"{fp}: unable to parse file for scenario tags")
        if violations:
            print("Spec tag violations:", file=sys.stderr)
            for v in violations:
                print(f"- {v}", file=sys.stderr)
            return 1

    if args.enforce_unique_spec_ids and spec_sources:
        dupe_violations = _duplicate_spec_id_violations(spec_sources)
        if dupe_violations:
            print("Duplicate spec ids:", file=sys.stderr)
            for v in dupe_violations:
                print(f"- {v}", file=sys.stderr)
            return 1

    required_ids = {s.spec_id for s in spec_sources}
    if not required_ids:
        print("No spec ids to enforce (nothing changed or no @spec- tags found).")
        return 0

    # Determine search dirs for test/code references.
    if args.search_dir:
        search_dirs = [root / p for p in args.search_dir]
    else:
        auto = []
        for d in ("tests", "test", "src", "packages"):
            p = root / d
            if p.is_dir():
                auto.append(p)
        search_dirs = auto or [root]

    search_files = _iter_search_files(root, search_dirs)
    found_in_code = _collect_spec_ids_in_code(search_files)

    missing: list[str] = []
    for spec_id in sorted(required_ids):
        if spec_id not in found_in_code:
            missing.append(spec_id)

    if missing:
        print("Missing spec id references in test/code:", file=sys.stderr)
        for spec_id in missing:
            sources = sorted({s.file for s in spec_sources if s.spec_id == spec_id and s.file})
            origin = f" (from {', '.join(sources)})" if sources else ""
            print(f"- {spec_id}{origin}", file=sys.stderr)

        print(
            "\nFix: add the literal string (e.g. '@spec-...') into at least one test file "
            "that covers the scenario.",
            file=sys.stderr,
        )
        return 1

    print(f"Spec traceability OK ({len(required_ids)} spec id(s) found in code).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

