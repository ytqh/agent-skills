#!/usr/bin/env python3
"""
Generate/update test scaffolding and CI templates from Gherkin `.feature` specs.

This script is meant to be run locally by the agent/human while implementing a feature.
It must NOT be referenced from GitHub Actions (CI runners won't have this skill folder).
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path


_SCENARIO_RE = re.compile(r"^(Scenario Outline|Scenario)\s*:\s*(.+)$")
_FEATURE_RE = re.compile(r"^Feature\s*:\s*(.+)$")
_STEP_RE = re.compile(r"^(Given|When|Then|And|But)\b(.*)$")


@dataclass
class Scenario:
    kind: str  # "Scenario" | "Scenario Outline"
    name: str
    tags: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    examples: list[dict[str, str]] | None = None


@dataclass
class FeatureSpec:
    path: Path
    feature_name: str | None = None
    feature_tags: list[str] = field(default_factory=list)
    background_steps: list[str] = field(default_factory=list)
    scenarios: list[Scenario] = field(default_factory=list)


def _slugify(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "unnamed"


def _marker_name(tag: str) -> str:
    tag = tag.strip()
    if tag.startswith("@"):
        tag = tag[1:]
    tag = tag.replace("-", "_")
    tag = re.sub(r"[^a-zA-Z0-9_]+", "_", tag)
    tag = tag.lower().strip("_")
    if not tag:
        return "tag"
    if tag[0].isdigit():
        return f"tag_{tag}"
    return tag


def _parse_table_row(line: str) -> list[str]:
    # "| a | b |" -> ["a", "b"]
    parts = [p.strip() for p in line.strip().strip("|").split("|")]
    return [p for p in parts if p != ""]


def parse_feature(path: Path) -> FeatureSpec:
    spec = FeatureSpec(path=path)

    current_tags: list[str] = []
    in_background = False
    current_scenario: Scenario | None = None

    in_examples = False
    examples_header: list[str] | None = None
    examples_rows: list[dict[str, str]] = []

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("@"):
            # Tags can be multiple per line: "@happy-path @edge-case"
            tags = [t for t in stripped.split() if t.startswith("@")]
            if spec.feature_name is None:
                # Tags before `Feature:` apply to the entire feature.
                spec.feature_tags.extend(tags)
            else:
                current_tags.extend(tags)
            continue

        m_feat = _FEATURE_RE.match(stripped)
        if m_feat:
            spec.feature_name = m_feat.group(1).strip()
            in_background = False
            continue

        if stripped == "Background:":
            in_background = True
            current_scenario = None
            in_examples = False
            examples_header = None
            examples_rows = []
            continue

        m_scn = _SCENARIO_RE.match(stripped)
        if m_scn:
            # Finalize previous scenario examples if any.
            if current_scenario and current_scenario.kind == "Scenario Outline":
                if examples_header and examples_rows:
                    current_scenario.examples = examples_rows

            kind = m_scn.group(1)
            name = m_scn.group(2).strip()
            combined_tags = spec.feature_tags + current_tags
            current_scenario = Scenario(kind=kind, name=name, tags=combined_tags)
            spec.scenarios.append(current_scenario)
            current_tags = []

            in_background = False
            in_examples = False
            examples_header = None
            examples_rows = []
            continue

        if stripped == "Examples:":
            in_examples = True
            examples_header = None
            examples_rows = []
            continue

        if in_examples and "|" in stripped:
            cells = _parse_table_row(stripped)
            if not cells:
                continue
            if examples_header is None:
                examples_header = cells
            else:
                row = {examples_header[i]: (cells[i] if i < len(cells) else "") for i in range(len(examples_header))}
                examples_rows.append(row)
            continue

        # Leaving examples section.
        if in_examples and "|" not in stripped:
            in_examples = False
            if current_scenario and current_scenario.kind == "Scenario Outline":
                if examples_header and examples_rows:
                    current_scenario.examples = examples_rows
            examples_header = None
            examples_rows = []

        m_step = _STEP_RE.match(stripped)
        if m_step:
            step = f"{m_step.group(1)}{m_step.group(2)}".strip()
            if in_background:
                spec.background_steps.append(step)
            elif current_scenario:
                current_scenario.steps.append(step)
            continue

        # Any other line ends Background context in practice.
        if in_background:
            in_background = False

    # Finalize last scenario.
    if current_scenario and current_scenario.kind == "Scenario Outline":
        if examples_header and examples_rows:
            current_scenario.examples = examples_rows

    return spec


def _render_test_stub(
    *,
    feature: FeatureSpec,
    feature_slug: str,
    scenario: Scenario,
    test_name: str,
    rel_spec_path: str,
) -> str:
    tags = sorted(set(scenario.tags))
    markers = ["behavior_spec"] + [_marker_name(t) for t in tags]

    lines: list[str] = []
    for m in markers:
        lines.append(f"@pytest.mark.{m}")

    params: list[str] = []
    param_rows: list[tuple[str, ...]] = []
    if scenario.kind == "Scenario Outline" and scenario.examples:
        # Keep example order stable based on header order in the first row.
        header = list(scenario.examples[0].keys())
        params = [_slugify(h) for h in header]
        for row in scenario.examples:
            values = tuple(str(row.get(h, "")) for h in header)
            param_rows.append(values)

        param_list = ", ".join(params)
        lines.append(f"@pytest.mark.parametrize({param_list!r}, {param_rows!r})")

    sig = f"def {test_name}({', '.join(params)}):" if params else f"def {test_name}():"
    lines.append(sig)

    doc: list[str] = []
    doc.append(f"Spec file: {rel_spec_path}")
    if feature.feature_name:
        doc.append(f"Feature: {feature.feature_name}")
    doc.append(f"{scenario.kind}: {scenario.name}")
    if tags:
        doc.append("Tags: " + " ".join(tags))
    if feature.background_steps:
        doc.append("")
        doc.append("Background:")
        doc.extend([f"- {s}" for s in feature.background_steps])
    if scenario.steps:
        doc.append("")
        doc.append("Steps:")
        doc.extend([f"- {s}" for s in scenario.steps])

    lines.append('    """' + "\n    ".join(doc) + '"""')
    lines.append("    # TODO: Implement this scenario as UT/integration/e2e with DI+mocks.")
    lines.append(f"    raise NotImplementedError({(feature_slug + ' :: ' + scenario.name)!r})")
    return "\n".join(lines) + "\n"


def _ensure_dir(path: Path, *, dry_run: bool) -> None:
    if path.is_dir():
        return
    if dry_run:
        print(f"[dry-run] mkdir -p {path}")
        return
    path.mkdir(parents=True, exist_ok=True)


def _copy_asset(src: Path, dst: Path, *, overwrite: bool, dry_run: bool) -> None:
    if dst.exists() and not overwrite:
        print(f"Skip (exists): {dst}")
        return

    _ensure_dir(dst.parent, dry_run=dry_run)
    if dry_run:
        print(f"[dry-run] copy {src} -> {dst}")
        return
    shutil.copyfile(src, dst)
    print(f"Wrote: {dst}")


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""

def _safe_relpath(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def generate_pytest_stubs(
    *,
    repo_root: Path,
    specs: list[FeatureSpec],
    tests_dir: Path,
    overwrite_files: bool,
    dry_run: bool,
) -> None:
    _ensure_dir(tests_dir, dry_run=dry_run)

    for spec in specs:
        feature_slug = _slugify(spec.path.stem)
        out_path = tests_dir / f"test_{feature_slug}_from_spec.py"

        existing = _read_text(out_path)
        have_defs = set(re.findall(r"^def (test__[a-z0-9_]+)\(", existing, flags=re.MULTILINE))

        header = (
            "# Generated by behavior-spec-to-ci-checks from Gherkin specs.\n"
            "# Safe-to-edit: generator only appends missing tests; it does not overwrite existing functions.\n"
            f"# Source spec: {_safe_relpath(spec.path, repo_root)}\n\n"
            "import pytest\n\n"
        )

        chunks: list[str] = []
        if not out_path.exists() or overwrite_files:
            chunks.append(header)

        appended = 0
        seen_test_names: set[str] = set(have_defs)

        for scenario in spec.scenarios:
            base_name = f"test__{feature_slug}__{_slugify(scenario.name)}"
            test_name = base_name
            i = 2
            while test_name in seen_test_names:
                test_name = f"{base_name}__{i}"
                i += 1

            seen_test_names.add(test_name)
            if test_name in have_defs and not overwrite_files:
                continue

            stub = _render_test_stub(
                feature=spec,
                feature_slug=feature_slug,
                scenario=scenario,
                test_name=test_name,
                rel_spec_path=_safe_relpath(spec.path, repo_root),
            )
            chunks.append("\n" + stub)
            appended += 1

        if appended == 0 and out_path.exists() and not overwrite_files:
            print(f"No new scenarios to scaffold for: {out_path}")
            continue

        if dry_run:
            print(f"[dry-run] write {out_path} (+{appended} test(s))")
            continue

        if out_path.exists() and not overwrite_files:
            with out_path.open("a", encoding="utf-8") as f:
                for c in chunks:
                    f.write(c)
            print(f"Updated: {out_path} (+{appended} test(s))")
        else:
            out_path.write_text("".join(chunks), encoding="utf-8")
            print(f"Wrote: {out_path} ({len(spec.scenarios)} test(s))")


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate/update checks scaffolding from Gherkin specs.")
    ap.add_argument("--repo-root", default=".", help="Target repo root (default: current directory).")
    ap.add_argument(
        "--spec-root",
        action="append",
        default=[],
        help="Spec root directory (repeatable). Defaults: docs/spec and docs/specs if present.",
    )
    ap.add_argument("--tests-dir", default="tests/behavior", help="Where to write pytest stubs (repo-relative).")
    ap.add_argument("--overwrite-files", action="store_true", help="Overwrite entire generated test files.")
    ap.add_argument("--dry-run", action="store_true", help="Print actions without writing files.")

    ap.add_argument("--write-workflow", action="store_true", help="Copy the GitHub Actions workflow template.")
    ap.add_argument(
        "--workflow-path",
        default=".github/workflows/behavior-spec-quality-gate.yml",
        help="Workflow path in repo (default: .github/workflows/behavior-spec-quality-gate.yml).",
    )
    ap.add_argument("--overwrite-workflow", action="store_true", help="Overwrite workflow file if it exists.")

    ap.add_argument("--write-gherkin-lintc", action="store_true", help="Copy .gherkin-lintc template (optional).")
    ap.add_argument("--overwrite-gherkin-lintc", action="store_true", help="Overwrite .gherkin-lintc if it exists.")
    args = ap.parse_args()

    repo_root = Path(args.repo_root).resolve()
    if not repo_root.exists():
        print(f"ERROR: repo root does not exist: {repo_root}", file=sys.stderr)
        return 2

    spec_roots = [Path(p) for p in args.spec_root] if args.spec_root else []
    if not spec_roots:
        for p in ("docs/spec", "docs/specs"):
            cand = repo_root / p
            if cand.is_dir():
                spec_roots.append(cand)

    spec_files: list[Path] = []
    for root in spec_roots:
        root = (repo_root / root).resolve() if not root.is_absolute() else root
        if root.is_dir():
            spec_files.extend([p for p in root.rglob("*.feature") if p.is_file()])

    spec_files = sorted(set(spec_files))
    if not spec_files:
        print("No .feature specs found under spec roots.")
        return 0

    specs = [parse_feature(p) for p in spec_files]

    tests_dir = (repo_root / args.tests_dir).resolve()
    generate_pytest_stubs(
        repo_root=repo_root,
        specs=specs,
        tests_dir=tests_dir,
        overwrite_files=args.overwrite_files,
        dry_run=args.dry_run,
    )

    skill_root = Path(__file__).resolve().parents[1]

    if args.write_workflow:
        src = skill_root / "assets" / "github-actions" / "behavior-spec-quality-gate.python.yml"
        dst = repo_root / args.workflow_path
        _copy_asset(src, dst, overwrite=args.overwrite_workflow, dry_run=args.dry_run)

    if args.write_gherkin_lintc:
        src = skill_root / "assets" / "repo-config" / ".gherkin-lintc"
        dst = repo_root / ".gherkin-lintc"
        _copy_asset(src, dst, overwrite=args.overwrite_gherkin_lintc, dry_run=args.dry_run)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
