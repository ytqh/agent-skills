#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    platform: str
    severity: str
    regex: re.Pattern[str]
    reason: str
    suggestion: str


@dataclass
class Finding:
    rule_id: str
    platform: str
    severity: str
    line: int
    snippet: str
    reason: str
    suggestion: str


@dataclass
class SkillReport:
    scope: str
    skill_dir: str
    skill_md: str
    classification: str
    action: str
    likely_intentional_platform: str | None
    findings: list[Finding]


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="hardcoded-claude-skill-path",
        platform="claude",
        severity="high",
        regex=re.compile(r"(?:^|[`'\"\s])(?:~?/)?\.claude/skills/"),
        reason="Hardcodes Claude Code's skill root inside reusable instructions.",
        suggestion="Use canonical `.agents/skills` source paths in this environment or resolve bundled files relative to the skill directory instead of assuming `.claude/skills`.",
    ),
    Rule(
        rule_id="claude-orchestration-terms",
        platform="claude",
        severity="medium",
        regex=re.compile(r"\b(TaskOutput|run_in_background|TodoWrite|Task tool|Skill tool)\b"),
        reason="Uses Claude-specific orchestration or tool terminology.",
        suggestion="Add a Codex branch or rewrite the instruction in platform-neutral terms.",
    ),
    Rule(
        rule_id="claude-cli",
        platform="claude",
        severity="medium",
        regex=re.compile(r"\bclaude(?:\s|$)"),
        reason="Assumes the Claude Code CLI is available.",
        suggestion="Add a Codex alternative or mark the skill as intentionally Claude-specific.",
    ),
    Rule(
        rule_id="claude-frontmatter-extension",
        platform="claude",
        severity="low",
        regex=re.compile(r"^(?:disable-model-invocation|allowed-tools|user-invocable|context|agent)\s*:", re.MULTILINE),
        reason="Uses Claude Code frontmatter extensions whose behavior is not shared with Codex.",
        suggestion="If the behavior matters for Codex too, document the Codex equivalent separately instead of assuming the field carries over.",
    ),
    Rule(
        rule_id="claude-config-path",
        platform="claude",
        severity="medium",
        regex=re.compile(r"~/\.claude/"),
        reason="References a Claude Code home-directory path directly.",
        suggestion="Only keep this when the path is genuinely Claude-only; otherwise add a Codex or canonical `.agents` path.",
    ),
    Rule(
        rule_id="codex-tooling",
        platform="codex",
        severity="medium",
        regex=re.compile(r"\b(js_repl(?:_reset)?|spawn_agent|wait_agent|close_agent|update_plan|request_user_input|apply_patch)\b"),
        reason="Uses Codex-specific tools or workflow terms.",
        suggestion="Add a Claude Code alternative or mark the skill as intentionally Codex-specific.",
    ),
    Rule(
        rule_id="codex-cli",
        platform="codex",
        severity="medium",
        regex=re.compile(r"\bcodex(?:\s|$)"),
        reason="Assumes the Codex CLI is available.",
        suggestion="Add a Claude Code alternative or make the skill scope explicit.",
    ),
    Rule(
        rule_id="codex-config-path",
        platform="codex",
        severity="medium",
        regex=re.compile(r"~/\.codex/"),
        reason="References a Codex home-directory path directly.",
        suggestion="Only keep this when the path is genuinely Codex-only; otherwise add a Claude Code or canonical cross-agent path.",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit repo and user skills for Codex vs Claude Code portability gaps."
    )
    parser.add_argument(
        "--cwd",
        default=str(Path.cwd()),
        help="Working directory used to locate the current repository root.",
    )
    parser.add_argument(
        "--user-root",
        default=str(Path.home() / ".agents" / "skills"),
        help="Canonical user skill root to scan.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--show-portable",
        action="store_true",
        help="Include skills with no findings.",
    )
    parser.add_argument(
        "--no-mirror-check",
        action="store_true",
        help="Skip `.claude/skills` mirror validation in this local setup.",
    )
    return parser.parse_args()


def repo_root_from(cwd: Path) -> Path:
    try:
        result = subprocess.run(
            ["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return cwd
    return Path(result.stdout.strip())


def canonical_roots(cwd: Path, user_root: Path) -> list[tuple[str, Path]]:
    repo_root = repo_root_from(cwd)
    roots: list[tuple[str, Path]] = []
    repo_skills = repo_root / ".agents" / "skills"
    if repo_skills.is_dir():
        roots.append(("repo", repo_skills))
    if user_root.is_dir():
        roots.append(("user", user_root))
    return roots


def skill_dirs(root: Path) -> Iterable[Path]:
    for child in sorted(root.iterdir()):
        skill_md = child / "SKILL.md"
        if child.is_dir() and skill_md.is_file():
            yield child


def line_number(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def snippet_at(lines: list[str], line: int) -> str:
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()
    return ""


def should_ignore(rule_id: str, snippet: str) -> bool:
    lower = snippet.lower()
    if rule_id == "hardcoded-claude-skill-path":
        return any(
            marker in lower
            for marker in (
                "hardcoded",
                "prefer platform-neutral",
                "mirror entries",
                "mirror health",
                "missing or broken",
                "resolves to",
            )
        )
    if rule_id == "claude-config-path":
        return "mirror" in lower or "hardcoded" in lower or "resolves to" in lower
    if rule_id in {"claude-orchestration-terms", "codex-tooling"}:
        return "such as" in lower and "without a" in lower
    if rule_id in {"claude-cli", "codex-cli"}:
        return "assume only" in lower
    return False


def add_rule_matches(text: str, lines: list[str], findings: list[Finding]) -> None:
    seen: set[tuple[str, int, str]] = set()
    for rule in RULES:
        for match in rule.regex.finditer(text):
            line = line_number(text, match.start())
            snippet = snippet_at(lines, line)
            if should_ignore(rule.rule_id, snippet):
                continue
            key = (rule.rule_id, line, snippet)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    platform=rule.platform,
                    severity=rule.severity,
                    line=line,
                    snippet=snippet,
                    reason=rule.reason,
                    suggestion=rule.suggestion,
                )
            )


def add_instruction_file_findings(text: str, lines: list[str], findings: list[Finding]) -> None:
    if "CLAUDE.md" in text and "AGENTS.md" not in text:
        line = next((i for i, value in enumerate(lines, start=1) if "CLAUDE.md" in value), 1)
        findings.append(
            Finding(
                rule_id="claude-instructions-only",
                platform="claude",
                severity="medium",
                line=line,
                snippet=snippet_at(lines, line),
                reason="References Claude's instruction file without mentioning Codex's `AGENTS.md` equivalent.",
                suggestion="If the workflow should work in both environments, add the `AGENTS.md` counterpart explicitly.",
            )
        )
    if "AGENTS.md" in text and "CLAUDE.md" not in text:
        line = next((i for i, value in enumerate(lines, start=1) if "AGENTS.md" in value), 1)
        findings.append(
            Finding(
                rule_id="codex-instructions-only",
                platform="codex",
                severity="medium",
                line=line,
                snippet=snippet_at(lines, line),
                reason="References Codex's instruction file without mentioning Claude Code's `CLAUDE.md` equivalent.",
                suggestion="If the workflow should work in both environments, add the `CLAUDE.md` counterpart explicitly.",
            )
        )


def infer_intent(text: str) -> str | None:
    lower = text.lower()
    claude_markers = (
        "claude code",
        "claude.ai",
        "disable-model-invocation",
        "/agents",
        "~/.claude/",
    )
    codex_markers = (
        "codex",
        "js_repl",
        "agents/openai.yaml",
        "~/.codex/",
        "spawn_agent",
    )
    claude = any(marker in lower for marker in claude_markers)
    codex = any(marker in lower for marker in codex_markers)
    if claude and not codex:
        return "claude"
    if codex and not claude:
        return "codex"
    return None


def classify(findings: list[Finding], intent: str | None) -> tuple[str, str]:
    if not findings:
        return "portable", "none"

    platforms = {finding.platform for finding in findings}
    if len(platforms) == 1:
        only = next(iter(platforms))
        if intent == only:
            return f"{only}-specific (likely intentional)", "clarify-intent"
        if any(finding.severity == "high" for finding in findings):
            return f"{only}-specific", "fix-now"
        return f"{only}-leaning", "review"

    if any(finding.severity == "high" for finding in findings):
        return "mixed", "fix-now"
    return "mixed", "review"


def mirror_root_for(scope: str, repo_root: Path) -> Path:
    if scope == "repo":
        return repo_root / ".claude" / "skills"
    return Path.home() / ".claude" / "skills"


def mirror_findings(
    scope: str, skill_dir: Path, repo_root: Path, enabled: bool
) -> list[Finding]:
    if not enabled:
        return []

    mirror_root = mirror_root_for(scope, repo_root)
    if not mirror_root.exists():
        return []

    mirror_path = mirror_root / skill_dir.name
    findings: list[Finding] = []
    if not mirror_path.exists():
        findings.append(
            Finding(
                rule_id="missing-claude-mirror",
                platform="claude",
                severity="medium",
                line=1,
                snippet=str(mirror_path),
                reason="The local Claude mirror entry is missing for this canonical skill.",
                suggestion="Create or repair the `.claude/skills/<name>` symlink so Claude Code can discover the skill in this environment.",
            )
        )
        return findings

    if not mirror_path.is_symlink():
        findings.append(
            Finding(
                rule_id="non-symlink-claude-mirror",
                platform="claude",
                severity="medium",
                line=1,
                snippet=str(mirror_path),
                reason="The local Claude mirror entry exists but is not a symlink.",
                suggestion="Move real files back to `.agents/skills` and recreate the mirror as a symlink.",
            )
        )
        return findings

    try:
        resolved = mirror_path.resolve(strict=True)
    except FileNotFoundError:
        findings.append(
            Finding(
                rule_id="broken-claude-mirror",
                platform="claude",
                severity="medium",
                line=1,
                snippet=f"{mirror_path} -> broken",
                reason="The local Claude mirror symlink is broken.",
                suggestion="Repair the symlink so it resolves to the canonical `.agents/skills` source.",
            )
        )
        return findings

    if resolved != skill_dir.resolve():
        findings.append(
            Finding(
                rule_id="mismatched-claude-mirror",
                platform="claude",
                severity="medium",
                line=1,
                snippet=f"{mirror_path} -> {resolved}",
                reason="The local Claude mirror points somewhere other than this canonical skill directory.",
                suggestion="Retarget the symlink so it points to the matching `.agents/skills/<name>` directory.",
            )
        )
    return findings


def scan_skill(
    scope: str, skill_dir: Path, repo_root: Path, mirror_check: bool
) -> SkillReport:
    skill_md = skill_dir / "SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    lines = text.splitlines()
    findings: list[Finding] = []
    add_rule_matches(text, lines, findings)
    add_instruction_file_findings(text, lines, findings)
    findings.extend(mirror_findings(scope, skill_dir, repo_root, mirror_check))
    findings.sort(key=lambda finding: (SEVERITY_ORDER[finding.severity], finding.line, finding.rule_id))
    intent = infer_intent(text)
    classification, action = classify(findings, intent)
    return SkillReport(
        scope=scope,
        skill_dir=str(skill_dir),
        skill_md=str(skill_md),
        classification=classification,
        action=action,
        likely_intentional_platform=intent,
        findings=findings,
    )


def summary_counts(reports: list[SkillReport]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for report in reports:
        counts[report.classification] = counts.get(report.classification, 0) + 1
    return dict(sorted(counts.items()))


def render_markdown(
    reports: list[SkillReport],
    roots: list[tuple[str, Path]],
    repo_root: Path,
    show_portable: bool,
) -> str:
    total_skills = len(reports)
    portable_skills = sum(1 for report in reports if report.classification == "portable")
    lines = [
        "# Cross-Agent Skill Audit",
        "",
        f"Repo root: `{repo_root}`",
        f"Scanned {total_skills} skills across {len(roots)} canonical roots.",
        "",
        "## Roots",
    ]
    for scope, root in roots:
        count = sum(1 for report in reports if report.scope == scope)
        lines.append(f"- `{scope}`: `{root}` ({count} skills)")

    lines.extend(
        [
            "",
            "## Summary",
        ]
    )
    for classification, count in summary_counts(reports).items():
        lines.append(f"- `{classification}`: {count}")
    lines.append(f"- `portable` hidden by default: {portable_skills if not show_portable else 0}")

    visible_reports = [
        report for report in reports if show_portable or report.classification != "portable"
    ]
    lines.extend(["", "## Skills Requiring Review" if visible_reports else "",])

    if not visible_reports:
        lines.append("No portability findings.")
    else:
        for report in visible_reports:
            lines.extend(
                [
                    "",
                    f"### `{report.skill_md}`",
                    f"- Scope: `{report.scope}`",
                    f"- Classification: `{report.classification}`",
                    f"- Next action: `{report.action}`",
                    f"- Intent guess: `{report.likely_intentional_platform or 'none'}`",
                ]
            )
            if report.findings:
                for finding in report.findings:
                    lines.extend(
                        [
                            f"- [{finding.severity}] line {finding.line}: `{finding.rule_id}`",
                            f"  Snippet: `{finding.snippet}`",
                            f"  Reason: {finding.reason}",
                            f"  Suggested change: {finding.suggestion}",
                        ]
                    )
            else:
                lines.append("- No findings.")

    lines.extend(
        [
            "",
            "## Next Step",
            "Present the proposed changes to the user, wait for explicit approval, and edit only the canonical `.agents/skills` sources.",
        ]
    )
    return "\n".join(line for line in lines if line != "")


def render_json(reports: list[SkillReport], roots: list[tuple[str, Path]], repo_root: Path) -> str:
    payload = {
        "repo_root": str(repo_root),
        "roots": [{"scope": scope, "path": str(root)} for scope, root in roots],
        "reports": [
            {
                **asdict(report),
                "findings": [asdict(finding) for finding in report.findings],
            }
            for report in reports
        ],
    }
    return json.dumps(payload, indent=2)


def main() -> int:
    args = parse_args()
    cwd = Path(args.cwd).expanduser().resolve()
    user_root = Path(args.user_root).expanduser().resolve()
    repo_root = repo_root_from(cwd)
    roots = canonical_roots(cwd, user_root)

    if not roots:
        print("No canonical skill roots found to scan.", file=sys.stderr)
        return 1

    reports: list[SkillReport] = []
    for scope, root in roots:
        for skill_dir in skill_dirs(root):
            reports.append(
                scan_skill(
                    scope=scope,
                    skill_dir=skill_dir,
                    repo_root=repo_root,
                    mirror_check=not args.no_mirror_check,
                )
            )

    reports.sort(key=lambda report: report.skill_md)

    if args.format == "json":
        print(render_json(reports, roots, repo_root))
    else:
        print(render_markdown(reports, roots, repo_root, args.show_portable))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
