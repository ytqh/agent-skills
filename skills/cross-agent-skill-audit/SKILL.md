---
name: cross-agent-skill-audit
description: Audit repo and user skills for Codex vs Claude Code portability gaps. Use when creating or updating a skill that should work in both Codex and Claude Code, when reviewing existing skills for agent-specific assumptions, or when you need a report of proposed compatibility fixes before editing. By default, inspect the current repo `.agents/skills` plus `~/.agents/skills`, explain each needed change with reasons, stop for explicit user approval, and only then apply changes.
---

# Cross-Agent Skill Audit

Audit skill content against both platforms before editing anything.

## Workflow

1. Read `references/platform-portability.md`.
   - Re-check the linked official docs when platform behavior matters or may have changed.
   - Treat the reference as a summary, not the only source of truth.
2. Run the scanner:

```bash
python3 "$HOME/.agents/skills/cross-agent-skill-audit/scripts/audit_skill_portability.py"
```

Optional flags:

```bash
python3 "$HOME/.agents/skills/cross-agent-skill-audit/scripts/audit_skill_portability.py" --show-portable
python3 "$HOME/.agents/skills/cross-agent-skill-audit/scripts/audit_skill_portability.py" --format json
python3 "$HOME/.agents/skills/cross-agent-skill-audit/scripts/audit_skill_portability.py" --cwd /path/to/repo
```

3. Review the report and classify each flagged skill:
   - `fix-now`: a generally reusable skill has unguarded one-agent assumptions
   - `clarify-intent`: the skill is probably intentionally tied to one agent and should be labeled clearly instead of silently ported
   - `leave-alone`: false positive or acceptable local convention
4. Present a change plan to the user before editing. For every proposed change, include:
   - skill path
   - current one-agent assumption
   - proposed cross-agent change
   - reason tied to the official docs or the local mirror convention
5. Stop and wait for explicit user approval.
6. After approval, edit canonical source skills only:
   - repo: `.agents/skills/...`
   - user: `~/.agents/skills/...`
   - do not edit `.claude/skills/...` mirror entries directly unless the audit shows broken symlinks
7. After edits:
   - rerun the scanner
   - confirm the user-facing report is now clean or intentionally scoped
   - if a user-level skill changed, confirm `~/.claude/skills/<name>` still resolves to `~/.agents/skills/<name>`
   - if a repo skill changed and this repo uses mirrored links, confirm `./.claude/skills/<name>` still resolves to `./.agents/skills/<name>`

## Default Scan Scope

- current repo root `.agents/skills` if present
- current user root `~/.agents/skills`
- mirror health only: `./.claude/skills` and `~/.claude/skills`

## What Counts As A Portability Gap

- hardcoded `~/.claude/skills/...` or `.claude/skills/...` paths in a skill that should also work from Codex
- Claude-only orchestration terms such as `Task`, `TaskOutput`, `TodoWrite`, or `run_in_background` without a Codex note or equivalent
- Codex-only tooling such as `js_repl`, `spawn_agent`, `update_plan`, or `apply_patch` without a Claude note or an explicit Codex-only label
- references to only `CLAUDE.md` or only `AGENTS.md` when the workflow is meant to apply to both platforms
- CLI instructions that assume only `claude ...` or only `codex ...` for a skill that is otherwise presented as general
- missing or broken `.claude/skills` mirror entries in this local setup

## Fix Patterns

- prefer platform-neutral or canonical `.agents/skills` source paths over hardcoded `.claude/skills/...` paths
- prefer bundled relative resources over hardcoded home-directory mirrors when possible
- if behavior truly differs by platform, add explicit `If you are in Codex ...` and `If you are in Claude Code ...` branches
- keep shared frontmatter minimal unless a platform-specific extension is required
- use `agents/openai.yaml` for Codex-specific metadata rather than overloading shared `SKILL.md`
- if a skill really is one-agent-only, say so in the description and in the first paragraph of the body

## Reporting Template

Before editing, present findings like this:

```md
## Proposed Skill Fixes

1. /absolute/path/to/SKILL.md
- Classification: fix-now | clarify-intent | leave-alone
- Current issue: ...
- Proposed change: ...
- Reason: ...
```

Then ask for approval and wait.

## Resources

- `references/platform-portability.md`: official-doc-backed difference summary plus the local skill mirror convention
- `scripts/audit_skill_portability.py`: first-pass scanner for current repo and user skills
