# Cross-Agent Skill Portability Reference

Use this reference as a baseline, then re-check the linked official docs when platform behavior matters or may have changed.

## Official Sources

- Codex Agent Skills: `https://developers.openai.com/codex/skills/`
- Codex Customization / Skills: `https://developers.openai.com/codex/concepts/customization/#skills`
- Codex config reference: `https://developers.openai.com/codex/config-reference/`
- Claude Code skills: `https://code.claude.com/docs/en/slash-commands`
- Claude Code settings: `https://code.claude.com/docs/en/settings`
- Claude Code subagents: `https://code.claude.com/docs/en/sub-agents`

## Shared Baseline

Both platforms describe skills as an Agent Skills standard concept:

- a directory rooted by `SKILL.md`
- a `name` plus `description` frontmatter pair as the safe common baseline
- optional supporting files such as `scripts/`, `references/`, and other bundled resources
- skill descriptions determine whether the agent loads the skill automatically

For cross-platform work, prefer this shared baseline first and treat platform-specific extensions as optional branches.

## Key Differences

| Concern | Codex | Claude Code | Portability Guidance |
| --- | --- | --- | --- |
| User skill root | `$HOME/.agents/skills` | `~/.claude/skills/<skill>/SKILL.md` | In this environment, keep canonical sources in `.agents/skills` and expose them to Claude through symlinks. |
| Repo skill root | `.agents/skills` | `.claude/skills/<skill>/SKILL.md` | Scan `.agents/skills` as the source of truth here; use `.claude/skills` only as a mirror check. |
| Explicit invocation | `$skill-name` or skill picker | `/skill-name` | Mention both when writing user-facing examples for a dual-agent skill. |
| Instruction files | `AGENTS.md` | `CLAUDE.md` | A dual-agent skill should not assume only one of these exists. |
| Codex metadata | `agents/openai.yaml` | none | Safe to include for Codex; Claude ignores it. |
| Claude skill extensions | not documented as shared Codex behavior | `disable-model-invocation`, `allowed-tools`, `context: fork`, `agent`, `hooks` | If a skill depends on these, add a Codex fallback or label it Claude-specific. |
| Subagents | built-in multi-agent tools and `agents.*` config in `~/.codex/config.toml` | `.claude/agents/`, `/agents`, skill frontmatter like `context: fork` and `agent` | Do not write one platform's subagent terms as if they are universal. |
| Tool naming in skills | native Codex tool names and workflow terms | Claude tool names such as `Task`, `TodoWrite`, `Skill`, `TaskOutput` | Add explicit mapping or separate branches when a skill is meant for both. |

## Official Facts Worth Remembering

Codex:

- Codex scans repo `.agents/skills` and user `$HOME/.agents/skills`.
- Codex supports `agents/openai.yaml` for UI metadata and invocation policy.
- Codex skills can be explicit or implicit, with triggering driven by `description`.
- Codex uses `AGENTS.md` as the main project instruction file.

Claude Code:

- Claude Code stores personal skills in `~/.claude/skills` and project skills in `.claude/skills`.
- Claude Code says custom commands have been merged into skills.
- Claude Code extends the shared skill standard with frontmatter like `disable-model-invocation`, `allowed-tools`, `context: fork`, and `agent`.
- Claude Code uses `CLAUDE.md` for startup instructions and `.claude/agents/` for custom subagents.

## Local Convention In This Environment

This machine keeps canonical skill source files in `.agents/skills`:

- user source: `~/.agents/skills`
- user Claude mirror: `~/.claude/skills` symlinks
- repo source: `./.agents/skills`
- repo Claude mirror: `./.claude/skills` symlinks

When auditing or editing:

- edit the canonical `.agents/skills` source first
- treat `.claude/skills` as exposure mirrors for Claude Code
- fix mirrors only when they are missing, broken, or no longer point at the canonical source

## Common Fix Guidance

- Replace hardcoded `.claude/skills/...` script paths with canonical `.agents/skills/...` paths or bundled relative paths.
- If a skill uses Claude-only frontmatter or tool names, either add a Codex branch or mark the skill as Claude-specific.
- If a skill uses Codex-only features like `js_repl`, either add a Claude fallback or mark it as Codex-specific.
- If a skill references `CLAUDE.md` only, add `AGENTS.md` guidance when the workflow is supposed to be shared.
- If a skill references `AGENTS.md` only, add `CLAUDE.md` guidance when the workflow is supposed to be shared.
- If a skill is intentionally agent-specific, prefer clearer scoping language over forced portability.
