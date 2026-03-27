---
name: user-agent-config-sync
description: Synchronize the user-level Codex and Claude config across `local-mac`, `dev-server`, and `openclaw`, using `local-mac` as the default source, with mandatory backups before any write and an explicit user approval checkpoint after review. Use this whenever the user asks to keep these machines' agent config aligned, sync `codex`/`claude` settings, mirror TUI or feature settings, or says things like "同步 agent 配置", "sync codex config", "keep Claude settings consistent", or "先看 diff 再同步". This skill intentionally excludes skills and MCP config.
---

# User Agent Config Sync

Use this skill from `local-mac` unless the user explicitly wants a single-host manual check.

The purpose is narrow: keep the user-level Codex and Claude config on `local`, `dev-server`, and `openclaw` consistent for the managed subset, while leaving skill installation and MCP wiring alone.

## Device Map

- `local`: current machine
- `dev-server`: `hardfun@192.168.238.203`
- `openclaw`: `yutianqiuhao@192.168.238.15`

## Managed Scope

The helper script syncs only the stable config subset that should match across the two Linux hosts.

### Codex

Managed file: `~/.codex/config.toml`

Managed sections:
- top-level scalar keys such as `approval_policy`, `sandbox_mode`, `model`, `service_tier`, `personality`
- `[features]`
- `[tui]`
- `[notice]`

Excluded sections:
- `[projects]`
- `[mcp_servers]`
- `[[skills.config]]`
- auth, history, logs, caches, session state

### Claude

Managed file: `~/.claude/settings.json`

Managed keys:
- `$schema`
- `env`
- `statusLine`
- `enabledPlugins`
- `alwaysThinkingEnabled`
- `effortLevel`
- `skipDangerousModePermissionPrompt`
- `preferredNotifChannel`

Excluded keys and files:
- `mcpServers`
- `feedbackSurveyState`
- `settings.local.json`
- `.claude.json`
- history, telemetry, todos, debug files

### Auxiliary Files

If the managed Claude `statusLine.command` references a script inside `~/.claude/`, sync that script too. Rewrite the source home prefix to the target home prefix so `dev-server` paths do not leak into `openclaw`.

## Defaults

- Default source: `local`
- Default targets: `dev-server`, `openclaw`

`local` is the canonical source by default. If the source itself needs managed normalization, review it first and then apply it together with the target sync after the user approves.

## Guardrails

- Always run a dry-run audit before applying changes.
- Always review all three machines before applying changes.
- Always back up the target before writing.
- Always summarize what will change after sync and wait for explicit user approval before `--apply`.
- Do not sync in reverse unless the user explicitly says so.
- Do not touch `~/.agents/skills`, `~/.claude/skills`, or `~/.codex/skills`.
- Do not touch MCP config.
- Preserve target-only host state outside the managed subset.
- Report the backup directory after apply.

## Workflow

1. Review the three-machine managed diff and the post-sync plan.

```bash
python3 ~/.agents/skills/user-agent-config-sync/scripts/user_agent_config_sync.py review \
  --source local \
  --targets dev-server openclaw
```

2. Present the review summary to the user and wait for explicit approval.

The review must cover:
- source normalization changes on `local`, if any
- target changes for `dev-server`
- target changes for `openclaw`
- which files will be backed up and overwritten

3. If approved, sync with backup.

```bash
python3 ~/.agents/skills/user-agent-config-sync/scripts/user_agent_config_sync.py sync \
  --source local \
  --targets dev-server openclaw \
  --apply
```

4. Re-audit and confirm the managed diff is gone.

```bash
python3 ~/.agents/skills/user-agent-config-sync/scripts/user_agent_config_sync.py review \
  --source local \
  --targets dev-server openclaw
```

## Commands

- `status [--source ...] [--target ...]`
  Show the managed subset diff for Codex and Claude without writing anything.
- `review [--source ...] [--targets ...]`
  Show source normalization drift plus target diffs for all selected machines, and print the planned file updates that would happen after approval.
- `sync [--source ...] [--target ...] [--apply]`
  Back up each changed machine, sync the managed subset, and print the backup path. Without `--apply`, this stays a dry run.

## Notes

- This skill is intentionally narrower than `user-skill-sync`.
- If the user wants skills or Claude skill symlinks repaired, switch to `user-skill-sync`.
- If the user wants MCP parity too, handle that separately instead of silently widening scope.
- This skill may report a source-side normalization step before syncing targets. That is expected when the source itself is missing part of the managed subset.
