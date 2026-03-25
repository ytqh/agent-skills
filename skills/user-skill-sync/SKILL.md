---
name: user-skill-sync
description: Audit and synchronize the user-level skills repo at ~/.agents/skills across local-mac, dev-server, and openclaw, then repair per-skill symlinks inside ~/.claude/skills so user skills only resolve back to ~/.agents/skills. Use when Codex needs to inspect git sync status, commit and push or pull the shared skills repo, or fix missing or wrong ~/.claude/skills links on those three machines.
---

# User Skill Sync

Use this skill from `local-mac` unless the user explicitly wants a single-host check. The shared source of user-level skills is `~/.agents/skills` on each machine. `~/.claude/skills` stays as a directory of per-skill symlinks; do not replace it with a top-level symlink.

## Device Map

- `local`: current machine
- `dev-server`: `hardfun@192.168.238.203`
- `openclaw`: `yutianqiuhao@192.168.238.15`

## Guardrails

- Start with `python3 ~/.agents/skills/user-skill-sync/scripts/user_skill_sync.py status --fetch`.
- Treat multiple dirty devices or multiple incompatible git heads as divergence. Report the exact hosts and stop instead of guessing.
- Only auto-commit when exactly one device is the source and the user intent clearly allows a commit. Pass an explicit commit message.
- Use `git pull --ff-only`. Do not create merge commits, rewrite history, or reset other hosts.
- Repair only user-level entries backed by `~/.agents/skills/*`.
- Leave project-local links in `~/.claude/skills` alone if they point somewhere else.
- If a managed entry in `~/.claude/skills` is a real directory or file, back it up before replacing it with a symlink.

## Workflow

1. Audit all three hosts.

```bash
python3 ~/.agents/skills/user-skill-sync/scripts/user_skill_sync.py status --fetch
```

2. Pick the source with the safe reconcile policy.

- If exactly one device is dirty, that device is the source candidate.
- If no device is dirty and exactly one device is ahead of `origin` without being behind, that device is the source candidate.
- Otherwise stop and show the divergence.

3. Sync git state.

If the source has uncommitted changes:

```bash
python3 ~/.agents/skills/user-skill-sync/scripts/user_skill_sync.py sync \
  --source <local|dev-server|openclaw> \
  --commit-message "describe the skill sync" \
  --apply
```

If the source is already committed and only needs push and pull:

```bash
python3 ~/.agents/skills/user-skill-sync/scripts/user_skill_sync.py sync \
  --source <local|dev-server|openclaw> \
  --apply
```

4. Repair links without touching project-local skills.

```bash
python3 ~/.agents/skills/user-skill-sync/scripts/user_skill_sync.py repair-links --apply
```

Use `--prune-user-extras` only when stale links that still point inside `~/.agents/skills` should be removed from `~/.claude/skills`.

5. Re-audit and confirm the result.

```bash
python3 ~/.agents/skills/user-skill-sync/scripts/user_skill_sync.py status
```

## Commands

- `status [--fetch] [--devices ...]`
  Collect git state and per-skill link audit on the selected devices.
- `sync [--source ...] [--commit-message ...] [--devices ...] [--apply]`
  Choose or use a source device, optionally commit it, push it, pull the other selected devices with fast-forward only, and repair managed links.
- `repair-links [--devices ...] [--prune-user-extras] [--apply]`
  Repair only user-level symlinks in `~/.claude/skills`.

## Current Notes

- Observation captured on `2026-03-25`: all three machines use per-skill symlinks inside `~/.claude/skills`.
- Observation captured on `2026-03-25`: `local` and `dev-server` are currently dirty, so the safe reconcile policy should report divergence instead of auto-syncing.
