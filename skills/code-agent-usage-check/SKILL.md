---
name: code-agent-usage-check
description: Check the current remaining Claude Code and Codex usage quota across the operator's machines (local-mac and dev-server by default), including the 5-hour and weekly windows, account identity on each host, and exact reset times. Use this whenever the user asks how much Claude Code or Codex quota is left, when the 5h or weekly limit resets, which account is logged in where, whether they are near the current usage limit, or when they explicitly want remaining quota instead of token totals or cost analysis.
---

# Code Agent Usage Check

## Overview

Check the current remaining usage quota for:

- `Claude Code`
- `Codex`

Return, for each host:

- `account identity` (email, plan, org) parsed from the host's local auth files
- `5-hour remaining quota`
- `weekly remaining quota`
- `exact reset time` for each window
- `pace-based forecast` for whether current usage will exhaust the window before reset
- `estimated remaining percentage at reset` if the current usage speed continues

This skill is for **current remaining quota**, not lifetime token usage, session cost, or historical trend analysis. If the user wants token totals, cost trends, or multi-day usage analysis, use `coding-agent-token-analysis` instead.

## Default Scope

- Default to **both `local-mac` and `dev-server`**. Each host can be logged into a different Claude Code or Codex account, so always show the account identity alongside the quota numbers.
- Do not silently answer from stale memory or from an older session summary if a fresh local check is possible.
- Opt out to local-only with `--local` (or by passing `--hosts local`) when the user asks for "just this machine".
- If the user names another host, pass it in `--hosts` (e.g. `--hosts local,autonomous-agent-device`). The remote host must have this same skill synced under `~/.agents/skills/` (via `user-skill-sync`).

## Bundled Helper

Use the bundled script:

- `scripts/check_usage.py`

It performs the check against one or more hosts. For remote tokens it SSHes to that host and re-invokes itself with `--hosts local`, then merges the JSON back into a single multi-host result. Each host keeps its own per-machine pace-history cache at `~/.cache/code-agent-usage-check/history.jsonl`, so recent-history projections stay accurate even when accounts differ across machines.

### CLI

- `--hosts LIST` — comma-separated. `local` means this machine; any other token is an SSH target. Default: `local,dev-server`.
- `--local` — shortcut for `--hosts local`.
- `--ssh-timeout SECONDS` — per-host SSH timeout. Default `45`.
- `--json` — machine-readable JSON.

## Workflow

1. Verify that `claude` and/or `codex` are installed on the current machine (the helper does this).
2. Run the helper (default hosts):

```bash
python3 scripts/check_usage.py --json
```

Or for a single host:

```bash
python3 scripts/check_usage.py --local --json
```

3. Parse the result and answer in concise operator-style prose, grouped by host.
4. If one host succeeds and another fails (SSH timeout, remote script missing, etc.), report the successful host and clearly call out the failed host.
5. If a CLI on one host succeeds and the other CLI on the same host fails, report the successful one and note the failure.
6. If Codex cannot refresh a brand-new quota snapshot during the check, the helper falls back to the most recent stored local Codex rate-limit snapshot — say clearly that it is a fallback snapshot rather than a fresh refresh.
7. Always include per host:
   - host label and account identity (email/plan)
   - `Claude Code` 5-hour remaining percentage and reset time
   - `Claude Code` weekly remaining percentage and reset time
   - `Claude Code` projected remaining at 5-hour reset and whether the 5-hour limit is likely to be hit
   - `Claude Code` projected remaining at weekly reset and whether the weekly limit is likely to be hit
   - `Codex` 5-hour remaining percentage and reset time
   - `Codex` weekly remaining percentage and reset time
   - `Codex` projected remaining at 5-hour reset and whether the 5-hour limit is likely to be hit
   - `Codex` projected remaining at weekly reset and whether the weekly limit is likely to be hit

## Output Shape

Top-level JSON:

```jsonc
{
  "checked_at_local": "…",
  "hosts": {
    "local-mac":   { "status": "ok", "hostname": "local-mac",   "claude": {…}, "codex": {…} },
    "dev-server":  { "status": "ok", "hostname": "dev-server",  "claude": {…}, "codex": {…}, "ssh_target": "dev-server", "ssh_elapsed_seconds": 8.12 }
  }
}
```

Each agent block (`claude` or `codex`) carries:

- `account` — `{email, display_name?, organization?, billing_type?, chatgpt_plan_type?}`
- `five_hour` — `{used_percent, remaining_percent_display, resets_at_local, projection}`
- `weekly` — same shape as `five_hour`
- Codex-only: `freshness` (`fresh` / `fallback`), `snapshot_age_seconds`, `plan_type`

## Guardrails

- Do not confuse `remaining quota` with `tokens used in one session`.
- Do not answer with only `used %`; convert it to `remaining %` too.
- Always include absolute reset timestamps, not only relative phrases like `in 3 hours`.
- Always name the account on each host. The operator specifically cares about "which account is logged in where" — don't assume both machines share the same email.
- For pace-based forecasts, prefer recent local history deltas when available; if not, say the estimate is based on current-window average pace.
- If the helper had to rely on a local session snapshot for `Codex`, say so briefly and mention whether it was a fresh snapshot or a fallback snapshot.
- If a CLI is missing or not logged in, say that clearly instead of guessing.
- If a remote host errors (SSH timeout, missing script, etc.), surface the failure but still report the hosts that succeeded.
- Keep the answer tight; this is an operational check, not a long report.

## Trigger Examples

- `check codex and claude code current remain 5h and weekly quota`
- `how much claude code quota do i still have this week`
- `帮我看下 codex 5 小时和每周额度还剩多少，几点 reset`
- `i don't want token totals, just current remaining quota for codex and claude code`
- `which account is logged in on dev-server? and how much quota is left there?`
- `just this machine` / `only local` — invoke with `--local`.
