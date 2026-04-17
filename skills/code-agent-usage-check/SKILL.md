---
name: code-agent-usage-check
description: Check the current remaining Claude Code and Codex usage quota on this machine, including both the 5-hour window and the weekly window, plus exact reset times. Use this whenever the user asks how much Claude Code or Codex quota is left, when the 5h or weekly limit resets, whether they are near the current usage limit, or when they explicitly want remaining quota instead of token totals or cost analysis.
---

# Code Agent Usage Check

## Overview

Check the current remaining local usage quota for:

- `Claude Code`
- `Codex`

Return both:

- `5-hour remaining quota`
- `weekly remaining quota`
- `exact reset time` for each window

This skill is for **current remaining quota**, not lifetime token usage, session cost, or historical trend analysis. If the user wants token totals, cost trends, or multi-day usage analysis, use `coding-agent-token-analysis` instead.

## Default Scope

- Default to the **current machine only**.
- Use the currently logged-in local `claude` and `codex` accounts on that machine.
- Do not silently answer from stale memory or from an older session summary if a fresh local check is possible.

If the user explicitly names another host, say that this skill is local by default and then run the same helper on that host only if the user clearly wants a remote check.

## Bundled Helper

Use the bundled script:

- `scripts/check_usage.py`

It performs the live local check and returns structured JSON or a human-readable summary.

## Workflow

1. Verify that `claude` and/or `codex` are installed on the current machine.
2. Run the helper:

```bash
python3 scripts/check_usage.py --json
```

3. Parse the result and answer in concise operator-style prose.
4. If one CLI succeeds and the other fails, report the successful result and clearly call out the failure.
5. If Codex cannot refresh a brand-new quota snapshot during the check, fall back to the most recent stored local Codex rate-limit snapshot and say clearly that it is a fallback snapshot rather than a fresh refresh.
6. Always include:
   - check time
   - `Claude Code` 5-hour remaining percentage and reset time
   - `Claude Code` weekly remaining percentage and reset time
   - `Codex` 5-hour remaining percentage and reset time
   - `Codex` weekly remaining percentage and reset time

## Output Shape

Use this structure:

- `Checked at`: absolute local timestamp
- `Claude Code`:
  - `5h remaining`
  - `5h resets`
  - `weekly remaining`
  - `weekly resets`
- `Codex`:
  - `5h remaining`
  - `5h resets`
  - `weekly remaining`
  - `weekly resets`
- `Notes`: only if there is a caveat or partial failure

## Guardrails

- Do not confuse `remaining quota` with `tokens used in one session`.
- Do not answer with only `used %`; convert it to `remaining %` too.
- Always include absolute reset timestamps, not only relative phrases like `in 3 hours`.
- If the helper had to rely on a local session snapshot for `Codex`, say so briefly and mention whether it was a fresh snapshot or a fallback snapshot.
- If a CLI is missing or not logged in, say that clearly instead of guessing.
- Keep the answer tight; this is an operational check, not a long report.

## Trigger Examples

- `check codex and claude code current remain 5h and weekly quota`
- `how much claude code quota do i still have this week`
- `帮我看下 codex 5 小时和每周额度还剩多少，几点 reset`
- `i don't want token totals, just current remaining quota for codex and claude code`
