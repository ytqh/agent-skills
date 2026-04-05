# Diagnosis: bounce-daily-strategy-performance Cron Failure (2026-04-05)

## Summary

The `bounce-daily-strategy-performance` cron job (id `95cc2cfd`) failed after ~50 seconds due to an **exec allowlist miss** on the OpenClaw gateway. The agent was unable to execute any SSH commands to dev-server, causing it to exhaust its retry attempts and give up without producing analysis output.

## Timeline (from session transcript)

| Time (UTC) | Event |
|---|---|
| 08:00:09 | Session started. Model: `gpt-5.4-mini` via `openai-codex` provider. CWD: `/home/yutianqiuhao/.openclaw/workspaces/bounce` |
| 08:00:18 | Agent reads `using-superpowers` skill, then begins Step 1 (repo sync via SSH) |
| 08:00:23 | **First exec attempt** — `host: "auto"`, `security: "allowlist"` — rejected: `exec host not allowed (requested auto; configure tools.exec.host=gateway to allow)` |
| 08:00:28 | **Second exec attempt** — `host: "gateway"`, `security: "allowlist"` — rejected: `exec denied: allowlist miss` |
| 08:00:36 | **Third exec attempt** — `host: "node"`, `security: "full"` — rejected: `exec host not allowed (requested node; configure tools.exec.host=gateway to allow)` |
| 08:00:42 | **Fourth exec attempt** — minimal `ssh dev-server 'echo ok'` test — rejected: `exec denied: allowlist miss` |
| 08:00:48 | Agent gives up, returns explanation that SSH is blocked by the exec allowlist |

Total wall time: ~39 seconds of active processing + overhead = ~50 seconds total.

## Root Cause

The `ssh` binary (or the specific `ssh dev-server ...` command pattern) is **not included in the OpenClaw exec allowlist** for the `bounce` agent.

Per the workspace docs, the exec allowlist has 14 entries covering `git`, `codex`, `tmux`, and project directories. The `ssh` binary is not among them.

This is a configuration gap: the cron job's execution flow explicitly requires SSH to dev-server (to sync the repo, create a tmux session, launch Claude Code, poll output, and clean up), but the exec security policy blocks SSH commands because `ssh` is not on the allowlist.

### Why this may have worked before

The cron job definition references it was migrated from an older ACP/Codex-based approach ("Replaces: `Daily strategy performance analysis` (deleted, was ACP/Codex based)"). The new tmux-based approach was registered with the cron prompt explicitly calling `ssh dev-server ...`, but the exec allowlist was likely not updated to include `ssh` when the cron was migrated. Possible scenarios:

1. The allowlist was recently tightened or recreated without including `ssh`.
2. The cron was created/modified after the allowlist was last updated.
3. A prior OpenClaw version or configuration may have had different exec security defaults (e.g., `security=full` bypassing the allowlist), and an upgrade or config change now enforces the allowlist strictly.

### Key evidence

The agent tried multiple `host` values (`auto`, `gateway`, `node`) and `security` levels (`allowlist`, `full`). The gateway consistently enforced the allowlist regardless of the `security` parameter requested by the agent. This means the gateway-level allowlist is authoritative and cannot be overridden per-call.

## Impact

- No strategy performance analysis was delivered to Discord thread `1482646294244888637` on 2026-04-05.
- The same failure likely affects **all bounce cron jobs that use SSH to dev-server**, including:
  - `bounce-core-workflow-health-check` (id `26724657`)
  - `bounce-daily-account-balance-claim` (id `18ac6f28`)
  - `jim-qingsu-chat-cert-renew` (id `212b620c`)
- Cost was minimal (~$0.013 total across 4 LLM calls).

## Recommended Fix

### Immediate: Add `ssh` to the exec allowlist

SSH into the OpenClaw host and add the `ssh` binary to the exec allowlist:

```bash
ssh yutianqiuhao@192.168.238.15
# Then add ssh to the allowlist. The exact command depends on OpenClaw's
# allowlist management interface. Check:
openclaw exec-approvals list
openclaw exec-approvals add --binary /usr/bin/ssh
# Or if it uses pattern-based allowlisting:
openclaw exec-approvals add --pattern "ssh dev-server *"
```

Consult `openclaw exec-approvals --help` on the host for exact syntax.

### Verification after fix

1. Run `openclaw cron run 95cc2cfd` to trigger a manual test execution.
2. Confirm the session transcript shows successful SSH and tmux operations.
3. Confirm the analysis report is delivered to the Discord thread.

### Also check the other SSH-dependent cron jobs

After adding `ssh` to the allowlist, verify these jobs as well:
- `openclaw cron runs 26724657` (health check) -- check if recent runs also failed
- `openclaw cron runs 18ac6f28` (balance/claim) -- check if recent runs also failed
- `openclaw cron runs 212b620c` (jim cert renewal) -- runs monthly, check last run

### Preventive measure

When registering or migrating cron jobs that use `ssh`, always cross-check the exec allowlist to confirm the required binaries are permitted. Consider documenting the required allowlist entries alongside each cron job definition in the OpenClaw AGENTS.md.
