## Cron Health Care Report: bounce-core-workflow-health-check

### Classification: Business Failure

The cron execution infrastructure is working correctly. The inner health check task ran to
completion and produced substantive results. The system it monitors (Bounce core workflow)
is reporting real issues.

---

### Execution Diagnosis

- **Pattern**: N/A -- no execution failure patterns detected
- **Evidence**:
  - All 11 exec calls used default `host` and `security` parameters (no E1/E2 issues)
  - Both process poll calls used appropriate timeouts: 180,000ms and 60,000ms (no E3 short-polling issue)
  - Session duration: ~4m54s (06:27:45 to 06:32:39 UTC) -- within expected 3-10 min range
  - The outer agent (gpt-5.4-mini on OpenClaw) correctly orchestrated the full tmux-based inner session lifecycle:
    1. `git fetch && checkout master` on dev-server
    2. Created tmux session `cron-bounce-health`
    3. Launched `claude --dangerously-skip-permissions` inside tmux
    4. Sent the `/core-workflow-health-check` prompt
    5. Waited 180s via `sleep 180` with proper blocking (`timeout: 220`, not fire-and-forget)
    6. Captured tmux pane output; saw inner Claude was still working
    7. Waited another 60s, then captured again
    8. Extracted the JSON health artifact via `python3` on dev-server
    9. Extracted per-check failure details
    10. Killed the tmux session cleanly
  - Inner session: Claude Code v2.1.92, Opus 4.6 (1M context), ran `/core-workflow-health-check` skill
  - The "exec errors" flagged by the parser are false positives -- they are tmux capture-pane output containing the word "error" in Claude's idle prompt, not actual tool errors
- **Root Cause**: No execution failure. The cron orchestration is healthy.
- **Fix Applied**: None needed
- **Verification**: Session completed successfully with full health check artifact captured

---

### Business Diagnosis

- **Status**: UNHEALTHY
- **Overall verdict**: `healthy: false` (24-hour lookback window, generated 2026-04-05T06:29:12 UTC)

#### High Severity Issues

1. **Duplicate schedules** (`duplicate_any_schedules` check FAILED, 25 rows)
   - Multiple event/strategy pairs have extreme run duplication:
     - `event_id=322957` / `cbb_total_mean_reversion`: **220 scheduled runs**
     - `event_id=323402` / `cbb_total_mean_reversion`: **188 scheduled runs**
     - `event_id=338662` / `cbb_total_mean_reversion`: **140 scheduled runs**
     - `event_id=344650` / `cbb_total_mean_reversion`: **83 scheduled runs**
     - `event_id=338390` / `cbb_spread_mean_reversion`: **78 scheduled runs**
   - This is a scheduler bug -- events are being scheduled far more times than intended, wasting compute and potentially placing duplicate bets.

2. **Strategy coverage mismatch** (CBB subcategory)
   - `event_id=338390` and `event_id=344650` only have 2 of 4 expected strategies scheduled
   - Missing strategies: likely `cbb_spread_underdog` and `cbb_total_underdog` (only `mean_reversion` variants present)

#### Medium Severity Issues

3. **Late triggers** (delays ~295-296 minutes, far above 15-minute threshold)
   - Affects multiple strategies: `cbb_spread_underdog`, `nba_ml_underdog`, `conversational_v2`, `thesis_pick`
   - Affected events: 322957, 323402, 321672, 338662, 334884, 321665, 321670
   - Nearly 5 hours late -- suggests the Temporal trigger mechanism stalled or was backed up

4. **Missing betting run links** on completed Temporal runs
   - All 10+ reported cases are on `event_id=344650`
   - `betting_run_id=None` indicates the workflow completed but never linked to a betting execution
   - Could mean bets were never placed for these runs, or the linkage step failed silently

#### Low Severity / Informational

5. **Prediction coverage gaps**
   - `total=2165`, `missing_trace_id=1924` (89% missing Langfuse trace IDs)
   - `empty_predictions=2094` (97% of predictions are empty)
   - No errors (`errored=0`), so predictions are completing but not producing output

6. **Subsystem status**
   - Temporal logs: healthy
   - Railway production logs: healthy
   - Metabase: unhealthy (likely reflecting the duplicate schedule data)
   - Langfuse: check was still running when session was captured (incomplete)

#### Action Required

These are application-level issues, not cron infrastructure problems:

| Priority | Issue | Recommended Action |
|----------|-------|--------------------|
| P0 | Duplicate schedules (220x for single event) | Investigate scheduler dedup logic; likely a retry loop or missing idempotency guard |
| P1 | Late triggers (~295min delay) | Check Temporal worker backlog and task queue health |
| P1 | Missing betting_run_id on event 344650 | Trace the workflow for this event to find where bet linkage breaks |
| P2 | Strategy coverage gaps (2/4 strategies) | Verify strategy registration for CBB subcategory |
| P2 | 97% empty predictions | Check if prediction models are returning empty or if there is a data pipeline issue upstream |

---

### Session Metadata

| Field | Value |
|-------|-------|
| Session ID | `7bac327f-4677-4ee9-ae28-415dc0a13832` |
| Outer model | openai-codex / gpt-5.4-mini |
| Inner model | Claude Code v2.1.92, Opus 4.6 (1M context) |
| Start | 2026-04-05T06:27:45 UTC |
| End | 2026-04-05T06:32:39 UTC |
| Duration | ~4m54s |
| CWD | /home/yutianqiuhao/.openclaw/workspaces/bounce |
| Exec calls | 11 (all clean, no suspicious params) |
| Process polls | 2 (timeouts: 180s, 60s -- appropriate) |
| Diagnosis hints | None (no execution failure patterns) |
