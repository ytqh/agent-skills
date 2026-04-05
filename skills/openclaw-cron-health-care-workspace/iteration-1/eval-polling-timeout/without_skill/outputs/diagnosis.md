# Diagnosis: bounce-daily-strategy-performance Cron Failure

**Session ID:** `4818cc71-ccd8-4bc4-8004-3cd6afb77feb`
**Cron job:** `bounce-daily-strategy-performance` (id `95cc2cfd-ecd5-45fa-85f6-5e65e0114098`)
**Executing agent model:** gpt-5.4-mini (via openai-codex provider)
**Wall-clock duration:** 122 seconds (~2 minutes)
**Outcome:** No useful output. The agent reported the analysis was "still running" and killed the tmux session prematurely.

---

## Root Cause: `yieldMs` Defeated All Sleep/Wait Commands

The cron prompt instructs the outer agent to:
1. Launch Claude Code inside a tmux session on dev-server
2. Send the `/performance-analysis` task
3. **Wait 300 seconds (5 minutes)** before first poll
4. Poll every 60 seconds, at least 5 times
5. Capture the final report

The outer agent (gpt-5.4-mini) correctly understood these steps and attempted to follow them. However, every `exec` call used **`yieldMs: 1000`**, which tells the OpenClaw exec tool to return control to the caller after 1 second regardless of whether the command has finished. The exec tool then returns `"Command still running (session <name>, pid <N>)"` and the agent must use the `process` tool to poll for completion.

**The agent never waited for its own sleep commands to finish.** Here is the critical sequence:

| Wall time | Action | Expected wait | Actual wait |
|-----------|--------|---------------|-------------|
| T+37.6s | `exec: sleep 300` (yieldMs=1000) | 300s | ~1s yield, then abandoned |
| T+43.4s | `process: poll swift-lagoon` | Should block until sleep done | Returns "still running" immediately |
| T+49.6s | `exec: capture-pane` | Should not happen yet | Agent proceeds anyway |
| T+58.1s | `exec: sleep 60; capture-pane` (yieldMs=1000) | 60s | ~1s yield, then abandoned |
| T+62.3s | `process: poll quick-shell` | Should block until done | Returns "still running" immediately |
| T+73.2s | `exec: sleep 60; capture-pane` (yieldMs=1000) | 60s | ~1s yield, then abandoned |
| ... | (pattern repeats 4 times) | | |

Every `exec` call yields after 1 second. The agent polls once, sees "still running", and then **issues the next command instead of continuing to poll until the sleep completes**. The result is that:

- The mandatory 300-second wait consumed ~12 seconds of wall time
- Each 60-second polling interval consumed ~8-10 seconds of wall time
- The entire "5-minute wait + 5 polls at 60s intervals" sequence that should have taken ~10 minutes finished in under 80 seconds

## What the Agent Captured

The two meaningful tmux captures show:

1. **First capture (T+54s, ~16s after task was sent):** Claude Code had just received the prompt and was showing "Embellishing..." -- it had not even started executing the skill yet.

2. **Final capture (T+107s, ~69s after task was sent):** Claude Code had loaded the `performance-analysis` skill, spawned parallel sub-tasks (Metabase queries, schema checks, analysis script), and had `run_performance_analysis.py` in "Waiting..." state. It was 53 seconds into execution with "Embellishing..." active. The analysis was nowhere near complete.

The agent then killed the tmux session and reported "the session had not reached a completed report."

## Contributing Factors

1. **Model choice (gpt-5.4-mini with minimal thinking):** The agent's thinking blocks show it understood the need to wait, but it did not reason about the yieldMs/process-poll loop correctly. It issued `sleep 300` with `yieldMs: 1000` and then only polled the background process once before moving on. A model with deeper reasoning might have recognized the need to poll the sleep process repeatedly until it exited.

2. **No process-poll retry loop:** The exec/process two-phase pattern requires the agent to call `process(action=poll)` in a loop until the process exits. The agent polled each background process exactly once, saw "still running", and then moved on to the next step. This is a fundamental misuse of the async exec pattern.

3. **Prompt gap:** The cron prompt describes sleep/poll steps in terms of direct SSH commands (`sleep 300`, poll every 60 seconds) but does not account for the fact that the OpenClaw exec tool is async with `yieldMs`. The prompt assumes blocking execution semantics that the tool does not provide.

## Timeline Summary

```
T+0s      Session start
T+9s      Step 1: git sync (OK)
T+17s     Step 2: tmux session created (OK)
T+24s     Step 3: Claude Code launched in tmux (OK)
T+33s     Step 4: Task prompt sent with 15s pre-delay (OK, but yieldMs=1000)
T+38s     Step 5: sleep 300 issued (BROKEN - yields after 1s, never re-polled)
T+50s     Step 6: First poll attempt (only ~12s after task sent, way too early)
T+58-97s  Steps 6 cont: 4x "sleep 60; capture-pane" (all broken - yield after 1s each)
T+103s    Step 7: Final capture (analysis barely started, ~69s in)
T+110s    Step 8: tmux killed
T+122s    Step 9: Agent admits no report captured
```

## Recommended Fixes

1. **Fix the polling loop in the cron prompt:** Replace "sleep N" steps with explicit instructions: "After issuing `exec sleep 300`, you MUST call `process(action=poll, sessionId=<id>, timeout=310000)` with a timeout long enough for the sleep to complete. Do NOT proceed until the process exits."

2. **Use `yieldMs: 0` or a high value for blocking waits:** When the intent is to block, set `yieldMs` equal to the expected command duration (e.g., `yieldMs: 300000` for a 300-second sleep) so the exec tool blocks synchronously.

3. **Add an explicit completion-detection instruction:** "After each `process poll` that returns 'still running', you MUST call `process poll` again. Only proceed to the next step when the process reports exit."

4. **Consider a single blocking exec for the wait:** Instead of `exec: sleep 300` followed by separate captures, use a single command like: `exec: sleep 300 && ssh dev-server "tmux capture-pane ..."` with `yieldMs: 0` and a long timeout. This avoids the async polling problem entirely.

5. **Increase the cron timeout:** The job ran for 132 seconds but needed at minimum 10+ minutes. Even if the polling were fixed, the cron job timeout must accommodate the full analysis time (suggest 900s).
