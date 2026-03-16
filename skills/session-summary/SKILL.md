---
name: session-summary
description: >
  Summarize Claude Code and Codex sessions from a time window into a structured markdown report
  with work stream analysis, failure pattern detection, and key commit tracking. Use when the user
  asks to "summarize sessions", "what happened today/yesterday/this week", "session report",
  "daily summary of agent work", "review what agents did", or wants to understand what coding
  sessions accomplished and what failed. Also triggers on requests like "recap my sessions",
  "session digest", or "highlight failed patterns".
metadata:
  version: "1.0.0"
  depends_on: ["recall"]
---

# Session Summary — Multi-Session Digest with Failure Analysis

Generate a structured markdown report summarizing all Claude Code and Codex sessions within a
time window. The report covers work streams, success/failure status, failure pattern analysis,
and key outputs (commits, PRs, deployments).

## When to Use

- User asks for a summary/recap of recent agent sessions
- User wants to understand what happened in the last N hours/days
- User wants to identify failure patterns across sessions
- User asks "what did we get done today" or similar

## Workflow

### Step 1: Discover Session Files

FTS5 does not support bare `*` wildcard queries, so use filesystem discovery instead of the
recall search script.

```bash
# Claude Code sessions (skip /subagents/ paths)
find ~/.claude/projects/ -name "*.jsonl" -mmin -$MINUTES 2>/dev/null | grep -v '/subagents/'

# Codex sessions
find ~/.codex/sessions/ -name "*.jsonl" -mmin -$MINUTES 2>/dev/null
```

Convert the user's time window to minutes:
- "today" / "last day" → 1440 (or use -mtime -1)
- "this week" → 10080
- "last N hours" → N * 60

### Step 2: Read Sessions in Parallel

Use the `read_session.py` script from the recall skill to read each session:

```bash
python3 ~/.claude/skills/recall/scripts/read_session.py <session-file-path>
```

Spawn **two parallel subagents** — one for Claude sessions, one for Codex sessions — to process
all files concurrently. Each subagent should:

1. Read each session file using `read_session.py`
2. For very large sessions, read just the first 200 and last 100 lines to get the gist
3. Skip subagent session files (those under `/subagents/` directories)
4. Extract per-session:
   - **session_id**: from filename
   - **project**: which project/worktree
   - **timestamp**: when it ran
   - **summary**: 1-2 sentence description of what was done
   - **status**: success / failed / partial / abandoned / minimal
   - **failure_pattern**: if failed, what went wrong (tool errors, permission denied, loops, timeouts, etc.)
   - **topics**: key tags/keywords

Classification guide for status:
- `success`: completed its intended task
- `failed`: encountered errors that prevented completion
- `partial`: started meaningful work but didn't finish
- `abandoned`: user interrupted before significant progress, or session was a restart
- `minimal`: probe sessions, empty sessions, single-line exchanges

### Step 3: Compile the Report

Write a markdown report to `/tmp/session-summary-<DATE>.md` with these sections:

#### 3a. Overview Table

| Source | Total | Success | Partial | Failed | Abandoned/Minimal |
|--------|-------|---------|---------|--------|-------------------|

#### 3b. Work Streams

Group related sessions into logical work streams (by issue/PR number, feature area, or
operational task). For each stream:
- What was the goal
- How many sessions contributed
- Key outcomes (commits, decisions, artifacts)
- Any failures within the stream

#### 3c. Failed Patterns (highlighted)

This is the most valuable section. For each distinct failure pattern:
- **Pattern name**: descriptive label
- **Affected sessions**: list with IDs
- **Impact**: how many sessions affected
- **Root cause**: what went wrong
- **Fix needed**: actionable recommendation

If multiple failures trace to a common root cause, draw that connection explicitly.
Include an ASCII diagram showing the failure dependency tree if patterns are related.

#### 3d. Probe/Minimal Sessions

Count and characterize throwaway sessions (probes, empty, single-line). High probe counts
indicate infrastructure overhead worth investigating.

#### 3e. Key Outputs

Table of commits, PRs, deployments, or other concrete artifacts produced.

| Commit | Issue | Description |
|--------|-------|-------------|

### Step 4: Present to User

After writing the file, tell the user:
1. Where the report is saved
2. Quick stat summary (X sessions, Y succeeded, Z failed)
3. The dominant work stream
4. The key failure pattern headline

## Tips

- Sessions from the same issue/PR number are almost always part of the same work stream
- Adversarial review sessions come in clusters (controller + multiple reviewer lenses)
- Probe sessions (`probe ok`, `ready`, `hello-from-tmux`) are infrastructure overhead, not real work
- Codex sessions often run as batch reviewers — many sessions with the same prompt template
- Look for the same error appearing across multiple sessions — that's a systemic failure pattern
