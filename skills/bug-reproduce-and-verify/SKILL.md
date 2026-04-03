---
name: bug-reproduce-and-verify
description: Use when the user asks whether a bug is fixed, wants a bug reproduced, or gives a bug link, ID, title, or symptom and needs you to determine the current state from dev-server code, tmux sessions, recent commits, and observed app behavior. Use this whenever an issue may already have work in progress on dev-server and you need to decide whether to verify an existing fix or reproduce the bug from scratch.
---

# Bug Reproduce And Verify

## Overview

This skill is for bug-state determination, not generic debugging chat.

Given a bug handle, first recover what the bug actually is. Then decide whether the correct next move is:

- `verify` — existing work likely already targets the bug
- `reproduce` — no credible fix evidence exists yet

**REQUIRED BACKGROUND:** Use [systematic-debugging](/Users/aki/.agents/skills/systematic-debugging/SKILL.md) principles. No conclusions without evidence.

## Default Context

Unless the user says otherwise, assume:

- source-code execution host: `dev-server`
- SSH entry: `hardfun@192.168.238.203`
- primary repo path is project-specific on that machine
- if the bug is a WeChat Mini Program UI flow, use `miniprogram-browser`
- if the Mini Program bug needs a real authenticated staging user, use `jim-miniprogram-login` before verifying behavior

## Inputs

Typical bug handles:

- Notion page URL
- bug tracker row / issue ID
- bug title
- symptom description

If the original source is inaccessible, reconstruct the bug from the best available local evidence instead of stopping.

## Evidence Sources

Read [evidence-sources.md](./references/evidence-sources.md).

Use these in order:

1. Original bug source if accessible
2. Current uncommitted code on `dev-server`
3. Recent commits touching the relevant area
4. Active `tmux` sessions and pane history on `dev-server`
5. Local Claude/Codex transcript search
6. Black-box runtime verification

## Decision Rule

### Choose `verify` when any of these are true

- uncommitted diffs clearly touch the bug area
- a recent commit message names the same bug or symptom
- a `tmux` window/session is named after the bug or module
- session transcripts already contain root cause analysis or a proposed fix

### Choose `reproduce` when all of these are true

- no relevant working-tree changes
- no recent fix-looking commits
- no active tmux work for the bug
- no transcript evidence of ongoing investigation

### If mixed

Default to `verify` first.

If verification is inconclusive, fall back to `reproduce`.

## Phase 1: Recover The Bug

Before testing anything, recover the bug content:

1. Identify the exact bug handle
2. Summarize the expected bad behavior in one sentence
3. Extract the implied acceptance check

If the bug source cannot be read directly:

- inspect `git status` and recent commits
- inspect `tmux list-windows` and `tmux capture-pane`
- inspect session transcripts with `recall`
- infer the bug from concrete notes, not from guesses

Output of this phase:

```text
Bug title:
Module:
Expected broken behavior:
Expected fixed behavior:
Chosen mode: verify | reproduce
Why:
```

## Phase 2A: Verify Mode

Use this when fix evidence already exists.

### Step 1. Inspect current code

Check:

- exact files modified
- exact lines changed
- whether the change plausibly addresses the recovered bug

Do not stop at code review. Verification requires observed behavior.

### Step 2. Pick the smallest real verification path

Use the narrowest verification that can answer the bug:

- frontend display bug: inspect rendered UI behavior
- backend rule bug: run targeted unit/integration test or query current state
- navigation bug: run end-to-end UI flow
- data/logic bug: inspect live task state, API response, or persisted rows

### Step 3. Run the verification

For Mini Program UI bugs:

- **REQUIRED SUB-SKILL:** Use `miniprogram-browser`
- if the flow depends on real user state, **also** use `jim-miniprogram-login`

For backend/task bugs:

- run the smallest targeted test that directly exercises the broken rule
- inspect dev-server tmux pane history if the existing session already contains the investigation

### Step 3.5: UI-Level Verification (Required)

**Final verification must always be at the UI level.** Backend data verification (DB queries, API responses) is necessary but NOT sufficient. The bug is only "verified fixed" when the fix is confirmed through the actual user-facing interface.

- **Web / Mini Program bugs:** Use `miniprogram-browser` or equivalent browser automation to confirm the fix is visible to the end user. Checking that a database row changed or an API returns the right payload does NOT prove the UI renders correctly.
- if the Web / Mini Program bug depends on authenticated task, badge, report, or progress state, first use `jim-miniprogram-login` to complete a real login through the actual Mini Program UI.
- do not use token injection, debug-only endpoints, seeded badge state, or other fabricated test data as verification evidence.
- if the required live staging state does not exist for any available real user, report the verification as blocked or inconclusive instead of manufacturing the state.
- **API-only bugs:** The API response must be checked from the client's perspective (i.e., the same endpoint, auth context, and request shape a real client would use), not only via direct DB inspection.
- **Why this matters:** Bugs live in the gap between data and presentation. A correct DB row can still produce a broken UI due to serialization, caching, rendering logic, or client-side state. Only UI-level observation closes that gap.

If the bug affects user-visible behavior and you have not performed UI-level verification, you **must not** mark it as `verified fixed`.

### Step 4. Decide

A bug is `verified fixed` only if:

- the observed behavior now matches the expected fixed behavior, **and**
- **UI-level verification has passed** when the bug affects user-visible behavior. If only backend data (DB rows, API responses) has been verified but the UI has not been checked, the status must be `code suggests fixed but behavior not yet verified` until UI verification is completed.

Otherwise report:

- `not fixed`
- `partially fixed`
- `code suggests fixed but behavior not yet verified`

## Phase 2B: Reproduce Mode

Use this when no meaningful fix evidence exists.

### Step 1. Read the code path

Find:

- entrypoint
- state/data dependencies
- likely branch where behavior breaks

### Step 2. Reproduce minimally

Run the smallest concrete repro:

- one failing UI path
- one failing API call
- one failing rule-engine test

### Step 3. Record first failing boundary

Examples:

- page never navigates
- data missing in API response
- progress count stays zero
- automatic message is malformed
- field rendered in code but not visible in UI

Do not propose a fix unless the user asks. This skill is about state determination first.

## Mini Program Bug Verification

When the bug touches WeChat Mini Program behavior:

- start with `miniprogram-browser` on the current WSL-built `dist`
- if the bug needs a logged-in user or real per-user staging data, use `jim-miniprogram-login` first
- use only naturally existing staging data for badges, tasks, reports, and progress
- if the needed state does not exist, switch to another real user or report the verification as blocked
- normalize to the expected start page
- replay only the bug-relevant flow
- capture visible text and page path after each action

Good candidates:

- tab navigation bugs
- task card rendering bugs
- character selection / chat flow bugs
- missing text or duplicated UI content

## Tmux Usage

When `dev-server` already has relevant tmux work:

1. list sessions
2. identify relevant window names
3. capture recent pane output
4. extract:
   - bug statement
   - root cause
   - fix summary
   - tests already run

Treat tmux output as evidence, not final truth. Verify against code or runtime when possible.

## Transcript Usage

Use local session recall when you need bug context but the original issue source is unavailable.

Useful for:

- Notion auth failure
- bug title not fully descriptive
- knowing whether prior agents already determined root cause

Prefer transcripts that contain:

- exact bug URL
- module-specific terms
- fix summary or test output

## Report Format

Always report in this shape:

```text
Bug: <title or inferred title>
Mode: verify | reproduce

Recovered Intent
<what the bug actually means>

Evidence
<files / commits / tmux / transcripts / runtime observations>

Result
verified fixed | not fixed | partially fixed | inconclusive

Why
<short explanation tied to evidence>

If runtime verified:
<exact observed behavior>
```

## Common Mistakes

- Treating code diff alone as “fixed”
- Ignoring existing tmux evidence and redoing the whole investigation
- Treating a stale bug source as current truth without checking worktree or sessions
- Reproducing from scratch when a fix is already clearly in progress
- Verifying a Mini Program bug without using `miniprogram-browser`
- Marking a UI bug as "verified fixed" based only on database queries or API responses without checking the actual user-facing interface
- Trying to verify a logged-in Mini Program bug in anonymous state, or stopping at `refresh_token` injection instead of completing the real login flow

## Files

- Evidence guidance: [evidence-sources.md](./references/evidence-sources.md)
- Example eval prompts: [evals.json](./evals/evals.json)
