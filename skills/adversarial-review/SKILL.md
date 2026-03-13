---
name: adversarial-review
description: >-
  Adversarial code review using the opposite model in dedicated tmux reviewer sessions.
  Spawns 1-3 reviewers on the opposing model (Claude spawns Codex, Codex spawns Claude)
  and controls them only through tmux interaction: start session, paste prompts, capture pane,
  and send follow-up instructions. Triggers: "adversarial review".
schedule: "After cook sessions that produce large diffs (200+ lines), implement plan phases, or complete a planning session"
---

# Adversarial Review

Spawn reviewers on the **opposite model** in tmux sessions and synthesize their findings.
Reviewers attack from distinct lenses. The deliverable is a synthesized verdict. Do **not**
make code changes as part of this skill.

**Hard constraint:** Reviewers MUST run via the opposite model's CLI inside tmux sessions.
Do NOT use subagents, the Agent tool, or any internal delegation mechanism as reviewers.

**Control contract:** Interact with reviewers only through tmux session control:

- start interactive reviewer sessions in tmux
- send prompts through `tmux load-buffer` + `tmux paste-buffer` + `tmux send-keys`
- read reviewer output through `tmux capture-pane`
- send follow-up instructions to the same session when needed

Do **not** use one-shot reviewer commands such as `claude -p` or `codex exec` as the primary
review workflow. Those are batch jobs, not reviewer sessions.

## Step 1 — Determine Scope and Intent

Identify what to review from context: recent diffs, referenced plans, or the user message.

Determine the **intent** of the author. State it explicitly before proceeding. Reviewers should
challenge whether the work achieves that intent well, not whether the intent is desirable.

Assess change size:

| Size | Threshold | Reviewers |
|------|-----------|-----------|
| Small | < 50 lines, 1-2 files | 1 (Skeptic) |
| Medium | 50-200 lines, 3-5 files | 2 (Skeptic + Architect) |
| Large | 200+ lines or 5+ files | 3 (Skeptic + Architect + Minimalist) |

Read `references/reviewer-lenses.md` for the lens definitions.

## Step 2 — Detect Model and Prepare Review Context

Determine which model you are, then choose the opposite model's **interactive** CLI:

- **If you are Claude** → use interactive `codex`
- **If you are Codex** → use interactive `claude`

Use these launch commands:

```sh
# If you are Claude, reviewers run on Codex:
REVIEWER_LAUNCH="codex -C '$REPO_ROOT' --no-alt-screen -s read-only -a never"

# If you are Codex, reviewers run on Claude:
REVIEWER_LAUNCH="claude --permission-mode dontAsk --no-chrome"
```

Prepare the review context:

```sh
REPO_ROOT="$(pwd)"
REVIEW_DIR="$(mktemp -d /tmp/adversarial-review.XXXXXX)"
REVIEW_TAG="$(basename "$REVIEW_DIR" | tr -c '[:alnum:]_-' '-')"
```

Choose the artifact that matches the review scope:

```sh
git diff HEAD > "$REVIEW_DIR/diff.patch"          # local changes vs HEAD
git diff --cached > "$REVIEW_DIR/staged.patch"    # staged changes only
```

If the review scope is a PR rather than local changes, fetch the exact patch you want reviewed
into `"$REVIEW_DIR/diff.patch"` instead of relying on the current checkout.

Abort early if the chosen artifact is empty:

```sh
test -s "$REVIEW_DIR/diff.patch" || {
  echo "review artifact is empty"
  exit 1
}
```

## Step 3 — Start Reviewer Sessions in tmux

Use direct tmux sessions. `agent-manager` is not part of this workflow.

### Session naming

Use dot-free **run-scoped** session names:

```sh
SKEPTIC_SESSION="reviewer-${REVIEW_TAG}-skeptic"
ARCHITECT_SESSION="reviewer-${REVIEW_TAG}-architect"
MINIMALIST_SESSION="reviewer-${REVIEW_TAG}-minimalist"
```

Before starting, clear any stale sessions with the same names:

```sh
for session in "$SKEPTIC_SESSION" "$ARCHITECT_SESSION" "$MINIMALIST_SESSION"; do
  tmux kill-session -t "$session" 2>/dev/null || true
done
```

### Decide the reviewer set

Build the reviewer array from the scope size:

```sh
REVIEWERS=(skeptic)
# Medium:
# REVIEWERS=(skeptic architect)
# Large:
# REVIEWERS=(skeptic architect minimalist)
```

### Set cleanup immediately

Set tmux cleanup at the start, but keep `REVIEW_DIR` on failure for debugging:

```sh
trap 'for session in "$SKEPTIC_SESSION" "$ARCHITECT_SESSION" "$MINIMALIST_SESSION"; do tmux kill-session -t "$session" 2>/dev/null || true; done' EXIT
```

### Start sessions

Start one interactive session per reviewer:

```sh
tmux new-session -d -s "$SKEPTIC_SESSION" "cd '$REPO_ROOT' && $REVIEWER_LAUNCH"
tmux new-session -d -s "$ARCHITECT_SESSION" "cd '$REPO_ROOT' && $REVIEWER_LAUNCH"
tmux new-session -d -s "$MINIMALIST_SESSION" "cd '$REPO_ROOT' && $REVIEWER_LAUNCH"
```

If you only launched a subset of reviewers, only start those sessions.

Optional but useful: mirror pane output into transcript files for audit. These transcript files
are secondary artifacts derived from tmux, not the primary control plane:

```sh
tmux pipe-pane -o -t "$SKEPTIC_SESSION" "cat > '$REVIEW_DIR/skeptic.transcript.log'"
tmux pipe-pane -o -t "$ARCHITECT_SESSION" "cat > '$REVIEW_DIR/architect.transcript.log'"
tmux pipe-pane -o -t "$MINIMALIST_SESSION" "cat > '$REVIEW_DIR/minimalist.transcript.log'"
```

## Step 4 — Run a Canary Probe Before the Real Review

Do not assume interactive submission semantics. Verify them with a minimal probe first.

For each started session, create a session-specific token:

```sh
SKEPTIC_PROBE_TOKEN="PROBE_OK_${REVIEW_TAG}_skeptic"
ARCHITECT_PROBE_TOKEN="PROBE_OK_${REVIEW_TAG}_architect"
MINIMALIST_PROBE_TOKEN="PROBE_OK_${REVIEW_TAG}_minimalist"
```

Send the probe:

```sh
cat > "$REVIEW_DIR/skeptic.probe.txt" <<EOF
Reply with exactly one line and nothing else: ${SKEPTIC_PROBE_TOKEN}
EOF

tmux load-buffer -b skeptic-probe "$REVIEW_DIR/skeptic.probe.txt"
tmux paste-buffer -d -b skeptic-probe -t "$SKEPTIC_SESSION"

# Claude interactive reviewers:
tmux send-keys -t "$SKEPTIC_SESSION" Enter

# Codex interactive reviewers with multiline pasted text:
tmux send-keys -t "$SKEPTIC_SESSION" Enter
tmux send-keys -t "$SKEPTIC_SESSION" Enter
```

Then inspect the pane:

```sh
tmux capture-pane -p -t "$SKEPTIC_SESSION" -S -120
```

Proceed only if the pane contains the exact line `${SKEPTIC_PROBE_TOKEN}` within about 60 seconds.

If the prompt text appears in the pane but the token never appears, do **not** continue with
the real review. Fix the submit sequence for that CLI version first.

## Step 5 — Send the Real Review Prompt

Build a prompt file per reviewer. This is only a staging helper for tmux paste; it is **not**
the reviewer I/O mechanism.

Use a run-scoped final marker that appears only as a value inside instruction lines, not as a
standalone marker in the pasted prompt. This avoids false positives from prompt echo.

Example for `skeptic`:

```sh
SKEPTIC_BLOCK_ID="${REVIEW_TAG}_skeptic"

{
  cat <<EOF
You are an adversarial reviewer using the **Skeptic** lens.

## Intent
{stated intent from Step 1}

## Your Lens
{full lens text from references/reviewer-lenses.md}

## Instructions
- You are an adversarial reviewer. Your job is to find real problems, not validate the work.
- Be specific — cite files, lines, and concrete failure scenarios.
- Rate each finding: high (blocks ship), medium (should fix), low (worth noting).
- Start your final answer with the exact line: FINAL REVIEW START ${SKEPTIC_BLOCK_ID}
- End your final answer with the exact line: FINAL REVIEW END ${SKEPTIC_BLOCK_ID}

## Review Artifact
EOF
  cat "$REVIEW_DIR/diff.patch"
} > "$REVIEW_DIR/skeptic.prompt.txt"
```

Create equivalent prompt files for `architect` and `minimalist`.

For focused file reviews, append file contents instead of a diff:

```sh
{
  cat <<EOF
...
## Review Artifact
EOF
  cat /abs/path/to/file.py
} > "$REVIEW_DIR/skeptic.prompt.txt"
```

Send the prompt through tmux:

```sh
tmux load-buffer -b skeptic "$REVIEW_DIR/skeptic.prompt.txt"
tmux paste-buffer -d -b skeptic -t "$SKEPTIC_SESSION"

# Claude interactive reviewers:
tmux send-keys -t "$SKEPTIC_SESSION" Enter

# Codex interactive reviewers with multiline pasted text:
tmux send-keys -t "$SKEPTIC_SESSION" Enter
tmux send-keys -t "$SKEPTIC_SESSION" Enter
```

Repeat for the other reviewer sessions.

## Step 6 — Monitor Through tmux Only

The source of truth is the tmux pane content.

Check a session:

```sh
tmux capture-pane -p -t "$SKEPTIC_SESSION" -S -220
```

Recommended wait loop:

```sh
timeout_s=600
deadline=$((SECONDS + timeout_s))
expected="${#REVIEWERS[@]}"

while [ "$SECONDS" -lt "$deadline" ]; do
  completed=0
  for lens in "${REVIEWERS[@]}"; do
    case "$lens" in
      skeptic)
        session_name="$SKEPTIC_SESSION"
        block_id="${REVIEW_TAG}_skeptic"
        ;;
      architect)
        session_name="$ARCHITECT_SESSION"
        block_id="${REVIEW_TAG}_architect"
        ;;
      minimalist)
        session_name="$MINIMALIST_SESSION"
        block_id="${REVIEW_TAG}_minimalist"
        ;;
    esac

    pane="$(tmux capture-pane -p -t "$session_name" -S -320 2>/dev/null || true)"
    printf '%s\n' "$pane" > "$REVIEW_DIR/$lens.capture.txt"

    if printf '%s\n' "$pane" | rg -q "^FINAL REVIEW END ${block_id}$"; then
      completed=$((completed + 1))
    fi
  done

  [ "$completed" -eq "$expected" ] && break
  sleep 5
done
```

If a reviewer is unclear, incomplete, or obviously wrong, send a follow-up prompt to the same
session rather than starting over.

Example:

```sh
SKEPTIC_FOLLOWUP_ID="${REVIEW_TAG}_skeptic_followup_1"

cat > "$REVIEW_DIR/skeptic.followup.txt" <<EOF
Follow-up:
- clarify finding #2
- cite the exact file and line
- start your answer with the exact line: FINAL FOLLOWUP START ${SKEPTIC_FOLLOWUP_ID}
- end your answer with the exact line: FINAL FOLLOWUP END ${SKEPTIC_FOLLOWUP_ID}
EOF

tmux load-buffer -b skeptic-followup "$REVIEW_DIR/skeptic.followup.txt"
tmux paste-buffer -d -b skeptic-followup -t "$SKEPTIC_SESSION"
tmux send-keys -t "$SKEPTIC_SESSION" Enter
```

Then capture the pane again.

## Step 7 — Verify and Synthesize Verdict

Before reading results, log the launcher and save pane snapshots:

```sh
echo "reviewer_cli=$REVIEWER_LAUNCH"
for lens in "${REVIEWERS[@]}"; do
  case "$lens" in
    skeptic) session_name="$SKEPTIC_SESSION" ;;
    architect) session_name="$ARCHITECT_SESSION" ;;
    minimalist) session_name="$MINIMALIST_SESSION" ;;
  esac
  tmux capture-pane -p -t "$session_name" -S -420 > "$REVIEW_DIR/$lens.capture.txt"
done
```

Read each capture and extract the content between:

- `FINAL REVIEW START ${REVIEW_TAG}_<lens>`
- `FINAL REVIEW END ${REVIEW_TAG}_<lens>`

If those markers are missing for a reviewer, note that reviewer as failed or incomplete. Do not
silently skip it.

Produce a single verdict:

```text
## Intent
<what the author is trying to achieve>

## Verdict: PASS | CONTESTED | REJECT
<one-line summary>

## Findings
<numbered list ordered by severity>

## What Went Well
<1-3 things the reviewers found no issue with>
```

Verdict logic:

- **PASS** — no high-severity findings
- **CONTESTED** — high-severity findings but reviewers disagree on them
- **REJECT** — high-severity findings with reviewer consensus

Then apply your own judgment:

```text
## Lead Judgment
<for each finding: accept or reject with a one-line rationale>
```

## Step 8 — Cleanup

Stop the tmux sessions and remove temp files:

```sh
for session in "$SKEPTIC_SESSION" "$ARCHITECT_SESSION" "$MINIMALIST_SESSION"; do
  tmux kill-session -t "$session" 2>/dev/null || true
done

rm -rf "$REVIEW_DIR"
```
