---
name: adversarial-review
description: >-
  Adversarial code review using the opposite model in a tmux session via agent-manager.
  Spawns 1-3 reviewers on the opposing model (Claude spawns Codex, Codex spawns Claude)
  to challenge work from distinct critical lenses. Triggers: "adversarial review".
schedule: "After cook sessions that produce large diffs (200+ lines), implement plan phases, or complete a planning session"
---

# Adversarial Review

Spawn reviewers on the **opposite model** via tmux sessions (using agent-manager) to challenge
work. Reviewers attack from distinct lenses. The deliverable is a synthesized verdict — do NOT
make changes.

**Hard constraint:** Reviewers MUST run via the opposite model's CLI in a tmux session managed
by agent-manager. Do NOT use subagents, the Agent tool, or any internal delegation mechanism as
reviewers — those run on *your own* model, which defeats the purpose.

## Step 1 — Determine Scope and Intent

Identify what to review from context (recent diffs, referenced plans, user message).

Determine the **intent** — what the author is trying to achieve. This is critical: reviewers
challenge whether the work *achieves the intent well*, not whether the intent is correct.
State the intent explicitly before proceeding.

Assess change size:

| Size | Threshold | Reviewers |
|------|-----------|-----------|
| Small | < 50 lines, 1-2 files | 1 (Skeptic) |
| Medium | 50-200 lines, 3-5 files | 2 (Skeptic + Architect) |
| Large | 200+ lines or 5+ files | 3 (Skeptic + Architect + Minimalist) |

Read `references/reviewer-lenses.md` for lens definitions.

## Step 2 — Detect Model and Prepare Review Context

Determine which model you are, then choose the opposite model's CLI:

- **If you are Claude** → use `codex` as the launcher
- **If you are Codex** → use `claude` as the launcher

Prepare the review context:

1. Collect the diff or files to review
2. Write the diff/code to a temp file for the reviewer to read:

```sh
REVIEW_DIR=$(mktemp -d /tmp/adversarial-review.XXXXXX)
git diff > "$REVIEW_DIR/diff.patch"
# or for specific files:
# cp path/to/file "$REVIEW_DIR/"
```

## Step 3 — Create Reviewer Agent Configs and Spawn via Agent-Manager

Define the agent-manager CLI path:

```sh
CLI="python3 $HOME/.agents/skills/agent-manager/scripts/main.py"
```

For each reviewer lens needed, create a temporary agent config file and use agent-manager
to start+assign the review task in a tmux session.

### Create agent config files

Create temporary agent markdown files in `/tmp/adversarial-review-agents/`:

```sh
mkdir -p /tmp/adversarial-review-agents
```

For each reviewer (e.g., skeptic), create `/tmp/adversarial-review-agents/reviewer-{lens}.md`:

**If you are Claude** (spawning Codex reviewers):

```yaml
---
name: reviewer-{lens}
description: "Adversarial {Lens} reviewer"
working_directory: {repo_root}
launcher: codex
launcher_args:
  - --skip-git-repo-check
enabled: true
---
```

**If you are Codex** (spawning Claude reviewers):

```yaml
---
name: reviewer-{lens}
description: "Adversarial {Lens} reviewer"
working_directory: {repo_root}
launcher: claude
launcher_args:
  - -p
enabled: true
---
```

### Spawn reviewers

For each reviewer lens, use agent-manager to start the tmux session and assign the review task:

```sh
# Start the reviewer agent session
$CLI start reviewer-{lens} --agent-dir /tmp/adversarial-review-agents

# Assign the review task
$CLI assign reviewer-{lens} --agent-dir /tmp/adversarial-review-agents <<EOF
You are an adversarial reviewer using the **{Lens}** lens.

## Intent
{stated intent from Step 1}

## Your Lens
{full lens text from references/reviewer-lenses.md}

## Instructions
- You are an adversarial reviewer. Your job is to find real problems, not validate the work.
- Be specific — cite files, lines, and concrete failure scenarios.
- Rate each finding: high (blocks ship), medium (should fix), low (worth noting).
- Review the code/diff at: $REVIEW_DIR/diff.patch
- Write your findings as a numbered markdown list to: $REVIEW_DIR/{lens}.md

Read the diff, analyze it, write findings to the output file, then exit.
EOF
```

Spawn all reviewers in parallel (run each start+assign pair sequentially, but launch all
lenses without waiting for completion).

### Monitor progress

Poll reviewer output using agent-manager monitor:

```sh
$CLI monitor reviewer-{lens} -n 50
```

Wait until all reviewer output files exist in `$REVIEW_DIR/` or a reasonable timeout (10 min).

### Cleanup sessions

After collecting output, stop all reviewer sessions:

```sh
$CLI stop reviewer-skeptic
$CLI stop reviewer-architect
$CLI stop reviewer-minimalist
```

## Step 4 — Verify and Synthesize Verdict

Before reading reviewer output, log which CLI was used and confirm the output files exist:

```sh
echo "reviewer_cli=codex|claude"
ls "$REVIEW_DIR"/*.md
```

If any output file is missing or empty, note the failure in the verdict — do not silently skip
a reviewer.

Read each reviewer's output file from `$REVIEW_DIR/`. Deduplicate overlapping findings.
Produce a single verdict:

```
## Intent
<what the author is trying to achieve>

## Verdict: PASS | CONTESTED | REJECT
<one-line summary>

## Findings
<numbered list, ordered by severity (high -> medium -> low)>

For each finding:
- **[severity]** Description with file:line references
- Lens: which reviewer raised it
- Recommendation: concrete action, not vague advice

## What Went Well
<1-3 things the reviewers found no issue with — acknowledge good work>
```

**Verdict logic:**
- **PASS** — no high-severity findings
- **CONTESTED** — high-severity findings but reviewers disagree on them
- **REJECT** — high-severity findings with reviewer consensus

## Step 5 — Render Judgment

After synthesizing the reviewers, apply your own judgment. Using the stated intent as your
frame, state which findings you would accept and which you would reject — and why. Reviewers
are adversarial by design; not every finding warrants action. Call out false positives,
overreach, and findings that mistake style for substance.

Append to the verdict:

```
## Lead Judgment
<for each finding: accept or reject with a one-line rationale>
```

## Cleanup

Remove temp files after the review is complete:

```sh
rm -rf "$REVIEW_DIR"
rm -rf /tmp/adversarial-review-agents
```
