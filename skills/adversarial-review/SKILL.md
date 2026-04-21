---
name: adversarial-review
description: >-
  Adversarial code review using cross-model approach. Spawns reviewers on the opposing model
  (Claude uses Codex, Codex uses Claude) to challenge work from distinct critical lenses.
  Produces a synthesized verdict with findings and lead judgment. Triggers: "adversarial review".
schedule: "After cook sessions that produce large diffs (200+ lines), implement plan phases, or complete a planning session"
---

# Adversarial Review

Spawn reviewers on the **opposite model** to challenge work. Reviewers attack from distinct
lenses grounded in brain principles. The deliverable is a synthesized verdict — do NOT make
changes.

**Hard constraint:** Reviewers MUST run via the opposite model's CLI (`codex exec` or
`claude -p`). Do NOT use subagents, the Agent tool, or any internal delegation mechanism as
reviewers — those run on *your own* model, which defeats the purpose.

## Step 1 — Load Principles

Read `brain/principles.md`. Follow every `[[wikilink]]` and read each linked principle file.
These govern reviewer judgments.

## Step 2 — Determine Scope and Intent

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

## Step 3 — Detect Model and Spawn Reviewers

Create a temp directory for reviewer output:

```sh
REVIEW_DIR=$(mktemp -d /tmp/adversarial-review.XXXXXX)
```

Determine which model you are, then spawn reviewers on the opposite:

**If you are Claude** — spawn Codex reviewers via `codex exec`:

```sh
codex exec --skip-git-repo-check "prompt" > "$REVIEW_DIR/skeptic.md" 2>"$REVIEW_DIR/skeptic.err"
```

Do **not** use `codex exec -o` for reviewer findings. In prior runs this caused the
reviewer to treat the output path as an instruction and return a confirmation such as
"I wrote the findings" instead of the findings themselves. The reviewer must emit its
critique to stdout; the shell redirection above is the only file-writing mechanism.

Use `--profile edit` only if the reviewer needs to run tests. Default to read-only.
Run with `run_in_background: true`, monitor via `TaskOutput` with `block: true, timeout: 600000`.

**If you are Codex** — spawn Claude reviewers via `claude` CLI:

```sh
claude -p "prompt" > "$REVIEW_DIR/skeptic.md" 2>"$REVIEW_DIR/skeptic.err"
```

Run with `run_in_background: true`.

Name each output file after the lens: `skeptic.md`, `architect.md`, `minimalist.md`.

Build each reviewer's prompt using the template in `references/reviewer-prompt.md`.

### Step 3b — Sanity-check reviewer output before waiting on the whole batch

As soon as the first reviewer completes, inspect its output before spending time waiting
on the remaining reviewers. If the first output is a file-write confirmation, an apology,
or generic validation instead of a critique, stop the batch and rerun with a corrected
prompt/command. Do not let a bad capture pattern waste a full review round.

Run this check on each output file before synthesis:

```sh
python3 - <<'PY' "$REVIEW_DIR/skeptic.md"
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(errors="replace").strip()
lower = text.lower()

bad_confirmation = re.search(
    r"\b(wrote|written|saved|created|placed|stored)\b.{0,80}\b(file|output|findings)\b",
    lower,
)
has_critique_marker = re.search(
    r"\b(high|medium|low|verdict|pass|reject|contested|no blocking findings|no findings)\b",
    lower,
)
substantive = len(text) >= 300

if not text:
    raise SystemExit(f"{path}: empty reviewer output")
if bad_confirmation and not has_critique_marker:
    raise SystemExit(f"{path}: reviewer returned file-write confirmation, not critique")
if not has_critique_marker and not substantive:
    raise SystemExit(f"{path}: reviewer output lacks critique markers")
print(f"{path}: reviewer output sanity check ok")
PY
```

If this check fails:

1. Read the corresponding `.err` file for CLI/runtime errors.
2. Rerun that reviewer with an explicit instruction: "Return the review in stdout only.
   Do not write files. Do not say you wrote a file."
3. If multiple reviewers failed the same way, cancel/restart the whole batch with the
   fixed prompt pattern.

## Step 4 — Verify and Synthesize Verdict

Before reading reviewer output, log which CLI was used and confirm the output files exist:

```sh
echo "reviewer_cli=codex|claude"
ls -l "$REVIEW_DIR"/*.md
```

If any output file is missing, empty, or fails the Step 3b sanity check, note the failure in
the verdict — do not silently skip a reviewer. If the failure is a capture/prompt problem
rather than a real reviewer disagreement, rerun the reviewer before synthesizing.

Read each reviewer's output file from `$REVIEW_DIR/`. Deduplicate overlapping findings.
Produce a single verdict using the format in `references/verdict-format.md`.

## Step 5 — Render Judgment

After synthesizing the reviewers, apply your own judgment. Using the stated intent and brain
principles as your frame, state which findings you would accept and which you would reject —
and why. Reviewers are adversarial by design; not every finding warrants action. Call out
false positives, overreach, and findings that mistake style for substance.

Append the Lead Judgment section to the verdict (see `references/verdict-format.md`).
