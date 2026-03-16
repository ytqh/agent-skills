---
name: adversarial-review
description: >-
  Adversarial code review using the opposite model. Spawns 1–3 reviewers on the
  opposing model (Claude spawns Codex, Codex spawns Claude) to challenge work from
  distinct critical lenses. Triggers: "adversarial review".
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

Attempt to read `brain/principles.md`. Follow every `[[wikilink]]` and read each linked principle file.
These govern reviewer judgments.

Before proceeding, validate these resource paths:

- `brain/principles.md`
- `references/reviewer-lenses.md`

Rules:

- If `references/reviewer-lenses.md` is missing, stop and report the missing dependency.
- If `brain/principles.md` is missing, do **not** stop the review. Record that principles
  could not be loaded, continue with the lens-only review, and mention this limitation in the final verdict.

## Step 2 — Determine Scope and Intent

Identify what to review from context (recent diffs, referenced plans, user message).

Determine the **intent** — what the author is trying to achieve. This is critical: reviewers
challenge whether the work *achieves the intent well*, not whether the intent is correct.
State the intent explicitly before proceeding.

Assess change size:

| Size | Threshold | Reviewers |
|------|-----------|-----------|
| Small | < 50 lines, 1–2 files | 1 (Skeptic) |
| Medium | 50–200 lines, 3–5 files | 2 (Skeptic + Architect) |
| Large | 200+ lines or 5+ files | 3 (Skeptic + Architect + Minimalist) |

Read `references/reviewer-lenses.md` for lens definitions.

### Scope Slicing Rule

For large changes, do **not** automatically review every changed file together.
First slice the review scope by intent.

Examples:

- If the intent is runtime correctness, prioritize code, migrations, and runtime tests.
- If the intent is rollout safety, prioritize config, migrations, operational scripts, and trigger paths.
- If the intent is maintainability for future strategy additions, prioritize the configuration model,
  trigger fan-out path, and extension points.

Avoid stuffing docs, plans, specs, generated files, and unrelated test churn into the same review scope unless they are directly relevant to the stated intent.

If you exclude obvious files from scope, say so explicitly in the verdict.

## Step 3 — Detect Model and Spawn Reviewers

Create a temp directory for reviewer output:

```sh
REVIEW_DIR=$(mktemp -d /tmp/adversarial-review.XXXXXX)
```

## Step 3a — Prepare Review Inputs Before Spawning

Always complete the preparation phase before starting any reviewer process.

Prepare these files first:

```sh
git diff ... > "$REVIEW_DIR/diff.patch"
cat > "$REVIEW_DIR/skeptic_prompt.txt" <<'EOF'
...
EOF
cat > "$REVIEW_DIR/architect_prompt.txt" <<'EOF'
...
EOF
cat > "$REVIEW_DIR/minimalist_prompt.txt" <<'EOF'
...
EOF
```

Only after all prompt files exist should you spawn reviewers.

This avoids races where a reviewer starts before its prompt file has been fully written.

Determine which model you are, then spawn reviewers on the opposite:

**If you are Claude** → spawn Codex reviewers via `codex exec`:

```sh
codex exec --skip-git-repo-check -o "$REVIEW_DIR/skeptic.md" - < "$REVIEW_DIR/skeptic_prompt.txt" 2>/dev/null
```

Use `--profile edit` only if the reviewer needs to run tests. Default to read-only.
Run with `run_in_background: true`, monitor via `TaskOutput` with `block: true, timeout: 600000`.

**If you are Codex** → spawn Claude reviewers via `claude` CLI:

```sh
claude -p < "$REVIEW_DIR/skeptic_prompt.txt" > "$REVIEW_DIR/skeptic.md" 2>/dev/null
```

Run with `run_in_background: true`.

Name each output file after the lens: `skeptic.md`, `architect.md`, `minimalist.md`.

### Reviewer prompt template

Each reviewer gets a single prompt containing:

1. The stated intent (from Step 2)
2. Their assigned lens (full text from references/reviewer-lenses.md)
3. The principles relevant to their lens (file contents, not summaries)
4. The code or diff to review
5. Instructions: "You are an adversarial reviewer. Your job is to find real problems, not
   validate the work. Be specific — cite files, lines, and concrete failure scenarios.
   Rate each finding: high (blocks ship), medium (should fix), low (worth noting).
   Write findings as a numbered markdown list to your output file."

Spawn all reviewers in parallel.

### Prompt Transport Rule

Do **not** embed a large diff directly into the shell command argument string.
Always feed prompts through stdin from prepared temp files.

Reason:

- avoids shell command-length limits
- avoids quoting corruption on large diffs
- makes retries reproducible
- keeps the exact reviewer input inspectable in `REVIEW_DIR`

## Step 4 — Verify and Synthesize Verdict

Before reading reviewer output, log which CLI was used and confirm the output files exist:

```sh
echo "reviewer_cli=codex|claude"
ls "$REVIEW_DIR"/*.md
```

Then verify each output file is non-empty:

```sh
for f in "$REVIEW_DIR"/*.md; do
  [ -s "$f" ] || echo "empty_or_missing=$f"
done
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
<numbered list, ordered by severity (high → medium → low)>

For each finding:
- **[severity]** Description with file:line references
- Lens: which reviewer raised it
- Principle: which brain principle it maps to
- Recommendation: concrete action, not vague advice

## What Went Well
<1–3 things the reviewers found no issue with — acknowledge good work>
```

**Verdict logic:**
- **PASS** — no high-severity findings
- **CONTESTED** — high-severity findings but reviewers disagree on them
- **REJECT** — high-severity findings with reviewer consensus

## Step 5 — Render Judgment

After synthesizing the reviewers, apply your own judgment. Using the stated intent and brain
principles as your frame, state which findings you would accept and which you would reject —
and why. Reviewers are adversarial by design; not every finding warrants action. Call out
false positives, overreach, and findings that mistake style for substance.

If `brain/principles.md` was unavailable, explicitly say that the lead judgment was rendered
using the stated intent and reviewer lenses only.

Append to the verdict:

```
## Lead Judgment
<for each finding: accept or reject with a one-line rationale>
```
