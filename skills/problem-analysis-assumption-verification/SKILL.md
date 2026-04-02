---
name: problem-analysis-assumption-verification
description: >-
  Structured phenomenon analysis and hypothesis verification workflow. Guides the user through
  problem clarification, data integrity validation, orthogonal hypothesis generation with
  adversarial review, parallel subagent verification, and structured conclusion documentation.
  Use when the user reports an unexpected phenomenon, anomalous data, unclear system behavior,
  or any situation where the root cause is uncertain and multiple explanations are plausible.
  Also use when the user asks to "analyze why", "figure out what's happening", "verify
  assumptions", "test hypotheses", "investigate a gap", "decompose a metric", or describes
  something that "doesn't make sense". This skill is especially valuable for data-driven
  investigations, metric anomalies, business logic mysteries, cross-system behavioral issues,
  and theoretical-vs-actual discrepancy analysis — not just code bugs.
---

# Problem Analysis & Hypothesis Verification

A structured, iterative workflow for moving from "something seems wrong" to "here's what's
actually happening and why." The core loop: clarify the phenomenon, validate the data
foundation, generate competing hypotheses, verify them in parallel, and document conclusions.

This is distinct from simple debugging. Debugging assumes a code bug with a single root cause.
This skill handles situations where multiple explanations are plausible and you need a
systematic way to evaluate them — metric discrepancies, unexpected business outcomes,
theoretical-vs-actual gaps, cross-system behavioral differences, and similar investigative
work.

## Phase 1: Problem Clarification

Before analyzing anything, establish what you're actually looking at. Ambiguous problem
definitions lead to wasted investigation. Ask the user to clarify (or extract from context):

1. **What phenomenon was observed?** — The specific symptom, not the user's theory about it.
   Separate the observable fact ("Feb ROI dropped to -14%") from the interpretation ("the model
   lost its edge").
2. **Where was it observed?** — Dashboard, query, log, user report. Get the exact source URL
   or query.
3. **How can it be reproduced or confirmed?** — Exact steps, queries, filters, or conditions.
4. **What is the precise measurement criteria?** — Numbers, thresholds, time ranges, cohort
   definitions, and critically: **what are the constraints/scope?** (e.g., which strategy, which
   time period, which trigger type). Vague criteria must be sharpened before proceeding.
5. **What background context affects interpretation?** — Were there operational changes during
   the period? Manual interventions? Configuration changes? Policy shifts? These often explain
   more than the data alone suggests, and the user is usually the only one who knows about them.

Do not proceed until you and the user agree on what the problem actually is. A well-defined
problem is half the solution.

## Phase 2: Data Foundation & Reproduction

This phase has two parts that must both succeed before moving to hypotheses.

### 2A: Data Integrity Validation

Before trusting any numbers, validate the data pipeline that produces them. This step exists
because a wrong join, a missing filter, or a misunderstood field definition can invalidate
an entire analysis — and the error won't be visible in the results, only in the methodology.

Check for:
- **Join logic correctness** — Are table joins complete? Could records be missed by an
  incomplete join path? (e.g., taker-only vs taker+maker joins producing 14% vs 55% fill rates)
- **Field semantics** — Do the fields mean what you think they mean? Check for nulls, edge
  cases, and enum values that change meaning over time.
- **Filter alignment** — Are the same filters (time range, strategy, status) applied
  consistently across all queries that will be compared?
- **Aggregation level** — Are you comparing apples to apples? (order-level vs amount-level,
  distinct vs non-distinct counts, etc.)

If any integrity issue is found, fix it before proceeding. An analysis built on bad data
will produce confident-sounding wrong conclusions.

### 2B: Reproduction & Baseline

Attempt to reproduce the phenomenon through data queries, operations, or observation. The goal
is to confirm the problem actually exists and isn't a measurement artifact.

- Run the relevant queries against verified data sources (Metabase, database, dashboards).
- **Cross-validate against reference sources** — If the metric being computed exists on a
  known dashboard or report, compare your calculated value against that reference before
  presenting. If they disagree (even in sign), investigate the discrepancy rather than
  presenting your number as truth. Dashboard definitions often encode business logic
  (filters, join paths, aggregation rules) that raw queries miss.
- Produce a **factual data summary** — the raw numbers with no interpretation. This becomes
  the shared baseline everyone references.
- If the problem cannot be reproduced, that itself is an important finding — investigate why.

**CHECKPOINT — STOP HERE.** Share the data summary with the user and **wait for explicit
approval** before proceeding to hypothesis generation. Do not launch verification agents or
move to Phase 3 until the user confirms the baseline numbers are correct. This gate exists
because an analysis built on wrong baseline numbers will produce confident-sounding wrong
conclusions — and the user is often the only person who can spot a sign error or missing
filter by comparing against their operational knowledge.

## Phase 3: Hypothesis Generation & Adversarial Review

Generate **3 to 5 hypotheses** that could explain the observed phenomenon. Quality matters
more than quantity.

### Orthogonality

Hypotheses should point to genuinely different root causes, not variations of the same idea.
Bad: "the query is wrong" + "the query filter is wrong" + "the query join is wrong" (these are
one hypothesis). Good: "adverse selection by counterparties" vs "stake sizing concentrates
capital on losing picks" vs "execution slippage from stale prices."

### Completeness

Together, the hypotheses should cover the plausible explanation space. Ask yourself: if all
hypotheses are rejected, what would remain unexplained? If there's an obvious gap, add a
hypothesis for it.

### Verification Design

For each hypothesis, define a specific verification method — what data to check, what query to
run, what comparison to make. The verification must be **sufficient and necessary**:
- **Sufficient:** If the verification passes, the hypothesis is confirmed (not just consistent).
- **Necessary:** If the hypothesis is true, the verification must pass (rules out coincidence).

Pay special attention to:
- **Calculation criteria** — Are numerator/denominator definitions exactly right? Are time
  windows aligned? Are filters consistent?
- **Logic chain completeness** — Does A actually imply B, or is there a missing link? Watch
  for proxy variables that seem like direct measures but aren't (e.g., "fill rate" as a proxy
  for "market efficiency" conflates market structure with execution policy).
- **Confound separation** — If hypotheses share variance (e.g., selection and sizing effects
  both correlate with the same picks), the verification method must isolate each factor's
  independent contribution. Consider within-stratum comparisons, counterfactual
  decompositions, or Shapley-value approaches.

### Adversarial Self-Review

Before presenting hypotheses to the user, do an adversarial review pass:

1. **Challenge orthogonality** — Are any hypotheses actually the same root cause in disguise?
   Merge or replace.
2. **Challenge completeness** — Is there an obvious explanation nobody considered? Add it.
3. **Challenge verification logic** — Could a verification pass for the wrong reason? Could it
   fail even when the hypothesis is correct? Tighten the method.
4. **Challenge assumptions** — What implicit assumptions does each hypothesis make? Are they
   warranted? Pay special attention to mechanism claims — "X causes Y" requires more than
   "X correlates with Y."
5. **Challenge ordering effects** — If verification methods are sequential (waterfall
   decomposition), would a different ordering change the attribution? If so, use order-invariant
   methods (Shapley values, stratified analysis) instead.

### Output Format

Present to the user as a numbered list:

```
### Hypothesis [N]: [Short Title]

**Explanation:** [Why this could cause the observed phenomenon]

**Verification Method:** [Specific steps, queries, or comparisons to confirm/reject]

**Key Assumptions:** [What must be true for this hypothesis to hold]

**Confounds to Control For:** [Other hypotheses or factors that share variance with this one]
```

## Phase 4: User Review Checkpoint

**Stop and wait for the user's approval before verification.**

Present all hypotheses with their verification plans. The user may:
- Approve all and proceed
- Reject or modify certain hypotheses
- Add hypotheses you missed (they often have domain knowledge you don't)
- Correct mechanism assumptions (e.g., "stakes aren't model-confidence-driven — we manually
  scaled them based on daily event count")
- Adjust verification methods based on data access or feasibility

This checkpoint is critical. The user's operational knowledge often reveals that the
mechanism you assumed is wrong, even when the statistical pattern is real. Getting the
mechanism right changes both the verification method and the actionable conclusion.

## Phase 5: Parallel Hypothesis Verification

Launch verification of each approved hypothesis in parallel using subagents (Agent tool).
Each subagent receives:

- The problem description and factual data summary from Phase 2
- Its assigned hypothesis and verification method from Phase 3
- Access to the same data tools (Metabase, database, etc.)
- Instructions to execute the verification and report structured results

### Subagent Adversarial Review

Each subagent must perform up to **3 rounds of self-review** on its verification process:

1. **Round 1 — Execution check:** Did I actually execute the verification as designed, or
   did I take shortcuts? Are the query results what the verification method asked for?
2. **Round 2 — Logic check:** Does my data actually support my conclusion, or am I seeing
   what I want to see? Could the same data support the opposite conclusion? Am I confusing
   correlation with causation?
3. **Round 3 — Edge case check:** Did I consider boundary conditions, null data, time zone
   issues, sampling bias, join completeness, or other subtle pitfalls that could silently
   invalidate my results?

If any round reveals a flaw, the subagent corrects and re-verifies before reporting.

### Subagent Prompt Template

```
You are verifying a specific hypothesis about an observed phenomenon.

## Problem Context
[Problem description and factual data summary]

## Your Hypothesis
[Hypothesis N: title and explanation]

## Verification Method
[Specific steps to execute]

## Data Access
[Available tools: Metabase queries, database access, etc.]

## Instructions
1. Execute the verification method exactly as designed.
2. Record all data, queries, and intermediate results — show your work.
3. Perform 3 rounds of adversarial self-review on your work.
4. Report your conclusion using the structured format below.

## Output Format
### Hypothesis: [Title]
**Verification Conditions:** [What would confirm/reject this hypothesis]
**Analysis & Data:** [What you actually found — tables, numbers, comparisons]
**Self-Review Notes:** [Key challenges from your adversarial review rounds]
**Conclusion:** CONFIRMED | REJECTED | INCONCLUSIVE
**Confidence:** HIGH | MEDIUM | LOW
**Reasoning:** [Why you reached this conclusion]
**Magnitude:** [Quantify the effect size if confirmed — how many pp, what % of total gap]
```

### Cross-Hypothesis Synthesis

After all subagents complete, synthesize across results:

- **Check for double-counting** — If a sequential/waterfall decomposition was used, factors
  that go first absorb shared variance. Compare against order-invariant methods. The factor
  that appears dominant can flip depending on ordering.
- **Quantify each factor's independent contribution** — Use Shapley values, stratified
  counterfactuals, or similar decomposition when hypotheses share variance.
- **Verify the sum** — Individual factor contributions should sum to the total observed gap
  (within rounding). If they overcount (sum > 100%), the decomposition has confounds.

## Phase 6: Results Documentation

Collect all subagent results and synthesize into a single structured report.

### Output Targets

By default, write to a local markdown file. The user may request:
- **Notion page/subpage** — Use notion-create-pages for structured documentation
- **GitHub issue** — For actionable findings with priority ordering
- **Both** — Notion for the full analysis, GitHub issue for the action items

### Report Structure

```markdown
# Problem Analysis Report

## Problem Statement
[What was observed, where, and how it was reproduced]

## Scope & Constraints
[Time period, strategy, filters, and any operational context]

## Factual Data Summary
[Key numbers from Phase 2, with no interpretation]

## Hypotheses & Verification Results

### Hypothesis 1: [Title] — [CONFIRMED/REJECTED/INCONCLUSIVE]
- **Logic:** [Why this could explain the phenomenon]
- **Verification Conditions:** [What was tested]
- **Analysis & Data:** [What was found — tables, numbers]
- **Magnitude:** [Effect size, % of total gap]
- **Conclusion:** [Verdict with confidence level]

### Hypothesis 2: [Title] — [CONFIRMED/REJECTED/INCONCLUSIVE]
...

## Factor Decomposition
[Order-invariant attribution if multiple factors confirmed — Shapley values or equivalent]

## Overall Conclusion
[Which hypotheses were confirmed, the root cause ranking, and the interaction between factors]

## Recommended Actions (sorted by priority)
[For each confirmed hypothesis: what to do, expected impact, effort level]

## Open Questions
[Anything that remains uncertain or warrants further investigation]

## Data Integrity Notes
[Any join issues, calculation corrections, or methodology caveats discovered during analysis]
```

### Synthesizing Across Hypotheses

After documenting individual results:
- If exactly one hypothesis is confirmed → that's your conclusion.
- If multiple are confirmed → they are likely co-contributing causes. Quantify the independent
  contribution of each (decomposition), explain the interaction, and rank by magnitude for
  action priority.
- If none are confirmed → the hypothesis space was incomplete. Propose new hypotheses for a
  second round (return to Phase 3).
- If results are inconclusive → identify what additional data would resolve the ambiguity.

## When to Loop Back

This process is iterative. Return to earlier phases when:
- **Phase 2A finds data integrity issues** → Fix the data pipeline, re-run reproduction.
  Do not trust any prior analysis built on bad data.
- **Phase 2B fails to reproduce** → Return to Phase 1, sharpen the definition.
- **Phase 4 user review reveals mechanism errors** → Adjust hypotheses and verification methods.
- **Phase 5 rejects all hypotheses** → Return to Phase 3, generate new ones.
- **Phase 5 reveals the problem is different from what was assumed** → Return to Phase 1.
- **Phase 5 finds a new data integrity issue** → Return to Phase 2A. This can happen when
  subagent deep-dives reveal join bugs or calculation errors not caught in the initial check.

Loops frequently happen across conversation boundaries — the user discovers new context
overnight, a data bug surfaces days later, or operational knowledge emerges that changes the
mechanism story. When resuming a prior analysis, start by reviewing the current state of
conclusions and checking whether the data foundation is still valid before adding new work
on top.

The goal is a confirmed explanation with evidence, not a forced conclusion.
