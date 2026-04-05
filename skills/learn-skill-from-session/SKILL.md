---
name: learn-skill-from-session
description: >-
  Mine recent session transcripts for repeatable workflows, multi-step processes,
  and SOPs that can be extracted as new reusable skills. Classifies candidates as
  user-level (cross-project) or project-specific, assesses extraction value, and
  guides creation of new skills from validated patterns. Use this skill when the
  user says "find skills from sessions", "extract workflows", "what can we turn
  into a skill", "mine sessions for patterns", "learn skills from recent work",
  "what repeatable processes did I do", or uses /learn-skill-from-session. Also
  consider using proactively after a long session that involved a complex
  multi-step workflow, or during periodic skill-garden maintenance.
---

# Learn Skill from Session

A retrospective workflow that mines recent session transcripts for repeatable
multi-step processes, then helps turn them into new reusable skills — or enriches
existing ones.

The core insight: when the same sequence of tools, queries, and decisions appears
across multiple sessions (or even within one session as a clearly generalizable
pattern), that's a workflow worth capturing as a skill so it never needs to be
reinvented from scratch.

This skill complements `learn-from-mistake` — that one captures **corrections**
(what not to do), this one captures **workflows** (what to do, and how).

## Workflow

### Step 1 — Find sessions to analyze

Ask the user what to review. Two modes:

**Topic mode** — the user names a topic or keyword:
```bash
python3 ~/.claude/skills/recall/scripts/recall.py "QUERY" --limit 10
```

**Recent mode** (default) — review the last ~3 hours of sessions:
```bash
find ~/.claude/projects/ -name "*.jsonl" -mmin -180 2>/dev/null | grep -v '/subagents/'
find ~/.codex/sessions/ -name "*.jsonl" -mmin -180 2>/dev/null
```

If the user specifies a time window (e.g., "last 24 hours", "today"), adjust
`-mmin` accordingly.

Filter out subagent files at this stage — they're children of parent sessions and
will be analyzed in context when reading the parent. If no sessions are found,
widen the window or ask the user for a topic to search.

### Step 2 — Read the transcripts

For each session file found, read the transcript:
```bash
python3 ~/.claude/skills/recall/scripts/read_session.py <file_path>
```

For large sessions (>300 messages), read the first 150 and last 100 to keep
context manageable. Use subagents to read multiple sessions in parallel when
there are more than 2.

### Step 3 — Extract workflow patterns

Scan each transcript for **repeatable workflow signals** — sequences of actions
that form a coherent process someone would want to repeat.

Look for these signal categories:

| Signal type | What to look for |
|---|---|
| **Multi-step orchestration** | 3+ distinct tool calls chained together to accomplish one goal (e.g., query DB → read code → draft plan → dispatch implementation) |
| **Existing skill composition** | Multiple skills invoked in sequence as a larger workflow (e.g., `/recall` → `/dispatch-task-on-dev-server` → `/fix-pr-issues`) |
| **Manual SOP** | The user gave step-by-step instructions that Claude followed — this is a process the user already knows but hasn't automated |
| **Repeated subprocess** | The same tool sequence appeared 2+ times within one session or across sessions |
| **Timed/polling patterns** | Periodic checks at intervals (e.g., "check every 10 minutes", monitor deploy health) |
| **Data pipeline** | Fetch from source A → transform → write to destination B |
| **Diagnostic workflow** | Triage → investigate → fix → verify cycle with a specific domain (e.g., cron health, deploy check) |

For each workflow pattern found, extract:

1. **Name** — a short descriptive title (e.g., "Post-Deploy Production Monitor")
2. **Steps** — the ordered sequence of actions, tools, and decisions
3. **Inputs** — what parameters/context the workflow needs to start
4. **Outputs** — what the workflow produces (report, file, PR, etc.)
5. **Scope** — user-level (works across projects) or project-specific (tied to one domain)
6. **Frequency** — how often this workflow would be reused (one-off, weekly, per-PR, per-deploy)
7. **Existing coverage** — which parts are already handled by existing skills
8. **Automation potential** — what percentage of steps can be fully automated vs requiring human judgment

### Step 4 — Assess extraction value

Not every workflow is worth extracting. Apply these filters:

**Strong candidates** (extract as skill):
- High frequency: runs weekly or more, or per-event (per-PR, per-deploy)
- Mostly mechanical: >70% of steps are deterministic tool calls
- Multi-step: 4+ distinct steps that are easy to forget or get wrong
- Not already covered by an existing skill

**Weak candidates** (document as operational knowledge, not a skill):
- One-off: the workflow was specific to a single incident
- Judgment-heavy: >50% of steps require creative/strategic human decisions
- Already covered: an existing skill handles 80%+ of the workflow
- Simple: fewer than 3 steps, easily remembered

**Anti-patterns** (skip entirely):
- The workflow was a debugging session for a specific bug
- The process was exploratory research without a repeatable structure
- The "workflow" is just a single tool call with different parameters

### Step 5 — Cross-check existing skills

Before recommending new skills, check what already exists:

```bash
ls ~/.agents/skills/ | sort
```

For each candidate, compare against existing skills:
- **Full overlap** — an existing skill already does this. Recommend enriching it instead.
- **Partial overlap** — existing skills cover sub-steps. The new skill would orchestrate them. This is valuable — orchestration skills reduce the burden on the user.
- **No overlap** — genuinely new workflow. Strongest candidate for extraction.

### Step 6 — Present findings (READ-ONLY — do NOT write anything yet)

Present the extracted patterns as a structured report. For each candidate:

```
### Candidate N: [name]

**Workflow:** [1-2 sentence description]
**Steps:**
  1. [step with tool/command]
  2. ...
**Inputs:** [what it needs]
**Outputs:** [what it produces]
**Scope:** [user-level | project-specific (which project)]
**Frequency:** [how often reused]
**Existing coverage:** [which existing skills cover sub-steps, or "none"]
**Extraction value:** [HIGH | MEDIUM | LOW] — [1-line justification]
**Recommended action:** [create new skill | enrich existing skill X | document in AGENTS.md | skip]
```

Group candidates by scope:
1. User-level skills (cross-project)
2. Project-specific skills (grouped by project)

After listing all candidates, provide a priority-ranked summary:

```
## Extraction Priority

| # | Candidate | Value | Action |
|---|-----------|-------|--------|
| 1 | [name]    | HIGH  | Create new skill |
| 2 | [name]    | MED   | Enrich existing skill X |
| ...
```

**CRITICAL: STOP HERE AND WAIT FOR USER APPROVAL.**

Do NOT create, edit, or modify any files. The analysis report IS the deliverable
at this step.

Ask the user:
> "Which of these should I extract? For each approved candidate, I can:
> (a) create a new skill via /skill-creator,
> (b) enrich an existing skill with the new workflow steps,
> (c) document as operational knowledge in the relevant AGENTS.md, or
> (d) skip.
> Please tell me which candidates to proceed with and how."

**When running as a scheduled/automated task (user not present):** End here.
Output the analysis report only. Never create skills without explicit user
approval in the chat.

### Step 7 — Execute approved extractions (ONLY after user approval)

**Gate:** Only execute after the user has explicitly approved specific candidates.

#### Option A: Create new skill

Invoke `/skill-creator` with the extracted workflow as context. Provide:
- The skill name, description, and trigger phrases
- The ordered step sequence from the analysis
- Input/output specifications
- Which existing skills it should compose/orchestrate
- Any edge cases observed in the session transcripts

After the skill is created, run `/skill-symlink-correctness` to ensure proper
wiring between `.agents/skills/` and `.claude/skills/`.

#### Option B: Enrich existing skill

1. Read the existing skill's SKILL.md
2. Propose specific additions — new workflow steps, additional triggers, or
   a new section for the discovered subprocess
3. Show the before/after diff
4. Apply only after user confirms

#### Option C: Document as operational knowledge

For workflows that are too judgment-heavy or infrequent for a full skill, append
to the relevant workspace AGENTS.md:

```markdown
## Operational Workflows

### [Workflow Name]
**When:** [trigger condition]
**Steps:**
1. [step]
2. ...
**Notes:** [gotchas, edge cases observed]
```

#### Option D: Skip

No action — the pattern was situational or too simple.

### Step 8 — Summarize

After all approved candidates are processed:
- N workflow patterns found in analysis
- M created as new skills (list names)
- P enriched existing skills (list which)
- K documented in AGENTS.md (list where)
- J skipped

## Edge cases

- **No workflows found:** "No repeatable workflows found in the reviewed
  sessions — the work was mostly one-off or exploratory. Try a wider time
  window or search for a specific topic."

- **Workflow spans multiple sessions:** If the same process appears across
  sessions, consolidate into a single candidate and note all source sessions.

- **Workflow partially exists as a skill:** This is common and valuable — the
  gap between what the skill covers and what the user actually did is exactly
  what should be added.

- **User's manual steps contradict existing skill:** Flag the divergence. The
  user may have a good reason for doing it differently, or the skill may need
  updating.

- **Too many candidates:** If >8 workflows are found, present only the top 5
  by extraction value. Mention the others briefly and offer to elaborate.
