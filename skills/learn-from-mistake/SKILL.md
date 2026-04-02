---
name: learn-from-mistake
description: >-
  Retrospective learning from past sessions — extract patterns where the user
  corrected, redirected, or intervened on Claude's approach, then persist each
  lesson as a memory update or skill improvement. Use this skill when the user
  says "learn from mistakes", "what did I correct", "review last session",
  "extract lessons", "what patterns should we save", or wants to turn recent
  session corrections into durable knowledge. Also use proactively after a
  session with many user corrections, or when the user says /learn-from-mistake.
---

# Learn from Mistake

A retrospective workflow that mines recent session transcripts for moments where
the user corrected your behavior, then helps turn those corrections into durable
knowledge — either project/workspace memory or skill updates.

The core insight: every time a user says "no, not that", "I told you before",
or redirects your approach, that's a lesson worth preserving so it never needs
to be repeated.

## Workflow

### Step 1 — Find the sessions to analyze

Ask the user what to review. There are two modes:

**Topic mode** — the user names a topic or keyword:
```bash
python3 ~/.claude/skills/recall/scripts/recall.py "QUERY" --limit 10
```

**Recent mode** (default) — review the last ~1 hour of sessions:
```bash
find ~/.claude/projects/ -name "*.jsonl" -mmin -60 2>/dev/null | grep -v '/subagents/'
find ~/.codex/sessions/ -name "*.jsonl" -mmin -60 2>/dev/null
```

If the user specifies a time window (e.g., "last 3 hours", "today"), adjust
`-mmin` accordingly (180 for 3h, 1440 for 24h).

If no sessions are found, widen the window or ask the user for a topic to search.

### Step 2 — Read the transcripts

For each session file found, read the transcript:
```bash
python3 ~/.claude/skills/recall/scripts/read_session.py <file_path>
```

For large sessions (>300 messages), read just the first 150 and last 100 to
keep context manageable. Use subagents to read multiple sessions in parallel
when there are more than 2.

### Step 3 — Extract intervention patterns

Scan each transcript for **intervention signals** — places where the user
corrected, redirected, or expressed dissatisfaction with Claude's approach.

Look for these signal categories:

| Signal type | Examples |
|---|---|
| **Direct correction** | "no", "wrong", "that's not right", "don't do that" |
| **Redirection** | "instead do X", "use Y not Z", "I meant...", "what I actually want is..." |
| **Repeated instruction** | "I already said...", "again?", "I told you before", "as I mentioned" |
| **Frustration** | "stop", "why did you...", "that's not what I asked", "ugh" |
| **Approach override** | "skip that", "just do X", "too complicated", "simpler please" |
| **Explicit teaching** | "the way this works is...", "the convention here is...", "we always do X because..." |

For each intervention found, extract:
1. **What Claude did wrong** — the action or assumption that triggered the correction
2. **What the user wanted instead** — the correct approach
3. **Why** — the reasoning behind the correction, if stated
4. **Scope** — is this specific to one task, or a general pattern?

### Step 4 — Present findings

Present the extracted patterns as a numbered list. For each pattern:

```
### Pattern N: [short title]

**What happened:** Claude did X
**User correction:** "actual user quote"
**Lesson:** Do Y instead of X because Z
**Scope:** [project-specific | cross-project | general behavior]
**Suggested action:** [workspace AGENTS.md | generic memory | skill update | both | skip]
**Target:** [e.g., workspace/bounce/AGENTS.md | memory/feedback_xxx.md | skill-name]
```

Group related corrections together — if the user corrected the same thing 3
times across sessions, that's one pattern with strong signal, not three separate
ones.

After presenting, ask the user:
> "For each pattern, I can: (a) save it to the relevant workspace AGENTS.md,
> (b) save as generic memory, (c) update a specific skill, or (d) skip it.
> What would you like to do?"

The user may respond per-pattern or give a blanket instruction.

### Step 5 — Persist the lessons

#### Option A: Save as project/workspace knowledge

Lessons belong where they'll be seen next time the relevant context is active.
The personal-assistant repo organizes knowledge by workspace — each project has
its own `AGENTS.md` that Claude reads when working in that context.

**Placement rules (in priority order):**

1. **Project-specific lesson** → append to that workspace's `AGENTS.md`.
   The personal-assistant repo has workspaces at `workspace/<project>/AGENTS.md`
   (e.g., `workspace/bounce/AGENTS.md`, `workspace/jim/AGENTS.md`). If the
   lesson is about Bounce data analysis, it goes in `workspace/bounce/AGENTS.md`
   — not in a generic memory file.

2. **Cross-project / general behavior lesson** → save as a memory file in
   `~/.claude/projects/-Users-aki-Projects-personal-assistant/memory/` and
   update `MEMORY.md`.

3. **Skill-specific lesson** → update the skill directly (see Option B).

**When appending to AGENTS.md**, group related lessons under a section header
(create one if it doesn't exist). Use bullet-point format with a bold label,
the rule, and a brief origin note:

```markdown
## Lessons Learned (from [context], [date])

- **[Bold label]**: [The rule or pattern to follow]. Origin: [brief description
  of what went wrong and when].
```

Check the existing AGENTS.md first — if a related lesson is already there,
update it rather than adding a duplicate.

**When saving to generic memory**, use the standard frontmatter format:

```markdown
---
name: [descriptive-kebab-case-name]
description: [one-line — specific enough to judge relevance later]
type: [feedback|user|project|reference]
---

[The lesson, stated as a clear rule or fact]

**Why:** [The user's reasoning, or the incident that triggered this]
**How to apply:** [When and where this guidance kicks in]
```

After writing, update `MEMORY.md` with a one-line index entry.

#### Option B: Update a skill

If the lesson maps to a specific skill's behavior:

1. Identify which skill needs updating (ask the user if unclear)
2. Read the current SKILL.md
3. Propose the specific edit — show the before/after diff
4. Apply only after user confirms

Common skill updates from intervention patterns:
- Adding a "gotcha" or warning section
- Adjusting default behavior
- Adding a decision branch the skill was missing
- Fixing incorrect assumptions in the skill's instructions

#### Option C: Skip

No action needed — the correction was situational and doesn't generalize.

### Step 6 — Summarize

After all patterns are processed, give a brief summary:
- N patterns found
- M saved to workspace AGENTS.md (list which workspace + lesson)
- P saved as generic memory (list which)
- K applied as skill updates (list which skill)
- J skipped

## Edge cases

- **No interventions found:** Tell the user "No corrections or redirections
  found in the reviewed sessions — looks like things went smoothly." Offer to
  widen the search window or try a different topic.

- **Ambiguous patterns:** If you're not sure whether something is a correction
  or just normal conversation flow, include it but mark it as "uncertain" and
  let the user decide.

- **Contradictory corrections:** If the user corrected in opposite directions
  across sessions (e.g., "be more verbose" then "be more concise"), flag the
  contradiction and ask the user which one to persist.

- **Already-saved lessons:** Cross-reference against existing workspace
  AGENTS.md files and generic memories. If a pattern is already captured, tell
  the user: "This is already saved in [location] — want me to update it with
  the new context?"
