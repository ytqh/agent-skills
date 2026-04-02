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
**Scope:** [project-specific | workspace-wide | general behavior]
**Suggested action:** [memory | skill update | both | skip]
```

Group related corrections together — if the user corrected the same thing 3
times across sessions, that's one pattern with strong signal, not three separate
ones.

After presenting, ask the user:
> "For each pattern, I can: (a) save it as a memory so I remember next time,
> (b) update a specific skill, or (c) skip it. What would you like to do?"

The user may respond per-pattern or give a blanket instruction.

### Step 5 — Persist the lessons

#### Option A: Save as memory

Determine the right memory type based on the pattern:

| Pattern scope | Memory type | Example |
|---|---|---|
| How to approach work | `feedback` | "Don't mock the DB in integration tests" |
| User preferences/role | `user` | "User prefers terse output, no summaries" |
| Project context | `project` | "Auth rewrite is compliance-driven, not tech debt" |
| External resource pointer | `reference` | "Pipeline bugs tracked in Linear INGEST project" |

Write the memory file following the established format:

```markdown
---
name: [descriptive-kebab-case-name]
description: [one-line description — specific enough to judge relevance later]
type: [feedback|user|project|reference]
---

[The lesson, stated as a clear rule or fact]

**Why:** [The user's reasoning, or the incident that triggered this]
**How to apply:** [When and where this guidance kicks in]
```

Save to the appropriate memory directory. The default is the personal-assistant
project memory at:
`~/.claude/projects/-Users-aki-Projects-personal-assistant/memory/`

But if the pattern is specific to a different project, check whether that
project has its own memory directory under `~/.claude/projects/` and save there
instead.

After writing the memory file, update `MEMORY.md` with a one-line index entry.

Before writing, always check existing memories to avoid duplicates — if a
related memory exists, update it rather than creating a new one.

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
- M saved as memories (list which)
- K applied as skill updates (list which)
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

- **Already-saved lessons:** Cross-reference against existing memories. If a
  pattern is already captured, tell the user: "This is already saved in
  [memory-name] — want me to update it with the new context?"
