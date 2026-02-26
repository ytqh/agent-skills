---
name: issue-creator
description: "Create well-structured GitHub issues through guided clarification. Helps users clarify thinking, categorize issue type (feature/task/bug), structure the description with proper sections, then create the issue via `gh` CLI with labels, project linking, priority, and project-level Type. Use when the user wants to create an issue, report a bug, propose a feature, or file a change request. Triggers: 'create issue', 'file a bug', 'new feature request', 'open an issue', 'I want to propose...', 'there is a bug...', '创建issue', '提issue'"
---

# Issue Creator

Create well-structured GitHub issues through guided clarification dialogue, then publish via `gh` CLI with proper metadata.

## Process

### Phase 1: Clarify and Classify

Before structuring, clarify the issue through conversation. Ask questions **one at a time**.

**Step 1 — Detect repo and project context:**
- Run `gh repo view --json nameWithOwner,url -q .nameWithOwner` to get current repo
- Run `gh label list --json name -q '.[].name'` to get available labels
- If the user mentioned a specific repo, use `--repo OWNER/REPO`
- Discover linked GitHub Projects and fetch project fields (Priority, Status, Type options). Read [references/gh-project-api.md](references/gh-project-api.md) for the GraphQL API to:
  1. Discover projects linked to the repo
  2. Query field IDs for Priority, Status, and Type, including their available option names and IDs
- Cache the project ID, field IDs, and option mappings for use in Step 5-6 and Phase 3
- Query repository Issue Types (`Task`, `Bug`, `Feature`, etc.) and cache their IDs
  - Note: In many repos, the project UI "Type" column is backed by repository `issueType`, not a project single-select field.

**Step 2 — Classify issue type.** Ask the user:

> What type of issue is this?
> 1. **Feature** — new functionality or behavior change
> 2. **Task** — maintenance, refactor, process, or operational work
> 3. **Bug** — something is broken or behaving unexpectedly

**Step 3 — Guided clarification.** Ask one question at a time to fill in the required sections (see templates below). Use multiple-choice when possible. Cover:

- For **Feature/Task**: background context, what the change achieves, rough approach, potential side effects
- For **Bug**: what happened (symptoms), expected vs actual behavior, impact scope, reproduction steps if known

Keep probing until you have enough to write a clear issue. Prefer concise follow-ups over long question lists.

**Step 4 — Propose labels.** Based on the conversation, suggest labels from the repo's available labels. Let the user confirm or adjust.

**Step 5 — Suggest priority.** Use the priority options fetched from the GitHub Project in Step 1.

- If project priority options were found, present **only those options** to the user (do not hardcode or invent options that don't exist in the project).
- If no project is linked or the Priority field has no options, skip this step silently.

Example (options vary per project):

> What priority should this be?
> 1. **P0** — ...
> 2. **P1** — ...
> 3. **P2** — ...

**Step 6 — Resolve Type target (required when available).**

- First check project fields:
  - If project `Type` options were found, map the Step 2 classification to the corresponding option (`feature`, `task`, `bug`) using case-insensitive name matching.
  - If no exact match exists, present **only** the available project Type options and ask the user to pick one.
- If project `Type` field is missing, fall back to repository Issue Types:
  - Map Step 2 classification to repository `issueType` (`Feature` / `Task` / `Bug`) using case-insensitive name matching.
  - If no exact match exists, ask the user to choose from existing repository Issue Types.
- If neither project Type nor repository Issue Types are available, explicitly tell the user Type cannot be set (do not silently skip).

### Phase 2: Draft and Confirm

**Step 7 — Draft the issue.** Present the full issue (title + body) to the user for review using the appropriate template below. Ask for confirmation or edits.

#### Feature / Task Template

```markdown
## Background

[Why this change is needed. Context, motivation, links to related issues/discussions.]

## Goal

[What the change should achieve. Clear, measurable outcome.]

## Proposed Approach

[Brief description of the solution direction. Not a full design — just enough to scope the work.]

## Side Effects & Risks

[Potential impacts on existing functionality. Areas that need careful testing. Migration concerns if any.]

- [ ] Risk 1: ...
- [ ] Risk 2: ...
```

#### Bug Template

```markdown
## Symptoms

[What is happening. Observable behavior, error messages, screenshots if relevant.]

## Expected Behavior

[What should happen instead.]

## Impact

[Who/what is affected. Severity: data loss? degraded UX? blocking workflow?]

## Reproduction

[Steps to reproduce, if known. Environment details if relevant.]
```

### Phase 3: Create and Link

**Step 8 — Create the issue.**

```bash
gh issue create \
  --title "TITLE" \
  --body "BODY" \
  --label "label1,label2" \
  --assignee "@me"
```

Capture the issue URL and number from output.

**Step 9 — Link to project (if applicable).**

Using the project data already fetched in Step 1, read [references/gh-project-api.md](references/gh-project-api.md) for the GraphQL API to:
1. Add the issue to the project
2. Set Priority field using the cached field/option IDs from Step 1
   - Default behavior: leave project `Status` empty.
   - Only set project `Status` when the user explicitly asks for a specific status value.
3. Set Type using one of these paths:
   - Project Type field path: `updateProjectV2ItemFieldValue`
   - Repository Issue Type path: `updateIssue(input:{id, issueTypeId})`
4. Verify Type was actually applied by re-querying:
   - project item field value (if project Type path), or
   - `issue.issueType` (if repository Issue Type path)

If no projects were found in Step 1, skip this step silently.

**Step 10 — Report back.** Show the user:
- Issue URL
- Labels applied
- Project linkage status (if applicable)
- Priority set (if applicable)
- Status set status (if applicable): if not explicitly set, report it was intentionally left empty
- Type set status (required): value + source (`project field` or `repository issueType`)
- If Type could not be set, state exact blocker and next action needed

## Guidelines

- **Repo-agnostic**: Always detect repo from `gh` context or user input. Never hardcode repo names.
- **One question at a time**: Do not overwhelm the user with multiple questions per message.
- **Multiple choice preferred**: Easier to answer than open-ended.
- **Confirm before creating**: Always show the full draft and get explicit confirmation before running `gh issue create`.
- **Label from repo inventory**: Only suggest labels that exist in the repo. If none fit, ask if the user wants to create a new label.
- **Status defaults to empty**: Do not set project `Status` unless the user explicitly requests a specific status.
- **Type must be updated**: Do not finish without attempting Type update. Use project `Type` field first, then repository `issueType` fallback.
- **Type update must be verified**: After update, re-query and confirm the final Type value before reporting completion.
- **Minimal overhead**: For simple bugs, 2-3 clarifying questions may suffice. Scale depth to complexity.
