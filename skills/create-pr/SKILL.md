---
name: create-pr
description: "Create a GitHub pull request for current branch changes. Only use when the user explicitly asks to create a PR, push and create PR, or submit changes for review. Do NOT use proactively."
---

## Workflow

1. **Detect and run project checks** (if available):
   - Look for: `Makefile` (check/lint/format targets), `package.json` (lint/test scripts), `.pre-commit-config.yaml`, or CI config
   - Run the project's check/lint/format command if found. Fix auto-fixable issues
   - If unfixable issues remain, report to user and stop
   - If no check commands found, skip this step

2. **Commit changes** to the current branch:
   - Stage relevant files (avoid secrets, `.env`, large binaries)
   - Write a concise commit message summarizing the changes

3. **Push** the current branch:
   - Set upstream if not already tracking a remote branch (`git push -u origin <branch>`)

4. **Create a draft PR** (if one doesn't already exist for this branch):
   - Use `gh pr create --draft`
   - Infer related issue from branch name if it contains an issue number (e.g. `fix-42`, `feature/123-auth`, `42-bug`)
   - Title: concise summary of changes
   - Body: summary bullets + test plan (do **not** rely on `Fixes #...` / `Refs #...` keywords for issue linkage)

5. **Bind issue and PR via `gh api` (mandatory when related issue exists)**:
   - Do this **after** PR creation and **instead of** content-based linking in PR body.
   - Use `gh api` to create explicit linkage metadata/event between issue and PR.
   - Minimum requirement: create an issue timeline linkage event via API call (e.g., GraphQL `addComment` on the issue containing the PR URL/number and a stable machine prefix like `PR-LINK:`).
   - Recommended sequence:
     - Resolve issue number and PR number/url.
     - Resolve issue node id: `gh issue view <issue_number> --json id --jq .id`
     - Create linkage event:
       - `gh api graphql -f query='mutation($subjectId:ID!, $body:String!){addComment(input:{subjectId:$subjectId, body:$body}){clientMutationId}}' -f subjectId='<issue_node_id>' -f body='PR-LINK: <pr_url>'`
   - Verify linkage by checking issue timeline/comments via `gh api`/`gh issue view`.
