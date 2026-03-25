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
   - Body: summary bullets + test plan
   - If a related issue exists, include `Closes #<issue_number>` in the PR body
   - If the PR already exists and the closing keyword is missing, use `gh pr edit --body-file` to add it

5. **Verify issue linkage via GitHub's PR/issue reference fields** (mandatory when related issue exists):
   - Do this **after** PR creation or PR body edit.
   - Do **not** use issue comments such as `PR-LINK:` as the default linkage mechanism.
   - Preferred linkage mechanism is the PR body closing keyword:
     - `Closes #<issue_number>`
   - Verify the linkage through GraphQL fields rather than comments:
     - PR side:
       - `gh api graphql -f query='query($owner:String!, $repo:String!, $num:Int!){ repository(owner:$owner, name:$repo){ pullRequest(number:$num){ closingIssuesReferences(first:20){ nodes { number title url } } } } }' -F owner='<owner>' -F repo='<repo>' -F num=<pr_number>`
     - Issue side:
       - `gh api graphql -f query='query($owner:String!, $repo:String!, $num:Int!){ repository(owner:$owner, name:$repo){ issue(number:$num){ closedByPullRequestsReferences(first:20){ nodes { number title url state isDraft } } } } }' -F owner='<owner>' -F repo='<repo>' -F num=<issue_number>`
   - Success criteria:
     - the PR includes the target issue in `closingIssuesReferences`
     - the issue includes the PR in `closedByPullRequestsReferences`

6. **Wait for CI checks and deployment** (after PR creation or push):
   - Dispatch a **background subagent** to watch all CI checks and Railway deployments:
     - Use `gh pr checks <pr_number> --watch` to block until all checks settle
     - After watch completes, collect final status of all checks
     - Check for Railway deployment completion by inspecting PR comments or status checks for deployment URLs
   - When the subagent reports back:
     - If **all checks pass** and deployment succeeded: report success with check summary and deployment URL
     - If **any checks failed** or deployment failed: proceed to step 7

7. **Fix failed checks loop** (automatic when failures detected):
   - If any CI checks failed or deployment errors occurred:
     - Invoke `/fix-pr-issues` skill directly — it handles: fetching failed checks + review comments, BDD-first spec updates if needed, planning, implementing fixes, pushing, and polling until green
   - After `/fix-pr-issues` completes:
     - If all checks are now green: done
     - If checks still fail or new review issues appeared: re-invoke `/fix-pr-issues` (loop)
   - **Max loop iterations:** 3 — if still failing after 3 rounds, report the remaining failures to the user and stop
   - **Do not** attempt to fix `temporal-idle-gate` failures (this check is excluded from required checks)
