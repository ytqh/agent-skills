---
name: fix-pr-issues
description: Fix review issues and failed checks in a pull request.
---

Goal: Fix the pr issues, feedback comments and all failed checks on the current PR.

1. use `gh` cli to fetch the all **unresolved** inline code review, comments, checks status on the current PR.
2. analysis the issues, consider the urgency, if outdated and the importance of the issues
3. read realted issue as background context if needed.
4. use superpowers:write-plan skill to write the plan to determine the code changes needed to fix the issues. 
5. then use superpowers:exectue-plan skill to implement the plan and fix the issues.
6. use `gh` api mark related code review issues as resolved, hide the resolved comment if confirm the issues are fixed or not necessary to fix.
