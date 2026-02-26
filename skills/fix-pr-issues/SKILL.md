---
name: fix-pr-issues
description: Fix review issues and failed checks in a pull request.
---

Goal: Fix the pr issues, feedback comments and all failed checks on the current PR.

1. Use `gh` CLI to fetch all **unresolved** inline code reviews, comments, and check status on the current PR.
2. Analyze each issue for urgency, validity, outdated context, and impact.
3. Read related issues/PRs as background context when needed.
4. **BDD-first requirement when a real code issue is confirmed:**
   - Use `behavior-spec-writing` to update the existing feature spec (and affected core spec if needed) so the reported behavior is explicitly covered.
   - Lint updated `.feature` files with `gherkin-lint`.
   - Use `behavior-spec-to-ci-checks` to update/add tests and CI checks so the behavior is enforced by automated checks.
5. Use `superpowers:writing-plans` to write an implementation plan for the approved fix scope.
6. Use `superpowers:executing-plans` to implement the plan and fix the issues.
7. Run targeted tests and required checks to verify the fix and spec/check alignment.
8. Use `gh api` to mark related review threads as resolved; hide comments only when confirmed fixed or no longer applicable.
9. Commit and push all validated fixes before finishing.
10. **Mandatory completion gate:** after push + thread resolve, keep polling PR status for up to **15 minutes** with three conditions:
    - required checks excluding `temporal-idle-gate` are all green (`pass`);
    - `codex-review-gate` is `pass`;
    - after `codex-review-gate` first becomes `pass`, wait an additional **5 seconds** and re-check unresolved code review threads (must stay at `0` / not increase).
11. If timeout is reached, or unresolved code comments reappear/increase, do not claim task complete; report blockers explicitly and keep task status as blocked.

## Required polling behavior

- Start polling immediately after Step 8-9.
- Poll every 10-15 seconds.
- Stop only when:
  - all required checks except `temporal-idle-gate` are green, `codex-review-gate` is pass, and unresolved code comments are still stable/zero after the extra 5s wait, or
  - max wait time (15 minutes) is reached.
- During polling, re-query unresolved review threads; if new unresolved issues appear, stop waiting and return to fix loop immediately.
- Do **not** ignore `codex-review-gate`; only ignore `temporal-idle-gate`.

## Suggested command pattern

Use a bounded loop so the skill does not exit early:

```bash
start_ts=$(date +%s)
timeout_sec=$((15*60))
initial_unresolved="$(
  gh api graphql -F owner="$OWNER" -F name="$REPO_NAME" -F number="$PR_NUMBER" \
    -f query='query($owner:String!, $name:String!, $number:Int!){ repository(owner:$owner, name:$name){ pullRequest(number:$number){ reviewThreads(first:100){ nodes { isResolved } } } } }' \
    --jq '[.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved==false)] | length'
)"
while true; do
  gh pr checks "$PR_NUMBER" --required || true

  unresolved_now="$(
    gh api graphql -F owner="$OWNER" -F name="$REPO_NAME" -F number="$PR_NUMBER" \
      -f query='query($owner:String!, $name:String!, $number:Int!){ repository(owner:$owner, name:$name){ pullRequest(number:$number){ reviewThreads(first:100){ nodes { isResolved } } } } }' \
      --jq '[.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved==false)] | length'
  )"
  if (( unresolved_now > initial_unresolved )); then
    echo "new unresolved review issues detected"
    exit 1
  fi

  checks_json="$(gh pr checks "$PR_NUMBER" --required --json name,bucket)"
  required_pass_excluding_temporal="$(
    echo "$checks_json" | jq -r '
      [.[] | select(.name != "temporal-idle-gate")]
      | if length==0 then "true" else (all(.[]; .bucket=="pass")|tostring) end
    '
  )"
  codex_pass="$(
    echo "$checks_json" | jq -r '
      ([.[] | select(.name=="codex-review-gate" and .bucket=="pass")] | length) > 0
    '
  )"

  if [[ "$required_pass_excluding_temporal" == "true" && "$codex_pass" == "true" ]]; then
    echo "required checks are green (ignoring temporal-idle-gate), codex-review-gate is pass; waiting 5s for comment recheck"
    sleep 5

    unresolved_after_codex="$(
      gh api graphql -F owner="$OWNER" -F name="$REPO_NAME" -F number="$PR_NUMBER" \
        -f query='query($owner:String!, $name:String!, $number:Int!){ repository(owner:$owner, name:$name){ pullRequest(number:$number){ reviewThreads(first:100){ nodes { isResolved } } } } }' \
        --jq '[.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved==false)] | length'
    )"
    if (( unresolved_after_codex > initial_unresolved )); then
      echo "new unresolved review issues detected after codex pass"
      exit 1
    fi
    echo "completion gate satisfied"
    break
  fi

  now_ts=$(date +%s)
  if (( now_ts - start_ts >= timeout_sec )); then
    echo "timeout waiting for non-gate checks (15m)"
    exit 1
  fi
  sleep 12
done
```
