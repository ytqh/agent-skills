# Evidence Sources

Use these sources in descending order of authority for bug-state determination.

## 1. Original Bug Source

Examples:

- Notion bug page
- bug tracker row
- issue description

Use it to recover:

- title
- module
- expected broken behavior
- expected fixed behavior

If auth blocks access, do not stop. Move to local evidence.

## 2. Working Tree On dev-server

Start with:

```bash
ssh hardfun@192.168.238.203 'cd /path/to/repo && git status --short'
```

Why it matters:

- uncommitted diffs are the strongest signal that a fix is currently in progress
- file paths tell you which subsystem the bug belongs to

## 3. Recent Commits

Use:

```bash
ssh hardfun@192.168.238.203 'cd /path/to/repo && git log --oneline -n 20'
```

Then inspect only the commits that obviously touch the bug area.

Good signals:

- commit message names the symptom
- commit message names the module
- diff touches the exact field or navigation path described by the bug

## 4. tmux Sessions

Start with:

```bash
ssh hardfun@192.168.238.203 'tmux ls'
ssh hardfun@192.168.238.203 'tmux list-windows -t <session>'
ssh hardfun@192.168.238.203 'tmux capture-pane -p -S -250 -t <session>:<window>'
```

Strong signals:

- window title names the bug directly
- pane history includes root cause analysis
- pane history includes test results
- pane history includes files changed

Treat tmux output as a high-value hint. Confirm with code or runtime whenever possible.

## 5. Local Session Recall

Use when the direct bug source is unavailable or incomplete.

Useful queries:

- exact bug page ID
- title fragment
- module + symptom

What to extract:

- bug interpretation
- current status in tracker
- prior agent reasoning
- reproduction or fix steps already attempted

## 6. Runtime Verification

Use this to close the loop.

Examples:

- Mini Program UI bug: `miniprogram-browser`
- backend logic bug: targeted pytest / data query
- API bug: direct request / response inspection

Runtime evidence outranks speculation from code review.

## Choosing What To Trust

If sources disagree:

- prefer runtime over code comments
- prefer current working tree over stale tracker status
- prefer exact tmux transcript evidence over memory
- prefer explicit bug statement over inferred interpretation

If uncertainty remains, say so explicitly.
