---
name: miniprogram-browser
description: Use when reproducing, operating, validating, or end-to-end testing a WeChat Mini Program through dev-server-win and WeChat DevTools automation. Use this whenever the user wants to click through a mini program, verify page behavior, capture reply text, debug a flow, or test a WSL-built `chat-miniprogram/dist`, even if they mention only 微信小程序, 小程序页面, dev-server-win, 聊愈, or miniprogram-automator.
---

# Miniprogram Browser

## Overview

Drive the Windows WeChat DevTools on `dev-server-win` from the local session, then connect to the Mini Program with `miniprogram-automator`.

This skill is for real behavior verification, not static code review. Use it to open the Mini Program, click through flows, send chat input, inspect visible text, and confirm end-to-end behavior.

## Default Target

Unless the user explicitly provides another target, use this UNC path:

```text
\\wsl.localhost\Ubuntu-20.04\home\hardfun\Projects\jim.ai\apps\chat-miniprogram\dist
```

This maps to the WSL build output:

```text
/home/hardfun/Projects/jim.ai/apps/chat-miniprogram/dist
```

## Verified Environment

Read [verified-environment.md](./references/verified-environment.md) before the first run in a session.

Key facts:

- Control path is through `hardfun@192.168.238.203` (WSL), not `yutia@192.168.238.203`
- WeChat DevTools CLI lives on Windows
- `miniprogram-automator` runs on Windows and connects to `ws://127.0.0.1:9420`
- The stable workflow is:
  1. Start `cli auto` in the background
  2. Wait for Windows-side port `9420`
  3. Run a separate automator script that only connects and acts

## Standard Workflow

### 1. Verify the target path

Confirm the WSL path exists and contains a Mini Program build:

- `project.config.json`
- `app.json`
- page bundles under `pages*`

Do not assume the build exists just because the source repo exists.

### 2. Ensure port `9420`

Always start or refresh the automation port with:

```bash
python /Users/aki/.agents/skills/miniprogram-browser/scripts/ensure_port_9420.py
```

Override the target project when needed:

```bash
python /Users/aki/.agents/skills/miniprogram-browser/scripts/ensure_port_9420.py \
  --project '\\wsl.localhost\Ubuntu-20.04\home\hardfun\Projects\other-app\dist'
```

Important:

- Trust the Windows-side `Get-NetTCPConnection` result from the script
- Do not use a WSL `127.0.0.1:9420` probe as the source of truth
- **`ensure_port_9420` reporting `ready` does NOT guarantee the WebSocket is connectable.** A stale DevTools process can hold port 9420 in ESTABLISHED state without accepting new connections.
- **`ensure_port_9420` may report `PORT_NOT_READY` even when the listener comes up a few seconds later.** Observed on 2026-04-18: the first run after a kill reported failure, but a raw WS probe moments later succeeded. Always re-probe with the raw WebSocket test before concluding a real failure.

If the first `automator.connect` hangs or times out after `ensure_port_9420` succeeds:

1. Verify with a raw WebSocket test (connect to `ws://127.0.0.1:9420` with bare `ws` module, 10s timeout)
2. If the raw WS test fails, **kill ALL `wechatdevtools` processes on Windows — not just the one holding port 9420.** A stale DevTools GUI instance that does not show up in `Get-NetTCPConnection -LocalPort 9420` can still block a fresh `cli auto` from binding. Killing only the 9420-holding process leaves orphaned GUI instances that block re-launch. Verified one-liner (run from Mac Air):

    ```bash
    ssh -o BatchMode=yes dev-server-win 'powershell -Command "Get-Process -Name wechatdevtools -ErrorAction SilentlyContinue | Stop-Process -Force; Start-Sleep 3; Get-Process -Name wechatdevtools -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"'
    # Expect output: 0
    ```

3. Re-run `ensure_port_9420.py` to start a fresh `cli auto` background job
4. Verify again with the raw WS test before running automator scripts (do not trust a `PORT_NOT_READY` report alone — re-probe first)

This nuke-all-then-restart cycle is the **only reliable recovery** when connections hang. Verified during the P0.5 miniprogram UI smoke test on 2026-04-18 after multiple false starts where killing only the 9420-holding process was insufficient.

### 3. Run a focused automator script

Use the Windows runner helper:

```bash
python /Users/aki/.agents/skills/miniprogram-browser/scripts/run_dev_server_win_js.py <<'EOF'
const automator = require("miniprogram-automator");
(async () => {
  const miniProgram = await automator.connect({ wsEndpoint: "ws://127.0.0.1:9420" });
  const page = await miniProgram.currentPage();
  console.log(JSON.stringify({ path: page.path, query: page.query }, null, 2));
})();
EOF
```

Write short, single-purpose scripts. Prefer:

- one script to probe state
- one script to perform a user flow
- one script to inspect the result

Do not combine `cli auto` startup and long interaction logic in the same JS file unless you have a specific reason.

### 4. Validate step by step

After each meaningful action:

- re-read `currentPage()`
- inspect the rendered tree using the **currently working DOM surface** (see DOM inspection below)
- assert the expected path or text is present before continuing

Example checks:

- after tapping `即时疗愈`, expect `pages/home/index`
- after tapping `聊聊心里话`, expect `pages-chat/chat-character/index`
- after selecting a character, confirm the expected name appears before tapping `选择TA`
- after sending, confirm the textarea cleared or the input state changed

## DOM Inspection — Prefer `page.data()`, fall back to `page.wxml()`

The jim.ai miniprogram uses **Taro + Skyline** rendering. This makes most standard automator APIs non-functional:

| API | Status | Detail |
|-----|--------|--------|
| `page.data()` | **CURRENT PRIMARY PATH** | In the current automator build, returns the rendered Taro tree under `root.cn`. Use recursive string search and nearby `sid` values. |
| `page.wxml()` | BUILD-DEPENDENT | Older verified sessions exposed it; current build may return `TypeError: page.wxml is not a function`. Use only if present. |
| `page.$$('view')` | PARTIALLY WORKS | In the current build it can return non-zero results on some pages. Do not assume `text` nodes are exposed the same way. |
| `page.$$('text')` | UNRELIABLE | Often returns 0 even when text is visible in `page.data()`. |
| `page.windowProperty()` | BROKEN | `Cannot read property 'map' of null` |
| `miniProgram.screenshot()` | BROKEN | Hangs indefinitely (both absolute and relative paths) |
| `wx.createSelectorQuery()` via evaluate | BROKEN | Also hangs |
| `document.body.innerText` via evaluate | BROKEN | Returns `null` |

Current working inspection pattern:

```js
const page = await miniProgram.currentPage();
const data = await page.data();
const dump = JSON.stringify(data);
const hasTarget = dump.includes('本周进展');
```

When `page.data()` works, use it first. Search for visible text in the serialized tree and inspect nearby `sid` values to derive tappable element IDs. Only use `page.wxml()` when you have confirmed that the current automator build exposes it.

## Page Navigation Rules

Tabbar pages (`pages/home/index`, `pages/plan-home/index`, etc.) **cannot** use `navigateTo`. Use:

| Target | Method |
|--------|--------|
| Tabbar page | `miniProgram.switchTab('/pages/plan-home/index')` or `miniProgram.reLaunch('/pages/home/index')` |
| Non-tabbar page | `miniProgram.navigateTo('/pages-other/badge-list/index')` |
| Reset to known state | `miniProgram.reLaunch('/pages/home/index')` |

`reLaunch` clears the page stack and works for any page. Prefer it when normalizing state.

Important:

- In the current build, passing an object like `{ url: '/pages/plan-home/index' }` to `reLaunch` can trigger `parameter.url should be String instead of Object`
- prefer the string form shown above unless you have already confirmed the object form works in the current session

Verified navigation map:

```
reLaunch('/pages/home/index')           → 即时疗愈 tab (home)
switchTab('/pages/plan-home/index')     → AI规划助手 tab (plan)
navigateTo('/pages-other/badge-list/index')  → 技能徽章
navigateTo('/pages-chat/chat-character/index') → 角色选择
navigateTo('/pages/login/index')        → 登录页
```

## State Simulation

### Simulate logged-out state

```js
await miniProgram.evaluate(() => wx.clearStorage());
await miniProgram.reLaunch({ url: '/pages/home/index' });
```

Or remove only the auth token:

```js
await miniProgram.evaluate(() => wx.removeStorageSync('refresh_token'));
```

### User identity matters

The DevTools session runs as a specific miniprogram user. If verifying data that was generated for specific users (e.g., weekly reports), the DevTools session must be logged in as one of those users. Check storage for `refresh_token` to confirm identity.

Do not equate `refresh_token` presence with successful login. A written `refresh_token` can coexist with anonymous UI state if the runtime never executes the real login flow that sets the in-memory `access_token`.

## Interaction Patterns

### Element tapping

Two verified approaches for tapping elements:

1. **By ID** (when available from `wxml()` inspection): `page.$('#_LI').tap()`
2. **By visible text in `page.data()`**: recursively search the rendered tree, find the nearest ancestor `sid`, then tap it with `page.$('#<sid>').tap()`

Prefer exact visible text matches for taps:

- `即时疗愈`
- `聊聊心里话`
- `选择TA`

When multiple matches exist, choose the bottom-most relevant hit because repeated labels may exist in hidden or duplicated layout trees.

To find tappable element IDs, search the `page.wxml()` output for the target text and look for nearby `id=` attributes.

In the current build, prefer searching the `page.data()` tree for text and reading nearby `sid` values. The serialized `data.root.cn` tree is often enough to locate the right tappable node.

Example strategy:

```js
const data = await page.data();
const dump = JSON.stringify(data);
// Find text first, then inspect nearby sid in the structured tree
```

### Character selection page

The character page uses a Taroify swiper track:

```text
.taroify-swiper__track
```

It is not a native Mini Program `swiper` component in the verified flow, so do not assume `swiper.swipeTo()` will work.

Use touch events on `.taroify-swiper__track`:

- `touchstart`
- `touchmove`
- `touchend`

Verified heuristic for the default order:

1. first card: `晓晴 Sunny`
2. second card: `阿澄 Jim`
3. third card: `壮壮`

Two left swipes from the default position reach `壮壮`.

If selector-based swipe setup fails, inspect the page tree first and only then issue touch events. Do not assume the same swiper node ID across sessions.

### Chat page input

Verified flow on the current app:

- open chat page
- tap the left-bottom keyboard toggle area
- wait for `#message-sender-textarea` to appear
- use `textarea.input(...)`
- tap the right-bottom send icon

Important:

- The send icon is a no-text `view`, not a text button
- A successful send clears the textarea value
- After sending, collect visible text again and compare against the baseline

If the current automator build does not expose stable text selectors, use the same fallback as above:

- inspect `page.data()`
- identify the candidate `sid`
- tap by `page.$('#<sid>')`

### Reply extraction

When extracting the reply text, filter out static UI strings such as:

- `内容由AI生成，仅供参考`
- `继续对话，生成报告`
- `开启声音`
- `历史记录`
- `更换背景`
- `重启对话`
- `聊一聊`

Also exclude the user message itself.

If the reply streams in chunks, keep the longest candidate seen during polling rather than requiring an exact two-pass stable match.

## Analysis Expectations

When the user asks for verification, report:

1. which project path you used
2. whether `9420` was started successfully
3. each action you took
4. which page path you observed after each action
5. the final observed reply text or failure point

If the flow fails, include the first concrete failing boundary:

- port not listening
- path mismatch
- expected text missing
- textarea not found
- send icon not found
- reply not observed
- runtime stayed anonymous after token write
- login CTA present but direct `navigateTo('/pages/login/index')` timed out

## Common Pitfalls

- `cli auto` **must** run as a background PowerShell job. Foreground/inline `cli auto` never reliably brings up 9420.
- Use the helper scripts; hand-written PowerShell quoting is fragile
- The current page may already be inside chat when you attach; use `reLaunch` to normalize back to the expected start page before replaying a flow
- WSL and Windows do not always expose the same localhost state; prefer Windows-side checks for DevTools automation ports
- **Do not attempt `miniProgram.screenshot()`** — it hangs on Taro/Skyline pages. Use the working DOM surface for the current build (`page.data()` first, `page.wxml()` only if present).
- **Do not assume `page.wxml()` exists** — in the current build it may be absent while `page.data()` works
- **Do not assume `page.data()` is empty** — in the current build it returns the rendered Taro tree and is the best inspection path
- `page.$$('view')` may work while `page.$$('text')` does not; probe instead of assuming both are broken
- PowerShell kill scripts must avoid `$PID` as a variable name — it is a read-only automatic variable in PowerShell
- DevTools will spontaneously close WebSocket connections after extended sessions. Always be prepared to re-run the kill-restart cycle.
- `wx.request()` from within the miniprogram only works for whitelisted domains (currently `qingsu.chat`). Staging domains like `jimai.bomoon.fun` are NOT in the domain list.
- From WSL SSH you **cannot** `taskkill` DevTools GUI processes (`Access is denied`). The helper scripts work around this by using background PowerShell jobs.
- Writing `refresh_token` directly into storage does **not** guarantee authenticated UI state. For jim.ai, prefer the real login-page flow when a test needs a logged-in user.

## Files

- Environment notes: [verified-environment.md](./references/verified-environment.md)
- Port starter: [ensure_port_9420.py](./scripts/ensure_port_9420.py)
- Windows JS runner: [run_dev_server_win_js.py](./scripts/run_dev_server_win_js.py)
- Example eval prompts: [evals.json](./evals/evals.json)
