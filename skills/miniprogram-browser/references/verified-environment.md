# Verified Environment

Last verified from the local session on `2026-03-31`.

## Machines

- Local control session runs on the Mac
- The reachable SSH entry is:

```text
hardfun@192.168.238.203
```

- This lands in WSL on the Windows host
- The Windows-native SSH user `yutia@192.168.238.203` was not required for the verified flow

## Default Mini Program Path

WSL path:

```text
/home/hardfun/Projects/jim.ai/apps/chat-miniprogram/dist
```

Windows UNC path:

```text
\\wsl.localhost\Ubuntu-20.04\home\hardfun\Projects\jim.ai\apps\chat-miniprogram\dist
```

Verified facts:

- Windows PowerShell can `Get-Item -LiteralPath` this UNC path
- WeChat DevTools CLI can `open --project` this UNC path
- `project.config.json` in that directory includes:

```text
projectname = chat-miniprogram
appid = wx3bceaff7cfc4f12a
```

## Windows Tooling

WeChat DevTools CLI:

```text
C:\Program Files (x86)\Tencent\微信web开发者工具\cli.bat
```

Node.js was verified under a WinGet install path. Do not hardcode a single exact version in workflow logic. Resolve `node.exe` dynamically when possible.

The current runner directory that already contains `miniprogram-automator` is:

```text
C:\Users\yutia\Projects\miniprogram-automator-smoke
```

## Port Behavior

WeChat DevTools service port and `.ide/.cli` files are Windows-side state.

Important observation:

- A WSL `127.0.0.1:9420` socket probe was not a reliable source of truth
- Windows-side `Get-NetTCPConnection -State Listen -LocalPort 9420` was the reliable indicator

Use the helper script to start and verify `9420`.

## Verified UI Flow

This flow was successfully reproduced:

1. Tap tab text `即时疗愈`
2. Tap card CTA text `聊聊心里话`
3. On `pages-chat/chat-character/index`, swipe the Taroify swiper track left twice
4. Confirm `壮壮` is visible
5. Tap `选择TA`
6. On the chat page, tap the left-bottom keyboard toggle
7. Wait for `#message-sender-textarea`
8. Input text
9. Tap the right-bottom send icon
10. Extract the returned reply text

Observed returned reply body:

```text
（把刚晒暖的松果轻轻推到你手边）
看到你来，壮壮心里像升起一小片阳光 🌞
你不需要“准备好”，就这样来，就很好。💛
```

## Known UI Heuristics

Current verified chat page heuristics:

- keyboard toggle icon is a no-text `view` near left-bottom
- after toggling, `#message-sender-textarea` appears
- send icon is a no-text `view` near right-bottom
- a successful send clears the textarea value

These are heuristics, not contracts. Re-probe with `offset()`, `size()`, and visible text if the UI changes.

## Taro/Skyline Rendering Limitations

The jim.ai miniprogram uses Taro compiled to Skyline renderer. This has critical implications for automator:

- In the current automator build, `page.data()` returns a usable rendered tree under `root.cn`
- `page.$$('view')` can return non-zero results, but `page.$$('text')` is still unreliable
- `page.wxml()` is **not guaranteed**; current build may throw `TypeError: page.wxml is not a function`
- `miniProgram.screenshot()` **hangs indefinitely**
- `page.windowProperty()` throws `Cannot read property 'map' of null`

Current best practice:

- prefer `page.data()` first
- search the serialized tree for visible text
- inspect nearby `sid` values to derive tappable IDs
- use `page.wxml()` only if you have already confirmed that the current build exposes it

Example live observation from `pages/plan-home/index`:

- `page.data()` returned the full Taro tree, including visible text like `AI规划助手`, `暂未登录`, `去登录`
- `page.$$('view')` returned `121` elements
- `page.$$('text')` returned `0`
- `page.wxml()` was unavailable

## Navigation Notes (2026-03-31)

- `miniProgram.switchTab('/pages/plan-home/index')` works
- `miniProgram.reLaunch('/pages/plan-home/index')` string form works
- object form like `reLaunch({ url: ... })` can fail with `parameter.url should be String instead of Object`
- direct `navigateTo('/pages/login/index')` can time out in the current build
- if that happens, prefer locating and tapping the visible `去登录` CTA from the page tree

## Auth Notes (2026-03-31)

- writing `refresh_token` directly into storage is not enough to prove authenticated UI state
- the backend can accept `/service/auth/refresh-token` while the Mini Program still shows `暂未登录`
- for jim.ai, real authenticated verification should prefer the login-page flow that sets both:
  - persisted `refresh_token`
  - in-memory `access_token`

## Port 9420 Stability

Observed failure modes (2026-03-28/29):

1. `ensure_port_9420` reports ready, but WS connection hangs — stale process holding port
2. DevTools spontaneously closes WS after extended session (~10+ minutes of inactivity)
3. PowerShell `$PID` variable collision when scripting process kills

Recovery: kill all port holders → fresh `ensure_port_9420` → raw WS verify before automator.

## Domain Whitelist

`wx.request()` from the miniprogram runtime only works for whitelisted domains:

- `qingsu.chat` — works
- `jimai.bomoon.fun` (staging) — **blocked** (`url not in domain list`)
- `jim-staging.moon-bo.com` — **blocked**

To verify API responses, use `curl` via SSH on dev-server, not `wx.request` from within the miniprogram.

## Verified Bug Verification Flows (2026-03-28/29)

These E2E flows ran successfully:

1. **Task card content**: connect → `pages/plan-home/index` → `page.wxml()` → search for task `value` text
2. **Auto-send message**: connect → `pages-chat/chat-character/index` → select character → `pages-chat/chat/index` → verify first auto-sent message text
3. **Weekly progress popup**: connect → `switchTab('/pages/plan-home/index')` → `page.wxml()` search `本周进展` → `page.$('#_LI').tap()` → inspect popup wxml
4. **Badge list (logged-out)**: `wx.clearStorage()` → `navigateTo('/pages-other/badge-list/index')` → verify via API fallback (automator selectors failed)
