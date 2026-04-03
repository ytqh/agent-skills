---
name: chrome-applescript
description: Control Google Chrome via AppleScript using the user's real login session. Navigate pages, extract content, execute JavaScript, interact with elements, manage tabs, and take screenshots — all with full access to the user's cookies and authenticated sessions. macOS only.
---

# Chrome AppleScript — Browser Automation with Real Login State

Control Chrome via AppleScript to leverage the user's actual authenticated sessions. Unlike Playwright or other automated browsers, this approach uses the real Chrome instance with all cookies, extensions, and login state intact.

## Prerequisites

Enable JavaScript from Apple Events in Chrome:

**Chrome > View > Developer > Allow JavaScript from Apple Events** (check it)

## Quick Start

```bash
CHROME=~/.agents/skills/chrome-applescript/scripts/chrome.sh

# Navigate and extract
$CHROME goto https://example.com
$CHROME get-text

# Open in new tab
$CHROME open https://x.com/user/status/123

# Extract text, scroll, extract more
$CHROME get-text
$CHROME scroll-bottom
sleep 2
$CHROME get-text

# Execute custom JavaScript
$CHROME eval "document.title"
$CHROME eval "document.querySelectorAll('article').length"

# Take screenshot
$CHROME screenshot /tmp/page.png
```

## Why Use This Over Playwright / agent-browser

| Feature | chrome-applescript | Playwright / agent-browser |
|---|---|---|
| Uses real login session | Yes | No (isolated profile) |
| Cookies & auth preserved | Yes | No (needs re-login) |
| Detected as bot | No | Often yes |
| Extensions available | Yes | No |
| Headless mode | No (real Chrome) | Yes |
| Cross-platform | macOS only | Cross-platform |

**Use this when:** you need to access authenticated pages (X/Twitter, Gmail, internal tools, etc.) using the user's existing login.

**Use Playwright when:** you need headless automation, cross-platform support, or don't need authentication.

## Commands Reference

### Navigation

```bash
$CHROME get-url                     # Get active tab URL
$CHROME get-title                   # Get active tab title
$CHROME goto <url>                  # Navigate active tab
$CHROME open <url>                  # Open URL in new tab
$CHROME reload                      # Reload active tab
$CHROME back                        # Go back
$CHROME forward                     # Go forward
```

### Content Extraction

```bash
$CHROME get-text                    # Get full page text (innerText)
$CHROME get-html                    # Get full HTML source
$CHROME get-text-selector "div.content"  # Get text of specific element
$CHROME get-links                   # Get all links as JSON array
```

### JavaScript Execution

```bash
# Simple expression
$CHROME eval "document.title"

# Complex JS via stdin (avoids shell quoting issues)
echo 'JSON.stringify(Array.from(document.querySelectorAll("h2")).map(h => h.textContent))' | $CHROME eval-stdin
```

### Interaction

```bash
$CHROME click-selector "button.submit"        # Click element
$CHROME fill-selector "input[name=email]" "user@example.com"  # Fill input
$CHROME scroll-down 500                       # Scroll down 500px
$CHROME scroll-bottom                         # Scroll to page bottom
$CHROME scroll-top                            # Scroll to top
```

### Tab Management

```bash
$CHROME tabs                        # List all open tabs
$CHROME tab-select 2                # Switch to tab 2
$CHROME tab-close                   # Close active tab
```

### Wait

```bash
$CHROME wait 3                      # Wait 3 seconds
$CHROME wait-for "#content" 10      # Wait for element (up to 10s)
```

### Screenshots

```bash
$CHROME screenshot                  # Screenshot to /tmp/
$CHROME screenshot ./page.png       # Screenshot to specific path
```

## Example: Scrape Authenticated Page

```bash
CHROME=~/.agents/skills/chrome-applescript/scripts/chrome.sh

# Navigate to an authenticated page (user is already logged in)
$CHROME goto "https://x.com/user/status/123456"
sleep 3

# Extract full page content
$CHROME get-text > /tmp/thread.txt

# Scroll and get more
$CHROME scroll-bottom
sleep 2
$CHROME get-text > /tmp/thread-full.txt

# Extract specific elements
echo 'JSON.stringify(Array.from(document.querySelectorAll("article")).map(a => a.innerText))' | $CHROME eval-stdin
```

## Example: Multi-Page Workflow

```bash
CHROME=~/.agents/skills/chrome-applescript/scripts/chrome.sh

# Open multiple tabs
$CHROME open "https://site-a.com/dashboard"
$CHROME open "https://site-b.com/settings"

# List tabs
$CHROME tabs

# Switch between tabs
$CHROME tab-select 1
$CHROME get-text > /tmp/page1.txt
$CHROME tab-select 2
$CHROME get-text > /tmp/page2.txt
```

## Limitations

- **macOS only** — relies on AppleScript
- **Chrome only** — does not work with Safari, Firefox, or other browsers
- **Requires "Allow JavaScript from Apple Events"** to be enabled
- **No headless mode** — Chrome must be running and visible
- **No fine-grained element targeting** — uses CSS selectors, not accessibility refs
- **Shell quoting** — for complex JS, use `eval-stdin` to pipe via stdin
