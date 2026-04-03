#!/usr/bin/env bash
# chrome.sh — AppleScript-based Chrome automation using the user's real login session.
# Usage: chrome.sh <command> [args...]

set -euo pipefail

CMD="${1:-help}"
shift 2>/dev/null || true

case "$CMD" in

  # --- Navigation ---

  get-url)
    osascript -e 'tell application "Google Chrome" to get URL of active tab of window 1'
    ;;

  get-title)
    osascript -e 'tell application "Google Chrome" to get title of active tab of window 1'
    ;;

  goto)
    URL="$1"
    osascript -e "tell application \"Google Chrome\" to set URL of active tab of window 1 to \"$URL\""
    echo "Navigated to: $URL"
    ;;

  open)
    URL="$1"
    osascript <<EOF
tell application "Google Chrome"
  activate
  tell window 1
    make new tab with properties {URL:"$URL"}
  end tell
end tell
EOF
    echo "Opened new tab: $URL"
    ;;

  reload)
    osascript -e 'tell application "Google Chrome" to reload active tab of window 1'
    echo "Reloaded"
    ;;

  back)
    osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "history.back()"'
    echo "Navigated back"
    ;;

  forward)
    osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "history.forward()"'
    echo "Navigated forward"
    ;;

  # --- Content Extraction ---

  get-text)
    osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "document.body.innerText"'
    ;;

  get-html)
    osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "document.documentElement.outerHTML"'
    ;;

  get-text-selector)
    SELECTOR="$1"
    osascript -e "tell application \"Google Chrome\" to execute active tab of window 1 javascript \"document.querySelector('$SELECTOR')?.innerText || '(not found)'\""
    ;;

  get-links)
    osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "JSON.stringify(Array.from(document.querySelectorAll(\"a[href]\")).map(a => ({text: a.innerText.trim().substring(0,80), href: a.href})).filter(a => a.text && a.href.startsWith(\"http\")), null, 2)"'
    ;;

  # --- JavaScript Execution ---

  eval)
    JS="$1"
    osascript -e "tell application \"Google Chrome\" to execute active tab of window 1 javascript \"$JS\""
    ;;

  eval-stdin)
    JS=$(cat)
    osascript <<EOF
tell application "Google Chrome"
  execute active tab of window 1 javascript "$JS"
end tell
EOF
    ;;

  # --- Interaction ---

  click-selector)
    SELECTOR="$1"
    osascript -e "tell application \"Google Chrome\" to execute active tab of window 1 javascript \"document.querySelector('$SELECTOR')?.click()\""
    echo "Clicked: $SELECTOR"
    ;;

  fill-selector)
    SELECTOR="$1"
    VALUE="$2"
    osascript -e "tell application \"Google Chrome\" to execute active tab of window 1 javascript \"(function(){var el=document.querySelector('$SELECTOR');if(el){el.focus();el.value='$VALUE';el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}))}})()\""
    echo "Filled: $SELECTOR"
    ;;

  scroll-down)
    AMOUNT="${1:-500}"
    osascript -e "tell application \"Google Chrome\" to execute active tab of window 1 javascript \"window.scrollBy(0, $AMOUNT)\""
    echo "Scrolled down ${AMOUNT}px"
    ;;

  scroll-bottom)
    osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "window.scrollTo(0, document.body.scrollHeight)"'
    echo "Scrolled to bottom"
    ;;

  scroll-top)
    osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "window.scrollTo(0, 0)"'
    echo "Scrolled to top"
    ;;

  # --- Tab Management ---

  tabs)
    osascript <<'EOF'
tell application "Google Chrome"
  set output to ""
  set winCount to 0
  repeat with w in windows
    set winCount to winCount + 1
    set tabCount to 0
    repeat with t in tabs of w
      set tabCount to tabCount + 1
      set output to output & "[w" & winCount & ":t" & tabCount & "] " & (title of t) & linefeed & "  " & (URL of t) & linefeed
    end repeat
  end repeat
  return output
end tell
EOF
    ;;

  tab-select)
    INDEX="$1"
    osascript -e "tell application \"Google Chrome\" to set active tab index of window 1 to $INDEX"
    echo "Switched to tab $INDEX"
    ;;

  tab-close)
    osascript -e 'tell application "Google Chrome" to close active tab of window 1'
    echo "Closed active tab"
    ;;

  # --- Screenshots ---

  screenshot)
    OUTPUT="${1:-/tmp/chrome-screenshot-$(date +%s).png}"
    # Use screencapture on the Chrome window
    osascript -e 'tell application "Google Chrome" to activate'
    sleep 0.5
    WINDOW_ID=$(osascript -e 'tell application "Google Chrome" to id of window 1')
    screencapture -l "$WINDOW_ID" "$OUTPUT"
    echo "Screenshot saved: $OUTPUT"
    ;;

  # --- Wait ---

  wait)
    SECONDS="${1:-3}"
    sleep "$SECONDS"
    echo "Waited ${SECONDS}s"
    ;;

  wait-for)
    SELECTOR="$1"
    TIMEOUT="${2:-10}"
    for i in $(seq 1 "$TIMEOUT"); do
      FOUND=$(osascript -e "tell application \"Google Chrome\" to execute active tab of window 1 javascript \"!!document.querySelector('$SELECTOR')\"" 2>/dev/null || echo "false")
      if [ "$FOUND" = "true" ]; then
        echo "Found: $SELECTOR (after ${i}s)"
        exit 0
      fi
      sleep 1
    done
    echo "Timeout waiting for: $SELECTOR"
    exit 1
    ;;

  # --- Cookies ---

  get-cookies)
    DOMAIN="${1:-}"
    if [ -n "$DOMAIN" ]; then
      osascript -e "tell application \"Google Chrome\" to execute active tab of window 1 javascript \"document.cookie\""
    else
      osascript -e 'tell application "Google Chrome" to execute active tab of window 1 javascript "document.cookie"'
    fi
    ;;

  # --- Help ---

  help)
    cat <<'HELP'
chrome.sh — Control Chrome via AppleScript (uses real login session)

Prerequisites:
  Chrome > View > Developer > Allow JavaScript from Apple Events

Navigation:
  get-url                     Get active tab URL
  get-title                   Get active tab title
  goto <url>                  Navigate active tab to URL
  open <url>                  Open URL in new tab
  reload                      Reload active tab
  back / forward              Navigate history

Content:
  get-text                    Get page text (innerText)
  get-html                    Get full HTML
  get-text-selector <sel>     Get text of CSS selector
  get-links                   Get all links as JSON

JavaScript:
  eval <js>                   Execute JavaScript
  eval-stdin                  Execute JS from stdin (for complex scripts)

Interaction:
  click-selector <sel>        Click element by CSS selector
  fill-selector <sel> <val>   Fill input by CSS selector
  scroll-down [px]            Scroll down (default 500px)
  scroll-bottom               Scroll to page bottom
  scroll-top                  Scroll to page top

Tabs:
  tabs                        List all tabs
  tab-select <index>          Switch to tab by index
  tab-close                   Close active tab

Capture:
  screenshot [path]           Screenshot Chrome window

Wait:
  wait [seconds]              Wait N seconds (default 3)
  wait-for <selector> [timeout]  Wait for element (default 10s)

Other:
  get-cookies                 Get cookies for current page
  help                        Show this help
HELP
    ;;

  *)
    echo "Unknown command: $CMD"
    echo "Run 'chrome.sh help' for usage"
    exit 1
    ;;
esac
