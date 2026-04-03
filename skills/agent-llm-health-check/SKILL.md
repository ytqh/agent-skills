---
name: agent-llm-health-check
description: Use when the user asks whether Claude or Codex/OpenAI is currently down, degraded, impacted, or wants an official status-page confirmation of current incidents, outages, or service health.
---

# Agent LLM Health Check

## Overview

Confirm current official service health for Claude and Codex/OpenAI from vendor status pages only.
Answer what is happening now, not just what happened earlier in the day.

## Scope

- Claude: `https://status.claude.com`
- Codex/OpenAI: `https://status.openai.com`
- Use only official status pages and incident detail pages linked from them.
- Do not add local connectivity tests, API probes, social media reports, or third-party monitors unless the user explicitly asks for them.

## Tooling

- Prefer available browser or web-browsing tools that can read live pages.
- If a preferred browser CLI is unavailable, fall back to another live official-source browsing method.

## Workflow

1. Decide whether the user wants `Claude`, `Codex/OpenAI`, or both.
2. Open the relevant official status page.
3. Capture the current check time in both local time and UTC.
4. Read the homepage summary first.
5. If the page shows `active incident`, `degraded`, `investigating`, `identified`, `monitoring`, or another non-green state, open the relevant active incident page or pages.
6. Extract:
   - overall status
   - active incident titles
   - current incident state
   - posted or updated timestamps
   - impacted products or components
   - any workaround explicitly stated by the vendor
7. Distinguish clearly between:
   - current active issues
   - resolved historical incidents
8. If checking Codex via OpenAI status, say whether the issue is:
   - specifically marked against `Codex`, or
   - a broader OpenAI issue whose impact on Codex is not separately stated

## Output

Start with one sentence answering the user's question directly.

Then include:

- `Checked at`: local time and UTC
- `Official status`: overall page state
- `Active incidents`: `none`, or a short list
- `Impact`: affected products or components
- `Sources`: direct status-page links

## Guardrails

- Never treat a resolved history item as a current outage.
- Never say there is a current impact without tying it to what the status page shows now.
- For words like `today`, `now`, `currently`, or `目前`, always include absolute timestamps.
- If the page says fully operational or no known issues, say that explicitly.
- If the page is unavailable or blocked, say you could not verify from the official source.
- Do not collapse `Codex`, `ChatGPT`, and `OpenAI API` into one bucket unless the status page itself gives only a single combined signal.

## Trigger Examples

- `确认下 Claude 现在是不是挂了`
- `check if Codex has an official incident right now`
- `看一下 OpenAI status page 目前有没有影响 Codex`
- `帮我确认 Claude 官方状态页现在有没有已知故障`
