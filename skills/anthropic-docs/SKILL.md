---
name: anthropic-docs
description: Use when the user asks how to use Claude Code, the Claude Code Agent SDK, Anthropic API features, or Claude model selection and needs current official documentation with citations. Always browse official Anthropic or Claude docs first, restrict sources to official Anthropic-owned domains, and use bundled references only as entry-point hints.
---

# Anthropic Docs

Provide authoritative, current guidance from official Anthropic and Claude documentation. There is no dedicated Anthropic docs MCP in this environment, so start with web browsing on official domains instead of answering from memory.

## Quick start

- Use `web.search_query` with `domains` restricted to official Anthropic-owned domains.
- Expect `docs.anthropic.com` entry URLs to redirect to newer canonical docs on `code.claude.com` for Claude Code and `platform.claude.com` for Agent SDK and API docs.
- Read `references/official-pages.md` only when you need likely entry URLs or the current domain map.
- Cite the final canonical page you land on after redirects, not just the initial search result.

## Supported scope

1. Claude Code: setup, quickstart, commands, slash commands, settings, permissions, hooks, MCP, subagents, workflows, troubleshooting, security.
2. Claude Code Agent SDK: overview, headless mode, TypeScript, Python, permissions, MCP, streaming, tool use, multi-agent patterns.
3. Anthropic API and models: model selection, platform release notes, pricing, features, current product behavior.

## Official domains

Use only these unless the user explicitly asks otherwise:

- `docs.anthropic.com`
- `code.claude.com`
- `platform.claude.com`
- `anthropic.com`
- `github.com/anthropics/claude-code` only when official release-note pages redirect there or point to the official changelog

Do not use community tutorials, mirrors, summaries, or forum posts as primary sources for Anthropic product guidance.

## Workflow

1. Clarify whether the request is about Claude Code, the Agent SDK, API/models, or release notes.
2. If you need likely entry pages, read `references/official-pages.md`.
3. Search with precise queries and official-domain filters. Prefer one narrow query over one broad query.
4. Open the best result and follow redirects to the canonical page.
5. If current behavior is unclear, compare two official pages and say what is directly documented versus what you infer.
6. For "latest", "current", or "recent" questions, verify by browsing and include exact dates in the answer when possible.

## Search patterns

Use patterns like these:

- `site:code.claude.com/docs/en <topic>`
- `site:platform.claude.com/docs/en/agent-sdk <topic>`
- `site:platform.claude.com/docs/en/release-notes <topic>`
- `site:docs.anthropic.com/en/docs <topic>`
- `site:anthropic.com <topic>`
- `site:github.com/anthropics/claude-code <topic>` only for official Claude Code changelog or release-note redirects

## Quality rules

- Treat current official Anthropic docs as the source of truth.
- Do not answer volatile Anthropic product questions from memory when browsing can verify them.
- Prefer docs pages over marketing pages; prefer product docs over blogs.
- Keep quotes short and within policy limits; prefer paraphrase with links.
- If official docs do not cover the user's need, say so explicitly and separate inference from documentation.
- When the docs differ across pages, cite both and state the difference clearly.

## Reference map

- `references/official-pages.md`
  Current entry points for Claude Code, Agent SDK, release notes, and model-selection docs, plus notes on current redirects as of 2026-03-25.
