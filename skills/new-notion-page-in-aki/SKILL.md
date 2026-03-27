---
name: new-notion-page-in-aki
description: Create a new page in Aki's personal Notion workspace Notes database. Use when the user asks to "save to Notion", "upload to Notion", "create a Notion page", "put this in my notes", "add to Notes database", or wants to persist a summary, analysis, report, or any structured content to their personal Notion. Also triggers on "写到Notion", "保存到笔记", "上传到Notion". This skill should be used proactively whenever the user has produced a substantial piece of content (analysis, report, summary) and asks to save or share it via Notion.
---

# Create New Page in Aki's Notion Notes Database

Creates a new page in Aki's personal "Notes" database in the Aki Notion workspace, formatting the content in Notion-flavored Markdown.

## Important: Workspace Selection

Aki has multiple Notion workspaces. This skill targets the **Aki** personal workspace, NOT the "心澄AI" workspace. The Notes database lives in the Aki workspace.

## Database Details

- **Database name:** Notes
- **Database ID:** `dc628348-8616-41a0-8a9e-318b7f2d6287`
- **Data source ID:** `54e31b79-7e36-4b9e-ac10-69894ddd2b65`

## Required MCP Tools

This skill requires the Notion MCP server to be connected. The key tools used:

1. `mcp__notion__notion-create-pages` — to create the page
2. `mcp__notion__notion-fetch` — to verify database schema if needed
3. `ReadMcpResourceTool` with `server: "notion"` and `uri: "notion://docs/enhanced-markdown-spec"` — to get the latest Notion markdown spec

## Step 1: Determine Content and Properties

From the user's request, extract:

- **Title** (`Name` property): A concise, descriptive title for the page
- **Date** (`Custom Date`): Default to today's date unless the user specifies otherwise
- **Tags** (optional): See **Tag Handling** below
- **Content**: The body of the page — the analysis, summary, report, or whatever the user wants to save

If the user says "upload above summary" or similar, gather the content from the current conversation context.

### Tag Handling

The `Tags` property is a `multi_select` field. **By default, do NOT attach any tags** unless the user explicitly requests tags or responds to a tag suggestion.

**Known existing tags:** `Diary`, `Monthly Review`, `Weekly Review`, `OKR`, `Communication`, `Writing`, `666`, `面试`, `绩效`, `bounce-autoresearch`

**Workflow:**

1. **User explicitly specifies tags** (e.g., "tag it as Writing" or "add tags: OKR, Communication"):
   - Use the requested tags directly.
   - If a requested tag does not exist in the known list, **create it anyway** — Notion `multi_select` auto-creates new options when you pass a new value.
   - Update the "known existing tags" list in this skill file after creating new tags so future invocations have an accurate list.

2. **User asks for tag suggestions** (e.g., "what tags should I use?" or "suggest tags"):
   - Analyze the page content and suggest 1–3 suitable tags from the known list.
   - Briefly explain why each tag fits.
   - Also suggest a new tag if none of the existing ones are a good match.
   - **Wait for the user to confirm or modify** before attaching tags.

3. **User says nothing about tags** (the default):
   - Do NOT attach any tags. Do NOT proactively suggest tags.
   - Just create the page without the `Tags` property.

## Step 2: Format Content as Notion-Flavored Markdown

Convert the content to Notion-flavored Markdown. Key formatting rules:

- Use `<table>` XML blocks for tables (NOT standard markdown tables — Notion requires `<table>`, `<tr>`, `<td>` format)
- Use `<details><summary>` for toggles/collapsible sections
- Use `<callout>` for callout blocks
- Use standard `#`, `##`, `###` for headings
- Use `- [ ]` for checkboxes
- Use `---` for dividers
- Use `**bold**`, `*italic*`, `` `code` `` as normal
- Color support: `{color="blue_bg"}` on blocks, `<span color="red">text</span>` inline
- Do NOT include the page title in the content body (it's set via properties)

### Table Format Example

```
<table fit-page-width="true" header-row="true">
	<tr color="blue_bg">
		<td>**Header 1**</td>
		<td>**Header 2**</td>
	</tr>
	<tr>
		<td>Cell 1</td>
		<td>Cell 2</td>
	</tr>
</table>
```

## Step 3: Create the Page

Use `mcp__notion__notion-create-pages` with:

```json
{
  "parent": {
    "data_source_id": "54e31b79-7e36-4b9e-ac10-69894ddd2b65"
  },
  "pages": [{
    "properties": {
      "Name": "<title>",
      "date:Custom Date:start": "<YYYY-MM-DD>",
      "date:Custom Date:is_datetime": 0
    },
    "icon": "<appropriate emoji>",
    "content": "<notion-flavored-markdown>"
  }]
}
```

**With tags** (only when user explicitly requests or confirms tags):

```json
{
  "parent": {
    "data_source_id": "54e31b79-7e36-4b9e-ac10-69894ddd2b65"
  },
  "pages": [{
    "properties": {
      "Name": "<title>",
      "date:Custom Date:start": "<YYYY-MM-DD>",
      "date:Custom Date:is_datetime": 0,
      "Tags": "[\"Writing\", \"NewTagName\"]"
    },
    "icon": "<appropriate emoji>",
    "content": "<notion-flavored-markdown>"
  }]
}
```

### Property Notes

- `Name` is the title property (type: `title`)
- `Custom Date` is a date property — use expanded format with `date:Custom Date:start`, `date:Custom Date:end` (optional), `date:Custom Date:is_datetime`
- `Tags` is a multi_select — pass as JSON array string, e.g. `"[\"Writing\"]"`
- `Mood` is a select — one of `Good`, `Normal`, `Bad`
- Icon should be a relevant emoji for the content topic

### Available Templates

If the content matches a known template category, you can use `template_id` instead of `content`:

- `ae19a1ea-84f5-432d-97fa-0306f2f3de1b` — 日记 (Diary)
- `7872e336-719d-4273-b374-db318e61dec3` — Week xx (Weekly review)
- `95b4246f-0a68-47dd-986e-4af6e8199b9b` — Thoughts
- `28ca8a14-09ed-489b-99ef-0681383b8cdf` — Writing
- `23ebc06b-64ff-807c-9287-f1b312963c84` — Bounce
- `23ebc06b-64ff-8066-a6d5-cff45f38b2c0` — 心澄

Most of the time you'll provide content directly rather than using a template.

## Step 4: Return the URL

After creation, return the Notion page URL to the user so they can verify it. The response from create-pages includes the page `id` and `url`.

## Tips

- For long content, break it into clear sections with headings
- Use toggles (`<details>`) for per-item details that would otherwise make the page too long
- Use colored table rows to highlight key items (e.g., `color="green_bg"` for best results, `color="red_bg"` for warnings)
- Keep callouts for important alerts or summaries
- If the Notion MCP connection is on a different server name (e.g., `claude_ai_Notion` vs `notion`), adapt the tool names accordingly — check which MCP tools are available
