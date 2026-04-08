#!/usr/bin/env python3
"""Pretty-print a Claude Code, Codex, or OpenCode session transcript."""

import json
import sqlite3
import sys
from pathlib import Path

TEXT_BLOCK_TYPES = {"text", "input_text", "output_text"}

SKIP_MARKERS = (
    "<user_instructions>",
    "<environment_context>",
    "<permissions instructions>",
    "# AGENTS.md instructions",
)

OPENCODE_DB_PATH = Path.home() / ".local" / "share" / "opencode" / "opencode.db"


def extract_text(content):
    """Extract plain text from message content (string or array format)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type", "") in TEXT_BLOCK_TYPES
        ]
        return "\n".join(filter(None, parts))
    return ""


def iter_messages(path, session_id=None):
    """Yield (role, text) pairs from a session file, auto-detecting format."""
    fmt = detect_format(path)

    if fmt == "opencode" and session_id:
        yield from iter_opencode_messages(session_id)
        return

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Skip Codex state snapshots (legacy)
            if entry.get("record_type") == "state":
                continue

            if fmt == "claude":
                # Resolve role from type or role fields
                role = entry.get("role", "")
                if role not in ("user", "assistant"):
                    etype = entry.get("type", "")
                    if etype in ("user", "human"):
                        role = "user"
                    elif etype == "assistant":
                        role = "assistant"
                    else:
                        continue

                # Claude wraps in entry.message.content
                content = entry.get("message", {})
                if isinstance(content, dict):
                    content = content.get("content", "")
                elif not isinstance(content, str):
                    content = entry.get("content", "")

            else:
                # Codex — handle both legacy and current (wrapped payload) formats
                etype = entry.get("type", "")

                if etype in ("session_meta", "event_msg", "turn_context"):
                    continue

                if etype == "response_item":
                    payload = entry.get("payload", {})
                    role = payload.get("role", "")
                    content = payload.get("content", "")
                else:
                    role = entry.get("role", "")
                    content = entry.get("content", "")

                if role not in ("user", "assistant"):
                    continue

            text = extract_text(content)
            if not text or any(marker in text for marker in SKIP_MARKERS):
                continue

            yield role, text


def detect_format(path):
    """Detect whether a session file is Claude Code, Codex, or OpenCode format."""
    # Check if path is the OpenCode database path
    if Path(path) == OPENCODE_DB_PATH:
        return "opencode"

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("record_type") == "state":
                return "codex"
            if "parentUuid" in entry or "message" in entry:
                return "claude"
            if "id" in entry and "instructions" in entry:
                return "codex"
            # Current Codex format uses type: "session_meta"
            if entry.get("type") == "session_meta":
                return "codex"
    return "claude"


def iter_opencode_messages(session_id):
    """Yield (role, text) pairs from an OpenCode session stored in SQLite."""
    if not OPENCODE_DB_PATH.exists():
        return

    try:
        conn = sqlite3.connect(f"file:{OPENCODE_DB_PATH}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            "SELECT data FROM message WHERE session_id = ? ORDER BY time_created",
            (session_id,),
        ).fetchall()

        for row in rows:
            try:
                msg = json.loads(row["data"])
            except (json.JSONDecodeError, TypeError):
                continue

            role = msg.get("role", "")
            if role not in ("user", "assistant"):
                continue

            text_parts = []

            # OpenCode stores content in summary.diffs
            summary = msg.get("summary") or {}
            if isinstance(summary, dict):
                diffs = summary.get("diffs", [])
            else:
                diffs = []
            for diff in diffs:
                if isinstance(diff, dict):
                    after_content = diff.get("after", "")
                    if after_content:
                        text_parts.append(after_content)

            text = "\n".join(text_parts) if text_parts else ""

            if text and not any(marker in text for marker in SKIP_MARKERS):
                yield role, text

        conn.close()
    except (sqlite3.Error, OSError) as e:
        print(f"Error reading OpenCode database: {e}", file=sys.stderr)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Pretty-print a Claude Code, Codex, or OpenCode session transcript"
    )
    parser.add_argument("path", help="Path to a session .jsonl file")
    parser.add_argument(
        "--session-id",
        dest="session_id",
        help="Session ID (required for OpenCode sessions from database)",
    )
    parser.add_argument(
        "--pretty", action="store_true", help="Human-readable output instead of JSON"
    )
    args = parser.parse_args()

    fmt = detect_format(args.path)

    if args.pretty:
        for role, text in iter_messages(args.path, session_id=args.session_id):
            print(f"--- {role} ---")
            print(text[:500])
            print()
    else:
        msgs = [
            {"role": role, "text": text}
            for role, text in iter_messages(args.path, session_id=args.session_id)
        ]
        print(json.dumps(msgs, indent=2))


if __name__ == "__main__":
    main()
