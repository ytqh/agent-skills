#!/usr/bin/env python3
"""Check current remaining Claude Code and Codex quota on the local machine."""

from __future__ import annotations

import argparse
import json
import os
import pty
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any


LOCAL_TZ = datetime.now().astimezone().tzinfo


def now_local_iso() -> str:
    return datetime.now().astimezone().isoformat()


def format_reset(ts: Any) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(int(ts), tz=LOCAL_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")


def format_percent(value: Any) -> str | None:
    if value is None:
        return None
    number = float(value)
    if number.is_integer():
        return f"{int(number)}%"
    return f"{number:.1f}%"


def remaining_percent(used: Any) -> float | None:
    if used is None:
        return None
    return max(0.0, 100.0 - float(used))


def safe_jsonl_loads(line: str) -> dict[str, Any] | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict):
        return data
    return None


def spawn_pty(argv: list[str], env: dict[str, str]) -> tuple[subprocess.Popen[bytes], int]:
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        argv,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        close_fds=True,
    )
    os.close(slave_fd)
    return proc, master_fd


def drain_fd(fd: int) -> bytes:
    chunks: list[bytes] = []
    while True:
        ready, _, _ = select.select([fd], [], [], 0)
        if not ready:
            break
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks)


def stop_proc(proc: subprocess.Popen[bytes], fd: int) -> None:
    if proc.poll() is None:
        for _ in range(2):
            try:
                os.write(fd, b"\x03")
            except OSError:
                break
            try:
                proc.wait(timeout=1.5)
                break
            except subprocess.TimeoutExpired:
                continue
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1.5)
    try:
        os.close(fd)
    except OSError:
        pass


def build_window(source_used_key: str, data: dict[str, Any]) -> dict[str, Any]:
    used = data.get(source_used_key)
    remaining = remaining_percent(used)
    resets_at = data.get("resets_at")
    return {
        "used_percent": used,
        "used_percent_display": format_percent(used),
        "remaining_percent": remaining,
        "remaining_percent_display": format_percent(remaining),
        "resets_at": resets_at,
        "resets_at_local": format_reset(resets_at),
    }


def check_claude() -> dict[str, Any]:
    claude_path = shutil.which("claude")
    if not claude_path:
        return {"status": "unavailable", "reason": "claude CLI not found on PATH"}

    dump_path = Path(tempfile.gettempdir()) / f"claude-statusline-input-{os.getpid()}.json"
    settings_path = Path(tempfile.gettempdir()) / f"claude-statusline-settings-{os.getpid()}.json"
    try:
        dump_path.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        settings_path.unlink(missing_ok=True)
    except OSError:
        pass

    command = (
        "python3 -c "
        f"'import pathlib,sys; pathlib.Path(r\"{dump_path}\").write_text(sys.stdin.read()); print()'"
    )
    settings_path.write_text(
        json.dumps({"statusLine": {"type": "command", "command": command, "refreshInterval": 1}})
    )
    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")

    shell = os.environ.get("SHELL", "/bin/zsh")
    command_line = f"{shlex.quote(claude_path)} --settings {shlex.quote(str(settings_path))}"
    proc, fd = spawn_pty([shell, "-lc", command_line], env)
    payload: dict[str, Any] | None = None
    started_at = time.time()
    try:
        while time.time() - started_at < 20:
            drain_fd(fd)
            if dump_path.exists():
                text = dump_path.read_text(errors="replace")
                if text.strip():
                    try:
                        candidate = json.loads(text)
                    except json.JSONDecodeError:
                        candidate = None
                    if isinstance(candidate, dict) and isinstance(candidate.get("rate_limits"), dict):
                        payload = candidate
                        break
            if proc.poll() is not None and payload is not None:
                break
            time.sleep(0.2)
    finally:
        stop_proc(proc, fd)
        try:
            dump_path.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            settings_path.unlink(missing_ok=True)
        except OSError:
            pass

    if payload is None:
        return {"status": "error", "reason": "could not read Claude Code rate limits from status line"}

    rate_limits = payload.get("rate_limits") or {}
    five_hour = rate_limits.get("five_hour") or {}
    seven_day = rate_limits.get("seven_day") or {}
    return {
        "status": "ok",
        "checked_at_local": now_local_iso(),
        "source": "Claude Code statusLine JSON",
        "five_hour": build_window("used_percentage", five_hour),
        "weekly": build_window("used_percentage", seven_day),
    }


def parse_codex_snapshot(path: Path) -> dict[str, Any] | None:
    latest: dict[str, Any] | None = None
    try:
        with path.open() as handle:
            for line in handle:
                record = safe_jsonl_loads(line)
                if not record or record.get("type") != "event_msg":
                    continue
                payload = record.get("payload") or {}
                rate_limits = payload.get("rate_limits")
                if not isinstance(rate_limits, dict):
                    continue
                latest = {
                    "timestamp": record.get("timestamp"),
                    "rate_limits": rate_limits,
                }
    except OSError:
        return None
    return latest


def parse_iso_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def codex_snapshot_record(path: Path) -> dict[str, Any] | None:
    parsed = parse_codex_snapshot(path)
    if not parsed:
        return None
    parsed["path"] = path
    parsed["mtime"] = path.stat().st_mtime
    parsed["timestamp_dt"] = parse_iso_datetime(parsed.get("timestamp"))
    return parsed


def find_latest_codex_snapshot(base_dir: Path, limit: int = 40) -> dict[str, Any] | None:
    if not base_dir.exists():
        return None

    files = sorted(
        base_dir.rglob("rollout-*.jsonl"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    best: dict[str, Any] | None = None
    for path in files[:limit]:
        record = codex_snapshot_record(path)
        if not record:
            continue
        if best is None:
            best = record
            continue
        best_dt = best.get("timestamp_dt")
        record_dt = record.get("timestamp_dt")
        if record_dt and best_dt:
            if record_dt > best_dt:
                best = record
        elif record.get("mtime", 0) > best.get("mtime", 0):
            best = record
    return best


def check_codex() -> dict[str, Any]:
    codex_path = shutil.which("codex")
    if not codex_path:
        return {"status": "unavailable", "reason": "codex CLI not found on PATH"}

    now = datetime.now().astimezone()
    sessions_root = Path.home() / ".codex" / "sessions"
    sessions_dir = sessions_root / now.strftime("%Y") / now.strftime("%m") / now.strftime("%d")
    known_files = {path: path.stat().st_mtime for path in sessions_dir.glob("rollout-*.jsonl")} if sessions_dir.exists() else {}

    env = os.environ.copy()
    env.setdefault("TERM", "xterm-256color")
    proc, fd = spawn_pty([codex_path, "--no-alt-screen"], env)
    started_at = time.time()
    snapshot: dict[str, Any] | None = None
    snapshot_path: Path | None = None

    try:
        while time.time() - started_at < 25:
            drain_fd(fd)
            if sessions_dir.exists():
                candidates = sorted(sessions_dir.glob("rollout-*.jsonl"), key=lambda path: path.stat().st_mtime, reverse=True)
                for candidate in candidates[:5]:
                    mtime = candidate.stat().st_mtime
                    if candidate in known_files and mtime <= known_files[candidate] and mtime < started_at:
                        continue
                    parsed = parse_codex_snapshot(candidate)
                    if parsed and parsed.get("rate_limits"):
                        snapshot = parsed
                        snapshot_path = candidate
                        break
            if snapshot is not None:
                break
            if proc.poll() is not None and snapshot is not None:
                break
            time.sleep(0.25)
    finally:
        stop_proc(proc, fd)

    if snapshot is None:
        fallback = find_latest_codex_snapshot(sessions_root)
        if fallback is None:
            return {"status": "error", "reason": "could not read Codex rate limits from a fresh or stored session snapshot"}
        snapshot = fallback
        snapshot_path = fallback["path"]
        source = "Codex recent local session snapshot (fallback; no fresh refresh)"
        freshness = "fallback"
    else:
        source = "Codex fresh local session snapshot"
        freshness = "fresh"

    rate_limits = snapshot.get("rate_limits") or {}
    primary = rate_limits.get("primary") or {}
    secondary = rate_limits.get("secondary") or {}
    snapshot_dt = parse_iso_datetime(snapshot.get("timestamp"))
    snapshot_age_seconds = None
    if snapshot_dt is not None:
        snapshot_age_seconds = int((datetime.now(snapshot_dt.tzinfo) - snapshot_dt).total_seconds())
    return {
        "status": "ok",
        "checked_at_local": now_local_iso(),
        "snapshot_timestamp": snapshot.get("timestamp"),
        "snapshot_path": str(snapshot_path) if snapshot_path else None,
        "snapshot_age_seconds": snapshot_age_seconds,
        "freshness": freshness,
        "source": source,
        "plan_type": rate_limits.get("plan_type"),
        "five_hour": build_window("used_percent", primary),
        "weekly": build_window("used_percent", secondary),
    }


def make_result() -> dict[str, Any]:
    return {
        "checked_at_local": now_local_iso(),
        "claude": check_claude(),
        "codex": check_codex(),
    }


def print_human(result: dict[str, Any]) -> None:
    print(f"Checked at: {result['checked_at_local']}")
    print()
    for label, key in (("Claude Code", "claude"), ("Codex", "codex")):
        item = result[key]
        print(f"{label}:")
        if item["status"] != "ok":
            print(f"  status: {item['status']}")
            print(f"  reason: {item.get('reason', 'unknown error')}")
            print()
            continue

        five = item["five_hour"]
        weekly = item["weekly"]
        print(f"  5h remaining: {five['remaining_percent_display']}")
        print(f"  5h resets:    {five['resets_at_local']}")
        print(f"  weekly remaining: {weekly['remaining_percent_display']}")
        print(f"  weekly resets:    {weekly['resets_at_local']}")
        if item.get("plan_type"):
            print(f"  plan type:    {item['plan_type']}")
        print(f"  source:       {item['source']}")
        if item.get("snapshot_age_seconds") is not None:
            print(f"  snapshot age: {item['snapshot_age_seconds']}s")
        if item.get("snapshot_path"):
            print(f"  snapshot:     {item['snapshot_path']}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Check current Claude Code and Codex remaining quota.")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    args = parser.parse_args()

    result = make_result()
    if args.json:
        json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
