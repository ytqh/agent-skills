#!/usr/bin/env python3

import argparse
import copy
import difflib
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import tomllib


DEVICE_CONFIG = {
    "local": {
        "label": "local-mac",
        "ssh": None,
        "home": str(Path.home()),
    },
    "dev-server": {
        "label": "dev-server",
        "ssh": [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "hardfun@192.168.238.203",
        ],
        "home": "/home/hardfun",
    },
    "openclaw": {
        "label": "openclaw",
        "ssh": [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=8",
            "yutianqiuhao@192.168.238.15",
        ],
        "home": "/home/yutianqiuhao",
    },
}

MANAGED_CODEX_TABLES = {"features", "tui", "notice"}
MANAGED_CLAUDE_KEYS = {
    "$schema",
    "env",
    "statusLine",
    "enabledPlugins",
    "alwaysThinkingEnabled",
    "effortLevel",
    "skipDangerousModePermissionPrompt",
    "preferredNotifChannel",
}
REQUIRED_CLAUDE_ENABLED_PLUGINS = {
    "pyright-lsp@claude-plugins-official": True,
}
STATUSLINE_PATTERN = re.compile(r"(/(?:home|Users)/[^/\s\"']+/.claude/[^\s\"']+)")


def expand_home(device_name: str, path: str) -> str:
    home = DEVICE_CONFIG[device_name]["home"]
    if path == "~":
        return home
    if path.startswith("~/"):
        return f"{home}/{path[2:]}"
    return path


def run_device(device_name: str, command: str, *, input_text: str | None = None, check: bool = True):
    device = DEVICE_CONFIG[device_name]
    if device["ssh"] is None:
        return subprocess.run(
            ["/bin/zsh", "-lc", command],
            input=input_text,
            text=True,
            capture_output=True,
            check=check,
        )
    return subprocess.run(
        [*device["ssh"], command],
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


def read_text(device_name: str, path: str) -> str:
    abs_path = expand_home(device_name, path)
    result = run_device(device_name, f"cat {shlex.quote(abs_path)}", check=False)
    if result.returncode != 0:
        raise FileNotFoundError(abs_path)
    return result.stdout


def exists(device_name: str, path: str) -> bool:
    abs_path = expand_home(device_name, path)
    result = run_device(device_name, f"test -e {shlex.quote(abs_path)}", check=False)
    return result.returncode == 0


def ensure_parent_dir(device_name: str, path: str) -> None:
    parent = str(Path(path).parent)
    run_device(device_name, f"mkdir -p {shlex.quote(parent)}")


def write_text(device_name: str, path: str, content: str) -> None:
    abs_path = expand_home(device_name, path)
    ensure_parent_dir(device_name, abs_path)
    run_device(device_name, f"cat > {shlex.quote(abs_path)}", input_text=content)


def backup_file(device_name: str, src_path: str, backup_root: str) -> None:
    abs_src = expand_home(device_name, src_path)
    rel = abs_src.lstrip("/")
    backup_path = f"{backup_root}/{rel}"
    cmd = (
        f"mkdir -p {shlex.quote(str(Path(backup_path).parent))} && "
        f"cp -a {shlex.quote(abs_src)} {shlex.quote(backup_path)}"
    )
    run_device(device_name, cmd)


def json_text(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def quote_toml_key(key: str) -> str:
    """Quote a TOML key if it contains characters not allowed in bare keys.

    TOML bare keys may only contain ASCII letters, digits, dashes, and
    underscores.  Keys with dots, spaces, or other characters must be quoted
    to avoid being misinterpreted as dotted (nested) keys.
    """
    if re.match(r'^[A-Za-z0-9_-]+$', key):
        return key
    return json.dumps(key)


def format_toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(format_toml_value(item) for item in value) + "]"
    raise TypeError(f"Unsupported TOML value: {value!r}")


def emit_toml_table(lines: list[str], prefix: list[str], mapping: dict) -> None:
    scalar_items = []
    table_items = []
    array_table_items = []
    for key, value in mapping.items():
        if isinstance(value, dict):
            table_items.append((key, value))
        elif isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            array_table_items.append((key, value))
        else:
            scalar_items.append((key, value))

    if prefix:
        lines.append(f"[{'.'.join(quote_toml_key(p) for p in prefix)}]")
    for key, value in scalar_items:
        lines.append(f"{quote_toml_key(key)} = {format_toml_value(value)}")

    child_blocks = []
    for key, value in table_items:
        child_lines: list[str] = []
        emit_toml_table(child_lines, prefix + [key], value)
        child_blocks.append(child_lines)
    for key, items in array_table_items:
        for item in items:
            child_lines = [f"[[{'.'.join(quote_toml_key(p) for p in prefix + [key])}]]"]
            for child_key, child_value in item.items():
                if isinstance(child_value, dict):
                    raise TypeError("Nested dict inside array-of-tables is not supported")
                child_lines.append(f"{quote_toml_key(child_key)} = {format_toml_value(child_value)}")
            child_blocks.append(child_lines)

    if scalar_items and child_blocks:
        lines.append("")
    for index, block in enumerate(child_blocks):
        lines.extend(block)
        if index != len(child_blocks) - 1:
            lines.append("")


def dump_toml(data: dict) -> str:
    lines: list[str] = []
    emit_toml_table(lines, [], data)
    return "\n".join(lines).rstrip() + "\n"


def extract_passthrough_toml_blocks(raw_text: str) -> str:
    kept_blocks: list[str] = []
    current_block: list[str] = []
    keep_current = False

    def flush() -> None:
        nonlocal current_block, keep_current
        if keep_current and current_block:
            kept_blocks.append("\n".join(current_block).strip("\n"))
        current_block = []
        keep_current = False

    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            flush()
            current_block = [line]
            match = re.match(r"^\[\[?([A-Za-z0-9_]+)", stripped)
            top_key = match.group(1) if match else ""
            keep_current = top_key not in MANAGED_CODEX_TABLES
        elif current_block:
            current_block.append(line)

    flush()
    if not kept_blocks:
        return ""
    return "\n\n".join(block.rstrip() for block in kept_blocks if block.strip()) + "\n"


def merged_codex_config(source_text: str, target_text: str) -> str:
    source = tomllib.loads(source_text)

    merged: dict = {}
    for key, value in source.items():
        if key in MANAGED_CODEX_TABLES or not isinstance(value, dict):
            merged[key] = copy.deepcopy(value)

    managed_text = dump_toml(merged).rstrip()
    excluded_text = extract_passthrough_toml_blocks(target_text).strip()
    if excluded_text:
        return managed_text + "\n\n" + excluded_text + "\n"
    return managed_text + "\n"


def merged_claude_config(
    source_text: str,
    target_text: str,
    *,
    source_home: str,
    target_home: str,
) -> tuple[str, tuple[str, str, str] | None]:
    source = json.loads(source_text)
    target = json.loads(target_text)

    merged = copy.deepcopy(target)

    for key in list(merged):
        if key in MANAGED_CLAUDE_KEYS and key not in source:
            del merged[key]

    for key in MANAGED_CLAUDE_KEYS:
        if key in source:
            merged[key] = copy.deepcopy(source[key])

    enabled_plugins = copy.deepcopy(source.get("enabledPlugins") or {})
    enabled_plugins.update(REQUIRED_CLAUDE_ENABLED_PLUGINS)
    merged["enabledPlugins"] = enabled_plugins

    aux_sync = None
    status_line = merged.get("statusLine")
    if isinstance(status_line, dict):
        command = status_line.get("command")
        if isinstance(command, str):
            match = STATUSLINE_PATTERN.search(command)
            if match:
                src_script = match.group(1)
                if src_script.startswith(f"{source_home}/.claude/"):
                    target_script = src_script.replace(source_home, target_home, 1)
                    status_line["command"] = command.replace(src_script, target_script, 1)
                    aux_sync = (src_script, target_script, "")

    return json_text(merged), aux_sync


def unified_diff(label: str, current_text: str, expected_text: str) -> str:
    lines = list(
        difflib.unified_diff(
            current_text.splitlines(),
            expected_text.splitlines(),
            fromfile=f"{label}:current",
            tofile=f"{label}:expected",
            lineterm="",
        )
    )
    return "\n".join(lines)


def plan_sync(source_name: str, target_name: str) -> dict:
    source_codex = read_text(source_name, "~/.codex/config.toml")
    target_codex = read_text(target_name, "~/.codex/config.toml")
    source_claude = read_text(source_name, "~/.claude/settings.json")
    target_claude = read_text(target_name, "~/.claude/settings.json")

    expected_codex = merged_codex_config(source_codex, target_codex)
    expected_claude, aux_sync = merged_claude_config(
        source_claude,
        target_claude,
        source_home=DEVICE_CONFIG[source_name]["home"],
        target_home=DEVICE_CONFIG[target_name]["home"],
    )

    aux_payload = None
    if aux_sync is not None:
        src_script, target_script, _ = aux_sync
        script_text = read_text(source_name, src_script)
        aux_payload = (src_script, target_script, script_text)

    return {
        "source": source_name,
        "target": target_name,
        "codex": {
            "path": expand_home(target_name, "~/.codex/config.toml"),
            "current": target_codex,
            "expected": expected_codex,
        },
        "claude": {
            "path": expand_home(target_name, "~/.claude/settings.json"),
            "current": target_claude,
            "expected": expected_claude,
        },
        "statusline_script": aux_payload,
    }


def plan_source_normalization(source_name: str) -> dict:
    source_codex = read_text(source_name, "~/.codex/config.toml")
    source_claude = read_text(source_name, "~/.claude/settings.json")
    expected_claude, aux_sync = merged_claude_config(
        source_claude,
        source_claude,
        source_home=DEVICE_CONFIG[source_name]["home"],
        target_home=DEVICE_CONFIG[source_name]["home"],
    )

    aux_payload = None
    if aux_sync is not None:
        src_script, target_script, _ = aux_sync
        script_text = read_text(source_name, src_script)
        aux_payload = (src_script, target_script, script_text)

    return {
        "source": source_name,
        "target": source_name,
        "codex": {
            "path": expand_home(source_name, "~/.codex/config.toml"),
            "current": source_codex,
            "expected": source_codex,
        },
        "claude": {
            "path": expand_home(source_name, "~/.claude/settings.json"),
            "current": source_claude,
            "expected": expected_claude,
        },
        "statusline_script": aux_payload,
    }


def collect_actions(plan: dict) -> list[str]:
    actions = []
    for name in ("codex", "claude"):
        if plan[name]["current"] != plan[name]["expected"]:
            actions.append(f"update {plan[name]['path']}")

    aux = plan["statusline_script"]
    if aux is not None:
        _, target_path, script_text = aux
        current_script = read_text(plan["target"], target_path) if exists(plan["target"], target_path) else ""
        if current_script != script_text:
            actions.append(f"update {target_path}")
    return actions


def print_plan(plan: dict, *, heading: str | None = None) -> bool:
    if heading:
        print(heading)
    print(f"source={plan['source']} target={plan['target']}")
    has_diff = False
    for name in ("codex", "claude"):
        current_text = plan[name]["current"]
        expected_text = plan[name]["expected"]
        if current_text == expected_text:
            print(f"{name}: in-sync ({plan[name]['path']})")
            continue
        has_diff = True
        print(f"{name}: diff ({plan[name]['path']})")
        print(unified_diff(name, current_text, expected_text))
    aux = plan["statusline_script"]
    if aux is None:
        print("statusline-script: none")
    else:
        _, target_path, script_text = aux
        current_script = read_text(plan["target"], target_path) if exists(plan["target"], target_path) else ""
        if current_script == script_text:
            print(f"statusline-script: in-sync ({target_path})")
        else:
            has_diff = True
            print(f"statusline-script: diff ({target_path})")
            print(
                unified_diff(
                    "statusline-script",
                    current_script,
                    script_text,
                )
            )
    actions = collect_actions(plan)
    if actions:
        print("planned-actions:")
        for action in actions:
            print(f"  - {action}")
    else:
        print("planned-actions: none")
    return has_diff


def print_status(plan: dict) -> int:
    return 1 if print_plan(plan) else 0


def review(source_name: str, targets: list[str]) -> int:
    seen = set()
    ordered_targets = []
    for target in targets:
        if target == source_name or target in seen:
            continue
        seen.add(target)
        ordered_targets.append(target)

    has_diff = False
    source_plan = plan_source_normalization(source_name)
    print("== Source Normalization Review ==")
    has_diff = print_plan(source_plan) or has_diff
    for target in ordered_targets:
        print("")
        print(f"== Target Review: {target} ==")
        target_plan = plan_sync(source_name, target)
        has_diff = print_plan(target_plan) or has_diff
    return 1 if has_diff else 0


def build_backup_root(plan: dict) -> str:
    suffix = (
        f"{plan['source']}-self"
        if plan["source"] == plan["target"]
        else f"{plan['source']}-to-{plan['target']}"
    )
    return (
        f"{DEVICE_CONFIG[plan['target']]['home']}/.agent-config-sync-backups/"
        f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{suffix}"
    )


def sync(plan: dict, apply: bool) -> int:
    backup_root = (
        build_backup_root(plan)
    )
    actions = collect_actions(plan)

    for name in ("codex", "claude"):
        current_text = plan[name]["current"]
        expected_text = plan[name]["expected"]
        if current_text == expected_text:
            continue
        abs_path = plan[name]["path"]
        if apply:
            backup_file(plan["target"], abs_path, backup_root)
            write_text(plan["target"], abs_path, expected_text)

    aux = plan["statusline_script"]
    if aux is not None:
        _, target_path, script_text = aux
        current_script = read_text(plan["target"], target_path) if exists(plan["target"], target_path) else ""
        if current_script != script_text:
            if apply:
                if exists(plan["target"], target_path):
                    backup_file(plan["target"], target_path, backup_root)
                write_text(plan["target"], target_path, script_text)

    print(f"source={plan['source']} target={plan['target']} apply={'yes' if apply else 'no'}")
    if not actions:
        print("actions: none; managed subset already in sync")
        return 0

    print("planned-actions:")
    for action in actions:
        print(f"  - {action}")

    if apply:
        print(f"backup-root: {backup_root}")
    else:
        print("backup-root: not created (dry-run)")
    return 0


def sync_many(source_name: str, targets: list[str], apply: bool) -> int:
    seen = set()
    ordered_targets = []
    for target in targets:
        if target == source_name or target in seen:
            continue
        seen.add(target)
        ordered_targets.append(target)

    plans = [plan_source_normalization(source_name), *[plan_sync(source_name, target) for target in ordered_targets]]
    for index, plan in enumerate(plans):
        if index:
            print("")
        sync(plan, apply)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common_args(subparser):
        subparser.add_argument("--source", default="local", choices=sorted(DEVICE_CONFIG))
        subparser.add_argument("--target", choices=sorted(DEVICE_CONFIG))
        subparser.add_argument("--targets", nargs="+", choices=sorted(DEVICE_CONFIG))

    status_parser = subparsers.add_parser("status")
    add_common_args(status_parser)

    review_parser = subparsers.add_parser("review")
    add_common_args(review_parser)

    sync_parser = subparsers.add_parser("sync")
    add_common_args(sync_parser)
    sync_parser.add_argument("--apply", action="store_true")

    args = parser.parse_args()
    targets = []
    if args.target:
        targets.append(args.target)
    if args.targets:
        targets.extend(args.targets)
    if args.command in {"review", "sync"} and not targets:
        targets = ["dev-server", "openclaw"]
    if args.command == "status" and not targets:
        targets = ["openclaw"]

    if args.command == "status":
        if len(targets) != 1:
            parser.error("status accepts exactly one target")
        if args.source == targets[0]:
            parser.error("--source and --target must differ for status")
        plan = plan_sync(args.source, targets[0])
        return print_status(plan)
    if args.command == "review":
        return review(args.source, targets)
    if args.command == "sync":
        return sync_many(args.source, targets, args.apply)
    return 1


if __name__ == "__main__":
    sys.exit(main())
