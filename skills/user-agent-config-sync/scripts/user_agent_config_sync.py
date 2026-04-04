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
VERSION_PATTERN = re.compile(r"(\d+\.\d+\.\d+)")
TOOL_PACKAGES = {
    "codex": "@openai/codex",
    "claude": "@anthropic-ai/claude-code",
}


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


def parse_version(text: str) -> str | None:
    match = VERSION_PATTERN.search(text)
    if not match:
        return None
    return match.group(1)


def latest_tool_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for tool_name, package_name in TOOL_PACKAGES.items():
        result = subprocess.run(
            ["npm", "view", package_name, "version"],
            text=True,
            capture_output=True,
            check=True,
        )
        version = result.stdout.strip()
        if not version:
            raise RuntimeError(f"Could not determine latest version for {package_name}")
        versions[tool_name] = version
    return versions


def gather_tool_state(device_name: str) -> dict:
    script = """python3 - <<'PY'
import json
import os
import shutil
import subprocess


def run(args):
    result = subprocess.run(args, text=True, capture_output=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def detect(tool_name):
    path = shutil.which(tool_name) or ""
    resolved = os.path.realpath(path) if path else ""
    version = None
    raw_version = ""
    if path:
        code, stdout, stderr = run([tool_name, "--version"])
        raw_version = stdout or stderr
        if code == 0:
            import re
            match = re.search(r"(\\d+\\.\\d+\\.\\d+)", raw_version)
            if match:
                version = match.group(1)

    install_method = "unknown"
    if tool_name == "codex":
        if "/node_modules/@openai/codex/" in resolved:
            install_method = "npm-global"
    elif tool_name == "claude":
        if "/.local/share/claude/versions/" in resolved:
            install_method = "native"
        elif "/node_modules/@anthropic-ai/claude-code/" in resolved:
            install_method = "npm-global"

    return {
        "path": path,
        "resolved_path": resolved,
        "version": version,
        "raw_version": raw_version,
        "install_method": install_method,
    }


_, npm_prefix, _ = run(["npm", "config", "get", "prefix"])
print(json.dumps({
    "npm_prefix": npm_prefix,
    "tools": {
        "codex": detect("codex"),
        "claude": detect("claude"),
    },
}))
PY"""
    result = run_device(device_name, script)
    return json.loads(result.stdout)


def build_tool_plan(device_name: str, stable_versions: dict[str, str]) -> dict:
    state = gather_tool_state(device_name)
    plan = {
        "device": device_name,
        "npm_prefix": state.get("npm_prefix"),
        "stable_versions": stable_versions,
        "tools": {},
        "raw_state": state,
    }
    for tool_name, stable_version in stable_versions.items():
        tool_state = state["tools"][tool_name]
        installed = tool_state.get("version")
        install_method = tool_state.get("install_method")
        upgrade_command = None
        issue = None
        if tool_name == "codex":
            upgrade_command = f"npm install -g {TOOL_PACKAGES[tool_name]}@{stable_version}"
        elif tool_name == "claude":
            if install_method == "native":
                upgrade_command = f"claude install {stable_version} --force"
            elif install_method == "npm-global":
                upgrade_command = f"npm install -g {TOOL_PACKAGES[tool_name]}@{stable_version}"
            else:
                issue = "unsupported install method"

        needs_upgrade = installed != stable_version
        plan["tools"][tool_name] = {
            "installed_version": installed,
            "stable_version": stable_version,
            "install_method": install_method,
            "path": tool_state.get("path"),
            "resolved_path": tool_state.get("resolved_path"),
            "raw_version": tool_state.get("raw_version"),
            "needs_upgrade": needs_upgrade,
            "upgrade_command": upgrade_command,
            "issue": issue,
        }
    return plan


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


def plan_sync(source_name: str, target_name: str, stable_versions: dict[str, str]) -> dict:
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
        "tool_versions": build_tool_plan(target_name, stable_versions),
    }


def plan_source_normalization(source_name: str, stable_versions: dict[str, str]) -> dict:
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
        "tool_versions": build_tool_plan(source_name, stable_versions),
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

    tool_plan = plan["tool_versions"]
    for tool_name, details in tool_plan["tools"].items():
        if not details["needs_upgrade"]:
            continue
        if details["upgrade_command"] is None:
            actions.append(
                f"manual intervention for {tool_name} on {plan['target']}: {details['issue'] or 'missing upgrade command'}"
            )
            continue
        current = details["installed_version"] or "missing"
        actions.append(
            f"upgrade {tool_name} on {plan['target']} from {current} to {details['stable_version']} via {details['upgrade_command']}"
        )
    return actions


def tool_manifest_path(backup_root: str, phase: str) -> str:
    return f"{backup_root}/tool-state-{phase}.json"


def write_tool_manifest(device_name: str, backup_root: str, phase: str, payload: dict) -> None:
    write_text(device_name, tool_manifest_path(backup_root, phase), json_text(payload))


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

    print("tool-versions:")
    for tool_name, details in plan["tool_versions"]["tools"].items():
        installed = details["installed_version"] or "missing"
        stable = details["stable_version"]
        method = details["install_method"]
        if not details["needs_upgrade"]:
            print(f"  {tool_name}: in-sync ({installed}, method={method})")
            continue
        has_diff = True
        print(f"  {tool_name}: upgrade needed ({installed} -> {stable}, method={method})")
        if details["upgrade_command"] is not None:
            print(f"    command: {details['upgrade_command']}")
        if details["issue"] is not None:
            print(f"    issue: {details['issue']}")
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
    stable_versions = latest_tool_versions()
    seen = set()
    ordered_targets = []
    for target in targets:
        if target == source_name or target in seen:
            continue
        seen.add(target)
        ordered_targets.append(target)

    has_diff = False
    print("stable-tool-versions:")
    for tool_name, version in stable_versions.items():
        print(f"  {tool_name}: {version}")
    print("")
    source_plan = plan_source_normalization(source_name, stable_versions)
    print("== Source Normalization Review ==")
    has_diff = print_plan(source_plan) or has_diff
    for target in ordered_targets:
        print("")
        print(f"== Target Review: {target} ==")
        target_plan = plan_sync(source_name, target, stable_versions)
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

    tool_actions = [details for details in plan["tool_versions"]["tools"].values() if details["needs_upgrade"]]
    if apply and tool_actions:
        write_tool_manifest(plan["target"], backup_root, "pre", plan["tool_versions"]["raw_state"])
        for tool_name, details in plan["tool_versions"]["tools"].items():
            if not details["needs_upgrade"]:
                continue
            if details["upgrade_command"] is None:
                raise RuntimeError(
                    f"Cannot upgrade {tool_name} on {plan['target']}: {details['issue'] or 'missing upgrade command'}"
                )
            run_device(plan["target"], details["upgrade_command"])

        verified_tools = build_tool_plan(plan["target"], plan["tool_versions"]["stable_versions"])
        remaining = [
            tool_name
            for tool_name, details in verified_tools["tools"].items()
            if details["needs_upgrade"]
        ]
        write_tool_manifest(plan["target"], backup_root, "post", verified_tools["raw_state"])
        if remaining:
            raise RuntimeError(
                f"Tool upgrades incomplete on {plan['target']}: {', '.join(sorted(remaining))}"
            )

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
    stable_versions = latest_tool_versions()
    seen = set()
    ordered_targets = []
    for target in targets:
        if target == source_name or target in seen:
            continue
        seen.add(target)
        ordered_targets.append(target)

    plans = [
        plan_source_normalization(source_name, stable_versions),
        *[plan_sync(source_name, target, stable_versions) for target in ordered_targets],
    ]
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
        plan = plan_sync(args.source, targets[0], latest_tool_versions())
        return print_status(plan)
    if args.command == "review":
        return review(args.source, targets)
    if args.command == "sync":
        return sync_many(args.source, targets, args.apply)
    return 1


if __name__ == "__main__":
    sys.exit(main())
