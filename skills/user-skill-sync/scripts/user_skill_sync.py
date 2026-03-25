#!/usr/bin/env python3

import argparse
import json
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path


DEVICE_CONFIG = {
    "local": {
        "label": "local-mac",
        "ssh": None,
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
    },
}

LOCAL_SKILLS_DIR = Path.home() / ".agents" / "skills"
REMOTE_HELPER = textwrap.dedent(
    r"""
    import argparse
    import json
    import os
    import shutil
    import subprocess
    import time
    from pathlib import Path

    skills_dir = Path.home() / ".agents" / "skills"
    claude_dir = Path.home() / ".claude" / "skills"

    def run(cmd, cwd=None, check=False):
        return subprocess.run(
            cmd,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=check,
        )

    def git_text(*args):
        result = run(["git", "-C", str(skills_dir), *args])
        if result.returncode != 0:
            return ""
        return result.stdout.strip()

    def collect_state(fetch=False):
        git_info = {
            "exists": False,
            "repo_root": "",
            "branch": "",
            "head": "",
            "upstream": "",
            "ahead": 0,
            "behind": 0,
            "dirty": False,
            "changes": [],
            "fetch_error": "",
        }
        audit = []
        stale_user_entries = []

        git_info["repo_root"] = git_text("rev-parse", "--show-toplevel")
        git_info["exists"] = bool(git_info["repo_root"])

        if not git_info["exists"]:
            return {
                "skills_dir": str(skills_dir),
                "claude_dir": str(claude_dir),
                "git": git_info,
                "links": {
                    "audit": audit,
                    "issues": audit,
                    "stale_user_entries": stale_user_entries,
                },
            }

        if fetch:
            fetch_result = run(["git", "-C", str(skills_dir), "fetch", "--all", "--prune"])
            if fetch_result.returncode != 0:
                git_info["fetch_error"] = fetch_result.stderr.strip() or fetch_result.stdout.strip()

        git_info["branch"] = git_text("rev-parse", "--abbrev-ref", "HEAD")
        git_info["head"] = git_text("rev-parse", "HEAD")
        git_info["upstream"] = git_text("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")

        if git_info["upstream"]:
            counts = git_text("rev-list", "--left-right", "--count", f'{git_info["upstream"]}...HEAD')
            if counts:
                behind, ahead = counts.split()
                git_info["behind"] = int(behind)
                git_info["ahead"] = int(ahead)

        status_result = run(
            [
                "git",
                "-C",
                str(skills_dir),
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                ".",
            ]
        )
        changes = [line.rstrip() for line in status_result.stdout.splitlines() if line.strip()]
        git_info["changes"] = changes
        git_info["dirty"] = bool(changes)

        source_skills = sorted(
            path.name
            for path in skills_dir.iterdir()
            if path.is_dir() and not path.name.startswith(".")
        )
        skill_root_real = os.path.realpath(skills_dir)

        if claude_dir.exists():
            for name in source_skills:
                source = skills_dir / name
                destination = claude_dir / name
                entry = {
                    "name": name,
                    "desired_target": str(source),
                    "path": str(destination),
                    "state": "ok",
                    "current_target": "",
                }

                if destination.is_symlink():
                    entry["current_target"] = os.readlink(destination)
                    if os.path.realpath(destination) != os.path.realpath(source):
                        entry["state"] = "wrong_symlink"
                elif destination.exists():
                    entry["state"] = "non_symlink"
                else:
                    entry["state"] = "missing"

                audit.append(entry)

            for destination in claude_dir.iterdir():
                if destination.name.startswith(".") or destination.name in source_skills:
                    continue
                if not destination.is_symlink():
                    continue
                real_target = os.path.realpath(destination)
                if real_target.startswith(skill_root_real + os.sep):
                    stale_user_entries.append(
                        {
                            "name": destination.name,
                            "path": str(destination),
                            "current_target": os.readlink(destination),
                            "resolved_target": real_target,
                        }
                    )

        issues = [entry for entry in audit if entry["state"] != "ok"]
        return {
            "skills_dir": str(skills_dir),
            "claude_dir": str(claude_dir),
            "git": git_info,
            "links": {
                "audit": audit,
                "issues": issues,
                "stale_user_entries": stale_user_entries,
            },
        }

    def repair_links(apply=False, prune_user_extras=False):
        state = collect_state(fetch=False)
        claude_dir.mkdir(parents=True, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        actions = []

        for entry in state["links"]["audit"]:
            destination = Path(entry["path"])
            source = Path(entry["desired_target"])
            if entry["state"] == "ok":
                continue

            if entry["state"] == "missing":
                action = {"name": entry["name"], "action": "create_symlink", "path": str(destination)}
                if apply:
                    destination.symlink_to(source)
                actions.append(action)
                continue

            if entry["state"] == "wrong_symlink":
                action = {
                    "name": entry["name"],
                    "action": "replace_symlink",
                    "path": str(destination),
                    "from": entry["current_target"],
                    "to": str(source),
                }
                if apply:
                    destination.unlink()
                    destination.symlink_to(source)
                actions.append(action)
                continue

            if entry["state"] == "non_symlink":
                backup = claude_dir / f".backup-{entry['name']}-{timestamp}"
                action = {
                    "name": entry["name"],
                    "action": "backup_and_symlink",
                    "path": str(destination),
                    "backup": str(backup),
                }
                if apply:
                    shutil.move(str(destination), str(backup))
                    destination.symlink_to(source)
                actions.append(action)

        if prune_user_extras:
            for entry in state["links"]["stale_user_entries"]:
                action = {
                    "name": entry["name"],
                    "action": "remove_stale_user_symlink",
                    "path": entry["path"],
                }
                if apply:
                    Path(entry["path"]).unlink()
                actions.append(action)

        updated_state = collect_state(fetch=False)
        return {
            "apply": apply,
            "prune_user_extras": prune_user_extras,
            "actions": actions,
            "state": updated_state,
        }

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--fetch", action="store_true")

    repair_parser = subparsers.add_parser("repair-links")
    repair_parser.add_argument("--apply", action="store_true")
    repair_parser.add_argument("--prune-user-extras", action="store_true")

    args = parser.parse_args()

    if args.command == "status":
        print(json.dumps(collect_state(fetch=args.fetch)))
    elif args.command == "repair-links":
        print(json.dumps(repair_links(apply=args.apply, prune_user_extras=args.prune_user_extras)))
    """
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit and sync ~/.agents/skills across local, dev-server, and openclaw."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--fetch", action="store_true")
    status_parser.add_argument("--devices", nargs="+", choices=list(DEVICE_CONFIG), default=list(DEVICE_CONFIG))

    repair_parser = subparsers.add_parser("repair-links")
    repair_parser.add_argument("--devices", nargs="+", choices=list(DEVICE_CONFIG), default=list(DEVICE_CONFIG))
    repair_parser.add_argument("--prune-user-extras", action="store_true")
    repair_parser.add_argument("--apply", action="store_true")

    sync_parser = subparsers.add_parser("sync")
    sync_parser.add_argument("--devices", nargs="+", choices=list(DEVICE_CONFIG), default=list(DEVICE_CONFIG))
    sync_parser.add_argument("--source", choices=list(DEVICE_CONFIG))
    sync_parser.add_argument("--commit-message")
    sync_parser.add_argument("--apply", action="store_true")

    return parser.parse_args()


def run_process(cmd, input_text=None, check=True):
    result = subprocess.run(
        cmd,
        text=True,
        input=input_text,
        capture_output=True,
    )
    if check and result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        detail = stderr or stdout or f"command failed: {' '.join(cmd)}"
        raise RuntimeError(detail)
    return result


def run_helper(device, command, *extra_args):
    ssh = DEVICE_CONFIG[device]["ssh"]
    if ssh is None:
        cmd = [sys.executable, "-", command, *extra_args]
    else:
        cmd = [*ssh, "python3", "-", command, *extra_args]
    result = run_process(cmd, input_text=REMOTE_HELPER)
    return json.loads(result.stdout)


def collect_states(devices, fetch=False):
    states = {}
    for device in devices:
        args = ["--fetch"] if fetch else []
        states[device] = run_helper(device, "status", *args)
    return states


def summarize_link_counts(state):
    counts = {
        "ok": 0,
        "missing": 0,
        "wrong_symlink": 0,
        "non_symlink": 0,
    }
    for entry in state["links"]["audit"]:
        counts[entry["state"]] = counts.get(entry["state"], 0) + 1
    return counts


def print_states(states):
    for device, state in states.items():
        git_info = state["git"]
        link_counts = summarize_link_counts(state)
        short_head = git_info["head"][:12] if git_info["head"] else "-"
        upstream = git_info["upstream"] or "-"
        print(f"{device} ({DEVICE_CONFIG[device]['label']})")
        print(f"  skills_dir: {state['skills_dir']}")
        print(f"  claude_dir: {state['claude_dir']}")
        if git_info["repo_root"] and git_info["repo_root"] != state["skills_dir"]:
            print(f"  repo_root: {git_info['repo_root']}")
        print(
            "  git:"
            f" branch={git_info['branch'] or '-'}"
            f" head={short_head}"
            f" upstream={upstream}"
            f" ahead={git_info['ahead']}"
            f" behind={git_info['behind']}"
            f" dirty={'yes' if git_info['dirty'] else 'no'}"
        )
        if git_info["fetch_error"]:
            print(f"  fetch_error: {git_info['fetch_error']}")
        if git_info["changes"]:
            print("  changes:")
            for line in git_info["changes"]:
                print(f"    {line}")
        print(
            "  links:"
            f" ok={link_counts.get('ok', 0)}"
            f" missing={link_counts.get('missing', 0)}"
            f" wrong={link_counts.get('wrong_symlink', 0)}"
            f" non_symlink={link_counts.get('non_symlink', 0)}"
            f" stale_user_extras={len(state['links']['stale_user_entries'])}"
        )
        if state["links"]["issues"]:
            print("  link_issues:")
            for entry in state["links"]["issues"]:
                detail = entry.get("current_target") or entry["desired_target"]
                print(f"    {entry['name']}: {entry['state']} ({detail})")
        if state["links"]["stale_user_entries"]:
            print("  stale_user_entries:")
            for entry in state["links"]["stale_user_entries"]:
                print(f"    {entry['name']}: {entry['current_target']}")
        print()


def ensure_clean_selection(states, source):
    missing = [device for device, state in states.items() if not state["git"]["exists"]]
    if missing:
        raise RuntimeError("missing ~/.agents/skills on: " + ", ".join(sorted(missing)))

    dirty_devices = [device for device, state in states.items() if state["git"]["dirty"]]
    if len(dirty_devices) > 1:
        raise RuntimeError(
            "multiple devices have uncommitted changes: " + ", ".join(sorted(dirty_devices))
        )

    if source:
        if states[source]["git"]["behind"] > 0:
            raise RuntimeError(f"source {source} is behind upstream; resolve that before syncing")
        for device, state in states.items():
            if device == source:
                continue
            if state["git"]["dirty"]:
                raise RuntimeError(f"non-source device {device} is dirty")
            if state["git"]["ahead"] > 0:
                raise RuntimeError(f"non-source device {device} is ahead of upstream")
        return

    clean_heads = {state["git"]["head"] for state in states.values() if state["git"]["head"]}
    if dirty_devices:
        raise RuntimeError("source selection required because one device is dirty")
    if len(clean_heads) > 1:
        ahead_devices = [
            device
            for device, state in states.items()
            if state["git"]["ahead"] > 0 and state["git"]["behind"] == 0
        ]
        if len(ahead_devices) != 1:
            raise RuntimeError("devices have divergent committed states")


def choose_source(states, requested_source=None):
    if requested_source:
        return requested_source

    dirty_devices = [device for device, state in states.items() if state["git"]["dirty"]]
    if len(dirty_devices) == 1:
        return dirty_devices[0]
    if len(dirty_devices) > 1:
        raise RuntimeError(
            "multiple devices have uncommitted changes: " + ", ".join(sorted(dirty_devices))
        )

    ahead_devices = [
        device
        for device, state in states.items()
        if state["git"]["ahead"] > 0 and state["git"]["behind"] == 0
    ]
    if len(ahead_devices) == 1:
        return ahead_devices[0]

    clean_heads = {state["git"]["head"] for state in states.values() if state["git"]["head"]}
    if len(clean_heads) <= 1:
        return None

    raise RuntimeError("devices have divergent committed states")


def local_git(args):
    cmd = ["git", "-C", str(LOCAL_SKILLS_DIR), *args]
    return run_process(cmd)


def remote_shell(device, command):
    ssh = DEVICE_CONFIG[device]["ssh"]
    if ssh is None:
        return run_process(["bash", "-lc", command])
    # ssh joins remote argv into a shell string, so the bash -lc payload must
    # be shell-quoted here or the remote side will see `bash -lc git ...` and
    # execute bare `git` instead of the full command string.
    return run_process([*ssh, "bash", "-lc", shlex.quote(command)])


def git_on_device(device, args):
    if DEVICE_CONFIG[device]["ssh"] is None:
        return local_git(args)
    quoted = shlex.join(args)
    command = f'git -C "$HOME/.agents/skills" {quoted}'
    return remote_shell(device, command)


def repair_links(devices, apply=False, prune_user_extras=False):
    results = {}
    for device in devices:
        helper_args = []
        if apply:
            helper_args.append("--apply")
        if prune_user_extras:
            helper_args.append("--prune-user-extras")
        results[device] = run_helper(device, "repair-links", *helper_args)
    return results


def print_repair_results(results):
    for device, result in results.items():
        print(f"{device} ({DEVICE_CONFIG[device]['label']})")
        if result["actions"]:
            for action in result["actions"]:
                details = [action["action"], action["name"]]
                if "backup" in action:
                    details.append(f"backup={action['backup']}")
                print("  " + " ".join(details))
        else:
            print("  no link changes needed")
        print()


def cmd_status(args):
    states = collect_states(args.devices, fetch=args.fetch)
    print_states(states)


def cmd_repair_links(args):
    results = repair_links(
        args.devices,
        apply=args.apply,
        prune_user_extras=args.prune_user_extras,
    )
    print_repair_results(results)
    if args.apply:
        print_states({device: result["state"] for device, result in results.items()})


def cmd_sync(args):
    if args.source and args.source not in args.devices:
        raise RuntimeError("--source must be included in --devices")

    states = collect_states(args.devices, fetch=True)
    print_states(states)

    source = choose_source(states, requested_source=args.source)
    ensure_clean_selection(states, source)

    if source is None:
        print("No git source change detected. Repaired links only if requested with --apply.")
        if args.apply:
            results = repair_links(args.devices, apply=True, prune_user_extras=False)
            print_repair_results(results)
        return

    source_state = states[source]
    planned_actions = []

    if source_state["git"]["dirty"]:
        if not args.commit_message:
            raise RuntimeError(f"source {source} is dirty; pass --commit-message to sync it")
        planned_actions.append(
            f"{source}: git add --all -- . && git commit -m {args.commit_message!r}"
        )

    planned_actions.append(f"{source}: git push")
    for device in args.devices:
        if device == source:
            continue
        planned_actions.append(f"{device}: git pull --ff-only")
    planned_actions.append("all selected devices: repair managed ~/.claude/skills symlinks")

    print("Planned actions:")
    for action in planned_actions:
        print(f"  - {action}")

    if not args.apply:
        print("\nDry run only. Re-run with --apply to execute.")
        return

    if source_state["git"]["dirty"]:
        git_on_device(source, ["add", "--all", "--", "."])
        git_on_device(source, ["commit", "-m", args.commit_message])

    git_on_device(source, ["push"])
    for device in args.devices:
        if device == source:
            continue
        git_on_device(device, ["pull", "--ff-only"])

    results = repair_links(args.devices, apply=True, prune_user_extras=False)
    print()
    print_repair_results(results)
    print_states(collect_states(args.devices, fetch=False))


def main():
    args = parse_args()
    if args.command == "status":
        cmd_status(args)
    elif args.command == "repair-links":
        cmd_repair_links(args)
    elif args.command == "sync":
        cmd_sync(args)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
