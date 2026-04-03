#!/usr/bin/env python3
import argparse
import base64
import pathlib
import re
import subprocess
import sys


DEFAULT_SSH_TARGET = "hardfun@192.168.238.203"
DEFAULT_REMOTE_WORKDIR = r"C:\Users\yutia\Projects\miniprogram-automator-smoke"
DEFAULT_REMOTE_SCRIPT = "miniprogram-browser-run.js"


def is_windows_native_target(ssh_target: str) -> bool:
    target = ssh_target.lower()
    return target == "dev-server-win" or target.startswith("yutia@")


def encode_powershell(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def run_remote_powershell(ssh_target: str, script: str, *, stdin_data: str | None = None) -> subprocess.CompletedProcess[str]:
    encoded = encode_powershell(script)
    powershell = "powershell -NoProfile" if is_windows_native_target(ssh_target) else "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile"
    cmd = [
        "ssh",
        ssh_target,
        f"{powershell} -EncodedCommand {encoded}",
    ]
    return subprocess.run(cmd, text=True, capture_output=True, input=stdin_data)


def clean_output(text: str) -> str:
    if not text:
        return text
    return re.sub(r"#< CLIXML\s*<Objs[\s\S]*?</Objs>", "", text, flags=re.S).strip()


def load_js(args: argparse.Namespace) -> str:
    if args.file:
        return pathlib.Path(args.file).read_text(encoding="utf-8")
    return sys.stdin.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Write a JS file to dev-server-win and execute it with Windows Node.js.")
    parser.add_argument("--ssh-target", default=DEFAULT_SSH_TARGET)
    parser.add_argument("--remote-workdir", default=DEFAULT_REMOTE_WORKDIR)
    parser.add_argument("--remote-script", default=DEFAULT_REMOTE_SCRIPT)
    parser.add_argument("--file", help="Local JS file to send. Defaults to stdin.")
    args = parser.parse_args()

    js_source = load_js(args)
    if not js_source.strip():
        print("No JS source provided.", file=sys.stderr)
        return 2

    if is_windows_native_target(args.ssh_target):
        ps = rf"""
$ProgressPreference = 'SilentlyContinue'
$workdir = '{args.remote_workdir}'
$scriptPath = Join-Path $workdir '{args.remote_script}'
$nodeCandidates = @(
  'C:\Users\yutia\AppData\Local\Microsoft\WinGet\Packages\OpenJS.NodeJS.LTS_Microsoft.Winget.Source_8wekyb3d8bbwe\node-v24.14.1-win-x64\node.exe',
  'C:\Program Files\nodejs\node.exe'
)

if (-not (Test-Path $workdir)) {{
  New-Item -ItemType Directory -Force -Path $workdir | Out-Null
}}

$resolvedNode = $nodeCandidates | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
if (-not $resolvedNode) {{
  $resolvedNode = Get-ChildItem 'C:\Users\yutia\AppData\Local\Microsoft\WinGet\Packages' -Recurse -Filter node.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
}}
if (-not $resolvedNode) {{
  throw 'NODE_NOT_FOUND'
}}

$js = [Console]::In.ReadToEnd()
Set-Content -Path $scriptPath -Value $js -Encoding UTF8

Set-Location $workdir
& $resolvedNode $scriptPath
exit $LASTEXITCODE
"""
        result = run_remote_powershell(args.ssh_target, ps, stdin_data=js_source)
    else:
        js_b64 = base64.b64encode(js_source.encode("utf-8")).decode("ascii")

        ps = rf"""
$ProgressPreference = 'SilentlyContinue'
$workdir = '{args.remote_workdir}'
$scriptPath = Join-Path $workdir '{args.remote_script}'
$nodeCandidates = @(
  'C:\Users\yutia\AppData\Local\Microsoft\WinGet\Packages\OpenJS.NodeJS.LTS_Microsoft.Winget.Source_8wekyb3d8bbwe\node-v24.14.1-win-x64\node.exe',
  'C:\Program Files\nodejs\node.exe'
)

if (-not (Test-Path $workdir)) {{
  New-Item -ItemType Directory -Force -Path $workdir | Out-Null
}}

$resolvedNode = $nodeCandidates | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
if (-not $resolvedNode) {{
  $resolvedNode = Get-ChildItem 'C:\Users\yutia\AppData\Local\Microsoft\WinGet\Packages' -Recurse -Filter node.exe -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
}}
if (-not $resolvedNode) {{
  throw 'NODE_NOT_FOUND'
}}

$bytes = [Convert]::FromBase64String('{js_b64}')
[System.IO.File]::WriteAllBytes($scriptPath, $bytes)

Set-Location $workdir
& $resolvedNode $scriptPath
exit $LASTEXITCODE
"""
        result = run_remote_powershell(args.ssh_target, ps)
    cleaned_stdout = clean_output(result.stdout)
    cleaned_stderr = clean_output(result.stderr)
    if cleaned_stdout:
        sys.stdout.write(cleaned_stdout + "\n")
    if cleaned_stderr:
        sys.stderr.write(cleaned_stderr + "\n")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
