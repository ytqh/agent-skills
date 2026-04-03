#!/usr/bin/env python3
import argparse
import base64
import re
import subprocess
import sys


DEFAULT_SSH_TARGET = "hardfun@192.168.238.203"
DEFAULT_PROJECT = r"\\wsl.localhost\Ubuntu-20.04\home\hardfun\Projects\jim.ai\apps\chat-miniprogram\dist"
CLI_PATH = r"C:\Program Files (x86)\Tencent\微信web开发者工具\cli.bat"
OUT_LOG = r"C:\Users\yutia\miniprogram-browser-auto.out.log"
ERR_LOG = r"C:\Users\yutia\miniprogram-browser-auto.err.log"


def is_windows_native_target(ssh_target: str) -> bool:
    target = ssh_target.lower()
    return target == "dev-server-win" or target.startswith("yutia@")


def encode_powershell(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def run_remote_powershell(ssh_target: str, script: str) -> subprocess.CompletedProcess[str]:
    encoded = encode_powershell(script)
    powershell = "powershell -NoProfile" if is_windows_native_target(ssh_target) else "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe -NoProfile"
    cmd = [
        "ssh",
        ssh_target,
        f"{powershell} -EncodedCommand {encoded}",
    ]
    return subprocess.run(cmd, text=True, capture_output=True, errors="replace")


def clean_output(text: str) -> str:
    if not text:
        return text
    return re.sub(r"#< CLIXML\s*<Objs[\s\S]*?</Objs>", "", text, flags=re.S).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Start WeChat DevTools automation port 9420 on dev-server-win.")
    parser.add_argument("--ssh-target", default=DEFAULT_SSH_TARGET)
    parser.add_argument("--project", default=DEFAULT_PROJECT)
    parser.add_argument("--port", type=int, default=9420)
    parser.add_argument("--timeout-seconds", type=int, default=30)
    args = parser.parse_args()

    ps = rf"""
$ProgressPreference = 'SilentlyContinue'
$project = '{args.project}'
$cli = '{CLI_PATH}'
$out = '{OUT_LOG}'
$err = '{ERR_LOG}'
$port = {args.port}
$timeout = {args.timeout_seconds}

Remove-Item $out,$err -Force -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath $cli -ArgumentList @('auto','--project',$project,'--auto-port',$port) -PassThru -RedirectStandardOutput $out -RedirectStandardError $err

$deadline = (Get-Date).AddSeconds($timeout)
$ready = $false
while ((Get-Date) -lt $deadline) {{
  try {{
    $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction Stop
    if ($listener) {{
      $ready = $true
      break
    }}
  }} catch {{}}
  Start-Sleep -Milliseconds 500
}}

if ($ready) {{
  [pscustomobject]@{{
    status = 'ready'
    port = $port
    launcher_pid = $proc.Id
    stdout_log = $out
    stderr_log = $err
  }} | ConvertTo-Json -Compress
  exit 0
}}

Write-Output 'PORT_NOT_READY'
if (Test-Path $out) {{ Write-Output '---OUT---'; Get-Content $out }}
if (Test-Path $err) {{ Write-Output '---ERR---'; Get-Content $err }}
exit 1
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
