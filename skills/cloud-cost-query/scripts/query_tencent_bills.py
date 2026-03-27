#!/usr/bin/env python3
"""Pull recent Tencent Cloud billing cycles and aggregate by product."""

from __future__ import annotations

import argparse
import calendar
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--months", type=int, default=3, help="Number of billing cycles to query.")
    parser.add_argument(
        "--end-cycle",
        default=date.today().strftime("%Y-%m"),
        help="Last billing cycle in YYYY-MM format. Defaults to the current month.",
    )
    parser.add_argument("--profile", help="Tencent CLI profile name.")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        help="Optional directory to store raw DescribeBillSummaryByProduct responses.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional output file. Defaults to stdout.",
    )
    return parser.parse_args()


def shift_month(year: int, month: int, delta: int) -> tuple[int, int]:
    total = year * 12 + (month - 1) + delta
    return total // 12, total % 12 + 1


def billing_cycles(end_cycle: str, months: int) -> list[str]:
    year_s, month_s = end_cycle.split("-", 1)
    year = int(year_s)
    month = int(month_s)
    cycles = []
    for offset in range(months - 1, -1, -1):
        y, m = shift_month(year, month, -offset)
        cycles.append(f"{y:04d}-{m:02d}")
    return cycles


def month_range(cycle: str) -> tuple[str, str]:
    year_s, month_s = cycle.split("-", 1)
    year = int(year_s)
    month = int(month_s)
    last_day = calendar.monthrange(year, month)[1]
    return f"{year:04d}-{month:02d}-01", f"{year:04d}-{month:02d}-{last_day:02d}"


def to_float(value: Any) -> float:
    if value in (None, "", "NULL"):
        return 0.0
    return float(value)


def run_tccli_json(action: str, params: list[str], *, profile: str | None) -> dict[str, Any]:
    cmd = ["tccli", "billing", action, *params]
    if profile:
        cmd.extend(["--profile", profile])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or f"tccli command failed: {' '.join(cmd)}"
        raise RuntimeError(message)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"tccli returned non-JSON output for {action}: {exc}") from exc


@dataclass
class ProductSummary:
    name: str
    code: str | None = None
    total_amount: float = 0.0
    months: dict[str, float] | None = None

    def __post_init__(self) -> None:
        if self.months is None:
            self.months = {}


def main() -> int:
    args = parse_args()
    if args.months < 1:
        raise SystemExit("--months must be >= 1")

    cycles = billing_cycles(args.end_cycle, args.months)
    today_cycle = date.today().strftime("%Y-%m")

    balance = run_tccli_json("DescribeAccountBalance", [], profile=args.profile)

    raw_by_cycle: dict[str, dict[str, Any]] = {}
    month_summaries: list[dict[str, Any]] = []
    products: dict[str, ProductSummary] = {}
    not_ready_months: list[str] = []

    for cycle in cycles:
        begin_time, end_time = month_range(cycle)
        payload = run_tccli_json(
            "DescribeBillSummaryByProduct",
            ["--BeginTime", begin_time, "--EndTime", end_time],
            profile=args.profile,
        )
        raw_by_cycle[cycle] = payload
        ready = int(payload.get("Ready", 0) or 0)
        total = to_float((payload.get("SummaryTotal") or {}).get("RealTotalCost"))

        month_summaries.append(
            {
                "month": cycle,
                "beginTime": begin_time,
                "endTime": end_time,
                "totalRealCost": round(total, 6),
                "ready": ready,
                "monthToDate": cycle == today_cycle,
            }
        )

        if ready != 1:
            not_ready_months.append(cycle)
            continue

        for item in payload.get("SummaryOverview") or []:
            name = item.get("BusinessCodeName") or "Unknown"
            code = item.get("BusinessCode")
            amount = to_float(item.get("RealTotalCost"))
            summary = products.setdefault(name, ProductSummary(name=name, code=code))
            summary.total_amount += amount
            summary.months[cycle] = round(summary.months.get(cycle, 0.0) + amount, 6)

    if args.raw_dir:
        args.raw_dir.mkdir(parents=True, exist_ok=True)
        for cycle, payload in raw_by_cycle.items():
            (args.raw_dir / f"tencent-{cycle}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
            )

    result = {
        "provider": "tencent",
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "amountField": "RealTotalCost",
        "profile": args.profile,
        "endCycle": args.end_cycle,
        "monthSummaries": month_summaries,
        "topProducts": [
            {
                "name": item.name,
                "code": item.code,
                "totalAmount": round(item.total_amount, 6),
                "months": dict(sorted(item.months.items())),
            }
            for item in sorted(products.values(), key=lambda x: x.total_amount, reverse=True)
        ],
        "balance": balance,
        "notReadyMonths": not_ready_months,
        "rawDir": str(args.raw_dir) if args.raw_dir else None,
    }

    output = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
