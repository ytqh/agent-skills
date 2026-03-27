#!/usr/bin/env python3
"""Pull recent Aliyun billing cycles and aggregate by service."""

from __future__ import annotations

import argparse
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
    parser.add_argument(
        "--region",
        default="cn-hangzhou",
        help="Aliyun region to pass to billing commands.",
    )
    parser.add_argument("--profile", help="Aliyun CLI profile name.")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        help="Optional directory to store raw QueryBillOverview responses.",
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
    return [
        f"{shift_month(year, month, -offset)[0]:04d}-{shift_month(year, month, -offset)[1]:02d}"
        for offset in range(months - 1, -1, -1)
    ]


def to_float(value: Any) -> float:
    if value in (None, "", "NULL"):
        return 0.0
    return float(value)


def run_aliyun_json(api: str, params: list[str], *, region: str, profile: str | None) -> dict[str, Any]:
    cmd = ["aliyun", "bssopenapi", api, *params, "--region", region]
    if profile:
        cmd.extend(["--profile", profile])
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or f"aliyun command failed: {' '.join(cmd)}"
        raise RuntimeError(message)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"aliyun returned non-JSON output for {api}: {exc}") from exc


@dataclass
class ProductSummary:
    name: str
    total_pretax: float = 0.0
    total_outstanding: float = 0.0
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

    balance = run_aliyun_json("QueryAccountBalance", [], region=args.region, profile=args.profile)

    raw_by_cycle: dict[str, dict[str, Any]] = {}
    month_summaries: list[dict[str, Any]] = []
    products: dict[str, ProductSummary] = {}
    details: dict[str, ProductSummary] = {}

    for cycle in cycles:
        payload = run_aliyun_json(
            "QueryBillOverview",
            ["--BillingCycle", cycle],
            region=args.region,
            profile=args.profile,
        )
        raw_by_cycle[cycle] = payload
        items = payload.get("Data", {}).get("Items", {}).get("Item", [])
        total_pretax = 0.0
        total_outstanding = 0.0

        for item in items:
            pretax = to_float(item.get("PretaxAmount"))
            outstanding = to_float(item.get("OutstandingAmount"))
            product_name = item.get("ProductName") or "Unknown"
            product_detail = item.get("ProductDetail") or product_name
            detail_key = f"{product_name} / {product_detail}"

            total_pretax += pretax
            total_outstanding += outstanding

            product_summary = products.setdefault(product_name, ProductSummary(product_name))
            product_summary.total_pretax += pretax
            product_summary.total_outstanding += outstanding
            product_summary.months[cycle] = round(product_summary.months.get(cycle, 0.0) + pretax, 6)

            detail_summary = details.setdefault(detail_key, ProductSummary(detail_key))
            detail_summary.total_pretax += pretax
            detail_summary.total_outstanding += outstanding
            detail_summary.months[cycle] = round(detail_summary.months.get(cycle, 0.0) + pretax, 6)

        month_summaries.append(
            {
                "month": cycle,
                "totalPretax": round(total_pretax, 6),
                "totalOutstanding": round(total_outstanding, 6),
                "monthToDate": cycle == today_cycle,
            }
        )

    if args.raw_dir:
        args.raw_dir.mkdir(parents=True, exist_ok=True)
        for cycle, payload in raw_by_cycle.items():
            (args.raw_dir / f"aliyun-{cycle}.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
            )

    def serialize(summary: ProductSummary) -> dict[str, Any]:
        return {
            "name": summary.name,
            "totalPretax": round(summary.total_pretax, 6),
            "totalOutstanding": round(summary.total_outstanding, 6),
            "months": dict(sorted(summary.months.items())),
        }

    result = {
        "provider": "aliyun",
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "amountField": "PretaxAmount",
        "region": args.region,
        "profile": args.profile,
        "endCycle": args.end_cycle,
        "monthSummaries": month_summaries,
        "topProducts": [serialize(item) for item in sorted(products.values(), key=lambda x: x.total_pretax, reverse=True)],
        "topDetails": [serialize(item) for item in sorted(details.values(), key=lambda x: x.total_pretax, reverse=True)],
        "balance": balance.get("Data", {}),
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
