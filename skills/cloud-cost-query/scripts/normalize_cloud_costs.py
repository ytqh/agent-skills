#!/usr/bin/env python3
"""Merge provider billing summaries into shared cost categories."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any


CATEGORY_KEYWORDS = {
    "AI": ["百炼", "模型", "大模型", "hunyuan", "混元", "asr", "tts", "语音识别", "语音合成", "machine learning"],
    "Security": ["云安全", "安全中心", "waf", "ddos", "防火墙", "ssl"],
    "Compute": ["ecs", "cvm", "云服务器", "lighthouse", "轻量应用服务器", "cdh"],
    "Storage": ["oss", "cos", "对象存储", "块存储", "快照", "cbs", "cfs", "日志服务", "sls", "cls"],
    "Observability": ["arms", "apm", "opentelemetry", "tracing", "可观测", "应用实时监控", "监控", "链路"],
    "Network": ["clb", "负载均衡", "eip", "cdn", "vpc", "nat", "公网ip"],
    "Database": ["rds", "redis", "mysql", "postgresql", "mongodb", "数据库"],
    "Communication": ["短信", "sms", "邮件", "ses", "消息", "通知"],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="Provider summary JSON files.")
    parser.add_argument("--output", type=Path, help="Optional output path. Defaults to stdout.")
    return parser.parse_args()


def detect_category(name: str) -> str:
    lowered = name.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(keyword in lowered for keyword in keywords):
            return category
    return "Other"


def provider_services(payload: dict[str, Any]) -> list[dict[str, Any]]:
    provider = payload.get("provider")
    services = []

    if provider == "aliyun":
        for item in payload.get("topProducts", []):
            services.append(
                {
                    "provider": provider,
                    "name": item["name"],
                    "amount": float(item.get("totalPretax", 0.0)),
                    "months": item.get("months", {}),
                }
            )
    elif provider == "tencent":
        for item in payload.get("topProducts", []):
            services.append(
                {
                    "provider": provider,
                    "name": item["name"],
                    "amount": float(item.get("totalAmount", 0.0)),
                    "months": item.get("months", {}),
                }
            )
    else:
        raise ValueError(f"Unsupported provider in {provider!r}")

    return services


def main() -> int:
    args = parse_args()

    provider_totals: dict[str, float] = defaultdict(float)
    category_totals: dict[str, float] = defaultdict(float)
    category_providers: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    provider_status: dict[str, dict[str, Any]] = {}
    services_out: list[dict[str, Any]] = []

    for path in args.inputs:
        payload = json.loads(path.read_text())
        provider = payload.get("provider")
        provider_totals.setdefault(provider, 0.0)
        provider_status[provider] = {
            "queriedMonths": [item.get("month") for item in payload.get("monthSummaries", [])],
            "notReadyMonths": payload.get("notReadyMonths", []),
        }
        for service in provider_services(payload):
            category = detect_category(service["name"])
            service_provider = service["provider"]
            amount = round(service["amount"], 6)
            provider_totals[service_provider] += amount
            category_totals[category] += amount
            category_providers[category][service_provider] += amount
            services_out.append(
                {
                    "provider": service_provider,
                    "name": service["name"],
                    "category": category,
                    "amount": amount,
                    "months": service["months"],
                }
            )

    result = {
        "combinedTotal": round(sum(provider_totals.values()), 6),
        "providerTotals": {key: round(value, 6) for key, value in sorted(provider_totals.items())},
        "providerStatus": provider_status,
        "byCategory": [
            {
                "category": category,
                "amount": round(amount, 6),
                "providers": {
                    provider: round(provider_amount, 6)
                    for provider, provider_amount in sorted(category_providers[category].items())
                },
            }
            for category, amount in sorted(category_totals.items(), key=lambda item: item[1], reverse=True)
        ],
        "byService": sorted(services_out, key=lambda item: item["amount"], reverse=True),
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
