---
name: cloud-cost-query
description: Query and analyze cloud-service billing with a repeatable workflow. Use when users ask about Aliyun or Tencent Cloud costs, bills, spending, charges, 账单, 费用, 成本, billing trends, month-by-month changes, category breakdowns, or resource-level attribution. Default providers are Aliyun and Tencent Cloud. Supports validating CLI auth, pulling recent monthly summaries, normalizing service categories, and drilling down into resource evidence when attribution matters.
---

# Cloud Cost Query

## Overview

Use this skill to analyze cloud bills from official CLIs first, then normalize the results into provider, service, category, and resource-level summaries.

Default scope is `aliyun` plus `tencent`. Only expand to other providers if the user explicitly asks.

## Quick Start

For the default path, run:

```bash
python3 scripts/query_aliyun_bills.py --months 3 --output /tmp/aliyun-bills.json
python3 scripts/query_tencent_bills.py --months 3 --output /tmp/tencent-bills.json
python3 scripts/normalize_cloud_costs.py /tmp/aliyun-bills.json /tmp/tencent-bills.json
```

Then write a concise report with:

- total by provider
- month-by-month movement
- top services
- grouped category totals
- explicit caveats for current-month partial data or not-ready billing windows

## Workflow

### 1. Reuse Local Evidence First

Before hitting provider APIs, check whether the workspace or the machine already has:

- prior bill exports
- cost-analysis scripts
- Notion settlement pages
- local dashboards or CSV exports

Use existing artifacts when they are already the requested source of truth. Otherwise continue with live CLI queries.

### 2. Fix Scope Before Querying

Confirm three things early:

- providers: default to `aliyun` and `tencent`
- window: default to the most recent `3` billing cycles
- granularity: service/category summary first, resource attribution only if the user asks or the account mixes workloads

When the user says "this month", "recent", or "latest", state exact month boundaries in the answer. If the current month is included, label it as month-to-date with the exact date.

### 3. Validate Auth With the Smallest Read-Only Calls

Do not start with a broad bill export. First prove that auth and billing-read permission are working.

For Aliyun:

- run `aliyun configure list`
- run `aliyun bssopenapi QueryAccountBalance --region cn-hangzhou`

For Tencent Cloud:

- run `tccli billing DescribeAccountBalance`
- run one settled-cycle summary such as `tccli billing DescribeBillSummaryByProduct --BeginTime 2026-02-01 --EndTime 2026-02-28`

If auth is missing, stop at the exact login or permission boundary and tell the user the minimum required permission.

### 4. Pull Monthly Summaries

Use the helper scripts unless the user explicitly wants raw commands only.

- `scripts/query_aliyun_bills.py` pulls `QueryBillOverview` for each billing cycle and aggregates by `ProductName` and `ProductDetail`
- `scripts/query_tencent_bills.py` pulls `DescribeBillSummaryByProduct` for each billing window and aggregates by product

If command syntax or response fields are unclear, verify against official provider documentation before continuing. Prefer official docs only.

### 5. Normalize Categories

Use `scripts/normalize_cloud_costs.py` to merge provider outputs into cross-provider categories.

Read [references/category-mapping.md](./references/category-mapping.md) when:

- the user wants a unified category report across providers
- product names do not map cleanly
- you need to explain why a service landed in a category

Always preserve the raw provider service names in the final write-up even after grouping.

### 6. Drill Into Resource Attribution Only When Needed

Do not assume the whole account belongs to one workload.

For mixed-use accounts:

- start from summary services that matter
- query instance-level bills or resource metadata
- use resource groups, bucket names, instance IDs, tags, and workload-specific log names as evidence

Read [references/aliyun.md](./references/aliyun.md) for the Aliyun attribution workflow. Read [references/tencent.md](./references/tencent.md) for Tencent-specific notes.

### 7. Report Conservatively

Separate:

- confirmed costs
- inferred or probable costs
- unavailable or not-ready periods

Do not flatten uncertainty. If a provider returns partial or not-ready data, say so explicitly.

## Provider References

- Read [references/aliyun.md](./references/aliyun.md) when the scope includes `aliyun`, `阿里云`, `Alibaba Cloud`, `ECS`, `OSS`, `ARMS`, `百炼`, or Aliyun-specific billing APIs.
- Read [references/tencent.md](./references/tencent.md) when the scope includes `tencent`, `腾讯云`, `tccli`, `CVM`, `COS`, or Tencent billing APIs.
- Read [references/category-mapping.md](./references/category-mapping.md) when producing a combined category report.

## Scripts

- [scripts/query_aliyun_bills.py](./scripts/query_aliyun_bills.py): Pull recent Aliyun billing cycles and aggregate by service and service detail.
- [scripts/query_tencent_bills.py](./scripts/query_tencent_bills.py): Pull recent Tencent Cloud billing cycles and aggregate by product.
- [scripts/normalize_cloud_costs.py](./scripts/normalize_cloud_costs.py): Merge provider reports into a combined view by provider, service, and category.

## Output Standard

Prefer this answer shape:

1. one-paragraph summary with the exact date scope
2. provider totals
3. top services with month deltas
4. category totals
5. caveats and next drill-down options

If the user asked for "latest" or "today", include exact dates such as `March 26, 2026` rather than relative phrasing alone.
