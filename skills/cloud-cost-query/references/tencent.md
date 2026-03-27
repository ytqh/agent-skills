# Tencent Notes

## Use When

Read this file when the request mentions:

- `tencent`
- `腾讯云`
- `tccli`
- Tencent billing APIs
- `CVM`, `COS`, `CLB`, `CLS`

## CLI and Permissions

- CLI: `tccli`
- Safest billing-read permission: `QcloudFinanceBillReadOnlyAccess`

Official references:

- Billing action list: `https://cloud.tencent.com/document/product/555/19170`
- DescribeBillSummaryByProduct data types: `https://intl.cloud.tencent.com/document/product/555/30757`
- DescribeBillDetail example: `https://intl.cloud.tencent.com/document/product/555/30756`

## Validation Order

1. `tccli billing DescribeAccountBalance`
2. `tccli billing DescribeBillSummaryByProduct --BeginTime 2026-02-01 --EndTime 2026-02-28`

Use a settled month first. If you query the active month and get `Ready: 0`, do not treat that as a credential failure.

## Core Billing APIs

Use these in this order:

1. `DescribeAccountBalance`
2. `DescribeBillSummaryByProduct`
3. `DescribeBillSummaryByRegion` or `DescribeBillSummaryByProject` when needed
4. `DescribeBillDetail` only when the user specifically needs detail rows

Key output fields for `DescribeBillSummaryByProduct`:

- `Ready`
- `SummaryTotal.RealTotalCost`
- `SummaryOverview[].BusinessCodeName`
- `SummaryOverview[].RealTotalCost`
- `SummaryOverview[].RealTotalCostRatio`

## Known Quirks

- `DescribeBillSummaryByProduct` needs `BeginTime` and `EndTime`; a bare `--Month` call is not enough for the workflow used here.
- `Ready: 0` usually means the period is not ready or the account is initializing bill data.
- Summary calls are safer than detail calls for first-pass validation.
- `DescribeBillDetail` may require extra parameters depending on the bill shape. Do not start there.

## Reporting Rules

- Use exact windows like `2026-02-01` to `2026-02-28`
- Prefer `RealTotalCost` as the spend amount unless the user asks for gross or pre-discount numbers
- Preserve the raw Tencent product names in the final report
