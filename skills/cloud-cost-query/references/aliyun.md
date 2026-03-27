# Aliyun Notes

## Use When

Read this file when the request mentions:

- `aliyun`
- `阿里云`
- `Alibaba Cloud`
- `ECS`, `OSS`, `ARMS`, `SLS`
- `百炼`, `Bailian`, `sfm`
- Aliyun billing APIs or `bssopenapi`

## CLI and Permissions

- CLI: `aliyun-cli`
- Billing plugin: `aliyun-cli-bssopenapi`
- Safest billing-read permission: `AliyunBSSReadOnlyAccess`

Official references:

- BSS OpenAPI auth overview: `https://help.aliyun.com/zh/user-center/developer-reference/api-calling-authorization`
- QueryBillOverview: `https://help.aliyun.com/zh/user-center/developer-reference/api-bssopenapi-2017-12-14-querybilloverview`
- QueryInstanceBill: `https://help.aliyun.com/zh/user-center/developer-reference/api-bssopenapi-2017-12-14-queryinstancebill`

## Validation Order

1. `aliyun configure list`
2. `aliyun bssopenapi QueryAccountBalance --region cn-hangzhou`
3. `aliyun bssopenapi QueryBillOverview --BillingCycle 2026-03 --region cn-hangzhou`

Known quirk:

- `aliyun configure list` may show the default profile as `Invalid` when the profile has no default region.
- That does not always mean auth is unusable.
- If billing calls succeed with an explicit `--region`, treat credentials as valid and note that the profile is missing a default region.

## Core Billing APIs

Use these in this order:

1. `QueryAccountBalance`
2. `QueryBillOverview`
3. `QueryBill`
4. `QueryInstanceBill`

`QueryBillOverview` is the default monthly summary source. Aggregate by:

- `PretaxAmount`
- `OutstandingAmount`
- `ProductName`
- `ProductDetail`
- `ProductCode`

## Resource Attribution Workflow

Only do this when account-level service totals are not enough.

Common follow-up commands:

```bash
aliyun bssopenapi QueryInstanceBill --BillingCycle 2026-03 --ProductCode ecs --PageSize 300 --region cn-hangzhou
aliyun bssopenapi QueryInstanceBill --BillingCycle 2026-03 --ProductCode snapshot --PageSize 300 --region cn-hangzhou
aliyun ecs DescribeDisks --region cn-hangzhou --PageSize 100
aliyun ecs DescribeSnapshots --region cn-hangzhou --PageSize 100
aliyun oss ls --region cn-hangzhou
aliyun oss resource-group --method get oss://jim-ai --region cn-hangzhou
aliyun oss du oss://jim-ai --region cn-hangzhou
aliyun oss stat oss://jim-ai --region cn-hangzhou
```

Evidence to prefer:

- `ResourceGroup`
- instance ID to workload mapping
- bucket name to workload mapping
- workload-specific logstore or trace names
- public or private IPs already documented in the workspace

## Product Codes Seen In Practice

These codes were useful in prior investigations:

- `ecs`
- `snapshot`
- `oss`
- `sls`
- `xtrace`
- `dysms`
- `sas`
- `sfm`

Treat them as examples, not a closed list.

## Reporting Rules

- Use exact billing cycles such as `2026-01`, `2026-02`, `2026-03`
- If the current cycle is included, label it as month-to-date
- Prefer `PretaxAmount` for consistent monthly service totals unless the user asks for another accounting basis
