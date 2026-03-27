# Category Mapping

Use this mapping only to create a cross-provider summary. Always keep the original provider service names in the report.

## Priority

Map in this order:

1. explicit service name match
2. service detail text
3. product code
4. fallback to `Other`

## Default Categories

### AI

Match keywords such as:

- `百炼`
- `模型`
- `大模型`
- `Hunyuan`
- `混元`
- `ASR`
- `TTS`
- `语音识别`
- `语音合成`
- `machine learning`

### Security

Match keywords such as:

- `云安全`
- `安全中心`
- `WAF`
- `DDoS`
- `防火墙`
- `SSL`

### Compute

Match keywords such as:

- `ECS`
- `CVM`
- `云服务器`
- `轻量应用服务器`
- `Lighthouse`
- `CDH`

### Storage

Match keywords such as:

- `OSS`
- `COS`
- `对象存储`
- `块存储`
- `快照`
- `CBS`
- `CFS`
- `日志服务`
- `SLS`
- `CLS`

### Observability

Match keywords such as:

- `ARMS`
- `APM`
- `OpenTelemetry`
- `Tracing`
- `可观测`
- `应用实时监控`
- `监控`
- `链路`

### Network

Match keywords such as:

- `CLB`
- `负载均衡`
- `EIP`
- `CDN`
- `VPC`
- `NAT`
- `公网IP`

### Database

Match keywords such as:

- `RDS`
- `Redis`
- `MySQL`
- `PostgreSQL`
- `MongoDB`
- `数据库`

### Communication

Match keywords such as:

- `短信`
- `SMS`
- `邮件`
- `SES`
- `消息`
- `通知`

### Other

Use only when none of the above match cleanly.

## Reporting Guidance

- If a service could reasonably fit two categories, explain the choice briefly.
- If the mapping is important for a decision, include one line of justification.
- If the user asks for fewer buckets, merge `Compute + Storage` or `Observability + Logging` in the answer layer rather than changing the raw mapping.
