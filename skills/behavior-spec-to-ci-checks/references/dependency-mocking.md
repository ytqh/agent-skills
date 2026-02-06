# Dependency Inventory and Mocking Rules

目标：让核心业务逻辑在 UT/Integration/E2E 中可重复、可控、无副作用，并在 CI 中稳定跑完。

核心原则：
- 默认不触达外网，不消耗付费 API，不产生真实订单/资金/状态变更。
- 通过依赖注入（DI）隔离外部依赖，核心逻辑只依赖接口/抽象。
- UT 用 fakes/mocks；Integration 用容器化依赖；E2E 仅在显式开关下跑。

## External Dependencies Matrix

| Dependency | Unit Tests (Mock/Fake) | Integration Tests | E2E Notes |
| --- | --- | --- | --- |
| Postgres (polymarket data) | 抽象成 `Repository`/`DAO` 接口，用 in-memory fake 或临时 sqlite 代替（仅限不依赖 PG 特性的场景） | 用 GitHub Actions `services:` 或 docker compose 起 PG，跑迁移/种子数据 | E2E 只连隔离环境，禁止连生产 |
| Redis (task dispatch + comm) | 抽象成 queue/pubsub 接口，用内存队列 fake（或 fakeredis） | redis 容器，验证分布式/并发行为 | E2E 同上，显式开关 |
| Env/Flagsmith dynamic config | 抽象成 `ConfigProvider`，UT 用 dict/fixture 固定值 | 可用 stub server 或本地 Flagsmith 容器 | 不依赖真实 Flagsmith 服务器作为 required checks |
| LLM providers (incl. deepresearch) | fake client 返回固定响应；对 prompt/parse 做 snapshot | 仅做 contract tests（mock server/recording），禁止真实 deepresearch 调用 | 如必须联调，放到手动 workflow，不作为 PR required check |
| Polymarket API | 用 stubbed client；HTTP 层用 responses/vcr 等 | 可用 mock server 或录制回放 | Order 相关操作默认禁用，需要显式 `ENABLE_POLYMARKET_SIDE_EFFECTS=1` 且使用 sandbox key |
| ws-gateway (realtime stream) | fake event emitter / 录制数据回放 | 本地 websocket server + replay fixture | 不连生产网关 |
| Flagsmith server | stub/fixture | container 或 mock server | 不作为 required checks 的硬依赖 |
| Temporal server | mock workflow client；或用官方 testing env（若项目支持） | temporalite/temporal auto-setup 容器 | 不连生产 Temporal |
| Langfuse prompt | prompt 作为版本化输入；UT snapshot prompt + render output | 可用 mock server 或固定导出 | 不依赖真实 Langfuse 在线服务 |

## DI Pattern (Minimum Bar)

要求：核心业务逻辑模块中禁止直接 new 外部 client 或读全局单例，必须由上层注入。

示例（Python）：

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class Deps:
    db: "DbPort"
    redis: "QueuePort"
    config: "ConfigPort"
    polymarket: "PolymarketPort"

def place_order(cmd: PlaceOrder, deps: Deps) -> PlaceOrderResult:
    # core logic uses deps.* only
    ...
```

## Safety Switches (Suggested)

建议统一使用环境变量开关，在 CI 默认关闭所有副作用：
- `ALLOW_EXTERNAL_NETWORK=0`
- `ENABLE_POLYMARKET_SIDE_EFFECTS=0`
- `RUN_E2E=0`

required checks 必须在默认关闭的情况下能通过。

