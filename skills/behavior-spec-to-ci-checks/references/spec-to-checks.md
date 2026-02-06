# Spec -> Checks (Generate/Update Tests + CI)

目标：把 `docs/spec*/**/*.feature` 中定义的行为，转化为“可执行的自动化 checks”（UT/Integration/E2E + coverage gate），作为 PR required checks。

## What "Checks" Means Here

checks 指的是“跑起来的测试与覆盖率门禁”，不是对 `.feature` 文件做静态校验。

典型 required checks（建议最小集合）：
- `quality-gate`：运行测试 + 对核心逻辑模块强制 100% branch coverage

可选 checks（按项目需要添加）：
- `integration`：只跑需要 Postgres/Redis/Temporal 的集成用例
- `e2e`：端到端流程（默认关闭副作用开关，或仅在手动触发时运行）

## Derive Test Cases From Specs

对每个 `.feature` 文件：
1. 把 `Background` 作为共享 fixture（系统初始化、连接建立等）
2. 每个 `Scenario` 生成 1 个测试用例
3. 每个 `Scenario Outline + Examples` 生成参数化测试（每行 examples 对应 1 case）

建议在测试里保留原始 spec 文本片段，便于 review：
- Feature 名称
- Scenario 名称
- Given/When/Then 步骤列表（原样注释即可）

## Decide Test Level Per Scenario

按“最小代价拿到最高确定性”的原则：
- UT：优先覆盖核心业务逻辑分支（纯函数/纯逻辑），全部外部依赖 mock/fake
- Integration：验证 data layer / queue / temporal 等组件边界（可用容器）
- E2E：只覆盖少量关键链路（例如从触发到下单的完整 pipeline），但必须无副作用或只打 sandbox

## Update Strategy (Generate/Update)

推荐做法：由本 skill 的生成脚本在本地基于 spec 输出“测试骨架”，然后你补齐断言与依赖 mock。

要求：
- 生成脚本只做“新增骨架/新增用例”的增量更新，避免覆盖你已经写好的测试逻辑
- 对于改名/删除 scenario，手工清理对应测试函数

## Coverage Gate (100% Branch)

核心模块范围必须显式定义（例如 `src/core/*`）。

强制项：
- required checks 中对核心模块 branch coverage 必须是 100%
- 如果 coverage 不足：优先补 UT；必要时补 integration/e2e（但不要引入外部副作用）

