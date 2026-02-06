# Spec Traceability (Spec -> Tests) Enforcement

目的：把 `.feature` 的行为定义变成可验证的质量门禁，避免出现“spec 写了，但没有任何测试覆盖”的 PR。

## Tag Convention

对每个 `Scenario` / `Scenario Outline`：
- 必须有且仅有一个 `@spec-...` tag
- tag 采用 kebab-case，例如 `@spec-order-create-001`
- 一个 spec id 只能对应一个 scenario（禁止复用）

## Enforcement Modes

`scripts/spec_trace_check.py` 支持逐步落地：

1. `--mode diff-tags` (recommended for rollout)
   - 只检查 PR diff 中新增的 `@spec-...` tag
   - 适合存量仓库渐进式引入

2. `--mode changed-files`
   - 检查 PR 中所有被修改的 `.feature` 文件里的全部 spec ids
   - 更严格，适合逐步提高门槛

3. `--mode all`
   - 检查全仓库 `.feature` spec ids
   - 适合已经完成迁移的成熟仓库

## Extra Gates

- `--require-scenario-tags`
  - 对选中的 `.feature` 文件，检查每个 scenario 是否有且仅有一个 `@spec-...`

- `--enforce-unique-spec-ids`
  - 对选中的 `.feature` 文件，检查 spec id 是否跨文件重复

推荐组合（逐步升级）：
1. diff-tags
2. diff-tags + require-scenario-tags
3. changed-files + require-scenario-tags + enforce-unique-spec-ids
4. all + require-scenario-tags + enforce-unique-spec-ids

