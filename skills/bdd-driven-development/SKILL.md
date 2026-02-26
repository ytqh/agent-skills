---
name: bdd-driven-development
description: "Use this skill AFTER requirement/feature design is complete and BEFORE implementation. Enforce BDD flow: feature analysis/design -> write/update *.feature specs directly into docs/spec/** -> ask user to review and WAIT for explicit approval command -> generate/update checks (UT/Integration/E2E + CI gate) from approved specs -> prove RED state (new tests fail first) before any implementation."
---

# BDD Driven Development

将行为规范与 CI checks 合并为一个 BDD 开发前置流程。目标是先把行为定义清楚、再把行为转成可执行检查，并且先看到 RED（失败）再进入实现。

## Hard Gates

1. 不要在本 skill 中实现业务功能代码；本 skill 只负责 spec + checks + red proof。
2. 先写 spec，再等用户明确批准，再写 checks。
3. checks 必须先 RED：新增/更新测试需要在当前实现上失败，证明覆盖了尚未实现或不符合预期的行为。
4. 如果 tests 直接通过，说明检查不够有效，必须增强断言或补充分支直到 RED。

## Workflow (Design -> Spec -> Review -> Checks -> RED)

1. Confirm scope and prerequisites
   - 需求设计已完成（例如已有 `docs/plan/**`）。
   - 本步骤仅做变更范围确认：feature 名、受影响模块、验收边界。

2. Feature analysis and impact assessment
   - 确认 feature spec 文件：`docs/spec/feature-spec/{feature-name}.feature`
   - 评估 core spec 影响并按需更新：`docs/spec/core-spec/{module}.feature`
   - 仅更新受影响 core modules，避免无关改动。

3. Write spec files directly
   - 直接写入/更新上述 `.feature` 文件（不是先口头草稿）。
   - 规范格式参考：`references/spec-format.md`
   - 建议标注场景标签：`@happy-path`、`@edge-case`、`@error-handling`、`@regression`、`@pending`

4. Lint spec files
   - 若仓库根目录不存在 `.gherkin-lintc`，复制模板：
     - `cp "$HOME/.agents/skills/bdd-driven-development/assets/repo-config/.gherkin-lintc" ./.gherkin-lintc`
   - 运行：
     - `npx -y gherkin-lint -c .gherkin-lintc <path/to/spec.feature>`
   - 所有更新过的 `.feature` 必须 lint clean。

5. Ask user review and WAIT
   - 向用户展示：
     - 影响范围（feature/core）
     - 已写入的文件路径
     - 关键行为变化摘要
   - 然后等待用户明确指令，例如：
     - `通过 spec，继续 checks`
     - `approve spec and continue`
   - 在收到明确继续指令前，不进入 checks 阶段。

6. Build checks from approved specs
   - 从已批准 `.feature` 推导 test/check 矩阵（UT/Integration/E2E）。
   - 先复用或创建 reusable setup workflow（`workflow_call`），再创建 feature-level e2e caller workflows。
   - 参考与模板：
     - `references/spec-to-checks.md`
     - `references/dependency-mocking.md`
     - `references/ci-quality-gate.md`
     - `assets/github-actions/e2e-setup-reusable.template.yml`
     - `assets/github-actions/e2e-feature-caller.template.yml`
     - `assets/github-actions/behavior-spec-quality-gate.python.yml`
   - 可使用生成脚本做本地骨架生成：
     - `python "$HOME/.agents/skills/bdd-driven-development/scripts/generate_checks_from_gherkin.py" --repo-root . --tests-dir tests/behavior --write-workflow`

7. Enforce RED before implementation
   - 仅运行本次新增/更新的 tests 与对应 gate。
   - 预期结果：至少一个与新行为强相关的用例失败（RED）。
   - 若全部通过：
     - 增强断言（行为结果、错误分支、边界条件）
     - 补充漏测分支（尤其 core logic）
     - 重新运行直到出现 RED
   - 对 core logic modules 维持 100% branch coverage gate（按项目声明的 include 范围）。

8. Handoff for implementation
   - 只有在“spec 已批准 + checks 已建立 + RED 已证明”后，才进入实现阶段（Green/Refactor）。
   - 向用户交付 RED 证据：命令、失败测试名、失败原因摘要。

## Deliverables

- 已写入并 lint clean 的 behavior specs：
  - `docs/spec/feature-spec/{feature-name}.feature`
  - `docs/spec/core-spec/{module}.feature`（如有影响）
- 由 spec 驱动的 checks：
  - UT/Integration/E2E tests
  - reusable setup workflow + feature caller workflows
  - coverage gate（核心逻辑分支覆盖率要求）
- RED 证明（实现前失败证据）

## Important Constraints

- GitHub Actions workflow 中不要引用 `~/.agents/...` 路径；CI 只能运行目标仓库内文件与命令。
- e2e 采用“最小 mock、近真实环境”原则：本地依赖服务优先，第三方外部系统才 mock/stub。

