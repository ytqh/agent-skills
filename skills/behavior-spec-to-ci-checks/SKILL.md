---
name: behavior-spec-to-ci-checks
description: "Generate/update automated PR quality gates from behavior specs (`docs/spec*/**/*.feature`): implement UT/integration/e2e tests with DI + mocks for external deps (Postgres/Redis/Flagsmith/LLM/Polymarket/ws-gateway/Temporal/Langfuse), and wire GitHub Actions required checks that enforce correct execution plus 100% branch coverage for declared core logic modules. Use after behavior-spec-writing."
---

# Behavior Spec To CI Checks

将 `docs/spec*/**/*.feature` 的行为定义落地为“可执行的测试 checks（UT/Integration/E2E + coverage gate）”，并作为 PR required checks 的质量门禁。

重要：
- GitHub Actions 只能运行目标仓库内的文件和命令，不要在 workflow 里引用本 skill 包内的任何路径（例如 `~/.agents/...`）。
- 本 skill 的脚本只用于本地生成/更新测试与 workflow 模板，不应被 CI 直接调用。

## Workflow (Spec -> Tests -> CI)

1. Read spec scope
   - Read changed `.feature` files under `docs/spec/**` or `docs/specs/**`.
2. Define "core logic modules" for the 100% branch coverage gate
   - 明确核心逻辑范围（路径/模块边界），并把它配置到 CI coverage gate 的 `--include`。
3. Inventory external dependencies and plan DI
   - Split dependencies into: data layer, providers/APIs, external services.
   - Refactor to pass dependencies via constructors/factories/parameters (no hidden globals).
4. Prepare mocks/fakes + integration harness
   - Use `references/dependency-mocking.md` as the dependency matrix.
5. Generate/update checks from specs (local generation)
   - Run `scripts/generate_checks_from_gherkin.py` to scaffold/extend behavior tests from `.feature`.
   - Copy/adapt the workflow template from `assets/github-actions/`.
6. Implement tests per scenario
   - UT 优先覆盖核心业务逻辑分支；integration/e2e 只在必要时引入，并默认关闭副作用。
7. Verify locally (must be green)
   - Run tests with branch coverage and enforce 100% for core modules (see `references/ci-quality-gate.md`).

## Deliverables (Write Into Target Repo)

- UT/Integration/E2E tests that cover the behaviors described in specs
- GitHub Actions workflow that runs tests and enforces core-module 100% branch coverage
- DI + mocks/fakes so tests run without external side effects by default

Templates you can copy/adapt into the target repo:
- `assets/github-actions/behavior-spec-quality-gate.python.yml`
- `assets/repo-config/.gherkin-lintc` (optional)

Example (run from inside the target repo):

```bash
python "$HOME/.agents/skills/behavior-spec-to-ci-checks/scripts/generate_checks_from_gherkin.py" \
  --repo-root . \
  --tests-dir tests/behavior \
  --write-workflow
```

## References

- `references/dependency-mocking.md` - external dependency inventory and mocking rules (Postgres/Redis/Flagsmith/LLM/Polymarket/ws-gateway/Temporal/Langfuse)
- `references/ci-quality-gate.md` - required checks, job names, and GitHub Actions wiring
- `references/spec-to-checks.md` - how to derive tests/checks from specs
