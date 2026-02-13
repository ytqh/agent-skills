---
name: behavior-spec-to-ci-checks
description: "Generate/update CI quality gates from behavior specs (`docs/spec*/**/*.feature`): first create/reuse a reusable GitHub Actions setup workflow for CI environment bootstrapping, then create feature-level e2e checks that run on top of it; also implement UT/integration/e2e tests with DI and enforce 100% branch coverage for declared core modules."
---

# Behavior Spec To CI Checks

将 `docs/spec*/**/*.feature` 的行为定义落地为“可执行的 CI checks（UT/Integration/E2E + coverage gate）”，并作为 PR required checks 的质量门禁。

核心策略（通用，跨项目）：
- 先建设/复用可复用的 CI setup workflow（环境层，`workflow_call`）。
- 再为每个 feature 建立独立的 e2e caller workflow（场景层，按 feature 拆分 checks）。
- e2e 默认优先“少 mock、近真实环境”：在 CI 内启动本地依赖服务 + 固定 seed 数据；仅对无法本地稳定运行的外部第三方依赖做 fixture mock。

重要：
- GitHub Actions 只能运行目标仓库内的文件和命令，不要在 workflow 里引用本 skill 包内的任何路径（例如 `~/.agents/...`）。
- 本 skill 的脚本只用于本地生成/更新测试与 workflow 模板，不应被 CI 直接调用。
- 不要假定目标项目的技术栈、目录结构、启动命令完全一致；只使用“可覆盖的通用 convention”。

## Workflow (Spec -> Tests -> CI)

1. Read spec scope
   - Read changed `.feature` files under `docs/spec/**` or `docs/specs/**`.
2. Build test/check matrix from specs
   - Group scenarios by feature; define check granularity (`e2e-<feature>`, integration, unit).
   - Decide which scenarios must be endpoint-level e2e and which can stay integration/unit.
3. Inventory external dependencies and plan DI
   - Split dependencies into: data layer, providers/APIs, external services.
   - Refactor to pass dependencies via constructors/factories/parameters (no hidden globals).
4. Create or reuse reusable CI setup workflow (foundation)
   - First detect existing reusable workflow(s) under `.github/workflows/*.yml` using `on.workflow_call`.
   - If one already provides stable env setup for e2e (services, migration, seed, app startup, health check), reuse/optimize it.
   - Otherwise create a reusable setup workflow (convention example: `.github/workflows/e2e-setup-reusable.yml`).
   - Keep setup workflow focused on environment bootstrapping and execution plumbing, not feature logic.
   - Recommended reusable inputs:
     - runtime/install parameters (language version, install command, working directory)
     - infra/bootstrap commands (migration command, seed command, startup command, healthcheck URL/timeout)
     - test command args (e.g., pytest args)
     - optional behavior toggles (fail-if-no-tests, artifact/log upload)
5. Create feature e2e caller workflows (feature layer)
   - For each feature (or stable feature group), add caller workflow that `uses` the reusable setup workflow.
   - Pass only feature-specific parameters: test selector/tag/path, seed profile, optional overrides.
   - Conventions (customizable):
     - workflow file: `.github/workflows/e2e-<feature>.yml`
     - check/job name: `e2e-<feature>`
     - tests path: `tests/e2e/features/<feature>/`
     - seed loader entry: `tests/e2e/seed/load_seed.* --profile <feature-profile>`
6. Prepare mocks/fakes with "minimal mocking" rule
   - Use `references/dependency-mocking.md` as dependency matrix.
   - Prefer real local services in CI for DB/cache/queue/workflow engines when feasible.
   - Mock/stub only true external dependencies (third-party APIs, paid SaaS, unstable network systems).
7. Generate/update checks from specs (local generation)
   - Run `scripts/generate_checks_from_gherkin.py` to scaffold/extend behavior tests from `.feature`.
   - Copy/adapt workflow template(s) from `assets/github-actions/`.
8. Implement tests per scenario
   - e2e: endpoint-level, BDD-oriented, backed by seeded fixtures.
   - integration/unit: cover branch-heavy business logic and failure branches.
9. Define "core logic modules" for the 100% branch coverage gate
   - 明确核心逻辑范围（路径/模块边界），并把它配置到 CI coverage gate 的 `--include`。
10. Verify locally (must be green)
   - Run tests with branch coverage and enforce 100% for core modules (see `references/ci-quality-gate.md`).

## Deliverables (Write Into Target Repo)

- Reusable CI setup workflow for e2e foundation (create or optimize existing one)
- Feature-level e2e caller workflows that reuse setup workflow
- UT/Integration/E2E tests that cover the behaviors described in specs
- Coverage gate workflow enforcing 100% branch coverage for declared core modules
- DI + fixture/mocks strategy document in tests (what is real local service vs what is mocked)

Templates you can copy/adapt into the target repo:
- `assets/github-actions/e2e-setup-reusable.template.yml`
- `assets/github-actions/e2e-feature-caller.template.yml`
- `assets/github-actions/behavior-spec-quality-gate.python.yml`
- `assets/repo-config/.gherkin-lintc` (optional)

Example (run from inside the target repo):

```bash
python "$HOME/.agents/skills/behavior-spec-to-ci-checks/scripts/generate_checks_from_gherkin.py" \
  --repo-root . \
  --tests-dir tests/behavior \
  --write-workflow
```

## Reusable Workflow Conventions (Cross-Project)

Use these as defaults, not hard requirements:

- Reusable setup workflow:
  - `.github/workflows/e2e-setup-reusable.yml`
  - trigger: `on: workflow_call`
  - job purpose: setup infra + bootstrap app + execute passed test command
- Feature caller workflows:
  - `.github/workflows/e2e-<feature>.yml`
  - trigger: `pull_request`/`workflow_dispatch`
  - job uses reusable setup via `jobs.<job_id>.uses`
- Seed conventions:
  - Use fixed deterministic seed profiles in CI
  - Do not sync production data in CI
- Required check stability:
  - Keep check names stable over time to avoid branch protection churn

## References

- `references/dependency-mocking.md` - external dependency inventory and mocking rules (Postgres/Redis/Flagsmith/LLM/Polymarket/ws-gateway/Temporal/Langfuse)
- `references/ci-quality-gate.md` - required checks, job names, and GitHub Actions wiring
- `references/spec-to-checks.md` - how to derive tests/checks from specs
