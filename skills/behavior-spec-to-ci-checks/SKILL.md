---
name: behavior-spec-to-ci-checks
description: "Turn Gherkin behavior specs (`docs/spec/**.feature` or `docs/specs/**.feature`) into PR quality gates: dependency inventory, DI/mocks plan, unit/integration/e2e tests, and GitHub Actions required checks (gherkin-lint, spec traceability, 100% branch coverage for core logic). Use after behavior-spec-writing to prevent untested or side-effectful changes."
---

# Behavior Spec To CI Checks

将 `docs/spec*/**/*.feature` 的行为定义落地为可执行的自动化 checks，并作为 PR required checks 的质量门禁。

## Workflow (Spec -> Tests -> CI)

1. Read spec scope
   - Read changed `.feature` files under:
     - `docs/spec/feature-spec/` and `docs/spec/core-spec/`
     - or `docs/specs/**` if the repo uses that layout
2. Define "core logic modules" for the 100% branch coverage gate
   - Write down exact path/module boundaries (keep it small and business-critical).
3. Inventory external dependencies and plan DI
   - Split dependencies into: data layer, providers/APIs, external services.
   - Refactor to pass dependencies via constructors/factories/parameters (no hidden globals).
4. Prepare mocks/fakes + integration harness
   - Use the dependency matrix in `references/dependency-mocking.md`.
5. Implement tests per scenario
   - Add/confirm a stable spec id tag for each scenario (see "Spec IDs").
   - Write unit tests for pure business logic; write integration/e2e only where needed.
6. Wire CI required checks (GitHub Actions)
   - Add jobs:
     - `spec-lint` (gherkin-lint)
     - `spec-trace` (spec id -> test reference)
     - `coverage-core-100` (100% branch coverage for core modules)
     - Optional: `integration` (Postgres/Redis/Temporal)
   - Use the template under `assets/github-actions/` and guidance in `references/ci-quality-gate.md`.
7. Verify locally (must be green)
   - Run gherkin lint, spec trace check, tests, and coverage gate.
   - Iterate until: behavior traceability is 100% and core modules are 100% branch covered.

## Spec IDs (Traceability Convention)

Automation assumes every `Scenario` / `Scenario Outline` has exactly one tag with prefix `@spec-`.

- Required: one and only one `@spec-...` tag per scenario.
- Stable: never reuse the same spec id for different scenarios.
- Kebab-case: `@spec-order-strategy-001`

Example:

```gherkin
@happy-path @spec-order-create-001
Scenario: Create an order successfully
  Given ...
  When ...
  Then ...
```

In tests, reference the same id as a literal string (anywhere in the test file is fine):

```python
def test_create_order_happy_path():
    \"\"\"@spec-order-create-001\"\"\"
    ...
```

## Scripts (Vendor Into Target Repo For CI)

GitHub Actions runners do not have this skill folder. Vendor the scripts into the target repo (do not reference `~/.agents` in CI), for example:

- `scripts/ci/gherkin_lint_changed.py`
- `scripts/ci/spec_trace_check.py`
- `scripts/ci/python_coverage_gate.py`

### gherkin-lint (changed specs)

```bash
python scripts/ci/gherkin_lint_changed.py --base origin/main --head HEAD
```

### Spec Traceability (PR diff tags)

```bash
python scripts/ci/spec_trace_check.py --mode diff-tags --base origin/main --head HEAD
```

Stricter modes are documented in `references/spec-traceability.md`.

### 100% Branch Coverage Gate (core modules)

1. Run tests with branch coverage:
   - `python -m coverage run --branch -m pytest`
2. Enforce 100% for core modules:
   - `python scripts/ci/python_coverage_gate.py --include 'src/core/*' --fail-under 100`

## References

- `references/dependency-mocking.md` - external dependency inventory and mocking rules (Postgres/Redis/Flagsmith/LLM/Polymarket/ws-gateway/Temporal/Langfuse)
- `references/spec-traceability.md` - spec id conventions and enforcement modes
- `references/ci-quality-gate.md` - required checks, job names, and GitHub Actions wiring
