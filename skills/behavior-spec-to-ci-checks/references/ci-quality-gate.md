# CI Quality Gate (GitHub Actions)

目标：将以下 checks 作为 PR required checks：
- `spec-lint`：Gherkin `.feature` lint（gherkin-lint）
- `spec-trace`：新增/修改行为必须被测试引用（Spec -> Tests）
- `tests + coverage-core-100`：核心模块 100% branch coverage
- 可选：`integration`（Postgres/Redis/Temporal）

## Required Checks Naming

GitHub branch protection 依赖 check name。保持 job `name:` 稳定，避免 matrix 产生多份 check 导致 required checks 配置复杂化。

## Make CI Self-Contained

不要在 workflow 里引用 `~/.agents/...`。CI runner 不会携带本地 skills。

做法：
1. 将本 skill 下 `scripts/*.py` vendoring 到目标仓库（例如 `scripts/ci/`）
2. workflow 只调用仓库内脚本

## Workflow Template

见 `assets/github-actions/behavior-spec-quality-gate.python.yml`（复制到目标仓库的 `.github/workflows/` 后按项目实际依赖安装方式修改）。

## Coverage Gate Notes (Python)

必须启用 branch coverage 数据：
- `python -m coverage run --branch -m pytest`
- 或 `.coveragerc` 设置 `branch = True`

然后用 gate 脚本强制 100%：
- `python scripts/ci/python_coverage_gate.py --require-branch-data --fail-under 100 --include 'src/core/*'`

