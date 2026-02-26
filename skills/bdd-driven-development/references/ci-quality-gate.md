# CI Quality Gate (GitHub Actions)

目标：将“行为验证 tests + 100% branch coverage（核心逻辑模块）”作为 PR required checks 的质量门禁。

## Required Checks Naming

GitHub branch protection 依赖 check name。保持 job `name:` 稳定，避免 matrix 产生多份 check 导致 required checks 配置复杂化。

## Make CI Self-Contained

不要在 workflow 里引用 `~/.agents/...` 或任何本地 skills 路径。CI runner 不会携带本 skill 包。

做法：
1. 将所有 checks 逻辑以“目标仓库内的文件 + 标准命令”的形式落地（tests / lint / coverage）
2. workflow 只调用目标仓库中的命令（例如 `pytest`, `go test`, `npm test`, `coverage report`, `npx gherkin-lint`）

## Workflow Template

见 `assets/github-actions/behavior-spec-quality-gate.python.yml`（复制到目标仓库的 `.github/workflows/` 后按项目实际依赖安装方式修改）。

## Coverage Gate Notes (Python)

必须启用 branch coverage 数据：
- `python -m coverage run --branch -m pytest`
- 或 `.coveragerc` 设置 `branch = True`

然后用 gate 脚本强制 100%：
- `python -m coverage report --precision=2 --show-missing --fail-under=100 --include 'src/core/*'`
