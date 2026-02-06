---
name: behavior-spec-writing
description: Write and maintain Gherkin `.feature` behavior specifications (behavior specs) for features and core system modules. Use AFTER completing requirement clarification and writing-plans (docs/plan ready), BEFORE implementation begins. Triggers writing behavior specs, defining acceptance criteria, updating system behavior definitions, creating feature specs, reviewing core module behavior changes, Gherkin specs, BDD specs, 行为规范, 行为定义, 验收标准, 系统行为. Outputs `.feature` files to docs/spec/feature-spec/ and docs/spec/core-spec/ and lints generated specs with gherkin-lint. Also serves as agent memory for understanding current system behavior across modules.
---

# Behavior Spec Writing

Write Gherkin-based behavior specifications that define expected system behavior across features and core modules. Specs serve dual purpose: verification criteria and agent memory for understanding system behavior.

## Workflow

1. Read the implementation plan from `docs/plan/` to understand the change scope
2. Identify affected dimensions:
   - **Feature spec**: new/changed feature → `docs/spec/feature-spec/{feature-name}.feature`
   - **Core specs**: evaluate impact on each core module → `docs/spec/core-spec/{module}.feature`
3. Read existing spec files for affected modules (if they exist)
4. Draft new/updated specs as standard Gherkin `.feature` files (see `references/spec-format.md`)
5. Ensure gherkin-lint config exists in the repo root:
   - If `.gherkin-lintc` does not exist, copy the bundled config from this skill: `cp "$HOME/.agents/skills/behavior-spec-writing/.gherkin-lintc" ./.gherkin-lintc`
6. Lint the drafted spec content (use a temp file if you haven't written the final path yet):
   - `npx -y gherkin-lint -c .gherkin-lintc <path/to/spec.feature>`
   - Fix lint issues and re-run until clean
7. Present specs to user for review before writing
8. Write approved specs to the correct file paths
9. After writing, lint the created/updated `.feature` files again with gherkin-lint (must be clean)

## File Structure

### Feature Specs — per feature, created/updated with each feature change

```
docs/spec/feature-spec/{feature-name}.feature
```

Example: `docs/spec/feature-spec/order-strategy.feature`

One file per feature. Created when a new feature is introduced. Updated when the feature changes.

### Core Specs — per core module, long-lived and stable

```
docs/spec/core-spec/{module}.feature
```

Example:
Fixed core modules (create only when first needed, then maintain):

- `docs/spec/core-spec/predict.feature` — prediction engine behavior
- `docs/spec/core-spec/bet.feature` — betting logic behavior
- `docs/spec/core-spec/order.feature` — order processing behavior
- `docs/spec/core-spec/data-sync.feature` — data synchronization behavior
- `docs/spec/core-spec/trigger.feature` — trigger/event behavior

After any feature change, evaluate ALL core modules for behavioral impact. Update affected core specs to keep them consistent. Do NOT update core specs that are unaffected.

## Spec File Format

Use standard Gherkin `.feature` format. See `references/spec-format.md` for the complete format reference and examples.

Key rules:
- Write in **declarative style** — describe WHAT the system does, not HOW
- Use **business language**, not implementation details
- Cover **happy path, edge cases, and error handling**
- Use `Scenario Outline` + `Examples` for parameterized cases
- Tag scenarios: `@happy-path`, `@edge-case`, `@error-handling`, `@regression`
- Write specs in the **language matching the project** (Chinese comments OK if project uses Chinese)

## Impact Assessment Checklist

When a new feature or change is planned, evaluate each core module:
Mark affected modules → read their current specs → draft updates → present to user.

## Review Protocol

ALWAYS present drafted specs to the user before writing files:

1. Show the impact assessment checklist result
2. For each affected file, show the full `.feature` content
3. Highlight what changed vs. previous version (if updating)
4. Wait for user approval or revision requests
5. Only write files after approval
