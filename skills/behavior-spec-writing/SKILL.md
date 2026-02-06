---
name: behavior-spec-writing
description: Write and maintain Gherkin-based behavior specifications (behavior specs) for features and core system modules. Use AFTER completing requirement clarification and writing-plans (docs/plan ready), BEFORE implementation begins. Triggers writing behavior specs, defining acceptance criteria, updating system behavior definitions, creating feature specs, reviewing core module behavior changes, Gherkin specs, BDD specs, 行为规范, 行为定义, 验收标准, 系统行为. Outputs YAML files with embedded Gherkin to docs/spec/feature-spec/ and docs/spec/core-spec/. Also serves as agent memory for understanding current system behavior across modules.
---

# Behavior Spec Writing

Write Gherkin-based behavior specifications that define expected system behavior across features and core modules. Specs serve dual purpose: verification criteria and agent memory for understanding system behavior.

## Workflow

1. Read the implementation plan from `docs/plan/` to understand the change scope
2. Identify affected dimensions:
   - **Feature spec**: new/changed feature → `docs/spec/feature-spec/{feature-name}.yaml`
   - **Core specs**: evaluate impact on each core module → `docs/spec/core-spec/{module}.yaml`
3. Read existing spec files for affected modules (if they exist)
4. Draft new/updated specs using Gherkin syntax in YAML format
5. Present specs to user for review before writing
6. Write approved specs to the correct file paths

## File Structure

### Feature Specs — per feature, created/updated with each feature change

```
docs/spec/feature-spec/{feature-name}.yaml
```

Example: `docs/spec/feature-spec/order-strategy.yaml`

One file per feature. Created when a new feature is introduced. Updated when the feature changes.

### Core Specs — per core module, long-lived and stable

```
docs/spec/core-spec/{module}.yaml
```

Example:
Fixed core modules (create only when first needed, then maintain):

- `docs/spec/core-spec/predict.yaml` — prediction engine behavior
- `docs/spec/core-spec/bet.yaml` — betting logic behavior
- `docs/spec/core-spec/order.yaml` — order processing behavior
- `docs/spec/core-spec/data-sync.yaml` — data synchronization behavior
- `docs/spec/core-spec/trigger.yaml` — trigger/event behavior

After any feature change, evaluate ALL core modules for behavioral impact. Update affected core specs to keep them consistent. Do NOT update core specs that are unaffected.

## Spec File Format

Use YAML with embedded Gherkin. See `references/spec-format.md` for the complete format reference and examples.

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
2. For each affected file, show the full YAML content
3. Highlight what changed vs. previous version (if updating)
4. Wait for user approval or revision requests
5. Only write files after approval
