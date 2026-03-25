---
name: skill-symlink-correctness
description: Ensure all skills follow the correct directory convention — real files live in `.agents/skills/` and `.claude/skills/` contains only symlinks pointing to `../../.agents/skills/{name}`. Run this automatically after creating any new skill (e.g., after skill-creator finishes) to fix any skill that was placed directly in `.claude/skills/` instead of `.agents/skills/`. Also use proactively whenever you notice a skill directory in `.claude/skills/` that is not a symlink.
---

# Skill Symlink Correctness

## Convention

This project keeps skill source files in `.agents/skills/` (the canonical location) and uses symlinks in `.claude/skills/` so Claude Code can discover them.

```
.agents/skills/{skill-name}/     ← real files (SKILL.md, references/, scripts/)
.claude/skills/{skill-name}      ← symlink → ../../.agents/skills/{skill-name}
```

## When to Run

- After `skill-creator` creates or modifies a skill
- After any manual skill creation
- When you notice a non-symlink directory inside `.claude/skills/`

## Steps

### 1. Scan for violations

```bash
for d in .claude/skills/*/; do
  name=$(basename "$d")
  if [ ! -L ".claude/skills/$name" ]; then
    echo "VIOLATION: .claude/skills/$name is a real directory, not a symlink"
  fi
done
```

### 2. Fix each violation

For each real directory found in `.claude/skills/`:

```bash
# Move real files to .agents/skills/
mv .claude/skills/{name} .agents/skills/{name}

# Create symlink
ln -s ../../.agents/skills/{name} .claude/skills/{name}
```

If `.agents/skills/{name}` already exists, merge carefully — check for conflicting files before overwriting.

### 3. Verify

```bash
# Confirm symlink points correctly
ls -la .claude/skills/{name}
# Should show: .claude/skills/{name} -> ../../.agents/skills/{name}

# Confirm real files are accessible through symlink
ls .claude/skills/{name}/SKILL.md
```

### 4. Report

List what was fixed:

```
Fixed: {name} — moved to .agents/skills/{name}, symlinked from .claude/skills/{name}
```

If nothing was wrong, report: "All skills correctly symlinked."
