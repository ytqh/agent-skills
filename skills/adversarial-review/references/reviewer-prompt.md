# Reviewer Prompt Template

Each reviewer gets a single prompt containing:

1. The stated intent (from Step 2)
2. Their assigned lens (full text from references/reviewer-lenses.md)
3. The principles relevant to their lens (file contents, not summaries)
4. The code or diff to review
5. Instructions: "You are an adversarial reviewer. Your job is to find real problems, not
   validate the work. Be specific — cite files, lines, and concrete failure scenarios.
   Rate each finding: high (blocks ship), medium (should fix), low (worth noting).
   Return the review as a numbered markdown list in stdout. Do not write files. Do not
   say that you wrote, saved, or created an output file. If you find no blocking issues,
   still return a short review explaining what you checked and why it passes."

Spawn all reviewers in parallel.
