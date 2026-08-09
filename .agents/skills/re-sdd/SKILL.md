---
name: re-sdd
description: Execute an approved RE-MCP implementation plan using fresh implementer and reviewer subagents.
---

# RE-MCP Subagent-Driven Development

Execute the implementation plan supplied by the user using subagents.

## Preflight

1. Read the complete approved implementation plan.
2. Read relevant repository documentation and existing tests.
3. Inspect git status and current branch.
4. Never perform production implementation directly on `main`.
5. If currently on `main`, create a feature branch before changing production files.
6. Identify the plan's existing task boundaries.
7. Identify dependencies between tasks.
8. Stop only if the plan is genuinely ambiguous or internally contradictory.

## Per-Task Workflow

For every implementation task:

1. Invoke a fresh `re-implementer` subagent.
2. Give it:
   - only that task's requirements;
   - relevant decisions established by earlier tasks;
   - required repository safety invariants.
3. Wait for implementation and focused verification.
4. Invoke a fresh `re-task-reviewer` subagent.
5. Give the reviewer:
   - the same task requirements;
   - the implementation diff or commit range;
   - relevant safety requirements.
6. Require independent review of:
   - requirement compliance;
   - correctness;
   - edge cases;
   - failure behavior;
   - test quality;
   - regression risk;
   - scope control.
7. If the reviewer reports BLOCKER or HIGH findings:
   - invoke an implementer to correct them;
   - invoke a fresh reviewer afterward.
8. Do not continue to the next dependent task until the current task passes review.
9. Do not ask the user whether to continue between normal tasks.

## Parallelism

Parallelize independent read-only investigation when useful.

Do not allow multiple implementation subagents to edit overlapping production files concurrently.

Prefer sequential implementation when tasks depend on earlier interfaces or decisions.

## RE-MCP Safety Invariants

Do not weaken:

- source-ROM immutability;
- SHA-256 identity/provenance checks;
- exact-byte/component guards;
- workspace and path containment;
- bounded operations;
- deterministic output requirements;
- mutation conflict detection;
- structural verification;
- static/runtime ambiguity handling;
- fail-closed error behavior.

Never weaken validation merely to make tests pass.

## Final Review

After every implementation task passes individual review:

1. Invoke a fresh `re-final-reviewer` subagent.
2. Give it the complete approved plan and full branch diff.
3. Run the complete appropriate repository verification suite.
4. Resolve any load-bearing findings and re-review.
5. Do not merge automatically.

## Completion Report

Report:

- branch name;
- exact commits;
- tasks completed;
- tests and verification performed;
- reviewer results;
- unresolved risks;
- whether the branch is READY, NOT READY, or BLOCKED for external review/merge.
