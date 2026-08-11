# Controller Efficiency / High-Level RE Orchestration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce controller-facing MCP schema overhead, move deterministic RE sequencing into RE-MCP, persist successful investigation progress automatically, and prove the result with a machine-scored targeted-function benchmark.

**Architecture:** Keep the existing low-level tools and services unchanged as the expert foundation. Add profile-based advertisement in front of registration, then add high-level orchestration services that compose existing static-analysis/Ghidra services directly and persist exact-ROM-SHA investigation records. Extend the existing deterministic controller benchmark with a targeted reverse-engineering scenario and schema-size reporting.

**Tech Stack:** TypeScript 5.7, Node.js >=20, Model Context Protocol SDK, Zod, existing Capstone/Ghidra services, node:test.

## Global Constraints

- Existing 52 low-level tools remain available through `re-full`.
- Tool profiles are source-controlled allowlists; invalid profiles fail startup.
- `re-static-core` serialized tool schema payload must be at least 70% smaller than `re-full`.
- Static high-level tools are read-only with respect to the ROM and may not invoke mutation/debugger execution.
- Ghidra escalation requires an already-current exact-ROM-SHA project and never bootstraps/reconciles automatically.
- Successful consequential high-level operations must persist resumable exact-ROM-SHA state before returning success.
- Persistence failures fail closed.
- No chain-of-thought, prompts, secrets, or arbitrary model transcripts are stored.
- All existing source-ROM immutability, ambiguity preservation, and output-bound invariants remain intact.

---

### Task 1 / PR A: MCP profile and advertisement filtering foundation

**Files:**
- Create: `src/tools/profiles.ts`
- Modify: `src/config.ts`
- Modify: `src/index.ts`
- Create: `tests/tool-profiles.test.ts`
- Modify: `tests/config.test.ts`
- Create: `scripts/measure-tool-schemas.mjs`
- Modify: `docs/controller-fallback.md`

**Interfaces:**
- Produces: `ToolProfileName`, `TOOL_PROFILES`, `resolveToolProfile(name)`, `createProfiledToolRegistrar(server, profile)`.
- Produces config field: `ServerConfig.toolProfile: ToolProfileName` from `RE_MCP_TOOL_PROFILE`, default `re-full`.
- Produces script output: JSON with `profile`, `toolCount`, `serializedBytes`, `estimatedTokens`.

- [ ] **Step 1: Write profile/config tests first.** Add tests asserting default `re-full`, rejection of unknown profile, exact allowlist behavior, and that `re-full` contains every currently shipped tool name.
- [ ] **Step 2: Run the focused tests and verify RED.** `npm test -- --test-name-pattern='tool profile|RE_MCP_TOOL_PROFILE'` must fail because profile support does not exist.
- [ ] **Step 3: Implement `src/tools/profiles.ts`.** Define the six named profiles as immutable allowlists. Implement a registrar wrapper whose `tool(...)` forwards registration only when the first argument tool name is allowlisted; record no hidden schema and throw if an unknown profile name is requested.
- [ ] **Step 4: Add config parsing.** `loadConfig()` reads `RE_MCP_TOOL_PROFILE`, defaults to `re-full`, and rejects unsupported values with a deterministic message.
- [ ] **Step 5: Wire the profile in `src/index.ts`.** Create one profiled registrar and pass it to every existing `register*Tools` function and top-level tool registration so excluded tools are never registered/advertised. `server_capabilities` is available only in profiles that explicitly include it and returns `activeToolProfile` without enumerating hidden tool schemas.
- [ ] **Step 6: Implement schema measurement script.** Launch the compiled server once per requested profile, issue MCP `tools/list`, serialize the returned tool descriptors, and print deterministic JSON. Do not estimate from source definitions.
- [ ] **Step 7: Verify profile size acceptance.** Build, run the script for `re-full` and `re-static-core`, and assert `re-static-core` is >=70% smaller in serialized bytes. Add the measurement assertion to `tests/tool-profiles.test.ts` using a deterministic descriptor fixture if process-level testing is too environment-dependent.
- [ ] **Step 8: Document Continue configuration.** Add `RE_MCP_TOOL_PROFILE=re-static-core` and `re-full` examples to `docs/controller-fallback.md`.
- [ ] **Step 9: Run `npm run typecheck && npm test && npm run build`.** All pass.
- [ ] **Step 10: Commit PR A changes.** Commit message: `feat: add controller tool profiles`.

---

### Task 2 / PR B: High-level static reverse-engineering orchestration

**Files:**
- Create: `src/services/re-orchestration/types.ts`
- Create: `src/services/re-orchestration/trace-function.ts`
- Create: `src/services/re-orchestration/data-usage.ts`
- Create: `src/tools/re-orchestration.ts`
- Modify: `src/tools/profiles.ts`
- Modify: `src/index.ts`
- Create: `tests/re-orchestration.test.ts`

**Interfaces:**
- Produces common `ReEvidenceEnvelope` with `operation`, `sourceRomSha256`, `component`, `subject`, `confirmedDeterministicEvidence`, `candidates`, `ambiguities`, `completedPrimitiveStages`, `artifacts`, `recommendedNextAction`, and optional `checkpointRevision`.
- Produces MCP tools `re_trace_function` and `re_investigate_data_usage`.
- Both tools accept exact ROM path plus bounded processor/address/mode/overlay inputs and explicit maxima; they never accept arbitrary shell/output paths.

- [ ] **Step 1: Write synthetic-fixture tests first.** Build a small synthetic ARM9 fixture with a known helper, multiple callers, direct references, and an ambiguous overlay case. Assert compact envelope structure and strict bounds.
- [ ] **Step 2: Run focused tests and verify RED.** `node --test --import tsx tests/re-orchestration.test.ts` must fail because the orchestration services do not exist.
- [ ] **Step 3: Implement common envelope types/normalizers.** Enforce deterministic ordering, bounded candidate arrays, no semantic ranking, and explicit ambiguity records.
- [ ] **Step 4: Implement `traceNdsFunction`.** Compose existing ROM mapping, Capstone backend, xref/reference/function-analysis/CFG services directly. Include only bounded call-site windows and proven function context; preserve partial/inconclusive proof status.
- [ ] **Step 5: Implement `investigateNdsDataUsage`.** Resolve a runtime/data address or exact deterministic pattern hit, find bounded direct users, associate proven containing functions where possible, and return candidates without semantic conclusions.
- [ ] **Step 6: Register MCP tools.** Add `registerReOrchestrationTools`; inputs are Zod-bounded and outputs respect `RE_MCP_MAX_OUTPUT_BYTES`.
- [ ] **Step 7: Add tools to static profiles only.** `re-static-core` includes the two high-level tools plus checkpoint tools and only the minimal low-level escape hatches needed for explicit analyst follow-up.
- [ ] **Step 8: Add negative safety tests.** Assert static orchestration code has no imports from mutation or DeSmuME execution services and cannot write ROM bytes.
- [ ] **Step 9: Run `npm run typecheck && npm test && npm run build`.** All pass.
- [ ] **Step 10: Commit PR B changes.** Commit message: `feat: add bounded static RE orchestration`.

---

### Task 3 / PR C: Controlled Ghidra escalation and automatic investigation persistence

**Files:**
- Create: `src/services/re-orchestration/investigation-journal.ts`
- Create: `src/services/re-orchestration/decompile-candidate.ts`
- Create: `src/services/re-orchestration/resume.ts`
- Modify: `src/tools/re-orchestration.ts`
- Modify: `src/tools/profiles.ts`
- Modify: `src/index.ts`
- Create: `tests/re-investigation-journal.test.ts`
- Create: `tests/re-decompile-resume.test.ts`

**Interfaces:**
- Produces append-only exact-ROM-SHA journal entries with `sequence`, `operationId`, normalized inputs, source SHA, completed stages, artifact hashes, result digest, completion status, and timestamp metadata.
- Produces `persistInvestigationResult(...)`, `readInvestigationJournal(...)`, and `projectInvestigationCheckpoint(...)`.
- Produces MCP tools `re_decompile_candidate` and `re_resume_investigation`.

- [ ] **Step 1: Write journal failure-atomicity tests first.** Assert exact-ROM-SHA scoping, monotonic sequence, integrity hashes, atomic replacement, rejection of corrupted journal state, and no success return if persistence fails.
- [ ] **Step 2: Run focused tests and verify RED.** New journal tests must fail before implementation.
- [ ] **Step 3: Implement journal persistence.** Store only normalized deterministic operation state under `analysis/generated/nds/<sha-prefix>/controller/investigation-journal.jsonl` plus a compact integrity metadata file. Use temporary sibling + fsync/close + rename for metadata/projection updates.
- [ ] **Step 4: Integrate automatic persistence into high-level static tools.** After deterministic analysis succeeds but before MCP success is returned, append the journal entry and update a bounded checkpoint projection. Persistence error converts the operation to a fail-closed error.
- [ ] **Step 5: Implement `decompileReCandidate`.** Require existing current SHA-scoped Ghidra state through existing status/reconciliation checks, inspect exactly one function, run bounded read-only decompilation, and mark Ghidra-derived text as non-authoritative candidate evidence.
- [ ] **Step 6: Implement `resumeInvestigation`.** Revalidate ROM SHA, verify journal integrity, read the current controller checkpoint if present, and return completed deterministic stages/artifact hashes plus the mechanically smallest unresolved next actions without promoting checkpoint prose to ROM fact.
- [ ] **Step 7: Register profile exposure.** `re-ghidra-escalation` exposes static high-level tools, Ghidra candidate escalation, resume/checkpoint tools, and only required read-only Ghidra low-level escapes.
- [ ] **Step 8: Add provider-death regression.** Simulate a successful first operation followed by no further controller work; a fresh `re_resume_investigation` call must recover the persisted successful operation without replaying its primitive analysis.
- [ ] **Step 9: Run `npm run typecheck && npm test && npm run build`.** All pass.
- [ ] **Step 10: Commit PR C changes.** Commit message: `feat: persist and resume RE investigations`.

---

### Task 4 / PR D: Controller-efficiency benchmark and constrained-controller acceptance

**Files:**
- Modify: `benchmarks/controller/scenarios.json`
- Modify: `scripts/controller-benchmark.mjs`
- Modify: `tests/controller-benchmark.test.ts`
- Modify: `docs/controller-benchmark.md`
- Create: `docs/controller-efficiency-acceptance.md`

**Interfaces:**
- Adds scenario ID `targeted-function-investigation`.
- Benchmark preparation emits fixed helper address plus `re-static-core` requirement.
- Scorer verifies source immutability, correct identity-dependent candidate artifact/journal state, completed high-level operation, and checkpoint/journal integrity.
- Score output adds `activeToolProfile`, `advertisedToolCount`, `toolSchemaBytes`, and `toolSchemaEstimatedTokens`.

- [ ] **Step 1: Write benchmark tests first.** Assert scenario registration, deterministic synthetic ROM fixture containing one identity-dependent restriction caller and generic-bounds distractors, and score failure when the wrong caller is persisted.
- [ ] **Step 2: Run benchmark tests and verify RED.** `node --test --import tsx tests/controller-benchmark.test.ts` must fail on the new scenario expectations.
- [ ] **Step 3: Extend fixture preparation.** Emit ARM/Thumb bytes and deterministic metadata sufficient for `re_trace_function` to identify all direct callers while only one caller contains the identity-dependent restriction signature.
- [ ] **Step 4: Extend scorer.** Validate journal/checkpoint integrity and exact evidence for the correct candidate; do not grade prose.
- [ ] **Step 5: Add schema metrics to benchmark output.** Reuse the real `tools/list` measurement path from PR A; metrics are external performance metadata, not ROM evidence.
- [ ] **Step 6: Add constrained-controller runbook.** Document exact prepare/run/score commands, require `RE_MCP_TOOL_PROFILE=re-static-core`, forbid manual repair, and record provider/model label, request acceptance, turns/tool calls, and score.
- [ ] **Step 7: Run all deterministic verification.** `npm run typecheck && npm test && npm run build` and all five benchmark scenarios pass in deterministic harness coverage.
- [ ] **Step 8: Perform the live constrained-controller gate when a free/limited provider is available.** The milestone is practically accepted only after at least one run completes without manual repair. Provider outage is recorded separately and does not weaken deterministic correctness.
- [ ] **Step 9: Commit PR D changes.** Commit message: `test: add targeted controller efficiency benchmark`.

---

## Final verification and merge sequence

For each PR A–D:

1. Branch from the freshly merged previous PR (`main` for PR A).
2. Keep the PR scoped to its task above.
3. Run typecheck, full tests, build, and existing package workflows.
4. Review changed files for fail-closed invariants and unresolved threads.
5. Merge with `expected_head_sha` protection only after exact-head checks pass.
6. Pull/branch from the new `main` before beginning the next PR.

The live free-controller gate is the only part that depends on external provider availability; PR D may merge with deterministic tests and the gate documented as pending, but the overall Controller Efficiency milestone must remain marked **not practically accepted** until one constrained controller passes without manual repair.