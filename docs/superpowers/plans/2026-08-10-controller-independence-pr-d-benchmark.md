# Controller Independence 1.0 — PR D Deterministic Controller Benchmark Implementation Plan

> Execute TDD-first on `agent/controller-independence-pr-d-benchmark`. The user's standing authorization covers implementation, review, and merge of this recommended PR D.

**Goal:** Ship a packaged, provider-neutral controller acceptance harness that prepares deterministic synthetic NDS scenarios and scores only machine-verifiable RE-MCP outcomes.

**Architecture:** A standalone Node CLI prepares fresh benchmark workspaces and later scores them using the compiled canonical NDS, controller-checkpoint, extraction, and mutation services. The harness never calls model providers and never collects transcripts or chain-of-thought. Scenario definitions/prompts live in a versioned JSON registry. Package acceptance executes the compiled harness in temporary workspaces without network access.

## Global constraints

- No model/provider API calls or provider credentials.
- No new MCP tools.
- No production ROM/debugger/mutation semantic changes.
- Benchmark source ROM is generated synthetically; no caller-supplied/private ROM is accepted.
- `prepare` writes only into an absent or empty explicit benchmark workspace.
- `score` is read-only.
- Every score regenerates the expected source fixture and requires exact byte identity before scenario-specific checks.
- Existing RE-MCP services remain authoritative for canonical parsing, checkpoint integrity, evidence binding, and published mutation verification.
- Scenario success is deterministic; prose wording, transcripts, chain-of-thought, token counts, and provider self-reporting are not scored.
- Physical Continue/provider/DeSmuME acceptance remains separate from CI.

---

## Task 1 — RED benchmark contract

**Create:**
- `tests/controller-benchmark.test.ts`

### RED

Add source-level tests requiring:

- `benchmarks/controller/scenarios.json` with `benchmarkVersion: 1` and exactly:
  - `analysis-handoff`
  - `checkpoint-resume`
  - `verified-mutation`
  - `guard-rejection`
- each scenario has a non-empty fixed prompt and bounded informational `expectedTools` list;
- `scripts/controller-benchmark.mjs` exposes `prepare` and `score` modes and references compiled canonical services;
- the benchmark script contains no `fetch`, HTTP client, provider key, transcript, or chain-of-thought capture path;
- preparation requires absent/empty workspace and synthetic ROM creation;
- scoring includes source byte-identity validation before scenario-specific checks;
- `docs/controller-benchmark.md` documents fresh-workspace comparison and native/provider acceptance limits;
- Package workflow eventually ships/runs the benchmark smoke.

Open PR D as draft with the design/plan and RED test only. Require CI/Package to fail because the benchmark registry/scripts/docs are absent.

Commit: `test: define deterministic controller benchmark contract`.

---

## Task 2 — Scenario registry and deterministic preparation

**Create:**
- `benchmarks/controller/scenarios.json`
- `scripts/controller-benchmark.mjs`

### Registry

Use one JSON document:

```json
{
  "benchmarkVersion": 1,
  "scenarios": [
    {
      "id": "analysis-handoff",
      "title": "Analysis handoff",
      "prompt": "...",
      "expectedTools": ["nds_inspect_rom", "nds_extract_analysis_bundle", "controller_checkpoint_write"]
    }
  ]
}
```

Prompts state required objective and safety boundary without revealing hidden score implementation details.

### CLI preparation contract

```text
node scripts/controller-benchmark.mjs prepare <scenario-id> <workspace>
```

Implementation:

1. parse and validate scenario registry;
2. require target path to be absent or an empty non-symlink directory;
3. create controlled subdirectories only;
4. generate one deterministic valid NDS ROM at `roms/controller-benchmark.nds`;
5. write valid and invalid mutation manifests only for scenarios that need them;
6. for `checkpoint-resume`, seed revision 1 through the compiled `writeControllerCheckpoint` service;
7. emit bounded JSON with benchmark version, scenario ID, source SHA, ROM relative path, and fixed prompt.

Synthetic ROM construction should reuse the same minimal NDS geometry already proven in packaged mutation smoke: valid header, ARM9/ARM7 ranges, one FNT/FAT file, header CRC, and deterministic bytes.

### TDD / package-level proof

Source tests turn GREEN for registry/script shape. Functional execution waits for Task 5 package smoke where compiled `dist` exists.

Commit: `feat: add deterministic controller benchmark preparation`.

---

## Task 3 — Deterministic analysis/checkpoint scoring

**Modify:**
- `scripts/controller-benchmark.mjs`
- `tests/controller-benchmark.test.ts`

### Shared score preflight

```text
node scripts/controller-benchmark.mjs score <scenario-id> <workspace> [controller-label]
```

Before any scenario score:

1. workspace must exist and not be a symlink;
2. regenerate expected fixture bytes in memory;
3. require the ROM file bytes to equal them exactly;
4. parse via compiled `readNdsRomMap` and require exact expected SHA;
5. controller label, if supplied, must be bounded display metadata only.

Scorecard:

```json
{
  "benchmarkVersion": 1,
  "scenarioId": "analysis-handoff",
  "controllerLabel": null,
  "passed": true,
  "sourceRomSha256": "...",
  "checks": [
    { "id": "source-immutable", "passed": true },
    { "id": "checkpoint-valid", "passed": true }
  ]
}
```

Failed deterministic checks print the scorecard and exit 1. Setup/usage errors exit 2.

### `analysis-handoff`

Require:

- canonical `analysis/generated/nds/<prefix>/manifest.json` exists as a regular file;
- checkpoint read through compiled service succeeds at revision 1;
- checkpoint authority is `controller-state-only`;
- some confirmed-fact evidence ref equals that exact manifest path and hash.

### `checkpoint-resume`

Require:

- same canonical bundle manifest;
- checkpoint validates at revision 2;
- some completed action has `outcome: completed` and exact manifest evidence path/hash.

Do not grade statement/action prose.

Commit: `feat: score controller analysis and checkpoint scenarios`.

---

## Task 4 — Deterministic mutation/rejection scoring

**Modify:**
- `scripts/controller-benchmark.mjs`
- `tests/controller-benchmark.test.ts`

### `verified-mutation`

Preparation creates `plans/valid-mutation.json`:

- format/version 1;
- exact generated source SHA;
- one `replace-bytes` ARM9 operation at a known relative offset;
- exact original bytes and same-size replacement.

Scoring:

1. source identity already passed shared preflight;
2. load manifest using compiled mutation manifest service;
3. call compiled `verifyPublishedNdsMutationBuild` for fresh deterministic revalidation;
4. require verification status `passed` and zero unexpected changed bytes;
5. require checkpoint revision 1;
6. require a completed action with `outcome: completed` and exact hash-bound evidence to that build's `verification.json`.

### `guard-rejection`

Preparation creates `plans/invalid-guard.json` with deliberately incorrect expected original ARM9 bytes.

Scoring:

- source identity passes;
- exact source-SHA controlled output root must be absent or contain no build directories;
- checkpoint validates at revision 1;
- at least one completed action has `outcome: failed`;
- at least one next action exists.

No failure narrative wording is graded.

Commit: `feat: score controller mutation safety scenarios`.

---

## Task 5 — Live protocol docs and packaged functional acceptance

**Create:**
- `docs/controller-benchmark.md`
- `scripts/check-controller-benchmark-install.mjs`

**Modify:**
- `.github/workflows/package.yml`
- `tests/controller-benchmark.test.ts`

### Documentation

Document:

- build RE-MCP before source-tree benchmark use;
- `prepare` → controller run → `score` flow;
- exact fixed prompt use;
- fresh workspace per controller/scenario pair;
- no manual repair before scoring;
- controller label is non-authoritative metadata;
- elapsed time/cost may be recorded externally but is not RE-MCP evidence;
- all four scenarios must pass for functional Controller Independence 1.0 acceptance;
- CI does not claim a real Copilot/Continue/provider or physical DeSmuME run.

### Package smoke

Assembled package must include:

- `benchmarks/controller/scenarios.json`;
- `scripts/controller-benchmark.mjs`;
- `docs/controller-benchmark.md`;
- `scripts/check-controller-benchmark-install.mjs`.

Smoke uses compiled modules and temporary workspaces only. It must:

1. prepare all four scenarios and parse each generated ROM;
2. prove preparing into a non-empty directory fails without changing existing contents;
3. seed/complete `analysis-handoff` using compiled extraction + checkpoint services, then score PASS;
4. score a freshly prepared incomplete `analysis-handoff` as FAIL;
5. complete `verified-mutation` using compiled mutation build + checkpoint services, then score PASS;
6. prove a freshly prepared `guard-rejection` has no output and can be completed with a failed checkpoint state, then score PASS;
7. verify all benchmark source ROMs remain byte-identical;
8. perform no network/provider call.

Package workflow runs this after the existing controller-fallback smoke and before artifact publication.

Successful smoke prints exactly:

```text
Controller benchmark package smoke passed
```

Commit: `test: ship controller benchmark package acceptance`.

---

## Task 6 — Exact-head review and merge

1. Require exact-head CI and Package success.
2. Review full diff for provider/network calls, private ROM inputs, generic workspace writers, transcript/CoT capture, or duplicated RE-MCP trust logic.
3. Require changed production `src/` behavior to remain zero.
4. Require zero unresolved review threads and current head mergeable.
5. Update PR body with RED→GREEN history, package benchmark smoke evidence, exact SHA, and native/provider acceptance exclusions.
6. Mark ready and merge with `expected_head_sha` under standing user authorization.
7. Verify merge on `main`.
