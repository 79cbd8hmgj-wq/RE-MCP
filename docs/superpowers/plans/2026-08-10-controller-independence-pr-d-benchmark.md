# Controller Independence 1.0 — PR D Deterministic Controller Benchmark Implementation Plan

> Execute TDD-first on `agent/controller-independence-pr-d-benchmark`. The user's standing authorization covers implementation, review, and merge of this recommended PR D.

**Goal:** Ship a packaged, provider-neutral controller acceptance harness that prepares deterministic synthetic NDS scenarios and scores only machine-verifiable RE-MCP outcomes.

**Architecture:** A standalone Node CLI prepares fresh benchmark workspaces and later scores them using compiled canonical NDS, extraction, controller-checkpoint, and mutation services. It never calls model providers and never collects transcripts or hidden reasoning. A versioned scenario registry owns the fixed prompts. Package acceptance executes the compiled harness in temporary workspaces without network access.

## Global constraints

- No model/provider API calls or provider credentials.
- No new MCP tools.
- No production ROM/debugger/mutation semantic changes.
- Benchmark source ROM is generated synthetically; no caller-supplied/private ROM is accepted.
- `prepare` writes only into an absent or empty explicit benchmark workspace.
- `score` is read-only.
- Every score regenerates the expected source fixture and requires exact byte identity before scenario-specific checks.
- Existing RE-MCP services remain authoritative for canonical parsing, checkpoint integrity/evidence binding, extraction semantics, mutation planning, and published-build verification.
- Scenario success is deterministic; prose wording, transcripts, hidden reasoning, token counts, and provider self-reporting are not scored.
- Physical Continue/provider/DeSmuME acceptance remains separate from CI.

---

## Task 1 — RED benchmark contract

**Create:** `tests/controller-benchmark.test.ts`

Write source-level tests requiring:

- `benchmarks/controller/scenarios.json` with `benchmarkVersion: 1` and exactly `analysis-handoff`, `checkpoint-resume`, `verified-mutation`, and `guard-rejection`;
- each scenario has a bounded fixed prompt and informational `expectedTools` list;
- `scripts/controller-benchmark.mjs` exposes `prepare`/`score`, uses compiled RE-MCP services, regenerates source bytes, has bounded exit semantics, and contains no provider/network/credential or transcript collection surface;
- guard scoring explicitly requires `original-byte-guard-failed` rather than accepting any exception;
- `docs/controller-benchmark.md` documents fresh-workspace comparison and native/provider limits;
- Package workflow ships/runs the benchmark smoke.

Open PR D as draft with the design/plan and RED test before implementation. Require CI/Package to fail because the planned registry/harness/docs are absent.

Commit: `test: define deterministic controller benchmark contract`.

---

## Task 2 — Scenario registry and deterministic preparation

**Create:**
- `benchmarks/controller/scenarios.json`
- `scripts/controller-benchmark.mjs`

Registry format:

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

`expectedTools` is diagnostic metadata only; no transcript/tool-call log is required for scoring.

`prepare` contract:

```text
node scripts/controller-benchmark.mjs prepare <scenario-id> <workspace>
```

Implementation:

1. validate scenario registry/version;
2. require target to be absent or an empty non-symlink directory;
3. create only controlled subdirectories;
4. generate a deterministic valid NDS fixture at `roms/controller-benchmark.nds` using the proven package-smoke geometry (header CRC, ARM9/ARM7, one FAT/FNT file);
5. write valid/invalid mutation manifests only for the scenarios that need them;
6. for `checkpoint-resume`, seed revision 1 through compiled `writeControllerCheckpoint`;
7. write bounded non-authoritative scenario metadata;
8. print bounded JSON containing scenario ID, source SHA, ROM relative path, and fixed prompt.

Commit: `feat: add deterministic controller benchmark preparation`.

---

## Task 3 — Deterministic analysis/checkpoint scoring

**Modify:**
- `scripts/controller-benchmark.mjs`
- `tests/controller-benchmark.test.ts`

Shared `score` preflight:

```text
node scripts/controller-benchmark.mjs score <scenario-id> <workspace> [controller-label]
```

Before scenario-specific checks:

1. require a real non-symlink workspace directory;
2. regenerate expected fixture bytes in memory;
3. require exact ROM byte identity;
4. parse through compiled `readNdsRomMap` and require the expected SHA;
5. validate prepared scenario metadata;
6. treat optional controller label as bounded display metadata only.

Failed deterministic checks print a scorecard and exit 1. Usage/setup failures exit 2.

### `analysis-handoff`

Require:

- canonical `analysis/generated/nds/<prefix>/manifest.json` with the expected static-analysis format/source SHA;
- valid checkpoint revision 1 with authority `controller-state-only`;
- confirmed-fact evidence exactly bound to the current manifest path and SHA.

### `checkpoint-resume`

Do **not** regenerate the full analysis bundle after the seeded checkpoint. The full bundle exporter atomically replaces the whole SHA-scoped analysis directory, which also contains `controller/checkpoint.json`.

Instead require:

- `analysis/generated/nds/<prefix>/arm9.bin` exists and its bytes exactly equal the fixture's canonical ARM9 range;
- checkpoint validates at revision 2;
- a completed action with `outcome: completed` has an exact current path/SHA evidence reference to `arm9.bin`.

Commit: `feat: score controller analysis and checkpoint scenarios`.

---

## Task 4 — Deterministic mutation/rejection scoring

**Modify:**
- `scripts/controller-benchmark.mjs`
- `tests/controller-benchmark.test.ts`

### `verified-mutation`

Preparation writes a format-version-1 exact-SHA manifest containing one guarded same-size ARM9 `replace-bytes` operation.

Scoring:

1. load the manifest through compiled `loadNdsMutationManifest`;
2. call compiled `verifyPublishedNdsMutationBuild` for fresh deterministic revalidation;
3. require verification status `passed` and zero unexpected changed bytes;
4. require checkpoint revision 1;
5. require a completed action with an exact current path/SHA evidence reference to the build's `verification.json`.

### `guard-rejection`

Preparation writes an exact-SHA manifest with deliberately incorrect expected original ARM9 bytes.

Scoring:

1. load through compiled mutation manifest service;
2. call compiled `compileNdsMutationPlan`;
3. require failure with **exact category** `original-byte-guard-failed`—missing/corrupt/different-invalid manifests must not receive credit;
4. require the exact source-SHA controlled output root to be absent or contain no build directories;
5. require checkpoint revision 1 with at least one failed completed action and at least one next action.

No narrative wording is graded.

Commit: `feat: score controller mutation safety scenarios`.

---

## Task 5 — Live protocol docs and packaged functional acceptance

**Create:**
- `docs/controller-benchmark.md`
- `scripts/check-controller-benchmark-install.mjs`

**Modify:**
- `.github/workflows/package.yml`
- `tests/controller-benchmark.test.ts`

Documentation must define:

- build before source-tree benchmark use;
- `prepare` → controller run → `score` flow;
- exact fixed-prompt use and fresh workspace per controller/scenario pair;
- no manual repair before scoring;
- controller label/time/cost are non-authoritative metadata;
- all four scenarios must pass for functional Controller Independence 1.0 acceptance;
- CI does not claim a real Copilot/Continue/provider or Physical DeSmuME run.

Package must ship the registry, harness, guide, smoke, and compiled services.

Assembled-package smoke must:

1. prepare every scenario and canonically parse each generated ROM;
2. prove preparation into a non-empty directory fails without changing its sentinel;
3. complete `analysis-handoff` using compiled bundle extraction + checkpoint services, then score PASS;
4. complete `checkpoint-resume` using compiled ARM9 component extraction + checkpoint revision update, then score PASS;
5. complete `verified-mutation` using compiled mutation build + checkpoint services, then score PASS;
6. complete `guard-rejection` with no output plus a failed-action checkpoint, then score PASS while the scorer independently proves exact canonical guard failure;
7. score an untouched `analysis-handoff` as FAIL;
8. perform no network/provider call.

Successful smoke prints exactly:

```text
Controller benchmark package smoke passed
```

Commit: `test: ship controller benchmark package acceptance`.

---

## Task 6 — Exact-head review and merge

1. Require exact-head CI and Package success.
2. Review the full diff for provider/network calls, private ROM inputs, generic workspace writers, transcript/hidden-reasoning capture, stale scenario semantics, or duplicated trust logic.
3. Require changed production `src/` behavior to remain zero.
4. Require zero unresolved review threads and a mergeable current head.
5. Update the PR body with RED→GREEN history, review fixes, package benchmark-smoke evidence, exact SHA, and live/native exclusions.
6. Mark ready and merge with `expected_head_sha` under standing user authorization.
7. Verify the merge on `main`.
