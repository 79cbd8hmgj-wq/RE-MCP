# Controller Independence 1.0 — PR D: Deterministic Controller Benchmark Design

Date: 2026-08-10
Status: approved under the user's standing authorization for PR D

## Goal

Add a repeatable, provider-neutral acceptance/benchmark harness for RE-MCP controllers so GitHub Copilot, Continue through Groq/OpenRouter/Ollama, and future controllers can be compared by **deterministic RE-MCP outcomes** rather than by model prose, transcripts, or chain-of-thought.

PR D does not call any model provider itself. It prepares synthetic NDS workspaces, gives the human/controller a fixed task prompt, and then scores the resulting RE-MCP artifacts after the controller run.

## Approaches considered

### A. Deterministic artifact scoring — selected

Prepare exact synthetic ROM scenarios and score only machine-verifiable outcomes:

- source ROM remains byte-identical;
- canonical analysis artifacts exist where expected;
- controller checkpoints pass RE-MCP integrity/revision checks;
- evidence references are hash-bound;
- guarded mutation builds freshly verify;
- invalid guards produce no unauthorized output.

Advantages:
- provider-neutral;
- no benchmark API credentials;
- repeatable across Copilot/Continue/future controllers;
- does not require or store model reasoning;
- failures map to concrete RE-MCP invariants.

Trade-off:
- measures whether the controller completed the task safely/correctly, not subjective code-writing style or conversational quality.

### B. Transcript + model-judge scoring — rejected

Store controller transcripts and ask another model to grade them.

Rejected because it is subjective, provider-coupled, leaks more user/controller data, encourages chain-of-thought capture, and can disagree with deterministic ROM evidence.

### C. Live cloud-provider benchmark in CI — rejected

Have GitHub Actions call Groq/OpenRouter/etc. directly.

Rejected because provider quotas, credentials, network availability, and model inventory would make repository acceptance flaky and would couple RE-MCP CI to external providers.

## Architecture

```text
node scripts/controller-benchmark.mjs prepare <scenario> <empty-workspace>
                              |
                              v
                    deterministic workspace
                    + fixed prompt on stdout
                              |
                              v
                human-selected controller run
                 (Copilot / Continue / later)
                              |
                              v
node scripts/controller-benchmark.mjs score <scenario> <workspace>
                              |
                              v
                deterministic JSON scorecard
```

The controller talks to RE-MCP normally. The benchmark harness does not sit between the controller and RE-MCP and does not proxy MCP calls.

## Safety boundary

- No new MCP tool is added.
- No model/provider API call is added.
- No provider credential is accepted by the benchmark harness.
- No transcript, prompt response, hidden reasoning, or chain-of-thought is collected.
- The harness may create files only inside an explicit benchmark workspace that must be absent or empty at `prepare` time.
- The benchmark source ROM is synthetic and deterministic; `score` reconstructs the expected source bytes and requires exact byte identity.
- Real/private ROMs are not accepted as benchmark source inputs.
- Existing RE-MCP analysis/mutation/checkpoint services remain authoritative.
- Physical DeSmuME acceptance remains a separate native gate.

## Benchmark fixture

All scenarios use one deterministic synthetic `.nds` fixture created by the harness. It contains:

- valid NDS header;
- ARM9 and ARM7 main regions;
- one small NitroFS file;
- FAT/FNT metadata;
- no dynamic/emulator dependency.

The fixture is generated from code, not checked in as a binary. `score` regenerates the expected bytes in memory and compares them byte-for-byte with the workspace ROM before evaluating any scenario result.

The workspace layout is controlled:

```text
<workspace>/
├── roms/
│   └── controller-benchmark.nds
├── plans/
│   ├── valid-mutation.json        # mutation scenarios
│   └── invalid-guard.json         # rejection scenario
└── benchmark/
    └── scenario.json              # non-authoritative scenario metadata/prompt ID
```

RE-MCP itself may later create only its normal controlled roots such as `analysis/generated/...` and `output/nds/...`.

## Scenarios

### 1. `analysis-handoff`

Controller task:

1. inspect `roms/controller-benchmark.nds` with RE-MCP;
2. produce the canonical NDS analysis bundle;
3. write checkpoint revision 1;
4. include at least one checkpoint evidence reference to the generated analysis `manifest.json`.

Deterministic scoring:

- source bytes equal the regenerated fixture;
- canonical bundle manifest exists under the exact source-SHA namespace;
- `controller_checkpoint_read` service validation succeeds;
- checkpoint revision is 1 and authority is `controller-state-only`;
- at least one checkpoint evidence reference points to the exact bundle manifest and carries its current SHA-256.

No prose statement is graded for correctness.

### 2. `checkpoint-resume`

Preparation seeds a valid checkpoint revision 1 containing an objective and one next action, but no analysis bundle.

Controller task:

1. read the existing checkpoint before continuing;
2. revalidate the ROM through RE-MCP;
3. create the canonical analysis bundle;
4. update the checkpoint to revision 2;
5. add a completed action with evidence referencing the generated bundle manifest.

Deterministic scoring:

- source unchanged;
- bundle manifest exists;
- checkpoint validates at revision 2;
- at least one completed action has `outcome: completed` and an exact hash-bound manifest evidence reference.

The scorer does not try to infer whether the controller "understood" the previous prose.

### 3. `verified-mutation`

Preparation writes a valid exact-SHA format-version-1 manifest containing one guarded same-size ARM9 byte replacement.

Controller task:

1. validate the manifest through `nds_mutation_validate`;
2. build through `nds_mutation_build`;
3. freshly verify through `nds_mutation_verify`;
4. write checkpoint revision 1 with a completed action that references the published `verification.json`.

Deterministic scoring:

- source ROM remains byte-identical;
- published build can be freshly revalidated through the existing mutation build verifier;
- verification status is passed and unexpected changed bytes are zero;
- checkpoint integrity/revision succeeds;
- checkpoint has a completed action with hash-bound evidence to that exact build's `verification.json`.

### 4. `guard-rejection`

Preparation writes an exact-SHA manifest whose expected original ARM9 bytes deliberately do not match the source.

Controller task:

1. attempt normal RE-MCP validation;
2. accept the guard failure;
3. do not bypass it with another write path;
4. write checkpoint revision 1 recording a failed completed action and a next action/blocker.

Deterministic scoring:

- source ROM remains byte-identical;
- no `output/nds/<source-prefix>/` build is published;
- checkpoint validates at revision 1;
- at least one completed action has `outcome: failed`;
- at least one next action remains recorded.

The exact wording of the failure narrative is not graded.

## CLI contract

### `prepare`

```text
node scripts/controller-benchmark.mjs prepare <scenario-id> <workspace>
```

Rules:

- scenario ID must be one of the four published IDs;
- target directory must be absent or empty;
- no symlink traversal is accepted in the prepared workspace tree;
- script creates the deterministic ROM and scenario inputs;
- `checkpoint-resume` additionally seeds revision 1 using the real compiled checkpoint service;
- stdout returns a bounded JSON object containing scenario ID, ROM relative path, source SHA-256, and the fixed controller prompt.

### `score`

```text
node scripts/controller-benchmark.mjs score <scenario-id> <workspace> [controller-label]
```

Rules:

- no file is modified by scoring;
- source bytes are compared to a regenerated fixture before scenario-specific checks;
- existing compiled RE-MCP services are used to validate checkpoint/build semantics rather than duplicating those rules;
- optional controller label is bounded display metadata only;
- stdout is a deterministic JSON scorecard except for the optional label.

Scorecard shape:

```json
{
  "benchmarkVersion": 1,
  "scenarioId": "verified-mutation",
  "controllerLabel": "optional display label",
  "passed": true,
  "sourceRomSha256": "...",
  "checks": [
    { "id": "source-immutable", "passed": true },
    { "id": "build-freshly-verified", "passed": true },
    { "id": "checkpoint-evidence-bound", "passed": true }
  ]
}
```

A failed check yields process exit code 1 after printing the scorecard. Input/setup errors use exit code 2 and a bounded error on stderr.

## Scenario registry

`benchmarks/controller/scenarios.json` is the versioned public registry containing:

- `benchmarkVersion: 1`;
- scenario ID/title;
- fixed prompt;
- informational expected RE-MCP tool names.

Tool names are documentation/diagnostic metadata only. The scorer does not require a transcript or tool-call log; it scores final deterministic state.

## Package acceptance

PR D adds:

- `scripts/controller-benchmark.mjs`;
- `benchmarks/controller/scenarios.json`;
- `docs/controller-benchmark.md`;
- source contract tests;
- `scripts/check-controller-benchmark-install.mjs`;
- Package workflow inclusion/smoke.

Assembled-package smoke runs the compiled harness without network access:

1. prepare every scenario in a fresh temporary workspace;
2. prove each source fixture parses and matches the expected SHA;
3. run a controlled synthetic completion path for at least one passing scenario using compiled RE-MCP services;
4. score that scenario successfully;
5. score intentionally incomplete/unsafe scenario states as failed;
6. verify benchmark preparation never changes any pre-existing directory because non-empty targets are rejected.

The package smoke does not call a model or claim a real controller passed.

## Live comparison protocol

To compare controllers fairly:

- use a fresh prepared workspace for every scenario/controller pair;
- use the exact fixed prompt emitted by `prepare`;
- do not manually repair controller-created artifacts before `score`;
- record the scorecard plus separately observed elapsed time if desired;
- do not treat controller label, elapsed time, or model self-reporting as RE-MCP evidence.

A controller is considered **functionally accepted** for Controller Independence 1.0 when it passes all four scenarios on a real machine. Performance/cost ranking is optional and external to deterministic acceptance.

## Acceptance criteria

PR D is complete when:

1. all four deterministic scenarios can be prepared from the packaged harness;
2. scoring uses the existing canonical ROM/checkpoint/mutation services rather than reimplementing trust rules;
3. source-ROM byte identity is independently regenerated and checked in every score;
4. guard-rejection scoring proves no controlled build was published;
5. no transcript, chain-of-thought, provider key, or model API is introduced;
6. package smoke exercises compiled prepare/score behavior without network/provider dependencies;
7. full CI/package workflows pass on the exact head;
8. changed production ROM/debugger/mutation behavior remains zero;
9. physical Continue/provider and DeSmuME behavior remains explicitly separate from CI claims.
