# Controller Independence 1.0 — PR D: Deterministic Controller Benchmark Design

Date: 2026-08-10
Status: approved under the user's standing authorization for PR D

## Goal

Add a repeatable, provider-neutral acceptance benchmark for RE-MCP controllers so GitHub Copilot, Continue through Groq/OpenRouter/Ollama, and future controllers can be compared by deterministic RE-MCP outcomes rather than model prose, transcripts, or hidden reasoning.

PR D never calls a model provider itself. It prepares a deterministic synthetic NDS workspace, prints one fixed task prompt, and later scores only the resulting RE-MCP artifacts and safety invariants.

## Selected approach

Use deterministic artifact scoring.

The benchmark checks things such as:

- source ROM remains byte-identical;
- expected canonical analysis artifacts exist;
- controller checkpoints pass RE-MCP integrity/revision validation;
- evidence references remain exact-path/SHA bound;
- guarded mutation builds freshly verify;
- intentionally invalid guards fail closed without publishing output.

Transcript/model-judge scoring and live cloud-provider CI are intentionally rejected because they would be subjective, provider-coupled, credential-dependent, and less trustworthy than RE-MCP's deterministic state.

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

The controller talks to RE-MCP normally. The benchmark harness does not proxy MCP calls and does not sit in the inference path.

## Safety boundary

- No new MCP tool.
- No provider/model API call.
- No provider credential input.
- No transcript or hidden-reasoning collection.
- No production ROM/debugger/mutation behavior change.
- The source ROM is generated synthetically; private/real ROM inputs are not accepted.
- `prepare` writes only into an absent or empty explicit benchmark workspace.
- `score` is read-only with respect to the benchmark workspace.
- Every score regenerates the expected source fixture and requires exact byte identity before scenario-specific checks.
- Existing compiled RE-MCP services remain authoritative for parsing, checkpoint integrity/evidence binding, extraction semantics, mutation planning, and published-build verification.
- Physical DeSmuME and real controller/provider operation remain separate live/native gates.

## Synthetic fixture

All scenarios use one deterministic generated `.nds` fixture containing:

- a valid NDS header and header CRC;
- small ARM9 and ARM7 main regions;
- one FNT/FAT-backed NitroFS file;
- no overlay/runtime/emulator dependency.

The fixture is generated from source code rather than committed as a binary. `score` regenerates the expected bytes in memory and compares them byte-for-byte with `roms/controller-benchmark.nds`.

Prepared layout:

```text
<workspace>/
├── roms/
│   └── controller-benchmark.nds
├── plans/
│   ├── valid-mutation.json
│   └── invalid-guard.json
└── benchmark/
    └── scenario.json
```

RE-MCP may subsequently create only its normal controlled analysis/output roots.

## Scenarios

### 1. `analysis-handoff`

Controller task:

1. inspect the synthetic ROM through RE-MCP;
2. produce the canonical NDS analysis bundle;
3. write checkpoint revision 1;
4. include a confirmed-fact evidence reference to the generated bundle `manifest.json`.

Scoring requires exact source identity, a valid canonical analysis manifest, valid revision-1 `controller-state-only` checkpoint state, and an exact current manifest-path/SHA evidence reference. Prose is not graded.

### 2. `checkpoint-resume`

Preparation seeds a valid checkpoint revision 1 with an objective and next action.

Controller task:

1. read the existing checkpoint before continuing;
2. revalidate the ROM through RE-MCP;
3. extract the ARM9 component with `nds_extract_component`;
4. update checkpoint revision 1 to revision 2;
5. record a completed action with evidence referencing the generated `arm9.bin`.

This intentionally uses component extraction instead of regenerating the full analysis bundle. The canonical full-bundle exporter atomically replaces the entire SHA-scoped analysis directory, and the controller checkpoint lives beneath that same root; component extraction preserves the existing checkpoint while producing fresh controlled evidence.

Scoring requires source immutability, exact ARM9 artifact bytes, revision-2 checkpoint integrity, and an exact current ARM9 path/SHA evidence reference on a completed action.

### 3. `verified-mutation`

Preparation writes a valid exact-SHA format-version-1 manifest containing one guarded same-size ARM9 byte replacement.

Controller task:

1. `nds_mutation_validate`;
2. `nds_mutation_build`;
3. `nds_mutation_verify`;
4. write checkpoint revision 1 with completed-action evidence referencing the exact published `verification.json`.

Scoring freshly revalidates the deterministic published build through the existing mutation service, requires verification status passed with zero unexpected changed bytes, and validates the checkpoint evidence binding.

### 4. `guard-rejection`

Preparation writes a format-version-1 manifest whose expected original ARM9 bytes deliberately do not match the source.

Controller task:

1. attempt normal RE-MCP validation;
2. accept the guard failure;
3. do not bypass it through another writer;
4. write checkpoint revision 1 containing a failed completed action and at least one next action.

Scoring requires the canonical planner to fail with the **exact** `original-byte-guard-failed` category, requires no controlled build under the source-SHA output root, and validates the failed-action checkpoint. Missing/corrupt/different-invalid manifests do not receive guard-rejection credit.

## CLI contract

### Prepare

```text
node scripts/controller-benchmark.mjs prepare <scenario-id> <workspace>
```

Rules:

- scenario ID must be published in the registry;
- target must be absent or an empty real directory, not a symlink;
- the script creates only the controlled fixture/scenario inputs;
- `checkpoint-resume` additionally seeds revision 1 through the real compiled checkpoint service;
- stdout is bounded JSON containing benchmark version, scenario ID, source SHA, ROM relative path, and fixed controller prompt.

### Score

```text
node scripts/controller-benchmark.mjs score <scenario-id> <workspace> [controller-label]
```

Rules:

- benchmark workspace must be a real directory;
- source bytes are regenerated and compared before any scenario-specific scoring;
- existing compiled RE-MCP services validate checkpoint/build/planner semantics instead of duplicated trust logic;
- optional controller label is bounded display metadata only;
- failed deterministic checks print the scorecard and exit 1;
- usage/setup errors print a bounded error and exit 2.

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

## Scenario registry

`benchmarks/controller/scenarios.json` contains `benchmarkVersion: 1`, the exact four scenario IDs/titles, each fixed prompt, and a bounded informational list of expected RE-MCP tool names. Tool names are diagnostic documentation only; the scorer does not require or store a tool-call transcript.

## Package acceptance

The downloadable bundle ships:

- `benchmarks/controller/scenarios.json`;
- `scripts/controller-benchmark.mjs`;
- `docs/controller-benchmark.md`;
- `scripts/check-controller-benchmark-install.mjs`.

Package smoke uses compiled RE-MCP services and temporary workspaces only. It prepares all four scenarios, proves non-empty prepare targets fail without modification, completes and scores representative passing analysis/resume/mutation/rejection states, scores an intentionally incomplete state as failed, and makes no provider/network call.

Successful package smoke prints:

```text
Controller benchmark package smoke passed
```

## Live comparison protocol

For fair comparisons:

1. use a fresh prepared workspace for every controller/scenario pair;
2. use the exact fixed prompt emitted by `prepare`;
3. use the same RE-MCP revision/package;
4. do not manually repair controller outputs before `score`;
5. retain the JSON scorecard;
6. record time/cost separately if desired, but never treat those as RE-MCP evidence.

A controller is functionally accepted for Controller Independence 1.0 when it passes all four scenarios on a real machine.

## CI/native boundary

CI proves deterministic benchmark implementation/package behavior only. It does not prove real GitHub Copilot or Continue Agent execution, current Groq/OpenRouter availability, local Ollama performance, live provider failover, arbitrary ROM-solving capability, or Physical DeSmuME / Intel Catalina debugger acceptance.

## Acceptance criteria

PR D is complete when:

1. all four scenarios prepare deterministically from the shipped package;
2. scoring relies on existing canonical RE-MCP services;
3. every score independently regenerates and checks source bytes;
4. `guard-rejection` requires exact `original-byte-guard-failed` semantics and no published build;
5. no provider/network/credential/transcript surface is introduced;
6. package smoke executes compiled prepare/score behavior without network access;
7. exact-head CI and Package workflows pass;
8. changed production `src/` behavior remains zero;
9. live provider/controller and physical DeSmuME acceptance remain explicitly separate.
