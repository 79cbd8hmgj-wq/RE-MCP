# RE-MCP Controller Independence benchmark

Controller Independence PR D provides a deterministic acceptance benchmark for controllers that drive RE-MCP. It is intended for GitHub Copilot, Continue through Groq, OpenRouter, or Ollama, and later controllers.

The benchmark does **not** grade model prose or store transcripts. It prepares a synthetic Nintendo DS workspace, gives the selected controller a fixed prompt, and then scores only machine-verifiable RE-MCP outcomes such as source-ROM immutability, checkpoint integrity, evidence hashes, guarded mutation verification, and fail-closed behavior.

## Build first

From the RE-MCP repository or downloadable bundle:

```bash
npm install
npm run build
```

The benchmark uses the compiled RE-MCP services under `dist/`. It does not call a model provider itself.

## Basic flow

Every controller/scenario pair uses a **fresh workspace**.

### 1. Prepare

```bash
node scripts/controller-benchmark.mjs prepare analysis-handoff /tmp/re-mcp-bench-analysis
```

`prepare` prints a bounded JSON object containing:

- benchmark version;
- scenario ID;
- synthetic source-ROM SHA-256;
- ROM relative path;
- the exact **fixed prompt** for the controller.

Use that prompt unchanged for the selected controller. The prepared workspace must be absent or empty. The harness refuses a non-empty target rather than deleting or overwriting existing files.

### 2. Run the controller

Open the prepared workspace with the controller being evaluated and give it the emitted fixed prompt.

For GitHub Copilot, use Agent mode with the repository RE-MCP MCP server configured as documented in `docs/github-copilot-agent.md`.

For Continue, use Agent mode and the Continue + LiteLLM fallback configuration in `docs/controller-fallback.md`. The current fallback examples cover Groq, OpenRouter, and local Ollama, but the benchmark does not depend on any of those providers specifically.

Allow the controller to use RE-MCP normally. Do **not manually repair** generated files, checkpoints, mutation outputs, or evidence before scoring. A manual repair would measure the operator rather than the controller.

### 3. Score

```bash
node scripts/controller-benchmark.mjs score analysis-handoff /tmp/re-mcp-bench-analysis "copilot-run-1"
```

The optional controller label is bounded display metadata only. It is not RE-MCP evidence and does not affect scoring.

A successful score prints JSON similar to:

```json
{
  "benchmarkVersion": 1,
  "scenarioId": "analysis-handoff",
  "controllerLabel": "copilot-run-1",
  "passed": true,
  "sourceRomSha256": "...",
  "checks": [
    { "id": "source-immutable", "passed": true },
    { "id": "checkpoint-valid", "passed": true },
    { "id": "checkpoint-evidence-bound", "passed": true }
  ]
}
```

A completed but failing deterministic score exits with code 1 after printing the scorecard. Usage, setup, or invalid-workspace errors exit with code 2.

## The four scenarios

A controller must pass **all four scenarios** for functional Controller Independence 1.0 acceptance.

### `analysis-handoff`

The controller must inspect the synthetic ROM, create its canonical NDS analysis bundle, and write checkpoint revision 1 with an evidence reference to the generated analysis `manifest.json`.

The scorer verifies the source bytes, analysis-manifest identity, checkpoint revision/authority, and exact evidence SHA. It does not grade the checkpoint prose.

### `checkpoint-resume`

Preparation seeds a valid revision-1 checkpoint. The controller must read it before continuing, revalidate the ROM, extract the ARM9 component through RE-MCP, and update the checkpoint to revision 2 with completed-action evidence referencing the generated `arm9.bin`.

The checkpoint remains `controller-state-only`; the scorer checks revision/integrity and artifact bytes/hash rather than treating the previous controller's statements as ROM truth.

### `verified-mutation`

Preparation supplies a valid guarded same-size mutation manifest. The controller must validate, build, and freshly verify it through RE-MCP, then write checkpoint revision 1 with completed-action evidence referencing the exact published `verification.json`.

The scorer independently verifies source immutability, freshly revalidates the deterministic published build with RE-MCP, requires zero unexpected changed bytes, and validates the evidence binding.

### `guard-rejection`

Preparation supplies a mutation manifest with deliberately incorrect expected original bytes. The controller must accept RE-MCP's guard rejection, avoid creating a build through another path, and write checkpoint revision 1 with a failed completed action plus at least one next action.

The scorer requires the source ROM to remain unchanged, canonical planning to reject the guard, no controlled build to exist, and a valid failed-action checkpoint. The exact narrative wording is not scored.

## Fair controller comparisons

For comparable results:

1. use a newly prepared workspace for every scenario/controller pair;
2. use the exact fixed prompt emitted by `prepare`;
3. use the same RE-MCP commit or packaged release;
4. do not manually repair controller results before `score`;
5. record the JSON scorecard for each run;
6. if you track elapsed time, token usage, or provider cost, keep those as external performance metadata rather than RE-MCP evidence.

A provider switch during a Continue/LiteLLM run does not invalidate the benchmark. The deterministic final state is what is scored.

## What the benchmark proves

Passing all four scenarios demonstrates that, for the tested controller/environment, the controller can drive the shipped RE-MCP contracts through representative analysis, handoff/resume, verified mutation, and fail-closed rejection workflows without violating the source-ROM/evidence boundaries that the scorer checks.

## What CI does not prove

Repository/package CI runs deterministic synthetic smoke coverage. It **does not prove** that:

- GitHub Copilot completed a real Agent-mode benchmark run;
- Continue completed a real Agent-mode benchmark run;
- Groq or OpenRouter currently has quota or availability;
- Ollama is installed or performant enough on the user's machine;
- provider failover occurred during a live inference request;
- a model will solve arbitrary ROM reverse-engineering work from these four fixtures;
- Physical DeSmuME / Intel Catalina debugger acceptance has passed.

Those remain live/native acceptance gates. The benchmark deliberately separates controller capability evidence from provider marketing claims or model self-reporting.
