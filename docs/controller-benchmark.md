# RE-MCP controller benchmark

The controller benchmark provides deterministic acceptance for controllers that drive RE-MCP, including GitHub Copilot and Continue through Groq, OpenRouter, or Ollama. Controller Efficiency PR D adds a fifth scenario that measures whether a constrained controller can use the focused high-level reverse-engineering surface instead of receiving or manually chaining the full tool catalog.

The benchmark does **not** grade model prose or store transcripts. It prepares a synthetic Nintendo DS workspace, gives the selected controller a fixed prompt, and scores only machine-verifiable RE-MCP outcomes: source-ROM immutability, checkpoint/journal integrity, evidence hashes, guarded mutation verification, fail-closed behavior, and deterministic candidate selection.

## Build first

From the RE-MCP repository or downloadable bundle:

```bash
npm install
npm run build
```

The harness uses compiled RE-MCP services under `dist/`. It does not call a model provider itself.

## Basic flow

Every controller/scenario pair uses a **fresh workspace**.

### 1. Prepare

```bash
node scripts/controller-benchmark.mjs prepare targeted-function-investigation /tmp/re-mcp-bench-targeted
```

`prepare` prints bounded JSON containing the benchmark version, scenario ID, synthetic source-ROM SHA-256, ROM path, exact fixed prompt, and—when required—the tool profile. The targeted scenario also emits only the known helper address needed to start the investigation.

Use that prompt unchanged. The prepared workspace must be absent or empty; the harness refuses a non-empty target instead of deleting or overwriting existing files.

### 2. Run the controller

Open the prepared workspace with the controller being evaluated and give it the emitted fixed prompt.

For GitHub Copilot, use Agent mode with the RE-MCP server configured as documented in `docs/github-copilot-agent.md`.

For Continue, use Agent mode and the Continue + LiteLLM fallback configuration in `docs/controller-fallback.md`. The examples cover Groq, OpenRouter, and local Ollama, but the benchmark itself is provider-neutral.

For `targeted-function-investigation`, launch RE-MCP with:

```bash
RE_MCP_TOOL_PROFILE=re-static-core
```

Allow the controller to use RE-MCP normally. **Do not manually repair** generated files, journal/checkpoint state, candidate selections, mutation outputs, or evidence before scoring.

### 3. Score

For the targeted scenario, score under the same declared profile:

```bash
RE_MCP_TOOL_PROFILE=re-static-core \
node scripts/controller-benchmark.mjs score \
  targeted-function-investigation \
  /tmp/re-mcp-bench-targeted \
  "continue-groq-run-1"
```

The optional controller label is bounded display metadata only. It is not RE-MCP evidence and does not affect deterministic scoring.

Every scorecard now reports the actual MCP advertisement measured through `tools/list`:

```json
{
  "benchmarkVersion": 1,
  "scenarioId": "targeted-function-investigation",
  "controllerLabel": "continue-groq-run-1",
  "activeToolProfile": "re-static-core",
  "advertisedToolCount": 9,
  "toolSchemaBytes": 12000,
  "toolSchemaEstimatedTokens": 3000,
  "controllerRun": {
    "requestAccepted": null,
    "turns": null,
    "toolCalls": null
  },
  "passed": true,
  "sourceRomSha256": "...",
  "checks": []
}
```

The numeric example above is illustrative; the scorer records the current serialized schema values from the tested build. A completed but failing deterministic score exits with code 1. Usage, setup, or invalid-workspace errors exit with code 2.

## The five scenarios

A deterministic release candidate must pass **all five scenarios**.

### `analysis-handoff`

The controller creates the canonical NDS analysis bundle and writes checkpoint revision 1 with an exact evidence reference to the generated analysis `manifest.json`. The scorer checks bytes, identity, checkpoint authority, and evidence SHA—not prose.

### `checkpoint-resume`

Preparation seeds revision 1. The controller reads it, revalidates the ROM, extracts ARM9 through RE-MCP, and advances to revision 2 with completed-action evidence for `arm9.bin`. The checkpoint remains `controller-state-only`.

### `verified-mutation`

The controller validates, builds, and freshly verifies the prepared guarded same-size mutation, then binds the published `verification.json` into checkpoint state. The scorer independently verifies the build and requires zero unexpected changed bytes.

### `guard-rejection`

The prepared manifest has an intentionally wrong original-byte guard. The controller must accept canonical rejection, publish no build, and record a failed action plus unresolved next action. The scorer checks the exact rejection category and absence of output.

### `targeted-function-investigation`

The synthetic ARM9 fixture contains a known helper at `0x02000080`, three deterministic direct callers, two generic bounds-validation distractors, and exactly one caller that loads identity state and applies an identity-dependent restriction.

The fixed prompt requires the focused `re-static-core` profile and `re_trace_function` as the primary operation. A successful high-level trace automatically persists an integrity-bound investigation journal and compact `re-resume-state` artifact. The controller records the selected caller in structured checkpoint action state using the prescribed `identity-restriction-<address>` ID.

The scorer verifies:

- source ROM is unchanged;
- `re-static-core` was explicitly declared;
- the successful `re_trace_function` operation is journaled;
- journal/projection integrity passes;
- the compact resume artifact is hash-valid and bound to the exact ROM SHA;
- the direct caller set is exactly the fixture's three callers;
- the selected structured candidate is the known identity-dependent caller;
- selecting a generic-bounds distractor fails deterministically.

No checkpoint narrative, model explanation, or decompiler prose is graded.

## Fair controller comparisons

For comparable results:

1. use a newly prepared workspace for every scenario/controller pair;
2. use the exact fixed prompt emitted by `prepare`;
3. use the same RE-MCP commit or packaged release;
4. use the scenario's required profile exactly;
5. do not manually repair controller results before `score`;
6. record the JSON scorecard;
7. record provider/model and request telemetry separately from deterministic ROM evidence.

A provider switch does not change RE-MCP evidence authority. The deterministic final state is what is scored.

## Live constrained-controller metadata

The scorer can include non-authoritative live-run metadata when these environment variables are set:

```bash
RE_MCP_BENCHMARK_REQUEST_ACCEPTED=true
RE_MCP_BENCHMARK_TURNS=4
RE_MCP_BENCHMARK_TOOL_CALLS=3
```

Use the controller label for the provider/model label. These fields record whether the request was accepted and how many turns/tool calls occurred; they do not affect ROM evidence authority.

## What the benchmark proves

Passing all five deterministic scenarios demonstrates that the shipped RE-MCP contracts can produce and score the required analysis, resume, mutation, rejection, focused static investigation, persistence, and candidate-selection states without violating the checked source-ROM/evidence boundaries.

## What CI does not prove

Repository/package CI runs deterministic synthetic smoke coverage. It **does not prove** that:

- GitHub Copilot completed a real Agent-mode run;
- Continue completed a live constrained run;
- Groq or OpenRouter currently has quota or availability;
- Ollama is installed or performant enough on the target machine;
- a free/limited controller accepted the prompt and completed the fifth scenario without manual repair;
- a model will solve arbitrary ROM reverse-engineering work;
- Physical DeSmuME / Intel Catalina debugger acceptance has passed.

Those remain live/native acceptance gates. See `docs/controller-efficiency-acceptance.md` for the practical constrained-controller gate and the distinction between deterministic CI acceptance and being **practically accepted**.
