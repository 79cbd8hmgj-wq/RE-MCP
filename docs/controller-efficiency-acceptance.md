# Controller Efficiency acceptance

Controller Efficiency is accepted in two separate layers: deterministic repository acceptance and practical constrained-controller acceptance. The layers must not be conflated.

## Deterministic merge gate

PR D may merge when repository CI and the downloadable package smoke test pass all five deterministic controller benchmark scenarios, including `targeted-function-investigation` and its wrong-caller negative control.

The deterministic gate requires:

- source-ROM immutability;
- exact-ROM-SHA journal/checkpoint integrity;
- successful high-level `re_trace_function` persistence;
- the correct identity-dependent caller selected from deterministic candidate evidence;
- a generic-bounds distractor selection to fail;
- `RE_MCP_TOOL_PROFILE=re-static-core` for the targeted scenario;
- real `tools/list` schema measurement in the scorecard;
- no manual repair of benchmark state.

This gate is reproducible in CI and does not require a model provider.

## Practical constrained-controller gate

The milestone is **not practically accepted** until at least one real free or limited controller completes `targeted-function-investigation` from the fixed prompt under the focused profile without operator repair.

Prepare a fresh workspace:

```bash
node scripts/controller-benchmark.mjs prepare \
  targeted-function-investigation \
  /tmp/re-mcp-controller-efficiency-live
```

Launch the controller with RE-MCP configured as:

```bash
RE_MCP_TOOL_PROFILE=re-static-core
```

Give the controller the exact fixed prompt emitted by `prepare`. Do not rewrite the prompt, inject the correct caller, manually invoke missing analysis on its behalf, edit journal/checkpoint files, or otherwise repair the run.

After the controller finishes, score under the same profile. Record whether the provider accepted the request, plus turn and tool-call counts:

```bash
RE_MCP_TOOL_PROFILE=re-static-core \
RE_MCP_BENCHMARK_REQUEST_ACCEPTED=true \
RE_MCP_BENCHMARK_TURNS=<turn-count> \
RE_MCP_BENCHMARK_TOOL_CALLS=<tool-call-count> \
node scripts/controller-benchmark.mjs score \
  targeted-function-investigation \
  /tmp/re-mcp-controller-efficiency-live \
  "<provider/model label>"
```

Record the resulting JSON scorecard unchanged. The scorecard includes:

- provider/model label through `controllerLabel`;
- request accepted status;
- turns;
- tool calls;
- `activeToolProfile`;
- `advertisedToolCount`;
- `toolSchemaBytes`;
- `toolSchemaEstimatedTokens`;
- deterministic pass/fail checks.

A provider refusal, quota error, unavailable free endpoint, or model/tooling failure does not invalidate deterministic CI. It means practical acceptance remains pending.

## Passing practical acceptance

A live run passes the practical gate only when all of the following are true:

1. the request was accepted by the constrained controller/provider;
2. the controller used `RE_MCP_TOOL_PROFILE=re-static-core`;
3. the fixed prompt was not changed;
4. no manual repair occurred;
5. the deterministic scorecard reports `passed: true`;
6. the journal contains a completed high-level `re_trace_function` operation;
7. the selected caller is the identity-dependent restriction caller, not either generic-bounds distractor;
8. source-ROM immutability and integrity checks pass.

Turn count, tool-call count, and schema size are efficiency measurements rather than correctness substitutions. A short run that selects the wrong caller still fails.

## Provider-neutral runbook

Use the same procedure for GitHub Copilot, Continue, Groq, OpenRouter, Ollama, or another compatible controller. The benchmark harness never makes provider requests itself and does not store prompts, chain-of-thought, credentials, or model transcripts in RE-MCP evidence.

For a fair comparison, use a fresh workspace and the same RE-MCP commit for every provider/model run. If a provider switch or fallback occurs, record it in the external run label/notes; do not rewrite deterministic evidence.

## Acceptance status language

Use these terms precisely:

- **Deterministically accepted**: all five repository/package scenarios pass, including the wrong-caller negative control.
- **Practically accepted**: deterministic acceptance is green **and** at least one real constrained free/limited controller passes the live targeted scenario without manual repair.
- **Pending practical acceptance**: deterministic acceptance is green, but no qualifying live constrained run has succeeded yet.

Deterministic CI alone does not prove live provider availability, model quality on arbitrary ROMs, or Physical DeSmuME / Intel Catalina debugger acceptance.
