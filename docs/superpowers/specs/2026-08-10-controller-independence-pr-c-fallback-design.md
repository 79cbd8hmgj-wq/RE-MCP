# Controller Independence 1.0 — PR C: Continue + LiteLLM Fallback Design

Date: 2026-08-10
Status: approved under the user's standing authorization

## Goal

Ship a provider-neutral fallback controller path for periods when GitHub Copilot is unavailable or quota-limited, without putting provider APIs, provider credentials, or model-routing behavior inside RE-MCP.

## Architecture

```text
GitHub Copilot Agent -> RE-MCP                 # preferred controller

Continue Agent
   |-- MCP stdio -----------------> RE-MCP     # tools / deterministic truth
   `-- OpenAI-compatible inference -> LiteLLM  # inference only
                                  |-> Groq
                                  |-> OpenRouter Free
                                  `-> Ollama local
```

LiteLLM never proxies MCP calls. RE-MCP never calls LiteLLM or a model provider. Provider/controller switching uses the exact-ROM checkpoint protocol shipped in PR B.

## Current upstream contracts

The configuration in this PR follows the current upstream controller/provider contracts verified on 2026-08-10:

- Continue uses schema `v1` YAML, supports project-local MCP blocks under `.continue/mcpServers/`, supports secret references through `${{ secrets.NAME }}`, and requires Agent mode for MCP tools.
- Continue can talk to an OpenAI-compatible endpoint by using `provider: openai` plus `apiBase`.
- Groq currently exposes `openai/gpt-oss-120b` with tool use.
- OpenRouter currently exposes the zero-cost `openrouter/free` router and filters candidates for requested capabilities such as tool use.
- LiteLLM proxy configuration uses `model_list`; current proxy/router source treats `fallbacks`, `num_retries`, and `timeout` as router settings. Proxy authentication belongs under `general_settings.master_key`.
- Ollama is loopback-only in this shipped example and remains optional.

These are configuration/package contracts only; provider availability and quotas remain external.

## Shipped configuration

- `.continue/mcpServers/re-mcp.yaml`: project-local RE-MCP stdio MCP server for Continue.
- `.continue/rules/re-mcp-controller.md`: provider-neutral evidence/checkpoint rules equivalent to the Copilot trust boundary.
- `configs/controller/continue-re-mcp.yaml`: Continue Agent model configuration pointing to `http://127.0.0.1:4000/v1`, model alias `re-mcp-controller`, explicit `tool_use`, and secret-backed local proxy API key.
- `configs/controller/litellm-re-mcp.yaml`: LiteLLM routing configuration.
- `configs/controller/controller.env.example`: environment-variable names/examples only; no usable cloud credentials.
- `docs/controller-fallback.md`: setup, operation, failure/handoff procedure, and live-acceptance boundary.

## Routing policy

LiteLLM exposes three model groups:

1. `re-mcp-controller` -> Groq `groq/openai/gpt-oss-120b`
2. `re-mcp-openrouter` -> OpenRouter `openrouter/openrouter/free`
3. `re-mcp-ollama` -> Ollama `ollama/llama3.1` at `http://127.0.0.1:11434`

`router_settings.fallbacks` defines the ordered chain:

```text
re-mcp-controller -> re-mcp-openrouter -> re-mcp-ollama
```

The same `router_settings` block bounds retry/timeout behavior. This is inference failover only. A successful provider response must still drive RE-MCP through Continue's Agent loop.

Cloud keys are read only through LiteLLM environment references `GROQ_API_KEY` and `OPENROUTER_API_KEY`. The local proxy is intended to bind to loopback. A separate local proxy key (`LITELLM_MASTER_KEY`) protects the Continue-to-LiteLLM hop through `general_settings.master_key`; it is user-supplied and never committed.

## Controller policy

Continue must:

- read `controller_checkpoint_read` before resuming pre-existing ROM work;
- treat checkpoint prose as `controller-state-only`;
- revalidate consequential facts through deterministic RE-MCP tools;
- write a checkpoint before planned handoff or when controller/provider availability is deteriorating;
- never store chain-of-thought, transcripts, API keys, or provider secrets in checkpoints;
- preserve source-ROM immutability and all existing mutation/build/verification boundaries;
- never fabricate tool output or bypass a failed RE-MCP guard by writing through another path.

## Acceptance

CI/package acceptance validates:

- configuration shape and expected file locations;
- exact model-group/fallback order;
- loopback endpoints;
- environment-only cloud secrets;
- Continue `tool_use` capability;
- RE-MCP MCP registration;
- checkpoint/evidence rules;
- absence of checked-in usable credentials, private user paths, ROM paths, or caller-selected output paths;
- inclusion in the downloadable bundle.

CI does **not** claim:

- live Groq/OpenRouter quota or availability;
- a specific cloud model will remain offered indefinitely;
- a real LiteLLM network failover occurred;
- Continue completed a native Agent-mode RE-MCP workflow;
- local Ollama is installed or performant enough;
- physical DeSmuME acceptance.

Those remain external/native gates. PR D will add a repeatable controller benchmark/acceptance harness and provider-neutral scorecard for real RE-MCP scenarios.

## Out of scope

- model-provider calls from RE-MCP;
- provider credentials in the repository;
- provider-specific ROM logic;
- automatic installation of Continue, LiteLLM, Groq, OpenRouter, or Ollama;
- changes to mutation/rebuild/debugger semantics;
- controller quality benchmarking (PR D).
