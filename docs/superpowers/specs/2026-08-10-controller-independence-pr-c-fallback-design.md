# Controller Independence 1.0 — PR C: Continue + LiteLLM Fallback Design

Date: 2026-08-10
Status: approved under the user's standing authorization

## Goal

Ship a provider-neutral fallback controller path for periods when GitHub Copilot is unavailable or quota-limited, without putting provider APIs or credentials inside RE-MCP.

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

LiteLLM never proxies MCP calls and RE-MCP never calls LiteLLM or a model provider.

Provider/controller switching uses the exact-ROM checkpoint protocol already shipped in PR B.

## Shipped configuration

- `.continue/mcpServers/re-mcp.yaml`: project-local RE-MCP stdio MCP server for Continue.
- `.continue/rules/re-mcp-controller.md`: provider-neutral evidence/checkpoint rules equivalent to the Copilot trust boundary.
- `configs/controller/continue-re-mcp.yaml`: Continue Agent model configuration pointing to a local LiteLLM OpenAI-compatible endpoint at `http://127.0.0.1:4000/v1`, model alias `re-mcp-controller`, explicit `tool_use` capability.
- `configs/controller/litellm-re-mcp.yaml`: LiteLLM routing config.
- `configs/controller/controller.env.example`: names only for required cloud credentials; no keys.
- `docs/controller-fallback.md`: setup, operation, failure/handoff procedure, and live-acceptance boundary.

## Routing policy

LiteLLM exposes `re-mcp-controller` to Continue. The primary deployment is Groq `groq/openai/gpt-oss-120b`. Ordered provider failover is:

1. `re-mcp-controller` (Groq)
2. `re-mcp-openrouter` (`openrouter/openrouter/free`)
3. `re-mcp-ollama` (`ollama/llama3.1` on `http://127.0.0.1:11434`)

`router_settings.fallbacks` provides ordered failover after bounded retries. This is inference failover only. A successful provider response still has to drive RE-MCP through Continue's Agent loop.

Cloud keys are read only through LiteLLM environment references `GROQ_API_KEY` and `OPENROUTER_API_KEY`. The local LiteLLM endpoint is not an authorization boundary; it is intended to remain loopback-only.

## Controller policy

Continue must:
- read `controller_checkpoint_read` before resuming existing ROM work;
- treat checkpoint prose as `controller-state-only`;
- revalidate consequential facts through deterministic RE-MCP tools;
- write a checkpoint before a planned handoff or when provider availability is deteriorating;
- never store chain-of-thought, transcripts, API keys, or provider secrets in checkpoints;
- preserve all existing mutation/build/verification boundaries.

## Acceptance

CI/package acceptance validates configuration shape, provider order, loopback endpoints, absence of checked-in secrets/private paths, Continue tool capability, MCP registration, checkpoint rules, and inclusion in the downloadable bundle.

CI does **not** claim:
- live Groq/OpenRouter free quota or availability;
- a specific cloud model will remain offered indefinitely;
- real LiteLLM failover occurred over the network;
- Continue successfully completed a native Agent-mode RE-MCP workflow;
- local Ollama is installed or fast enough;
- physical DeSmuME acceptance.

Those are external/native acceptance gates. PR D will benchmark controllers on real RE-MCP scenarios.

## Out of scope

- model-provider calls from RE-MCP;
- storing provider credentials in the repository;
- provider-specific ROM logic;
- automatic installation of Continue, LiteLLM, Groq, OpenRouter, or Ollama;
- changing mutation/rebuild/debugger semantics;
- controller quality benchmarking.
