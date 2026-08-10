# Controller Independence 1.0 — PR C Fallback Controller Plan

**Goal:** Ship a reproducible Continue Agent + LiteLLM fallback path that uses RE-MCP directly for MCP tools and ordered free/local inference failover.

## Task 1 — RED configuration contract

Create `tests/controller-fallback.test.ts` requiring:
- project-local Continue MCP config launching `node dist/index.js` with only secret-backed `RE_MCP_WORKSPACE_ROOT`;
- provider-neutral Continue rule requiring checkpoint resume/handoff and deterministic revalidation;
- Continue model config using OpenAI-compatible `http://127.0.0.1:4000/v1`, alias `re-mcp-controller`, and explicit `tool_use`;
- LiteLLM model groups for Groq `groq/openai/gpt-oss-120b`, OpenRouter `openrouter/openrouter/free`, and Ollama `ollama/llama3.1` on loopback;
- ordered fallback `re-mcp-controller -> re-mcp-openrouter -> re-mcp-ollama`;
- cloud keys only through `os.environ/GROQ_API_KEY` and `os.environ/OPENROUTER_API_KEY`;
- no checked-in key values, user-home paths, ROM paths, or output paths.

Run CI and require RED only because the new config files are absent.

## Task 2 — GREEN configuration + controller rules

Create:
- `.continue/mcpServers/re-mcp.yaml`
- `.continue/rules/re-mcp-controller.md`
- `configs/controller/continue-re-mcp.yaml`
- `configs/controller/litellm-re-mcp.yaml`
- `configs/controller/controller.env.example`

Keep inference routing completely outside RE-MCP `src/`.

## Task 3 — Package/documentation acceptance

RED-test then add:
- `docs/controller-fallback.md`
- `scripts/check-controller-fallback-install.mjs`
- package workflow inclusion/smoke

The smoke validates shipped configuration structure and safety only. It must explicitly not claim live provider/free-quota/native Continue acceptance.

## Task 4 — Exact-head review + merge

Require current-head CI and Package success, review the entire diff for secrets/provider coupling/ROM logic changes, require no unresolved threads, update PR evidence, and merge with `expected_head_sha` under the user's standing authorization.
