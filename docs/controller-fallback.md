# RE-MCP Continue + LiteLLM fallback controller

GitHub Copilot Agent in VS Code is the preferred RE-MCP controller. This guide provides a provider-neutral fallback for periods when Copilot is unavailable or quota-limited.

The fallback architecture keeps the trust boundary unchanged:

```text
Continue Agent -- MCP stdio --> RE-MCP
       |
       `-- inference --> LiteLLM on 127.0.0.1:4000
                          |-> Groq
                          |-> OpenRouter Free
                          `-> Ollama local
```

RE-MCP remains the provider-independent authority for deterministic ROM facts, debugger evidence, guarded mutation, rebuild, and verification. LiteLLM handles inference routing only and never proxies MCP calls.

## 1. Build RE-MCP

From the repository root:

```bash
npm install
npm run build
```

Continue launches the existing server with `node dist/index.js` through `.continue/mcpServers/re-mcp.yaml`.

## 2. Configure local secrets

Copy the example to the repository's ignored `.env` file:

```bash
cp configs/controller/controller.env.example .env
```

Fill only the values you intend to use:

```text
RE_MCP_WORKSPACE_ROOT=
GROQ_API_KEY=
OPENROUTER_API_KEY=
LITELLM_MASTER_KEY=
```

`RE_MCP_WORKSPACE_ROOT` must point to the dedicated ROM-modding workspace that RE-MCP is allowed to operate within.

`GROQ_API_KEY` enables the primary Groq deployment. `OPENROUTER_API_KEY` enables the free-router fallback. `LITELLM_MASTER_KEY` is a user-chosen local proxy key used by Continue when calling LiteLLM. Do not commit `.env`.

Continue resolves `${{ secrets.NAME }}` from workspace/global secret sources. In the IDE, use the workspace `.env` or `.continue/.env`; do not rely on a shell `export` being inherited by the VS Code extension.

## 3. Start LiteLLM on loopback

Install the proxy with the current LiteLLM package method:

```bash
uv tool install 'litellm[proxy]'
```

Load the local environment and bind the proxy only to loopback:

```bash
set -a
. ./.env
set +a

litellm \
  --config configs/controller/litellm-re-mcp.yaml \
  --host 127.0.0.1 \
  --port 4000
```

The shipped routing order is:

```text
re-mcp-controller
  -> Groq openai/gpt-oss-120b
  -> OpenRouter openrouter/free
  -> Ollama llama3.1 at 127.0.0.1:11434
```

If Ollama is not installed/running, that last fallback simply remains unavailable. Cloud-provider availability, quotas, and free-model inventory can change independently of RE-MCP.

## 4. Configure Continue

### VS Code / IDE

Open Continue's local configuration (`~/.continue/config.yaml` on macOS/Linux) from the Agent selector's configuration control. Merge or copy the model block from:

```text
configs/controller/continue-re-mcp.yaml
```

Keep the repository open as the Continue workspace. Continue discovers the project-local blocks under:

```text
.continue/mcpServers/
.continue/rules/
```

Select **Agent mode**. MCP tools are available only in Agent mode.

The model alias sent to LiteLLM is `re-mcp-controller` through:

```text
http://127.0.0.1:4000/v1
```

### Continue CLI

The same model configuration can be selected explicitly:

```bash
cn --config configs/controller/continue-re-mcp.yaml
```

For normal RE-MCP work, do not use a CLI mode that prevents required MCP tool access.

### MCP tool profiles

RE-MCP can advertise a task-specific allowlist instead of sending every low-level tool schema to the controller. The default remains the backward-compatible full surface:

```text
RE_MCP_TOOL_PROFILE=re-full
```

For ordinary read-only static reverse engineering, prefer:

```text
RE_MCP_TOOL_PROFILE=re-static-core
```

Other source-controlled profiles are `re-ghidra-escalation`, `re-runtime`, `re-build`, and `re-project`. An unknown profile prevents RE-MCP startup rather than silently falling back.

The profile changes only MCP advertisement. It does not weaken service semantics or source-ROM safeguards. Excluded tools are not registered with the MCP server, so their schemas are not sent to the model. Use `re-full` for expert/debug sessions that genuinely need the complete surface.

After building, measure the real serialized `tools/list` payload for a profile with:

```bash
node scripts/measure-tool-schemas.mjs re-static-core
node scripts/measure-tool-schemas.mjs re-full
```

The report contains only profile name, advertised tool count, serialized schema bytes, and a four-bytes-per-token estimate; provider-side prompt overhead remains outside RE-MCP's control.

## 5. Resume or hand off ROM work

Controller switching is state transfer, not evidence transfer.

Before Continue resumes pre-existing ROM work:

1. call `controller_checkpoint_read` for the exact ROM;
2. inspect the returned objective, reported facts/hypotheses, completed actions, and next actions;
3. remember that checkpoint authority is `controller-state-only`;
4. revalidate every consequential fact through deterministic RE-MCP tools before mutation/build decisions.

Before a planned handoff away from Continue, or when controller/provider availability is deteriorating:

1. summarize only bounded controller state;
2. reference existing exact-source-SHA evidence artifacts where useful;
3. call `controller_checkpoint_write` using the current expected revision;
4. do not store chain-of-thought, transcripts, API keys, provider secrets, or credentials.

A stale checkpoint revision must be resolved by reading the current checkpoint; never overwrite or bypass the revision guard.

## 6. Mutation safety is unchanged

A model/provider switch never relaxes RE-MCP's rules:

- Never modify the source ROM.
- Never fabricate tool output or treat a model assertion as deterministic evidence.
- Never bypass an RE-MCP guard with an alternate file writer or raw ROM edit.
- Use `nds_mutation_validate` before `nds_mutation_build`.
- Use `nds_mutation_verify` before calling a rebuilt ROM complete.
- Preserve stored compressed-overlay bytes versus decoded runtime-image provenance.
- Preserve ambiguity instead of guessing loaded overlays or code ownership.

Provider inference success is not ROM verification.

## 7. Failure behavior

If Groq fails because of quota, rate limiting, provider availability, or another routable inference error, LiteLLM may attempt the configured OpenRouter and Ollama groups according to its router behavior. If every inference provider fails, Continue should stop cleanly rather than invent progress.

The RE-MCP server is independent of that inference path. Existing deterministic evidence/checkpoints remain available to another controller.

If RE-MCP itself rejects an operation, diagnose the structured error and satisfy the stated guard. Provider switching is never a reason to bypass a deterministic failure.

## Acceptance boundary

Repository CI/package checks validate the shipped configuration shape, safety rules, secret placeholders, loopback endpoints, fallback order, assembled-package contents, and tool-profile advertisement contracts.

They **do not prove**:

- that Groq or OpenRouter currently has quota/availability for the user;
- that `openrouter/free` will select a particular free model;
- that a live LiteLLM network request actually failed over between providers;
- that Continue completed a native Agent-mode workflow on the user's machine;
- that Ollama is installed or fast enough on the user's hardware;
- Physical DeSmuME / Intel Catalina debugger acceptance.

Those are separate live/native acceptance gates. Controller Independence PR D provides the repeatable controller benchmark/acceptance protocol for evaluating real controller runs without converting model prose into RE-MCP evidence.
