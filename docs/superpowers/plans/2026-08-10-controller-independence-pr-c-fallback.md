# Controller Independence 1.0 — PR C Fallback Controller Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a reproducible Continue Agent + LiteLLM fallback path that uses RE-MCP directly for MCP tools and ordered cloud/free/local inference failover.

**Architecture:** Continue connects directly to the existing RE-MCP stdio server for deterministic tools and separately to a loopback LiteLLM OpenAI-compatible endpoint for inference. LiteLLM owns provider retry/fallback only; RE-MCP remains provider-independent and the exact-ROM checkpoint protocol carries handoff state between controllers.

**Tech Stack:** Continue schema-v1 YAML, LiteLLM proxy YAML, Node.js 20 source/package contract tests, GitHub Actions package acceptance.

## Global Constraints

- No production `src/` changes are required or allowed unless a failing acceptance test proves a packaging defect that cannot be solved outside the ROM engine.
- RE-MCP must never call LiteLLM, Groq, OpenRouter, Ollama, or another model provider.
- Cloud credentials are referenced only through environment/secret placeholders; no usable key value may be committed.
- Continue MCP tools must launch `node dist/index.js` and receive only secret-backed `RE_MCP_WORKSPACE_ROOT`.
- LiteLLM fallback order is `re-mcp-controller` -> `re-mcp-openrouter` -> `re-mcp-ollama` using `litellm_settings.fallbacks`.
- Provider endpoints in shipped examples are loopback except provider traffic initiated by LiteLLM.
- Checkpoint prose remains `controller-state-only`; consequential facts require deterministic RE-MCP revalidation.
- CI/package acceptance must not claim live provider availability, native Continue success, local Ollama availability, or physical DeSmuME acceptance.

---

### Task 1: RED fallback configuration contract

**Files:**
- Create: `tests/controller-fallback.test.ts`

**Interfaces:**
- Consumes: repository text/config files only.
- Produces: source-level acceptance contract for the configuration files created in Task 2 and package wiring created in Task 3.

- [ ] **Step 1: Write the failing source contract test**

Create tests that read the planned files and assert:

```ts
assert.match(continueMcp, /name:\s*RE-MCP/i);
assert.match(continueMcp, /command:\s*node/);
assert.match(continueMcp, /dist\/index\.js/);
assert.match(continueMcp, /RE_MCP_WORKSPACE_ROOT/);

assert.match(continueConfig, /provider:\s*openai/);
assert.match(continueConfig, /model:\s*re-mcp-controller/);
assert.match(continueConfig, /http:\/\/127\.0\.0\.1:4000\/v1/);
assert.match(continueConfig, /tool_use/);

assert.match(litellmConfig, /groq\/openai\/gpt-oss-120b/);
assert.match(litellmConfig, /openrouter\/openrouter\/free/);
assert.match(litellmConfig, /ollama\/llama3\.1/);
assert.match(litellmConfig, /litellm_settings:[\s\S]*fallbacks:/);
```

Also reject checked-in private paths, `.nds` paths, output paths, `sk-`/`gsk_`/`sk-or-` key-shaped values, and cloud keys outside environment references.

- [ ] **Step 2: Verify RED through the PR workflow**

Open the PR as draft with only the new test plus approved docs. Require CI to fail because the planned configuration files do not exist; typecheck must remain valid.

- [ ] **Step 3: Commit the RED gate**

Commit message: `test: define fallback controller contract`.

---

### Task 2: GREEN Continue and LiteLLM configuration

**Files:**
- Create: `.continue/mcpServers/re-mcp.yaml`
- Create: `.continue/rules/re-mcp-controller.md`
- Create: `configs/controller/continue-re-mcp.yaml`
- Create: `configs/controller/litellm-re-mcp.yaml`
- Create: `configs/controller/controller.env.example`

**Interfaces:**
- Continue MCP block launches the existing RE-MCP stdio server.
- Continue model config calls LiteLLM at `http://127.0.0.1:4000/v1` with model alias `re-mcp-controller`.
- LiteLLM model groups are `re-mcp-controller`, `re-mcp-openrouter`, and `re-mcp-ollama`.

- [ ] **Step 1: Add the project-local Continue MCP block**

Use schema-v1 block metadata and:

```yaml
mcpServers:
  - name: RE-MCP
    command: node
    args:
      - dist/index.js
    env:
      RE_MCP_WORKSPACE_ROOT: ${{ secrets.RE_MCP_WORKSPACE_ROOT }}
```

- [ ] **Step 2: Add provider-neutral controller rules**

Require checkpoint read-before-resume, checkpoint write-before-handoff, deterministic revalidation, source-ROM immutability, mutation validate/build/verify discipline, no fabricated tool output, no guard bypass, and no secrets/transcripts/chain-of-thought in checkpoints.

- [ ] **Step 3: Add Continue inference configuration**

Use:

```yaml
name: RE-MCP Fallback Controller
version: 1.0.0
schema: v1
models:
  - name: RE-MCP Controller
    provider: openai
    model: re-mcp-controller
    apiBase: http://127.0.0.1:4000/v1
    apiKey: ${{ secrets.LITELLM_MASTER_KEY }}
    capabilities:
      - tool_use
    roles:
      - chat
      - edit
      - apply
```

- [ ] **Step 4: Add LiteLLM model groups and ordered fallbacks**

Use environment-only keys and current provider identifiers:

```yaml
model_list:
  - model_name: re-mcp-controller
    litellm_params:
      model: groq/openai/gpt-oss-120b
      api_key: os.environ/GROQ_API_KEY
  - model_name: re-mcp-openrouter
    litellm_params:
      model: openrouter/openrouter/free
      api_key: os.environ/OPENROUTER_API_KEY
  - model_name: re-mcp-ollama
    litellm_params:
      model: ollama/llama3.1
      api_base: http://127.0.0.1:11434
litellm_settings:
  fallbacks:
    - re-mcp-controller:
        - re-mcp-openrouter
        - re-mcp-ollama
router_settings:
  num_retries: 1
  timeout: 120
```

Protect the local proxy with `general_settings.master_key: os.environ/LITELLM_MASTER_KEY` and document loopback binding at launch.

- [ ] **Step 5: Add environment example**

List only variable names with empty/example placeholders: `RE_MCP_WORKSPACE_ROOT`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`, and `LITELLM_MASTER_KEY`.

- [ ] **Step 6: Verify GREEN**

Require the Task 1 source contract and the complete repository `npm run check` to pass in CI.

- [ ] **Step 7: Commit**

Commit message: `feat: add Continue fallback controller configuration`.

---

### Task 3: Package and documentation acceptance

**Files:**
- Create: `docs/controller-fallback.md`
- Create: `scripts/check-controller-fallback-install.mjs`
- Modify: `.github/workflows/package.yml`
- Modify: `tests/controller-fallback.test.ts`
- Modify: `README.md`

**Interfaces:**
- Package workflow must ship `.continue`, `configs/controller`, the fallback guide, and smoke script.
- Smoke script validates assembled-bundle structure/safety without making network calls.

- [ ] **Step 1: Extend tests to require package wiring**

Require `package.yml` to copy `.continue`, `configs/controller`, and `docs/controller-fallback.md`, then execute `node scripts/check-controller-fallback-install.mjs .` inside the assembled package.

- [ ] **Step 2: Verify package RED**

Require Package workflow failure while the smoke/wiring is absent, without changing production `src/`.

- [ ] **Step 3: Add the fallback guide**

Document build/start sequence, Continue Agent mode, LiteLLM loopback launch, secret setup, direct provider failure behavior, checkpoint handoff, deterministic fact revalidation, and explicit external/native acceptance limits.

- [ ] **Step 4: Add assembled-package smoke**

The script must fail unless all fallback files exist, verify safe loopback/config strings, reject key-shaped committed values/private paths, and print exactly `Controller fallback package smoke passed` on success. It performs no provider request.

- [ ] **Step 5: Update package workflow and README**

Ship the new directories/docs and run the smoke after existing Copilot/checkpoint acceptance. README must identify Copilot as preferred, Continue+LiteLLM as fallback, and RE-MCP as provider-independent truth/execution authority.

- [ ] **Step 6: Verify GREEN**

Require exact-head CI and Package workflows to pass, including the assembled package smoke.

- [ ] **Step 7: Commit**

Commit message: `docs: ship fallback controller acceptance`.

---

### Task 4: Exact-head review and merge

**Files:**
- Review all PR files; no new implementation files expected.

**Interfaces:**
- Produces merged PR C on `main`, which PR D must use as its base.

- [ ] **Step 1: Review the entire diff**

Reject provider calls from `src/`, generic filesystem APIs, checked-in credentials, user-home/ROM/output paths, controller-specific mutation behavior, or any weakening of the checkpoint authority boundary.

- [ ] **Step 2: Require exact-head verification**

Require CI and Package success for the current head and zero unresolved review threads.

- [ ] **Step 3: Mark ready and update PR evidence**

Record exact head SHA and workflow outcomes in the PR body, including the explicit native/provider acceptance exclusions.

- [ ] **Step 4: Merge safely**

Merge with `expected_head_sha` under the user's standing authorization and verify `main` contains the merge before rebasing/updating PR D.
