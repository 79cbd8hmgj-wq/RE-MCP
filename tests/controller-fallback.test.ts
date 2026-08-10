import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const root = process.cwd();

async function readText(relative: string): Promise<string> {
  return readFile(path.join(root, relative), "utf8");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertNoCommittedSecretsOrPrivatePaths(text: string): void {
  for (const pattern of [
    /\bgsk_[A-Za-z0-9_-]{8,}/,
    /\bsk-or-v1-[A-Za-z0-9_-]{8,}/,
    /\bsk-[A-Za-z0-9_-]{16,}/,
    /\/Users\//,
    /\/home\/[A-Za-z0-9._-]+\//,
    /\b[A-Za-z0-9._-]+\.nds\b/i,
    /outputPath/i,
    /output_path/i,
  ]) {
    assert.doesNotMatch(text, pattern);
  }
}

test("Continue project MCP block launches only the existing RE-MCP stdio server", async () => {
  const source = await readText(".continue/mcpServers/re-mcp.yaml");

  for (const phrase of [
    "name: RE-MCP",
    "version:",
    "schema: v1",
    "mcpServers:",
    "type: stdio",
    "command: node",
    "dist/index.js",
    "RE_MCP_WORKSPACE_ROOT",
    "${{ secrets.RE_MCP_WORKSPACE_ROOT }}",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assertNoCommittedSecretsOrPrivatePaths(source);
  assert.doesNotMatch(source, /GROQ_API_KEY|OPENROUTER_API_KEY|LITELLM_MASTER_KEY/);
});

test("Continue controller rules preserve checkpoint and deterministic evidence authority", async () => {
  const rules = await readText(".continue/rules/re-mcp-controller.md");

  for (const phrase of [
    "controller_checkpoint_read",
    "controller_checkpoint_write",
    "controller-state-only",
    "revalidate",
    "Never modify the source ROM",
    "nds_mutation_validate",
    "nds_mutation_build",
    "nds_mutation_verify",
    "never fabricate tool output",
    "never bypass",
    "chain-of-thought",
    "API keys",
  ]) {
    assert.match(rules, new RegExp(escapeRegex(phrase), "i"));
  }
});

test("Continue fallback model uses loopback LiteLLM and explicit tool capability", async () => {
  const source = await readText("configs/controller/continue-re-mcp.yaml");

  for (const phrase of [
    "schema: v1",
    "provider: openai",
    "model: re-mcp-controller",
    "apiBase: http://127.0.0.1:4000/v1",
    "apiKey: ${{ secrets.LITELLM_MASTER_KEY }}",
    "capabilities:",
    "tool_use",
    "roles:",
    "chat",
    "edit",
    "apply",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assertNoCommittedSecretsOrPrivatePaths(source);
});

test("LiteLLM config has exact provider groups and current router fallback semantics", async () => {
  const source = await readText("configs/controller/litellm-re-mcp.yaml");

  for (const phrase of [
    "model_name: re-mcp-controller",
    "model: groq/openai/gpt-oss-120b",
    "api_key: os.environ/GROQ_API_KEY",
    "model_name: re-mcp-openrouter",
    "model: openrouter/openrouter/free",
    "api_key: os.environ/OPENROUTER_API_KEY",
    "model_name: re-mcp-ollama",
    "model: ollama/llama3.1",
    "api_base: http://127.0.0.1:11434",
    "router_settings:",
    "fallbacks:",
    "num_retries: 1",
    "timeout: 120",
    "general_settings:",
    "master_key: os.environ/LITELLM_MASTER_KEY",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assert.match(
    source,
    /router_settings:[\s\S]*fallbacks:[\s\S]*-\s*re-mcp-controller:[\s\S]*-\s*re-mcp-openrouter[\s\S]*-\s*re-mcp-ollama/,
  );
  assert.doesNotMatch(source, /litellm_settings:[\s\S]*fallbacks:/);
  assertNoCommittedSecretsOrPrivatePaths(source);
});

test("controller environment example contains names only and no usable cloud credentials", async () => {
  const source = await readText("configs/controller/controller.env.example");

  for (const name of [
    "RE_MCP_WORKSPACE_ROOT",
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "LITELLM_MASTER_KEY",
  ]) {
    assert.match(source, new RegExp(`^${name}=`, "m"));
  }

  assertNoCommittedSecretsOrPrivatePaths(source);
  assert.doesNotMatch(source, /=\s*(?:gsk_|sk-or-v1-|sk-)[A-Za-z0-9_-]+/);
});

test("fallback package and documentation acceptance are wired into the assembled bundle", async () => {
  const workflow = await readText(".github/workflows/package.yml");
  const smoke = await readText("scripts/check-controller-fallback-install.mjs");
  const guide = await readText("docs/controller-fallback.md");

  assert.match(workflow, /cp -R \.continue/);
  assert.match(workflow, /configs\/controller/);
  assert.match(workflow, /controller-fallback\.md/);
  assert.match(workflow, /check-controller-fallback-install\.mjs/);

  for (const phrase of [
    ".continue",
    "configs/controller",
    "controller-fallback.md",
    "Controller fallback package smoke passed",
  ]) {
    assert.match(smoke, new RegExp(escapeRegex(phrase), "i"));
  }

  for (const phrase of [
    "GitHub Copilot Agent",
    "preferred RE-MCP controller",
    "Continue",
    "LiteLLM",
    "provider-independent",
    "Groq",
    "OpenRouter",
    "Ollama",
    "controller_checkpoint_read",
    "controller_checkpoint_write",
    "controller-state-only",
    "Agent mode",
    "do not prove",
    "Physical DeSmuME",
  ]) {
    assert.match(guide, new RegExp(escapeRegex(phrase), "i"));
  }
});
