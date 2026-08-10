#!/usr/bin/env node

import { readFile, stat } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? ".");

const files = {
  continueMcp: ".continue/mcpServers/re-mcp.yaml",
  continueRules: ".continue/rules/re-mcp-controller.md",
  continueModel: "configs/controller/continue-re-mcp.yaml",
  litellm: "configs/controller/litellm-re-mcp.yaml",
  envExample: "configs/controller/controller.env.example",
  guide: "docs/controller-fallback.md",
  server: "dist/index.js",
};

async function readRequired(relativePath) {
  const absolute = path.join(root, relativePath);
  const info = await stat(absolute);
  if (!info.isFile()) {
    throw new Error(`${relativePath} is not a regular file`);
  }
  return readFile(absolute, "utf8");
}

function requireText(source, needle, label) {
  if (!source.includes(needle)) {
    throw new Error(`${label} is missing required text: ${needle}`);
  }
}

function rejectUnsafe(source, label) {
  const forbidden = [
    /\bgsk_[A-Za-z0-9_-]{8,}/,
    /\bsk-or-v1-[A-Za-z0-9_-]{8,}/,
    /\bsk-[A-Za-z0-9_-]{16,}/,
    /\/Users\//,
    /\/home\/[A-Za-z0-9._-]+\//,
    /\b[A-Za-z0-9._-]+\.nds\b/i,
    /outputPath/i,
    /output_path/i,
  ];
  for (const pattern of forbidden) {
    if (pattern.test(source)) {
      throw new Error(`${label} contains forbidden committed/private configuration matching ${pattern}`);
    }
  }
}

const continueMcp = await readRequired(files.continueMcp);
const continueRules = await readRequired(files.continueRules);
const continueModel = await readRequired(files.continueModel);
const litellm = await readRequired(files.litellm);
const envExample = await readRequired(files.envExample);
const guide = await readRequired(files.guide);
await readRequired(files.server);

for (const [label, source] of [
  ["Continue MCP", continueMcp],
  ["Continue rules", continueRules],
  ["Continue model", continueModel],
  ["LiteLLM", litellm],
  ["controller environment example", envExample],
]) {
  rejectUnsafe(source, label);
}

for (const needle of [
  "schema: v1",
  "mcpServers:",
  "type: stdio",
  "command: node",
  "dist/index.js",
  "RE_MCP_WORKSPACE_ROOT: ${{ secrets.RE_MCP_WORKSPACE_ROOT }}",
]) {
  requireText(continueMcp, needle, "Continue MCP block");
}
for (const providerName of ["GROQ_API_KEY", "OPENROUTER_API_KEY", "LITELLM_MASTER_KEY"]) {
  if (continueMcp.includes(providerName)) {
    throw new Error(`Continue MCP block must not receive inference credential ${providerName}`);
  }
}

for (const needle of [
  "controller_checkpoint_read",
  "controller_checkpoint_write",
  "controller-state-only",
  "nds_mutation_validate",
  "nds_mutation_build",
  "nds_mutation_verify",
  "Never modify the source ROM",
]) {
  requireText(continueRules, needle, "Continue controller rules");
}

for (const needle of [
  "provider: openai",
  "model: re-mcp-controller",
  "apiBase: http://127.0.0.1:4000/v1",
  "apiKey: ${{ secrets.LITELLM_MASTER_KEY }}",
  "tool_use",
]) {
  requireText(continueModel, needle, "Continue fallback model");
}

for (const needle of [
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
  "general_settings:",
  "master_key: os.environ/LITELLM_MASTER_KEY",
]) {
  requireText(litellm, needle, "LiteLLM fallback config");
}

const routerStart = litellm.indexOf("router_settings:");
const fallbackStart = litellm.indexOf("fallbacks:", routerStart);
const primaryStart = litellm.indexOf("- re-mcp-controller:", fallbackStart);
const openRouterStart = litellm.indexOf("- re-mcp-openrouter", primaryStart);
const ollamaStart = litellm.indexOf("- re-mcp-ollama", openRouterStart);
if (!(routerStart >= 0 && fallbackStart > routerStart && primaryStart > fallbackStart && openRouterStart > primaryStart && ollamaStart > openRouterStart)) {
  throw new Error("LiteLLM ordered router fallback chain is missing or out of order");
}

for (const name of ["RE_MCP_WORKSPACE_ROOT", "GROQ_API_KEY", "OPENROUTER_API_KEY", "LITELLM_MASTER_KEY"]) {
  if (!new RegExp(`^${name}=\\s*$`, "m").test(envExample)) {
    throw new Error(`controller environment example must contain an empty ${name}= entry`);
  }
}

for (const needle of [
  "Continue",
  "LiteLLM",
  "controller_checkpoint_read",
  "controller-state-only",
  "Agent mode",
  "Physical DeSmuME",
]) {
  requireText(guide, needle, "controller fallback guide");
}

console.log("Controller fallback package smoke passed");
