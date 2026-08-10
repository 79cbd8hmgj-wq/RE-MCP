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

test("VS Code Copilot workspace config launches only the RE-MCP stdio server", async () => {
  const config = JSON.parse(await readText(".vscode/mcp.json")) as {
    servers?: Record<string, {
      type?: string;
      command?: string;
      args?: string[];
      env?: Record<string, string>;
    }>;
    inputs?: Array<{
      id?: string;
      type?: string;
      description?: string;
      password?: boolean;
    }>;
  };

  assert.deepEqual(Object.keys(config.servers ?? {}), ["re-mcp"]);
  assert.equal(config.servers?.["re-mcp"]?.type, "stdio");
  assert.equal(config.servers?.["re-mcp"]?.command, "node");
  assert.deepEqual(config.servers?.["re-mcp"]?.args, ["${workspaceFolder}/dist/index.js"]);
  assert.equal(
    config.servers?.["re-mcp"]?.env?.RE_MCP_WORKSPACE_ROOT,
    "${input:reMcpWorkspaceRoot}",
  );

  assert.equal(config.inputs?.length, 1);
  assert.equal(config.inputs?.[0]?.id, "reMcpWorkspaceRoot");
  assert.equal(config.inputs?.[0]?.type, "promptString");
  assert.equal(config.inputs?.[0]?.password, false);
  assert.match(config.inputs?.[0]?.description ?? "", /dedicated RE-MCP ROM-modding workspace/i);
});

test("VS Code Copilot workspace config contains no checked-in private or unsafe paths", async () => {
  const configText = await readText(".vscode/mcp.json");
  const forbidden = [
    /sk-[A-Za-z0-9]/i,
    /ghp_[A-Za-z0-9]/i,
    /\/Users\//,
    /\/home\//,
    /\.nds\b/i,
    /RE_MCP_GHIDRA_HOME/,
    /outputPath/i,
    /output_path/i,
  ];

  for (const pattern of forbidden) {
    assert.doesNotMatch(configText, pattern);
  }
});

test("Copilot instructions preserve the deterministic RE-MCP trust boundary", async () => {
  const instructions = await readText(".github/copilot-instructions.md");
  for (const required of [
    "RE-MCP owns truth and deterministic execution",
    "Never modify the source ROM",
    "canonical NDS",
    "compressed overlay",
    "nds_mutation_validate",
    "nds_mutation_verify",
    "Physical DeSmuME",
    "genuine blocker",
  ]) {
    assert.match(instructions, new RegExp(escapeRegex(required), "i"));
  }

  assert.match(instructions, /never bypass guards/i);
  assert.match(instructions, /never.*fabricate tool output/i);
  assert.match(instructions, /alternate ROM writer/i);
});

test("package workflow ships and smoke-checks the Copilot controller integration", async () => {
  const workflow = await readText(".github/workflows/package.yml");
  const smoke = await readText("scripts/check-copilot-mcp-install.mjs");

  assert.match(workflow, /cp -R \.vscode/);
  assert.match(workflow, /copilot-instructions\.md/);
  assert.match(workflow, /github-copilot-agent\.md/);
  assert.match(workflow, /check-copilot-mcp-install\.mjs/);

  assert.match(smoke, /\.vscode["']?,\s*["']mcp\.json/);
  assert.match(smoke, /copilot-instructions\.md/);
  assert.match(smoke, /github-copilot-agent\.md/);
  assert.match(smoke, /dist["']?,\s*["']index\.js/);
  assert.match(smoke, /GitHub Copilot RE-MCP package smoke passed/);
});

test("controller guide documents the reproducible GitHub Copilot Agent setup", async () => {
  const guide = await readText("docs/github-copilot-agent.md");
  for (const phrase of [
    "GitHub Copilot Agent",
    ".vscode/mcp.json",
    "npm run build",
    "reMcpWorkspaceRoot",
    "Configure Tools",
    "trust",
    "not part of RE-MCP's trust boundary",
    "does not prove a native VS Code/Copilot session",
  ]) {
    assert.match(guide, new RegExp(escapeRegex(phrase), "i"));
  }

  assert.match(guide, /mcp-config\.example\.json/);
  assert.match(guide, /Ghidra.*machine-specific/is);
  assert.match(guide, /Physical DeSmuME/i);
});
