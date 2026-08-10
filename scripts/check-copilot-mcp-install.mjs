import { access, readFile } from "node:fs/promises";
import path from "node:path";

const root = path.resolve(process.argv[2] ?? process.cwd());
const mcpPath = path.join(root, ".vscode", "mcp.json");
const instructionsPath = path.join(root, ".github", "copilot-instructions.md");

await access(path.join(root, "dist", "index.js"));
await access(mcpPath);
await access(instructionsPath);

const configText = await readFile(mcpPath, "utf8");
const config = JSON.parse(configText);
const serverNames = Object.keys(config.servers ?? {});
if (serverNames.length !== 1 || serverNames[0] !== "re-mcp") {
  throw new Error("Expected exactly one packaged re-mcp MCP server");
}

const server = config.servers["re-mcp"];
if (server?.type !== "stdio" || server?.command !== "node") {
  throw new Error("Packaged re-mcp server must use node stdio");
}
if (JSON.stringify(server.args) !== JSON.stringify(["${workspaceFolder}/dist/index.js"])) {
  throw new Error("Packaged re-mcp server path is not workspace-relative");
}
if (server.env?.RE_MCP_WORKSPACE_ROOT !== "${input:reMcpWorkspaceRoot}") {
  throw new Error("Packaged workspace root must use the VS Code input");
}

const inputs = config.inputs ?? [];
const input = inputs.find((entry) => entry.id === "reMcpWorkspaceRoot");
if (inputs.length !== 1 || input?.type !== "promptString" || input.password !== false) {
  throw new Error("Packaged workspace-root input contract is invalid");
}

for (const forbidden of [
  /sk-[A-Za-z0-9]/i,
  /ghp_[A-Za-z0-9]/i,
  /\/Users\//,
  /\/home\//,
  /\.nds\b/i,
  /RE_MCP_GHIDRA_HOME/,
  /outputPath/i,
  /output_path/i,
]) {
  if (forbidden.test(configText)) {
    throw new Error(`Unsafe packaged MCP configuration matched ${forbidden}`);
  }
}

const instructions = await readFile(instructionsPath, "utf8");
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
  if (!instructions.toLowerCase().includes(required.toLowerCase())) {
    throw new Error(`Missing Copilot controller instruction: ${required}`);
  }
}

console.log("GitHub Copilot RE-MCP package smoke passed");
