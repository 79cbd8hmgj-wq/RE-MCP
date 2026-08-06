import { access } from "node:fs/promises";
import path from "node:path";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { loadConfig } from "./config.js";
import { assertSimpleProjectName, resolveInside } from "./security/paths.js";
import { OwnedProcessManager } from "./services/owned-process.js";
import { runProcess } from "./services/process-runner.js";
import { registerBakuganTools } from "./tools/bakugan.js";
import { registerDesmumeTools } from "./tools/desmume.js";
import { registerRuntimeEvidenceTools } from "./tools/runtime-evidence.js";

const config = loadConfig();
const server = new McpServer({ name: "re-mcp", version: "0.6.0" });
const desmumeManager = new OwnedProcessManager();

function projectDirectory(project: string): string {
  return resolveInside(config.workspaceRoot, assertSimpleProjectName(project));
}

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    isError,
  };
}

server.tool(
  "get_project_status",
  "Read Git status for one project under the configured workspace root.",
  { project: z.string().min(1) },
  async ({ project }) => {
    try {
      const cwd = projectDirectory(project);
      await access(path.join(cwd, ".git"));
      const result = await runProcess({
        executable: "git",
        args: ["status", "--short", "--branch"],
        cwd,
        timeoutMs: Math.min(config.commandTimeoutMs, 30_000),
        maxOutputBytes: config.maxOutputBytes,
      });
      return textResult(result, result.exitCode !== 0 || result.timedOut);
    } catch (error) {
      return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  },
);

const verificationScript = z.enum(["test", "typecheck", "build", "check"]);

server.tool(
  "run_project_verification",
  "Run one allowlisted npm verification script in a project. Arbitrary commands are not accepted.",
  {
    project: z.string().min(1),
    script: verificationScript,
  },
  async ({ project, script }) => {
    try {
      const cwd = projectDirectory(project);
      await access(path.join(cwd, "package.json"));
      const result = await runProcess({
        executable: "npm",
        args: ["run", script],
        cwd,
        timeoutMs: config.commandTimeoutMs,
        maxOutputBytes: config.maxOutputBytes,
      });
      return textResult(result, result.exitCode !== 0 || result.timedOut);
    } catch (error) {
      return textResult({ error: error instanceof Error ? error.message : String(error) }, true);
    }
  },
);

registerBakuganTools(server, config);
registerDesmumeTools(server, config, desmumeManager);
registerRuntimeEvidenceTools(server, config, desmumeManager);

server.tool(
  "server_capabilities",
  "Describe the current RE-MCP safety boundary and available operations.",
  {},
  async () =>
    textResult({
      version: "0.6.0",
      transport: "stdio",
      workspaceRoot: config.workspaceRoot,
      arbitraryShell: false,
      mutationPolicy: "Milestone 6E install is dry-run only",
      processPolicy: "One DeSmuME process owned by this server instance",
      debuggerPolicy: "Read-only ARM9 registers and bounded memory reads",
      evidencePolicy: "Atomic raw evidence under project analysis/generated only",
      tools: [
        "get_project_status",
        "run_project_verification",
        "bakugan_run_quality_suite",
        "bakugan_regenerate_m6e_contracts",
        "bakugan_install_m6e_dry_run",
        "bakugan_analyze_m6e_roster",
        "verify_file_sha256",
        "desmume_status",
        "desmume_start",
        "desmume_probe_gdb",
        "desmume_wait_for_gdb",
        "desmume_read_register_packet",
        "desmume_read_memory",
        "desmume_capture_runtime_evidence",
        "desmume_stop",
        "server_capabilities",
      ],
    }),
);

let shuttingDown = false;
async function shutdown(signal: NodeJS.Signals): Promise<void> {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  await desmumeManager.stop();
  process.exit(signal === "SIGINT" ? 130 : 143);
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));
process.once("beforeExit", () => void desmumeManager.stop());

const transport = new StdioServerTransport();
await server.connect(transport);
