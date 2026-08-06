import { access } from "node:fs/promises";
import path from "node:path";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { loadConfig } from "./config.js";
import { runProcess } from "./services/process-runner.js";
import { assertSimpleProjectName, resolveInside } from "./security/paths.js";
import { registerBakuganTools } from "./tools/bakugan.js";

const config = loadConfig();
const server = new McpServer({ name: "re-mcp", version: "0.2.0" });

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

server.tool(
  "server_capabilities",
  "Describe the current RE-MCP safety boundary and available operations.",
  {},
  async () =>
    textResult({
      version: "0.2.0",
      transport: "stdio",
      workspaceRoot: config.workspaceRoot,
      arbitraryShell: false,
      mutationPolicy: "Milestone 6E install is dry-run only",
      tools: [
        "get_project_status",
        "run_project_verification",
        "bakugan_run_quality_suite",
        "bakugan_regenerate_m6e_contracts",
        "bakugan_install_m6e_dry_run",
        "bakugan_analyze_m6e_roster",
        "verify_file_sha256",
        "server_capabilities",
      ],
    }),
);

const transport = new StdioServerTransport();
await server.connect(transport);
