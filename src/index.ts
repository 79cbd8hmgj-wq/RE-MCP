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
import { registerNdsFunctionTools } from "./tools/nds-functions.js";
import { registerNdsGhidraTools } from "./tools/nds-ghidra.js";
import { registerNdsPatternTools } from "./tools/nds-pattern.js";
import { registerNdsTools } from "./tools/nds.js";
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
registerNdsTools(server, config);
registerNdsPatternTools(server, config);
registerNdsFunctionTools(server, config);
registerNdsGhidraTools(server, config);
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
      debuggerPolicy:
        "Controlled ARM9 software breakpoints and bounded execution control on the owned localhost GDB stub; read-only register/memory inspection; no register writes, general memory writes, watchpoints, or arbitrary GDB packets",
      evidencePolicy: "Atomic raw evidence under project analysis/generated only",
      ndsStaticAnalysisPolicy:
        "Read-only Nintendo DS ROM parsing, deterministic address resolution, bounded NDS-mapped ARM/Thumb disassembly/direct CFG analysis, bounded deterministic single-instruction reference/xref analysis, bounded deterministic raw pattern search, and bounded proven function-entry/call-graph analysis over canonical executable components; function entries are proven only by program-entry or deterministic resolved direct-call evidence and function ends are not inferred; reverse scans/function proof may report partial or inconclusive coverage; optional Ghidra integration creates one full-SHA-256-scoped analyst-preserving project through configured analyzeHeadless, imports canonical RE-MCP evidence before normal Ghidra auto-analysis, and treats all Ghidra-derived inference as non-authoritative to RE-MCP; controlled Ghidra inspection requires an already-current SHA-scoped project and runs read-only with auto-analysis disabled while exposing only bounded canonical function/decompiler/symbol/reference/call queries; no loaded-overlay inference, generic binary analysis, heuristic pointer/function discovery, Ghidra-to-RE-MCP evidence promotion, ROM mutation/rebuild, arbitrary byte-range extraction, arbitrary Ghidra command/script execution, or caller-controlled output/project paths",
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
        "desmume_breakpoint_add",
        "desmume_breakpoint_remove",
        "desmume_breakpoint_list",
        "desmume_continue",
        "desmume_step_instruction",
        "desmume_pause",
        "desmume_wait_for_stop",
        "desmume_capture_stop_context",
        "desmume_executable_ranges_replace",
        "desmume_capture_runtime_evidence",
        "desmume_stop",
        "nds_inspect_rom",
        "nds_list_files",
        "nds_list_overlays",
        "nds_resolve_runtime_address",
        "nds_resolve_rom_offset",
        "nds_extract_component",
        "nds_extract_analysis_bundle",
        "nds_disassemble_range",
        "nds_analyze_control_flow",
        "nds_list_references",
        "nds_find_xrefs",
        "nds_search_pattern",
        "nds_discover_functions",
        "nds_analyze_function",
        "nds_ghidra_bootstrap",
        "nds_ghidra_status",
        "nds_ghidra_inspect_function",
        "nds_ghidra_decompile_function",
        "nds_ghidra_search_symbols",
        "nds_ghidra_list_references",
        "nds_ghidra_list_calls",
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
