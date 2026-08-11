import { access } from "node:fs/promises";
import path from "node:path";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { loadConfig } from "./config.js";
import { assertSimpleProjectName, resolveInside } from "./security/paths.js";
import { OwnedProcessManager } from "./services/owned-process.js";
import { runProcess } from "./services/process-runner.js";
import { registerControllerCheckpointTools } from "./tools/controller-checkpoint.js";
import { createProfiledToolRegistrar, TOOL_PROFILES } from "./tools/profiles.js";

const config = loadConfig();
const activeToolProfile = config.toolProfile ?? "re-full";
const activeProfileTools = new Set(TOOL_PROFILES[activeToolProfile]);
const transportServer = new McpServer({ name: "re-mcp", version: "0.6.0" });
const server = createProfiledToolRegistrar(transportServer, activeToolProfile);
const desmumeManager = new OwnedProcessManager();

const projectToolNames = [
  "get_project_status",
  "run_project_verification",
] as const;

const bakuganToolNames = [
  "bakugan_run_quality_suite",
  "bakugan_regenerate_m6e_contracts",
  "bakugan_install_m6e_dry_run",
  "bakugan_analyze_m6e_roster",
  "verify_file_sha256",
] as const;

const ndsCoreToolNames = [
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
] as const;

const ndsPatternToolNames = [
  "nds_find_xrefs",
  "nds_search_pattern",
] as const;

const ndsFunctionToolNames = [
  "nds_discover_functions",
  "nds_analyze_function",
] as const;

const runtimeToolNames = [
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
  "nds_correlate_stop_context",
] as const;

const ndsStaticAnalysisToolNames = [
  ...ndsCoreToolNames,
  ...ndsPatternToolNames,
] as const;

const ndsMutationToolNames = [
  "nds_mutation_validate",
  "nds_mutation_build",
  "nds_mutation_verify",
] as const;

const ndsGhidraToolNames = [
  "nds_ghidra_bootstrap",
  "nds_ghidra_status",
  "nds_ghidra_inspect_function",
  "nds_ghidra_decompile_function",
  "nds_ghidra_search_symbols",
  "nds_ghidra_list_references",
  "nds_ghidra_list_calls",
] as const;

const reOrchestrationToolNames = [
  "re_trace_function",
  "re_investigate_data_usage",
  "re_decompile_candidate",
  "re_resume_investigation",
] as const;

function profileIncludesAny(names: readonly string[]): boolean {
  return names.some((name) => activeProfileTools.has(name));
}

function visibleProfileTools(names: readonly string[]): readonly string[] {
  return names.filter((name) => activeProfileTools.has(name));
}

function projectDirectory(project: string): string {
  return resolveInside(config.workspaceRoot, assertSimpleProjectName(project));
}

function textResult(value: unknown, isError = false) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }],
    isError,
  };
}

if (profileIncludesAny(projectToolNames)) {
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
}

if (profileIncludesAny(bakuganToolNames)) {
  const { registerBakuganTools } = await import("./tools/bakugan.js");
  registerBakuganTools(server, config);
}

if (profileIncludesAny(runtimeToolNames)) {
  const { registerDesmumeTools } = await import("./tools/desmume.js");
  const { registerNdsRuntimeTools } = await import("./tools/nds-runtime.js");
  const { registerRuntimeEvidenceTools } = await import("./tools/runtime-evidence.js");
  const desmumeDebugger = registerDesmumeTools(server, config, desmumeManager);
  registerNdsRuntimeTools(server, config, desmumeManager, desmumeDebugger);
  registerRuntimeEvidenceTools(server, config, desmumeManager);
}

if (profileIncludesAny(ndsCoreToolNames)) {
  const { registerNdsTools } = await import("./tools/nds.js");
  registerNdsTools(server, config);
}

if (profileIncludesAny(ndsPatternToolNames)) {
  const { registerNdsPatternTools } = await import("./tools/nds-pattern.js");
  registerNdsPatternTools(server, config);
}

if (profileIncludesAny(ndsFunctionToolNames)) {
  const { registerNdsFunctionTools } = await import("./tools/nds-functions.js");
  registerNdsFunctionTools(server, config);
}

if (profileIncludesAny(reOrchestrationToolNames)) {
  const { registerReOrchestrationTools } = await import("./tools/re-orchestration.js");
  registerReOrchestrationTools(server, config);
}

if (profileIncludesAny(ndsMutationToolNames)) {
  const { registerNdsMutationTools } = await import("./tools/nds-mutation.js");
  registerNdsMutationTools(server, config);
}

if (profileIncludesAny(ndsGhidraToolNames)) {
  const { registerNdsGhidraTools } = await import("./tools/nds-ghidra.js");
  registerNdsGhidraTools(server, config);
}

registerControllerCheckpointTools(server, config);

server.tool(
  "server_capabilities",
  "Describe the current RE-MCP safety boundary and active tool profile.",
  {},
  async () =>
    textResult({
      version: "0.6.0",
      transport: "stdio",
      workspaceRoot: config.workspaceRoot,
      activeToolProfile,
      advertisedToolCount: TOOL_PROFILES[activeToolProfile].length,
      tools: TOOL_PROFILES[activeToolProfile],
      arbitraryShell: false,
      mutationPolicy:
        "Controlled manifest-driven NDS build operations may publish verified deterministic outputs beneath output/nds; source ROMs remain immutable. Milestone 1 permits only same-size guarded canonical byte/component replacements, with no arbitrary ROM offsets and no caller-selected output paths.",
      ndsMutationTools: visibleProfileTools(ndsMutationToolNames),
      processPolicy: "One DeSmuME process owned by this server instance",
      debuggerPolicy:
        "Controlled ARM9 software breakpoints and bounded execution control on the owned localhost GDB stub; read-only register/memory inspection and current-stop NDS static correlation with opt-in already-current Ghidra enrichment; no register writes, general memory writes, watchpoints, arbitrary GDB packets, automatic execution during correlation, or Ghidra bootstrap/reconciliation during correlation",
      evidencePolicy:
        "Atomic raw evidence under project analysis/generated plus deterministic NDS mutation evidence under controlled output/nds build directories",
      controllerCheckpointPolicy:
        "Provider-neutral exact-ROM-SHA controller checkpoints are stored only beneath analysis/generated/nds/<sha-prefix>/controller. Checkpoint prose has authority controller-state-only, uses fail-closed revisions and integrity hashes, and must not replace deterministic RE-MCP revalidation of consequential ROM facts.",
      ndsStaticAnalysisTools: visibleProfileTools(ndsStaticAnalysisToolNames),
      ndsGhidraTools: visibleProfileTools(ndsGhidraToolNames),
      reOrchestrationTools: visibleProfileTools(reOrchestrationToolNames),
      reOrchestrationPolicy:
        "Read-only bounded deterministic orchestration composes canonical NDS mapping, function proof, CFG, direct xrefs, compact disassembly windows, exact-ROM-SHA resumable journal persistence, and opt-in already-current read-only Ghidra candidate enrichment. It preserves ambiguity, fails closed on persistence/integrity errors, performs no mutation or debugger execution, accepts no caller-selected output path, and does not promote Ghidra or controller prose to ROM fact.",
      investigationPersistencePolicy:
        "Successful consequential high-level RE operations are persisted before success under analysis/generated/nds/<sha-prefix>/controller as an integrity-bound append-only logical journal plus compact projection and bounded exact-ROM resume evidence. Prompts, secrets, chain-of-thought, and arbitrary model transcripts are never persisted.",
      ndsStaticAnalysisPolicy:
        "Read-only Nintendo DS ROM parsing, deterministic address resolution, bounded NDS-mapped ARM/Thumb disassembly/direct CFG analysis, bounded deterministic single-instruction reference/xref analysis, bounded deterministic raw pattern search, bounded proven function-entry/call-graph analysis, and exact-ROM-SHA current-stop ARM9 correlation over canonical executable components; current-stop correlation may opt in to read-only already-current Ghidra enrichment, but performs no Ghidra bootstrap, reconciliation, migration, auto-analysis, or mutation; runtime correlation preserves overlapping overlay candidates and uses the observed CPSR mode without guessing loaded overlay state; function entries are proven only by program-entry or deterministic resolved direct-call evidence and function ends are not inferred; reverse scans/function proof may report partial or inconclusive coverage; optional Ghidra integration creates one full-SHA-256-scoped analyst-preserving project through configured analyzeHeadless, imports canonical RE-MCP evidence before normal Ghidra auto-analysis, and treats all Ghidra-derived inference as non-authoritative to RE-MCP; controlled Ghidra inspection requires an already-current SHA-scoped project and runs read-only with auto-analysis disabled while exposing only bounded canonical function/decompiler/symbol/reference/call queries; no loaded-overlay inference, generic binary analysis, heuristic pointer/function discovery, Ghidra-to-RE-MCP evidence promotion, arbitrary byte-range extraction, arbitrary Ghidra command/script execution, or caller-controlled Ghidra output/project paths",
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
await transportServer.connect(transport);
