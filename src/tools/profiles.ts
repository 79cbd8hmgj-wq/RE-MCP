import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export const TOOL_PROFILE_NAMES = [
  "re-static-core",
  "re-ghidra-escalation",
  "re-runtime",
  "re-build",
  "re-project",
  "re-full",
] as const;

export type ToolProfileName = (typeof TOOL_PROFILE_NAMES)[number];

export const FULL_TOOL_NAMES = [
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
  "nds_mutation_validate",
  "nds_mutation_build",
  "nds_mutation_verify",
  "nds_correlate_stop_context",
  "nds_ghidra_bootstrap",
  "nds_ghidra_status",
  "nds_ghidra_inspect_function",
  "nds_ghidra_decompile_function",
  "nds_ghidra_search_symbols",
  "nds_ghidra_list_references",
  "nds_ghidra_list_calls",
  "re_trace_function",
  "re_investigate_data_usage",
  "controller_checkpoint_read",
  "controller_checkpoint_write",
  "server_capabilities",
] as const;

export type ShippedToolName = (typeof FULL_TOOL_NAMES)[number];

const staticCore = [
  "nds_inspect_rom",
  "nds_disassemble_range",
  "nds_find_xrefs",
  "nds_search_pattern",
  "re_trace_function",
  "re_investigate_data_usage",
  "controller_checkpoint_read",
  "controller_checkpoint_write",
] as const satisfies readonly ShippedToolName[];

const ghidraEscalation = [
  ...staticCore,
  "nds_ghidra_status",
  "nds_ghidra_inspect_function",
  "nds_ghidra_decompile_function",
  "nds_ghidra_search_symbols",
  "nds_ghidra_list_references",
  "nds_ghidra_list_calls",
] as const satisfies readonly ShippedToolName[];

const runtime = [
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
  "desmume_capture_runtime_evidence",
  "desmume_stop",
  "nds_correlate_stop_context",
  "controller_checkpoint_read",
  "controller_checkpoint_write",
] as const satisfies readonly ShippedToolName[];

const build = [
  "verify_file_sha256",
  "nds_inspect_rom",
  "nds_mutation_validate",
  "nds_mutation_build",
  "nds_mutation_verify",
  "controller_checkpoint_read",
  "controller_checkpoint_write",
] as const satisfies readonly ShippedToolName[];

const project = [
  "get_project_status",
  "run_project_verification",
  "bakugan_run_quality_suite",
  "bakugan_regenerate_m6e_contracts",
  "bakugan_install_m6e_dry_run",
  "bakugan_analyze_m6e_roster",
  "verify_file_sha256",
  "controller_checkpoint_read",
  "controller_checkpoint_write",
] as const satisfies readonly ShippedToolName[];

export const TOOL_PROFILES: Readonly<Record<ToolProfileName, readonly string[]>> = Object.freeze({
  "re-static-core": Object.freeze([...staticCore]),
  "re-ghidra-escalation": Object.freeze([...ghidraEscalation]),
  "re-runtime": Object.freeze([...runtime]),
  "re-build": Object.freeze([...build]),
  "re-project": Object.freeze([...project]),
  "re-full": Object.freeze([...FULL_TOOL_NAMES]),
});

export function isToolProfileName(value: string): value is ToolProfileName {
  return (TOOL_PROFILE_NAMES as readonly string[]).includes(value);
}

export function resolveToolProfile(value: string): readonly string[] {
  if (!isToolProfileName(value)) {
    throw new Error(
      `RE_MCP_TOOL_PROFILE must be one of: ${TOOL_PROFILE_NAMES.join(", ")}`,
    );
  }
  return TOOL_PROFILES[value];
}

export function createProfiledToolRegistrar(
  server: McpServer,
  profileName: ToolProfileName,
): McpServer {
  const allowed = new Set(resolveToolProfile(profileName));
  const tool = server.tool.bind(server) as (...args: unknown[]) => unknown;

  return new Proxy(server, {
    get(target, property, receiver) {
      if (property === "tool") {
        return (...args: unknown[]) => {
          const name = args[0];
          if (typeof name !== "string") {
            throw new Error("MCP tool registration requires a string tool name");
          }
          if (!allowed.has(name)) {
            return undefined;
          }
          return tool(...args);
        };
      }

      const value = Reflect.get(target, property, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
