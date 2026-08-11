import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import {
  FULL_TOOL_NAMES,
  TOOL_PROFILE_NAMES,
  TOOL_PROFILES,
  createProfiledToolRegistrar,
  resolveToolProfile,
  type ToolProfileName,
} from "../src/tools/profiles.js";

const PRE_CONTROLLER_EFFICIENCY_TOOL_NAMES = [
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
  "controller_checkpoint_read",
  "controller_checkpoint_write",
  "server_capabilities",
] as const;

const CONTROLLER_EFFICIENCY_ADDITIONS = [
  "re_trace_function",
  "re_investigate_data_usage",
  "re_decompile_candidate",
  "re_resume_investigation",
] as const;

type ToolDescriptor = Awaited<ReturnType<Client["listTools"]>>["tools"][number];

function sorted(values: readonly string[]): string[] {
  return [...values].sort();
}

function processEnvironment(workspace: string, profile?: ToolProfileName): Record<string, string> {
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      (entry): entry is [string, string] =>
        entry[1] !== undefined
        && entry[0] !== "RE_MCP_WORKSPACE_ROOT"
        && entry[0] !== "RE_MCP_TOOL_PROFILE",
    ),
  );
  return {
    ...environment,
    RE_MCP_WORKSPACE_ROOT: workspace,
    ...(profile === undefined ? {} : { RE_MCP_TOOL_PROFILE: profile }),
  };
}

function parseTextPayload(response: unknown): Record<string, unknown> {
  const record = response as { readonly content?: unknown };
  assert.equal(Array.isArray(record.content), true);
  const first = (record.content as unknown[])[0] as {
    readonly type?: unknown;
    readonly text?: unknown;
  } | undefined;
  assert.equal(first?.type, "text");
  assert.equal(typeof first?.text, "string");
  return JSON.parse(first.text as string) as Record<string, unknown>;
}

async function inspectProfile(profile?: ToolProfileName): Promise<{
  readonly tools: readonly ToolDescriptor[];
  readonly capabilities: Record<string, unknown>;
}> {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "re-mcp-profile-"));
  const client = new Client({ name: "tool-profile-test", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["--import", "tsx", "src/index.ts"],
    env: processEnvironment(workspace, profile),
    stderr: "pipe",
  });

  try {
    await client.connect(transport);
    const tools = (await client.listTools()).tools;
    const capabilities = parseTextPayload(await client.callTool({
      name: "server_capabilities",
      arguments: {},
    }));
    return { tools, capabilities };
  } finally {
    await client.close().catch(() => undefined);
    await rm(workspace, { recursive: true, force: true });
  }
}

test("re-full preserves the exact pre-efficiency low-level capability surface and adds only orchestration", () => {
  const legacy = new Set<string>(PRE_CONTROLLER_EFFICIENCY_TOOL_NAMES);
  const current = new Set<string>(FULL_TOOL_NAMES);

  assert.equal(PRE_CONTROLLER_EFFICIENCY_TOOL_NAMES.length, 52);
  assert.equal(FULL_TOOL_NAMES.length, 56);
  assert.deepEqual(TOOL_PROFILES["re-full"], FULL_TOOL_NAMES);
  for (const tool of PRE_CONTROLLER_EFFICIENCY_TOOL_NAMES) {
    assert.equal(current.has(tool), true, `legacy tool disappeared from re-full: ${tool}`);
  }
  assert.deepEqual(
    sorted(FULL_TOOL_NAMES.filter((tool) => !legacy.has(tool))),
    sorted(CONTROLLER_EFFICIENCY_ADDITIONS),
  );
});

test("profile registrar is a pure advertisement filter for included tools", () => {
  assert.throws(() => resolveToolProfile("unknown"), /RE_MCP_TOOL_PROFILE must be one of:/);

  const registrations: unknown[][] = [];
  const sentinel = { registered: true };
  const fakeServer = {
    tool(...args: unknown[]) {
      registrations.push(args);
      return sentinel;
    },
  };
  const profiled = createProfiledToolRegistrar(fakeServer as never, "re-build");
  const schema = { exact: "same-reference" };
  const handler = () => "same-handler";
  const forwarded = (profiled.tool as (...args: unknown[]) => unknown)(
    "nds_mutation_validate",
    "description",
    schema,
    handler,
  );
  const hidden = (profiled.tool as (...args: unknown[]) => unknown)(
    "desmume_start",
    "hidden",
    schema,
    handler,
  );

  assert.equal(forwarded, sentinel);
  assert.equal(hidden, undefined);
  assert.equal(registrations.length, 1);
  assert.equal(registrations[0]?.[0], "nds_mutation_validate");
  assert.equal(registrations[0]?.[1], "description");
  assert.equal(registrations[0]?.[2], schema);
  assert.equal(registrations[0]?.[3], handler);
});

test("every profile advertises exactly its allowlist with full-profile descriptor parity", async () => {
  const full = await inspectProfile("re-full");
  const fullByName = new Map(full.tools.map((tool) => [tool.name, tool] as const));
  assert.deepEqual(sorted(full.tools.map((tool) => tool.name)), sorted(FULL_TOOL_NAMES));

  for (const profile of TOOL_PROFILE_NAMES) {
    const inspected = profile === "re-full" ? full : await inspectProfile(profile);
    assert.deepEqual(
      sorted(inspected.tools.map((tool) => tool.name)),
      sorted(TOOL_PROFILES[profile]),
      `advertised names drifted for ${profile}`,
    );
    for (const descriptor of inspected.tools) {
      assert.deepEqual(
        descriptor,
        fullByName.get(descriptor.name),
        `profile filtering changed the descriptor for ${descriptor.name} in ${profile}`,
      );
    }

    assert.equal(inspected.capabilities.activeToolProfile, profile);
    assert.equal(inspected.capabilities.advertisedToolCount, TOOL_PROFILES[profile].length);
    assert.deepEqual(
      sorted(inspected.capabilities.tools as string[]),
      sorted(TOOL_PROFILES[profile]),
    );
  }
});

test("default startup remains backward-compatible re-full", async () => {
  const defaultProfile = await inspectProfile();
  assert.deepEqual(
    sorted(defaultProfile.tools.map((tool) => tool.name)),
    sorted(FULL_TOOL_NAMES),
  );
  assert.equal(defaultProfile.capabilities.activeToolProfile, "re-full");
});

test("focused profiles keep phase-critical escape hatches and capability discovery", () => {
  for (const profile of TOOL_PROFILE_NAMES.filter((name) => name !== "re-full")) {
    assert.equal(
      TOOL_PROFILES[profile].includes("server_capabilities"),
      true,
      `${profile} must expose server_capabilities`,
    );
  }

  const runtime = new Set(TOOL_PROFILES["re-runtime"]);
  for (const tool of FULL_TOOL_NAMES.filter((name) => name.startsWith("desmume_"))) {
    assert.equal(runtime.has(tool), true, `re-runtime omitted debugger capability ${tool}`);
  }

  assert.equal(TOOL_PROFILES["re-static-core"].includes("nds_disassemble_range"), true);
  assert.equal(TOOL_PROFILES["re-static-core"].includes("nds_find_xrefs"), true);
  assert.equal(TOOL_PROFILES["re-ghidra-escalation"].includes("nds_ghidra_bootstrap"), false);
  assert.equal(TOOL_PROFILES["re-build"].includes("nds_mutation_validate"), true);
  assert.equal(TOOL_PROFILES["re-build"].includes("nds_mutation_build"), true);
  assert.equal(TOOL_PROFILES["re-build"].includes("nds_mutation_verify"), true);
});

test("re-static-core still cuts actual schema payload by at least 70%", async () => {
  const full = await inspectProfile("re-full");
  const compact = await inspectProfile("re-static-core");
  const fullBytes = Buffer.byteLength(JSON.stringify(full.tools), "utf8");
  const compactBytes = Buffer.byteLength(JSON.stringify(compact.tools), "utf8");

  assert.ok(
    compactBytes <= Math.floor(fullBytes * 0.3),
    `expected re-static-core schema payload <=30% of re-full; full=${fullBytes}, compact=${compactBytes}`,
  );
});
