import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

import type { ServerConfig } from "../../config.js";
import { resolveInside } from "../../security/paths.js";
import { runProcess, type RunResult } from "../process-runner.js";
import { NdsError } from "./errors.js";
import type { GeneratedGhidraBridge } from "./ghidra-bridge.js";
import type { ValidatedGhidraInstallation } from "./ghidra-installation.js";
import {
  ghidraProgramName,
  ghidraProjectName,
  ghidraProjectRoot,
} from "./ghidra-model.js";
import type { NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

export type { ValidatedGhidraInstallation } from "./ghidra-installation.js";

const DEFAULT_GHIDRA_TIMEOUT_MS = 900_000;
const GHIDRA_DIAGNOSTIC_STREAM_BYTES = 4 * 1024;

export interface GhidraInvocationInput {
  readonly installation: ValidatedGhidraInstallation;
  readonly map: NdsRomMap;
  readonly bridge: GeneratedGhidraBridge;
  readonly processor: NdsProcessor;
  readonly workspaceRoot: string;
}

export interface GhidraInvocation {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly stage: "arm9-import" | "arm9-process" | "arm7-import" | "arm7-process";
}

function candidateScriptPaths(): readonly string[] {
  return [
    fileURLToPath(new URL("../../../resources/ghidra/", import.meta.url)),
    fileURLToPath(new URL("../../../../resources/ghidra/", import.meta.url)),
  ];
}

export function resolveReMcpGhidraScriptPath(): string {
  for (const candidate of candidateScriptPaths()) {
    if (existsSync(candidate)) {
      return path.resolve(candidate);
    }
  }
  throw new NdsError(
    "invalid-ghidra-installation",
    "RE-MCP packaged Ghidra script resources are missing",
  );
}

function processorManifest(input: GhidraInvocationInput) {
  const manifest = input.bridge.manifest.processors.find(
    (entry) => entry.processor === input.processor,
  );
  if (manifest === undefined) {
    throw new NdsError(
      "bridge-generation-failed",
      `Ghidra bridge manifest is missing ${input.processor.toUpperCase()} metadata`,
    );
  }
  return manifest;
}

function generatedArtifact(
  bridge: GeneratedGhidraBridge,
  relativePath: string,
): string {
  const generatedRoot = path.dirname(bridge.bridgeRoot);
  const candidate = path.resolve(bridge.bridgeRoot, relativePath);
  const relative = path.relative(generatedRoot, candidate);
  return resolveInside(generatedRoot, relative);
}

function resultPath(
  bridge: GeneratedGhidraBridge,
  processor: NdsProcessor,
): string {
  return resolveInside(bridge.bridgeRoot, bridge.manifest.generatedResultPaths[processor]);
}

function commonScriptArgs(input: GhidraInvocationInput): string[] {
  const scriptPath = resolveReMcpGhidraScriptPath();
  return [
    "-scriptPath",
    scriptPath,
    "-preScript",
    "ReMcpPrepareProgram.java",
    input.bridge.manifestPath,
    input.processor,
    "-preScript",
    "ReMcpImportEvidence.java",
    input.bridge.manifestPath,
    input.processor,
    "-postScript",
    "ReMcpRecordAnalysis.java",
    input.bridge.manifestPath,
    input.processor,
    resultPath(input.bridge, input.processor),
  ];
}

function projectPrefix(input: GhidraInvocationInput): string[] {
  return [
    ghidraProjectRoot(input.map, input.workspaceRoot),
    ghidraProjectName(input.map),
  ];
}

function addressHex(value: number): string {
  return `0x${value.toString(16)}`;
}

export function buildGhidraImportInvocation(
  input: GhidraInvocationInput,
): GhidraInvocation {
  const processor = processorManifest(input);
  const executable = generatedArtifact(input.bridge, processor.main.artifactPath);
  return {
    executable: input.installation.analyzeHeadless,
    args: [
      ...projectPrefix(input),
      "-import",
      executable,
      "-loader",
      "BinaryLoader",
      "-processor",
      processor.language,
      "-loader-baseAddr",
      addressHex(processor.main.runtimeAddress),
      ...commonScriptArgs(input),
    ],
    cwd: path.dirname(input.bridge.bridgeRoot),
    stage: input.processor === "arm9" ? "arm9-import" : "arm7-import",
  };
}

export function buildGhidraProcessInvocation(
  input: GhidraInvocationInput,
): GhidraInvocation {
  processorManifest(input);
  return {
    executable: input.installation.analyzeHeadless,
    args: [
      ...projectPrefix(input),
      "-process",
      ghidraProgramName(input.processor),
      ...commonScriptArgs(input),
    ],
    cwd: path.dirname(input.bridge.bridgeRoot),
    stage: input.processor === "arm9" ? "arm9-process" : "arm7-process",
  };
}

function isImportStage(stage: GhidraInvocation["stage"]): boolean {
  return stage.endsWith("-import");
}

function looksLikeProjectLock(stderr: string): boolean {
  return /LockException|write-lock|project[^\n]*locked|already[^\n]*open/iu.test(stderr);
}

function combinedOutput(result: RunResult): string {
  return `${result.stdout}\n${result.stderr}`;
}

function hasReportedImportFailure(result: RunResult): boolean {
  return /REPORT:\s+(?:Save failed for:|Import failed\b)/iu.test(combinedOutput(result));
}

function hasReportedScriptError(result: RunResult): boolean {
  return /REPORT SCRIPT ERROR:/u.test(combinedOutput(result));
}

function diagnosticTail(value: string): {
  readonly text: string;
  readonly clipped: boolean;
} {
  const encoded = Buffer.from(value, "utf8");
  if (encoded.length <= GHIDRA_DIAGNOSTIC_STREAM_BYTES) {
    return { text: value.trim(), clipped: false };
  }
  return {
    text: encoded.subarray(encoded.length - GHIDRA_DIAGNOSTIC_STREAM_BYTES).toString("utf8").trim(),
    clipped: true,
  };
}

function failureDiagnostics(result: RunResult): string {
  const sections: string[] = [];
  for (const [name, value] of [["stdout", result.stdout], ["stderr", result.stderr]] as const) {
    if (value.length === 0) continue;
    const tail = diagnosticTail(value);
    const clipping = tail.clipped
      ? ` [diagnostic clipped to last ${GHIDRA_DIAGNOSTIC_STREAM_BYTES} bytes]`
      : "";
    sections.push(`${name}${clipping}:\n${tail.text}`);
  }
  return sections.length === 0 ? "" : `\n${sections.join("\n")}`;
}

export async function runGhidraInvocation(
  invocation: GhidraInvocation,
  config: ServerConfig,
): Promise<RunResult> {
  const result = await runProcess({
    executable: invocation.executable,
    args: invocation.args,
    cwd: invocation.cwd,
    timeoutMs: config.ghidraTimeoutMs ?? DEFAULT_GHIDRA_TIMEOUT_MS,
    maxOutputBytes: config.maxOutputBytes,
    terminateOnOutputLimit: true,
  });

  if (result.timedOut) {
    throw new NdsError(
      "ghidra-analysis-timeout",
      `${invocation.stage} exceeded the configured Ghidra timeout`,
    );
  }
  if (result.outputLimitExceeded) {
    throw new NdsError(
      "ghidra-output-limit",
      `${invocation.stage} exceeded RE_MCP_MAX_OUTPUT_BYTES`,
    );
  }
  if (result.exitCode !== 0 || result.signal !== null) {
    if (looksLikeProjectLock(result.stderr)) {
      throw new NdsError(
        "ghidra-project-locked",
        `${invocation.stage} could not obtain the Ghidra project write lock${failureDiagnostics(result)}`,
      );
    }
    throw new NdsError(
      isImportStage(invocation.stage)
        ? "ghidra-import-failed"
        : "ghidra-analysis-failed",
      `${invocation.stage} failed with exit code ${result.exitCode ?? "null"}${result.signal === null ? "" : ` and signal ${result.signal}`}${failureDiagnostics(result)}`,
    );
  }
  if (hasReportedScriptError(result)) {
    throw new NdsError(
      isImportStage(invocation.stage)
        ? "ghidra-import-failed"
        : "ghidra-analysis-failed",
      `${invocation.stage} reported a Ghidra script error despite exit code 0${failureDiagnostics(result)}`,
    );
  }
  if (isImportStage(invocation.stage) && hasReportedImportFailure(result)) {
    throw new NdsError(
      "ghidra-import-failed",
      `${invocation.stage} reported an import/save failure despite exit code 0${failureDiagnostics(result)}`,
    );
  }

  return result;
}
