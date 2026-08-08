import { readFile, stat } from "node:fs/promises";
import path from "node:path";

import type { ServerConfig } from "../../config.js";
import { NdsError } from "./errors.js";
import {
  ghidraGeneratedBridgeRoot,
  ghidraProjectName,
  ghidraProjectRoot,
  ghidraStateRoot,
} from "./ghidra-model.js";
import { hashFileSha256 } from "./io.js";
import type { NdsProcessor } from "./overlays.js";
import { readNdsRomMap, type NdsRomMap } from "./rom-map.js";

const PROCESSORS: readonly NdsProcessor[] = ["arm9", "arm7"];
const RUN_STATE_FORMAT = "re-mcp-nds-ghidra-run-state" as const;
const RUN_STATE_VERSION = 1 as const;

interface InspectionRunState {
  readonly sourceRomSha256: string;
  readonly manifestSha256: string;
  readonly ghidraVersion: string;
  readonly stage: string;
  readonly existingProcessors: readonly NdsProcessor[];
  readonly completedProcessors: readonly NdsProcessor[];
}

export interface TrustedGhidraInspectionState {
  readonly map: NdsRomMap;
  readonly projectRoot: string;
  readonly projectName: string;
  readonly bridgeRoot: string;
  readonly bridgeManifestPath: string;
  readonly manifestSha256: string;
  readonly ghidraVersion: string;
  readonly completedProcessors: readonly ["arm9", "arm7"];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Expected non-empty string field ${key}`);
  }
  return value;
}

function processorArray(value: unknown, key: string): readonly NdsProcessor[] {
  if (!Array.isArray(value)) {
    throw new Error(`Expected processor array field ${key}`);
  }
  const seen = new Set<NdsProcessor>();
  for (const item of value) {
    if (item !== "arm9" && item !== "arm7") {
      throw new Error(`Expected ${key} entries to be arm9 or arm7`);
    }
    seen.add(item);
  }
  return PROCESSORS.filter((processor) => seen.has(processor));
}

function parseRunState(value: unknown, label: string): InspectionRunState {
  if (!isRecord(value)) {
    throw new NdsError(
      "project-state-mismatch",
      `${label} is not a trusted Ghidra run-state object`,
    );
  }
  try {
    if (value.format !== RUN_STATE_FORMAT || value.formatVersion !== RUN_STATE_VERSION) {
      throw new Error("unsupported run-state format/version");
    }
    return {
      sourceRomSha256: requiredString(value, "sourceRomSha256"),
      manifestSha256: requiredString(value, "manifestSha256"),
      ghidraVersion: requiredString(value, "ghidraVersion"),
      stage: requiredString(value, "stage"),
      existingProcessors: processorArray(value.existingProcessors, "existingProcessors"),
      completedProcessors: processorArray(value.completedProcessors, "completedProcessors"),
    };
  } catch (error) {
    throw new NdsError(
      "project-state-mismatch",
      `Unable to trust ${label}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function readJsonIfExists(filePath: string): Promise<unknown | null> {
  try {
    return JSON.parse(await readFile(filePath, "utf8")) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    if (error instanceof SyntaxError) {
      throw new NdsError(
        "project-state-mismatch",
        `Unable to parse trusted Ghidra state ${path.basename(filePath)}: ${error.message}`,
      );
    }
    throw error;
  }
}

async function regularFileExists(filePath: string): Promise<boolean> {
  try {
    return (await stat(filePath)).isFile();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function directoryExists(directoryPath: string): Promise<boolean> {
  try {
    return (await stat(directoryPath)).isDirectory();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function hasBothProcessors(values: readonly NdsProcessor[]): boolean {
  const present = new Set(values);
  return PROCESSORS.every((processor) => present.has(processor));
}

function requireMatchingState(
  state: InspectionRunState,
  map: NdsRomMap,
  label: string,
): void {
  if (state.sourceRomSha256 !== map.sha256) {
    throw new NdsError(
      "project-state-mismatch",
      `${label} belongs to ROM SHA-256 ${state.sourceRomSha256}, not ${map.sha256}`,
    );
  }
  if (state.stage !== "complete") {
    throw new NdsError(
      "ghidra-project-not-current",
      `${label} is at stage ${state.stage}; run nds_ghidra_bootstrap before inspection`,
    );
  }
  if (!hasBothProcessors(state.existingProcessors) || !hasBothProcessors(state.completedProcessors)) {
    throw new NdsError(
      "ghidra-project-not-current",
      `${label} does not contain complete ARM9 and ARM7 processor state`,
    );
  }
}

export async function readTrustedGhidraInspectionState(
  romPath: string,
  config: ServerConfig,
): Promise<TrustedGhidraInspectionState> {
  const map = await readNdsRomMap(romPath);
  const workspaceRoot = config.workspaceRoot;
  const projectRoot = ghidraProjectRoot(map, workspaceRoot);
  const projectName = ghidraProjectName(map);
  const projectFile = path.join(projectRoot, `${projectName}.gpr`);
  const projectRepository = path.join(projectRoot, `${projectName}.rep`);
  const [hasProjectFile, hasProjectRepository] = await Promise.all([
    regularFileExists(projectFile),
    directoryExists(projectRepository),
  ]);
  if (!hasProjectFile || !hasProjectRepository) {
    throw new NdsError(
      "ghidra-project-not-current",
      "The SHA-scoped Ghidra project is missing or incomplete; run nds_ghidra_bootstrap before inspection",
    );
  }

  const stateRoot = ghidraStateRoot(map, workspaceRoot);
  const [rawRun, rawSuccess, rawFailure] = await Promise.all([
    readJsonIfExists(path.join(stateRoot, "latest-run.json")),
    readJsonIfExists(path.join(stateRoot, "latest-success.json")),
    readJsonIfExists(path.join(stateRoot, "latest-failure.json")),
  ]);
  if (rawFailure !== null) {
    throw new NdsError(
      "ghidra-project-not-current",
      "The latest Ghidra reconciliation recorded a failure; run nds_ghidra_bootstrap before inspection",
    );
  }
  if (rawRun === null || rawSuccess === null) {
    throw new NdsError(
      "ghidra-project-not-current",
      "The SHA-scoped Ghidra project lacks complete trusted run/success state; run nds_ghidra_bootstrap before inspection",
    );
  }

  const latestRun = parseRunState(rawRun, "latest-run.json");
  const latestSuccess = parseRunState(rawSuccess, "latest-success.json");
  requireMatchingState(latestRun, map, "latest-run.json");
  requireMatchingState(latestSuccess, map, "latest-success.json");

  if (
    latestRun.manifestSha256 !== latestSuccess.manifestSha256
    || latestRun.ghidraVersion !== latestSuccess.ghidraVersion
  ) {
    throw new NdsError(
      "ghidra-project-not-current",
      "The latest Ghidra run and trusted success do not describe the same project state",
    );
  }

  const bridgeRoot = ghidraGeneratedBridgeRoot(map, workspaceRoot);
  const bridgeManifestPath = path.join(bridgeRoot, "manifest.json");
  if (!(await regularFileExists(bridgeManifestPath))) {
    throw new NdsError(
      "ghidra-project-not-current",
      "The trusted Ghidra bridge manifest is missing; run nds_ghidra_bootstrap before inspection",
    );
  }
  const actualManifestSha256 = await hashFileSha256(bridgeManifestPath);
  if (actualManifestSha256 !== latestSuccess.manifestSha256) {
    throw new NdsError(
      "ghidra-project-not-current",
      "The generated Ghidra bridge manifest no longer matches the trusted project state",
    );
  }

  return {
    map,
    projectRoot,
    projectName,
    bridgeRoot,
    bridgeManifestPath,
    manifestSha256: latestSuccess.manifestSha256,
    ghidraVersion: latestSuccess.ghidraVersion,
    completedProcessors: ["arm9", "arm7"],
  };
}
