import { access, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import type { ServerConfig } from "../../config.js";
import { NdsError } from "./errors.js";
import {
  generateNdsGhidraBridge,
  type GeneratedGhidraBridge,
} from "./ghidra-bridge.js";
import { validateGhidraInstallation } from "./ghidra-installation.js";
import {
  ghidraGeneratedBridgeRoot,
  ghidraProgramName,
  ghidraProjectName,
  ghidraProjectRoot,
  ghidraStateRoot,
} from "./ghidra-model.js";
import {
  buildGhidraImportInvocation,
  buildGhidraProcessInvocation,
  runGhidraInvocation,
  type GhidraInvocation,
} from "./ghidra-runner.js";
import { hashFileSha256 } from "./io.js";
import type { NdsProcessor } from "./overlays.js";
import { readNdsRomMap, type NdsRomMap } from "./rom-map.js";

const PROCESSORS: readonly NdsProcessor[] = ["arm9", "arm7"];
const RUN_STATE_FORMAT = "re-mcp-nds-ghidra-run-state" as const;
const RUN_STATE_VERSION = 1 as const;
const PROCESSOR_RESULT_FORMAT = "re-mcp-nds-ghidra-processor-result" as const;
const PROCESSOR_RESULT_VERSION = 1 as const;

export interface GhidraProcessorBootstrapResult {
  readonly processor: NdsProcessor;
  readonly programName: string;
  readonly language: string;
  readonly status: "imported" | "reconciled" | "already-current";
  readonly importedOverlays: number;
  readonly compressedOverlayIds: readonly number[];
  readonly provenEntries: number;
  readonly directCalls: number;
  readonly analysisStatus: "complete";
}

export interface NdsGhidraBootstrapResult {
  readonly sourceRomSha256: string;
  readonly projectPath: string;
  readonly ghidraVersion: string;
  readonly manifestSha256: string;
  readonly runKind: "initial" | "reconciled" | "already-current";
  readonly processors: readonly GhidraProcessorBootstrapResult[];
}

export interface GhidraProcessorStatus {
  readonly processor: NdsProcessor;
  readonly programName: string;
  readonly language: string;
  readonly analysisStatus: "complete";
  readonly importedOverlays: number;
  readonly compressedOverlayIds: readonly number[];
  readonly provenEntries: number;
  readonly directCalls: number;
}

export interface GhidraFailureSidecar {
  readonly format: typeof RUN_STATE_FORMAT;
  readonly formatVersion: typeof RUN_STATE_VERSION;
  readonly sourceRomSha256: string;
  readonly manifestSha256: string;
  readonly ghidraVersion: string;
  readonly failedProcessor: NdsProcessor | null;
  readonly completedProcessors: readonly NdsProcessor[];
  readonly existingProcessors: readonly NdsProcessor[];
  readonly category: string;
  readonly message: string;
}

export interface NdsGhidraStatusResult {
  readonly sourceRomSha256: string;
  readonly projectPath: string;
  readonly projectExists: boolean;
  readonly bridgeExists: boolean;
  readonly manifestSha256: string | null;
  readonly ghidraVersion: string | null;
  readonly processors: readonly GhidraProcessorStatus[];
  readonly lastFailure: GhidraFailureSidecar | null;
}

export interface GhidraProjectDependencies {
  readonly validateInstallation: typeof validateGhidraInstallation;
  readonly generateBridge: typeof generateNdsGhidraBridge;
  readonly runInvocation: typeof runGhidraInvocation;
}

interface ValidatedProcessorResult extends GhidraProcessorStatus {
  readonly format: typeof PROCESSOR_RESULT_FORMAT;
  readonly formatVersion: typeof PROCESSOR_RESULT_VERSION;
  readonly sourceRomSha256: string;
  readonly manifestSha256: string;
  readonly ghidraVersion: string;
}

interface GhidraRunState {
  readonly format: typeof RUN_STATE_FORMAT;
  readonly formatVersion: typeof RUN_STATE_VERSION;
  readonly sourceRomSha256: string;
  readonly manifestSha256: string;
  readonly ghidraVersion: string | null;
  readonly stage: string;
  readonly existingProcessors: readonly NdsProcessor[];
  readonly completedProcessors: readonly NdsProcessor[];
  readonly processors: readonly ValidatedProcessorResult[];
}

const DEFAULT_DEPS: GhidraProjectDependencies = {
  validateInstallation: validateGhidraInstallation,
  generateBridge: generateNdsGhidraBridge,
  runInvocation: runGhidraInvocation,
};

let temporaryStateCounter = 0;

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

function requiredNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`Expected non-negative integer field ${key}`);
  }
  return value;
}

function processorValue(value: unknown): NdsProcessor {
  if (value !== "arm9" && value !== "arm7") {
    throw new Error("Expected processor arm9 or arm7");
  }
  return value;
}

function processorArray(value: unknown): readonly NdsProcessor[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new Error("Expected processor array");
  }
  const seen = new Set<NdsProcessor>();
  const result: NdsProcessor[] = [];
  for (const item of value) {
    const processor = processorValue(item);
    if (!seen.has(processor)) {
      seen.add(processor);
      result.push(processor);
    }
  }
  return PROCESSORS.filter((processor) => seen.has(processor));
}

function numberArray(value: unknown): readonly number[] {
  if (!Array.isArray(value)) {
    throw new Error("Expected numeric array");
  }
  return value.map((item) => {
    if (typeof item !== "number" || !Number.isSafeInteger(item) || item < 0) {
      throw new Error("Expected non-negative integer array item");
    }
    return item;
  });
}

function regularFileExists(filePath: string): Promise<boolean> {
  return stat(filePath)
    .then((info) => info.isFile())
    .catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    });
}

function directoryExists(directoryPath: string): Promise<boolean> {
  return stat(directoryPath)
    .then((info) => info.isDirectory())
    .catch((error: unknown) => {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    });
}

function projectMarkers(map: NdsRomMap, workspaceRoot: string) {
  const projectRoot = ghidraProjectRoot(map, workspaceRoot);
  const projectName = ghidraProjectName(map);
  return {
    projectRoot,
    gpr: path.join(projectRoot, `${projectName}.gpr`),
    rep: path.join(projectRoot, `${projectName}.rep`),
  };
}

async function inspectProject(map: NdsRomMap, workspaceRoot: string): Promise<{
  readonly exists: boolean;
  readonly partial: boolean;
}> {
  const markers = projectMarkers(map, workspaceRoot);
  const [gpr, rep] = await Promise.all([
    regularFileExists(markers.gpr),
    directoryExists(markers.rep),
  ]);
  return { exists: gpr && rep, partial: gpr !== rep };
}

async function readJsonIfExists(filePath: string): Promise<unknown | null> {
  try {
    return JSON.parse(await readFile(filePath, "utf8")) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
}

async function writeJsonAtomic(directory: string, name: string, value: unknown): Promise<void> {
  await mkdir(directory, { recursive: true });
  temporaryStateCounter += 1;
  const destination = path.join(directory, name);
  const temporary = path.join(
    directory,
    `.${name}.${process.pid}.${temporaryStateCounter}.tmp`,
  );
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    await rename(temporary, destination);
  } catch (error) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

function parseProcessorResult(value: unknown): ValidatedProcessorResult {
  if (!isRecord(value)) throw new Error("Processor result is not an object");
  if (value.format !== PROCESSOR_RESULT_FORMAT || value.formatVersion !== PROCESSOR_RESULT_VERSION) {
    throw new Error("Processor result format/version is unsupported");
  }
  const analysisStatus = requiredString(value, "analysisStatus");
  if (analysisStatus !== "complete") {
    throw new Error("Processor result does not report complete analysis");
  }
  return {
    format: PROCESSOR_RESULT_FORMAT,
    formatVersion: PROCESSOR_RESULT_VERSION,
    sourceRomSha256: requiredString(value, "sourceRomSha256"),
    manifestSha256: requiredString(value, "manifestSha256"),
    processor: processorValue(value.processor),
    programName: requiredString(value, "programName"),
    language: requiredString(value, "language"),
    analysisStatus: "complete",
    ghidraVersion: requiredString(value, "ghidraVersion"),
    importedOverlays: requiredNumber(value, "importedOverlays"),
    compressedOverlayIds: numberArray(value.compressedOverlayIds),
    provenEntries: requiredNumber(value, "provenEntries"),
    directCalls: requiredNumber(value, "directCalls"),
  };
}

function parseRunState(value: unknown): GhidraRunState {
  if (!isRecord(value)) throw new Error("Ghidra run state is not an object");
  if (value.format !== RUN_STATE_FORMAT || value.formatVersion !== RUN_STATE_VERSION) {
    throw new Error("Ghidra run state format/version is unsupported");
  }
  const completedProcessors = processorArray(value.completedProcessors);
  const existingProcessors = value.existingProcessors === undefined
    ? completedProcessors
    : processorArray(value.existingProcessors);
  const rawProcessors = value.processors;
  const processors = Array.isArray(rawProcessors)
    ? rawProcessors.map(parseProcessorResult)
    : [];
  return {
    format: RUN_STATE_FORMAT,
    formatVersion: RUN_STATE_VERSION,
    sourceRomSha256: requiredString(value, "sourceRomSha256"),
    manifestSha256: requiredString(value, "manifestSha256"),
    ghidraVersion: typeof value.ghidraVersion === "string" ? value.ghidraVersion : null,
    stage: typeof value.stage === "string" ? value.stage : "unknown",
    existingProcessors,
    completedProcessors,
    processors,
  };
}

function parseFailure(value: unknown): GhidraFailureSidecar {
  if (!isRecord(value)) throw new Error("Ghidra failure state is not an object");
  if (value.format !== RUN_STATE_FORMAT || value.formatVersion !== RUN_STATE_VERSION) {
    throw new Error("Ghidra failure state format/version is unsupported");
  }
  return {
    format: RUN_STATE_FORMAT,
    formatVersion: RUN_STATE_VERSION,
    sourceRomSha256: requiredString(value, "sourceRomSha256"),
    manifestSha256: requiredString(value, "manifestSha256"),
    ghidraVersion: requiredString(value, "ghidraVersion"),
    failedProcessor: value.failedProcessor === null
      ? null
      : processorValue(value.failedProcessor),
    completedProcessors: processorArray(value.completedProcessors),
    existingProcessors: processorArray(value.existingProcessors),
    category: requiredString(value, "category"),
    message: requiredString(value, "message"),
  };
}

async function readStateFile(
  stateRoot: string,
  name: string,
): Promise<GhidraRunState | null> {
  const value = await readJsonIfExists(path.join(stateRoot, name));
  if (value === null) return null;
  try {
    return parseRunState(value);
  } catch (error) {
    throw new NdsError(
      "project-state-mismatch",
      `Unable to trust ${name}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function validateStateIdentity(
  state: GhidraRunState | null,
  map: NdsRomMap,
  label: string,
): void {
  if (state !== null && state.sourceRomSha256 !== map.sha256) {
    throw new NdsError(
      "project-state-mismatch",
      `${label} belongs to ROM SHA-256 ${state.sourceRomSha256}, not ${map.sha256}`,
    );
  }
}

function hasAllProcessors(processors: readonly NdsProcessor[]): boolean {
  const values = new Set(processors);
  return PROCESSORS.every((processor) => values.has(processor));
}

async function assertRomUnchanged(map: NdsRomMap): Promise<void> {
  const current = await hashFileSha256(map.romPath);
  if (current !== map.sha256) {
    throw new NdsError(
      "invalid-rom",
      "Source ROM changed during the Ghidra bootstrap operation",
    );
  }
}

function processorManifest(bridge: GeneratedGhidraBridge, processor: NdsProcessor) {
  const value = bridge.manifest.processors.find((entry) => entry.processor === processor);
  if (value === undefined) {
    throw new NdsError(
      "bridge-generation-failed",
      `Ghidra bridge is missing ${processor.toUpperCase()} processor metadata`,
    );
  }
  return value;
}

function processorDiscovery(bridge: GeneratedGhidraBridge, processor: NdsProcessor) {
  const value = bridge.manifest.discovery.find((entry) => entry.processor === processor);
  if (value === undefined) {
    throw new NdsError(
      "bridge-generation-failed",
      `Ghidra bridge is missing ${processor.toUpperCase()} discovery metadata`,
    );
  }
  return value;
}

async function validateProcessorResult(
  bridge: GeneratedGhidraBridge,
  processor: NdsProcessor,
  ghidraVersion: string,
): Promise<ValidatedProcessorResult> {
  const resultPath = path.join(
    bridge.bridgeRoot,
    bridge.manifest.generatedResultPaths[processor],
  );
  let parsed: ValidatedProcessorResult;
  try {
    parsed = parseProcessorResult(
      JSON.parse(await readFile(resultPath, "utf8")) as unknown,
    );
  } catch (error) {
    throw new NdsError(
      "ghidra-analysis-failed",
      `${processor.toUpperCase()} did not produce a valid RE-MCP analysis result: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const manifest = processorManifest(bridge, processor);
  const discovery = processorDiscovery(bridge, processor);
  const expectedCompressed = manifest.overlays
    .filter((entry) => entry.importStatus === "not-imported-compressed")
    .map((entry) => entry.overlayId);
  const expectedImported = manifest.overlays
    .filter((entry) => entry.importStatus === "importable")
    .length;

  if (
    parsed.sourceRomSha256 !== bridge.manifest.sourceRomSha256
    || parsed.manifestSha256 !== bridge.manifestSha256
    || parsed.processor !== processor
    || parsed.programName !== manifest.programName
    || parsed.language !== manifest.language
    || parsed.ghidraVersion !== ghidraVersion
    || parsed.importedOverlays !== expectedImported
    || parsed.provenEntries !== discovery.functions.length
    || parsed.directCalls !== discovery.calls.length
    || JSON.stringify(parsed.compressedOverlayIds) !== JSON.stringify(expectedCompressed)
  ) {
    throw new NdsError(
      "ghidra-analysis-failed",
      `${processor.toUpperCase()} RE-MCP analysis result does not match the canonical bridge`,
    );
  }
  return parsed;
}

function invocationFor(
  existing: boolean,
  input: {
    readonly installation: Awaited<ReturnType<typeof validateGhidraInstallation>>;
    readonly map: NdsRomMap;
    readonly bridge: GeneratedGhidraBridge;
    readonly processor: NdsProcessor;
    readonly workspaceRoot: string;
  },
): GhidraInvocation {
  return existing
    ? buildGhidraProcessInvocation(input)
    : buildGhidraImportInvocation(input);
}

function runState(input: {
  readonly map: NdsRomMap;
  readonly bridge: GeneratedGhidraBridge;
  readonly ghidraVersion: string;
  readonly stage: string;
  readonly existingProcessors: ReadonlySet<NdsProcessor>;
  readonly completedProcessors: ReadonlySet<NdsProcessor>;
  readonly processors: readonly ValidatedProcessorResult[];
}): GhidraRunState {
  return {
    format: RUN_STATE_FORMAT,
    formatVersion: RUN_STATE_VERSION,
    sourceRomSha256: input.map.sha256,
    manifestSha256: input.bridge.manifestSha256,
    ghidraVersion: input.ghidraVersion,
    stage: input.stage,
    existingProcessors: PROCESSORS.filter((processor) => input.existingProcessors.has(processor)),
    completedProcessors: PROCESSORS.filter((processor) => input.completedProcessors.has(processor)),
    processors: input.processors,
  };
}

function failureCategory(error: unknown): string {
  return error instanceof NdsError ? String(error.category) : "ghidra-analysis-failed";
}

function failureMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function bootstrapNdsGhidraProject(
  romPath: string,
  config: ServerConfig,
  dependencies: GhidraProjectDependencies = DEFAULT_DEPS,
): Promise<NdsGhidraBootstrapResult> {
  const map = await readNdsRomMap(romPath);
  const workspaceRoot = config.workspaceRoot;
  const stateRoot = ghidraStateRoot(map, workspaceRoot);
  const project = await inspectProject(map, workspaceRoot);
  if (project.partial) {
    throw new NdsError(
      "project-state-mismatch",
      "Ghidra project has only one of its .gpr/.rep markers; RE-MCP will not repair it destructively",
    );
  }

  const [priorRun, priorSuccess] = await Promise.all([
    readStateFile(stateRoot, "latest-run.json"),
    readStateFile(stateRoot, "latest-success.json"),
  ]);
  validateStateIdentity(priorRun, map, "latest-run.json");
  validateStateIdentity(priorSuccess, map, "latest-success.json");
  const priorState = priorRun ?? priorSuccess;
  const priorExisting = new Set<NdsProcessor>(priorState?.existingProcessors ?? []);

  if (project.exists && priorState === null) {
    throw new NdsError(
      "project-state-mismatch",
      "Existing Ghidra project has no matching RE-MCP state metadata",
    );
  }
  if (project.exists && priorExisting.size === 0) {
    throw new NdsError(
      "project-state-mismatch",
      "Existing Ghidra project is not associated with any RE-MCP-owned processor program",
    );
  }
  if (!project.exists && priorExisting.size > 0) {
    throw new NdsError(
      "project-state-mismatch",
      "RE-MCP state claims processor programs exist but the SHA-scoped Ghidra project is missing",
    );
  }

  const installation = await dependencies.validateInstallation(config);
  const bridge = await dependencies.generateBridge(map, workspaceRoot);
  if (bridge.manifest.sourceRomSha256 !== map.sha256) {
    throw new NdsError(
      "bridge-generation-failed",
      "Generated Ghidra bridge does not belong to the requested ROM SHA-256",
    );
  }
  await assertRomUnchanged(map);

  const alreadyCurrent = project.exists
    && priorSuccess !== null
    && priorSuccess.manifestSha256 === bridge.manifestSha256
    && hasAllProcessors(priorSuccess.completedProcessors);
  const runKind: NdsGhidraBootstrapResult["runKind"] = priorExisting.size === 0
    ? "initial"
    : alreadyCurrent
      ? "already-current"
      : "reconciled";

  const existingProcessors = new Set<NdsProcessor>(priorExisting);
  const completedProcessors = new Set<NdsProcessor>();
  const processorResults: ValidatedProcessorResult[] = [];
  let activeProcessor: NdsProcessor | null = null;
  let stateStarted = false;

  await writeJsonAtomic(
    stateRoot,
    "latest-run.json",
    runState({
      map,
      bridge,
      ghidraVersion: installation.version,
      stage: "starting",
      existingProcessors,
      completedProcessors,
      processors: processorResults,
    }),
  );
  stateStarted = true;

  try {
    const responseProcessors: GhidraProcessorBootstrapResult[] = [];
    for (const processor of PROCESSORS) {
      activeProcessor = processor;
      await assertRomUnchanged(map);
      const existedBefore = existingProcessors.has(processor);
      const invocation = invocationFor(existedBefore, {
        installation,
        map,
        bridge,
        processor,
        workspaceRoot,
      });
      const resultPath = path.join(
        bridge.bridgeRoot,
        bridge.manifest.generatedResultPaths[processor],
      );
      await rm(resultPath, { force: true });
      await dependencies.runInvocation(invocation, config);
      const validated = await validateProcessorResult(
        bridge,
        processor,
        installation.version,
      );
      const projectAfter = await inspectProject(map, workspaceRoot);
      if (!projectAfter.exists) {
        throw new NdsError(
          existedBefore ? "project-state-mismatch" : "ghidra-import-failed",
          `${processor.toUpperCase()} completed without a complete SHA-scoped Ghidra project marker`,
        );
      }

      existingProcessors.add(processor);
      completedProcessors.add(processor);
      processorResults.push(validated);
      const status: GhidraProcessorBootstrapResult["status"] = !existedBefore
        ? "imported"
        : runKind === "already-current"
          ? "already-current"
          : "reconciled";
      responseProcessors.push({
        processor,
        programName: validated.programName,
        language: validated.language,
        status,
        importedOverlays: validated.importedOverlays,
        compressedOverlayIds: validated.compressedOverlayIds,
        provenEntries: validated.provenEntries,
        directCalls: validated.directCalls,
        analysisStatus: "complete",
      });

      await writeJsonAtomic(
        stateRoot,
        "latest-run.json",
        runState({
          map,
          bridge,
          ghidraVersion: installation.version,
          stage: `${processor}-complete`,
          existingProcessors,
          completedProcessors,
          processors: processorResults,
        }),
      );
    }

    activeProcessor = null;
    await assertRomUnchanged(map);
    const success = runState({
      map,
      bridge,
      ghidraVersion: installation.version,
      stage: "complete",
      existingProcessors,
      completedProcessors,
      processors: processorResults,
    });
    await writeJsonAtomic(stateRoot, "latest-run.json", success);
    await writeJsonAtomic(stateRoot, "latest-success.json", success);
    await rm(path.join(stateRoot, "latest-failure.json"), { force: true });

    return {
      sourceRomSha256: map.sha256,
      projectPath: path.relative(workspaceRoot, ghidraProjectRoot(map, workspaceRoot)),
      ghidraVersion: installation.version,
      manifestSha256: bridge.manifestSha256,
      runKind,
      processors: responseProcessors,
    };
  } catch (error) {
    if (stateStarted) {
      const failure: GhidraFailureSidecar = {
        format: RUN_STATE_FORMAT,
        formatVersion: RUN_STATE_VERSION,
        sourceRomSha256: map.sha256,
        manifestSha256: bridge.manifestSha256,
        ghidraVersion: installation.version,
        failedProcessor: activeProcessor,
        completedProcessors: PROCESSORS.filter((processor) => completedProcessors.has(processor)),
        existingProcessors: PROCESSORS.filter((processor) => existingProcessors.has(processor)),
        category: failureCategory(error),
        message: failureMessage(error),
      };
      await writeJsonAtomic(stateRoot, "latest-failure.json", failure).catch(() => undefined);
    }
    throw error;
  }
}

function statusProcessors(state: GhidraRunState | null): readonly GhidraProcessorStatus[] {
  if (state === null) return [];
  return state.processors.map((processor) => ({
    processor: processor.processor,
    programName: processor.programName,
    language: processor.language,
    analysisStatus: processor.analysisStatus,
    importedOverlays: processor.importedOverlays,
    compressedOverlayIds: processor.compressedOverlayIds,
    provenEntries: processor.provenEntries,
    directCalls: processor.directCalls,
  }));
}

export async function readNdsGhidraStatus(
  romPath: string,
  config: ServerConfig,
): Promise<NdsGhidraStatusResult> {
  const map = await readNdsRomMap(romPath);
  const workspaceRoot = config.workspaceRoot;
  const stateRoot = ghidraStateRoot(map, workspaceRoot);
  const project = await inspectProject(map, workspaceRoot);
  const bridgeManifestPath = path.join(
    ghidraGeneratedBridgeRoot(map, workspaceRoot),
    "manifest.json",
  );
  const bridgeExists = await regularFileExists(bridgeManifestPath);

  const [latestRun, latestSuccess, rawFailure] = await Promise.all([
    readStateFile(stateRoot, "latest-run.json"),
    readStateFile(stateRoot, "latest-success.json"),
    readJsonIfExists(path.join(stateRoot, "latest-failure.json")),
  ]);
  validateStateIdentity(latestRun, map, "latest-run.json");
  validateStateIdentity(latestSuccess, map, "latest-success.json");
  const state = latestRun ?? latestSuccess;

  let lastFailure: GhidraFailureSidecar | null = null;
  if (rawFailure !== null) {
    try {
      lastFailure = parseFailure(rawFailure);
      if (lastFailure.sourceRomSha256 !== map.sha256) {
        throw new Error("failure sidecar belongs to another ROM SHA-256");
      }
    } catch (error) {
      throw new NdsError(
        "project-state-mismatch",
        `Unable to trust latest-failure.json: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  let manifestSha256 = state?.manifestSha256 ?? null;
  if (manifestSha256 === null && bridgeExists) {
    manifestSha256 = await hashFileSha256(bridgeManifestPath);
  }

  return {
    sourceRomSha256: map.sha256,
    projectPath: path.relative(workspaceRoot, ghidraProjectRoot(map, workspaceRoot)),
    projectExists: project.exists,
    bridgeExists,
    manifestSha256,
    ghidraVersion: state?.ghidraVersion ?? null,
    processors: statusProcessors(state),
    lastFailure,
  };
}
