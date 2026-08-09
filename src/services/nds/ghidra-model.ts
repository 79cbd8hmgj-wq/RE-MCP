import path from "node:path";

import { resolveInside } from "../../security/paths.js";
import type {
  DiscoverNdsFunctionsResult,
  DiscoveredFunction,
  FunctionComponentCoverage,
  FunctionDiscoveryTruncationReason,
} from "./function-discovery.js";
import {
  compareFunctionCallEdge,
  compareFunctionProof,
  compareProvenFunctionIdentity,
  type ProvenFunctionCallEdge,
} from "./function-model.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

export const GHIDRA_BRIDGE_FORMAT = "re-mcp-nds-ghidra" as const;
export const GHIDRA_BRIDGE_FORMAT_VERSION = 2 as const;
export const GHIDRA_ARM9_LANGUAGE = "ARM:LE:32:v5t" as const;
export const GHIDRA_ARM7_LANGUAGE = "ARM:LE:32:v4t" as const;

export type GhidraLanguage =
  | typeof GHIDRA_ARM9_LANGUAGE
  | typeof GHIDRA_ARM7_LANGUAGE;

export interface GhidraBridgeArtifact {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface GhidraMainManifest {
  readonly artifactPath: string;
  readonly romOffset: number;
  readonly runtimeAddress: number;
  readonly entryAddress: number;
  readonly fileBackedSize: number;
}

// The legacy value remains in the type only while Task 9 migrates existing
// v1 project/result handling. The v2 manifest builder rejects it and never emits it.
export type GhidraOverlayImportStatus =
  | "importable"
  | "importable-derived"
  | "not-imported-compressed";

export type GhidraOverlayRepresentation =
  | "rom-file-backed"
  | "derived-blz";

export interface GhidraOverlayManifest {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly spaceName: string;
  readonly artifactPath: string;
  readonly fileId: number;
  readonly runtimeAddress: number;
  readonly ramSize: number;
  readonly bssSize: number;
  readonly representation: GhidraOverlayRepresentation;
  readonly initializedSize: number;
  readonly storedRomOffset: number;
  readonly storedSize: number;
  readonly compressedSize: number | null;
  readonly storedSha256: string;
  readonly runtimeSha256: string;
  readonly compressed: boolean;
  readonly importStatus: GhidraOverlayImportStatus;
}

export interface GhidraProcessorManifest {
  readonly processor: NdsProcessor;
  readonly language: GhidraLanguage;
  readonly programName: "RE-MCP_ARM9" | "RE-MCP_ARM7";
  readonly main: GhidraMainManifest;
  readonly overlays: readonly GhidraOverlayManifest[];
}

export interface GhidraDiscoveryManifest {
  readonly processor: NdsProcessor;
  readonly status: DiscoverNdsFunctionsResult["status"];
  readonly functions: readonly DiscoveredFunction[];
  readonly calls: readonly ProvenFunctionCallEdge[];
  readonly coverage: readonly FunctionComponentCoverage[];
  readonly truncationReasons: readonly FunctionDiscoveryTruncationReason[];
  readonly totals: DiscoverNdsFunctionsResult["totals"];
}

export interface GhidraBridgeManifest {
  readonly format: typeof GHIDRA_BRIDGE_FORMAT;
  readonly formatVersion: typeof GHIDRA_BRIDGE_FORMAT_VERSION;
  readonly sourceRomSha256: string;
  readonly sha256Prefix: string;
  readonly processors: readonly GhidraProcessorManifest[];
  readonly discovery: readonly GhidraDiscoveryManifest[];
  readonly artifacts: readonly GhidraBridgeArtifact[];
  readonly generatedResultPaths: Readonly<Record<NdsProcessor, string>>;
}

const PROCESSORS: readonly NdsProcessor[] = ["arm9", "arm7"];
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

function portable(relativePath: string): string {
  return relativePath.split(path.sep).join("/");
}

export function ghidraGeneratedBridgeRoot(
  map: NdsRomMap,
  workspaceRoot: string,
): string {
  return resolveInside(
    workspaceRoot,
    path.join(
      "analysis",
      "generated",
      "nds",
      map.sha256Prefix,
      "ghidra-bridge",
    ),
  );
}

export function ghidraPersistentRoot(
  map: NdsRomMap,
  workspaceRoot: string,
): string {
  return resolveInside(
    workspaceRoot,
    path.join("analysis", "ghidra", "nds", map.sha256),
  );
}

export function ghidraProjectRoot(
  map: NdsRomMap,
  workspaceRoot: string,
): string {
  return resolveInside(ghidraPersistentRoot(map, workspaceRoot), "project");
}

export function ghidraStateRoot(
  map: NdsRomMap,
  workspaceRoot: string,
): string {
  return resolveInside(ghidraPersistentRoot(map, workspaceRoot), "state");
}

export function ghidraProjectName(map: NdsRomMap): string {
  return `RE-MCP-${map.sha256}`;
}

export function ghidraProgramName(
  processor: NdsProcessor,
): "RE-MCP_ARM9" | "RE-MCP_ARM7" {
  return processor === "arm9" ? "RE-MCP_ARM9" : "RE-MCP_ARM7";
}

export function ghidraOverlaySpaceName(
  processor: NdsProcessor,
  overlayId: number,
): string {
  return `RE_MCP_${processor.toUpperCase()}_OVL_${overlayId}`;
}

export function ghidraStoredOverlayArtifactPath(
  processor: NdsProcessor,
  overlayId: number,
): string {
  return portable(path.join("..", "overlays", processor, `overlay_${overlayId}.bin`));
}

export function ghidraDerivedOverlayArtifactPath(
  processor: NdsProcessor,
  overlayId: number,
): string {
  return portable(path.join("..", "runtime", "overlays", processor, `overlay_${overlayId}.bin`));
}

function languageFor(processor: NdsProcessor): GhidraLanguage {
  return processor === "arm9"
    ? GHIDRA_ARM9_LANGUAGE
    : GHIDRA_ARM7_LANGUAGE;
}

function canonicalOverlays(map: NdsRomMap): readonly NdsOverlay[] {
  return [...map.overlays.arm9, ...map.overlays.arm7];
}

function overlayKey(processor: NdsProcessor, overlayId: number): string {
  return `${processor}:${overlayId}`;
}

function validateOverlayHash(value: string, label: string): void {
  if (!SHA256_PATTERN.test(value)) {
    throw new Error(`${label} must be a lowercase SHA-256 digest`);
  }
}

function validatePreparedOverlay(
  canonical: NdsOverlay,
  prepared: GhidraOverlayManifest,
): void {
  const expectedRepresentation: GhidraOverlayRepresentation = canonical.compressed
    ? "derived-blz"
    : "rom-file-backed";
  const expectedImportStatus: GhidraOverlayImportStatus = canonical.compressed
    ? "importable-derived"
    : "importable";
  const expectedInitializedSize = canonical.compressed
    ? canonical.ramSize
    : Math.min(canonical.ramSize, canonical.romSize);
  const expectedArtifactPath = canonical.compressed
    ? ghidraDerivedOverlayArtifactPath(canonical.processor, canonical.overlayId)
    : ghidraStoredOverlayArtifactPath(canonical.processor, canonical.overlayId);

  if (
    prepared.processor !== canonical.processor
    || prepared.overlayId !== canonical.overlayId
    || prepared.spaceName !== ghidraOverlaySpaceName(canonical.processor, canonical.overlayId)
    || prepared.artifactPath !== expectedArtifactPath
    || prepared.fileId !== canonical.fileId
    || prepared.runtimeAddress !== canonical.ramAddress
    || prepared.ramSize !== canonical.ramSize
    || prepared.bssSize !== canonical.bssSize
    || prepared.representation !== expectedRepresentation
    || prepared.initializedSize !== expectedInitializedSize
    || prepared.storedRomOffset !== canonical.romOffset
    || prepared.storedSize !== canonical.romSize
    || prepared.compressedSize !== (canonical.compressed ? canonical.compressedSize : null)
    || prepared.compressed !== canonical.compressed
    || prepared.importStatus !== expectedImportStatus
  ) {
    throw new Error(
      `Prepared Ghidra overlay metadata does not match canonical ${canonical.processor.toUpperCase()} overlay ${canonical.overlayId}`,
    );
  }
  if (prepared.initializedSize <= 0) {
    throw new Error(
      `Ghidra overlay ${canonical.processor}:${canonical.overlayId} has no initialized runtime bytes`,
    );
  }
  validateOverlayHash(prepared.storedSha256, "Stored overlay hash");
  validateOverlayHash(prepared.runtimeSha256, "Runtime overlay hash");
}

function canonicalPreparedOverlays(
  map: NdsRomMap,
  prepared: readonly GhidraOverlayManifest[] | undefined,
): readonly GhidraOverlayManifest[] {
  const canonical = canonicalOverlays(map);
  if (prepared === undefined) {
    if (canonical.length === 0) {
      return [];
    }
    throw new Error("Ghidra overlay manifests are required when canonical overlays are present");
  }

  const byKey = new Map<string, GhidraOverlayManifest>();
  for (const entry of prepared) {
    const key = overlayKey(entry.processor, entry.overlayId);
    if (byKey.has(key)) {
      throw new Error(`Duplicate prepared Ghidra overlay manifest: ${key}`);
    }
    byKey.set(key, entry);
  }

  if (byKey.size !== canonical.length) {
    throw new Error("Prepared Ghidra overlay count does not match the canonical ROM map");
  }

  const result: GhidraOverlayManifest[] = [];
  for (const overlay of canonical) {
    const entry = byKey.get(overlayKey(overlay.processor, overlay.overlayId));
    if (entry === undefined) {
      throw new Error(
        `Prepared Ghidra overlay is missing ${overlay.processor}:${overlay.overlayId}`,
      );
    }
    validatePreparedOverlay(overlay, entry);
    result.push(entry);
  }
  return result;
}

function processorManifest(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlays: readonly GhidraOverlayManifest[],
): GhidraProcessorManifest {
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  return {
    processor,
    language: languageFor(processor),
    programName: ghidraProgramName(processor),
    main: {
      artifactPath: portable(path.join("imports", ghidraProgramName(processor))),
      romOffset: executable.romOffset,
      runtimeAddress: executable.ramAddress,
      entryAddress: executable.entryAddress,
      fileBackedSize: executable.size,
    },
    overlays: overlays
      .filter((entry) => entry.processor === processor)
      .sort((left, right) => left.overlayId - right.overlayId),
  };
}

function canonicalFunction(entry: DiscoveredFunction): DiscoveredFunction {
  return {
    ...entry,
    evidence: [...entry.evidence].sort(compareFunctionProof),
    cfg: {
      ...entry.cfg,
      truncationReasons: [...entry.cfg.truncationReasons],
    },
  };
}

function compareCoverage(
  left: FunctionComponentCoverage,
  right: FunctionComponentCoverage,
): number {
  if (left.component !== right.component) {
    return left.component === "main" ? -1 : 1;
  }
  return (left.overlayId ?? -1) - (right.overlayId ?? -1);
}

function discoveryManifest(
  result: DiscoverNdsFunctionsResult,
): GhidraDiscoveryManifest {
  return {
    processor: result.processor,
    status: result.status,
    functions: [...result.functions]
      .sort((left, right) => compareProvenFunctionIdentity(left.entry, right.entry))
      .map(canonicalFunction),
    calls: [...result.calls].sort(compareFunctionCallEdge),
    coverage: [...result.coverage].sort(compareCoverage),
    truncationReasons: [...result.truncationReasons],
    totals: { ...result.totals },
  };
}

function compareArtifact(
  left: GhidraBridgeArtifact,
  right: GhidraBridgeArtifact,
): number {
  return left.path < right.path ? -1 : left.path > right.path ? 1 : 0;
}

export function buildGhidraBridgeManifest(input: {
  readonly map: NdsRomMap;
  readonly arm9: DiscoverNdsFunctionsResult;
  readonly arm7: DiscoverNdsFunctionsResult;
  readonly artifacts: readonly GhidraBridgeArtifact[];
  readonly overlays?: readonly GhidraOverlayManifest[];
}): GhidraBridgeManifest {
  if (input.arm9.processor !== "arm9" || input.arm7.processor !== "arm7") {
    throw new Error("Ghidra bridge discovery results must match ARM9 and ARM7 processors");
  }

  const overlays = canonicalPreparedOverlays(input.map, input.overlays);
  const discoveryByProcessor: Readonly<Record<NdsProcessor, DiscoverNdsFunctionsResult>> = {
    arm9: input.arm9,
    arm7: input.arm7,
  };

  return {
    format: GHIDRA_BRIDGE_FORMAT,
    formatVersion: GHIDRA_BRIDGE_FORMAT_VERSION,
    sourceRomSha256: input.map.sha256,
    sha256Prefix: input.map.sha256Prefix,
    processors: PROCESSORS.map((processor) => processorManifest(input.map, processor, overlays)),
    discovery: PROCESSORS.map((processor) =>
      discoveryManifest(discoveryByProcessor[processor])),
    artifacts: [...input.artifacts].sort(compareArtifact),
    generatedResultPaths: {
      arm9: "results/arm9.json",
      arm7: "results/arm7.json",
    },
  };
}
