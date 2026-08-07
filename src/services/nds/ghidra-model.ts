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
export const GHIDRA_BRIDGE_FORMAT_VERSION = 1 as const;
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

export type GhidraOverlayImportStatus =
  | "importable"
  | "not-imported-compressed";

export interface GhidraOverlayManifest {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly spaceName: string;
  readonly artifactPath: string;
  readonly fileId: number;
  readonly romOffset: number;
  readonly runtimeAddress: number;
  readonly ramSize: number;
  readonly fileBackedSize: number;
  readonly bssSize: number;
  readonly compressed: boolean;
  readonly compressedSize: number | null;
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

function languageFor(processor: NdsProcessor): GhidraLanguage {
  return processor === "arm9"
    ? GHIDRA_ARM9_LANGUAGE
    : GHIDRA_ARM7_LANGUAGE;
}

function overlayArtifactPath(overlay: NdsOverlay): string {
  return portable(
    path.join(
      "..",
      "overlays",
      overlay.processor,
      `overlay_${overlay.overlayId}.bin`,
    ),
  );
}

function overlayManifest(overlay: NdsOverlay): GhidraOverlayManifest {
  return {
    processor: overlay.processor,
    overlayId: overlay.overlayId,
    spaceName: ghidraOverlaySpaceName(overlay.processor, overlay.overlayId),
    artifactPath: overlayArtifactPath(overlay),
    fileId: overlay.fileId,
    romOffset: overlay.romOffset,
    runtimeAddress: overlay.ramAddress,
    ramSize: overlay.ramSize,
    fileBackedSize: overlay.romSize,
    bssSize: overlay.bssSize,
    compressed: overlay.compressed,
    compressedSize: overlay.compressed ? overlay.compressedSize : null,
    importStatus: overlay.compressed
      ? "not-imported-compressed"
      : "importable",
  };
}

function processorManifest(
  map: NdsRomMap,
  processor: NdsProcessor,
): GhidraProcessorManifest {
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
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
    overlays: [...overlays]
      .sort((left, right) => left.overlayId - right.overlayId)
      .map(overlayManifest),
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
}): GhidraBridgeManifest {
  if (input.arm9.processor !== "arm9" || input.arm7.processor !== "arm7") {
    throw new Error("Ghidra bridge discovery results must match ARM9 and ARM7 processors");
  }

  const discoveryByProcessor: Readonly<Record<NdsProcessor, DiscoverNdsFunctionsResult>> = {
    arm9: input.arm9,
    arm7: input.arm7,
  };

  return {
    format: GHIDRA_BRIDGE_FORMAT,
    formatVersion: GHIDRA_BRIDGE_FORMAT_VERSION,
    sourceRomSha256: input.map.sha256,
    sha256Prefix: input.map.sha256Prefix,
    processors: PROCESSORS.map((processor) => processorManifest(input.map, processor)),
    discovery: PROCESSORS.map((processor) =>
      discoveryManifest(discoveryByProcessor[processor])),
    artifacts: [...input.artifacts].sort(compareArtifact),
    generatedResultPaths: {
      arm9: "results/arm9.json",
      arm7: "results/arm7.json",
    },
  };
}
