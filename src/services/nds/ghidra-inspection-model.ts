import path from "node:path";

import { resolveInside } from "../../security/paths.js";
import type { NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

export const GHIDRA_INSPECTION_FORMAT = "re-mcp-nds-ghidra-inspection" as const;
export const GHIDRA_INSPECTION_FORMAT_VERSION = 1 as const;

const REQUEST_ID_PATTERN = /^[a-f0-9]{16}$/u;
const DEFAULT_PAGE_LIMIT = 100;
const MAX_PAGE_LIMIT = 1_000;
const MAX_PAGE_OFFSET = 100_000;
const DEFAULT_DECOMPILE_CHARACTERS = 20_000;
const MAX_DECOMPILE_CHARACTERS = 100_000;
const MAX_SYMBOL_QUERY_CHARACTERS = 128;

export type GhidraInspectionOperation =
  | "inspect-function"
  | "decompile-function"
  | "search-symbols"
  | "list-references"
  | "list-calls";

export type GhidraSymbolMatch = "exact" | "prefix" | "contains";
export type GhidraReferenceDirection = "from" | "to" | "both";
export type GhidraCallDirection = "callers" | "callees" | "both";

export interface GhidraCanonicalAddressIdentity {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  /** Null means use the current Ghidra program's default address space. */
  readonly addressSpace: string | null;
  readonly fileBacked: boolean;
  readonly bss: boolean;
  readonly compressed: boolean;
}

export interface GhidraInspectionRequest {
  readonly format: typeof GHIDRA_INSPECTION_FORMAT;
  readonly formatVersion: typeof GHIDRA_INSPECTION_FORMAT_VERSION;
  readonly requestId: string;
  readonly sourceRomSha256: string;
  readonly processor: NdsProcessor;
  readonly programName: "RE-MCP_ARM9" | "RE-MCP_ARM7";
  readonly operation: GhidraInspectionOperation;
  readonly selector: GhidraCanonicalAddressIdentity | null;
  readonly parameters: Readonly<Record<string, string | number | boolean>>;
}

export interface GhidraInspectionResultEnvelope {
  readonly format: typeof GHIDRA_INSPECTION_FORMAT;
  readonly formatVersion: typeof GHIDRA_INSPECTION_FORMAT_VERSION;
  readonly requestId: string;
  readonly sourceRomSha256: string;
  readonly processor: NdsProcessor;
  readonly programName: string;
  readonly operation: GhidraInspectionOperation;
  readonly payload: unknown;
}

export function validateInspectionRequestId(value: string): string {
  if (!REQUEST_ID_PATTERN.test(value)) {
    throw new Error("Ghidra inspection request id must be exactly 16 lowercase hexadecimal characters");
  }
  return value;
}

export function ghidraInspectionRoot(map: NdsRomMap, workspaceRoot: string): string {
  return resolveInside(
    workspaceRoot,
    path.join("analysis", "generated", "nds", map.sha256Prefix, "ghidra-inspection"),
  );
}

function inspectionArtifactPath(
  map: NdsRomMap,
  workspaceRoot: string,
  requestId: string,
  suffix: "request" | "result",
): string {
  const safeId = validateInspectionRequestId(requestId);
  const root = ghidraInspectionRoot(map, workspaceRoot);
  return resolveInside(root, `${safeId}.${suffix}.json`);
}

export function ghidraInspectionRequestPath(
  map: NdsRomMap,
  workspaceRoot: string,
  requestId: string,
): string {
  return inspectionArtifactPath(map, workspaceRoot, requestId, "request");
}

export function ghidraInspectionResultPath(
  map: NdsRomMap,
  workspaceRoot: string,
  requestId: string,
): string {
  return inspectionArtifactPath(map, workspaceRoot, requestId, "result");
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < minimum || resolved > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return resolved;
}

export function clampInspectionPage(
  limit: number | undefined,
  offset: number | undefined,
): { readonly limit: number; readonly offset: number } {
  return {
    limit: boundedInteger(limit, DEFAULT_PAGE_LIMIT, 1, MAX_PAGE_LIMIT, "limit"),
    offset: boundedInteger(offset, 0, 0, MAX_PAGE_OFFSET, "offset"),
  };
}

export function clampDecompilerCharacters(value: number | undefined): number {
  return boundedInteger(
    value,
    DEFAULT_DECOMPILE_CHARACTERS,
    1,
    MAX_DECOMPILE_CHARACTERS,
    "maxCharacters",
  );
}

export function validateSymbolQuery(value: string): string {
  const characterCount = [...value].length;
  if (characterCount < 1 || characterCount > MAX_SYMBOL_QUERY_CHARACTERS) {
    throw new Error(`symbol query must contain between 1 and ${MAX_SYMBOL_QUERY_CHARACTERS} Unicode characters`);
  }
  return value;
}

export function validateSymbolMatch(value: string | undefined): GhidraSymbolMatch {
  const resolved = value ?? "prefix";
  if (resolved !== "exact" && resolved !== "prefix" && resolved !== "contains") {
    throw new Error("symbol match must be exact, prefix, or contains");
  }
  return resolved;
}

export function validateReferenceDirection(value: string | undefined): GhidraReferenceDirection {
  const resolved = value ?? "both";
  if (resolved !== "from" && resolved !== "to" && resolved !== "both") {
    throw new Error("reference direction must be from, to, or both");
  }
  return resolved;
}

export function validateCallDirection(value: string | undefined): GhidraCallDirection {
  const resolved = value ?? "both";
  if (resolved !== "callers" && resolved !== "callees" && resolved !== "both") {
    throw new Error("call direction must be callers, callees, or both");
  }
  return resolved;
}
