import { randomBytes as nodeRandomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import type { ServerConfig } from "../../config.js";
import { NdsError } from "./errors.js";
import {
  validateGhidraInstallation,
  type ValidatedGhidraInstallation,
} from "./ghidra-installation.js";
import {
  GHIDRA_INSPECTION_FORMAT,
  GHIDRA_INSPECTION_FORMAT_VERSION,
  clampDecompilerCharacters,
  clampInspectionPage,
  ghidraInspectionRequestPath,
  ghidraInspectionResultPath,
  ghidraInspectionRoot,
  validateCallDirection,
  validateReferenceDirection,
  validateSymbolMatch,
  validateSymbolQuery,
  type GhidraCallDirection,
  type GhidraCanonicalAddressIdentity,
  type GhidraInspectionOperation,
  type GhidraInspectionRequest,
  type GhidraReferenceDirection,
  type GhidraSymbolMatch,
} from "./ghidra-inspection-model.js";
import {
  readTrustedGhidraInspectionState,
  type TrustedGhidraInspectionState,
} from "./ghidra-inspection-readiness.js";
import { ghidraOverlaySpaceName, ghidraProgramName } from "./ghidra-model.js";
import {
  buildGhidraInspectionInvocation,
  runGhidraInvocation,
  type GhidraInvocation,
} from "./ghidra-runner.js";
import { hashFileSha256 } from "./io.js";
import type { NdsProcessor } from "./overlays.js";
import {
  resolveRuntimeAddress,
  type RuntimeCandidate,
} from "./resolver.js";
import type { NdsRomMap } from "./rom-map.js";
import type { RunResult } from "../process-runner.js";

const UINT32_MAX = 0xffffffff;
const UINT32_END = 0x1_0000_0000;
const MAX_FUNCTION_BODY_RANGES = 256;

export interface GhidraAddressSelector {
  readonly processor: NdsProcessor;
  readonly runtimeAddress: number;
  readonly overlayId?: number;
}

export type GhidraInspectionAddressOperation =
  | "inspect-function"
  | "decompile-function"
  | "list-references"
  | "list-calls";

export interface GhidraInspectionDependencies {
  readonly readTrustedState: (
    romPath: string,
    config: ServerConfig,
  ) => Promise<TrustedGhidraInspectionState>;
  readonly validateInstallation: (
    config: ServerConfig,
  ) => Promise<ValidatedGhidraInstallation>;
  readonly runInvocation: (
    invocation: GhidraInvocation,
    config: ServerConfig,
  ) => Promise<RunResult>;
  readonly randomBytes: (size: number) => Buffer;
}

export interface GhidraInspectionAuthorityResult {
  readonly canonical: Readonly<Record<string, unknown>>;
  readonly reMcpEvidence: Readonly<Record<string, string | null>> | null;
  readonly ghidraDerived: Readonly<Record<string, unknown>>;
}

const DEFAULT_DEPENDENCIES: GhidraInspectionDependencies = {
  readTrustedState: readTrustedGhidraInspectionState,
  validateInstallation: validateGhidraInstallation,
  runInvocation: runGhidraInvocation,
  randomBytes: nodeRandomBytes,
};

function inspectionError(message: string): NdsError<"ghidra-inspection-result-invalid"> {
  return new NdsError("ghidra-inspection-result-invalid", message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw inspectionError(`${label} must be a JSON object`);
  }
  return value;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") {
    throw inspectionError(`Ghidra inspection result field ${key} must be a string`);
  }
  return value;
}

function requireBoolean(record: Record<string, unknown>, key: string): boolean {
  const value = record[key];
  if (typeof value !== "boolean") {
    throw inspectionError(`Ghidra inspection result field ${key} must be a boolean`);
  }
  return value;
}

function requireBoundedInteger(
  record: Record<string, unknown>,
  key: string,
  minimum: number,
  maximum: number,
): number {
  const value = record[key];
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw inspectionError(
      `Ghidra inspection result field ${key} must be an integer between ${minimum} and ${maximum}`,
    );
  }
  return value as number;
}

function nullableString(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string") {
    throw inspectionError(`${label} must be a string or null`);
  }
  return value;
}

function validateAddress(value: unknown, label: string): Readonly<Record<string, unknown>> {
  const address = requireRecord(value, label);
  const space = requireString(address, "space");
  if (space.length === 0) {
    throw inspectionError(`${label}.space must not be empty`);
  }
  const offset = requireBoundedInteger(address, "offset", 0, UINT32_MAX);
  return { space, offset };
}

function validateEvidence(value: unknown): Readonly<Record<string, string | null>> {
  const evidence = requireRecord(value, "reMcpEvidence");
  return {
    functionId: nullableString(evidence.functionId, "reMcpEvidence.functionId"),
    functionProof: nullableString(evidence.functionProof, "reMcpEvidence.functionProof"),
    functionMode: nullableString(evidence.functionMode, "reMcpEvidence.functionMode"),
    overlayId: nullableString(evidence.overlayId, "reMcpEvidence.overlayId"),
  };
}

function validateFunctionPayload(
  value: unknown,
): { readonly payload: Record<string, unknown>; readonly evidence: Readonly<Record<string, string | null>> | null } {
  const payload = requireRecord(value, "function inspection payload");
  const found = requireBoolean(payload, "found");
  if (!found) {
    return { payload: { found: false }, evidence: null };
  }

  const entry = validateAddress(payload.entry, "function entry");
  const name = requireString(payload, "name");
  const namespace = requireString(payload, "namespace");
  const signature = requireString(payload, "signature");
  const callingConvention = requireString(payload, "callingConvention");
  const thunk = requireBoolean(payload, "thunk");
  const external = requireBoolean(payload, "external");
  const varArgs = requireBoolean(payload, "varArgs");
  if (!Array.isArray(payload.bodyRanges) || payload.bodyRanges.length > MAX_FUNCTION_BODY_RANGES) {
    throw inspectionError(`function bodyRanges must contain at most ${MAX_FUNCTION_BODY_RANGES} ranges`);
  }
  const bodyRanges = payload.bodyRanges.map((range, index) => {
    const record = requireRecord(range, `function body range ${index}`);
    const space = requireString(record, "space");
    const start = requireBoundedInteger(record, "start", 0, UINT32_MAX);
    const endExclusive = requireBoundedInteger(record, "endExclusive", 0, UINT32_END);
    if (endExclusive <= start) {
      throw inspectionError(`function body range ${index} must have endExclusive > start`);
    }
    return { space, start, endExclusive };
  });
  const bodyRangesTruncated = requireBoolean(payload, "bodyRangesTruncated");

  let entrySymbol: Record<string, unknown> | null = null;
  if (payload.entrySymbol !== null) {
    const symbol = requireRecord(payload.entrySymbol, "entrySymbol");
    entrySymbol = {
      name: requireString(symbol, "name"),
      source: requireString(symbol, "source"),
      primary: requireBoolean(symbol, "primary"),
      dynamic: requireBoolean(symbol, "dynamic"),
    };
  }

  const evidence = validateEvidence(payload.reMcpEvidence);
  return {
    payload: {
      found: true,
      entry,
      name,
      namespace,
      signature,
      callingConvention,
      thunk,
      external,
      varArgs,
      bodyRanges,
      bodyRangesTruncated,
      entrySymbol,
    },
    evidence,
  };
}

function validateDecompilePayload(
  value: unknown,
  maxCharacters: number,
): { readonly payload: Record<string, unknown>; readonly evidence: Readonly<Record<string, string | null>> | null } {
  const raw = requireRecord(value, "decompile payload");
  const found = requireBoolean(raw, "found");
  if (!found) {
    const completed = requireBoolean(raw, "completed");
    const truncated = requireBoolean(raw, "truncated");
    const c = requireString(raw, "c");
    const error = requireString(raw, "error");
    if (c.length > maxCharacters) {
      throw inspectionError("decompiler output exceeds the requested maxCharacters");
    }
    return { payload: { found, completed, truncated, c, error }, evidence: null };
  }

  const functionResult = validateFunctionPayload(raw);
  const completed = requireBoolean(raw, "completed");
  const truncated = requireBoolean(raw, "truncated");
  const c = requireString(raw, "c");
  const error = requireString(raw, "error");
  if (c.length > maxCharacters) {
    throw inspectionError("decompiler output exceeds the requested maxCharacters");
  }
  return {
    payload: {
      ...functionResult.payload,
      completed,
      truncated,
      c,
      error,
    },
    evidence: functionResult.evidence,
  };
}

function validatePagedPayload(
  value: unknown,
  arrayName: "results" | "edges",
  requestedLimit: number,
): Record<string, unknown> {
  const payload = requireRecord(value, `${arrayName} payload`);
  const totalMatches = requireBoundedInteger(payload, "totalMatches", 0, Number.MAX_SAFE_INTEGER);
  const returned = requireBoundedInteger(payload, "returned", 0, requestedLimit);
  const offset = requireBoundedInteger(payload, "offset", 0, 100_000);
  const limit = requireBoundedInteger(payload, "limit", 1, 1_000);
  const truncated = requireBoolean(payload, "truncated");
  const items = payload[arrayName];
  if (!Array.isArray(items) || items.length !== returned || items.length > requestedLimit) {
    throw inspectionError(`${arrayName} must contain exactly returned items within the requested limit`);
  }
  for (const [index, item] of items.entries()) {
    requireRecord(item, `${arrayName}[${index}]`);
  }
  return { totalMatches, returned, offset, limit, truncated, [arrayName]: items };
}

function validateEnvelope(
  value: unknown,
  request: GhidraInspectionRequest,
): Record<string, unknown> {
  const envelope = requireRecord(value, "Ghidra inspection result");
  const exact: ReadonlyArray<readonly [string, unknown]> = [
    ["format", GHIDRA_INSPECTION_FORMAT],
    ["formatVersion", GHIDRA_INSPECTION_FORMAT_VERSION],
    ["requestId", request.requestId],
    ["sourceRomSha256", request.sourceRomSha256],
    ["processor", request.processor],
    ["programName", request.programName],
    ["operation", request.operation],
  ];
  for (const [key, expected] of exact) {
    if (envelope[key] !== expected) {
      throw inspectionError(`Ghidra inspection result ${key} does not match the request`);
    }
  }
  return envelope;
}

function candidateForOverlay(
  candidates: readonly RuntimeCandidate[],
  overlayId: number,
): RuntimeCandidate | null {
  return candidates.find((candidate) => candidate.overlayId === overlayId) ?? null;
}

function requireOverlayId(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new NdsError("ghidra-address-not-inspectable", "overlayId must be an unsigned 32-bit integer");
  }
  return value;
}

export function resolveGhidraInspectionSelector(
  map: NdsRomMap,
  selector: GhidraAddressSelector,
  operation: GhidraInspectionAddressOperation,
): GhidraCanonicalAddressIdentity {
  const requestedOverlayId = requireOverlayId(selector.overlayId);
  const resolution = resolveRuntimeAddress(map, selector.runtimeAddress, selector.processor);
  let candidate: RuntimeCandidate | null = null;

  if (resolution.status === "unmapped") {
    throw new NdsError(
      "ghidra-address-not-inspectable",
      "The requested runtime address is not mapped by the canonical NDS model",
    );
  }
  if (resolution.status === "ambiguous-runtime-address") {
    if (requestedOverlayId === undefined) {
      throw new NdsError(
        "ghidra-address-not-inspectable",
        "The requested runtime address has overlapping static candidates; specify overlayId to select one canonical overlay",
      );
    }
    candidate = candidateForOverlay(resolution.candidates, requestedOverlayId);
    if (candidate === null) {
      throw new NdsError(
        "ghidra-address-not-inspectable",
        `overlayId ${requestedOverlayId} is not a candidate for the requested runtime address`,
      );
    }
  } else {
    candidate = resolution.candidate;
    if (requestedOverlayId !== undefined && candidate.overlayId !== requestedOverlayId) {
      throw new NdsError(
        "ghidra-address-not-inspectable",
        `overlayId ${requestedOverlayId} does not own the requested runtime address`,
      );
    }
  }

  if (candidate.compressed) {
    throw new NdsError(
      "ghidra-address-not-inspectable",
      "The requested address belongs to a compressed overlay that is intentionally not imported into Ghidra",
    );
  }

  const component = candidate.overlayId === null ? "main" : "overlay";
  const bss = candidate.kind === "overlay-bss";
  const fileBacked = candidate.kind === "arm9-main"
    || candidate.kind === "arm7-main"
    || candidate.romOffset !== null;

  if (
    operation === "inspect-function"
    || operation === "decompile-function"
    || operation === "list-calls"
  ) {
    if (bss || !fileBacked) {
      throw new NdsError(
        "ghidra-address-not-inspectable",
        `${operation} requires exact file-backed executable code rather than runtime-only/unbacked memory`,
      );
    }
  }

  return {
    processor: selector.processor,
    runtimeAddress: selector.runtimeAddress,
    component,
    overlayId: candidate.overlayId,
    addressSpace: candidate.overlayId === null
      ? null
      : ghidraOverlaySpaceName(selector.processor, candidate.overlayId),
    fileBacked,
    bss,
    compressed: false,
  };
}

async function writeRequestAtomically(
  requestPath: string,
  request: GhidraInspectionRequest,
): Promise<void> {
  const temporary = `${requestPath}.tmp`;
  await writeFile(temporary, `${JSON.stringify(request, null, 2)}\n`, "utf8");
  await rename(temporary, requestPath);
}

async function verifyRomIdentity(state: TrustedGhidraInspectionState): Promise<void> {
  const current = await hashFileSha256(state.map.romPath);
  if (current !== state.map.sha256) {
    throw new NdsError(
      "invalid-rom",
      `Source ROM SHA-256 changed during Ghidra inspection: expected ${state.map.sha256}, found ${current}`,
    );
  }
}

function publicCanonical(
  state: TrustedGhidraInspectionState,
  selector: GhidraCanonicalAddressIdentity | null,
  processor: NdsProcessor,
): Readonly<Record<string, unknown>> {
  if (selector === null) {
    return { sourceRomSha256: state.map.sha256, processor };
  }
  return {
    sourceRomSha256: state.map.sha256,
    processor: selector.processor,
    runtimeAddress: selector.runtimeAddress,
    component: selector.component,
    overlayId: selector.overlayId,
    fileBacked: selector.fileBacked,
    bss: selector.bss,
    compressed: selector.compressed,
  };
}

async function performInspection(
  romPath: string,
  processor: NdsProcessor,
  operation: GhidraInspectionOperation,
  selectorInput: GhidraAddressSelector | null,
  parameters: Readonly<Record<string, string | number | boolean>>,
  config: ServerConfig,
  dependencies: GhidraInspectionDependencies,
): Promise<GhidraInspectionAuthorityResult> {
  const state = await dependencies.readTrustedState(romPath, config);
  await verifyRomIdentity(state);
  const installation = await dependencies.validateInstallation(config);
  if (installation.version !== state.ghidraVersion) {
    throw new NdsError(
      "ghidra-version-mismatch",
      `Configured Ghidra ${installation.version} does not match trusted project version ${state.ghidraVersion}`,
    );
  }

  const selector = selectorInput === null
    ? null
    : resolveGhidraInspectionSelector(
      state.map,
      selectorInput,
      operation as GhidraInspectionAddressOperation,
    );
  const requestId = dependencies.randomBytes(8).toString("hex");
  if (!/^[a-f0-9]{16}$/u.test(requestId)) {
    throw new NdsError("ghidra-inspection-failed", "Generated Ghidra inspection request ID is invalid");
  }
  const request: GhidraInspectionRequest = {
    format: GHIDRA_INSPECTION_FORMAT,
    formatVersion: GHIDRA_INSPECTION_FORMAT_VERSION,
    requestId,
    sourceRomSha256: state.map.sha256,
    processor,
    programName: ghidraProgramName(processor),
    operation,
    selector,
    parameters,
  };
  const root = ghidraInspectionRoot(state.map, config.workspaceRoot);
  const requestPath = ghidraInspectionRequestPath(state.map, config.workspaceRoot, requestId);
  const resultPath = ghidraInspectionResultPath(state.map, config.workspaceRoot, requestId);
  const temporaryRequestPath = `${requestPath}.tmp`;
  await mkdir(root, { recursive: true });

  try {
    await writeRequestAtomically(requestPath, request);
    const invocation = buildGhidraInspectionInvocation({
      installation,
      map: state.map,
      processor,
      workspaceRoot: config.workspaceRoot,
      requestPath,
      resultPath,
    });
    await dependencies.runInvocation(invocation, config);

    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(resultPath, "utf8")) as unknown;
    } catch (error) {
      throw inspectionError(
        `Unable to read a valid Ghidra inspection result: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    const envelope = validateEnvelope(parsed, request);

    let payload: Record<string, unknown>;
    let evidence: Readonly<Record<string, string | null>> | null = null;
    if (operation === "inspect-function") {
      const validated = validateFunctionPayload(envelope.payload);
      payload = validated.payload;
      evidence = validated.evidence;
    } else if (operation === "decompile-function") {
      const maxCharacters = parameters.maxCharacters;
      if (typeof maxCharacters !== "number") {
        throw inspectionError("Internal decompile request lacks maxCharacters");
      }
      const validated = validateDecompilePayload(envelope.payload, maxCharacters);
      payload = validated.payload;
      evidence = validated.evidence;
    } else if (operation === "search-symbols" || operation === "list-references") {
      const limit = parameters.limit;
      if (typeof limit !== "number") {
        throw inspectionError(`Internal ${operation} request lacks limit`);
      }
      payload = validatePagedPayload(envelope.payload, "results", limit);
    } else {
      const limit = parameters.limit;
      if (typeof limit !== "number") {
        throw inspectionError("Internal list-calls request lacks limit");
      }
      const rawPayload = requireRecord(envelope.payload, "call payload");
      const found = requireBoolean(rawPayload, "found");
      payload = {
        ...validatePagedPayload(rawPayload, "edges", limit),
        found,
        ...(rawPayload.function === undefined ? {} : { function: rawPayload.function }),
      };
    }

    await verifyRomIdentity(state);
    return {
      canonical: publicCanonical(state, selector, processor),
      reMcpEvidence: evidence,
      ghidraDerived: payload,
    };
  } finally {
    await Promise.all([
      rm(requestPath, { force: true }),
      rm(resultPath, { force: true }),
      rm(temporaryRequestPath, { force: true }),
    ]).catch(() => undefined);
  }
}

export async function inspectNdsGhidraFunction(
  romPath: string,
  selector: GhidraAddressSelector,
  config: ServerConfig,
  dependencies: GhidraInspectionDependencies = DEFAULT_DEPENDENCIES,
): Promise<GhidraInspectionAuthorityResult> {
  return performInspection(
    romPath,
    selector.processor,
    "inspect-function",
    selector,
    {},
    config,
    dependencies,
  );
}

export async function decompileNdsGhidraFunction(
  romPath: string,
  input: GhidraAddressSelector & { readonly maxCharacters?: number },
  config: ServerConfig,
  dependencies: GhidraInspectionDependencies = DEFAULT_DEPENDENCIES,
): Promise<GhidraInspectionAuthorityResult> {
  const maxCharacters = clampDecompilerCharacters(input.maxCharacters);
  return performInspection(
    romPath,
    input.processor,
    "decompile-function",
    input,
    { maxCharacters },
    config,
    dependencies,
  );
}

export async function searchNdsGhidraSymbols(
  romPath: string,
  input: {
    readonly processor: NdsProcessor;
    readonly query: string;
    readonly match?: GhidraSymbolMatch;
    readonly limit?: number;
    readonly offset?: number;
  },
  config: ServerConfig,
  dependencies: GhidraInspectionDependencies = DEFAULT_DEPENDENCIES,
): Promise<GhidraInspectionAuthorityResult> {
  const query = validateSymbolQuery(input.query);
  const match = validateSymbolMatch(input.match);
  const page = clampInspectionPage(input.limit, input.offset);
  return performInspection(
    romPath,
    input.processor,
    "search-symbols",
    null,
    { query, match, ...page },
    config,
    dependencies,
  );
}

export async function listNdsGhidraReferences(
  romPath: string,
  input: GhidraAddressSelector & {
    readonly direction?: GhidraReferenceDirection;
    readonly limit?: number;
    readonly offset?: number;
  },
  config: ServerConfig,
  dependencies: GhidraInspectionDependencies = DEFAULT_DEPENDENCIES,
): Promise<GhidraInspectionAuthorityResult> {
  const direction = validateReferenceDirection(input.direction);
  const page = clampInspectionPage(input.limit, input.offset);
  return performInspection(
    romPath,
    input.processor,
    "list-references",
    input,
    { direction, ...page },
    config,
    dependencies,
  );
}

export async function listNdsGhidraCalls(
  romPath: string,
  input: GhidraAddressSelector & {
    readonly direction?: GhidraCallDirection;
    readonly limit?: number;
    readonly offset?: number;
  },
  config: ServerConfig,
  dependencies: GhidraInspectionDependencies = DEFAULT_DEPENDENCIES,
): Promise<GhidraInspectionAuthorityResult> {
  const direction = validateCallDirection(input.direction);
  const page = clampInspectionPage(input.limit, input.offset);
  return performInspection(
    romPath,
    input.processor,
    "list-calls",
    input,
    { direction, ...page },
    config,
    dependencies,
  );
}
