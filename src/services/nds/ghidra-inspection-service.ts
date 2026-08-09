import { randomBytes as nodeRandomBytes } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";

import type { ServerConfig } from "../../config.js";
import type { RunResult } from "../process-runner.js";
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
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import {
  resolveRuntimeAddress,
  type RuntimeCandidate,
} from "./resolver.js";
import type { NdsRomMap } from "./rom-map.js";

const UINT32_MAX = 0xffffffff;
const UINT32_END = 0x1_0000_0000;
const MAX_FUNCTION_BODY_RANGES = 256;
const MAX_PAGE_OFFSET = 100_000;
const MAX_PAGE_LIMIT = 1_000;

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

interface ValidatedGhidraAddress {
  readonly space: string;
  readonly offset: number;
  readonly overlaySpace: boolean;
  readonly defaultSpace: boolean;
}

interface ValidatedFunctionIdentity {
  readonly entry: ValidatedGhidraAddress;
  readonly name: string;
  readonly namespace: string;
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
  if (!isRecord(value)) throw inspectionError(`${label} must be a JSON object`);
  return value;
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string") {
    throw inspectionError(`Ghidra inspection result field ${key} must be a string`);
  }
  return value;
}

function requireNonEmptyString(record: Record<string, unknown>, key: string): string {
  const value = requireString(record, key);
  if (value.length === 0) {
    throw inspectionError(`Ghidra inspection result field ${key} must not be empty`);
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

function requireSafeInteger(
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
  if (typeof value !== "string") throw inspectionError(`${label} must be a string or null`);
  return value;
}

function validateAddress(value: unknown, label: string): ValidatedGhidraAddress {
  const address = requireRecord(value, label);
  const result = {
    space: requireNonEmptyString(address, "space"),
    offset: requireSafeInteger(address, "offset", 0, UINT32_MAX),
    overlaySpace: requireBoolean(address, "overlaySpace"),
    defaultSpace: requireBoolean(address, "defaultSpace"),
  };
  if (result.overlaySpace && result.defaultSpace) {
    throw inspectionError(`${label} cannot be both overlaySpace and defaultSpace`);
  }
  return result;
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

function validateFunctionIdentity(value: unknown, label: string): ValidatedFunctionIdentity {
  const identity = requireRecord(value, label);
  return {
    entry: validateAddress(identity.entry, `${label}.entry`),
    name: requireString(identity, "name"),
    namespace: requireString(identity, "namespace"),
  };
}

function validateFunctionPayload(
  value: unknown,
): { readonly payload: Record<string, unknown>; readonly evidence: Readonly<Record<string, string | null>> | null } {
  const payload = requireRecord(value, "function inspection payload");
  const found = requireBoolean(payload, "found");
  if (!found) return { payload: { found: false }, evidence: null };

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
    const space = requireNonEmptyString(record, "space");
    const start = requireSafeInteger(record, "start", 0, UINT32_MAX);
    const endExclusive = requireSafeInteger(record, "endExclusive", 0, UINT32_END);
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
    if (c.length > maxCharacters) throw inspectionError("decompiler output exceeds maxCharacters");
    return { payload: { found, completed, truncated, c, error }, evidence: null };
  }

  const functionResult = validateFunctionPayload(raw);
  const completed = requireBoolean(raw, "completed");
  const truncated = requireBoolean(raw, "truncated");
  const c = requireString(raw, "c");
  const error = requireString(raw, "error");
  if (c.length > maxCharacters) throw inspectionError("decompiler output exceeds maxCharacters");
  return {
    payload: { ...functionResult.payload, completed, truncated, c, error },
    evidence: functionResult.evidence,
  };
}

function resolutionCandidates(map: NdsRomMap, processor: NdsProcessor, runtimeAddress: number): readonly RuntimeCandidate[] {
  const resolution = resolveRuntimeAddress(map, runtimeAddress, processor);
  if (resolution.status === "unmapped") return [];
  if (resolution.status === "ambiguous-runtime-address") return resolution.candidates;
  return [resolution.candidate];
}

function canonicalCandidate(
  processor: NdsProcessor,
  runtimeAddress: number,
  candidate: RuntimeCandidate,
): Readonly<Record<string, unknown>> {
  const bss = candidate.kind === "overlay-bss";
  const fileBacked = candidate.kind === "arm9-main"
    || candidate.kind === "arm7-main"
    || candidate.romOffset !== null;
  return {
    processor,
    runtimeAddress,
    component: candidate.overlayId === null ? "main" : "overlay",
    overlayId: candidate.overlayId,
    fileBacked,
    bss,
    compressed: candidate.compressed,
  };
}

function overlayForSpace(
  map: NdsRomMap,
  processor: NdsProcessor,
  space: string,
): NdsOverlay | null {
  return map.overlays[processor].find(
    (overlay) => ghidraOverlaySpaceName(processor, overlay.overlayId) === space,
  ) ?? null;
}

function classifyGhidraAddress(
  map: NdsRomMap,
  processor: NdsProcessor,
  address: ValidatedGhidraAddress,
): Readonly<Record<string, unknown>> | null {
  const candidates = resolutionCandidates(map, processor, address.offset);
  if (address.defaultSpace) {
    const main = candidates.find((candidate) => candidate.overlayId === null);
    return main === undefined ? null : canonicalCandidate(processor, address.offset, main);
  }
  if (address.overlaySpace) {
    const overlay = overlayForSpace(map, processor, address.space);
    if (overlay === null) return null;
    const candidate = candidates.find((entry) => entry.overlayId === overlay.overlayId);
    return candidate === undefined ? null : canonicalCandidate(processor, address.offset, candidate);
  }
  return null;
}

function validateSymbolItem(value: unknown): Readonly<Record<string, unknown>> {
  const item = requireRecord(value, "symbol result");
  const evidence = validateEvidence(item.reMcpEvidence);
  return {
    reMcpEvidence: evidence,
    ghidraDerived: {
      name: requireString(item, "name"),
      namespace: requireString(item, "namespace"),
      type: requireString(item, "type"),
      address: validateAddress(item.address, "symbol address"),
      primary: requireBoolean(item, "primary"),
      dynamic: requireBoolean(item, "dynamic"),
      source: requireString(item, "source"),
    },
  };
}

function validateReferenceCore(
  value: unknown,
  map: NdsRomMap,
  processor: NdsProcessor,
  label: string,
): {
  readonly canonical: Readonly<Record<string, unknown>>;
  readonly ghidraDerived: Readonly<Record<string, unknown>>;
  readonly from: ValidatedGhidraAddress;
  readonly to: ValidatedGhidraAddress;
} {
  const item = requireRecord(value, label);
  const from = validateAddress(item.from, `${label}.from`);
  const to = validateAddress(item.to, `${label}.to`);
  return {
    canonical: {
      from: classifyGhidraAddress(map, processor, from),
      to: classifyGhidraAddress(map, processor, to),
    },
    ghidraDerived: {
      from,
      to,
      type: requireString(item, "type"),
      source: requireString(item, "source"),
      operandIndex: requireSafeInteger(item, "operandIndex", -128, 0x7fffffff),
      primary: requireBoolean(item, "primary"),
    },
    from,
    to,
  };
}

function validateReferenceItem(
  value: unknown,
  map: NdsRomMap,
  processor: NdsProcessor,
): Readonly<Record<string, unknown>> {
  const validated = validateReferenceCore(value, map, processor, "reference result");
  return {
    canonical: validated.canonical,
    ghidraDerived: validated.ghidraDerived,
  };
}

function validateNullableFunctionIdentity(value: unknown, label: string): ValidatedFunctionIdentity | null {
  return value === null ? null : validateFunctionIdentity(value, label);
}

function validateCallItem(
  value: unknown,
  map: NdsRomMap,
  processor: NdsProcessor,
): Readonly<Record<string, unknown>> {
  const raw = requireRecord(value, "call edge");
  const reference = validateReferenceCore(raw, map, processor, "call edge");
  const callSite = validateAddress(raw.callSite, "call edge.callSite");
  if (
    callSite.space !== reference.from.space
    || callSite.offset !== reference.from.offset
    || callSite.overlaySpace !== reference.from.overlaySpace
    || callSite.defaultSpace !== reference.from.defaultSpace
  ) {
    throw inspectionError("call edge.callSite must equal its from address");
  }
  const directCall = nullableString(raw.reMcpDirectCallEvidence, "call edge.reMcpDirectCallEvidence");
  return {
    canonical: reference.canonical,
    reMcpEvidence: { directCall },
    ghidraDerived: {
      ...reference.ghidraDerived,
      callSite,
      sourceFunction: validateNullableFunctionIdentity(raw.sourceFunction, "call edge.sourceFunction"),
      targetFunction: validateNullableFunctionIdentity(raw.targetFunction, "call edge.targetFunction"),
    },
  };
}

function validatePagedPayload(
  value: unknown,
  arrayName: "results" | "edges",
  requestedLimit: number,
  requestedOffset: number,
  validateItem: (item: unknown) => Readonly<Record<string, unknown>>,
): Record<string, unknown> {
  const payload = requireRecord(value, `${arrayName} payload`);
  const totalMatches = requireSafeInteger(payload, "totalMatches", 0, Number.MAX_SAFE_INTEGER);
  const returned = requireSafeInteger(payload, "returned", 0, requestedLimit);
  const offset = requireSafeInteger(payload, "offset", 0, MAX_PAGE_OFFSET);
  const limit = requireSafeInteger(payload, "limit", 1, MAX_PAGE_LIMIT);
  const truncated = requireBoolean(payload, "truncated");
  if (limit !== requestedLimit || offset !== requestedOffset) {
    throw inspectionError(`${arrayName} pagination metadata does not match the request`);
  }
  const rawItems = payload[arrayName];
  if (!Array.isArray(rawItems) || rawItems.length !== returned || rawItems.length > requestedLimit) {
    throw inspectionError(`${arrayName} must contain exactly returned items within the requested limit`);
  }
  if (totalMatches < returned) {
    throw inspectionError(`${arrayName} totalMatches cannot be smaller than returned`);
  }
  const expectedTruncated = Math.min(offset, totalMatches) + returned < totalMatches;
  if (truncated !== expectedTruncated) {
    throw inspectionError(`${arrayName} truncated flag is inconsistent with pagination metadata`);
  }
  const items = rawItems.map(validateItem);
  return { totalMatches, returned, offset, limit, truncated, [arrayName]: items };
}

function validateEnvelope(value: unknown, request: GhidraInspectionRequest): Record<string, unknown> {
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

function candidatesForSelector(
  map: NdsRomMap,
  selector: GhidraAddressSelector,
): readonly RuntimeCandidate[] {
  return resolutionCandidates(map, selector.processor, selector.runtimeAddress);
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
  const candidates = candidatesForSelector(map, selector);
  if (candidates.length === 0) {
    throw new NdsError(
      "ghidra-address-not-inspectable",
      "The requested runtime address is not mapped by the canonical NDS model",
    );
  }

  let candidate: RuntimeCandidate | undefined;
  if (requestedOverlayId === undefined) {
    if (candidates.length !== 1) {
      throw new NdsError(
        "ghidra-address-not-inspectable",
        "The requested runtime address has overlapping static candidates; specify overlayId to select one canonical overlay",
      );
    }
    candidate = candidates[0];
  } else {
    candidate = candidates.find((entry) => entry.overlayId === requestedOverlayId);
    if (candidate === undefined) {
      throw new NdsError(
        "ghidra-address-not-inspectable",
        `overlayId ${requestedOverlayId} does not own the requested runtime address`,
      );
    }
  }

  if (candidate === undefined) {
    throw new NdsError(
      "ghidra-address-not-inspectable",
      "Unable to resolve one canonical runtime candidate for Ghidra inspection",
    );
  }

  const component = candidate.overlayId === null ? "main" : "overlay";
  const bss = candidate.kind === "overlay-bss";
  const fileBacked = candidate.kind === "arm9-main"
    || candidate.kind === "arm7-main"
    || candidate.romOffset !== null;
  const derivedOverlay = candidate.representation === "derived-overlay";
  const executableCodeAvailable = fileBacked || derivedOverlay;
  if (
    (operation === "inspect-function" || operation === "decompile-function" || operation === "list-calls")
    && (bss || !executableCodeAvailable)
  ) {
    throw new NdsError(
      "ghidra-address-not-inspectable",
      `${operation} requires exact imported executable code rather than runtime-only/unbacked memory`,
    );
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
    compressed: candidate.compressed,
  };
}

async function writeRequestAtomically(requestPath: string, request: GhidraInspectionRequest): Promise<void> {
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
  if (selector === null) return { sourceRomSha256: state.map.sha256, processor };
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
    : resolveGhidraInspectionSelector(state.map, selectorInput, operation as GhidraInspectionAddressOperation);
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
      if (typeof maxCharacters !== "number") throw inspectionError("Internal decompile request lacks maxCharacters");
      const validated = validateDecompilePayload(envelope.payload, maxCharacters);
      payload = validated.payload;
      evidence = validated.evidence;
    } else if (operation === "search-symbols") {
      const limit = parameters.limit;
      const offset = parameters.offset;
      if (typeof limit !== "number" || typeof offset !== "number") {
        throw inspectionError("Internal search-symbols request lacks pagination");
      }
      payload = validatePagedPayload(
        envelope.payload,
        "results",
        limit,
        offset,
        validateSymbolItem,
      );
    } else if (operation === "list-references") {
      const limit = parameters.limit;
      const offset = parameters.offset;
      if (typeof limit !== "number" || typeof offset !== "number") {
        throw inspectionError("Internal list-references request lacks pagination");
      }
      payload = validatePagedPayload(
        envelope.payload,
        "results",
        limit,
        offset,
        (item) => validateReferenceItem(item, state.map, processor),
      );
    } else {
      const limit = parameters.limit;
      const offset = parameters.offset;
      if (typeof limit !== "number" || typeof offset !== "number") {
        throw inspectionError("Internal list-calls request lacks pagination");
      }
      const rawPayload = requireRecord(envelope.payload, "call payload");
      const found = requireBoolean(rawPayload, "found");
      const paged = validatePagedPayload(
        rawPayload,
        "edges",
        limit,
        offset,
        (item) => validateCallItem(item, state.map, processor),
      );
      if (found) {
        if (rawPayload.function === undefined || rawPayload.function === null) {
          throw inspectionError("found call payload must include its selected function identity");
        }
        payload = { ...paged, found: true, function: validateFunctionIdentity(rawPayload.function, "call payload.function") };
      } else {
        if (rawPayload.function !== undefined && rawPayload.function !== null) {
          throw inspectionError("missing-function call payload must not include a function identity");
        }
        payload = { ...paged, found: false };
      }
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
  return performInspection(romPath, selector.processor, "inspect-function", selector, {}, config, dependencies);
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
