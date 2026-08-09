import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import { resolveInside } from "../../../security/paths.js";
import { NdsError } from "../errors.js";

const SHA256_RE = /^[0-9a-f]{64}$/u;
const BYTE_HEX_RE = /^(?:[0-9a-fA-F]{2})+$/u;
const OUTPUT_FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,122}\.nds$/u;
const UINT32_MAX = 0xffffffff;
const MAX_PATH_BYTES = 4096;
const MAX_NITRO_PATH_SEGMENT_BYTES = 127;

export type NdsMutationComponentSelector =
  | { readonly component: "arm9" }
  | { readonly component: "arm7" }
  | { readonly component: "arm9-overlay"; readonly overlayId: number }
  | { readonly component: "arm7-overlay"; readonly overlayId: number }
  | { readonly component: "nitrofs-file"; readonly fileId: number }
  | { readonly component: "nitrofs-path"; readonly filePath: string };

export type NdsMutationByteTarget =
  | { readonly component: "arm9"; readonly relativeOffset: number }
  | { readonly component: "arm9"; readonly runtimeAddress: number }
  | { readonly component: "arm7"; readonly relativeOffset: number }
  | { readonly component: "arm7"; readonly runtimeAddress: number }
  | {
    readonly component: "arm9-overlay";
    readonly overlayId: number;
    readonly relativeOffset: number;
  }
  | {
    readonly component: "arm9-overlay";
    readonly overlayId: number;
    readonly runtimeAddress: number;
  }
  | {
    readonly component: "arm7-overlay";
    readonly overlayId: number;
    readonly relativeOffset: number;
  }
  | {
    readonly component: "arm7-overlay";
    readonly overlayId: number;
    readonly runtimeAddress: number;
  }
  | {
    readonly component: "nitrofs-file";
    readonly fileId: number;
    readonly relativeOffset: number;
  }
  | {
    readonly component: "nitrofs-path";
    readonly filePath: string;
    readonly relativeOffset: number;
  };

export interface NdsReplaceBytesOperation {
  readonly type: "replace-bytes";
  readonly target: NdsMutationByteTarget;
  readonly expected: string;
  readonly replacement: string;
}

export interface NdsReplaceComponentOperation {
  readonly type: "replace-component";
  readonly target: NdsMutationComponentSelector;
  readonly expectedOriginalSha256: string;
  readonly replacement: Readonly<{
    readonly artifact: string;
    readonly sha256: string;
  }>;
}

export type NdsExistingNitroTarget =
  | { readonly fileId: number }
  | { readonly filePath: string };

export interface NdsReplaceNitroFsFileOperation {
  readonly type: "replace-nitrofs-file";
  readonly target: NdsExistingNitroTarget;
  readonly expectedOriginalSha256: string;
  readonly replacement: Readonly<{
    readonly artifact: string;
    readonly sha256: string;
  }>;
}

export interface NdsAddNitroFsFileOperation {
  readonly type: "add-nitrofs-file";
  readonly path: string;
  readonly replacement: Readonly<{
    readonly artifact: string;
    readonly sha256: string;
  }>;
}

export interface NdsReplaceDecodedOverlayOperation {
  readonly type: "replace-decoded-overlay";
  readonly target: Readonly<{
    readonly processor: "arm9" | "arm7";
    readonly overlayId: number;
  }>;
  readonly expectedStoredSha256: string;
  readonly expectedRuntimeSha256: string;
  readonly replacement: Readonly<{
    readonly artifact: string;
    readonly sha256: string;
  }>;
}

/** Milestone 1 operation union. Keep this alias v1-only for existing callers. */
export type NdsMutationOperation =
  | NdsReplaceBytesOperation
  | NdsReplaceComponentOperation;

export type NdsMutationOperationV2 =
  | NdsReplaceBytesOperation
  | NdsReplaceComponentOperation
  | NdsReplaceNitroFsFileOperation
  | NdsAddNitroFsFileOperation
  | NdsReplaceDecodedOverlayOperation;

export interface NdsMutationManifestV1 {
  readonly format: "re-mcp-nds-mutation";
  readonly formatVersion: 1;
  readonly source: Readonly<{ readonly sha256: string }>;
  readonly output: Readonly<{ readonly filename: string }>;
  readonly operations: readonly NdsMutationOperation[];
}

export interface NdsMutationManifestV2 {
  readonly format: "re-mcp-nds-mutation";
  readonly formatVersion: 2;
  readonly source: Readonly<{ readonly sha256: string }>;
  readonly output: Readonly<{ readonly filename: string }>;
  readonly operations: readonly NdsMutationOperationV2[];
}

export type NdsMutationManifest = NdsMutationManifestV1 | NdsMutationManifestV2;

export interface LoadedNdsMutationManifest {
  readonly manifestPath: string;
  readonly workspaceRelativePath: string;
  readonly manifest: NdsMutationManifest;
  readonly canonicalJson: string;
  readonly sha256: string;
}

const uint32Schema = z.number().int().min(0).max(UINT32_MAX);
const safeOffsetSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const sha256Schema = z.string().regex(SHA256_RE);
const byteHexSchema = z.string().refine(
  (value) => BYTE_HEX_RE.test(value),
  "Byte strings must contain one or more whole hexadecimal bytes",
);

const sourceSchema = z.object({ sha256: sha256Schema }).strict();
const outputSchema = z.object({
  filename: z.string().regex(OUTPUT_FILENAME_RE),
}).strict();

const mainComponentSchemas = [
  z.object({ component: z.literal("arm9") }).strict(),
  z.object({ component: z.literal("arm7") }).strict(),
] as const;
const overlayComponentSchemas = [
  z.object({ component: z.literal("arm9-overlay"), overlayId: uint32Schema }).strict(),
  z.object({ component: z.literal("arm7-overlay"), overlayId: uint32Schema }).strict(),
] as const;
const nitroComponentSchemas = [
  z.object({ component: z.literal("nitrofs-file"), fileId: uint32Schema }).strict(),
  z.object({ component: z.literal("nitrofs-path"), filePath: z.string().min(1).max(MAX_PATH_BYTES) }).strict(),
] as const;

const componentSchema = z.union([
  ...mainComponentSchemas,
  ...overlayComponentSchemas,
  ...nitroComponentSchemas,
]);

const byteTargetSchema = z.union([
  z.object({ component: z.literal("arm9"), relativeOffset: safeOffsetSchema }).strict(),
  z.object({ component: z.literal("arm9"), runtimeAddress: uint32Schema }).strict(),
  z.object({ component: z.literal("arm7"), relativeOffset: safeOffsetSchema }).strict(),
  z.object({ component: z.literal("arm7"), runtimeAddress: uint32Schema }).strict(),
  z.object({
    component: z.literal("arm9-overlay"),
    overlayId: uint32Schema,
    relativeOffset: safeOffsetSchema,
  }).strict(),
  z.object({
    component: z.literal("arm9-overlay"),
    overlayId: uint32Schema,
    runtimeAddress: uint32Schema,
  }).strict(),
  z.object({
    component: z.literal("arm7-overlay"),
    overlayId: uint32Schema,
    relativeOffset: safeOffsetSchema,
  }).strict(),
  z.object({
    component: z.literal("arm7-overlay"),
    overlayId: uint32Schema,
    runtimeAddress: uint32Schema,
  }).strict(),
  z.object({
    component: z.literal("nitrofs-file"),
    fileId: uint32Schema,
    relativeOffset: safeOffsetSchema,
  }).strict(),
  z.object({
    component: z.literal("nitrofs-path"),
    filePath: z.string().min(1).max(MAX_PATH_BYTES),
    relativeOffset: safeOffsetSchema,
  }).strict(),
]);

function isPortableWorkspacePath(value: string): boolean {
  if (
    value.length === 0
    || value.includes("\0")
    || value.includes("\\")
    || value.startsWith("/")
    || value.endsWith("/")
    || path.posix.isAbsolute(value)
  ) {
    return false;
  }
  const segments = value.split("/");
  return segments.every(
    (segment) => segment.length > 0 && segment !== "." && segment !== "..",
  );
}

function isPortableNewNitroPath(value: string): boolean {
  if (!isPortableWorkspacePath(value) || Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES) {
    return false;
  }
  return value.split("/").every((segment) => {
    const bytes = Buffer.from(segment, "utf8");
    if (bytes.length < 1 || bytes.length > MAX_NITRO_PATH_SEGMENT_BYTES) {
      return false;
    }
    return [...bytes].every((byte) => byte >= 0x20 && byte <= 0x7e);
  });
}

const artifactPathSchema = z.string().max(MAX_PATH_BYTES).refine(
  isPortableWorkspacePath,
  "Artifact path must be a portable workspace-relative POSIX path",
);

const newNitroPathSchema = z.string().min(1).max(MAX_PATH_BYTES).refine(
  isPortableNewNitroPath,
  "New NitroFS path must use printable-ASCII portable POSIX segments of 1 through 127 bytes",
);

const replacementArtifactSchema = z.object({
  artifact: artifactPathSchema,
  sha256: sha256Schema,
}).strict();

const replaceBytesSchema = z.object({
  type: z.literal("replace-bytes"),
  target: byteTargetSchema,
  expected: byteHexSchema,
  replacement: byteHexSchema,
}).strict().superRefine((operation, context) => {
  if (operation.expected.length !== operation.replacement.length) {
    context.addIssue({
      code: z.ZodIssueCode.custom,
      path: ["replacement"],
      message: "Replacement byte length must equal expected byte length",
    });
  }
});

const replaceComponentSchema = z.object({
  type: z.literal("replace-component"),
  target: componentSchema,
  expectedOriginalSha256: sha256Schema,
  replacement: replacementArtifactSchema,
}).strict();

const existingNitroTargetSchema = z.union([
  z.object({ fileId: uint32Schema }).strict(),
  z.object({ filePath: z.string().min(1).max(MAX_PATH_BYTES) }).strict(),
]);

const replaceNitroFsFileSchema = z.object({
  type: z.literal("replace-nitrofs-file"),
  target: existingNitroTargetSchema,
  expectedOriginalSha256: sha256Schema,
  replacement: replacementArtifactSchema,
}).strict();

const addNitroFsFileSchema = z.object({
  type: z.literal("add-nitrofs-file"),
  path: newNitroPathSchema,
  replacement: replacementArtifactSchema,
}).strict();

const replaceDecodedOverlaySchema = z.object({
  type: z.literal("replace-decoded-overlay"),
  target: z.object({
    processor: z.union([z.literal("arm9"), z.literal("arm7")]),
    overlayId: uint32Schema,
  }).strict(),
  expectedStoredSha256: sha256Schema,
  expectedRuntimeSha256: sha256Schema,
  replacement: replacementArtifactSchema,
}).strict();

const v1OperationSchema = z.union([
  replaceBytesSchema,
  replaceComponentSchema,
]);

const v2OperationSchema = z.union([
  replaceBytesSchema,
  replaceComponentSchema,
  replaceNitroFsFileSchema,
  addNitroFsFileSchema,
  replaceDecodedOverlaySchema,
]);

const manifestV1Schema = z.object({
  format: z.literal("re-mcp-nds-mutation"),
  formatVersion: z.literal(1),
  source: sourceSchema,
  output: outputSchema,
  operations: z.array(v1OperationSchema).min(1).max(4096),
}).strict();

const manifestV2Schema = z.object({
  format: z.literal("re-mcp-nds-mutation"),
  formatVersion: z.literal(2),
  source: sourceSchema,
  output: outputSchema,
  operations: z.array(v2OperationSchema).min(1).max(4096),
}).strict();

const manifestSchema = z.discriminatedUnion("formatVersion", [
  manifestV1Schema,
  manifestV2Schema,
]);

type ParsedV1Operation = z.infer<typeof v1OperationSchema>;
type ParsedV2Operation = z.infer<typeof v2OperationSchema>;

function normalizeV1Operation(operation: ParsedV1Operation): NdsMutationOperation {
  if (operation.type === "replace-bytes") {
    const expected = operation.expected.toLowerCase();
    const replacement = operation.replacement.toLowerCase();
    if (expected === replacement) {
      throw new NdsError(
        "mutation-no-op",
        "Byte mutation replacement must differ from its expected original bytes",
      );
    }
    return {
      type: operation.type,
      target: operation.target as NdsMutationByteTarget,
      expected,
      replacement,
    };
  }
  return {
    type: operation.type,
    target: operation.target as NdsMutationComponentSelector,
    expectedOriginalSha256: operation.expectedOriginalSha256,
    replacement: {
      artifact: operation.replacement.artifact,
      sha256: operation.replacement.sha256,
    },
  };
}

function normalizeV2Operation(operation: ParsedV2Operation): NdsMutationOperationV2 {
  if (operation.type === "replace-bytes" || operation.type === "replace-component") {
    return normalizeV1Operation(operation);
  }
  if (operation.type === "replace-nitrofs-file") {
    return {
      type: operation.type,
      target: operation.target as NdsExistingNitroTarget,
      expectedOriginalSha256: operation.expectedOriginalSha256,
      replacement: {
        artifact: operation.replacement.artifact,
        sha256: operation.replacement.sha256,
      },
    };
  }
  if (operation.type === "add-nitrofs-file") {
    return {
      type: operation.type,
      path: operation.path,
      replacement: {
        artifact: operation.replacement.artifact,
        sha256: operation.replacement.sha256,
      },
    };
  }
  return {
    type: operation.type,
    target: {
      processor: operation.target.processor,
      overlayId: operation.target.overlayId,
    },
    expectedStoredSha256: operation.expectedStoredSha256,
    expectedRuntimeSha256: operation.expectedRuntimeSha256,
    replacement: {
      artifact: operation.replacement.artifact,
      sha256: operation.replacement.sha256,
    },
  };
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalize(entry));
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      result[key] = canonicalize(record[key]);
    }
    return result;
  }
  return value;
}

export function serializeCanonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function normalizeManifest(
  parsed: z.infer<typeof manifestSchema>,
): NdsMutationManifest {
  if (parsed.formatVersion === 1) {
    return {
      format: parsed.format,
      formatVersion: 1,
      source: { sha256: parsed.source.sha256 },
      output: { filename: parsed.output.filename },
      operations: parsed.operations.map((operation) => normalizeV1Operation(operation)),
    };
  }
  return {
    format: parsed.format,
    formatVersion: 2,
    source: { sha256: parsed.source.sha256 },
    output: { filename: parsed.output.filename },
    operations: parsed.operations.map((operation) => normalizeV2Operation(operation)),
  };
}

export function serializeCanonicalMutationManifest(
  manifest: NdsMutationManifest,
): string {
  return serializeCanonicalJson(manifest);
}

function mutationManifestError(message: string): NdsError<"mutation-manifest-invalid"> {
  return new NdsError("mutation-manifest-invalid", message);
}

export async function loadNdsMutationManifest(
  workspaceRoot: string,
  requestedPath: string,
): Promise<LoadedNdsMutationManifest> {
  try {
    const manifestPath = resolveInside(workspaceRoot, requestedPath);
    const info = await lstat(manifestPath);
    if (!info.isFile() || info.isSymbolicLink()) {
      throw new Error("Mutation manifest path must reference a regular non-symlink file");
    }
    const rawText = await readFile(manifestPath, "utf8");
    const raw = JSON.parse(rawText) as unknown;
    const parsed = manifestSchema.parse(raw);
    const manifest = normalizeManifest(parsed);
    const canonicalJson = serializeCanonicalMutationManifest(manifest);
    const sha256 = createHash("sha256").update(canonicalJson, "utf8").digest("hex");
    const workspaceRelativePath = path
      .relative(path.resolve(workspaceRoot), manifestPath)
      .split(path.sep)
      .join("/");
    if (!isPortableWorkspacePath(workspaceRelativePath)) {
      throw new Error("Mutation manifest must resolve to a portable workspace-relative path");
    }
    return {
      manifestPath,
      workspaceRelativePath,
      manifest,
      canonicalJson,
      sha256,
    };
  } catch (error) {
    if (
      error instanceof NdsError
      && (error.category === "mutation-manifest-invalid" || error.category === "mutation-no-op")
    ) {
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    throw mutationManifestError(`Invalid NDS mutation manifest: ${message}`);
  }
}
