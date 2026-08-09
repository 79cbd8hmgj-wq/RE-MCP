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

export type NdsMutationOperation =
  | NdsReplaceBytesOperation
  | NdsReplaceComponentOperation;

export interface NdsMutationManifestV1 {
  readonly format: "re-mcp-nds-mutation";
  readonly formatVersion: 1;
  readonly source: Readonly<{ readonly sha256: string }>;
  readonly output: Readonly<{ readonly filename: string }>;
  readonly operations: readonly NdsMutationOperation[];
}

export interface LoadedNdsMutationManifest {
  readonly manifestPath: string;
  readonly workspaceRelativePath: string;
  readonly manifest: NdsMutationManifestV1;
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
  z.object({ component: z.literal("nitrofs-path"), filePath: z.string().min(1).max(4096) }).strict(),
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
    filePath: z.string().min(1).max(4096),
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

const artifactPathSchema = z.string().max(4096).refine(
  isPortableWorkspacePath,
  "Artifact path must be a portable workspace-relative POSIX path",
);

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
  replacement: z.object({
    artifact: artifactPathSchema,
    sha256: sha256Schema,
  }).strict(),
}).strict();

const manifestSchema = z.object({
  format: z.literal("re-mcp-nds-mutation"),
  formatVersion: z.literal(1),
  source: z.object({ sha256: sha256Schema }).strict(),
  output: z.object({
    filename: z.string().regex(OUTPUT_FILENAME_RE),
  }).strict(),
  operations: z.array(z.union([replaceBytesSchema, replaceComponentSchema])).min(1).max(4096),
}).strict();

function normalizeOperation(
  operation: z.infer<typeof replaceBytesSchema> | z.infer<typeof replaceComponentSchema>,
): NdsMutationOperation {
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

function normalizeManifest(parsed: z.infer<typeof manifestSchema>): NdsMutationManifestV1 {
  const operations = parsed.operations.map((operation) => normalizeOperation(operation));
  return {
    format: parsed.format,
    formatVersion: parsed.formatVersion,
    source: { sha256: parsed.source.sha256 },
    output: { filename: parsed.output.filename },
    operations,
  };
}

export function serializeCanonicalMutationManifest(
  manifest: NdsMutationManifestV1,
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
