import { createHash } from "node:crypto";
import { lstat, mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";

import { resolveInside } from "../../security/paths.js";
import type { ReArtifactReference } from "./types.js";

const JOURNAL_FORMAT = "re-mcp-investigation-journal" as const;
const JOURNAL_VERSION = 1 as const;
const METADATA_FORMAT = "re-mcp-investigation-journal-meta" as const;
const PROJECTION_FORMAT = "re-mcp-investigation-checkpoint" as const;
const MAX_JOURNAL_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 4096;
const MAX_PROJECTION_OPERATIONS = 128;
const MAX_PROJECTION_ARTIFACTS = 256;

export type InvestigationJournalErrorCategory =
  | "investigation-journal-integrity-failure"
  | "investigation-journal-io-failure"
  | "investigation-journal-invalid-input";

export class InvestigationJournalError extends Error {
  readonly category: InvestigationJournalErrorCategory;

  constructor(category: InvestigationJournalErrorCategory, message: string) {
    super(message);
    this.name = "InvestigationJournalError";
    this.category = category;
  }
}

export interface InvestigationSourceIdentity {
  readonly sha256: string;
  readonly sha256Prefix: string;
}

export interface InvestigationArtifactHash {
  readonly kind: string;
  readonly path: string | null;
  readonly sha256: string | null;
}

export interface InvestigationJournalEntry {
  readonly format: typeof JOURNAL_FORMAT;
  readonly formatVersion: typeof JOURNAL_VERSION;
  readonly sequence: number;
  readonly operationId: string;
  readonly operation: string;
  readonly normalizedInputs: unknown;
  readonly sourceRomSha256: string;
  readonly completedStages: readonly string[];
  readonly artifactHashes: readonly InvestigationArtifactHash[];
  readonly resultDigest: string;
  readonly completionStatus: "completed";
  readonly recordedAt: string;
  readonly entrySha256: string;
}

export interface InvestigationJournalMetadata {
  readonly format: typeof METADATA_FORMAT;
  readonly formatVersion: typeof JOURNAL_VERSION;
  readonly sourceRomSha256: string;
  readonly sourceRomSha256Prefix: string;
  readonly entryCount: number;
  readonly lastSequence: number;
  readonly journalSha256: string;
  readonly projectionSha256: string;
  readonly updatedAt: string;
  readonly contentSha256: string;
}

export interface InvestigationCheckpointProjection {
  readonly format: typeof PROJECTION_FORMAT;
  readonly formatVersion: typeof JOURNAL_VERSION;
  readonly authority: "deterministic-investigation-state";
  readonly sourceRomSha256: string;
  readonly sourceRomSha256Prefix: string;
  readonly latestSequence: number;
  readonly completedOperations: readonly {
    readonly sequence: number;
    readonly operationId: string;
    readonly operation: string;
    readonly resultDigest: string;
  }[];
  readonly completedStages: readonly string[];
  readonly artifactHashes: readonly InvestigationArtifactHash[];
  readonly recommendedNextActions: readonly string[];
  readonly contentSha256: string;
}

export interface InvestigationPersistenceInput {
  readonly operation: string;
  readonly normalizedInputs: unknown;
  readonly completedStages: readonly string[];
  readonly artifacts: readonly ReArtifactReference[];
  readonly result: unknown;
  readonly recommendedNextAction: string | null;
}

export interface InvestigationPersistenceResult {
  readonly entry: InvestigationJournalEntry;
  readonly projection: InvestigationCheckpointProjection;
  readonly journalRelativePath: string;
  readonly projectionRelativePath: string;
}

interface JournalPaths {
  readonly directory: string;
  readonly journal: string;
  readonly metadata: string;
  readonly projection: string;
}

interface MetadataPayload extends Omit<InvestigationJournalMetadata, "contentSha256"> {}
interface ProjectionPayload extends Omit<InvestigationCheckpointProjection, "contentSha256"> {}
interface EntryPayload extends Omit<InvestigationJournalEntry, "entrySha256"> {}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error;
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function validateSource(source: InvestigationSourceIdentity): void {
  if (!isSha256(source.sha256)) {
    throw new InvestigationJournalError(
      "investigation-journal-invalid-input",
      "Investigation source SHA-256 is invalid",
    );
  }
  if (
    !/^[0-9a-f]{8,64}$/.test(source.sha256Prefix)
    || !source.sha256.startsWith(source.sha256Prefix)
  ) {
    throw new InvestigationJournalError(
      "investigation-journal-invalid-input",
      "Investigation source SHA-256 prefix is inconsistent with the exact ROM identity",
    );
  }
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, canonicalize(record[key])]),
    );
  }
  if (
    value === null
    || typeof value === "string"
    || typeof value === "boolean"
    || (typeof value === "number" && Number.isFinite(value))
  ) {
    return value;
  }
  throw new InvestigationJournalError(
    "investigation-journal-invalid-input",
    "Investigation persistence accepts only finite JSON-compatible deterministic state",
  );
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function journalPaths(
  source: InvestigationSourceIdentity,
  workspaceRoot: string,
): JournalPaths {
  validateSource(source);
  const directory = resolveInside(
    workspaceRoot,
    path.join("analysis", "generated", "nds", source.sha256Prefix, "controller"),
  );
  return {
    directory,
    journal: path.join(directory, "investigation-journal.jsonl"),
    metadata: path.join(directory, "investigation-journal.meta.json"),
    projection: path.join(directory, "investigation-checkpoint.json"),
  };
}

function relativeWorkspacePath(workspaceRoot: string, target: string): string {
  return path.relative(path.resolve(workspaceRoot), target).split(path.sep).join("/");
}

async function assertNoSymlinkSegments(workspaceRoot: string, target: string): Promise<void> {
  const root = path.resolve(workspaceRoot);
  const resolved = path.resolve(target);
  const relative = path.relative(root, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new InvestigationJournalError(
      "investigation-journal-io-failure",
      "Investigation journal path escapes the configured workspace",
    );
  }
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const metadata = await lstat(current);
      if (metadata.isSymbolicLink()) {
        throw new InvestigationJournalError(
          "investigation-journal-io-failure",
          "Investigation journal path may not traverse symbolic links",
        );
      }
    } catch (error) {
      if (error instanceof InvestigationJournalError) throw error;
      if (isNodeError(error) && error.code === "ENOENT") return;
      throw new InvestigationJournalError(
        "investigation-journal-io-failure",
        `Unable to inspect investigation journal path: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}

async function readTextIfExists(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return null;
    throw new InvestigationJournalError(
      "investigation-journal-io-failure",
      `Unable to read investigation state: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function withHash<T extends object>(payload: T, key: "contentSha256" | "entrySha256"): T & Record<typeof key, string> {
  return {
    ...payload,
    [key]: sha256Text(canonicalJson(payload)),
  } as T & Record<typeof key, string>;
}

function artifactHashes(artifacts: readonly ReArtifactReference[]): InvestigationArtifactHash[] {
  return artifacts
    .map((artifact) => ({
      kind: artifact.kind,
      path: artifact.path ?? null,
      sha256: artifact.sha256 ?? null,
    }))
    .sort((left, right) =>
      left.kind.localeCompare(right.kind)
      || (left.path ?? "").localeCompare(right.path ?? "")
      || (left.sha256 ?? "").localeCompare(right.sha256 ?? ""));
}

function parseEntry(
  source: InvestigationSourceIdentity,
  value: unknown,
  expectedSequence: number,
): InvestigationJournalEntry {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InvestigationJournalError("investigation-journal-integrity-failure", "Journal entry is not an object");
  }
  const entry = value as Record<string, unknown>;
  if (
    entry.format !== JOURNAL_FORMAT
    || entry.formatVersion !== JOURNAL_VERSION
    || entry.completionStatus !== "completed"
    || entry.sequence !== expectedSequence
    || entry.sourceRomSha256 !== source.sha256
    || typeof entry.operationId !== "string"
    || !isSha256(entry.operationId)
    || typeof entry.operation !== "string"
    || entry.operation.length === 0
    || !Array.isArray(entry.completedStages)
    || !Array.isArray(entry.artifactHashes)
    || !isSha256(entry.resultDigest)
    || typeof entry.recordedAt !== "string"
    || !isSha256(entry.entrySha256)
  ) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      `Investigation journal entry ${expectedSequence} has invalid required fields`,
    );
  }
  const { entrySha256, ...payload } = entry;
  if (sha256Text(canonicalJson(payload)) !== entrySha256) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      `Investigation journal entry ${expectedSequence} failed its integrity hash`,
    );
  }
  return entry as unknown as InvestigationJournalEntry;
}

function parseMetadata(
  source: InvestigationSourceIdentity,
  serialized: string,
): InvestigationJournalMetadata {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch (error) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      `Investigation metadata is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InvestigationJournalError("investigation-journal-integrity-failure", "Investigation metadata is not an object");
  }
  const metadata = value as Record<string, unknown>;
  const { contentSha256, ...payload } = metadata;
  if (
    metadata.format !== METADATA_FORMAT
    || metadata.formatVersion !== JOURNAL_VERSION
    || metadata.sourceRomSha256 !== source.sha256
    || metadata.sourceRomSha256Prefix !== source.sha256Prefix
    || !Number.isSafeInteger(metadata.entryCount)
    || (metadata.entryCount as number) < 0
    || metadata.lastSequence !== metadata.entryCount
    || !isSha256(metadata.journalSha256)
    || !isSha256(metadata.projectionSha256)
    || typeof metadata.updatedAt !== "string"
    || !isSha256(contentSha256)
    || sha256Text(canonicalJson(payload)) !== contentSha256
  ) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation metadata failed schema or integrity validation",
    );
  }
  return metadata as unknown as InvestigationJournalMetadata;
}

function parseProjection(
  source: InvestigationSourceIdentity,
  serialized: string,
): InvestigationCheckpointProjection {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch (error) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      `Investigation projection is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new InvestigationJournalError("investigation-journal-integrity-failure", "Investigation projection is not an object");
  }
  const projection = value as Record<string, unknown>;
  const { contentSha256, ...payload } = projection;
  if (
    projection.format !== PROJECTION_FORMAT
    || projection.formatVersion !== JOURNAL_VERSION
    || projection.authority !== "deterministic-investigation-state"
    || projection.sourceRomSha256 !== source.sha256
    || projection.sourceRomSha256Prefix !== source.sha256Prefix
    || !Number.isSafeInteger(projection.latestSequence)
    || (projection.latestSequence as number) < 0
    || !Array.isArray(projection.completedOperations)
    || !Array.isArray(projection.completedStages)
    || !Array.isArray(projection.artifactHashes)
    || !Array.isArray(projection.recommendedNextActions)
    || !isSha256(contentSha256)
    || sha256Text(canonicalJson(payload)) !== contentSha256
  ) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation projection failed schema or integrity validation",
    );
  }
  return projection as unknown as InvestigationCheckpointProjection;
}

function serializeJournal(entries: readonly InvestigationJournalEntry[]): string {
  if (entries.length === 0) return "";
  return `${entries.map((entry) => JSON.stringify(entry)).join("\n")}\n`;
}

async function writeAtomic(filePath: string, serialized: string): Promise<void> {
  const temporary = `${filePath}.tmp-${process.pid}-${Date.now()}`;
  await rm(temporary, { force: true });
  let handle;
  try {
    handle = await open(temporary, "wx", 0o600);
    await handle.writeFile(serialized, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, filePath);
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await rm(temporary, { force: true }).catch(() => undefined);
    throw new InvestigationJournalError(
      "investigation-journal-io-failure",
      `Unable to atomically persist investigation state: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export async function readInvestigationJournal(
  source: InvestigationSourceIdentity,
  workspaceRoot: string,
): Promise<{
  readonly entries: readonly InvestigationJournalEntry[];
  readonly metadata: InvestigationJournalMetadata | null;
  readonly projection: InvestigationCheckpointProjection | null;
}> {
  validateSource(source);
  const paths = journalPaths(source, workspaceRoot);
  await assertNoSymlinkSegments(workspaceRoot, paths.directory);
  const [journalText, metadataText, projectionText] = await Promise.all([
    readTextIfExists(paths.journal),
    readTextIfExists(paths.metadata),
    readTextIfExists(paths.projection),
  ]);
  if (journalText === null && metadataText === null && projectionText === null) {
    return { entries: [], metadata: null, projection: null };
  }
  if (journalText === null || metadataText === null || projectionText === null) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation persistence is incomplete: journal, metadata, and projection must exist together",
    );
  }
  if (Buffer.byteLength(journalText, "utf8") > MAX_JOURNAL_BYTES) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      `Investigation journal exceeds ${MAX_JOURNAL_BYTES} bytes`,
    );
  }
  const rawLines = journalText.split("\n").filter((line) => line.length > 0);
  if (rawLines.length > MAX_ENTRIES) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      `Investigation journal exceeds ${MAX_ENTRIES} entries`,
    );
  }
  const entries = rawLines.map((line, index) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line) as unknown;
    } catch (error) {
      throw new InvestigationJournalError(
        "investigation-journal-integrity-failure",
        `Investigation journal line ${index + 1} is invalid JSON: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    return parseEntry(source, parsed, index + 1);
  });
  const metadata = parseMetadata(source, metadataText);
  const projection = parseProjection(source, projectionText);
  if (metadata.entryCount !== entries.length) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation metadata entry count does not match the journal",
    );
  }
  if (metadata.journalSha256 !== sha256Text(journalText)) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation journal SHA-256 does not match metadata",
    );
  }
  if (metadata.projectionSha256 !== sha256Text(projectionText)) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation projection SHA-256 does not match metadata",
    );
  }
  if (projection.latestSequence !== entries.length) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation projection sequence does not match the journal",
    );
  }
  return { entries, metadata, projection };
}

export function projectInvestigationCheckpoint(
  source: InvestigationSourceIdentity,
  entries: readonly InvestigationJournalEntry[],
  recommendedNextAction: string | null,
): InvestigationCheckpointProjection {
  validateSource(source);
  const completedOperations = entries
    .slice(-MAX_PROJECTION_OPERATIONS)
    .map((entry) => ({
      sequence: entry.sequence,
      operationId: entry.operationId,
      operation: entry.operation,
      resultDigest: entry.resultDigest,
    }));
  const completedStages = [...new Set(entries.flatMap((entry) => entry.completedStages))].sort();
  const artifactMap = new Map<string, InvestigationArtifactHash>();
  for (const artifact of entries.flatMap((entry) => entry.artifactHashes)) {
    const key = `${artifact.kind}\u0000${artifact.path ?? ""}\u0000${artifact.sha256 ?? ""}`;
    artifactMap.set(key, artifact);
  }
  const artifacts = [...artifactMap.values()]
    .sort((left, right) =>
      left.kind.localeCompare(right.kind)
      || (left.path ?? "").localeCompare(right.path ?? "")
      || (left.sha256 ?? "").localeCompare(right.sha256 ?? ""))
    .slice(0, MAX_PROJECTION_ARTIFACTS);
  const nextActions = recommendedNextAction === null ? [] : [recommendedNextAction];
  const payload: ProjectionPayload = {
    format: PROJECTION_FORMAT,
    formatVersion: JOURNAL_VERSION,
    authority: "deterministic-investigation-state",
    sourceRomSha256: source.sha256,
    sourceRomSha256Prefix: source.sha256Prefix,
    latestSequence: entries.length,
    completedOperations,
    completedStages,
    artifactHashes: artifacts,
    recommendedNextActions: nextActions,
  };
  return withHash(payload, "contentSha256") as InvestigationCheckpointProjection;
}

export async function persistInvestigationResult(
  source: InvestigationSourceIdentity,
  workspaceRoot: string,
  input: InvestigationPersistenceInput,
): Promise<InvestigationPersistenceResult> {
  validateSource(source);
  if (input.operation.trim().length === 0) {
    throw new InvestigationJournalError(
      "investigation-journal-invalid-input",
      "Investigation operation must not be empty",
    );
  }
  const paths = journalPaths(source, workspaceRoot);
  await assertNoSymlinkSegments(workspaceRoot, paths.directory);
  await mkdir(paths.directory, { recursive: true });
  await assertNoSymlinkSegments(workspaceRoot, paths.directory);
  const current = await readInvestigationJournal(source, workspaceRoot);
  if (current.entries.length >= MAX_ENTRIES) {
    throw new InvestigationJournalError(
      "investigation-journal-io-failure",
      `Investigation journal cannot exceed ${MAX_ENTRIES} entries`,
    );
  }

  const sequence = current.entries.length + 1;
  const normalizedInputs = canonicalize(input.normalizedInputs);
  const resultDigest = sha256Text(canonicalJson(input.result));
  const operationId = sha256Text(canonicalJson({
    sourceRomSha256: source.sha256,
    sequence,
    operation: input.operation,
    normalizedInputs,
    resultDigest,
  }));
  const payload: EntryPayload = {
    format: JOURNAL_FORMAT,
    formatVersion: JOURNAL_VERSION,
    sequence,
    operationId,
    operation: input.operation,
    normalizedInputs,
    sourceRomSha256: source.sha256,
    completedStages: [...new Set(input.completedStages)].sort(),
    artifactHashes: artifactHashes(input.artifacts),
    resultDigest,
    completionStatus: "completed",
    recordedAt: new Date().toISOString(),
  };
  const entry = withHash(payload, "entrySha256") as InvestigationJournalEntry;
  const entries = [...current.entries, entry];
  const journalText = serializeJournal(entries);
  if (Buffer.byteLength(journalText, "utf8") > MAX_JOURNAL_BYTES) {
    throw new InvestigationJournalError(
      "investigation-journal-io-failure",
      `Serialized investigation journal exceeds ${MAX_JOURNAL_BYTES} bytes`,
    );
  }
  const projection = projectInvestigationCheckpoint(source, entries, input.recommendedNextAction);
  const projectionText = `${JSON.stringify(projection, null, 2)}\n`;
  const metadataPayload: MetadataPayload = {
    format: METADATA_FORMAT,
    formatVersion: JOURNAL_VERSION,
    sourceRomSha256: source.sha256,
    sourceRomSha256Prefix: source.sha256Prefix,
    entryCount: entries.length,
    lastSequence: entries.length,
    journalSha256: sha256Text(journalText),
    projectionSha256: sha256Text(projectionText),
    updatedAt: entry.recordedAt,
  };
  const metadata = withHash(metadataPayload, "contentSha256") as InvestigationJournalMetadata;
  const metadataText = `${JSON.stringify(metadata, null, 2)}\n`;

  await writeAtomic(paths.journal, journalText);
  await writeAtomic(paths.projection, projectionText);
  await writeAtomic(paths.metadata, metadataText);

  const verified = await readInvestigationJournal(source, workspaceRoot);
  const verifiedEntry = verified.entries.at(-1);
  if (
    verifiedEntry === undefined
    || verifiedEntry.operationId !== entry.operationId
    || verified.metadata?.contentSha256 !== metadata.contentSha256
  ) {
    throw new InvestigationJournalError(
      "investigation-journal-integrity-failure",
      "Investigation persistence failed read-back verification",
    );
  }

  return {
    entry: verifiedEntry,
    projection: verified.projection!,
    journalRelativePath: relativeWorkspacePath(workspaceRoot, paths.journal),
    projectionRelativePath: relativeWorkspacePath(workspaceRoot, paths.projection),
  };
}
