import { createHash } from "node:crypto";
import { mkdir, open, readFile, rename, rm, stat } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import { resolveInside } from "../security/paths.js";
import { hashFileSha256 } from "./nds/io.js";

const MAX_CHECKPOINT_BYTES = 1024 * 1024;
const MAX_ENTRIES_PER_COLLECTION = 128;
const MAX_EVIDENCE_REFS_PER_ENTRY = 16;
const MAX_TOTAL_EVIDENCE_REFS = 256;

export type ControllerCheckpointErrorCategory =
  | "checkpoint-invalid-state"
  | "checkpoint-evidence-path-invalid"
  | "checkpoint-evidence-missing"
  | "checkpoint-evidence-sha-mismatch"
  | "checkpoint-revision-conflict"
  | "checkpoint-lock-conflict"
  | "checkpoint-integrity-failure"
  | "checkpoint-io-failure";

export class ControllerCheckpointError extends Error {
  readonly category: ControllerCheckpointErrorCategory;

  constructor(category: ControllerCheckpointErrorCategory, message: string) {
    super(message);
    this.name = "ControllerCheckpointError";
    this.category = category;
  }
}

export interface ControllerCheckpointSource {
  readonly sha256: string;
  readonly sha256Prefix: string;
}

export interface ControllerEvidenceRefInput {
  readonly path: string;
  readonly expectedSha256?: string;
}

export interface ControllerEvidenceRef {
  readonly path: string;
  readonly sha256: string;
}

export interface ControllerCheckpointFindingInput {
  readonly id: string;
  readonly statement: string;
  readonly evidenceRefs: readonly ControllerEvidenceRefInput[];
}

export interface ControllerCheckpointCompletedActionInput {
  readonly id: string;
  readonly description: string;
  readonly outcome: "completed" | "failed";
  readonly evidenceRefs: readonly ControllerEvidenceRefInput[];
}

export interface ControllerCheckpointNextActionInput {
  readonly id: string;
  readonly description: string;
}

export interface ControllerCheckpointStateInput {
  readonly objective: string;
  readonly confirmedFacts: readonly ControllerCheckpointFindingInput[];
  readonly hypotheses: readonly ControllerCheckpointFindingInput[];
  readonly completedActions: readonly ControllerCheckpointCompletedActionInput[];
  readonly nextActions: readonly ControllerCheckpointNextActionInput[];
}

export interface ControllerCheckpointFinding {
  readonly id: string;
  readonly statement: string;
  readonly evidenceRefs: readonly ControllerEvidenceRef[];
}

export interface ControllerCheckpointCompletedAction {
  readonly id: string;
  readonly description: string;
  readonly outcome: "completed" | "failed";
  readonly evidenceRefs: readonly ControllerEvidenceRef[];
}

export interface ControllerCheckpointNextAction {
  readonly id: string;
  readonly description: string;
}

export interface ControllerCheckpoint {
  readonly formatVersion: 1;
  readonly authority: "controller-state-only";
  readonly sourceRomSha256: string;
  readonly sourceRomSha256Prefix: string;
  readonly revision: number;
  readonly objective: string;
  readonly confirmedFacts: readonly ControllerCheckpointFinding[];
  readonly hypotheses: readonly ControllerCheckpointFinding[];
  readonly completedActions: readonly ControllerCheckpointCompletedAction[];
  readonly nextActions: readonly ControllerCheckpointNextAction[];
  readonly contentSha256: string;
}

export type ControllerCheckpointReadResult =
  | {
      readonly exists: false;
      readonly expectedRevision: 0;
      readonly sourceRomSha256: string;
      readonly sourceRomSha256Prefix: string;
      readonly relativePath: string;
    }
  | {
      readonly exists: true;
      readonly expectedRevision: number;
      readonly sourceRomSha256: string;
      readonly sourceRomSha256Prefix: string;
      readonly relativePath: string;
      readonly checkpoint: ControllerCheckpoint;
    };

const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const idSchema = z.string().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/);
const textSchema = z.string().min(1).max(4000).refine((value) => value.trim().length > 0);
const evidencePathSchema = z.string().min(1).max(512);
const evidenceInputSchema = z.object({
  path: evidencePathSchema,
  expectedSha256: sha256Schema.optional(),
}).strict();
const evidenceSchema = z.object({
  path: evidencePathSchema,
  sha256: sha256Schema,
}).strict();
const findingInputSchema = z.object({
  id: idSchema,
  statement: textSchema,
  evidenceRefs: z.array(evidenceInputSchema).max(MAX_EVIDENCE_REFS_PER_ENTRY),
}).strict();
const completedActionInputSchema = z.object({
  id: idSchema,
  description: textSchema,
  outcome: z.enum(["completed", "failed"]),
  evidenceRefs: z.array(evidenceInputSchema).max(MAX_EVIDENCE_REFS_PER_ENTRY),
}).strict();
const nextActionInputSchema = z.object({
  id: idSchema,
  description: textSchema,
}).strict();
const stateInputSchema = z.object({
  objective: textSchema,
  confirmedFacts: z.array(findingInputSchema).max(MAX_ENTRIES_PER_COLLECTION),
  hypotheses: z.array(findingInputSchema).max(MAX_ENTRIES_PER_COLLECTION),
  completedActions: z.array(completedActionInputSchema).max(MAX_ENTRIES_PER_COLLECTION),
  nextActions: z.array(nextActionInputSchema).max(MAX_ENTRIES_PER_COLLECTION),
}).strict();
const findingSchema = z.object({
  id: idSchema,
  statement: textSchema,
  evidenceRefs: z.array(evidenceSchema).max(MAX_EVIDENCE_REFS_PER_ENTRY),
}).strict();
const completedActionSchema = z.object({
  id: idSchema,
  description: textSchema,
  outcome: z.enum(["completed", "failed"]),
  evidenceRefs: z.array(evidenceSchema).max(MAX_EVIDENCE_REFS_PER_ENTRY),
}).strict();
const nextActionSchema = z.object({
  id: idSchema,
  description: textSchema,
}).strict();
const checkpointPayloadSchema = z.object({
  formatVersion: z.literal(1),
  authority: z.literal("controller-state-only"),
  sourceRomSha256: sha256Schema,
  sourceRomSha256Prefix: z.string().regex(/^[0-9a-f]{8,64}$/),
  revision: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
  objective: textSchema,
  confirmedFacts: z.array(findingSchema).max(MAX_ENTRIES_PER_COLLECTION),
  hypotheses: z.array(findingSchema).max(MAX_ENTRIES_PER_COLLECTION),
  completedActions: z.array(completedActionSchema).max(MAX_ENTRIES_PER_COLLECTION),
  nextActions: z.array(nextActionSchema).max(MAX_ENTRIES_PER_COLLECTION),
}).strict();
const checkpointSchema = checkpointPayloadSchema.extend({
  contentSha256: sha256Schema,
}).strict();

type ParsedStateInput = z.infer<typeof stateInputSchema>;
type StoredPayload = z.infer<typeof checkpointPayloadSchema>;

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error;
}

function relativeWorkspacePath(workspaceRoot: string, absolutePath: string): string {
  return path.relative(path.resolve(workspaceRoot), absolutePath).split(path.sep).join("/");
}

function validateSource(source: ControllerCheckpointSource): void {
  if (!/^[0-9a-f]{64}$/.test(source.sha256)) {
    throw new ControllerCheckpointError(
      "checkpoint-integrity-failure",
      "Controller checkpoint source SHA-256 is invalid",
    );
  }
  if (
    !/^[0-9a-f]{8,64}$/.test(source.sha256Prefix)
    || !source.sha256.startsWith(source.sha256Prefix)
  ) {
    throw new ControllerCheckpointError(
      "checkpoint-integrity-failure",
      "Controller checkpoint source SHA-256 prefix is inconsistent with the exact source identity",
    );
  }
}

function controllerDirectory(source: ControllerCheckpointSource, workspaceRoot: string): string {
  validateSource(source);
  return resolveInside(
    workspaceRoot,
    path.join("analysis", "generated", "nds", source.sha256Prefix, "controller"),
  );
}

export function controllerCheckpointPath(
  source: ControllerCheckpointSource,
  workspaceRoot: string,
): string {
  return path.join(controllerDirectory(source, workspaceRoot), "checkpoint.json");
}

function isInside(root: string, target: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(target));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function hashPayload(payload: StoredPayload): string {
  return createHash("sha256").update(JSON.stringify(payload), "utf8").digest("hex");
}

function assertUniqueIds(state: ParsedStateInput): void {
  const seen = new Set<string>();
  for (const entry of [
    ...state.confirmedFacts,
    ...state.hypotheses,
    ...state.completedActions,
    ...state.nextActions,
  ]) {
    if (seen.has(entry.id)) {
      throw new ControllerCheckpointError(
        "checkpoint-invalid-state",
        `Controller checkpoint ID is duplicated: ${entry.id}`,
      );
    }
    seen.add(entry.id);
  }
}

function countEvidenceRefs(state: ParsedStateInput): number {
  return [...state.confirmedFacts, ...state.hypotheses, ...state.completedActions]
    .reduce((total, entry) => total + entry.evidenceRefs.length, 0);
}

function parseState(input: ControllerCheckpointStateInput): ParsedStateInput {
  const parsed = stateInputSchema.safeParse(input);
  if (!parsed.success) {
    throw new ControllerCheckpointError(
      "checkpoint-invalid-state",
      `Controller checkpoint state is invalid: ${parsed.error.issues[0]?.message ?? "unknown validation error"}`,
    );
  }
  assertUniqueIds(parsed.data);
  if (countEvidenceRefs(parsed.data) > MAX_TOTAL_EVIDENCE_REFS) {
    throw new ControllerCheckpointError(
      "checkpoint-invalid-state",
      `Controller checkpoint exceeds ${MAX_TOTAL_EVIDENCE_REFS} total evidence references`,
    );
  }
  return parsed.data;
}

function evidenceRoots(source: ControllerCheckpointSource, workspaceRoot: string): readonly string[] {
  return [
    resolveInside(
      workspaceRoot,
      path.join("analysis", "generated", "nds", source.sha256Prefix),
    ),
    resolveInside(
      workspaceRoot,
      path.join("output", "nds", source.sha256Prefix),
    ),
  ];
}

async function bindEvidenceRef(
  source: ControllerCheckpointSource,
  workspaceRoot: string,
  input: z.infer<typeof evidenceInputSchema>,
): Promise<ControllerEvidenceRef> {
  let absolutePath: string;
  try {
    absolutePath = resolveInside(workspaceRoot, input.path);
  } catch (error) {
    throw new ControllerCheckpointError(
      "checkpoint-evidence-path-invalid",
      `Controller checkpoint evidence path escapes the workspace: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const roots = evidenceRoots(source, workspaceRoot);
  if (!roots.some((root) => isInside(root, absolutePath))) {
    throw new ControllerCheckpointError(
      "checkpoint-evidence-path-invalid",
      "Controller checkpoint evidence must be inside the exact source-SHA analysis/generated/nds or output/nds namespace",
    );
  }
  if (isInside(controllerDirectory(source, workspaceRoot), absolutePath)) {
    throw new ControllerCheckpointError(
      "checkpoint-evidence-path-invalid",
      "Controller checkpoint files, locks, and temporary files cannot be referenced as evidence",
    );
  }

  let metadata;
  try {
    metadata = await stat(absolutePath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new ControllerCheckpointError(
        "checkpoint-evidence-missing",
        `Controller checkpoint evidence file does not exist: ${input.path}`,
      );
    }
    throw new ControllerCheckpointError(
      "checkpoint-io-failure",
      `Unable to inspect controller checkpoint evidence: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!metadata.isFile()) {
    throw new ControllerCheckpointError(
      "checkpoint-evidence-path-invalid",
      `Controller checkpoint evidence must be a regular file: ${input.path}`,
    );
  }

  let sha256: string;
  try {
    sha256 = await hashFileSha256(absolutePath);
  } catch (error) {
    throw new ControllerCheckpointError(
      "checkpoint-io-failure",
      `Unable to hash controller checkpoint evidence: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (input.expectedSha256 !== undefined && input.expectedSha256 !== sha256) {
    throw new ControllerCheckpointError(
      "checkpoint-evidence-sha-mismatch",
      `Controller checkpoint evidence SHA-256 mismatch for ${input.path}`,
    );
  }
  return {
    path: relativeWorkspacePath(workspaceRoot, absolutePath),
    sha256,
  };
}

async function bindEvidenceRefs(
  source: ControllerCheckpointSource,
  workspaceRoot: string,
  refs: readonly z.infer<typeof evidenceInputSchema>[],
): Promise<ControllerEvidenceRef[]> {
  const result: ControllerEvidenceRef[] = [];
  for (const ref of refs) {
    result.push(await bindEvidenceRef(source, workspaceRoot, ref));
  }
  return result;
}

async function bindState(
  source: ControllerCheckpointSource,
  workspaceRoot: string,
  state: ParsedStateInput,
): Promise<Omit<StoredPayload, "formatVersion" | "authority" | "sourceRomSha256" | "sourceRomSha256Prefix" | "revision">> {
  const confirmedFacts: StoredPayload["confirmedFacts"] = [];
  for (const entry of state.confirmedFacts) {
    confirmedFacts.push({
      id: entry.id,
      statement: entry.statement,
      evidenceRefs: await bindEvidenceRefs(source, workspaceRoot, entry.evidenceRefs),
    });
  }
  const hypotheses: StoredPayload["hypotheses"] = [];
  for (const entry of state.hypotheses) {
    hypotheses.push({
      id: entry.id,
      statement: entry.statement,
      evidenceRefs: await bindEvidenceRefs(source, workspaceRoot, entry.evidenceRefs),
    });
  }
  const completedActions: StoredPayload["completedActions"] = [];
  for (const entry of state.completedActions) {
    completedActions.push({
      id: entry.id,
      description: entry.description,
      outcome: entry.outcome,
      evidenceRefs: await bindEvidenceRefs(source, workspaceRoot, entry.evidenceRefs),
    });
  }
  const nextActions: StoredPayload["nextActions"] = state.nextActions.map((entry) => ({
    id: entry.id,
    description: entry.description,
  }));
  return {
    objective: state.objective,
    confirmedFacts,
    hypotheses,
    completedActions,
    nextActions,
  };
}

function parseStoredCheckpoint(
  source: ControllerCheckpointSource,
  serialized: string,
): ControllerCheckpoint {
  if (Buffer.byteLength(serialized, "utf8") > MAX_CHECKPOINT_BYTES) {
    throw new ControllerCheckpointError(
      "checkpoint-integrity-failure",
      `Controller checkpoint exceeds ${MAX_CHECKPOINT_BYTES} bytes`,
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch (error) {
    throw new ControllerCheckpointError(
      "checkpoint-integrity-failure",
      `Controller checkpoint is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const parsed = checkpointSchema.safeParse(raw);
  if (!parsed.success) {
    throw new ControllerCheckpointError(
      "checkpoint-integrity-failure",
      `Controller checkpoint schema is invalid: ${parsed.error.issues[0]?.message ?? "unknown validation error"}`,
    );
  }
  const checkpoint = parsed.data;
  if (
    checkpoint.sourceRomSha256 !== source.sha256
    || checkpoint.sourceRomSha256Prefix !== source.sha256Prefix
  ) {
    throw new ControllerCheckpointError(
      "checkpoint-integrity-failure",
      "Controller checkpoint source identity does not match the current exact ROM",
    );
  }

  const { contentSha256, ...payload } = checkpoint;
  if (hashPayload(payload) !== contentSha256) {
    throw new ControllerCheckpointError(
      "checkpoint-integrity-failure",
      "Controller checkpoint content SHA-256 does not match the canonical payload",
    );
  }
  return checkpoint;
}

async function readCheckpointFile(
  source: ControllerCheckpointSource,
  checkpointPath: string,
): Promise<ControllerCheckpoint | null> {
  let serialized: string;
  try {
    serialized = await readFile(checkpointPath, "utf8");
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") return null;
    throw new ControllerCheckpointError(
      "checkpoint-io-failure",
      `Unable to read controller checkpoint: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return parseStoredCheckpoint(source, serialized);
}

export async function readControllerCheckpoint(
  source: ControllerCheckpointSource,
  workspaceRoot: string,
): Promise<ControllerCheckpointReadResult> {
  validateSource(source);
  const checkpointPath = controllerCheckpointPath(source, workspaceRoot);
  const relativePath = relativeWorkspacePath(workspaceRoot, checkpointPath);
  const checkpoint = await readCheckpointFile(source, checkpointPath);
  if (checkpoint === null) {
    return {
      exists: false,
      expectedRevision: 0,
      sourceRomSha256: source.sha256,
      sourceRomSha256Prefix: source.sha256Prefix,
      relativePath,
    };
  }
  return {
    exists: true,
    expectedRevision: checkpoint.revision,
    sourceRomSha256: source.sha256,
    sourceRomSha256Prefix: source.sha256Prefix,
    relativePath,
    checkpoint,
  };
}

async function writeCheckpointAtomic(checkpointPath: string, checkpoint: ControllerCheckpoint): Promise<void> {
  const serialized = `${JSON.stringify(checkpoint, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_CHECKPOINT_BYTES) {
    throw new ControllerCheckpointError(
      "checkpoint-invalid-state",
      `Serialized controller checkpoint exceeds ${MAX_CHECKPOINT_BYTES} bytes`,
    );
  }

  const temporaryPath = `${checkpointPath}.tmp-${process.pid}`;
  await rm(temporaryPath, { force: true });
  let handle;
  try {
    handle = await open(temporaryPath, "wx", 0o600);
    await handle.writeFile(serialized, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, checkpointPath);
  } catch (error) {
    if (handle !== undefined) {
      try {
        await handle.close();
      } catch {
        // Best-effort close before cleanup.
      }
    }
    await rm(temporaryPath, { force: true }).catch(() => undefined);
    if (error instanceof ControllerCheckpointError) throw error;
    throw new ControllerCheckpointError(
      "checkpoint-io-failure",
      `Unable to atomically write controller checkpoint: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export async function writeControllerCheckpoint(
  source: ControllerCheckpointSource,
  workspaceRoot: string,
  expectedRevision: number,
  stateInput: ControllerCheckpointStateInput,
): Promise<ControllerCheckpoint> {
  validateSource(source);
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new ControllerCheckpointError(
      "checkpoint-invalid-state",
      "Controller checkpoint expectedRevision must be a non-negative safe integer",
    );
  }

  const state = parseState(stateInput);
  const boundState = await bindState(source, workspaceRoot, state);
  const checkpointPath = controllerCheckpointPath(source, workspaceRoot);
  const directory = path.dirname(checkpointPath);
  const lockPath = path.join(directory, "checkpoint.lock");

  try {
    await mkdir(directory, { recursive: true });
  } catch (error) {
    throw new ControllerCheckpointError(
      "checkpoint-io-failure",
      `Unable to create controller checkpoint directory: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  let lockHandle;
  try {
    lockHandle = await open(lockPath, "wx", 0o600);
  } catch (error) {
    if (isNodeError(error) && error.code === "EEXIST") {
      throw new ControllerCheckpointError(
        "checkpoint-lock-conflict",
        "Controller checkpoint is locked by another writer or a stale fail-closed lock",
      );
    }
    throw new ControllerCheckpointError(
      "checkpoint-io-failure",
      `Unable to acquire controller checkpoint lock: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  try {
    const existing = await readCheckpointFile(source, checkpointPath);
    const currentRevision = existing?.revision ?? 0;
    if (currentRevision !== expectedRevision) {
      throw new ControllerCheckpointError(
        "checkpoint-revision-conflict",
        `Controller checkpoint revision conflict: expected ${expectedRevision}, current ${currentRevision}`,
      );
    }
    if (currentRevision >= Number.MAX_SAFE_INTEGER) {
      throw new ControllerCheckpointError(
        "checkpoint-revision-conflict",
        "Controller checkpoint revision cannot be advanced safely",
      );
    }

    const payload: StoredPayload = {
      formatVersion: 1,
      authority: "controller-state-only",
      sourceRomSha256: source.sha256,
      sourceRomSha256Prefix: source.sha256Prefix,
      revision: currentRevision + 1,
      objective: boundState.objective,
      confirmedFacts: boundState.confirmedFacts,
      hypotheses: boundState.hypotheses,
      completedActions: boundState.completedActions,
      nextActions: boundState.nextActions,
    };
    const checkpoint: ControllerCheckpoint = {
      ...payload,
      contentSha256: hashPayload(payload),
    };
    await writeCheckpointAtomic(checkpointPath, checkpoint);

    const verified = await readCheckpointFile(source, checkpointPath);
    if (verified === null || verified.contentSha256 !== checkpoint.contentSha256) {
      throw new ControllerCheckpointError(
        "checkpoint-integrity-failure",
        "Controller checkpoint read-back verification failed",
      );
    }
    return verified;
  } finally {
    try {
      await lockHandle.close();
    } finally {
      await rm(lockPath, { force: true }).catch(() => undefined);
    }
  }
}
