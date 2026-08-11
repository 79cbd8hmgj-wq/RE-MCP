import { createHash } from "node:crypto";
import { mkdir, open, readFile, rename, rm } from "node:fs/promises";
import path from "node:path";

import { resolveInside } from "../../security/paths.js";
import type { ReArtifactReference, ReEvidenceEnvelope } from "./types.js";

const RESUME_FORMAT = "re-mcp-investigation-resume-state" as const;
const RESUME_VERSION = 1 as const;
const MAX_RESUME_ARTIFACT_BYTES = 128 * 1024;
const MAX_CANDIDATES = 64;
const MAX_AMBIGUITIES = 64;

export interface InvestigationResumeArtifact {
  readonly format: typeof RESUME_FORMAT;
  readonly formatVersion: typeof RESUME_VERSION;
  readonly authority: "deterministic-resume-state";
  readonly sourceRomSha256: string;
  readonly operation: string;
  readonly component: unknown;
  readonly subject: unknown;
  readonly candidates: readonly unknown[];
  readonly ambiguities: readonly unknown[];
  readonly completedPrimitiveStages: readonly string[];
  readonly recommendedNextAction: string | null;
  readonly contentSha256: string;
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function scalarRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return {};
  const record = value as Record<string, unknown>;
  const compact: Record<string, unknown> = {};
  for (const key of keys) {
    const item = record[key];
    if (
      item === null
      || typeof item === "string"
      || typeof item === "boolean"
      || (typeof item === "number" && Number.isFinite(item))
    ) {
      compact[key] = item;
    }
  }
  return compact;
}

function compactReference(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  return {
    ...scalarRecord(record, ["kind"]),
    source: scalarRecord(record.source, [
      "functionId",
      "component",
      "overlayId",
      "instructionAddress",
      "instructionRomOffset",
      "mode",
    ]),
    target: scalarRecord(record.target, [
      "runtimeAddress",
      "romOffset",
      "component",
      "overlayId",
      "kind",
    ]),
  };
}

function compactCandidate(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  const record = value as Record<string, unknown>;
  const compact: Record<string, unknown> = scalarRecord(record, [
    "kind",
    "callerFunctionId",
    "component",
    "overlayId",
    "instructionAddress",
    "instructionRomOffset",
    "mode",
    "authority",
  ]);
  if ("reference" in record) compact.reference = compactReference(record.reference);
  return compact;
}

function compactAmbiguity(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  const record = value as Record<string, unknown>;
  const compact: Record<string, unknown> = scalarRecord(record, ["kind", "detail"]);
  if (Array.isArray(record.candidates)) {
    compact.candidates = record.candidates.slice(0, MAX_CANDIDATES).map(compactCandidate);
  }
  return compact;
}

function payloadFor(result: ReEvidenceEnvelope): Omit<InvestigationResumeArtifact, "contentSha256"> {
  return {
    format: RESUME_FORMAT,
    formatVersion: RESUME_VERSION,
    authority: "deterministic-resume-state",
    sourceRomSha256: result.sourceRomSha256,
    operation: result.operation,
    component: result.component,
    subject: result.subject,
    candidates: result.candidates.slice(0, MAX_CANDIDATES).map(compactCandidate),
    ambiguities: result.ambiguities.slice(0, MAX_AMBIGUITIES).map(compactAmbiguity),
    completedPrimitiveStages: [...result.completedPrimitiveStages],
    recommendedNextAction: result.recommendedNextAction,
  };
}

function serializePayload(payload: Omit<InvestigationResumeArtifact, "contentSha256">): InvestigationResumeArtifact {
  const contentSha256 = sha256Text(JSON.stringify(payload));
  return { ...payload, contentSha256 };
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
    throw error;
  }
}

function relativeWorkspacePath(workspaceRoot: string, target: string): string {
  return path.relative(path.resolve(workspaceRoot), target).split(path.sep).join("/");
}

export async function persistInvestigationResumeArtifact(
  source: { readonly sha256: string; readonly sha256Prefix: string },
  workspaceRoot: string,
  result: ReEvidenceEnvelope,
): Promise<ReArtifactReference> {
  if (result.sourceRomSha256 !== source.sha256) {
    throw new Error("Resume artifact source SHA-256 does not match the high-level operation result");
  }
  const artifact = serializePayload(payloadFor(result));
  const serialized = `${JSON.stringify(artifact, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_RESUME_ARTIFACT_BYTES) {
    throw new Error(`Resume artifact exceeds ${MAX_RESUME_ARTIFACT_BYTES} bytes`);
  }
  const directory = resolveInside(
    workspaceRoot,
    path.join("analysis", "generated", "nds", source.sha256Prefix, "controller", "investigation-results"),
  );
  await mkdir(directory, { recursive: true });
  const destination = path.join(directory, `${artifact.contentSha256}.json`);
  await writeAtomic(destination, serialized);
  const verifiedText = await readFile(destination, "utf8");
  if (sha256Text(verifiedText) !== sha256Text(serialized)) {
    throw new Error("Resume artifact read-back verification failed");
  }
  return {
    kind: "re-resume-state",
    path: relativeWorkspacePath(workspaceRoot, destination),
    sha256: sha256Text(serialized),
  };
}

export async function readInvestigationResumeArtifact(
  workspaceRoot: string,
  artifact: { readonly path: string; readonly sha256: string },
): Promise<InvestigationResumeArtifact> {
  const absolutePath = resolveInside(workspaceRoot, artifact.path);
  const serialized = await readFile(absolutePath, "utf8");
  if (sha256Text(serialized) !== artifact.sha256) {
    throw new Error(`Resume artifact SHA-256 mismatch: ${artifact.path}`);
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_RESUME_ARTIFACT_BYTES) {
    throw new Error(`Resume artifact exceeds ${MAX_RESUME_ARTIFACT_BYTES} bytes`);
  }
  const parsed = JSON.parse(serialized) as InvestigationResumeArtifact;
  if (
    parsed.format !== RESUME_FORMAT
    || parsed.formatVersion !== RESUME_VERSION
    || parsed.authority !== "deterministic-resume-state"
    || !/^[0-9a-f]{64}$/.test(parsed.sourceRomSha256)
    || !/^[0-9a-f]{64}$/.test(parsed.contentSha256)
  ) {
    throw new Error(`Resume artifact has invalid format: ${artifact.path}`);
  }
  const { contentSha256, ...payload } = parsed;
  if (sha256Text(JSON.stringify(payload)) !== contentSha256) {
    throw new Error(`Resume artifact content integrity mismatch: ${artifact.path}`);
  }
  return parsed;
}
