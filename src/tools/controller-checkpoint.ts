import path from "node:path";

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import type { ServerConfig } from "../config.js";
import { resolveInside } from "../security/paths.js";
import {
  ControllerCheckpointError,
  controllerCheckpointPath,
  readControllerCheckpoint,
  writeControllerCheckpoint,
  type ControllerCheckpointErrorCategory,
  type ControllerCheckpointStateInput,
} from "../services/controller-checkpoint.js";
import { NdsError } from "../services/nds/errors.js";
import { readNdsRomMap } from "../services/nds/rom-map.js";

const romSchema = z.string().min(1);
const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
const idSchema = z.string().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/);
const textSchema = z.string().min(1).max(4000).refine((value) => value.trim().length > 0);
const evidenceSchema = z.object({
  path: z.string().min(1).max(512),
  expectedSha256: sha256Schema.optional(),
}).strict();
const findingSchema = z.object({
  id: idSchema,
  statement: textSchema,
  evidenceRefs: z.array(evidenceSchema).max(16),
}).strict();
const completedActionSchema = z.object({
  id: idSchema,
  description: textSchema,
  outcome: z.enum(["completed", "failed"]),
  evidenceRefs: z.array(evidenceSchema).max(16),
}).strict();
const nextActionSchema = z.object({
  id: idSchema,
  description: textSchema,
}).strict();
const stateSchema = z.object({
  objective: textSchema,
  confirmedFacts: z.array(findingSchema).max(128),
  hypotheses: z.array(findingSchema).max(128),
  completedActions: z.array(completedActionSchema).max(128),
  nextActions: z.array(nextActionSchema).max(128),
}).strict();

function textResultFromText(text: string, isError = false) {
  return {
    content: [{ type: "text" as const, text }],
    isError,
  };
}

function textResult(value: unknown, isError = false) {
  return textResultFromText(JSON.stringify(value, null, 2), isError);
}

function boundedTextResult(
  config: ServerConfig,
  operation: string,
  value: unknown,
  isError = false,
) {
  const text = JSON.stringify(value, null, 2);
  if (!isError && Buffer.byteLength(text, "utf8") > config.maxOutputBytes) {
    return textResult({
      error: "Serialized controller checkpoint result exceeds RE_MCP_MAX_OUTPUT_BYTES",
      operation,
      category: "output-bound-exceeded",
      correctiveAction:
        "Reduce checkpoint state size before retrying; do not bypass RE_MCP_MAX_OUTPUT_BYTES.",
    }, true);
  }
  return textResultFromText(text, isError);
}

function correctiveAction(category: ControllerCheckpointErrorCategory | "invalid-rom"): string {
  switch (category) {
    case "invalid-rom":
      return "Use a readable Nintendo DS ROM path inside RE_MCP_WORKSPACE_ROOT and retry; checkpoint identity is derived from the current exact ROM SHA-256.";
    case "checkpoint-invalid-state":
      return "Provide bounded controller state with simple unique IDs and no arbitrary metadata, transcript, chain-of-thought, secret, or output-path fields.";
    case "checkpoint-evidence-path-invalid":
      return "Reference only regular files inside the exact ROM SHA-scoped analysis/generated/nds or output/nds evidence roots; controller checkpoint files cannot reference themselves.";
    case "checkpoint-evidence-missing":
      return "Regenerate or locate the referenced RE-MCP evidence artifact inside the exact source-SHA namespace, then write the checkpoint again.";
    case "checkpoint-evidence-sha-mismatch":
      return "Revalidate the referenced evidence artifact and use its current exact SHA-256; do not accept a changed artifact silently.";
    case "checkpoint-revision-conflict":
      return "Read the current controller checkpoint, merge/reconcile the newer state, then retry with its returned expectedRevision.";
    case "checkpoint-lock-conflict":
      return "Another checkpoint writer or a stale fail-closed lock exists; do not bypass it. Finish the active writer or inspect the controlled controller directory before retrying.";
    case "checkpoint-integrity-failure":
      return "Treat the checkpoint as untrusted/tampered, revalidate consequential facts through RE-MCP, and create a new valid handoff state only after resolving the corrupted artifact.";
    case "checkpoint-io-failure":
      return "Check workspace permissions/storage and retry; controller checkpoint writes remain restricted to the exact ROM SHA-scoped generated directory.";
  }
}

function checkpointErrorResult(
  config: ServerConfig,
  operation: string,
  error: unknown,
) {
  const category: ControllerCheckpointErrorCategory | "invalid-rom" =
    error instanceof ControllerCheckpointError
      ? error.category
      : error instanceof NdsError
        ? "invalid-rom"
        : "invalid-rom";
  const message = error instanceof Error ? error.message : String(error);
  return boundedTextResult(config, operation, {
    error: message,
    operation,
    category,
    correctiveAction: correctiveAction(category),
  }, true);
}

function relativeWorkspacePath(config: ServerConfig, absolutePath: string): string {
  return path.relative(config.workspaceRoot, absolutePath).split(path.sep).join("/");
}

async function readMap(config: ServerConfig, rom: string) {
  const romPath = resolveInside(config.workspaceRoot, rom);
  return await readNdsRomMap(romPath);
}

export function registerControllerCheckpointTools(
  server: McpServer,
  config: ServerConfig,
): void {
  server.tool(
    "controller_checkpoint_read",
    "Read the integrity-checked provider-neutral controller handoff state for the current exact NDS ROM SHA. Checkpoint prose is controller state, not authoritative ROM evidence.",
    { rom: romSchema },
    async ({ rom }) => {
      const operation = "controller_checkpoint_read";
      try {
        const map = await readMap(config, rom);
        const result = await readControllerCheckpoint(map, config.workspaceRoot);
        return boundedTextResult(config, operation, result);
      } catch (error) {
        return checkpointErrorResult(config, operation, error);
      }
    },
  );

  server.tool(
    "controller_checkpoint_write",
    "Atomically write bounded provider-neutral controller handoff state for the current exact NDS ROM SHA using optimistic revision protection. The output path is RE-MCP-owned.",
    {
      rom: romSchema,
      expectedRevision: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
      state: stateSchema,
    },
    async ({ rom, expectedRevision, state }) => {
      const operation = "controller_checkpoint_write";
      try {
        const map = await readMap(config, rom);
        const checkpoint = await writeControllerCheckpoint(
          map,
          config.workspaceRoot,
          expectedRevision,
          state as ControllerCheckpointStateInput,
        );
        return boundedTextResult(config, operation, {
          authority: checkpoint.authority,
          sourceRomSha256: checkpoint.sourceRomSha256,
          sourceRomSha256Prefix: checkpoint.sourceRomSha256Prefix,
          revision: checkpoint.revision,
          relativePath: relativeWorkspacePath(
            config,
            controllerCheckpointPath(map, config.workspaceRoot),
          ),
          contentSha256: checkpoint.contentSha256,
        });
      } catch (error) {
        return checkpointErrorResult(config, operation, error);
      }
    },
  );
}
