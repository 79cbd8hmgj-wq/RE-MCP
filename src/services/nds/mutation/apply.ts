import { createHash } from "node:crypto";
import { open as nativeOpen } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";

import { NdsError } from "../errors.js";
import type { GuardedNdsMutationOperation } from "./guards.js";
import {
  isNdsResolvedMutationPlanV2,
  type NdsResolvedMutationPlan,
  type NdsResolvedMutationPlanV2,
} from "./planner.js";
import type { NdsMutationStage } from "./staging.js";

const COPY_CHUNK_BYTES = 64 * 1024;

export interface NdsMutationApplyIo {
  open(filePath: string, flags: "r" | "r+"): Promise<FileHandle>;
}

const defaultApplyIo: NdsMutationApplyIo = {
  open: nativeOpen,
};

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function writeAll(
  handle: FileHandle,
  bytes: Uint8Array,
  position: number,
): Promise<void> {
  let written = 0;
  while (written < bytes.length) {
    const result = await handle.write(
      bytes,
      written,
      bytes.length - written,
      position + written,
    );
    if (result.bytesWritten < 1) {
      throw new Error("staged ROM write made no progress");
    }
    written += result.bytesWritten;
  }
}

async function applyByteOperation(
  stagedHandle: FileHandle,
  operation: Extract<GuardedNdsMutationOperation, { readonly type: "replace-bytes" }>,
): Promise<void> {
  await writeAll(
    stagedHandle,
    Buffer.from(operation.replacement, "hex"),
    operation.romStart,
  );
}

async function applyComponentOperation(
  stagedHandle: FileHandle,
  operation: Extract<GuardedNdsMutationOperation, { readonly type: "replace-component" }>,
  io: NdsMutationApplyIo,
): Promise<void> {
  const artifactHandle = await io.open(operation.replacement.absolutePath, "r");
  try {
    let copied = 0;
    while (copied < operation.size) {
      const length = Math.min(COPY_CHUNK_BYTES, operation.size - copied);
      const buffer = Buffer.alloc(length);
      let filled = 0;
      while (filled < length) {
        const { bytesRead } = await artifactHandle.read(
          buffer,
          filled,
          length - filled,
          copied + filled,
        );
        if (bytesRead < 1) {
          throw new Error(
            `replacement artifact ended after ${copied + filled} of ${operation.size} bytes`,
          );
        }
        filled += bytesRead;
      }
      await writeAll(stagedHandle, buffer, operation.romStart + copied);
      copied += length;
    }
  } finally {
    await artifactHandle.close();
  }
}

async function applyGuardedOperation(
  stagedHandle: FileHandle,
  operation: GuardedNdsMutationOperation,
  io: NdsMutationApplyIo,
): Promise<void> {
  if (operation.type === "replace-bytes") {
    await applyByteOperation(stagedHandle, operation);
  } else {
    await applyComponentOperation(stagedHandle, operation, io);
  }
}

async function applyV1Plan(
  plan: Exclude<NdsResolvedMutationPlan, NdsResolvedMutationPlanV2>,
  stagedHandle: FileHandle,
  io: NdsMutationApplyIo,
): Promise<void> {
  for (const operation of plan.applicationOperations) {
    await applyGuardedOperation(stagedHandle, operation, io);
  }
  const info = await stagedHandle.stat();
  if (info.size !== plan.sourceSize) {
    throw new NdsError(
      "staging-failed",
      `Staged ROM size changed to ${info.size} bytes, expected ${plan.sourceSize}`,
    );
  }
}

function assertV2SegmentIntegrity(plan: NdsResolvedMutationPlanV2): void {
  let previousEnd = plan.sourceSize;
  for (const segment of plan.layout.segments) {
    if (
      segment.start < plan.sourceSize
      || segment.end < segment.start
      || segment.end > plan.layout.finalSize
      || segment.size !== segment.end - segment.start
      || segment.bytes.length !== segment.size
      || segment.start < previousEnd
    ) {
      throw new NdsError(
        "staging-failed",
        `Resolved rebuild segment ${segment.ownerId} has invalid append-only geometry`,
      );
    }
    if (sha256(segment.bytes) !== segment.sha256) {
      throw new NdsError(
        "staging-failed",
        `Resolved rebuild segment ${segment.ownerId} bytes do not match planned SHA-256`,
      );
    }
    previousEnd = segment.end;
  }
  if (
    plan.layout.finalSize < plan.sourceSize
    || plan.layout.logicalUsedSize > plan.layout.finalSize
    || plan.headerPlan.outputHeaderBytes.length !== 0x160
  ) {
    throw new NdsError(
      "staging-failed",
      "Resolved v2 rebuild plan has invalid final-size or header geometry",
    );
  }
}

async function applyV2Plan(
  plan: NdsResolvedMutationPlanV2,
  stagedHandle: FileHandle,
  io: NdsMutationApplyIo,
): Promise<void> {
  assertV2SegmentIntegrity(plan);

  // Extend first so every unwritten gap and capacity-padding byte is deterministically zero.
  await stagedHandle.truncate(plan.layout.finalSize);

  for (const resolved of plan.operations) {
    if (resolved.kind === "fixed") {
      await applyGuardedOperation(stagedHandle, resolved.operation, io);
    }
  }
  for (const segment of plan.layout.segments) {
    await writeAll(stagedHandle, segment.bytes, segment.start);
  }
  await writeAll(stagedHandle, plan.headerPlan.outputHeaderBytes, 0);

  const info = await stagedHandle.stat();
  if (info.size !== plan.layout.finalSize) {
    throw new NdsError(
      "staging-failed",
      `Rebuilt staged ROM size is ${info.size} bytes, expected ${plan.layout.finalSize}`,
    );
  }
}

export async function applyNdsMutationPlan(
  plan: NdsResolvedMutationPlan,
  stage: NdsMutationStage,
  io: NdsMutationApplyIo = defaultApplyIo,
): Promise<void> {
  if (stage.buildId !== plan.buildId) {
    throw new NdsError("staging-failed", "Mutation stage build identity does not match the resolved plan");
  }
  if (path.resolve(stage.stagedRomPath) === path.resolve(plan.sourceRomPath)) {
    throw new NdsError("staging-failed", "Refusing to open the immutable source ROM for mutation");
  }

  const stagedHandle = await io.open(stage.stagedRomPath, "r+");
  let completed = false;
  try {
    if (isNdsResolvedMutationPlanV2(plan)) {
      await applyV2Plan(plan, stagedHandle, io);
    } else {
      await applyV1Plan(plan, stagedHandle, io);
    }
    await stagedHandle.sync();
    completed = true;
  } finally {
    try {
      await stagedHandle.close();
    } catch (error) {
      if (completed) {
        throw error;
      }
    }
  }
}
