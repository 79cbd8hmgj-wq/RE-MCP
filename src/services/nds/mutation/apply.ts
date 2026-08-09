import { open as nativeOpen } from "node:fs/promises";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";

import { NdsError } from "../errors.js";
import type { GuardedNdsMutationOperation } from "./guards.js";
import type { NdsResolvedMutationPlan } from "./planner.js";
import type { NdsMutationStage } from "./staging.js";

const COPY_CHUNK_BYTES = 64 * 1024;

export interface NdsMutationApplyIo {
  open(filePath: string, flags: "r" | "r+"): Promise<FileHandle>;
}

const defaultApplyIo: NdsMutationApplyIo = {
  open: nativeOpen,
};

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
    for (const operation of plan.applicationOperations) {
      if (operation.type === "replace-bytes") {
        await applyByteOperation(stagedHandle, operation);
      } else {
        await applyComponentOperation(stagedHandle, operation, io);
      }
    }
    const info = await stagedHandle.stat();
    if (info.size !== plan.sourceSize) {
      throw new NdsError(
        "staging-failed",
        `Staged ROM size changed to ${info.size} bytes, expected ${plan.sourceSize}`,
      );
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
