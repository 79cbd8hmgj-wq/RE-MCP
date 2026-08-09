import { NdsError } from "../errors.js";
import type { NdsRelocatedFilePlan } from "./filesystem-plan.js";
import type { GuardedNdsMutationOperation } from "./guards.js";

function rangesOverlap(
  leftStart: number,
  leftEnd: number,
  rightStart: number,
  rightEnd: number,
): boolean {
  return leftStart < rightEnd && rightStart < leftEnd;
}

export function assertNoNdsMutationConflicts(
  operations: readonly GuardedNdsMutationOperation[],
): void {
  const sorted = [...operations].sort(
    (left, right) => left.romStart - right.romStart
      || left.romEnd - right.romEnd
      || left.index - right.index,
  );

  for (let index = 1; index < sorted.length; index += 1) {
    const previous = sorted[index - 1];
    const current = sorted[index];
    if (previous === undefined || current === undefined) {
      continue;
    }
    if (current.romStart < previous.romEnd) {
      throw new NdsError(
        "mutation-overlap",
        `Mutation operations ${previous.index} and ${current.index} overlap physical ROM bytes 0x${Math.max(previous.romStart, current.romStart).toString(16)}..0x${Math.min(previous.romEnd, current.romEnd).toString(16)}`,
      );
    }
  }
}

export function assertNoNdsRebuildLogicalConflicts(
  fixedOperations: readonly GuardedNdsMutationOperation[],
  relocatedFiles: readonly NdsRelocatedFilePlan[],
): void {
  assertNoNdsMutationConflicts(fixedOperations);

  const byFileId = new Map<number, NdsRelocatedFilePlan>();
  for (const relocated of relocatedFiles) {
    const existing = byFileId.get(relocated.fileId);
    if (existing !== undefined) {
      throw new NdsError(
        "unsupported-rebuild-target",
        `Mutation operations ${existing.operationIndex} and ${relocated.operationIndex} both replace NitroFS file ${relocated.fileId}`,
      );
    }
    byFileId.set(relocated.fileId, relocated);

    for (const fixed of fixedOperations) {
      if (
        rangesOverlap(
          fixed.romStart,
          fixed.romEnd,
          relocated.sourceStart,
          relocated.sourceEnd,
        )
      ) {
        throw new NdsError(
          "mutation-overlap",
          `Fixed mutation operation ${fixed.index} overlaps variable replacement operation ${relocated.operationIndex} within source NitroFS file ${relocated.fileId}`,
        );
      }
    }
  }
}
