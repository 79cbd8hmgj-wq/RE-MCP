import { NdsError } from "../errors.js";
import type { GuardedNdsMutationOperation } from "./guards.js";

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
