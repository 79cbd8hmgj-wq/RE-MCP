import { NdsError } from "../errors.js";
import { createNdsOverlayRuntimeContext } from "../overlay-runtime.js";
import type { NdsOverlay, NdsProcessor } from "../overlays.js";
import { readNdsRomMap, type NdsRomMap } from "../rom-map.js";
import {
  isNdsResolvedMutationPlanV2,
  type NdsResolvedMutationPlan,
} from "./planner.js";
import type {
  NdsCompressedOverlayVerification,
  NdsMutationVerificationResult,
} from "./verify.js";

function overlayFor(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
): NdsOverlay | undefined {
  return map.overlays[processor].find((overlay) => overlay.overlayId === overlayId);
}

function overlayKey(processor: NdsProcessor, overlayId: number): string {
  return `${processor}:${overlayId}`;
}

export async function completeNdsMutationBuildVerification(
  sourceMap: NdsRomMap,
  plan: NdsResolvedMutationPlan,
  outputRomPath: string,
  verification: NdsMutationVerificationResult,
): Promise<NdsMutationVerificationResult> {
  if (!isNdsResolvedMutationPlanV2(plan)) {
    return verification;
  }

  const owners = new Map<string, { readonly processor: NdsProcessor; readonly overlayId: number }>();
  for (const resolved of plan.operations) {
    if (resolved.kind !== "fixed" || resolved.operation.type !== "replace-component") {
      continue;
    }
    for (const owner of resolved.operation.component.overlayOwners) {
      if (!owner.compressed) {
        continue;
      }
      owners.set(overlayKey(owner.processor, owner.overlayId), {
        processor: owner.processor,
        overlayId: owner.overlayId,
      });
    }
  }
  if (owners.size === 0) {
    return verification;
  }

  const outputMap = await readNdsRomMap(outputRomPath);
  const runtimeContext = createNdsOverlayRuntimeContext(outputMap);
  const merged = new Map<string, NdsCompressedOverlayVerification>();
  for (const entry of verification.compressedOverlays) {
    merged.set(overlayKey(entry.processor, entry.overlayId), entry);
  }

  const orderedOwners = [...owners.values()].sort(
    (left, right) => left.processor.localeCompare(right.processor)
      || left.overlayId - right.overlayId,
  );
  for (const owner of orderedOwners) {
    const sourceOverlay = overlayFor(sourceMap, owner.processor, owner.overlayId);
    const outputOverlay = overlayFor(outputMap, owner.processor, owner.overlayId);
    if (sourceOverlay === undefined || outputOverlay === undefined) {
      throw new NdsError(
        "compressed-overlay-invalid",
        `${owner.processor.toUpperCase()} overlay ${owner.overlayId} is missing during rebuilt-output verification`,
      );
    }

    try {
      const runtime = await runtimeContext.getCompressedOverlay(owner.processor, owner.overlayId);
      if (
        outputOverlay.romOffset !== sourceOverlay.romOffset
        || outputOverlay.romSize !== sourceOverlay.romSize
        || outputOverlay.ramAddress !== sourceOverlay.ramAddress
        || outputOverlay.ramSize !== sourceOverlay.ramSize
        || outputOverlay.bssSize !== sourceOverlay.bssSize
        || runtime.storedRomOffset !== outputOverlay.romOffset
        || runtime.storedSize !== outputOverlay.romSize
        || runtime.runtimeAddress !== outputOverlay.ramAddress
        || runtime.runtimeSize !== outputOverlay.ramSize
        || runtime.bssSize !== outputOverlay.bssSize
      ) {
        throw new Error("compressed overlay runtime geometry differs from the canonical source layout");
      }
      merged.set(overlayKey(owner.processor, owner.overlayId), {
        processor: owner.processor,
        overlayId: owner.overlayId,
        status: "passed",
        runtimeSha256: runtime.runtimeSha256,
      });
    } catch (error) {
      if (error instanceof NdsError && error.category === "compressed-overlay-invalid") {
        throw error;
      }
      throw new NdsError(
        "compressed-overlay-invalid",
        `${owner.processor.toUpperCase()} overlay ${owner.overlayId} failed rebuilt post-build runtime validation: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  return {
    ...verification,
    compressedOverlays: [...merged.values()].sort(
      (left, right) => left.processor.localeCompare(right.processor)
        || left.overlayId - right.overlayId,
    ),
  };
}
