import type { LoadedNdsMutationManifest } from "./manifest.js";
import {
  serializeResolvedNdsMutationPlan,
  type NdsResolvedMutationPlan,
} from "./planner.js";
import type { NdsMutationVerificationResult } from "./verify.js";

export const NDS_MUTATION_EVIDENCE_FILENAMES = [
  "mutation-manifest.json",
  "resolved-plan.json",
  "verification.json",
  "changed-components.json",
  "output.sha256",
] as const;

export type NdsMutationEvidenceFilename = typeof NDS_MUTATION_EVIDENCE_FILENAMES[number];

export interface NdsMutationEvidenceFile {
  readonly filename: NdsMutationEvidenceFilename;
  readonly bytes: Buffer;
}

function prettyJson(value: unknown): Buffer {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function componentIdentityKey(operation: NdsResolvedMutationPlan["operations"][number]): string {
  const component = operation.component;
  return [
    component.romStart,
    component.romEnd,
    component.component,
    component.processor ?? "",
    component.overlayId ?? "",
    component.fileId ?? "",
    component.filePath ?? "",
  ].join(":");
}

function changedComponents(plan: NdsResolvedMutationPlan): unknown {
  const grouped = new Map<string, {
    readonly component: NdsResolvedMutationPlan["operations"][number]["component"];
    readonly operationIndexes: number[];
  }>();
  for (const operation of plan.operations) {
    const key = componentIdentityKey(operation);
    const existing = grouped.get(key);
    if (existing !== undefined) {
      existing.operationIndexes.push(operation.index);
      continue;
    }
    grouped.set(key, {
      component: operation.component,
      operationIndexes: [operation.index],
    });
  }

  const components = [...grouped.values()]
    .sort((left, right) => left.component.romStart - right.component.romStart
      || left.component.romEnd - right.component.romEnd
      || componentIdentityKey({ component: left.component } as NdsResolvedMutationPlan["operations"][number])
        .localeCompare(componentIdentityKey({ component: right.component } as NdsResolvedMutationPlan["operations"][number])))
    .map(({ component, operationIndexes }) => ({
      component: component.component,
      processor: component.processor,
      overlayId: component.overlayId,
      fileId: component.fileId,
      filePath: component.filePath,
      romStart: component.romStart,
      romEnd: component.romEnd,
      size: component.size,
      compressed: component.compressed,
      overlayOwners: component.overlayOwners,
      operationIndexes: [...operationIndexes].sort((left, right) => left - right),
    }));
  return { components };
}

export function renderNdsMutationEvidence(
  loadedManifest: LoadedNdsMutationManifest,
  plan: NdsResolvedMutationPlan,
  verification: NdsMutationVerificationResult,
): readonly NdsMutationEvidenceFile[] {
  return [
    {
      filename: "mutation-manifest.json",
      bytes: prettyJson(loadedManifest.manifest),
    },
    {
      filename: "resolved-plan.json",
      bytes: prettyJson(serializeResolvedNdsMutationPlan(plan)),
    },
    {
      filename: "verification.json",
      bytes: prettyJson(verification),
    },
    {
      filename: "changed-components.json",
      bytes: prettyJson(changedComponents(plan)),
    },
    {
      filename: "output.sha256",
      bytes: Buffer.from(`${verification.outputSha256}  ${plan.outputFilename}\n`, "utf8"),
    },
  ];
}
