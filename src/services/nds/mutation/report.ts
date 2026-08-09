import type { LoadedNdsMutationManifest } from "./manifest.js";
import {
  serializeResolvedNdsMutationPlan,
  type NdsResolvedMutationPlan,
} from "./planner.js";
import type { NdsResolvedMutationComponent } from "./selectors.js";
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

function normalizePhysicalComponent(
  component: NdsResolvedMutationComponent,
): NdsResolvedMutationComponent {
  if (
    component.processor === null
    && component.overlayId === null
    && component.fileId !== null
  ) {
    return { ...component, component: "nitrofs-file" };
  }
  if (component.overlayId !== null && component.processor !== null) {
    return {
      ...component,
      component: component.processor === "arm9" ? "arm9-overlay" : "arm7-overlay",
    };
  }
  if (component.processor === "arm9") {
    return { ...component, component: "arm9" };
  }
  if (component.processor === "arm7") {
    return { ...component, component: "arm7" };
  }
  return component;
}

function componentIdentityKey(component: NdsResolvedMutationComponent): string {
  return [
    component.romStart,
    component.romEnd,
    component.processor ?? "",
    component.overlayId ?? "",
    component.fileId ?? "",
    component.filePath ?? "",
  ].join(":");
}

function changedComponents(plan: NdsResolvedMutationPlan): unknown {
  const grouped = new Map<string, {
    readonly component: NdsResolvedMutationComponent;
    readonly operationIndexes: number[];
  }>();
  for (const operation of plan.operations) {
    const component = normalizePhysicalComponent(operation.component);
    const key = componentIdentityKey(component);
    const existing = grouped.get(key);
    if (existing !== undefined) {
      existing.operationIndexes.push(operation.index);
      continue;
    }
    grouped.set(key, {
      component,
      operationIndexes: [operation.index],
    });
  }

  const components = [...grouped.values()]
    .sort((left, right) => left.component.romStart - right.component.romStart
      || left.component.romEnd - right.component.romEnd
      || componentIdentityKey(left.component).localeCompare(componentIdentityKey(right.component)))
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
