import type { GuardedNdsMutationOperation } from "./guards.js";
import type { LoadedNdsMutationManifest } from "./manifest.js";
import {
  serializeResolvedNdsMutationPlan,
  type NdsResolvedMutationPlan,
} from "./planner.js";
import type { NdsResolvedMutationComponent } from "./selectors.js";
import type {
  NdsMutationOperationVerification,
  NdsMutationVerificationResult,
} from "./verify.js";

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

interface NdsChangedComponentEvidence {
  readonly component: NdsResolvedMutationComponent["component"];
  readonly processor: NdsResolvedMutationComponent["processor"];
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly filePath: string | null;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
  readonly compressed: boolean;
  readonly overlayOwners: NdsResolvedMutationComponent["overlayOwners"];
  readonly operationIndexes: readonly number[];
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

function resolvedChangedComponents(
  plan: NdsResolvedMutationPlan,
): readonly NdsChangedComponentEvidence[] {
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

  return [...grouped.values()]
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
}

function serializedComponent(component: NdsResolvedMutationComponent): unknown {
  return {
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
  };
}

function operationVerificationByIndex(
  verification: NdsMutationVerificationResult,
): ReadonlyMap<number, NdsMutationOperationVerification> {
  return new Map(verification.operations.map((operation) => [operation.index, operation]));
}

function operationEvidence(
  operation: GuardedNdsMutationOperation,
  postBuild: NdsMutationOperationVerification,
): unknown {
  if (operation.type === "replace-bytes") {
    return {
      index: operation.index,
      type: operation.type,
      status: postBuild.status,
      target: operation.target,
      component: serializedComponent(operation.component),
      romStart: operation.romStart,
      romEnd: operation.romEnd,
      size: operation.size,
      guard: {
        kind: "expected-bytes",
        expected: operation.expected,
      },
      replacement: {
        kind: "bytes",
        bytes: operation.replacement,
      },
      postBuild: {
        status: postBuild.status,
        romStart: postBuild.romStart,
        romEnd: postBuild.romEnd,
      },
    };
  }
  return {
    index: operation.index,
    type: operation.type,
    status: postBuild.status,
    target: operation.target,
    component: serializedComponent(operation.component),
    romStart: operation.romStart,
    romEnd: operation.romEnd,
    size: operation.size,
    guard: {
      kind: "component-sha256",
      expectedOriginalSha256: operation.expectedOriginalSha256,
      actualOriginalSha256: operation.originalSha256,
    },
    replacement: {
      kind: "artifact",
      artifact: operation.replacement.workspacePath,
      sha256: operation.replacement.sha256,
      size: operation.replacement.size,
    },
    postBuild: {
      status: postBuild.status,
      romStart: postBuild.romStart,
      romEnd: postBuild.romEnd,
      outputComponentSha256: operation.replacement.sha256,
    },
  };
}

function verificationEvidence(
  plan: NdsResolvedMutationPlan,
  verification: NdsMutationVerificationResult,
  components: readonly NdsChangedComponentEvidence[],
): unknown {
  const verifiedByIndex = operationVerificationByIndex(verification);
  const operations = plan.operations.map((operation) => {
    const postBuild = verifiedByIndex.get(operation.index);
    if (postBuild === undefined) {
      throw new Error(`Missing post-build verification for mutation operation ${operation.index}`);
    }
    return operationEvidence(operation, postBuild);
  });
  return {
    status: verification.status,
    source: {
      rom: plan.sourceWorkspacePath,
      sha256: plan.sourceSha256,
      size: plan.sourceSize,
      unchanged: verification.sourceUnchanged,
    },
    output: {
      rom: `output/nds/${plan.sourceSha256Prefix}/${plan.buildId}/${plan.outputFilename}`,
      sha256: verification.outputSha256,
      size: verification.outputSize,
    },
    manifestSha256: plan.manifestSha256,
    buildId: plan.buildId,
    operationCount: plan.operations.length,
    changedComponentCount: components.length,
    changedByteCount: verification.changedByteCount,
    structuralMetadataUnchanged: verification.structuralMetadataUnchanged,
    structuralMapUnchanged: verification.structuralMapUnchanged,
    canonicalOutputParse: "passed",
    unexpectedChangedBytes: verification.unexpectedChangedBytes,
    compressedOverlays: verification.compressedOverlays,
    operations,
  };
}

export function renderNdsMutationEvidence(
  loadedManifest: LoadedNdsMutationManifest,
  plan: NdsResolvedMutationPlan,
  verification: NdsMutationVerificationResult,
): readonly NdsMutationEvidenceFile[] {
  const components = resolvedChangedComponents(plan);
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
      bytes: prettyJson(verificationEvidence(plan, verification, components)),
    },
    {
      filename: "changed-components.json",
      bytes: prettyJson({ components }),
    },
    {
      filename: "output.sha256",
      bytes: Buffer.from(`${verification.outputSha256}  ${plan.outputFilename}\n`, "utf8"),
    },
  ];
}
