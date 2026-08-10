import type { GuardedNdsMutationOperation } from "./guards.js";
import type { LoadedNdsMutationManifest } from "./manifest.js";
import {
  isNdsResolvedMutationPlanV2,
  serializeResolvedNdsMutationPlan,
  type NdsResolvedMutationPlan,
  type NdsResolvedMutationPlanV1,
  type NdsResolvedMutationPlanV2,
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
  plan: NdsResolvedMutationPlanV1,
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
  plan: NdsResolvedMutationPlanV1,
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

interface NdsChangedComponentEvidenceV2 {
  readonly component: string;
  readonly processor: "arm9" | "arm7" | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly filePath: string | null;
  readonly romStart: number;
  readonly romEnd: number;
  readonly size: number;
  readonly compressed: boolean;
  readonly operationIndexes: readonly number[];
}

function v2ChangedComponents(
  plan: NdsResolvedMutationPlanV2,
): readonly NdsChangedComponentEvidenceV2[] {
  const components: NdsChangedComponentEvidenceV2[] = [];
  for (const resolved of plan.operations) {
    if (resolved.kind === "fixed") {
      const component = normalizePhysicalComponent(resolved.operation.component);
      components.push({
        component: component.component,
        processor: component.processor,
        overlayId: component.overlayId,
        fileId: component.fileId,
        filePath: component.filePath,
        romStart: component.romStart,
        romEnd: component.romEnd,
        size: component.size,
        compressed: component.compressed,
        operationIndexes: [resolved.index],
      });
      continue;
    }
    const fileId = resolved.kind === "decoded-overlay"
      ? resolved.overlay.fileId
      : resolved.file.fileId;
    const range = plan.finalFat[fileId]!;
    if (resolved.kind === "decoded-overlay") {
      components.push({
        component: `${resolved.overlay.processor}-overlay`,
        processor: resolved.overlay.processor,
        overlayId: resolved.overlay.overlayId,
        fileId,
        filePath: null,
        romStart: range.startOffset,
        romEnd: range.endOffset,
        size: range.endOffset - range.startOffset,
        compressed: true,
        operationIndexes: [resolved.index],
      });
    } else {
      components.push({
        component: "nitrofs-file",
        processor: null,
        overlayId: null,
        fileId,
        filePath: resolved.kind === "new-file" ? resolved.file.path : resolved.file.filePath,
        romStart: range.startOffset,
        romEnd: range.endOffset,
        size: range.endOffset - range.startOffset,
        compressed: false,
        operationIndexes: [resolved.index],
      });
    }
  }
  return components.sort(
    (left, right) => left.romStart - right.romStart
      || left.romEnd - right.romEnd
      || left.operationIndexes[0]! - right.operationIndexes[0]!,
  );
}

function v2OperationEvidence(
  plan: NdsResolvedMutationPlanV2,
  verification: NdsMutationVerificationResult,
): readonly unknown[] {
  const verifiedByIndex = operationVerificationByIndex(verification);
  return plan.operations.map((resolved) => {
    const postBuild = verifiedByIndex.get(resolved.index);
    if (postBuild === undefined) {
      throw new Error(`Missing post-build verification for rebuild operation ${resolved.index}`);
    }
    if (resolved.kind === "fixed") {
      return operationEvidence(resolved.operation, postBuild);
    }
    if (resolved.kind === "relocated-file") {
      return {
        index: resolved.index,
        type: "replace-nitrofs-file",
        status: postBuild.status,
        fileId: resolved.file.fileId,
        filePath: resolved.file.filePath,
        guard: {
          kind: "component-sha256",
          expectedOriginalSha256: resolved.file.sourceSha256,
        },
        replacement: {
          kind: "artifact",
          artifact: resolved.file.replacementWorkspacePath,
          sha256: resolved.file.replacementSha256,
          size: resolved.file.replacementSize,
        },
        postBuild: {
          status: postBuild.status,
          romStart: postBuild.romStart,
          romEnd: postBuild.romEnd,
          outputComponentSha256: resolved.file.replacementSha256,
        },
      };
    }
    if (resolved.kind === "new-file") {
      return {
        index: resolved.index,
        type: "add-nitrofs-file",
        status: postBuild.status,
        fileId: resolved.file.fileId,
        filePath: resolved.file.path,
        replacement: {
          kind: "artifact",
          artifact: resolved.file.replacementWorkspacePath,
          sha256: resolved.file.replacementSha256,
          size: resolved.file.replacementSize,
        },
        postBuild: {
          status: postBuild.status,
          romStart: postBuild.romStart,
          romEnd: postBuild.romEnd,
          outputComponentSha256: resolved.file.replacementSha256,
        },
      };
    }
    return {
      index: resolved.index,
      type: "replace-decoded-overlay",
      status: postBuild.status,
      processor: resolved.overlay.processor,
      overlayId: resolved.overlay.overlayId,
      fileId: resolved.overlay.fileId,
      guard: {
        expectedStoredSha256: resolved.overlay.sourceStoredSha256,
        expectedRuntimeSha256: resolved.overlay.sourceRuntimeSha256,
      },
      replacement: {
        kind: "runtime-artifact",
        artifact: resolved.overlay.replacementRuntimeWorkspacePath,
        runtimeSha256: resolved.overlay.replacementRuntimeSha256,
        runtimeSize: resolved.overlay.runtimeSize,
        encodedSha256: resolved.overlay.encodedSha256,
        encodedSize: resolved.overlay.encodedSize,
      },
      postBuild: {
        status: postBuild.status,
        romStart: postBuild.romStart,
        romEnd: postBuild.romEnd,
        runtimeSha256: resolved.overlay.replacementRuntimeSha256,
      },
    };
  });
}

function verificationEvidenceV2(
  plan: NdsResolvedMutationPlanV2,
  verification: NdsMutationVerificationResult,
  components: readonly NdsChangedComponentEvidenceV2[],
): unknown {
  if (verification.rebuildSemanticsVerified !== true) {
    throw new Error("Missing successful rebuild semantic verification for v2 evidence");
  }
  return {
    status: verification.status,
    formatVersion: 2,
    rebuildContractVersion: plan.rebuildContractVersion,
    blzEncoderContractVersion: plan.blzEncoderContractVersion,
    rebuildSemanticsVerified: true,
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
      logicalUsedSize: plan.layout.logicalUsedSize,
      deviceCapacity: plan.layout.deviceCapacity,
    },
    manifestSha256: plan.manifestSha256,
    buildId: plan.buildId,
    operationCount: plan.operations.length,
    changedComponentCount: components.length,
    changedByteCount: verification.changedByteCount,
    canonicalOutputParse: "passed",
    unexpectedChangedBytes: verification.unexpectedChangedBytes,
    compressedOverlays: verification.compressedOverlays,
    operations: v2OperationEvidence(plan, verification),
  };
}

export function renderNdsMutationEvidence(
  loadedManifest: LoadedNdsMutationManifest,
  plan: NdsResolvedMutationPlan,
  verification: NdsMutationVerificationResult,
): readonly NdsMutationEvidenceFile[] {
  const components = isNdsResolvedMutationPlanV2(plan)
    ? v2ChangedComponents(plan)
    : resolvedChangedComponents(plan);
  const verificationReport = isNdsResolvedMutationPlanV2(plan)
    ? verificationEvidenceV2(plan, verification, components as readonly NdsChangedComponentEvidenceV2[])
    : verificationEvidence(plan, verification, components as readonly NdsChangedComponentEvidence[]);
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
      bytes: prettyJson(verificationReport),
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
