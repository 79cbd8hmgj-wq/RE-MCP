import { createHash } from "node:crypto";

import {
  MAX_NDS_REBUILT_ROM_BYTES,
  selectNdsDeviceCapacity,
} from "../header-rebuild.js";
import { NdsError } from "../errors.js";

export const NDS_REBUILD_CONTRACT_VERSION = 1 as const;
export const MAX_NDS_REBUILD_GROWTH_BYTES = 128 * 1024 * 1024;

const PAYLOAD_ALIGNMENT = 0x200 as const;
const METADATA_ALIGNMENT = 4 as const;
const MAX_ARTIFACT_BYTES = 64 * 1024 * 1024;
const MAX_AGGREGATE_NEW_PAYLOAD_BYTES = 64 * 1024 * 1024;
const MAX_FNT_FAT_BYTES = 4 * 1024 * 1024;
const UINT32_END = 0x1_0000_0000;

export interface NdsPayloadLayoutInput {
  readonly kind: "relocated-file" | "new-file";
  readonly ownerId: string;
  readonly fileId: number;
  readonly bytes: Buffer;
  readonly sha256: string;
}

export interface NdsRebuildSegment {
  readonly kind: "relocated-file" | "new-file" | "fnt" | "fat" | "arm9-overlay-table" | "arm7-overlay-table";
  readonly ownerId: string;
  readonly alignment: 0x200 | 4;
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly sha256: string;
  readonly bytes: Buffer;
}

export interface NdsPayloadLayout {
  readonly sourceSize: number;
  readonly tailStart: number;
  readonly logicalUsedSize: number;
  readonly finalSize: number;
  readonly deviceCapacity: number;
  readonly segments: readonly NdsRebuildSegment[];
  readonly nextOffset: number;
}

export interface NdsMetadataLayoutInput {
  readonly fnt?: Buffer | undefined;
  readonly fat: Buffer;
  readonly arm9OverlayTable?: Buffer | undefined;
  readonly arm7OverlayTable?: Buffer | undefined;
}

export interface NdsRebuildLayout {
  readonly sourceSize: number;
  readonly tailStart: number;
  readonly logicalUsedSize: number;
  readonly finalSize: number;
  readonly deviceCapacity: number;
  readonly segments: readonly NdsRebuildSegment[];
}

function layoutError(message: string): never {
  throw new NdsError("rebuild-layout-overflow", message);
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireSafeNonnegative(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    layoutError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function checkedAlignUp(value: number, alignment: 0x200 | 4, label: string): number {
  requireSafeNonnegative(value, label);
  const remainder = value % alignment;
  const aligned = remainder === 0 ? value : value + alignment - remainder;
  if (!Number.isSafeInteger(aligned) || aligned < value || aligned > UINT32_END) {
    layoutError(`${label} cannot be aligned to ${alignment} within unsigned 32-bit ROM geometry`);
  }
  return aligned;
}

function checkedEnd(start: number, size: number, label: string): number {
  requireSafeNonnegative(start, `${label} start`);
  requireSafeNonnegative(size, `${label} size`);
  const end = start + size;
  if (!Number.isSafeInteger(end) || end < start || end > UINT32_END) {
    layoutError(`${label} overflows unsigned 32-bit ROM geometry`);
  }
  return end;
}

function validatePayloadInput(input: NdsPayloadLayoutInput): void {
  if (!Number.isSafeInteger(input.fileId) || input.fileId < 0 || input.fileId > 0xffff) {
    layoutError(`${input.ownerId} file ID ${input.fileId} is outside the 0..65535 range`);
  }
  const size = input.bytes.length;
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_ARTIFACT_BYTES) {
    layoutError(
      `${input.ownerId} payload size ${size} is outside the 1..${MAX_ARTIFACT_BYTES} byte limit`,
    );
  }
}

function payloadOrder(
  left: NdsPayloadLayoutInput,
  right: NdsPayloadLayoutInput,
): number {
  const leftClass = left.kind === "relocated-file" ? 0 : 1;
  const rightClass = right.kind === "relocated-file" ? 0 : 1;
  return leftClass - rightClass
    || left.fileId - right.fileId
    || left.ownerId.localeCompare(right.ownerId);
}

function assertGrowth(sourceSize: number, end: number): void {
  const growth = Math.max(0, end - sourceSize);
  if (!Number.isSafeInteger(growth) || growth > MAX_NDS_REBUILD_GROWTH_BYTES) {
    layoutError(
      `NDS rebuild growth ${growth} bytes exceeds the ${MAX_NDS_REBUILD_GROWTH_BYTES}-byte limit`,
    );
  }
}

export function planNdsPayloadLayout(
  sourceSize: number,
  payloads: readonly NdsPayloadLayoutInput[],
): NdsPayloadLayout {
  if (
    !Number.isSafeInteger(sourceSize)
    || sourceSize < 1
    || sourceSize > MAX_NDS_REBUILT_ROM_BYTES
  ) {
    layoutError(
      `Source NDS ROM size ${sourceSize} must be a positive safe integer no larger than ${MAX_NDS_REBUILT_ROM_BYTES}`,
    );
  }

  let aggregateNewPayloadBytes = 0;
  const ownerIds = new Set<string>();
  const fileIds = new Set<number>();
  for (const input of payloads) {
    validatePayloadInput(input);
    if (ownerIds.has(input.ownerId)) {
      layoutError(`Payload owner ${input.ownerId} is present more than once`);
    }
    ownerIds.add(input.ownerId);
    if (fileIds.has(input.fileId)) {
      layoutError(`Payload file ID ${input.fileId} is present more than once`);
    }
    fileIds.add(input.fileId);
    if (input.kind === "new-file") {
      aggregateNewPayloadBytes += input.bytes.length;
      if (
        !Number.isSafeInteger(aggregateNewPayloadBytes)
        || aggregateNewPayloadBytes > MAX_AGGREGATE_NEW_PAYLOAD_BYTES
      ) {
        layoutError(
          `New-file payloads total ${aggregateNewPayloadBytes} bytes, above the ${MAX_AGGREGATE_NEW_PAYLOAD_BYTES}-byte limit`,
        );
      }
    }
  }

  const tailStart = checkedAlignUp(sourceSize, PAYLOAD_ALIGNMENT, "NDS rebuild tail start");
  const segments: NdsRebuildSegment[] = [];
  let nextOffset = tailStart;
  for (const input of [...payloads].sort(payloadOrder)) {
    const start = checkedAlignUp(nextOffset, PAYLOAD_ALIGNMENT, `${input.ownerId} start`);
    const end = checkedEnd(start, input.bytes.length, input.ownerId);
    assertGrowth(sourceSize, end);
    segments.push({
      kind: input.kind,
      ownerId: input.ownerId,
      alignment: PAYLOAD_ALIGNMENT,
      start,
      end,
      size: input.bytes.length,
      sha256: input.sha256,
      bytes: input.bytes,
    });
    nextOffset = end;
  }

  const preliminaryCapacity = selectNdsDeviceCapacity(nextOffset);
  return {
    sourceSize,
    tailStart,
    logicalUsedSize: nextOffset,
    finalSize: preliminaryCapacity.capacityBytes,
    deviceCapacity: preliminaryCapacity.deviceCapacity,
    segments,
    nextOffset,
  };
}

function metadataSegment(
  kind: "fnt" | "fat" | "arm9-overlay-table" | "arm7-overlay-table",
  bytes: Buffer,
  nextOffset: number,
): NdsRebuildSegment {
  const size = bytes.length;
  if (!Number.isSafeInteger(size) || size < 0) {
    layoutError(`${kind} metadata size is invalid`);
  }
  if ((kind === "fnt" || kind === "fat") && size > MAX_FNT_FAT_BYTES) {
    layoutError(
      `${kind.toUpperCase()} metadata size ${size} exceeds the ${MAX_FNT_FAT_BYTES}-byte limit`,
    );
  }
  if (size > MAX_ARTIFACT_BYTES) {
    layoutError(`${kind} metadata size ${size} exceeds the ${MAX_ARTIFACT_BYTES}-byte limit`);
  }
  const start = checkedAlignUp(nextOffset, METADATA_ALIGNMENT, `${kind} start`);
  const end = checkedEnd(start, size, kind);
  return {
    kind,
    ownerId: `metadata:${kind}`,
    alignment: METADATA_ALIGNMENT,
    start,
    end,
    size,
    sha256: sha256(bytes),
    bytes,
  };
}

export function finalizeNdsRebuildLayout(
  payloadLayout: NdsPayloadLayout,
  metadata: NdsMetadataLayoutInput,
): NdsRebuildLayout {
  if (
    !Number.isSafeInteger(payloadLayout.sourceSize)
    || payloadLayout.sourceSize < 1
    || !Number.isSafeInteger(payloadLayout.tailStart)
    || payloadLayout.tailStart < payloadLayout.sourceSize
    || !Number.isSafeInteger(payloadLayout.nextOffset)
    || payloadLayout.nextOffset < payloadLayout.tailStart
  ) {
    layoutError("Payload layout contains invalid source/tail geometry");
  }

  const metadataInputs: readonly [
    "fnt" | "fat" | "arm9-overlay-table" | "arm7-overlay-table",
    Buffer | undefined,
  ][] = [
    ["fnt", metadata.fnt],
    ["fat", metadata.fat],
    ["arm9-overlay-table", metadata.arm9OverlayTable],
    ["arm7-overlay-table", metadata.arm7OverlayTable],
  ];

  const segments = [...payloadLayout.segments];
  let nextOffset = payloadLayout.nextOffset;
  for (const [kind, bytes] of metadataInputs) {
    if (bytes === undefined) {
      continue;
    }
    const segment = metadataSegment(kind, bytes, nextOffset);
    assertGrowth(payloadLayout.sourceSize, segment.end);
    segments.push(segment);
    nextOffset = segment.end;
  }

  const logicalUsedSize = nextOffset;
  const capacity = selectNdsDeviceCapacity(logicalUsedSize);
  return {
    sourceSize: payloadLayout.sourceSize,
    tailStart: payloadLayout.tailStart,
    logicalUsedSize,
    finalSize: capacity.capacityBytes,
    deviceCapacity: capacity.deviceCapacity,
    segments,
  };
}
