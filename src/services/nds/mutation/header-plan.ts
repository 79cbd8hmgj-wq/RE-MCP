import { createHash } from "node:crypto";

import {
  serializeNdsRebuildHeader,
  type NdsOwnedHeaderRegionRewrite,
  type NdsRebuildHeaderSnapshot,
} from "../header-rebuild.js";
import { NdsError } from "../errors.js";
import type {
  NdsRebuildLayout,
  NdsRebuildSegment,
} from "./layout.js";

export interface NdsHeaderByteRewrite {
  readonly offset: number;
  readonly expected: string;
  readonly replacement: string;
  readonly label: string;
}

export interface NdsHeaderRewritePlan {
  readonly sourceHeaderSha256: string;
  readonly outputHeaderSha256: string;
  readonly rewrites: readonly NdsHeaderByteRewrite[];
  readonly outputHeaderBytes: Buffer;
}

interface AllowedRange {
  readonly start: number;
  readonly end: number;
  readonly label: string;
}

function sha256(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function headerPlanError(message: string): never {
  throw new NdsError("header-rebuild-failed", message);
}

function segmentFor(
  layout: NdsRebuildLayout,
  kind: NdsRebuildSegment["kind"],
): NdsRebuildSegment | undefined {
  const matches = layout.segments.filter((segment) => segment.kind === kind);
  if (matches.length > 1) {
    headerPlanError(`NDS rebuild layout contains more than one ${kind} segment`);
  }
  return matches[0];
}

function regionFor(segment: NdsRebuildSegment): NdsOwnedHeaderRegionRewrite {
  return { offset: segment.start, size: segment.size };
}

function allowedRanges(layout: NdsRebuildLayout): readonly AllowedRange[] {
  const ranges: AllowedRange[] = [
    { start: 0x14, end: 0x15, label: "device-capacity" },
    { start: 0x48, end: 0x50, label: "fat" },
    { start: 0x80, end: 0x84, label: "rom-used-size" },
    { start: 0x15e, end: 0x160, label: "header-crc16" },
  ];
  if (segmentFor(layout, "fnt") !== undefined) {
    ranges.push({ start: 0x40, end: 0x48, label: "fnt" });
  }
  if (segmentFor(layout, "arm9-overlay-table") !== undefined) {
    ranges.push({ start: 0x50, end: 0x58, label: "arm9-overlay-table" });
  }
  if (segmentFor(layout, "arm7-overlay-table") !== undefined) {
    ranges.push({ start: 0x58, end: 0x60, label: "arm7-overlay-table" });
  }
  return ranges;
}

function labelForOffset(ranges: readonly AllowedRange[], offset: number): string | null {
  const match = ranges.find((range) => offset >= range.start && offset < range.end);
  return match?.label ?? null;
}

function compileChangedRuns(
  source: Buffer,
  output: Buffer,
  ranges: readonly AllowedRange[],
): readonly NdsHeaderByteRewrite[] {
  if (source.length !== output.length) {
    headerPlanError("Source and rebuilt header lengths differ");
  }
  const rewrites: NdsHeaderByteRewrite[] = [];
  let offset = 0;
  while (offset < source.length) {
    if (source[offset] === output[offset]) {
      offset += 1;
      continue;
    }
    const label = labelForOffset(ranges, offset);
    if (label === null) {
      headerPlanError(
        `Rebuilt header changes byte 0x${offset.toString(16)} outside the owned rewrite allowlist`,
      );
    }
    const start = offset;
    offset += 1;
    while (
      offset < source.length
      && source[offset] !== output[offset]
      && labelForOffset(ranges, offset) === label
    ) {
      offset += 1;
    }
    rewrites.push({
      offset: start,
      expected: source.subarray(start, offset).toString("hex"),
      replacement: output.subarray(start, offset).toString("hex"),
      label,
    });
  }
  return rewrites;
}

export function compileNdsHeaderRewritePlan(
  source: NdsRebuildHeaderSnapshot,
  layout: NdsRebuildLayout,
): NdsHeaderRewritePlan {
  const fnt = segmentFor(layout, "fnt");
  const fat = segmentFor(layout, "fat");
  if (fat === undefined) {
    headerPlanError("NDS v2 rebuild layout must contain one rebuilt FAT segment");
  }
  const arm9 = segmentFor(layout, "arm9-overlay-table");
  const arm7 = segmentFor(layout, "arm7-overlay-table");

  const outputHeaderBytes = serializeNdsRebuildHeader(source, {
    deviceCapacity: layout.deviceCapacity,
    romUsedSize: layout.logicalUsedSize,
    fat: regionFor(fat),
    ...(fnt === undefined ? {} : { fnt: regionFor(fnt) }),
    ...(arm9 === undefined ? {} : { arm9OverlayTable: regionFor(arm9) }),
    ...(arm7 === undefined ? {} : { arm7OverlayTable: regionFor(arm7) }),
  });
  const rewrites = compileChangedRuns(
    source.bytes,
    outputHeaderBytes,
    allowedRanges(layout),
  );

  return {
    sourceHeaderSha256: sha256(source.bytes),
    outputHeaderSha256: sha256(outputHeaderBytes),
    rewrites,
    outputHeaderBytes,
  };
}
