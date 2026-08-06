import { mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";

import { sendRspCommand, validateMemoryRead } from "./gdb-rsp.js";

export interface MemoryRegionRequest {
  readonly label: string;
  readonly address: number;
  readonly length: number;
}

export interface RuntimeEvidence {
  readonly format: "re-mcp-arm9-runtime-evidence";
  readonly formatVersion: 1;
  readonly capturedAt: string;
  readonly registerHex: string;
  readonly memoryRegions: readonly {
    readonly label: string;
    readonly address: number;
    readonly length: number;
    readonly dataHex: string;
  }[];
}

export function validateEvidenceRegions(
  regions: readonly MemoryRegionRequest[],
): void {
  if (regions.length > 16) {
    throw new Error("Runtime evidence may contain at most 16 memory regions");
  }
  const labels = new Set<string>();
  let total = 0;
  for (const region of regions) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(region.label)) {
      throw new Error(`Invalid evidence region label: ${region.label}`);
    }
    if (labels.has(region.label)) {
      throw new Error(`Duplicate evidence region label: ${region.label}`);
    }
    labels.add(region.label);
    validateMemoryRead(region.address, region.length);
    total += region.length;
  }
  if (total > 16_384) {
    throw new Error("Runtime evidence memory total may not exceed 16384 bytes");
  }
}

export async function captureRuntimeEvidence(
  port: number,
  regions: readonly MemoryRegionRequest[],
  maxReplyBytes: number,
): Promise<RuntimeEvidence> {
  validateEvidenceRegions(regions);
  const registers = await sendRspCommand(
    "127.0.0.1",
    port,
    "g",
    3_000,
    maxReplyBytes,
  );
  const memoryRegions = [];
  for (const region of regions) {
    const reply = await sendRspCommand(
      "127.0.0.1",
      port,
      `m${region.address.toString(16)},${region.length.toString(16)}`,
      3_000,
      Math.min(maxReplyBytes, region.length * 2 + 64),
    );
    if (reply.payload.startsWith("E")) {
      throw new Error(`GDB memory read failed for ${region.label}: ${reply.payload}`);
    }
    memoryRegions.push({ ...region, dataHex: reply.payload });
  }
  return {
    format: "re-mcp-arm9-runtime-evidence",
    formatVersion: 1,
    capturedAt: new Date().toISOString(),
    registerHex: registers.payload,
    memoryRegions,
  };
}

export async function writeEvidenceAtomic(
  outputPath: string,
  evidence: RuntimeEvidence,
): Promise<void> {
  await mkdir(path.dirname(outputPath), { recursive: true });
  const temporary = `${outputPath}.tmp-${process.pid}-${Date.now()}`;
  try {
    await writeFile(temporary, `${JSON.stringify(evidence, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
    });
    await rename(temporary, outputPath);
  } catch (error) {
    try {
      const { unlink } = await import("node:fs/promises");
      await unlink(temporary);
    } catch {
      // Best-effort cleanup after a failed atomic write.
    }
    throw error;
  }
}
