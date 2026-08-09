import { createHash } from "node:crypto";
import { open } from "node:fs/promises";

import {
  DEFAULT_NDS_BLZ_LIMITS,
  decodeNdsBlz,
} from "./blz.js";
import { NdsError } from "./errors.js";
import { hashFileSha256, readExact } from "./io.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

const MAX_AGGREGATE_DECODED_BYTES = 64 * 1024 * 1024;

export interface NdsOverlayRuntimeImage {
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly fileId: number;
  readonly sourceRomSha256: string;
  readonly storedRomOffset: number;
  readonly storedSize: number;
  readonly compressedSize: number;
  readonly storedSha256: string;
  readonly compressedPayloadSha256: string;
  readonly runtimeAddress: number;
  readonly runtimeSize: number;
  readonly bssSize: number;
  readonly representation: "derived-blz";
  readonly runtimeSha256: string;
  readonly bytes: Buffer;
}

export interface NdsOverlayRuntimeLimits {
  readonly maxStoredBytes: number;
  readonly maxDecodedBytes: number;
  readonly maxAggregateDecodedBytes: number;
}

export interface NdsOverlayRuntimeContext {
  getCompressedOverlay(
    processor: NdsProcessor,
    overlayId: number,
  ): Promise<NdsOverlayRuntimeImage>;
  readonly decodedBytesCharged: number;
}

const DEFAULT_LIMITS: NdsOverlayRuntimeLimits = {
  maxStoredBytes: DEFAULT_NDS_BLZ_LIMITS.maxStoredBytes,
  maxDecodedBytes: DEFAULT_NDS_BLZ_LIMITS.maxDecodedBytes,
  maxAggregateDecodedBytes: MAX_AGGREGATE_DECODED_BYTES,
};

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function requirePositiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new NdsError(
      "blz-output-limit",
      `${label} must be a positive safe integer`,
    );
  }
  return value;
}

function resolvedLimits(
  limits: Partial<NdsOverlayRuntimeLimits>,
): NdsOverlayRuntimeLimits {
  return {
    maxStoredBytes: requirePositiveSafeInteger(
      limits.maxStoredBytes ?? DEFAULT_LIMITS.maxStoredBytes,
      "maxStoredBytes",
    ),
    maxDecodedBytes: requirePositiveSafeInteger(
      limits.maxDecodedBytes ?? DEFAULT_LIMITS.maxDecodedBytes,
      "maxDecodedBytes",
    ),
    maxAggregateDecodedBytes: requirePositiveSafeInteger(
      limits.maxAggregateDecodedBytes ?? DEFAULT_LIMITS.maxAggregateDecodedBytes,
      "maxAggregateDecodedBytes",
    ),
  };
}

async function assertSourceIdentity(map: NdsRomMap): Promise<void> {
  const actualSha256 = await hashFileSha256(map.romPath);
  if (actualSha256 !== map.sha256) {
    throw new NdsError(
      "invalid-rom",
      "Source ROM SHA-256 no longer matches the canonical NDS map; parse the ROM again before decoding overlays",
    );
  }
}

function selectCompressedOverlay(
  map: NdsRomMap,
  processor: NdsProcessor,
  overlayId: number,
): NdsOverlay {
  const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
  const overlay = overlays.find((candidate) => candidate.overlayId === overlayId);
  if (overlay === undefined || !overlay.compressed) {
    throw new NdsError(
      "compressed-overlay-runtime-unavailable",
      `${processor.toUpperCase()} overlay ${overlayId} is not a canonical compressed overlay`,
    );
  }
  if (overlay.compressedSize < 8 || overlay.compressedSize > overlay.romSize) {
    throw new NdsError(
      "compressed-overlay-runtime-unavailable",
      `${processor.toUpperCase()} overlay ${overlayId} has invalid compressed payload size ${overlay.compressedSize} for ${overlay.romSize} bytes of FAT backing`,
    );
  }
  return overlay;
}

function enforceOverlayLimits(
  overlay: NdsOverlay,
  limits: NdsOverlayRuntimeLimits,
  decodedBytesCharged: number,
  reservedDecodedBytes: number,
): void {
  if (overlay.romSize > limits.maxStoredBytes) {
    throw new NdsError(
      "blz-output-limit",
      `${overlay.processor.toUpperCase()} overlay ${overlay.overlayId} has ${overlay.romSize} stored bytes, above the ${limits.maxStoredBytes}-byte limit`,
    );
  }
  if (overlay.compressedSize > limits.maxStoredBytes) {
    throw new NdsError(
      "blz-output-limit",
      `${overlay.processor.toUpperCase()} overlay ${overlay.overlayId} has a ${overlay.compressedSize}-byte BLZ payload, above the ${limits.maxStoredBytes}-byte limit`,
    );
  }
  if (overlay.ramSize > limits.maxDecodedBytes) {
    throw new NdsError(
      "blz-output-limit",
      `${overlay.processor.toUpperCase()} overlay ${overlay.overlayId} has a ${overlay.ramSize}-byte initialized runtime image, above the ${limits.maxDecodedBytes}-byte limit`,
    );
  }
  if (
    decodedBytesCharged
    + reservedDecodedBytes
    + overlay.ramSize
    > limits.maxAggregateDecodedBytes
  ) {
    throw new NdsError(
      "blz-output-limit",
      `Decoding ${overlay.processor.toUpperCase()} overlay ${overlay.overlayId} would exceed the ${limits.maxAggregateDecodedBytes}-byte aggregate decoded-overlay limit`,
    );
  }
}

async function readStoredOverlay(map: NdsRomMap, overlay: NdsOverlay): Promise<Buffer> {
  const handle = await open(map.romPath, "r");
  try {
    return await readExact(
      handle,
      overlay.romOffset,
      overlay.romSize,
      `${overlay.processor.toUpperCase()} overlay ${overlay.overlayId} FAT backing`,
    );
  } finally {
    await handle.close();
  }
}

export function createNdsOverlayRuntimeContext(
  map: NdsRomMap,
  limitOverrides: Partial<NdsOverlayRuntimeLimits> = {},
): NdsOverlayRuntimeContext {
  const limits = resolvedLimits(limitOverrides);
  const cache = new Map<string, NdsOverlayRuntimeImage>();
  const inFlight = new Map<string, Promise<NdsOverlayRuntimeImage>>();
  let decodedBytesCharged = 0;
  let reservedDecodedBytes = 0;

  async function loadCompressedOverlay(
    processor: NdsProcessor,
    overlayId: number,
  ): Promise<NdsOverlayRuntimeImage> {
    const overlay = selectCompressedOverlay(map, processor, overlayId);
    enforceOverlayLimits(
      overlay,
      limits,
      decodedBytesCharged,
      reservedDecodedBytes,
    );

    reservedDecodedBytes += overlay.ramSize;
    try {
      const stored = await readStoredOverlay(map, overlay);
      const compressedPayload = stored.subarray(0, overlay.compressedSize);
      const decoded = decodeNdsBlz(compressedPayload, overlay.ramSize, {
        maxStoredBytes: limits.maxStoredBytes,
        maxDecodedBytes: limits.maxDecodedBytes,
      });

      await assertSourceIdentity(map);

      const image: NdsOverlayRuntimeImage = {
        processor,
        overlayId,
        fileId: overlay.fileId,
        sourceRomSha256: map.sha256,
        storedRomOffset: overlay.romOffset,
        storedSize: overlay.romSize,
        compressedSize: overlay.compressedSize,
        storedSha256: sha256(stored),
        compressedPayloadSha256: sha256(compressedPayload),
        runtimeAddress: overlay.ramAddress,
        runtimeSize: overlay.ramSize,
        bssSize: overlay.bssSize,
        representation: "derived-blz",
        runtimeSha256: sha256(decoded.bytes),
        bytes: decoded.bytes,
      };

      decodedBytesCharged += image.runtimeSize;
      cache.set(`${processor}:${overlayId}`, image);
      return image;
    } finally {
      reservedDecodedBytes -= overlay.ramSize;
    }
  }

  return {
    get decodedBytesCharged() {
      return decodedBytesCharged;
    },

    async getCompressedOverlay(
      processor: NdsProcessor,
      overlayId: number,
    ): Promise<NdsOverlayRuntimeImage> {
      await assertSourceIdentity(map);
      const key = `${processor}:${overlayId}`;
      const cached = cache.get(key);
      if (cached !== undefined) {
        return cached;
      }

      const active = inFlight.get(key);
      if (active !== undefined) {
        return active;
      }

      const promise = loadCompressedOverlay(processor, overlayId);
      inFlight.set(key, promise);
      try {
        return await promise;
      } finally {
        if (inFlight.get(key) === promise) {
          inFlight.delete(key);
        }
      }
    },
  };
}
