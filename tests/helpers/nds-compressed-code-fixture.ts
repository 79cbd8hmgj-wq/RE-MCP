import { readNdsRomMap } from "../../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./nds-fixture.js";

export const COMPRESSED_ARM_CODE_STORED = Buffer.from(
  "060000eb0034009fe5000000ea0000000df0110021a010402d1ce91eff2f0d606000201002011001f001f001f001f001f001f0fe01f001f001f001f00000a0e10f49000008b7000000",
  "hex",
);

const COMPRESSED_ARM_CODE_HEAD = Buffer.from(
  [
    "060000eb", // BL +0x20
    "34009fe5", // LDR r0, [pc, #0x34]
    "000000ea", // B +0x10
    "0000a0e1", // MOV r0, r0
    "1eff2fe1", // BX lr
    "0000a0e1",
    "0000a0e1",
    "0000a0e1",
    "1eff2fe1", // callee BX lr at +0x20
    "0000a0e1",
    "0000a0e1",
    "0000a0e1",
    "10402de9", // prologue-looking PUSH at +0x30; not proof by itself
    "1eff2fe1",
    "0000a0e1",
    "0000a0e1",
    "60002002", // literal/data word at +0x40
  ].join(""),
  "hex",
);

export const COMPRESSED_ARM_CODE_DECODED = Buffer.concat([
  COMPRESSED_ARM_CODE_HEAD,
  Buffer.from("0000a0e1".repeat(47), "hex"),
]);

export const COMPRESSED_ARM_CODE_OVERLAY_ID = 7;
export const COMPRESSED_ARM_CODE_RUNTIME_ADDRESS = 0x02200000;
export const COMPRESSED_ARM_CODE_STORED_OFFSET = 0x1200;

export async function createCompressedArmCodeFixture(options: {
  readonly overlayId?: number;
  readonly runtimeAddress?: number;
  readonly trailingBackingBytes?: number;
} = {}) {
  const overlayId = options.overlayId ?? COMPRESSED_ARM_CODE_OVERLAY_ID;
  const runtimeAddress = options.runtimeAddress ?? COMPRESSED_ARM_CODE_RUNTIME_ADDRESS;
  const trailingBackingBytes = options.trailingBackingBytes ?? 8;
  const backingSize = COMPRESSED_ARM_CODE_STORED.length + trailingBackingBytes;
  const fixture = await createNdsFixture({
    fileSize: 0x6000,
    arm9Size: 0x100,
    fatSize: 8,
    arm9OverlaySize: 32,
  });

  writeFatEntry(
    fixture.buffer,
    0x900,
    0,
    COMPRESSED_ARM_CODE_STORED_OFFSET,
    COMPRESSED_ARM_CODE_STORED_OFFSET + backingSize,
  );
  COMPRESSED_ARM_CODE_STORED.copy(
    fixture.buffer,
    COMPRESSED_ARM_CODE_STORED_OFFSET,
  );
  if (trailingBackingBytes > 0) {
    Buffer.alloc(trailingBackingBytes, 0x5a).copy(
      fixture.buffer,
      COMPRESSED_ARM_CODE_STORED_OFFSET + COMPRESSED_ARM_CODE_STORED.length,
    );
  }
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId,
    ramAddress: runtimeAddress,
    ramSize: COMPRESSED_ARM_CODE_DECODED.length,
    bssSize: 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: COMPRESSED_ARM_CODE_STORED.length,
    flags: 1,
  });
  await fixture.write();

  return {
    fixture,
    map: await readNdsRomMap(fixture.romPath),
    overlayId,
    runtimeAddress,
    decoded: COMPRESSED_ARM_CODE_DECODED,
    stored: COMPRESSED_ARM_CODE_STORED,
  };
}
