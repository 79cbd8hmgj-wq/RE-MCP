export type Arm9ExecutionMode = "arm" | "thumb";

export interface Arm9RegisterContext {
  readonly r0: number;
  readonly r1: number;
  readonly r2: number;
  readonly r3: number;
  readonly r4: number;
  readonly r5: number;
  readonly r6: number;
  readonly r7: number;
  readonly r8: number;
  readonly r9: number;
  readonly r10: number;
  readonly r11: number;
  readonly r12: number;
  readonly sp: number;
  readonly lr: number;
  readonly pc: number;
  readonly cpsr: number;
  readonly mode: Arm9ExecutionMode;
  readonly byteOrder: "little";
  readonly raw: string;
}

const DESMUME_REGISTER_PACKET_HEX_LENGTH = 336;
const GENERAL_REGISTER_COUNT = 16;
const HEX_CHARS_PER_U32 = 8;
const CPSR_HEX_OFFSET = DESMUME_REGISTER_PACKET_HEX_LENGTH - HEX_CHARS_PER_U32;

function readLittleEndianU32(payload: string, hexOffset: number): number {
  const bytes = Buffer.from(payload.slice(hexOffset, hexOffset + HEX_CHARS_PER_U32), "hex");
  return bytes.readUInt32LE(0);
}

export function decodeArm9RegisterPacket(payload: string): Arm9RegisterContext {
  if (payload.length !== DESMUME_REGISTER_PACKET_HEX_LENGTH) {
    throw new Error(
      `DeSmuME ARM9 register packet must contain exactly ${DESMUME_REGISTER_PACKET_HEX_LENGTH} hexadecimal characters`,
    );
  }
  if (!/^[0-9a-fA-F]+$/.test(payload)) {
    throw new Error("DeSmuME ARM9 register packet must contain only hexadecimal characters");
  }

  const registers = Array.from({ length: GENERAL_REGISTER_COUNT }, (_, index) =>
    readLittleEndianU32(payload, index * HEX_CHARS_PER_U32),
  );
  const cpsr = readLittleEndianU32(payload, CPSR_HEX_OFFSET);

  return {
    r0: registers[0]!,
    r1: registers[1]!,
    r2: registers[2]!,
    r3: registers[3]!,
    r4: registers[4]!,
    r5: registers[5]!,
    r6: registers[6]!,
    r7: registers[7]!,
    r8: registers[8]!,
    r9: registers[9]!,
    r10: registers[10]!,
    r11: registers[11]!,
    r12: registers[12]!,
    sp: registers[13]!,
    lr: registers[14]!,
    pc: registers[15]!,
    cpsr,
    mode: (cpsr & 0x20) === 0 ? "arm" : "thumb",
    byteOrder: "little",
    raw: payload,
  };
}
