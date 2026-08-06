import { open, stat } from "node:fs/promises";

const HEADER_BYTES = 0x30;
const ARM9_ROM_OFFSET_FIELD = 0x20;
const ARM9_RAM_ADDRESS_FIELD = 0x28;
const ARM9_SIZE_FIELD = 0x2c;
const MAIN_RAM_START = 0x02000000;
const MAIN_RAM_END = 0x02400000;

export interface Arm9ExecutableRange {
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly source: "arm9-header";
  readonly label: "ARM9 main";
}

function readU32Le(header: Buffer, offset: number): number {
  return header.readUInt32LE(offset);
}

export async function readArm9ExecutableRange(
  romPath: string,
): Promise<Arm9ExecutableRange> {
  const info = await stat(romPath);
  if (!info.isFile() || info.size < HEADER_BYTES) {
    throw new Error("NDS ROM is too short to contain an ARM9 header");
  }

  const handle = await open(romPath, "r");
  try {
    const header = Buffer.alloc(HEADER_BYTES);
    const { bytesRead } = await handle.read(header, 0, HEADER_BYTES, 0);
    if (bytesRead !== HEADER_BYTES) {
      throw new Error("NDS ROM is too short to contain an ARM9 header");
    }

    const romOffset = readU32Le(header, ARM9_ROM_OFFSET_FIELD);
    const start = readU32Le(header, ARM9_RAM_ADDRESS_FIELD);
    const size = readU32Le(header, ARM9_SIZE_FIELD);
    if (size === 0) throw new Error("NDS ARM9 executable size must be positive");

    const end = start + size;
    if (!Number.isSafeInteger(end) || end > 0x1_0000_0000 || end <= start) {
      throw new Error("NDS ARM9 executable range overflows 32-bit address space");
    }
    if (start < MAIN_RAM_START || end > MAIN_RAM_END) {
      throw new Error("NDS ARM9 executable range is outside DS main RAM");
    }

    const romEnd = romOffset + size;
    if (!Number.isSafeInteger(romEnd) || romEnd > info.size) {
      throw new Error("NDS ARM9 executable extends beyond the ROM file");
    }

    return {
      start,
      end,
      size,
      source: "arm9-header",
      label: "ARM9 main",
    };
  } finally {
    await handle.close();
  }
}
