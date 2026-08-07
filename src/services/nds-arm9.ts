import { readArm9HeaderMetadata } from "./nds/header.js";

const MAIN_RAM_START = 0x02000000;
const MAIN_RAM_END = 0x02400000;

export interface Arm9ExecutableRange {
  readonly start: number;
  readonly end: number;
  readonly size: number;
  readonly source: "arm9-header";
  readonly label: "ARM9 main";
}

export async function readArm9ExecutableRange(
  romPath: string,
): Promise<Arm9ExecutableRange> {
  const arm9 = await readArm9HeaderMetadata(romPath);
  const start = arm9.ramAddress;
  const end = arm9.ramEnd;
  const size = arm9.size;

  if (start < MAIN_RAM_START || end > MAIN_RAM_END) {
    throw new Error("NDS ARM9 executable range is outside DS main RAM");
  }

  return {
    start,
    end,
    size,
    source: "arm9-header",
    label: "ARM9 main",
  };
}
