import { parseNdsFat, type NdsFatEntry } from "./fat.js";
import { parseNdsFnt, type NdsFilesystem } from "./fnt.js";
import { parseNdsHeader, type NdsHeader } from "./header.js";
import {
  parseNdsOverlays,
  type NdsOverlay,
  type NdsProcessor,
} from "./overlays.js";

export interface NdsExecutableRange {
  readonly kind: "arm9-main" | "arm7-main" | "arm9-overlay" | "arm7-overlay";
  readonly processor: NdsProcessor;
  readonly start: number;
  readonly initializedEnd: number;
  readonly end: number;
  readonly sourceId: string;
  readonly overlayId: number | null;
  readonly compressed: boolean;
}

export interface NdsRomMap {
  readonly romPath: string;
  readonly fileSize: number;
  readonly sha256: string;
  readonly sha256Prefix: string;
  readonly header: NdsHeader;
  readonly fat: readonly NdsFatEntry[];
  readonly filesystem: NdsFilesystem;
  readonly overlays: Readonly<{
    arm9: readonly NdsOverlay[];
    arm7: readonly NdsOverlay[];
  }>;
  readonly executableRanges: readonly NdsExecutableRange[];
}

function mainRange(
  processor: NdsProcessor,
  header: NdsHeader,
): NdsExecutableRange {
  const executable = processor === "arm9" ? header.arm9 : header.arm7;
  return {
    kind: processor === "arm9" ? "arm9-main" : "arm7-main",
    processor,
    start: executable.ramAddress,
    initializedEnd: executable.ramEnd,
    end: executable.ramEnd,
    sourceId: `${processor}-main`,
    overlayId: null,
    compressed: false,
  };
}

function overlayRange(overlay: NdsOverlay): NdsExecutableRange {
  return {
    kind: overlay.processor === "arm9" ? "arm9-overlay" : "arm7-overlay",
    processor: overlay.processor,
    start: overlay.ramAddress,
    initializedEnd: overlay.ramEnd,
    end: overlay.bssEnd,
    sourceId: `${overlay.processor}-overlay:${overlay.overlayId}`,
    overlayId: overlay.overlayId,
    compressed: overlay.compressed,
  };
}

function sortOverlays(overlays: readonly NdsOverlay[]): readonly NdsOverlay[] {
  return [...overlays].sort((left, right) => left.overlayId - right.overlayId);
}

export async function readNdsRomMap(romPath: string): Promise<NdsRomMap> {
  const parsed = await parseNdsHeader(romPath);
  const fat = await parseNdsFat(parsed);
  const filesystem = await parseNdsFnt(parsed, fat);
  const arm9 = sortOverlays(await parseNdsOverlays(parsed, fat, "arm9"));
  const arm7 = sortOverlays(await parseNdsOverlays(parsed, fat, "arm7"));

  const executableRanges: NdsExecutableRange[] = [
    mainRange("arm9", parsed.header),
    mainRange("arm7", parsed.header),
    ...arm9.map(overlayRange),
    ...arm7.map(overlayRange),
  ];

  return {
    romPath: parsed.romPath,
    fileSize: parsed.fileSize,
    sha256: parsed.sha256,
    sha256Prefix: parsed.sha256Prefix,
    header: parsed.header,
    fat,
    filesystem,
    overlays: { arm9, arm7 },
    executableRanges,
  };
}
