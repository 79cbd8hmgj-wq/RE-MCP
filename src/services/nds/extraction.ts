import { createReadStream, createWriteStream } from "node:fs";
import {
  mkdir as nativeMkdir,
  open,
  readFile,
  rename as nativeRename,
  rm as nativeRm,
  stat,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";

import { resolveInside } from "../../security/paths.js";
import { NdsError } from "./errors.js";
import { hashFileSha256 } from "./io.js";
import {
  createNdsOverlayRuntimeContext,
  type NdsOverlayRuntimeImage,
} from "./overlay-runtime.js";
import type { NdsOverlay, NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

export type NdsExtractionRequest =
  | { readonly component: "arm9" }
  | { readonly component: "arm7" }
  | { readonly component: "arm9-overlay"; readonly overlayId: number }
  | { readonly component: "arm7-overlay"; readonly overlayId: number }
  | { readonly component: "nitrofs-file"; readonly fileId: number }
  | { readonly component: "nitrofs-path"; readonly filePath: string };

export interface NdsExtractedArtifact {
  readonly output: string;
  readonly component: string;
  readonly sourceRomSha256: string;
  readonly outputSha256: string;
  readonly romOffset: number;
  readonly size: number;
  readonly ramAddress: number | null;
  readonly processor: NdsProcessor | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly compressed: boolean;
  readonly compressedSize: number | null;
}

export interface NdsDerivedRuntimeArtifact {
  readonly output: string;
  readonly processor: NdsProcessor;
  readonly overlayId: number;
  readonly fileId: number;
  readonly sourceRomSha256: string;
  readonly representation: "derived-blz";
  readonly romOffset: null;
  readonly storedRomOffset: number;
  readonly storedSize: number;
  readonly compressedSize: number;
  readonly storedSha256: string;
  readonly compressedPayloadSha256: string;
  readonly runtimeAddress: number;
  readonly runtimeSize: number;
  readonly bssSize: number;
  readonly runtimeSha256: string;
  readonly outputSha256: string;
}

export interface NdsExtractionFs {
  mkdir(target: string, options: { recursive: true }): Promise<string | undefined>;
  rename(source: string, destination: string): Promise<void>;
  rm(target: string, options: { recursive: true; force: true }): Promise<void>;
}

const defaultExtractionFs: NdsExtractionFs = {
  mkdir: nativeMkdir,
  rename: nativeRename,
  rm: nativeRm,
};

interface ComponentSource {
  readonly component: string;
  readonly relativeOutput: string;
  readonly romOffset: number;
  readonly size: number;
  readonly ramAddress: number | null;
  readonly processor: NdsProcessor | null;
  readonly overlayId: number | null;
  readonly fileId: number | null;
  readonly compressed: boolean;
  readonly compressedSize: number | null;
}

function generatedRoot(map: NdsRomMap, workspaceRoot: string): string {
  return resolveInside(
    workspaceRoot,
    path.join("analysis", "generated", "nds", map.sha256Prefix),
  );
}

function asGeneratedError(operation: string, error: unknown): NdsError {
  if (error instanceof NdsError) {
    return error;
  }
  return new NdsError(
    "generated-path-failure",
    `${operation} failed: ${error instanceof Error ? error.message : String(error)}`,
  );
}

async function assertSourceIdentity(map: NdsRomMap, workspaceRoot: string): Promise<void> {
  let resolvedSource: string;
  try {
    resolvedSource = resolveInside(workspaceRoot, map.romPath);
  } catch (error) {
    throw new NdsError(
      "invalid-rom",
      `Source ROM is outside the configured workspace: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (path.resolve(resolvedSource) !== path.resolve(map.romPath)) {
    throw new NdsError("invalid-rom", "Canonical ROM path no longer matches the workspace source path");
  }
  const actualSha256 = await hashFileSha256(map.romPath);
  if (actualSha256 !== map.sha256) {
    throw new NdsError(
      "invalid-rom",
      "Source ROM SHA-256 no longer matches the canonical NDS map; parse the ROM again before extraction",
    );
  }
}

function overlaySource(overlay: NdsOverlay): ComponentSource {
  return {
    component: `${overlay.processor}-overlay`,
    relativeOutput: path.join(
      "overlays",
      overlay.processor,
      `overlay_${overlay.overlayId}.bin`,
    ),
    romOffset: overlay.romOffset,
    size: overlay.romSize,
    ramAddress: overlay.ramAddress,
    processor: overlay.processor,
    overlayId: overlay.overlayId,
    fileId: overlay.fileId,
    compressed: overlay.compressed,
    compressedSize: overlay.compressed ? overlay.compressedSize : null,
  };
}

function selectComponent(map: NdsRomMap, request: NdsExtractionRequest): ComponentSource {
  if (request.component === "arm9" || request.component === "arm7") {
    const processor = request.component;
    const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
    return {
      component: processor,
      relativeOutput: `${processor}.bin`,
      romOffset: executable.romOffset,
      size: executable.size,
      ramAddress: executable.ramAddress,
      processor,
      overlayId: null,
      fileId: null,
      compressed: false,
      compressedSize: null,
    };
  }

  if (request.component === "arm9-overlay" || request.component === "arm7-overlay") {
    const processor: NdsProcessor = request.component === "arm9-overlay" ? "arm9" : "arm7";
    const overlays = processor === "arm9" ? map.overlays.arm9 : map.overlays.arm7;
    const overlay = overlays.find((candidate) => candidate.overlayId === request.overlayId);
    if (overlay === undefined) {
      throw new NdsError(
        "unknown-overlay-id",
        `${processor.toUpperCase()} overlay ${request.overlayId} does not exist in the canonical ROM map`,
      );
    }
    return overlaySource(overlay);
  }

  const file = request.component === "nitrofs-file"
    ? map.filesystem.files.find((candidate) => candidate.fileId === request.fileId)
    : map.filesystem.files.find((candidate) => candidate.path === request.filePath);
  if (file === undefined) {
    const selector = request.component === "nitrofs-file"
      ? `file ID ${request.fileId}`
      : `path ${JSON.stringify(request.filePath)}`;
    throw new NdsError("unknown-file-id", `NitroFS ${selector} does not exist in the canonical ROM map`);
  }
  return {
    component: "nitrofs-file",
    relativeOutput: path.join("nitrofs", `file_${file.fileId}.bin`),
    romOffset: file.startOffset,
    size: file.size,
    ramAddress: null,
    processor: null,
    overlayId: null,
    fileId: file.fileId,
    compressed: false,
    compressedSize: null,
  };
}

async function syncFile(filePath: string): Promise<void> {
  const handle = await open(filePath, "r+");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function copyRangeAtomic(
  sourcePath: string,
  start: number,
  length: number,
  outputPath: string,
): Promise<string> {
  const temporary = `${outputPath}.tmp-${process.pid}-${Date.now()}`;
  await nativeMkdir(path.dirname(outputPath), { recursive: true });
  try {
    if (length === 0) {
      await writeFile(temporary, Buffer.alloc(0), { flag: "wx" });
    } else {
      await pipeline(
        createReadStream(sourcePath, { start, end: start + length - 1 }),
        createWriteStream(temporary, { flags: "wx" }),
      );
    }
    await syncFile(temporary);
    await nativeRename(temporary, outputPath);
    return await hashFileSha256(outputPath);
  } catch (error) {
    try {
      await nativeRm(temporary, { force: true });
    } catch {
      // Best-effort cleanup.
    }
    throw asGeneratedError("Atomic NDS component extraction", error);
  }
}

async function writeBufferAtomic(outputPath: string, bytes: Buffer): Promise<string> {
  const temporary = `${outputPath}.tmp-${process.pid}-${Date.now()}`;
  await nativeMkdir(path.dirname(outputPath), { recursive: true });
  try {
    await writeFile(temporary, bytes, { flag: "wx" });
    await syncFile(temporary);
    await nativeRename(temporary, outputPath);
    return await hashFileSha256(outputPath);
  } catch (error) {
    try {
      await nativeRm(temporary, { force: true });
    } catch {
      // Best-effort cleanup.
    }
    throw asGeneratedError("Atomic NDS runtime artifact write", error);
  }
}

async function writeJsonAtomic(outputPath: string, value: unknown): Promise<void> {
  const temporary = `${outputPath}.tmp-${process.pid}-${Date.now()}`;
  await nativeMkdir(path.dirname(outputPath), { recursive: true });
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
    });
    await syncFile(temporary);
    await nativeRename(temporary, outputPath);
  } catch (error) {
    try {
      await nativeRm(temporary, { force: true });
    } catch {
      // Best-effort cleanup.
    }
    throw asGeneratedError("Atomic NDS metadata write", error);
  }
}

async function extractSourceTo(
  map: NdsRomMap,
  source: ComponentSource,
  outputPath: string,
): Promise<NdsExtractedArtifact> {
  if (
    source.romOffset < 0
    || source.size < 0
    || source.romOffset + source.size > map.fileSize
  ) {
    throw new NdsError("range-out-of-bounds", `${source.component} extraction range is outside the ROM`);
  }
  const outputSha256 = await copyRangeAtomic(
    map.romPath,
    source.romOffset,
    source.size,
    outputPath,
  );
  return {
    output: outputPath,
    component: source.component,
    sourceRomSha256: map.sha256,
    outputSha256,
    romOffset: source.romOffset,
    size: source.size,
    ramAddress: source.ramAddress,
    processor: source.processor,
    overlayId: source.overlayId,
    fileId: source.fileId,
    compressed: source.compressed,
    compressedSize: source.compressedSize,
  };
}

async function writeRuntimeArtifactTo(
  image: NdsOverlayRuntimeImage,
  outputPath: string,
): Promise<NdsDerivedRuntimeArtifact> {
  const outputSha256 = await writeBufferAtomic(outputPath, image.bytes);
  if (outputSha256 !== image.runtimeSha256) {
    try {
      await nativeRm(outputPath, { force: true });
    } catch {
      // Best-effort cleanup of an artifact whose hash failed validation.
    }
    throw new NdsError(
      "generated-path-failure",
      `Decoded ${image.processor.toUpperCase()} overlay ${image.overlayId} artifact hash does not match the canonical runtime image`,
    );
  }
  return {
    output: outputPath,
    processor: image.processor,
    overlayId: image.overlayId,
    fileId: image.fileId,
    sourceRomSha256: image.sourceRomSha256,
    representation: image.representation,
    romOffset: null,
    storedRomOffset: image.storedRomOffset,
    storedSize: image.storedSize,
    compressedSize: image.compressedSize,
    storedSha256: image.storedSha256,
    compressedPayloadSha256: image.compressedPayloadSha256,
    runtimeAddress: image.runtimeAddress,
    runtimeSize: image.runtimeSize,
    bssSize: image.bssSize,
    runtimeSha256: image.runtimeSha256,
    outputSha256,
  };
}

export async function extractNdsComponent(
  map: NdsRomMap,
  workspaceRoot: string,
  request: NdsExtractionRequest,
): Promise<NdsExtractedArtifact> {
  await assertSourceIdentity(map, workspaceRoot);
  const source = selectComponent(map, request);
  const root = generatedRoot(map, workspaceRoot);
  const outputPath = resolveInside(root, source.relativeOutput);
  const artifact = await extractSourceTo(map, source, outputPath);
  const afterSha256 = await hashFileSha256(map.romPath);
  if (afterSha256 !== map.sha256) {
    try {
      await nativeRm(outputPath, { force: true });
    } catch {
      // Best-effort cleanup of an artifact produced from a changing source.
    }
    throw new NdsError(
      "invalid-rom",
      "Source ROM changed during extraction; the generated artifact was discarded",
    );
  }
  return artifact;
}

async function exists(target: string): Promise<boolean> {
  try {
    await stat(target);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

function manifestArtifact(
  artifact: NdsExtractedArtifact,
  root: string,
): Omit<NdsExtractedArtifact, "output"> & { readonly output: string } {
  return {
    ...artifact,
    output: path.relative(root, artifact.output).split(path.sep).join("/"),
  };
}

function manifestRuntimeArtifact(
  artifact: NdsDerivedRuntimeArtifact,
  root: string,
): Omit<NdsDerivedRuntimeArtifact, "output"> & { readonly output: string } {
  return {
    ...artifact,
    output: path.relative(root, artifact.output).split(path.sep).join("/"),
  };
}

export async function extractNdsAnalysisBundle(
  map: NdsRomMap,
  workspaceRoot: string,
  fsOps: NdsExtractionFs = defaultExtractionFs,
): Promise<{ readonly outputRoot: string; readonly manifestPath: string }> {
  await assertSourceIdentity(map, workspaceRoot);
  const finalRoot = generatedRoot(map, workspaceRoot);
  const parentRoot = path.dirname(finalRoot);
  const suffix = `${process.pid}-${Date.now()}`;
  const temporaryRoot = resolveInside(parentRoot, `${map.sha256Prefix}.tmp-${suffix}`);
  const backupRoot = resolveInside(parentRoot, `${map.sha256Prefix}.bak-${suffix}`);
  await fsOps.mkdir(parentRoot, { recursive: true });
  await fsOps.rm(temporaryRoot, { recursive: true, force: true });
  await fsOps.mkdir(temporaryRoot, { recursive: true });

  const artifacts: NdsExtractedArtifact[] = [];
  const runtimeArtifacts: NdsDerivedRuntimeArtifact[] = [];
  const runtimeContext = createNdsOverlayRuntimeContext(map);
  try {
    const arm9 = selectComponent(map, { component: "arm9" });
    const arm7 = selectComponent(map, { component: "arm7" });
    artifacts.push(await extractSourceTo(map, arm9, resolveInside(temporaryRoot, arm9.relativeOutput)));
    artifacts.push(await extractSourceTo(map, arm7, resolveInside(temporaryRoot, arm7.relativeOutput)));
    for (const overlay of [...map.overlays.arm9, ...map.overlays.arm7]) {
      const source = overlaySource(overlay);
      artifacts.push(
        await extractSourceTo(map, source, resolveInside(temporaryRoot, source.relativeOutput)),
      );
      if (overlay.compressed) {
        const image = await runtimeContext.getCompressedOverlay(
          overlay.processor,
          overlay.overlayId,
        );
        const runtimeOutput = resolveInside(
          temporaryRoot,
          path.join(
            "runtime",
            "overlays",
            overlay.processor,
            `overlay_${overlay.overlayId}.bin`,
          ),
        );
        runtimeArtifacts.push(await writeRuntimeArtifactTo(image, runtimeOutput));
      }
    }

    await writeJsonAtomic(resolveInside(temporaryRoot, "address-map.json"), {
      sourceRomSha256: map.sha256,
      executableRanges: map.executableRanges,
    });
    await writeJsonAtomic(resolveInside(temporaryRoot, "filesystem.json"), {
      sourceRomSha256: map.sha256,
      directories: map.filesystem.directories,
      files: map.filesystem.files,
    });
    await writeJsonAtomic(resolveInside(temporaryRoot, "overlays.json"), {
      sourceRomSha256: map.sha256,
      overlays: map.overlays,
    });
    await writeJsonAtomic(resolveInside(temporaryRoot, "manifest.json"), {
      format: "re-mcp-nds-static-analysis",
      formatVersion: 1,
      sourceRom: path.relative(workspaceRoot, map.romPath).split(path.sep).join("/"),
      sourceRomSha256: map.sha256,
      sha256Prefix: map.sha256Prefix,
      artifacts: artifacts.map((artifact) => manifestArtifact(artifact, temporaryRoot)),
      runtimeArtifacts: runtimeArtifacts.map(
        (artifact) => manifestRuntimeArtifact(artifact, temporaryRoot),
      ),
    });

    const afterSha256 = await hashFileSha256(map.romPath);
    if (afterSha256 !== map.sha256) {
      throw new NdsError(
        "invalid-rom",
        "Source ROM changed while the analysis bundle was being generated",
      );
    }
  } catch (error) {
    try {
      await fsOps.rm(temporaryRoot, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
    throw asGeneratedError("NDS analysis bundle generation", error);
  }

  let backupCreated = false;
  try {
    if (await exists(finalRoot)) {
      await fsOps.rename(finalRoot, backupRoot);
      backupCreated = true;
    }
    await fsOps.rename(temporaryRoot, finalRoot);
    if (backupCreated) {
      await fsOps.rm(backupRoot, { recursive: true, force: true });
    }
  } catch (error) {
    try {
      if (await exists(finalRoot)) {
        await fsOps.rm(finalRoot, { recursive: true, force: true });
      }
      if (backupCreated && await exists(backupRoot)) {
        await fsOps.rename(backupRoot, finalRoot);
      }
    } catch {
      // Best-effort restoration; the primary promotion failure is reported below.
    }
    try {
      await fsOps.rm(temporaryRoot, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
    throw asGeneratedError("NDS analysis bundle promotion", error);
  }

  return {
    outputRoot: finalRoot,
    manifestPath: path.join(finalRoot, "manifest.json"),
  };
}
