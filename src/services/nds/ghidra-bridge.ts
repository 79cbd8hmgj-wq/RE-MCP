import { existsSync } from "node:fs";
import {
  copyFile,
  mkdir,
  open,
  readFile,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { resolveInside } from "../../security/paths.js";
import { createCapstoneArmBackend } from "../disassembly/capstone.js";
import { extractNdsAnalysisBundle } from "./extraction.js";
import {
  discoverNdsFunctions,
  type FunctionDiscoveryLimits,
} from "./function-discovery.js";
import {
  buildGhidraBridgeManifest,
  ghidraGeneratedBridgeRoot,
  type GhidraBridgeArtifact,
  type GhidraBridgeManifest,
  type GhidraProcessorManifest,
} from "./ghidra-model.js";
import { NdsError } from "./errors.js";
import { hashFileSha256 } from "./io.js";
import type { NdsRomMap } from "./rom-map.js";

const GHIDRA_DISCOVERY_LIMITS: FunctionDiscoveryLimits = {
  maxComponents: 32,
  maxFunctions: 128,
  maxCallSites: 512,
  maxTotalBlocks: 512,
  maxTotalInstructions: 4096,
  maxTotalBytes: 32768,
  maxTotalEdges: 2048,
  perFunctionCfg: {
    maxBlocks: 64,
    maxInstructions: 512,
    maxBytes: 2048,
    maxEdges: 128,
  },
};

const SCRIPT_NAMES = [
  "ReMcpPrepareProgram.java",
  "ReMcpImportEvidence.java",
  "ReMcpRecordAnalysis.java",
] as const;

export interface GeneratedGhidraBridge {
  readonly bridgeRoot: string;
  readonly manifestPath: string;
  readonly manifestSha256: string;
  readonly manifest: GhidraBridgeManifest;
}

function portable(relativePath: string): string {
  return relativePath.split(path.sep).join("/");
}

function stableJson(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

async function syncFile(filePath: string): Promise<void> {
  const handle = await open(filePath, "r+");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeJson(filePath: string, value: unknown): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, stableJson(value), "utf8");
  await syncFile(filePath);
}

function candidateResourceRoots(): readonly string[] {
  return [
    fileURLToPath(new URL("../../../resources/ghidra/", import.meta.url)),
    fileURLToPath(new URL("../../../../resources/ghidra/", import.meta.url)),
  ];
}

export function resolveGhidraBridgeResourceRoot(): string {
  for (const candidate of candidateResourceRoots()) {
    if (existsSync(candidate)) {
      return path.resolve(candidate);
    }
  }
  throw new NdsError(
    "bridge-generation-failed",
    "RE-MCP packaged Ghidra bridge resources are missing",
  );
}

function resolveArtifactPath(bridgeRoot: string, relativePath: string): string {
  const generatedRoot = path.dirname(bridgeRoot);
  const candidate = path.resolve(bridgeRoot, relativePath);
  const relativeToGenerated = path.relative(generatedRoot, candidate);
  return resolveInside(generatedRoot, relativeToGenerated);
}

async function artifactFor(
  bridgeRoot: string,
  relativePath: string,
): Promise<GhidraBridgeArtifact> {
  const absolute = resolveArtifactPath(bridgeRoot, relativePath);
  const info = await stat(absolute);
  if (!info.isFile()) {
    throw new NdsError(
      "bridge-generation-failed",
      `Ghidra bridge artifact is not a regular file: ${relativePath}`,
    );
  }
  return {
    path: portable(relativePath),
    sha256: await hashFileSha256(absolute),
    size: info.size,
  };
}

function staticArtifactPaths(manifest: GhidraBridgeManifest): string[] {
  const paths: string[] = [];
  for (const processor of manifest.processors) {
    paths.push(processor.main.artifactPath);
    for (const overlay of processor.overlays) {
      paths.push(overlay.artifactPath);
    }
  }
  return paths;
}

async function copyMainImportArtifacts(
  temporaryRoot: string,
  processors: readonly GhidraProcessorManifest[],
): Promise<void> {
  const generatedRoot = path.dirname(temporaryRoot);
  for (const processor of processors) {
    const source = resolveInside(generatedRoot, `${processor.processor}.bin`);
    const destination = resolveArtifactPath(temporaryRoot, processor.main.artifactPath);
    await mkdir(path.dirname(destination), { recursive: true });
    await copyFile(source, destination);
    await syncFile(destination);
  }
}

async function copyScriptResources(temporaryRoot: string): Promise<string[]> {
  const resourceRoot = resolveGhidraBridgeResourceRoot();
  const scriptRoot = resolveInside(temporaryRoot, "scripts");
  await mkdir(scriptRoot, { recursive: true });
  const relativePaths: string[] = [];
  for (const name of SCRIPT_NAMES) {
    const source = resolveInside(resourceRoot, name);
    const destination = resolveInside(scriptRoot, name);
    await copyFile(source, destination);
    await syncFile(destination);
    relativePaths.push(portable(path.join("scripts", name)));
  }
  return relativePaths;
}

function functionsEvidence(manifest: GhidraBridgeManifest) {
  return {
    format: "re-mcp-nds-ghidra-functions",
    formatVersion: 1,
    sourceRomSha256: manifest.sourceRomSha256,
    processors: manifest.discovery.map((entry) => ({
      processor: entry.processor,
      status: entry.status,
      functions: entry.functions,
      coverage: entry.coverage,
      truncationReasons: entry.truncationReasons,
      totals: entry.totals,
    })),
  };
}

function callsEvidence(manifest: GhidraBridgeManifest) {
  return {
    format: "re-mcp-nds-ghidra-calls",
    formatVersion: 1,
    sourceRomSha256: manifest.sourceRomSha256,
    processors: manifest.discovery.map((entry) => ({
      processor: entry.processor,
      calls: entry.calls,
    })),
  };
}

async function buildTemporaryBridge(
  map: NdsRomMap,
  finalRoot: string,
  arm9: Awaited<ReturnType<typeof discoverNdsFunctions>>,
  arm7: Awaited<ReturnType<typeof discoverNdsFunctions>>,
): Promise<{
  readonly temporaryRoot: string;
  readonly manifest: GhidraBridgeManifest;
  readonly manifestSha256: string;
}> {
  const generatedRoot = path.dirname(finalRoot);
  const temporaryRoot = resolveInside(
    generatedRoot,
    `.ghidra-bridge.tmp-${process.pid}-${Date.now()}`,
  );
  await rm(temporaryRoot, { recursive: true, force: true });
  await mkdir(resolveInside(temporaryRoot, "evidence"), { recursive: true });
  await mkdir(resolveInside(temporaryRoot, "results"), { recursive: true });

  try {
    const canonical = buildGhidraBridgeManifest({
      map,
      arm9,
      arm7,
      artifacts: [],
    });

    await copyMainImportArtifacts(temporaryRoot, canonical.processors);
    const functionsPath = resolveInside(temporaryRoot, path.join("evidence", "functions.json"));
    const callsPath = resolveInside(temporaryRoot, path.join("evidence", "calls.json"));
    await writeJson(functionsPath, functionsEvidence(canonical));
    await writeJson(callsPath, callsEvidence(canonical));
    const scriptPaths = await copyScriptResources(temporaryRoot);

    const artifactPaths = [
      ...staticArtifactPaths(canonical),
      "evidence/functions.json",
      "evidence/calls.json",
      ...scriptPaths,
    ];
    const artifacts: GhidraBridgeArtifact[] = [];
    for (const relativePath of artifactPaths) {
      artifacts.push(await artifactFor(temporaryRoot, relativePath));
    }

    const manifest = buildGhidraBridgeManifest({ map, arm9, arm7, artifacts });
    const manifestPath = resolveInside(temporaryRoot, "manifest.json");
    await writeJson(manifestPath, manifest);
    const manifestSha256 = await hashFileSha256(manifestPath);
    return { temporaryRoot, manifest, manifestSha256 };
  } catch (error) {
    await rm(temporaryRoot, { recursive: true, force: true });
    throw error;
  }
}

function bridgeError(operation: string, error: unknown): never {
  if (error instanceof NdsError) {
    throw error;
  }
  throw new NdsError(
    "bridge-generation-failed",
    `${operation} failed: ${error instanceof Error ? error.message : String(error)}`,
  );
}

export async function generateNdsGhidraBridge(
  map: NdsRomMap,
  workspaceRoot: string,
): Promise<GeneratedGhidraBridge> {
  let temporaryRoot: string | null = null;
  try {
    const bundle = await extractNdsAnalysisBundle(map, workspaceRoot);
    const bridgeRoot = ghidraGeneratedBridgeRoot(map, workspaceRoot);
    if (path.dirname(bridgeRoot) !== path.resolve(bundle.outputRoot)) {
      throw new NdsError(
        "bridge-generation-failed",
        "Canonical Ghidra bridge root does not match the generated NDS analysis bundle",
      );
    }

    const backend = await createCapstoneArmBackend();
    let arm9;
    let arm7;
    try {
      arm9 = await discoverNdsFunctions(
        map,
        {
          processor: "arm9",
          scope: { kind: "all-executable-components" },
          seeds: [],
        },
        GHIDRA_DISCOVERY_LIMITS,
        backend,
      );
      arm7 = await discoverNdsFunctions(
        map,
        {
          processor: "arm7",
          scope: { kind: "all-executable-components" },
          seeds: [],
        },
        GHIDRA_DISCOVERY_LIMITS,
        backend,
      );
    } finally {
      backend.close();
    }

    const built = await buildTemporaryBridge(map, bridgeRoot, arm9, arm7);
    temporaryRoot = built.temporaryRoot;

    const afterSha256 = await hashFileSha256(map.romPath);
    if (afterSha256 !== map.sha256) {
      throw new NdsError(
        "invalid-rom",
        "Source ROM changed while the Ghidra bridge was being generated",
      );
    }

    await rm(bridgeRoot, { recursive: true, force: true });
    await rename(temporaryRoot, bridgeRoot);
    temporaryRoot = null;

    const manifestPath = resolveInside(bridgeRoot, "manifest.json");
    const result: GeneratedGhidraBridge = {
      bridgeRoot,
      manifestPath,
      manifestSha256: built.manifestSha256,
      manifest: built.manifest,
    };
    await validateGeneratedGhidraBridge(result);
    return result;
  } catch (error) {
    if (temporaryRoot !== null) {
      try {
        await rm(temporaryRoot, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup; report the primary failure.
      }
    }
    return bridgeError("NDS Ghidra bridge generation", error);
  }
}

export async function validateGeneratedGhidraBridge(
  bridge: GeneratedGhidraBridge,
): Promise<void> {
  try {
    const actualManifestSha256 = await hashFileSha256(bridge.manifestPath);
    if (actualManifestSha256 !== bridge.manifestSha256) {
      throw new NdsError(
        "bridge-generation-failed",
        "Ghidra bridge manifest SHA-256 no longer matches the generated bridge",
      );
    }

    const parsed = JSON.parse(await readFile(bridge.manifestPath, "utf8")) as GhidraBridgeManifest;
    if (
      parsed.format !== bridge.manifest.format
      || parsed.formatVersion !== bridge.manifest.formatVersion
      || parsed.sourceRomSha256 !== bridge.manifest.sourceRomSha256
    ) {
      throw new NdsError(
        "bridge-generation-failed",
        "Ghidra bridge manifest identity no longer matches the generated bridge",
      );
    }

    for (const artifact of bridge.manifest.artifacts) {
      const absolute = resolveArtifactPath(bridge.bridgeRoot, artifact.path);
      const info = await stat(absolute);
      if (!info.isFile() || info.size !== artifact.size) {
        throw new NdsError(
          "bridge-generation-failed",
          `Ghidra bridge artifact size mismatch: ${artifact.path}`,
        );
      }
      const actualSha256 = await hashFileSha256(absolute);
      if (actualSha256 !== artifact.sha256) {
        throw new NdsError(
          "bridge-generation-failed",
          `Ghidra bridge artifact hash mismatch: ${artifact.path}`,
        );
      }
    }
  } catch (error) {
    return bridgeError("Ghidra bridge validation", error);
  }
}
