import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = path.resolve(process.argv[2] ?? process.cwd());
const servicePath = path.join(root, "dist", "services", "controller-checkpoint.js");
const toolPath = path.join(root, "dist", "tools", "controller-checkpoint.js");
const serviceUrl = pathToFileURL(servicePath).href;
const toolUrl = pathToFileURL(toolPath).href;

const {
  ControllerCheckpointError,
  controllerCheckpointPath,
  readControllerCheckpoint,
  writeControllerCheckpoint,
} = await import(serviceUrl);
await import(toolUrl);

const sourceSha256 = "0123456789abcdef".repeat(4);
const source = {
  sha256: sourceSha256,
  sha256Prefix: sourceSha256.slice(0, 12),
};

const temp = await mkdtemp(path.join(os.tmpdir(), "re-mcp-controller-checkpoint-package-"));
try {
  const evidenceRelative = `analysis/generated/nds/${source.sha256Prefix}/package-proof.json`;
  const evidencePath = path.join(temp, evidenceRelative);
  const evidenceBytes = Buffer.from('{"package":true}\n', "utf8");
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, evidenceBytes);

  const state = {
    objective: "Verify packaged provider-neutral controller checkpoints",
    confirmedFacts: [{
      id: "package-proof",
      statement: "The packaged checkpoint smoke references this deterministic fixture.",
      evidenceRefs: [{ path: evidenceRelative }],
    }],
    hypotheses: [],
    completedActions: [],
    nextActions: [{
      id: "continue",
      description: "A replacement controller may resume only after revalidating consequential facts.",
    }],
  };

  const written = await writeControllerCheckpoint(source, temp, 0, state);
  if (
    written.revision !== 1
    || written.authority !== "controller-state-only"
    || !/^[0-9a-f]{64}$/.test(written.contentSha256)
  ) {
    throw new Error("Packaged checkpoint first-write contract failed");
  }
  const expectedPath = path.join(
    temp,
    "analysis",
    "generated",
    "nds",
    source.sha256Prefix,
    "controller",
    "checkpoint.json",
  );
  if (controllerCheckpointPath(source, temp) !== expectedPath) {
    throw new Error("Packaged checkpoint path escaped the controlled source-SHA namespace");
  }

  const read = await readControllerCheckpoint(source, temp);
  if (!read.exists || read.expectedRevision !== 1 || read.checkpoint.revision !== 1) {
    throw new Error("Packaged checkpoint read contract failed");
  }
  const evidenceRef = read.checkpoint.confirmedFacts[0]?.evidenceRefs[0];
  if (evidenceRef?.path !== evidenceRelative || !/^[0-9a-f]{64}$/.test(evidenceRef.sha256)) {
    throw new Error("Packaged checkpoint evidence binding contract failed");
  }

  let staleCategory = null;
  try {
    await writeControllerCheckpoint(source, temp, 0, state);
  } catch (error) {
    if (error instanceof ControllerCheckpointError) staleCategory = error.category;
    else throw error;
  }
  if (staleCategory !== "checkpoint-revision-conflict") {
    throw new Error(`Expected checkpoint-revision-conflict, received ${String(staleCategory)}`);
  }

  const checkpointPath = controllerCheckpointPath(source, temp);
  const parsed = JSON.parse(await readFile(checkpointPath, "utf8"));
  parsed.objective = "tampered package checkpoint";
  await writeFile(checkpointPath, `${JSON.stringify(parsed, null, 2)}\n`);

  let tamperCategory = null;
  try {
    await readControllerCheckpoint(source, temp);
  } catch (error) {
    if (error instanceof ControllerCheckpointError) tamperCategory = error.category;
    else throw error;
  }
  if (tamperCategory !== "checkpoint-integrity-failure") {
    throw new Error(`Expected checkpoint-integrity-failure, received ${String(tamperCategory)}`);
  }

  const evidenceAfter = await readFile(evidencePath);
  if (!evidenceAfter.equals(evidenceBytes)) {
    throw new Error("Controller checkpoint package smoke modified referenced evidence");
  }

  console.log("Controller checkpoint package smoke passed");
} finally {
  await rm(temp, { recursive: true, force: true });
}
