import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test, { type TestContext } from "node:test";

import {
  ControllerCheckpointError,
  controllerCheckpointPath,
  readControllerCheckpoint,
  writeControllerCheckpoint,
  type ControllerCheckpointSource,
  type ControllerCheckpointStateInput,
} from "../src/services/controller-checkpoint.js";

const SOURCE_SHA = "0123456789abcdef".repeat(4);
const SOURCE_PREFIX = SOURCE_SHA.slice(0, 12);
const SOURCE: ControllerCheckpointSource = {
  sha256: SOURCE_SHA,
  sha256Prefix: SOURCE_PREFIX,
};

function emptyState(objective = "Locate the Bakugan attribute dispatch path"): ControllerCheckpointStateInput {
  return {
    objective,
    confirmedFacts: [],
    hypotheses: [],
    completedActions: [],
    nextActions: [],
  };
}

async function workspace(t: TestContext): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), "re-mcp-controller-checkpoint-"));
  t.after(async () => {
    await rm(root, { recursive: true, force: true });
  });
  return root;
}

function assertCategory(category: string) {
  return (error: unknown): boolean =>
    error instanceof ControllerCheckpointError && error.category === category;
}

test("checkpoint path is derived only from exact source identity", async (t) => {
  const root = await workspace(t);
  assert.equal(
    controllerCheckpointPath(SOURCE, root),
    path.join(root, "analysis", "generated", "nds", SOURCE_PREFIX, "controller", "checkpoint.json"),
  );
});

test("first checkpoint write/read is revisioned and integrity-bound", async (t) => {
  const root = await workspace(t);
  const written = await writeControllerCheckpoint(SOURCE, root, 0, emptyState());

  assert.equal(written.revision, 1);
  assert.equal(written.authority, "controller-state-only");
  assert.equal(written.sourceRomSha256, SOURCE_SHA);
  assert.equal(written.sourceRomSha256Prefix, SOURCE_PREFIX);
  assert.match(written.contentSha256, /^[0-9a-f]{64}$/);

  const read = await readControllerCheckpoint(SOURCE, root);
  assert.equal(read.exists, true);
  if (!read.exists) return;
  assert.equal(read.checkpoint.revision, 1);
  assert.equal(read.checkpoint.contentSha256, written.contentSha256);
  assert.equal(read.relativePath, `analysis/generated/nds/${SOURCE_PREFIX}/controller/checkpoint.json`);
});

test("matching revision advances while stale writers fail closed", async (t) => {
  const root = await workspace(t);
  await writeControllerCheckpoint(SOURCE, root, 0, emptyState("first"));
  const second = await writeControllerCheckpoint(SOURCE, root, 1, emptyState("second"));
  assert.equal(second.revision, 2);

  await assert.rejects(
    writeControllerCheckpoint(SOURCE, root, 1, emptyState("stale")),
    assertCategory("checkpoint-revision-conflict"),
  );

  const current = await readControllerCheckpoint(SOURCE, root);
  assert.equal(current.exists, true);
  if (current.exists) assert.equal(current.checkpoint.objective, "second");
});

test("tampered checkpoint fails integrity validation instead of being repaired", async (t) => {
  const root = await workspace(t);
  await writeControllerCheckpoint(SOURCE, root, 0, emptyState());
  const checkpointPath = controllerCheckpointPath(SOURCE, root);
  const parsed = JSON.parse(await readFile(checkpointPath, "utf8")) as Record<string, unknown>;
  parsed.objective = "tampered";
  await writeFile(checkpointPath, `${JSON.stringify(parsed, null, 2)}\n`);

  await assert.rejects(
    readControllerCheckpoint(SOURCE, root),
    assertCategory("checkpoint-integrity-failure"),
  );
});

test("evidence references are confined to exact controlled source-SHA roots and hash-bound", async (t) => {
  const root = await workspace(t);
  const evidenceRelative = `analysis/generated/nds/${SOURCE_PREFIX}/analysis-proof.json`;
  const evidencePath = path.join(root, evidenceRelative);
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, "{\"proof\":true}\n");

  const written = await writeControllerCheckpoint(SOURCE, root, 0, {
    ...emptyState(),
    confirmedFacts: [{
      id: "arm9-entry",
      statement: "Controller reports that the ARM9 entry was inspected.",
      evidenceRefs: [{ path: evidenceRelative }],
    }],
  });

  assert.equal(written.confirmedFacts[0]?.evidenceRefs.length, 1);
  assert.match(written.confirmedFacts[0]?.evidenceRefs[0]?.sha256 ?? "", /^[0-9a-f]{64}$/);
  assert.equal(written.confirmedFacts[0]?.evidenceRefs[0]?.path, evidenceRelative);
});

test("evidence reference rejects sibling SHA namespace and expected SHA mismatch", async (t) => {
  const root = await workspace(t);
  const siblingPrefix = "f".repeat(12);
  const siblingRelative = `analysis/generated/nds/${siblingPrefix}/proof.json`;
  const siblingPath = path.join(root, siblingRelative);
  await mkdir(path.dirname(siblingPath), { recursive: true });
  await writeFile(siblingPath, "sibling");

  await assert.rejects(
    writeControllerCheckpoint(SOURCE, root, 0, {
      ...emptyState(),
      hypotheses: [{ id: "bad-ref", statement: "bad", evidenceRefs: [{ path: siblingRelative }] }],
    }),
    assertCategory("checkpoint-evidence-path-invalid"),
  );

  const allowedRelative = `output/nds/${SOURCE_PREFIX}/build/evidence.json`;
  const allowedPath = path.join(root, allowedRelative);
  await mkdir(path.dirname(allowedPath), { recursive: true });
  await writeFile(allowedPath, "evidence");
  await assert.rejects(
    writeControllerCheckpoint(SOURCE, root, 0, {
      ...emptyState(),
      hypotheses: [{
        id: "sha-mismatch",
        statement: "bad sha",
        evidenceRefs: [{ path: allowedRelative, expectedSha256: "0".repeat(64) }],
      }],
    }),
    assertCategory("checkpoint-evidence-sha-mismatch"),
  );
});

test("evidence references reject symlink escapes from an allowed SHA namespace", async (t) => {
  const root = await workspace(t);
  const outside = await mkdtemp(path.join(os.tmpdir(), "re-mcp-controller-evidence-outside-"));
  t.after(async () => {
    await rm(outside, { recursive: true, force: true });
  });
  const outsideFile = path.join(outside, "outside-proof.json");
  await writeFile(outsideFile, "outside");

  const evidenceRelative = `analysis/generated/nds/${SOURCE_PREFIX}/linked-proof.json`;
  const evidencePath = path.join(root, evidenceRelative);
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await symlink(outsideFile, evidencePath, "file");

  await assert.rejects(
    writeControllerCheckpoint(SOURCE, root, 0, {
      ...emptyState(),
      hypotheses: [{
        id: "symlink-escape",
        statement: "must not hash outside the controlled workspace",
        evidenceRefs: [{ path: evidenceRelative }],
      }],
    }),
    assertCategory("checkpoint-evidence-path-invalid"),
  );
});

test("checkpoint storage rejects a symlinked controller directory before writing outside", async (t) => {
  const root = await workspace(t);
  const outside = await mkdtemp(path.join(os.tmpdir(), "re-mcp-controller-storage-outside-"));
  t.after(async () => {
    await rm(outside, { recursive: true, force: true });
  });

  const controllerDirectory = path.dirname(controllerCheckpointPath(SOURCE, root));
  await mkdir(path.dirname(controllerDirectory), { recursive: true });
  await symlink(outside, controllerDirectory, "dir");

  await assert.rejects(
    writeControllerCheckpoint(SOURCE, root, 0, emptyState()),
    assertCategory("checkpoint-io-failure"),
  );
  await assert.rejects(readFile(path.join(outside, "checkpoint.json")), /ENOENT/);
});

test("checkpoint state rejects duplicate IDs and over-broad evidence paths", async (t) => {
  const root = await workspace(t);

  await assert.rejects(
    writeControllerCheckpoint(SOURCE, root, 0, {
      ...emptyState(),
      confirmedFacts: [{ id: "duplicate", statement: "fact", evidenceRefs: [] }],
      nextActions: [{ id: "duplicate", description: "next" }],
    }),
    assertCategory("checkpoint-invalid-state"),
  );

  await assert.rejects(
    writeControllerCheckpoint(SOURCE, root, 0, {
      ...emptyState(),
      hypotheses: [{
        id: "escape",
        statement: "escape",
        evidenceRefs: [{ path: "../../outside.json" }],
      }],
    }),
    assertCategory("checkpoint-evidence-path-invalid"),
  );
});

test("absent checkpoint reports expected revision zero without creating files", async (t) => {
  const root = await workspace(t);
  const read = await readControllerCheckpoint(SOURCE, root);
  assert.deepEqual(read, {
    exists: false,
    expectedRevision: 0,
    sourceRomSha256: SOURCE_SHA,
    sourceRomSha256Prefix: SOURCE_PREFIX,
    relativePath: `analysis/generated/nds/${SOURCE_PREFIX}/controller/checkpoint.json`,
  });
});
