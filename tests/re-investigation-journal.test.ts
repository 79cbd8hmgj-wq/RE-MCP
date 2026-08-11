import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  InvestigationJournalError,
  persistInvestigationResult,
  readInvestigationJournal,
} from "../src/services/re-orchestration/investigation-journal.js";

const SOURCE = {
  sha256: "a".repeat(64),
  sha256Prefix: "a".repeat(12),
} as const;

function persistenceInput(operation: string, marker: number) {
  return {
    operation,
    normalizedInputs: {
      processor: "arm9",
      runtimeAddress: 0x02000000 + marker,
      nested: { z: marker, a: true },
    },
    completedStages: ["canonical-rom-map", "bounded-xrefs"],
    artifacts: [{
      kind: "fixture-evidence",
      path: `analysis/generated/nds/${SOURCE.sha256Prefix}/evidence-${marker}.json`,
      sha256: String(marker).padStart(64, "0"),
    }],
    result: { marker, candidates: [2, 1] },
    recommendedNextAction: `inspect-candidate-${marker}`,
  } as const;
}

test("investigation journal is exact-ROM scoped, monotonic, and integrity bound", async () => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "re-mcp-journal-"));
  try {
    const first = await persistInvestigationResult(
      SOURCE,
      workspace,
      persistenceInput("re_trace_function", 1),
    );
    const second = await persistInvestigationResult(
      SOURCE,
      workspace,
      persistenceInput("re_investigate_data_usage", 2),
    );

    assert.equal(first.entry.sequence, 1);
    assert.equal(second.entry.sequence, 2);
    assert.match(first.entry.operationId, /^[0-9a-f]{64}$/);
    assert.match(second.entry.entrySha256, /^[0-9a-f]{64}$/);
    assert.equal(second.projection.latestSequence, 2);
    assert.deepEqual(
      second.projection.completedOperations.map((entry) => entry.operation),
      ["re_trace_function", "re_investigate_data_usage"],
    );
    assert.deepEqual(second.projection.recommendedNextActions, ["inspect-candidate-2"]);
    assert.match(second.journalRelativePath, new RegExp(`^analysis/generated/nds/${SOURCE.sha256Prefix}/controller/`));

    const read = await readInvestigationJournal(SOURCE, workspace);
    assert.equal(read.entries.length, 2);
    assert.equal(read.metadata?.entryCount, 2);
    assert.equal(read.metadata?.lastSequence, 2);
    assert.match(read.metadata?.journalSha256 ?? "", /^[0-9a-f]{64}$/);
    assert.match(read.metadata?.projectionSha256 ?? "", /^[0-9a-f]{64}$/);
    assert.equal(read.projection?.sourceRomSha256, SOURCE.sha256);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("journal canonicalizes normalized deterministic inputs before hashing", async () => {
  const left = await mkdtemp(path.join(os.tmpdir(), "re-mcp-journal-left-"));
  const right = await mkdtemp(path.join(os.tmpdir(), "re-mcp-journal-right-"));
  try {
    const first = await persistInvestigationResult(SOURCE, left, {
      ...persistenceInput("re_trace_function", 3),
      normalizedInputs: { b: 2, a: { d: 4, c: 3 } },
    });
    const second = await persistInvestigationResult(SOURCE, right, {
      ...persistenceInput("re_trace_function", 3),
      normalizedInputs: { a: { c: 3, d: 4 }, b: 2 },
    });
    assert.equal(first.entry.operationId, second.entry.operationId);
    assert.deepEqual(first.entry.normalizedInputs, second.entry.normalizedInputs);
  } finally {
    await Promise.all([
      rm(left, { recursive: true, force: true }),
      rm(right, { recursive: true, force: true }),
    ]);
  }
});

test("corrupted journal state is rejected instead of resumed", async () => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "re-mcp-journal-corrupt-"));
  try {
    const persisted = await persistInvestigationResult(
      SOURCE,
      workspace,
      persistenceInput("re_trace_function", 4),
    );
    const journalPath = path.join(workspace, persisted.journalRelativePath);
    const serialized = await readFile(journalPath, "utf8");
    await writeFile(journalPath, serialized.replace("re_trace_function", "re_trace_functioN"), "utf8");

    await assert.rejects(
      () => readInvestigationJournal(SOURCE, workspace),
      (error: unknown) => error instanceof InvestigationJournalError
        && error.category === "investigation-journal-integrity-failure",
    );
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test("persistence fails closed when the exact-ROM journal namespace cannot be created", async () => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "re-mcp-journal-fail-"));
  try {
    await writeFile(path.join(workspace, "analysis"), "blocking-file", "utf8");
    await assert.rejects(
      () => persistInvestigationResult(
        SOURCE,
        workspace,
        persistenceInput("re_trace_function", 5),
      ),
    );
    await assert.rejects(() => mkdir(path.join(workspace, "analysis", "generated"), { recursive: true }));
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});
