import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  captureRuntimeEvidence,
  validateEvidenceRegions,
  writeEvidenceAtomic,
} from "../src/services/runtime-evidence.js";

function packet(payload: string): string {
  let sum = 0;
  for (const byte of Buffer.from(payload, "ascii")) sum = (sum + byte) & 0xff;
  return `$${payload}#${sum.toString(16).padStart(2, "0")}`;
}

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected TCP address");
  return address.port;
}

test("evidence regions enforce labels, counts, and total bytes", () => {
  assert.doesNotThrow(() =>
    validateEvidenceRegions([{ label: "gate-cache", address: 0x02000000, length: 64 }]),
  );
  assert.throws(
    () => validateEvidenceRegions([{ label: "bad label", address: 0, length: 1 }]),
    /Invalid evidence region label/,
  );
  assert.throws(
    () =>
      validateEvidenceRegions([
        { label: "same", address: 0, length: 1 },
        { label: "same", address: 1, length: 1 },
      ]),
    /Duplicate evidence region label/,
  );
  assert.throws(
    () =>
      validateEvidenceRegions(
        Array.from({ length: 5 }, (_, index) => ({
          label: `r${index}`,
          address: index * 4096,
          length: 4096,
        })),
      ),
    /16384 bytes/,
  );
});

test("captureRuntimeEvidence preserves raw register and memory packets", async () => {
  const replies = ["00112233", "aabbccdd"];
  const server = net.createServer((socket) => {
    socket.once("data", () => socket.write(`+${packet(replies.shift() ?? "E01")}`, "ascii"));
  });
  const port = await listen(server);
  try {
    const evidence = await captureRuntimeEvidence(
      port,
      [{ label: "sample", address: 0x02000000, length: 4 }],
      1024,
    );
    assert.equal(evidence.registerHex, "00112233");
    assert.equal(evidence.memoryRegions[0]?.dataHex, "aabbccdd");
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("writeEvidenceAtomic writes canonical JSON with a trailing newline", async () => {
  const directory = await import("node:fs/promises").then(({ mkdtemp }) =>
    mkdtemp(path.join(os.tmpdir(), "re-mcp-evidence-")),
  );
  const output = path.join(directory, "nested", "evidence.json");
  await writeEvidenceAtomic(output, {
    format: "re-mcp-arm9-runtime-evidence",
    formatVersion: 1,
    capturedAt: "2026-08-06T12:00:00.000Z",
    registerHex: "00",
    memoryRegions: [],
  });
  const text = await readFile(output, "utf8");
  assert.equal(text.endsWith("\n"), true);
  assert.equal(JSON.parse(text).formatVersion, 1);
});
