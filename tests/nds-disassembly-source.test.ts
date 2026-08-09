import assert from "node:assert/strict";
import { appendFile } from "node:fs/promises";
import test from "node:test";

import {
  codeSourceAt,
  resolveNdsCodeSource,
  resolveNdsControlFlowTarget,
  withValidatedNdsRomReader,
  type NdsCodeSource,
} from "../src/services/nds/disassembly-source.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import {
  createNdsFixture,
  writeFatEntry,
  writeOverlayRecord,
} from "./helpers/nds-fixture.js";

test("auto mode resolves ARM9 and ARM7 header entry points as ARM", async () => {
  const fixture = await createNdsFixture({
    arm9EntryAddress: 0x02000020,
    arm7EntryAddress: 0x03800020,
  });
  const map = await readNdsRomMap(fixture.romPath);

  const arm9 = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02000020,
    mode: "auto",
  });
  assert.equal(arm9.status, "resolved");
  if (arm9.status === "resolved") {
    assert.equal(arm9.source.mode, "arm");
    assert.equal(arm9.source.component, "main");
    assert.equal(arm9.source.romOffset, 0x220);
  }

  const arm7 = resolveNdsCodeSource(map, {
    processor: "arm7",
    runtimeAddress: 0x03800020,
    mode: "auto",
  });
  assert.equal(arm7.status, "resolved");
  if (arm7.status === "resolved") {
    assert.equal(arm7.source.mode, "arm");
    assert.equal(arm7.source.romOffset, 0x620);
  }
});

test("auto mode rejects addresses away from a trusted main entry point", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.equal(
    resolveNdsCodeSource(map, {
      processor: "arm9",
      runtimeAddress: 0x02000004,
      mode: "auto",
    }).status,
    "mode-ambiguous",
  );
});

test("ROM-offset auto mode resolves runtime identity before testing the header seed", async () => {
  const fixture = await createNdsFixture({
    arm9RomOffset: 0x200,
    arm9RamAddress: 0x02000000,
    arm9EntryAddress: 0x02000020,
  });
  const map = await readNdsRomMap(fixture.romPath);
  const result = resolveNdsCodeSource(map, {
    processor: "arm9",
    romOffset: 0x220,
    mode: "auto",
  });
  assert.equal(result.status, "resolved");
  if (result.status === "resolved") {
    assert.equal(result.source.runtimeAddress, 0x02000020);
    assert.equal(result.source.mode, "arm");
  }
});

test("explicit ARM and Thumb modes enforce their alignments", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);

  assert.equal(
    resolveNdsCodeSource(map, {
      processor: "arm9",
      runtimeAddress: 0x02000004,
      mode: "arm",
    }).status,
    "resolved",
  );
  assert.equal(
    resolveNdsCodeSource(map, {
      processor: "arm9",
      runtimeAddress: 0x02000002,
      mode: "thumb",
    }).status,
    "resolved",
  );
  assert.throws(
    () => resolveNdsCodeSource(map, {
      processor: "arm9",
      runtimeAddress: 0x02000002,
      mode: "arm",
    }),
    /4-byte aligned/,
  );
  assert.throws(
    () => resolveNdsCodeSource(map, {
      processor: "arm9",
      runtimeAddress: 0x02000001,
      mode: "thumb",
    }),
    /2-byte aligned/,
  );
});

async function buildOverlayFixture(options: {
  readonly compressed?: boolean;
  readonly romSize?: number;
  readonly ramSize?: number;
  readonly bssSize?: number;
}) {
  const romSize = options.romSize ?? 0x80;
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 8,
    arm9OverlaySize: 32,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1200 + romSize);
  writeOverlayRecord(fixture.buffer, 0xa00, 0, {
    overlayId: 7,
    ramAddress: 0x02200000,
    ramSize: options.ramSize ?? 0x80,
    bssSize: options.bssSize ?? 0x20,
    staticInitStart: 0,
    staticInitEnd: 0,
    fileId: 0,
    compressedSize: options.compressed ? Math.min(romSize, 0x70) : 0,
    flags: options.compressed ? 1 : 0,
  });
  await fixture.write();
  return { fixture, map: await readNdsRomMap(fixture.romPath) };
}

test("compressed initialized overlays resolve as derived sources while BSS remains runtime-only", async () => {
  const compressed = await buildOverlayFixture({ compressed: true });
  const derived = resolveNdsCodeSource(compressed.map, {
    processor: "arm9",
    runtimeAddress: 0x02200010,
    mode: "arm",
  });
  assert.equal(derived.status, "resolved");
  if (derived.status === "resolved") {
    assert.equal(derived.source.representation, "derived-overlay");
    assert.equal(derived.source.romOffset, null);
    assert.equal(derived.source.runtimeImageOffset, 0x10);
  }

  const plain = await buildOverlayFixture({ bssSize: 0x20 });
  assert.equal(
    resolveNdsCodeSource(plain.map, {
      processor: "arm9",
      runtimeAddress: 0x02200088,
      mode: "arm",
    }).status,
    "runtime-only-bss",
  );
});

test("uncompressed overlays expose only their file-backed initialized prefix", async () => {
  const { map } = await buildOverlayFixture({ romSize: 0x40, ramSize: 0x80 });
  const backed = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02200020,
    mode: "arm",
  });
  assert.equal(backed.status, "resolved");
  if (backed.status === "resolved") {
    assert.equal(backed.source.runtimeStart, 0x02200000);
    assert.equal(backed.source.runtimeEnd, 0x02200040);
    assert.equal(backed.source.romStart, 0x1200);
    assert.equal(backed.source.romEnd, 0x1240);
  }

  assert.equal(
    resolveNdsCodeSource(map, {
      processor: "arm9",
      runtimeAddress: 0x02200060,
      mode: "arm",
    }).status,
    "unmapped-address",
  );
});

test("overlapping overlays remain ambiguous unless overlayId selects one", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  for (const [index, overlayId, fileId] of [[0, 7, 0], [1, 8, 1]] as const) {
    writeOverlayRecord(fixture.buffer, 0xa00, index, {
      overlayId,
      ramAddress: 0x02200000,
      ramSize: 0x80,
      bssSize: 0,
      staticInitStart: 0,
      staticInitEnd: 0,
      fileId,
      compressedSize: 0,
      flags: 0,
    });
  }
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);

  const ambiguous = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02200010,
    mode: "arm",
  });
  assert.equal(ambiguous.status, "ambiguous-code-source");
  if (ambiguous.status === "ambiguous-code-source") {
    assert.deepEqual(
      ambiguous.candidates.map((candidate) => candidate.overlayId),
      [7, 8],
    );
  }

  const selected = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02200010,
    overlayId: 7,
    mode: "arm",
  });
  assert.equal(selected.status, "resolved");
  if (selected.status === "resolved") {
    assert.equal(selected.source.overlayId, 7);
    assert.equal(selected.source.romOffset, 0x1210);
  }
});

test("ROM-offset requests respect the selected processor", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.equal(
    resolveNdsCodeSource(map, {
      processor: "arm7",
      romOffset: 0x220,
      mode: "arm",
    }).status,
    "unmapped-address",
  );
});

test("same-component control-flow preserves a selected overlapping overlay and target mode", async () => {
  const fixture = await createNdsFixture({
    fileSize: 0x5000,
    fatSize: 16,
    arm9OverlaySize: 64,
  });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1200, 0x1280);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1300, 0x1380);
  for (const [index, overlayId, fileId] of [[0, 7, 0], [1, 8, 1]] as const) {
    writeOverlayRecord(fixture.buffer, 0xa00, index, {
      overlayId,
      ramAddress: 0x02200000,
      ramSize: 0x80,
      bssSize: 0,
      staticInitStart: 0,
      staticInitEnd: 0,
      fileId,
      compressedSize: 0,
      flags: 0,
    });
  }
  await fixture.write();
  const map = await readNdsRomMap(fixture.romPath);
  const entry = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02200040,
    overlayId: 7,
    mode: "arm",
  });
  assert.equal(entry.status, "resolved");
  if (entry.status !== "resolved") return;

  const target = resolveNdsControlFlowTarget(
    map,
    entry.source,
    0x02200010,
    "thumb",
  );
  assert.equal(target.status, "resolved");
  if (target.status === "resolved") {
    assert.equal(target.source.overlayId, 7);
    assert.equal(target.source.mode, "thumb");
    assert.equal(target.source.romOffset, 0x1210);
  }
});

test("codeSourceAt maps addresses across the full selected component", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const result = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02000020,
    mode: "arm",
  });
  assert.equal(result.status, "resolved");
  if (result.status !== "resolved") return;

  const moved = codeSourceAt(result.source, 0x02000004);
  assert.equal(moved.runtimeAddress, 0x02000004);
  assert.equal(moved.romOffset, 0x204);
  assert.throws(() => codeSourceAt(result.source, 0x02400000), /outside the selected code source/);
});

test("validated ROM reader rejects stale identity before reading", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  await appendFile(fixture.romPath, Buffer.from([0xaa]));

  await assert.rejects(
    withValidatedNdsRomReader(map, async () => "unused"),
    /no longer matches the canonical map identity/,
  );
});

test("validated ROM reader detects mutation during the operation", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const sourceResult = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02000000,
    mode: "arm",
  });
  assert.equal(sourceResult.status, "resolved");
  if (sourceResult.status !== "resolved") return;
  const source: NdsCodeSource = sourceResult.source;

  await assert.rejects(
    withValidatedNdsRomReader(map, async (read) => {
      const bytes = await read(source, 4);
      assert.equal(bytes.length, 4);
      await appendFile(fixture.romPath, Buffer.from([0xbb]));
      return bytes;
    }),
    /changed during disassembly/,
  );
});

test("post-operation identity check still runs when the decode callback throws", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);

  await assert.rejects(
    withValidatedNdsRomReader(map, async () => {
      await appendFile(fixture.romPath, Buffer.from([0xcc]));
      throw new Error("decode failed first");
    }),
    /changed during disassembly/,
  );
});
