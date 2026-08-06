import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowPath = new URL(
  "../.github/workflows/build-desmume-debian.yml",
  import.meta.url,
);

async function workflow(): Promise<string> {
  return await readFile(workflowPath, "utf8");
}

test("Debian workflow is manual-only", async () => {
  const source = await workflow();
  assert.match(source, /workflow_dispatch:/);
  assert.doesNotMatch(source, /pull_request:/);
  assert.doesNotMatch(source, /\bpush:/);
});

test("Debian workflow builds inside Debian 13", async () => {
  const source = await workflow();
  assert.match(source, /debian:13-slim/);
  assert.match(source, /--enable-gdb-stub/);
  assert.match(source, /--enable-debug/);
  assert.match(source, /desmume-cli/);
});

test("Debian workflow pins DeSmuME source", async () => {
  const source = await workflow();
  assert.match(source, /84e445159ccf2fd7900748094518eb1e88bdc7d0/);
  assert.match(source, /git checkout --detach/);
  assert.match(source, /git rev-parse HEAD/);
});

test("Debian launcher validates ROM and ARM9 GDB port", async () => {
  const source = await workflow();
  assert.match(source, /--arm9gdb=\(\[0-9\]\+\)/);
  assert.match(source, /port < 1024 \|\| port > 65535/);
  assert.match(source, /ROM is missing or unreadable/);
  assert.match(source, /exec "\$binary" "\$gdb_argument" "\$rom_path"/);
});

test("Debian bundle verifies GDB support and emits checksums", async () => {
  const source = await workflow();
  assert.match(source, /grep -qi.*arm9gdb/);
  assert.match(source, /ldd.*desmume-cli/);
  assert.match(source, /sha256sum/);
  assert.match(source, /upload-artifact@v4/);
});
