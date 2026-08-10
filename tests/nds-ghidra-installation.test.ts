import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import { NdsError } from "../src/services/nds/errors.js";
import { validateGhidraInstallation } from "../src/services/nds/ghidra-installation.js";

function config(home: string | null): ServerConfig {
  return {
    workspaceRoot: "/workspace",
    commandTimeoutMs: 30_000,
    maxOutputBytes: 64 * 1024,
    ghidraHome: home,
    ghidraTimeoutMs: 900_000,
  };
}

async function fakeInstallation(options: {
  version?: string;
  languages?: readonly string[];
  executable?: boolean;
} = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), "re-mcp-ghidra-install-"));
  await mkdir(path.join(root, "support"), { recursive: true });
  await mkdir(path.join(root, "Ghidra", "Processors", "ARM", "data", "languages"), {
    recursive: true,
  });
  const analyzeHeadless = path.join(root, "support", "analyzeHeadless");
  if (options.executable !== false) {
    await writeFile(analyzeHeadless, "#!/bin/sh\nexit 0\n", "utf8");
    await chmod(analyzeHeadless, 0o755);
  }
  await writeFile(
    path.join(root, "Ghidra", "application.properties"),
    `application.version=${options.version ?? "12.1.2"}\n`,
    "utf8",
  );
  const languages = options.languages ?? ["ARM:LE:32:v5t", "ARM:LE:32:v4t"];
  await writeFile(
    path.join(root, "Ghidra", "Processors", "ARM", "data", "languages", "ARM.ldefs"),
    languages.map((id) => `<language id="${id}"/>`).join("\n"),
    "utf8",
  );
  return { root, analyzeHeadless };
}

function category(error: unknown): string | null {
  return error instanceof NdsError ? String(error.category) : null;
}

test("Ghidra installation validation rejects missing configuration", async () => {
  await assert.rejects(
    validateGhidraInstallation(config(null)),
    (error: unknown) => category(error) === "ghidra-not-configured",
  );
});

test("Ghidra installation validation accepts supported 12.x with exact ARM languages", async () => {
  const fixture = await fakeInstallation();
  try {
    const result = await validateGhidraInstallation(config(fixture.root));
    assert.equal(result.home, await realpath(fixture.root));
    assert.equal(result.analyzeHeadless, await realpath(fixture.analyzeHeadless));
    assert.equal(result.version, "12.1.2");
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("Ghidra installation validation rejects unsupported versions", async () => {
  const fixture = await fakeInstallation({ version: "11.4.1" });
  try {
    await assert.rejects(
      validateGhidraInstallation(config(fixture.root)),
      (error: unknown) => category(error) === "unsupported-ghidra-version",
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("Ghidra installation validation rejects missing required processor language", async () => {
  const fixture = await fakeInstallation({ languages: ["ARM:LE:32:v5t"] });
  try {
    await assert.rejects(
      validateGhidraInstallation(config(fixture.root)),
      (error: unknown) => category(error) === "ghidra-language-unavailable",
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("Ghidra installation validation rejects a missing analyzeHeadless executable", async () => {
  const fixture = await fakeInstallation({ executable: false });
  try {
    await assert.rejects(
      validateGhidraInstallation(config(fixture.root)),
      (error: unknown) => category(error) === "invalid-ghidra-installation",
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("Ghidra installation validation rejects analyzeHeadless symlinks that escape the configured home", async () => {
  const fixture = await fakeInstallation({ executable: false });
  const outside = await mkdtemp(path.join(os.tmpdir(), "re-mcp-ghidra-outside-"));
  try {
    const outsideExecutable = path.join(outside, "analyzeHeadless");
    await writeFile(outsideExecutable, "#!/bin/sh\nexit 0\n", "utf8");
    await chmod(outsideExecutable, 0o755);
    await symlink(outsideExecutable, fixture.analyzeHeadless);

    await assert.rejects(
      validateGhidraInstallation(config(fixture.root)),
      (error: unknown) => category(error) === "invalid-ghidra-installation",
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
