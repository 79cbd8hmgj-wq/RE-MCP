import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function readJson(path: string): Promise<Record<string, unknown>> {
  return JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;
}

test("production build emits the stable MCP entry at dist/index.js", async () => {
  const packageJson = await readJson("package.json");
  const scripts = packageJson.scripts as Record<string, string>;
  assert.equal(scripts.build, "tsc -p tsconfig.build.json");
  assert.equal(scripts.start, "node dist/index.js");

  const buildConfig = await readJson("tsconfig.build.json");
  assert.equal(buildConfig.extends, "./tsconfig.json");
  assert.deepEqual(buildConfig.compilerOptions, {
    rootDir: "src",
    outDir: "dist",
  });
  assert.deepEqual(buildConfig.include, ["src/**/*.ts"]);

  const packageWorkflow = await readFile(".github/workflows/package.yml", "utf8");
  assert.match(packageWorkflow, /cp -R dist\/\. "\$root\/dist\/"/u);
  assert.doesNotMatch(packageWorkflow, /cp -R dist\/src\/\. "\$root\/dist\/"/u);
});
