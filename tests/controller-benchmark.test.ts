import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";

const root = process.cwd();

async function readText(relative: string): Promise<string> {
  return readFile(path.join(root, relative), "utf8");
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertNoProviderOrTranscriptSurface(source: string): void {
  for (const pattern of [
    /from\s+["']node:https?["']/,
    /require\(["']node:https?["']\)/,
    /\bfetch\s*\(/,
    /GROQ_API_KEY/,
    /OPENROUTER_API_KEY/,
    /OPENAI_API_KEY/,
    /ANTHROPIC_API_KEY/,
    /chain[- ]of[- ]thought/i,
    /transcript(?:s)?\s*[:=]/i,
  ]) {
    assert.doesNotMatch(source, pattern);
  }
}

test("controller benchmark registry defines exactly four versioned deterministic scenarios", async () => {
  const registry = JSON.parse(await readText("benchmarks/controller/scenarios.json")) as {
    benchmarkVersion: number;
    scenarios: Array<{
      id: string;
      title: string;
      prompt: string;
      expectedTools: string[];
    }>;
  };

  assert.equal(registry.benchmarkVersion, 1);
  assert.deepEqual(
    registry.scenarios.map((scenario) => scenario.id),
    ["analysis-handoff", "checkpoint-resume", "verified-mutation", "guard-rejection"],
  );

  for (const scenario of registry.scenarios) {
    assert.ok(scenario.title.length >= 3 && scenario.title.length <= 120);
    assert.ok(scenario.prompt.length >= 40 && scenario.prompt.length <= 4000);
    assert.ok(scenario.expectedTools.length >= 1 && scenario.expectedTools.length <= 12);
    assert.equal(new Set(scenario.expectedTools).size, scenario.expectedTools.length);
    for (const tool of scenario.expectedTools) {
      assert.match(tool, /^[a-z0-9_]+$/);
    }
  }
});

test("benchmark CLI prepares synthetic workspaces and scores through compiled RE-MCP services", async () => {
  const source = await readText("scripts/controller-benchmark.mjs");

  for (const phrase of [
    "prepare",
    "score",
    "controller-benchmark.nds",
    "readNdsRomMap",
    "readControllerCheckpoint",
    "writeControllerCheckpoint",
    "verifyPublishedNdsMutationBuild",
    "loadNdsMutationManifest",
    "source-immutable",
    "controller-state-only",
    "analysis-handoff",
    "checkpoint-resume",
    "verified-mutation",
    "guard-rejection",
    "benchmarkVersion",
    "process.exitCode = 1",
    "process.exitCode = 2",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assert.match(source, /lstat/);
  assert.match(source, /readdir/);
  assert.match(source, /symlink/i);
  assert.match(source, /empty/i);
  assert.match(source, /Buffer\.compare|\.equals\(/);
  assertNoProviderOrTranscriptSurface(source);
});

test("benchmark scoring contract covers exact evidence binding and guard rejection", async () => {
  const source = await readText("scripts/controller-benchmark.mjs");

  for (const phrase of [
    "manifest.json",
    "verification.json",
    "checkpoint-valid",
    "checkpoint-evidence-bound",
    "build-freshly-verified",
    "guard-rejected-no-output",
    "outcome",
    "failed",
    "completed",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assert.doesNotMatch(source, /statement\s*===/);
  assert.doesNotMatch(source, /description\s*===/);
});

test("controller benchmark guide defines reproducible live comparison without overclaiming CI", async () => {
  const guide = await readText("docs/controller-benchmark.md");

  for (const phrase of [
    "prepare",
    "score",
    "fresh workspace",
    "fixed prompt",
    "GitHub Copilot",
    "Continue",
    "Groq",
    "OpenRouter",
    "Ollama",
    "controller-state-only",
    "do not manually repair",
    "all four scenarios",
    "does not prove",
    "Physical DeSmuME",
  ]) {
    assert.match(guide, new RegExp(escapeRegex(phrase), "i"));
  }
});

test("package ships and executes the compiled controller benchmark acceptance", async () => {
  const workflow = await readText(".github/workflows/package.yml");
  const smoke = await readText("scripts/check-controller-benchmark-install.mjs");

  assert.match(workflow, /benchmarks\/controller/);
  assert.match(workflow, /controller-benchmark\.md/);
  assert.match(workflow, /check-controller-benchmark-install\.mjs/);

  for (const phrase of [
    "benchmarks/controller/scenarios.json",
    "scripts/controller-benchmark.mjs",
    "analysis-handoff",
    "verified-mutation",
    "guard-rejection",
    "non-empty",
    "Controller benchmark package smoke passed",
  ]) {
    assert.match(smoke, new RegExp(escapeRegex(phrase), "i"));
  }

  assertNoProviderOrTranscriptSurface(smoke);
});
