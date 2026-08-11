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

test("controller benchmark registry defines exactly five versioned deterministic scenarios", async () => {
  const registry = JSON.parse(await readText("benchmarks/controller/scenarios.json")) as {
    benchmarkVersion: number;
    scenarios: Array<{
      id: string;
      title: string;
      prompt: string;
      expectedTools: string[];
      requiredToolProfile?: string;
    }>;
  };

  assert.equal(registry.benchmarkVersion, 1);
  assert.deepEqual(
    registry.scenarios.map((scenario) => scenario.id),
    [
      "analysis-handoff",
      "checkpoint-resume",
      "verified-mutation",
      "guard-rejection",
      "targeted-function-investigation",
    ],
  );

  for (const scenario of registry.scenarios) {
    assert.ok(scenario.title.length >= 3 && scenario.title.length <= 120);
    assert.ok(scenario.prompt.length >= 40 && scenario.prompt.length <= 4000);
    assert.ok(scenario.expectedTools.length >= 1 && scenario.expectedTools.length <= 12);
    assert.equal(new Set(scenario.expectedTools).size, scenario.expectedTools.length);
    for (const tool of scenario.expectedTools) assert.match(tool, /^[a-z0-9_]+$/);
  }

  const targeted = registry.scenarios.at(-1)!;
  assert.equal(targeted.requiredToolProfile, "re-static-core");
  assert.deepEqual(targeted.expectedTools, ["re_trace_function", "controller_checkpoint_write"]);
  assert.match(targeted.prompt, /0x02000080/);
  assert.match(targeted.prompt, /identity-dependent/i);
  assert.match(targeted.prompt, /broad bounds/i);
  assert.match(targeted.prompt, /identity-restriction-/);
});

test("benchmark CLI uses a deterministic targeted ARM fixture and compiled RE-MCP services", async () => {
  const wrapper = await readText("scripts/controller-benchmark.mjs");
  const source = await readText("scripts/controller-benchmark-core.mjs");

  assert.match(wrapper, /mainControllerBenchmark/);
  for (const phrase of [
    "prepare",
    "score",
    "controller-benchmark.nds",
    "readNdsRomMap",
    "readControllerCheckpoint",
    "writeControllerCheckpoint",
    "readInvestigationJournal",
    "readInvestigationResumeArtifact",
    "verifyPublishedNdsMutationBuild",
    "loadNdsMutationManifest",
    "source-immutable",
    "controller-state-only",
    "targeted-function-investigation",
    "TARGET_HELPER_ADDRESS",
    "TARGET_IDENTITY_CALLER",
    "re-static-core",
    "process.exitCode = 1",
    "process.exitCode = 2",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assert.match(source, /armBl/);
  assert.match(source, /0xe5d41012/); // ldrb identity byte
  assert.match(source, /0xe3510007/); // cmp identity, #7
  assert.match(source, /0xe3500040/); // generic bound A
  assert.match(source, /0xe3500020/); // generic bound B
  assert.match(source, /lstat/);
  assert.match(source, /readdir/);
  assert.match(source, /symlink/i);
  assert.match(source, /Buffer\.compare|\.equals\(/);
  assertNoProviderOrTranscriptSurface(source);
});

test("targeted scorer grades journal/artifact/checkpoint state rather than prose", async () => {
  const source = await readText("scripts/controller-benchmark-core.mjs");

  for (const phrase of [
    "investigation-journal-integrity",
    "high-level-trace-persisted",
    "resume-artifact-integrity",
    "target-caller-set",
    "identity-dependent-caller-selected",
    "identity-restriction-02000040",
    "direct-caller-xrefs",
    "re-resume-state",
    "completionStatus",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assert.doesNotMatch(source, /statement\s*===/);
  assert.doesNotMatch(source, /description\s*===/);
  assert.doesNotMatch(source, /ghidraDerived.*===/s);
});

test("benchmark scorecard uses the shared real tools/list schema measurement path", async () => {
  const benchmark = await readText("scripts/controller-benchmark-core.mjs");
  const cli = await readText("scripts/measure-tool-schemas.mjs");
  const shared = await readText("scripts/tool-schema-measurement.mjs");

  assert.match(benchmark, /measureToolSchemas/);
  assert.match(cli, /measureToolSchemas/);
  assert.match(shared, /StdioClientTransport/);
  assert.match(shared, /client\.listTools\(\)/);
  assert.match(shared, /JSON\.stringify\(result\.tools\)/);
  for (const phrase of [
    "activeToolProfile",
    "advertisedToolCount",
    "toolSchemaBytes",
    "toolSchemaEstimatedTokens",
    "RE_MCP_BENCHMARK_REQUEST_ACCEPTED",
    "RE_MCP_BENCHMARK_TURNS",
    "RE_MCP_BENCHMARK_TOOL_CALLS",
  ]) {
    assert.match(benchmark, new RegExp(escapeRegex(phrase)));
  }
});

test("legacy benchmark scoring still covers evidence binding and exact guard rejection", async () => {
  const source = await readText("scripts/controller-benchmark-core.mjs");

  for (const phrase of [
    "manifest.json",
    "verification.json",
    "checkpoint-valid",
    "checkpoint-evidence-bound",
    "build-freshly-verified",
    "guard-rejected-no-output",
    "original-byte-guard-failed",
    "outcome",
    "failed",
    "completed",
  ]) {
    assert.match(source, new RegExp(escapeRegex(phrase), "i"));
  }

  assert.match(
    source,
    /rejectedByCanonicalPlanner\s*=\s*[^;]*original-byte-guard-failed/s,
  );
  assert.doesNotMatch(source, /catch\s*\{\s*rejectedByCanonicalPlanner\s*=\s*true;/s);
});

test("controller benchmark docs define deterministic and live constrained acceptance without overclaiming", async () => {
  const guide = await readText("docs/controller-benchmark.md");
  const acceptance = await readText("docs/controller-efficiency-acceptance.md");
  const combined = `${guide}\n${acceptance}`;

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
    "all five scenarios",
    "targeted-function-investigation",
    "RE_MCP_TOOL_PROFILE=re-static-core",
    "request accepted",
    "tool calls",
    "schema",
    "does not prove",
    "practically accepted",
    "Physical DeSmuME",
  ]) {
    assert.match(combined, new RegExp(escapeRegex(phrase), "i"));
  }
});

test("package ships and executes the compiled five-scenario controller benchmark acceptance", async () => {
  const workflow = await readText(".github/workflows/package.yml");
  const smoke = await readText("scripts/check-controller-benchmark-install.mjs");

  assert.match(workflow, /benchmarks\/controller/);
  assert.match(workflow, /controller-benchmark\.md/);
  assert.match(workflow, /controller-efficiency-acceptance\.md/);
  assert.match(workflow, /check-controller-benchmark-install\.mjs/);

  for (const phrase of [
    "benchmarks/controller/scenarios.json",
    "scripts/controller-benchmark.mjs",
    "targeted-function-investigation",
    "re_trace_function",
    "persistInvestigationResult",
    "persistInvestigationResumeArtifact",
    "identity-restriction-02000040",
    "wrong-caller",
    "non-empty",
    "Controller benchmark package smoke passed",
  ]) {
    assert.match(smoke, new RegExp(escapeRegex(phrase), "i"));
  }

  assertNoProviderOrTranscriptSurface(smoke);
});
