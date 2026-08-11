import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

async function read(relative: string): Promise<string> {
  return readFile(relative, "utf8");
}

function requirePhrases(text: string, phrases: readonly string[]): void {
  for (const phrase of phrases) {
    assert.match(text, new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"));
  }
}

test("Copilot controller policy defines checkpoint handoff without promoting controller prose to evidence", async () => {
  const instructions = await read(".github/copilot-instructions.md");
  requirePhrases(instructions, [
    "controller_checkpoint_read",
    "controller_checkpoint_write",
    "controller-state-only",
    "revalidate consequential facts",
    "planned controller handoff",
    "chain-of-thought",
    "API keys",
  ]);
  assert.match(instructions, /existing ROM work.*checkpoint|checkpoint.*existing ROM work/is);
});

test("Copilot guide documents provider-neutral checkpoint resume and handoff workflow", async () => {
  const guide = await read("docs/github-copilot-agent.md");
  requirePhrases(guide, [
    "Provider-neutral controller checkpoints",
    "controller_checkpoint_read",
    "controller_checkpoint_write",
    "expectedRevision",
    "controller-state-only",
    "revalidate consequential facts",
    "chain-of-thought",
    "API keys",
  ]);
  assert.match(guide, /analysis\/generated\/nds\/<sha-prefix>\/controller\/checkpoint\.json/i);
  assert.match(guide, /Copilot.*Continue|Continue.*Copilot/is);
});

test("downloadable package ships and exercises compiled controller checkpoint support", async () => {
  const workflow = await read(".github/workflows/package.yml");
  const smoke = await read("scripts/check-controller-checkpoint-install.mjs");
  const index = await read("src/index.ts");

  assert.match(workflow, /check-controller-checkpoint-install\.mjs/);
  assert.match(smoke, /dist["']?,\s*["']services["']?,\s*["']controller-checkpoint\.js/);
  assert.match(smoke, /dist["']?,\s*["']tools["']?,\s*["']controller-checkpoint\.js/);
  assert.match(smoke, /checkpoint-revision-conflict/);
  assert.match(smoke, /checkpoint-integrity-failure/);
  assert.match(smoke, /Controller checkpoint package smoke passed/);
  assert.match(index, /registerControllerCheckpointTools\(server, config\)/);
});