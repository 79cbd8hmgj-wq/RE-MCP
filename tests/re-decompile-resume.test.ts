import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import test from "node:test";

import type { ServerConfig } from "../src/config.js";
import type { GhidraInspectionAuthorityResult } from "../src/services/nds/ghidra-inspection.js";
import { readNdsRomMap } from "../src/services/nds/rom-map.js";
import { decompileReCandidate } from "../src/services/re-orchestration/decompile-candidate.js";
import { persistInvestigationResult } from "../src/services/re-orchestration/investigation-journal.js";
import {
  persistInvestigationResumeArtifact,
  readInvestigationResumeArtifact,
} from "../src/services/re-orchestration/resume-artifact.js";
import { resumeInvestigation } from "../src/services/re-orchestration/resume.js";
import type { ReEvidenceEnvelope } from "../src/services/re-orchestration/types.js";
import { TOOL_PROFILES } from "../src/tools/profiles.js";
import { createNdsFixture } from "./helpers/nds-fixture.js";

function config(workspaceRoot: string): ServerConfig {
  return {
    workspaceRoot,
    commandTimeoutMs: 30_000,
    maxOutputBytes: 1_000_000,
    ghidraHome: null,
    ghidraTimeoutMs: 30_000,
    toolProfile: "re-ghidra-escalation",
  };
}

test("Ghidra candidate escalation persists its bounded non-authoritative evidence for resume", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  try {
    const fakeDecompile = async (): Promise<GhidraInspectionAuthorityResult> => ({
      canonical: {
        processor: "arm9",
        runtimeAddress: 0x02000000,
        component: "main",
        overlayId: null,
      },
      reMcpEvidence: {
        functionId: "arm9-main:0x02000000:arm",
        functionProof: "program-entry",
        functionMode: "arm",
        overlayId: null,
      },
      ghidraDerived: {
        found: true,
        completed: true,
        truncated: false,
        c: "int candidate(void) { return 1; }",
        error: "",
      },
    });

    const result = await decompileReCandidate(
      fixture.romPath,
      {
        processor: "arm9",
        runtimeAddress: 0x02000000,
        maxCharacters: 1024,
      },
      config(fixture.directory),
      fakeDecompile,
    );

    assert.equal(result.operation, "re_decompile_candidate");
    assert.equal(result.candidates.length, 1);
    assert.equal(result.candidates[0]?.authority, "non-authoritative-ghidra-candidate");
    assert.equal(result.confirmedDeterministicEvidence[0]?.kind, "deterministic-provenance");
    assert.equal(result.completedPrimitiveStages.includes("existing-ghidra-project-readiness"), true);
    assert.equal(result.completedPrimitiveStages.includes("bounded-read-only-ghidra-decompilation"), true);

    const map = await readNdsRomMap(fixture.romPath);
    const artifactRef = await persistInvestigationResumeArtifact(
      { sha256: map.sha256, sha256Prefix: map.sha256Prefix },
      fixture.directory,
      result,
    );
    assert.notEqual(artifactRef.path, null);
    assert.notEqual(artifactRef.sha256, null);
    const artifact = await readInvestigationResumeArtifact(
      fixture.directory,
      { path: artifactRef.path!, sha256: artifactRef.sha256! },
    );
    const persistedCandidate = artifact.candidates[0] as Record<string, unknown>;
    const ghidraDerived = persistedCandidate.ghidraDerived as Record<string, unknown>;
    assert.equal(artifact.resumeEvidenceComplete, true);
    assert.equal(ghidraDerived.c, "int candidate(void) { return 1; }");
    assert.equal(artifact.confirmedDeterministicEvidence?.[0] !== undefined, true);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("fresh provider resumes persisted bounded candidate evidence without replaying primitive analysis", async () => {
  const fixture = await createNdsFixture({ arm9Size: 0x80 });
  try {
    const map = await readNdsRomMap(fixture.romPath);
    const source = { sha256: map.sha256, sha256Prefix: map.sha256Prefix };
    const result: ReEvidenceEnvelope = {
      operation: "re_trace_function",
      sourceRomSha256: map.sha256,
      component: { processor: "arm9", component: "main", overlayId: null },
      subject: { runtimeAddress: 0x02000000, mode: "arm", romOffset: 0x200 },
      confirmedDeterministicEvidence: [{
        kind: "function-proof",
        value: { proofStatus: "proven" },
      }],
      candidates: [{
        kind: "direct-caller",
        callerFunctionId: "arm9-main:0x02000020:arm",
        component: "main",
        overlayId: null,
        instructionAddress: 0x02000020,
        instructionRomOffset: 0x220,
        mode: "arm",
        callSiteWindow: [{
          address: 0x02000020,
          romOffset: 0x220,
          size: 4,
          bytesHex: "000000eb",
          mode: "arm",
          mnemonic: "bl",
          operands: "#0x2000000",
          flow: {
            kind: "call",
            directTarget: 0x02000000,
            targetMode: "arm",
            fallthrough: 0x02000024,
          },
          source: {
            processor: "arm9",
            component: "main",
            overlayId: null,
          },
          targetResolution: null,
        }],
      }],
      ambiguities: [],
      completedPrimitiveStages: [
        "canonical-rom-map",
        "function-entry-proof",
        "bounded-cfg",
        "direct-caller-xrefs",
      ],
      artifacts: [],
      recommendedNextAction: "Inspect the bounded caller candidate at 0x02000020.",
    };
    const resumeArtifact = await persistInvestigationResumeArtifact(
      source,
      fixture.directory,
      result,
    );
    await persistInvestigationResult(
      source,
      fixture.directory,
      {
        operation: result.operation,
        normalizedInputs: {
          rom: fixture.romPath.split("/").at(-1),
          processor: "arm9",
          runtimeAddress: 0x02000000,
          mode: "arm",
        },
        completedStages: result.completedPrimitiveStages,
        artifacts: [resumeArtifact],
        result: { ...result, artifacts: [resumeArtifact] },
        recommendedNextAction: result.recommendedNextAction,
      },
    );

    const resumed = await resumeInvestigation(fixture.romPath, config(fixture.directory));
    assert.equal(resumed.sourceRomSha256, map.sha256);
    assert.equal(resumed.journal.entryCount, 1);
    assert.equal(resumed.journal.completedOperations[0]?.operation, "re_trace_function");
    assert.equal(resumed.journal.completedStages.includes("direct-caller-xrefs"), true);
    assert.equal(resumed.resumableResults.length, 1);
    const resumable = resumed.resumableResults[0]!;
    const candidate = resumable.candidates[0] as Record<string, unknown>;
    const window = candidate.callSiteWindow as Array<Record<string, unknown>>;
    assert.equal(candidate.instructionAddress, 0x02000020);
    assert.equal(candidate.callerFunctionId, "arm9-main:0x02000020:arm");
    assert.equal(window.length, 1);
    assert.equal(window[0]?.mnemonic, "bl");
    assert.equal(window[0]?.address, 0x02000020);
    assert.equal(resumable.resumeEvidenceComplete, true);
    assert.deepEqual(
      resumable.confirmedDeterministicEvidence,
      result.confirmedDeterministicEvidence,
    );
    assert.deepEqual(
      resumed.smallestUnresolvedNextActions,
      ["Inspect the bounded caller candidate at 0x02000020."],
    );
    assert.equal(resumed.replayRequired, false);
    assert.equal(resumed.controllerState.authority, "controller-state-only");
    assert.equal(resumed.controllerState.exists, false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("profile exposure keeps resume static and Ghidra escalation controlled", async () => {
  assert.equal(TOOL_PROFILES["re-static-core"].includes("re_resume_investigation"), true);
  assert.equal(TOOL_PROFILES["re-static-core"].includes("re_decompile_candidate"), false);
  assert.equal(TOOL_PROFILES["re-ghidra-escalation"].includes("re_decompile_candidate"), true);
  assert.equal(TOOL_PROFILES["re-ghidra-escalation"].includes("nds_ghidra_bootstrap"), false);

  const [decompileSource, orchestrationSource, resumeArtifactSource] = await Promise.all([
    readFile("src/services/re-orchestration/decompile-candidate.ts", "utf8"),
    readFile("src/tools/re-orchestration.ts", "utf8"),
    readFile("src/services/re-orchestration/resume-artifact.ts", "utf8"),
  ]);
  assert.doesNotMatch(decompileSource, /bootstrapNdsGhidraProject|nds_ghidra_bootstrap/);
  assert.match(decompileSource, /decompileNdsGhidraFunction/);
  assert.match(orchestrationSource, /persistInvestigationResumeArtifact/);
  assert.match(orchestrationSource, /persistEnvelope\(map, config, input, result\)/);
  assert.match(orchestrationSource, /re_resume_investigation/);
  assert.match(resumeArtifactSource, /callSiteWindow/);
  assert.match(resumeArtifactSource, /ghidraDerived/);
  assert.match(resumeArtifactSource, /resumeEvidenceComplete/);
});
