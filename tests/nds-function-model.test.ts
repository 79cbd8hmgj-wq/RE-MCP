import assert from "node:assert/strict";
import test from "node:test";

import {
  compareFunctionCallEdge,
  compareFunctionProof,
  compareProvenFunctionIdentity,
  provenFunctionId,
  type FunctionProof,
  type ProvenFunctionCallEdge,
  type ProvenFunctionIdentity,
} from "../src/services/nds/function-model.js";

function identity(
  overrides: Partial<ProvenFunctionIdentity> = {},
): ProvenFunctionIdentity {
  return {
    processor: "arm9",
    component: "main",
    overlayId: null,
    runtimeAddress: 0x02000000,
    romOffset: 0x4000,
    mode: "arm",
    ...overrides,
  };
}

test("proven function identity serializes every canonical ownership field", () => {
  assert.equal(
    provenFunctionId(identity({
      component: "overlay",
      overlayId: 7,
      runtimeAddress: 0x02200000,
      romOffset: 0x1200,
      mode: "thumb",
    })),
    "arm9:overlay:7:02200000:thumb",
  );

  assert.equal(
    provenFunctionId(identity({ runtimeAddress: 0x0200000c })),
    "arm9:main:0200000c:arm",
  );
});

test("proven function identity ordering is deterministic", () => {
  const values = [
    identity({ processor: "arm7" }),
    identity({ component: "overlay", overlayId: 9 }),
    identity({ component: "overlay", overlayId: 7 }),
    identity({ runtimeAddress: 0x02000010 }),
    identity({ mode: "thumb" }),
    identity(),
  ];

  values.sort(compareProvenFunctionIdentity);

  assert.deepEqual(
    values.map(provenFunctionId),
    [
      "arm9:main:02000000:arm",
      "arm9:main:02000000:thumb",
      "arm9:main:02000010:arm",
      "arm9:overlay:7:02000000:arm",
      "arm9:overlay:9:02000000:arm",
      "arm7:main:02000000:arm",
    ],
  );
});

test("function proof ordering keeps program entry before deterministic direct calls", () => {
  const target = identity({ runtimeAddress: 0x02000100, romOffset: 0x4100 });
  const proofs: FunctionProof[] = [
    {
      kind: "direct-call",
      caller: {
        functionId: "arm9:main:02000040:arm",
        component: "main",
        overlayId: null,
        instructionAddress: 0x02000048,
        instructionRomOffset: 0x4048,
        mode: "arm",
      },
      target,
    },
    {
      kind: "program-entry",
      processor: "arm9",
      headerEntryAddress: 0x02000100,
    },
    {
      kind: "direct-call",
      caller: {
        functionId: "arm9:main:02000020:arm",
        component: "main",
        overlayId: null,
        instructionAddress: 0x02000028,
        instructionRomOffset: 0x4028,
        mode: "arm",
      },
      target,
    },
  ];

  proofs.sort(compareFunctionProof);

  assert.equal(proofs[0]?.kind, "program-entry");
  assert.equal(
    proofs[1]?.kind === "direct-call"
      ? proofs[1].caller.instructionAddress
      : null,
    0x02000028,
  );
  assert.equal(
    proofs[2]?.kind === "direct-call"
      ? proofs[2].caller.instructionAddress
      : null,
    0x02000048,
  );
});

test("function call edge ordering uses caller then call site then callee", () => {
  const edges: ProvenFunctionCallEdge[] = [
    {
      callerFunctionId: "arm9:main:02000100:arm",
      instructionAddress: 0x02000110,
      instructionRomOffset: 0x4110,
      calleeFunctionId: "arm9:main:02000300:arm",
    },
    {
      callerFunctionId: "arm9:main:02000000:arm",
      instructionAddress: 0x02000020,
      instructionRomOffset: 0x4020,
      calleeFunctionId: "arm9:main:02000400:arm",
    },
    {
      callerFunctionId: "arm9:main:02000000:arm",
      instructionAddress: 0x02000020,
      instructionRomOffset: 0x4020,
      calleeFunctionId: "arm9:main:02000200:arm",
    },
    {
      callerFunctionId: "arm9:main:02000000:arm",
      instructionAddress: 0x02000010,
      instructionRomOffset: 0x4010,
      calleeFunctionId: "arm9:main:02000500:arm",
    },
  ];

  edges.sort(compareFunctionCallEdge);

  assert.deepEqual(
    edges.map((edge) => [
      edge.callerFunctionId,
      edge.instructionAddress,
      edge.calleeFunctionId,
    ]),
    [
      [
        "arm9:main:02000000:arm",
        0x02000010,
        "arm9:main:02000500:arm",
      ],
      [
        "arm9:main:02000000:arm",
        0x02000020,
        "arm9:main:02000200:arm",
      ],
      [
        "arm9:main:02000000:arm",
        0x02000020,
        "arm9:main:02000400:arm",
      ],
      [
        "arm9:main:02000100:arm",
        0x02000110,
        "arm9:main:02000300:arm",
      ],
    ],
  );
});
