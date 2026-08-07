# ARM/Thumb Static Disassembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded, read-only Nintendo DS ARM/Thumb linear disassembly and direct-control-flow analysis backed by `@alexaltea/capstone-js` 5.0.9, while preserving the canonical NDS mapping and ambiguity rules.

**Architecture:** Keep Capstone behind a narrow generic ARM decoder adapter, then layer NDS code-source resolution, canonical instruction normalization, and CFG traversal above it. Read bytes only from uniquely mapped ARM9/ARM7 main code or uncompressed overlays in the validated `.nds`; record but do not traverse calls, never guess indirect targets or ambiguous overlay state, and keep the public surface to exactly two NDS-aware MCP tools.

**Tech Stack:** TypeScript ES2022/NodeNext on Node.js >=20, Node `node:test`, Zod, existing RE-MCP NDS parser/resolver, `@alexaltea/capstone-js` 5.0.9 (JavaScript + WebAssembly), GitHub Actions package workflow.

## Global Constraints

- Pin `@alexaltea/capstone-js` exactly at `5.0.9`.
- Node.js runtime floor remains `>=20`; CI/package verification continues on Node 20.
- Public tools added by this milestone are exactly `nds_disassemble_range` and `nds_analyze_control_flow`.
- Inputs are NDS-aware only: no generic binary path, caller-provided byte buffer, arbitrary base address, arbitrary raw byte-range extraction, or caller-controlled output path.
- Decode sources are ARM9 main, ARM7 main, uncompressed ARM9 overlays, and uncompressed ARM7 overlays only.
- Compressed overlays return `compressed-overlay-not-decodable`; do not decompress or decode stored compressed bytes.
- BSS returns `runtime-only-bss`; it has no ROM bytes to decode.
- Ambiguous mappings are returned as `ambiguous-code-source`; never guess overlay loaded state.
- Initial `auto` mode is accepted only at the matching ARM9/ARM7 header entry point, which is an ARM seed. CFG-propagated mode must come from a deterministic decoded edge.
- ARM starts require 4-byte alignment; Thumb starts require 2-byte alignment; never round or silently adjust.
- Linear limits: default/max instructions `32/256`; default/max source bytes `128/1024`.
- CFG limits: default/max blocks `64/256`; total instructions `512/4096`; total decoded bytes `2048/16384`; traversal edges `128/1024`.
- CFG follows deterministic non-call direct branches and conditional fall-through. Direct calls are annotated but not traversed. Indirect branches/calls are never guessed.
- Cross-component traversal is same-processor only and requires a unique, uncompressed, file-backed target with proven mode.
- ROM SHA-256 identity is checked before and after each top-level static disassembly operation.
- WebAssembly/backend initialization failures are operational `disassembly-backend-failure` errors, not malformed-ROM results.
- Package acceptance must initialize the decoder and decode known ARM and Thumb fixtures from the assembled production bundle with no network or external disassembler.
- Physical Catalina/DeSmuME dynamic-debugging acceptance remains separate and is not claimed by this milestone.

---

## File Map and Responsibilities

### New files

- `src/types/alexaltea-capstone-js.d.ts` — minimal local type declaration for the untyped Capstone.js package surface RE-MCP actually uses.
- `src/services/disassembly/backend.ts` — RE-MCP-owned ARM decoder interface and normalized decoder metadata; contains no NDS logic.
- `src/services/disassembly/capstone.ts` — async Capstone.js/WASM loader and ARM/Thumb adapter; the only production file importing `@alexaltea/capstone-js`.
- `src/services/nds/disassembly-source.ts` — converts runtime addresses/ROM offsets into one deterministic file-backed NDS code source, enforces mode/alignment/compression/BSS/ambiguity policy, and provides SHA-validated bounded ROM reads.
- `src/services/nds/disassembly.ts` — canonical NDS instruction/flow model, direct-target annotation, and bounded linear disassembly.
- `src/services/nds/control-flow.ts` — bounded basic-block worklist traversal over canonical instructions.
- `tests/disassembly-backend.test.ts` — real Capstone.js adapter contract tests with known ARM/Thumb bytes.
- `tests/nds-disassembly-source.test.ts` — NDS source/mode/alignment/identity policy tests.
- `tests/nds-disassembly.test.ts` — canonical flow classification and bounded linear disassembly tests.
- `tests/nds-control-flow.test.ts` — CFG branch/call/cycle/cross-component/limit tests.

### Existing files modified

- `package.json`, `package-lock.json` — exact Capstone.js production dependency.
- `src/tools/nds.ts` — register the two tools, schemas, request normalization, output bounding, and backend-error mapping.
- `tests/nds-tools.test.ts` — tool-registration/schema/handler/security assertions.
- `src/index.ts` — advertise both tool names and the static-disassembly safety policy.
- `scripts/check-install.mjs` — require Capstone package/WASM assets and run packaged ARM/Thumb decoder smoke tests.
- `.github/workflows/package.yml` — keep the isolated production install and make the decoder smoke check an explicit named package acceptance step.
- `README.md` — document tool workflow, limits, mode semantics, ambiguity/BSS/compression behavior, call traversal, and separation from native debugger acceptance.

---

### Task 1: Pin Capstone.js and establish the isolated decoder adapter

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `src/types/alexaltea-capstone-js.d.ts`
- Create: `src/services/disassembly/backend.ts`
- Create: `src/services/disassembly/capstone.ts`
- Create/Test: `tests/disassembly-backend.test.ts`

**Interfaces:**
- Consumes: `@alexaltea/capstone-js` factory `MCapstone(): Promise<CapstoneModule>`, `Capstone`, `ARCH_ARM`, `MODE_ARM`, `MODE_THUMB`, `OPT_DETAIL`, `OPT_ON`, architecture-agnostic instruction groups, ARM operands/condition codes, `disasm_iter()`, and `close()`.
- Produces:

```ts
export type ArmMode = "arm" | "thumb";

export type DecodedArmOperand =
  | { readonly kind: "immediate"; readonly value: number }
  | { readonly kind: "register"; readonly name: string }
  | { readonly kind: "other" };

export interface DecodedArmInstruction {
  readonly address: number;
  readonly size: 2 | 4;
  readonly bytes: readonly number[];
  readonly mnemonic: string;
  readonly operandsText: string;
  readonly operands: readonly DecodedArmOperand[];
  readonly isJump: boolean;
  readonly isCall: boolean;
  readonly isReturn: boolean;
  readonly isConditional: boolean;
  readonly switchesMode: boolean;
}

export interface ArmDisassemblyBackend {
  decodeOne(bytes: Uint8Array, address: number, mode: ArmMode): DecodedArmInstruction | null;
  close(): void;
}

export class DisassemblyBackendError extends Error {
  readonly category = "disassembly-backend-failure" as const;
}

export async function createCapstoneArmBackend(): Promise<ArmDisassemblyBackend>;
```

- [ ] **Step 1: Install the exact production dependency**

Run:

```bash
npm install --save-exact @alexaltea/capstone-js@5.0.9
```

Expected: `package.json` contains `"@alexaltea/capstone-js": "5.0.9"` and `package-lock.json` records the package including its `dist/capstone.js`/`dist/capstone.wasm` package payload.

- [ ] **Step 2: Write the failing real-backend test**

Create `tests/disassembly-backend.test.ts`:

```ts
import assert from "node:assert/strict";
import test from "node:test";

import { createCapstoneArmBackend } from "../src/services/disassembly/capstone.js";

test("Capstone adapter decodes known ARM and Thumb instructions", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    const arm = backend.decodeOne(
      Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]), // bx lr
      0x02000000,
      "arm",
    );
    assert.ok(arm);
    assert.equal(arm.address, 0x02000000);
    assert.equal(arm.size, 4);
    assert.deepEqual(arm.bytes, [0x1e, 0xff, 0x2f, 0xe1]);
    assert.equal(arm.mnemonic, "bx");
    assert.equal(arm.operandsText, "lr");
    assert.equal(arm.isJump, true);
    assert.deepEqual(arm.operands[0], { kind: "register", name: "lr" });

    const thumb = backend.decodeOne(
      Uint8Array.from([0x70, 0x47]), // bx lr
      0x02000010,
      "thumb",
    );
    assert.ok(thumb);
    assert.equal(thumb.size, 2);
    assert.equal(thumb.mnemonic, "bx");
    assert.equal(thumb.isJump, true);
  } finally {
    backend.close();
  }
});

test("Capstone adapter returns null for an incomplete instruction", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    assert.equal(backend.decodeOne(Uint8Array.from([0x00]), 0x02000000, "arm"), null);
  } finally {
    backend.close();
  }
});
```

- [ ] **Step 3: Run the test to verify RED**

Run:

```bash
node --test --import tsx tests/disassembly-backend.test.ts
```

Expected: FAIL because `src/services/disassembly/capstone.ts` does not exist.

- [ ] **Step 4: Add the minimal package declaration and backend-owned types**

Create `src/types/alexaltea-capstone-js.d.ts` with only the fields used by the adapter:

```ts
declare module "@alexaltea/capstone-js" {
  export interface CapstoneOperand {
    readonly type: number;
    readonly imm?: number;
    readonly reg?: number;
  }

  export interface CapstoneInstruction {
    readonly id: number;
    readonly address: number;
    readonly size: number;
    readonly bytes: readonly number[];
    readonly mnemonic: string;
    readonly op_str: string;
    readonly detail: {
      readonly groups?: readonly number[];
      readonly cc?: number;
      readonly op?: readonly CapstoneOperand[];
    };
  }

  export interface CapstoneHandle {
    option(option: number, value: number): void;
    disasm_iter(
      bytes: ArrayLike<number>,
      address: number,
      callback: (instruction: CapstoneInstruction, pointer: number) => boolean,
    ): number;
    reg_name(registerId: number): string;
    close(): void;
  }

  export interface CapstoneModule {
    readonly ARCH_ARM: number;
    readonly MODE_ARM: number;
    readonly MODE_THUMB: number;
    readonly OPT_DETAIL: number;
    readonly OPT_ON: number;
    readonly GRP_JUMP: number;
    readonly GRP_CALL: number;
    readonly GRP_RET: number;
    readonly ARM_OP_IMM: number;
    readonly ARM_OP_REG: number;
    readonly ARM_CC_INVALID: number;
    readonly ARM_CC_AL: number;
    readonly ARM_INS_BLX: number;
    readonly ARM_INS_CBZ: number;
    readonly ARM_INS_CBNZ: number;
    readonly Capstone: new (architecture: number, mode: number) => CapstoneHandle;
  }

  export type CapstoneFactory = () => Promise<CapstoneModule>;
  const MCapstone: CapstoneFactory;
  export default MCapstone;
}
```

Create `src/services/disassembly/backend.ts` with the exact interfaces from the **Produces** block and:

```ts
export class DisassemblyBackendError extends Error {
  readonly category = "disassembly-backend-failure" as const;

  constructor(message: string, readonly causeValue?: unknown) {
    super(message);
    this.name = "DisassemblyBackendError";
  }
}
```

- [ ] **Step 5: Implement the Capstone adapter with detail mode and `disasm_iter`**

Create `src/services/disassembly/capstone.ts`:

```ts
import type {
  CapstoneFactory,
  CapstoneInstruction,
  CapstoneModule,
  CapstoneOperand,
} from "@alexaltea/capstone-js";

import {
  DisassemblyBackendError,
  type ArmDisassemblyBackend,
  type ArmMode,
  type DecodedArmInstruction,
  type DecodedArmOperand,
} from "./backend.js";

let modulePromise: Promise<CapstoneModule> | null = null;

async function loadCapstone(): Promise<CapstoneModule> {
  if (modulePromise === null) {
    modulePromise = import("@alexaltea/capstone-js")
      .then((loaded) => {
        const factory = loaded.default as CapstoneFactory;
        return factory();
      })
      .catch((error: unknown) => {
        modulePromise = null;
        throw new DisassemblyBackendError(
          `Unable to initialize Capstone.js: ${error instanceof Error ? error.message : String(error)}`,
          error,
        );
      });
  }
  return await modulePromise;
}

function hasGroup(instruction: CapstoneInstruction, group: number): boolean {
  return instruction.detail.groups?.includes(group) === true;
}

function normalizeOperand(
  cs: CapstoneModule,
  decoder: { reg_name(registerId: number): string },
  operand: CapstoneOperand,
): DecodedArmOperand {
  if (operand.type === cs.ARM_OP_IMM && operand.imm !== undefined) {
    return { kind: "immediate", value: operand.imm >>> 0 };
  }
  if (operand.type === cs.ARM_OP_REG && operand.reg !== undefined) {
    return { kind: "register", name: decoder.reg_name(operand.reg).toLowerCase() };
  }
  return { kind: "other" };
}

function normalizeInstruction(
  cs: CapstoneModule,
  decoder: { reg_name(registerId: number): string },
  instruction: CapstoneInstruction,
): DecodedArmInstruction {
  const size = instruction.size;
  if (size !== 2 && size !== 4) {
    throw new DisassemblyBackendError(`Unexpected ARM instruction size ${size}`);
  }
  const cc = instruction.detail.cc;
  const isConditional = instruction.id === cs.ARM_INS_CBZ
    || instruction.id === cs.ARM_INS_CBNZ
    || (cc !== undefined && cc !== cs.ARM_CC_INVALID && cc !== cs.ARM_CC_AL);
  return {
    address: instruction.address >>> 0,
    size,
    bytes: [...instruction.bytes],
    mnemonic: instruction.mnemonic,
    operandsText: instruction.op_str,
    operands: (instruction.detail.op ?? []).map((operand) => normalizeOperand(cs, decoder, operand)),
    isJump: hasGroup(instruction, cs.GRP_JUMP),
    isCall: hasGroup(instruction, cs.GRP_CALL),
    isReturn: hasGroup(instruction, cs.GRP_RET),
    isConditional,
    switchesMode: instruction.id === cs.ARM_INS_BLX,
  };
}

export async function createCapstoneArmBackend(): Promise<ArmDisassemblyBackend> {
  const cs = await loadCapstone();
  let arm;
  let thumb;
  try {
    arm = new cs.Capstone(cs.ARCH_ARM, cs.MODE_ARM);
    thumb = new cs.Capstone(cs.ARCH_ARM, cs.MODE_THUMB);
    arm.option(cs.OPT_DETAIL, cs.OPT_ON);
    thumb.option(cs.OPT_DETAIL, cs.OPT_ON);
  } catch (error) {
    arm?.close();
    thumb?.close();
    throw new DisassemblyBackendError(
      `Unable to open Capstone ARM decoders: ${error instanceof Error ? error.message : String(error)}`,
      error,
    );
  }

  return {
    decodeOne(bytes: Uint8Array, address: number, mode: ArmMode) {
      const decoder = mode === "arm" ? arm : thumb;
      let decoded: DecodedArmInstruction | null = null;
      try {
        decoder.disasm_iter(bytes, address, (instruction) => {
          decoded = normalizeInstruction(cs, decoder, instruction);
          return false;
        });
        return decoded;
      } catch (error) {
        throw new DisassemblyBackendError(
          `Capstone decode failed at 0x${address.toString(16)}: ${error instanceof Error ? error.message : String(error)}`,
          error,
        );
      }
    },
    close() {
      try {
        arm.close();
        thumb.close();
      } catch (error) {
        throw new DisassemblyBackendError(
          `Unable to close Capstone ARM decoders: ${error instanceof Error ? error.message : String(error)}`,
          error,
        );
      }
    },
  };
}
```

- [ ] **Step 6: Run adapter test and typecheck**

Run:

```bash
node --test --import tsx tests/disassembly-backend.test.ts
npm run typecheck
```

Expected: both PASS. If the package's Node ESM/CJS interop differs from the declared default factory, adjust only `loadCapstone()` and the declaration to the observed 5.0.9 runtime export; do not leak package-specific handling into later tasks.

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json src/types/alexaltea-capstone-js.d.ts src/services/disassembly/backend.ts src/services/disassembly/capstone.ts tests/disassembly-backend.test.ts
git commit -m "feat: add ARM Thumb disassembly backend"
```

---

### Task 2: Add deterministic NDS code-source and ROM-identity policy

**Files:**
- Create: `src/services/nds/disassembly-source.ts`
- Create/Test: `tests/nds-disassembly-source.test.ts`
- Reuse: `src/services/nds/resolver.ts`, `src/services/nds/rom-map.ts`, `src/services/nds/io.ts`, `src/services/nds/overlays.ts`

**Interfaces:**
- Consumes: `resolveRuntimeAddress(map, address, processor)`, `resolveRomOffset(map, offset)`, `hashFileSha256(path)`, `readExact(handle, offset, length, label)`, `NdsRomMap`, `NdsProcessor`, `ArmMode`.
- Produces:

```ts
export type NdsDisassemblyMode = ArmMode | "auto";

export interface NdsDisassemblyLocation {
  readonly processor: NdsProcessor;
  readonly mode: NdsDisassemblyMode;
  readonly runtimeAddress?: number;
  readonly romOffset?: number;
  readonly overlayId?: number;
}

export interface NdsCodeSource {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number;
  readonly romOffset: number;
  readonly runtimeEnd: number;
  readonly romEnd: number;
  readonly mode: ArmMode;
}

export type NdsCodeSourceResolution =
  | { readonly status: "resolved"; readonly source: NdsCodeSource }
  | { readonly status: "ambiguous-code-source"; readonly candidates: readonly unknown[] }
  | { readonly status: "compressed-overlay-not-decodable"; readonly candidate: unknown }
  | { readonly status: "runtime-only-bss"; readonly candidate: unknown }
  | { readonly status: "unmapped-address"; readonly address: number; readonly processor: NdsProcessor }
  | { readonly status: "mode-ambiguous"; readonly address: number; readonly processor: NdsProcessor };

export function resolveNdsCodeSource(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
): NdsCodeSourceResolution;

export function resolveNdsControlFlowTarget(
  map: NdsRomMap,
  current: NdsCodeSource,
  runtimeAddress: number,
  mode: ArmMode,
): NdsCodeSourceResolution;

export async function withValidatedNdsRomReader<T>(
  map: NdsRomMap,
  callback: (read: (source: NdsCodeSource, maxBytes: number) => Promise<Buffer>) => Promise<T>,
): Promise<T>;
```

- [ ] **Step 1: Write failing source-policy tests**

Create `tests/nds-disassembly-source.test.ts` using `createNdsFixture`, `writeFatEntry`, and `writeOverlayRecord`. Include these tests with concrete fixture values:

```ts
test("resolves ARM9 header entry in conservative auto mode", async () => {
  const fixture = await createNdsFixture({ arm9EntryAddress: 0x02000020 });
  const map = await readNdsRomMap(fixture.romPath);
  const result = resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02000020,
    mode: "auto",
  });
  assert.equal(result.status, "resolved");
  if (result.status === "resolved") assert.equal(result.source.mode, "arm");
});

test("rejects auto mode away from a trusted header entry", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  assert.equal(resolveNdsCodeSource(map, {
    processor: "arm9",
    runtimeAddress: 0x02000004,
    mode: "auto",
  }).status, "mode-ambiguous");
});

test("preserves overlapping overlay ambiguity unless overlayId disambiguates", async () => {
  const fixture = await createNdsFixture({ fatSize: 16, arm9OverlaySize: 64 });
  writeFatEntry(fixture.buffer, 0x900, 0, 0x1000, 0x1080);
  writeFatEntry(fixture.buffer, 0x900, 1, 0x1100, 0x1180);
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
  assert.equal(resolveNdsCodeSource(map, {
    processor: "arm9", runtimeAddress: 0x02200010, mode: "arm",
  }).status, "ambiguous-code-source");
  const chosen = resolveNdsCodeSource(map, {
    processor: "arm9", runtimeAddress: 0x02200010, mode: "arm", overlayId: 7,
  });
  assert.equal(chosen.status, "resolved");
  if (chosen.status === "resolved") assert.equal(chosen.source.overlayId, 7);
});
```

Also add explicit tests for: ARM/Thumb alignment, ARM7 main, ROM-offset entry, compressed overlay, overlay BSS, overlay physical-size shorter than `ramSize`, processor mismatch, same-component target preservation, cross-component ambiguity, and SHA mismatch before/after `withValidatedNdsRomReader`.

- [ ] **Step 2: Run source tests to verify RED**

Run:

```bash
node --test --import tsx tests/nds-disassembly-source.test.ts
```

Expected: FAIL because `disassembly-source.ts` does not exist.

- [ ] **Step 3: Implement source resolution without duplicating the parser**

Implement `src/services/nds/disassembly-source.ts` around the existing resolver. Core policies must be explicit:

```ts
function requireOneLocation(location: NdsDisassemblyLocation): "runtime" | "rom" {
  const hasRuntime = location.runtimeAddress !== undefined;
  const hasRom = location.romOffset !== undefined;
  if (hasRuntime === hasRom) {
    throw new NdsError("range-out-of-bounds", "Disassembly requires exactly one of runtimeAddress or romOffset");
  }
  return hasRuntime ? "runtime" : "rom";
}

function resolveMode(
  map: NdsRomMap,
  processor: NdsProcessor,
  address: number,
  requested: NdsDisassemblyMode,
): ArmMode | null {
  if (requested !== "auto") return requested;
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  return address === executable.entryAddress ? "arm" : null;
}

function requireAlignment(address: number, mode: ArmMode): void {
  const alignment = mode === "arm" ? 4 : 2;
  if (address % alignment !== 0) {
    throw new NdsError("range-out-of-bounds", `${mode.toUpperCase()} disassembly address must be ${alignment}-byte aligned`);
  }
}
```

For an uncompressed overlay, compute the file-backed initialized end from `Math.min(overlay.ramSize, overlay.romSize)`. Never include BSS or the unbacked runtime suffix.

When a runtime address is ambiguous and `overlayId` is supplied, select only the matching overlay candidate; otherwise return all candidates as `ambiguous-code-source`.

When resolving a control-flow target, preserve `current.overlayId` only if the target lies inside `current.runtimeAddress..current.runtimeEnd` after translating from the component base; otherwise resolve with no overlay hint so cross-component overlap remains ambiguous.

- [ ] **Step 4: Implement SHA-validated bounded reads**

Use the existing streaming hash and exact-read helper:

```ts
export async function withValidatedNdsRomReader<T>(
  map: NdsRomMap,
  callback: (read: (source: NdsCodeSource, maxBytes: number) => Promise<Buffer>) => Promise<T>,
): Promise<T> {
  if (await hashFileSha256(map.romPath) !== map.sha256) {
    throw new NdsError("invalid-rom", "Source ROM no longer matches the canonical map identity");
  }
  const handle = await open(map.romPath, "r");
  let result: T;
  try {
    result = await callback(async (source, maxBytes) => {
      const length = Math.min(maxBytes, source.romEnd - source.romOffset);
      return await readExact(handle, source.romOffset, length, "NDS disassembly source");
    });
  } finally {
    await handle.close();
  }
  if (await hashFileSha256(map.romPath) !== map.sha256) {
    throw new NdsError("invalid-rom", "Source ROM changed during disassembly");
  }
  return result;
}
```

- [ ] **Step 5: Run source tests and NDS resolver regression**

Run:

```bash
node --test --import tsx tests/nds-disassembly-source.test.ts tests/nds-resolver.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/disassembly-source.ts tests/nds-disassembly-source.test.ts
git commit -m "feat: resolve NDS disassembly sources"
```

---

### Task 3: Build canonical instruction flow and bounded linear disassembly

**Files:**
- Create: `src/services/nds/disassembly.ts`
- Create/Test: `tests/nds-disassembly.test.ts`
- Reuse: `src/services/disassembly/backend.ts`, `src/services/nds/disassembly-source.ts`

**Interfaces:**
- Consumes: `ArmDisassemblyBackend.decodeOne()`, `NdsCodeSource`, `resolveNdsControlFlowTarget()`, `withValidatedNdsRomReader()`.
- Produces:

```ts
export type StaticFlowKind =
  | "fallthrough"
  | "conditional-branch"
  | "unconditional-branch"
  | "call"
  | "return"
  | "indirect-branch"
  | "indirect-call";

export interface StaticInstruction {
  readonly address: number;
  readonly romOffset: number;
  readonly size: 2 | 4;
  readonly bytesHex: string;
  readonly mode: ArmMode;
  readonly mnemonic: string;
  readonly operands: string;
  readonly flow: {
    readonly kind: StaticFlowKind;
    readonly directTarget: number | null;
    readonly targetMode: ArmMode | null;
    readonly fallthrough: number | null;
  };
  readonly source: {
    readonly processor: NdsProcessor;
    readonly component: "main" | "overlay";
    readonly overlayId: number | null;
  };
  readonly targetResolution: NdsCodeSourceResolution | null;
}

export interface LinearDisassemblyOptions {
  readonly maxInstructions: number;
  readonly maxBytes: number;
}

export type LinearDisassemblyResult =
  | NdsCodeSourceResolution
  | {
      readonly status: "complete" | "decode-stopped" | "component-boundary";
      readonly source: NdsCodeSource;
      readonly instructions: readonly StaticInstruction[];
      readonly decodedBytes: number;
      readonly stopAddress: number;
    };

export async function disassembleNdsRange(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  options: LinearDisassemblyOptions,
  backend: ArmDisassemblyBackend,
): Promise<LinearDisassemblyResult>;
```

- [ ] **Step 1: Write failing canonical-flow tests with a fake backend**

In `tests/nds-disassembly.test.ts`, define a tiny deterministic fake:

```ts
class FakeBackend implements ArmDisassemblyBackend {
  constructor(private readonly decoded: ReadonlyMap<number, DecodedArmInstruction | null>) {}
  decodeOne(_bytes: Uint8Array, address: number): DecodedArmInstruction | null {
    return this.decoded.get(address) ?? null;
  }
  close(): void {}
}
```

Add cases for ordinary fall-through, conditional direct branch, unconditional direct branch, direct call, indirect call, indirect branch, `bx lr` return semantics, mode-preserving targets, and `switchesMode` targets. Example direct-call fixture:

```ts
const call: DecodedArmInstruction = {
  address: 0x02000000,
  size: 4,
  bytes: [0x00, 0x00, 0x00, 0xeb],
  mnemonic: "bl",
  operandsText: "#0x02000008",
  operands: [{ kind: "immediate", value: 0x02000008 }],
  isJump: false,
  isCall: true,
  isReturn: false,
  isConditional: false,
  switchesMode: false,
};
```

Assert that a call has `kind: "call"`, `directTarget: 0x02000008`, `targetMode: "arm"`, and `fallthrough: 0x02000004`.

- [ ] **Step 2: Run linear tests to verify RED**

Run:

```bash
node --test --import tsx tests/nds-disassembly.test.ts
```

Expected: FAIL because `src/services/nds/disassembly.ts` does not exist.

- [ ] **Step 3: Implement semantic flow normalization**

Use backend metadata first; do not parse branch targets from operand text:

```ts
function firstImmediate(decoded: DecodedArmInstruction): number | null {
  for (const operand of decoded.operands) {
    if (operand.kind === "immediate") return operand.value >>> 0;
  }
  return null;
}

function isLinkRegisterReturn(decoded: DecodedArmInstruction): boolean {
  return decoded.mnemonic.toLowerCase() === "bx"
    && decoded.operands.some((operand) => operand.kind === "register" && operand.name === "lr");
}

function opposite(mode: ArmMode): ArmMode {
  return mode === "arm" ? "thumb" : "arm";
}

function normalizeFlow(decoded: DecodedArmInstruction, mode: ArmMode): StaticInstruction["flow"] {
  const next = (decoded.address + decoded.size) >>> 0;
  const immediate = firstImmediate(decoded);
  if (decoded.isReturn || isLinkRegisterReturn(decoded)) {
    return { kind: "return", directTarget: null, targetMode: null, fallthrough: null };
  }
  if (decoded.isCall) {
    return {
      kind: immediate === null ? "indirect-call" : "call",
      directTarget: immediate,
      targetMode: immediate === null ? null : decoded.switchesMode ? opposite(mode) : mode,
      fallthrough: next,
    };
  }
  if (decoded.isJump) {
    if (immediate === null) {
      return { kind: "indirect-branch", directTarget: null, targetMode: null, fallthrough: null };
    }
    return {
      kind: decoded.isConditional ? "conditional-branch" : "unconditional-branch",
      directTarget: immediate,
      targetMode: decoded.switchesMode ? opposite(mode) : mode,
      fallthrough: decoded.isConditional ? next : null,
    };
  }
  return { kind: "fallthrough", directTarget: null, targetMode: null, fallthrough: next };
}
```

`isLinkRegisterReturn` is the narrow semantic fallback for `BX LR`; branch/call classification and immediate targets still come from Capstone groups/typed operands, not mnemonic text.

- [ ] **Step 4: Implement bounded linear decoding**

Resolve the source once, read no more than `options.maxBytes`, and decode from offset zero until instruction count, byte budget, component end, or decode stop. Before accepting an instruction, verify `cursor + decoded.size <= bytes.length` and `source.romOffset + cursor + decoded.size <= source.romEnd`.

For every direct target with a known mode, annotate `targetResolution` with `resolveNdsControlFlowTarget(map, currentSourceAtInstruction, target, targetMode)`. Do not traverse it in this function.

Use lowercase two-digit hex bytes:

```ts
const bytesHex = decoded.bytes.map((value) => value.toString(16).padStart(2, "0")).join("");
```

A zero-instruction decoder result returns `status: "decode-stopped"` with the successfully decoded prefix. Reaching the exact file-backed end returns `status: "component-boundary"`. Reaching the requested instruction/byte bound returns `status: "complete"`; the bound is the requested window, not a claim that the containing function is complete.

- [ ] **Step 5: Add real-backend ARM/Thumb integration cases**

Write one tiny fixture with ARM `BX LR` at ARM9 entry and one with Thumb `BX LR` at an explicitly Thumb address. Assert exact runtime address, ROM offset, bytes, mnemonic, mode, source identity, and return classification.

- [ ] **Step 6: Run linear, backend, and source tests**

Run:

```bash
node --test --import tsx tests/disassembly-backend.test.ts tests/nds-disassembly-source.test.ts tests/nds-disassembly.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/disassembly.ts tests/nds-disassembly.test.ts
git commit -m "feat: add bounded NDS linear disassembly"
```

---

### Task 4: Add bounded direct-control-flow traversal

**Files:**
- Create: `src/services/nds/control-flow.ts`
- Create/Test: `tests/nds-control-flow.test.ts`
- Reuse: `src/services/nds/disassembly.ts`, `src/services/nds/disassembly-source.ts`

**Interfaces:**
- Consumes: canonical `StaticInstruction`, source resolution, and the same backend/ROM reader used by linear disassembly.
- Produces:

```ts
export interface ControlFlowLimits {
  readonly maxBlocks: number;
  readonly maxInstructions: number;
  readonly maxBytes: number;
  readonly maxEdges: number;
}

export interface StaticBasicBlock {
  readonly id: string;
  readonly source: NdsCodeSource;
  readonly startAddress: number;
  readonly mode: ArmMode;
  readonly instructions: readonly StaticInstruction[];
  readonly stopReason: "branch" | "return" | "indirect" | "decode-stopped" | "component-boundary" | "limit";
}

export interface StaticControlFlowEdge {
  readonly fromBlockId: string;
  readonly type: "fallthrough" | "branch" | "conditional-taken" | "conditional-fallthrough";
  readonly targetAddress: number;
  readonly targetMode: ArmMode;
  readonly targetBlockId: string | null;
}

export interface StaticCallEdge {
  readonly fromBlockId: string;
  readonly instructionAddress: number;
  readonly targetAddress: number | null;
  readonly targetMode: ArmMode | null;
  readonly resolution: NdsCodeSourceResolution | null;
}

export interface StaticUnresolvedEdge {
  readonly fromBlockId: string;
  readonly instructionAddress: number;
  readonly kind: "indirect-branch" | "indirect-call" | "return" | "ambiguous-code-source" | "compressed-overlay-not-decodable" | "runtime-only-bss" | "unmapped-address";
}

export interface StaticControlFlowGraph {
  readonly entry: NdsCodeSource;
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly ("block-limit" | "instruction-limit" | "byte-limit" | "edge-limit")[];
  readonly blocks: readonly StaticBasicBlock[];
  readonly edges: readonly StaticControlFlowEdge[];
  readonly calls: readonly StaticCallEdge[];
  readonly unresolvedEdges: readonly StaticUnresolvedEdge[];
  readonly totals: { readonly blocks: number; readonly instructions: number; readonly bytes: number; readonly edges: number };
}

export async function analyzeNdsControlFlow(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  limits: ControlFlowLimits,
  backend: ArmDisassemblyBackend,
): Promise<NdsCodeSourceResolution | StaticControlFlowGraph>;
```

- [ ] **Step 1: Write failing CFG tests**

Create `tests/nds-control-flow.test.ts` with fake-backend graphs covering:

1. conditional branch creates taken + fall-through blocks;
2. unconditional branch creates only branch target;
3. direct call is added to `calls` but the callee is never queued and decoding continues after the call;
4. indirect call is recorded and decoding continues through its fall-through;
5. indirect branch terminates the block;
6. return terminates the block;
7. branch cycle produces each block once;
8. deterministic same-component overlay branch preserves overlay identity;
9. unique cross-component same-processor branch is traversed;
10. ambiguous/compressed/BSS/unmapped target becomes `unresolvedEdges` and is not queued;
11. ARM↔Thumb immediate switch uses the propagated target mode;
12. each of the four limits independently returns `status: "truncated"` with the exact reason;
13. simultaneous cap hits produce a deduplicated deterministic reason list.

Use a fixed block ID function in assertions:

```ts
function blockKey(source: NdsCodeSource): string {
  return [source.processor, source.component, source.overlayId ?? "main", source.runtimeAddress.toString(16), source.mode].join(":");
}
```

- [ ] **Step 2: Run CFG tests to verify RED**

Run:

```bash
node --test --import tsx tests/nds-control-flow.test.ts
```

Expected: FAIL because `control-flow.ts` does not exist.

- [ ] **Step 3: Implement deterministic worklist traversal**

Use FIFO traversal for stable output. The visited/worklist identity is exactly processor + component + overlay ID/main + runtime address + mode.

Block decode rules:

- ordinary instruction: stay in the same block;
- direct call: append call metadata, then continue at call fall-through in the same block;
- indirect call: append unresolved call metadata, then continue at its fall-through in the same block;
- conditional direct branch: terminate block, emit taken and fall-through edges, queue each resolved target;
- unconditional direct branch: terminate block, emit one branch edge, queue resolved target;
- indirect branch/return: terminate block and record unresolved/terminal event;
- decode failure/component end: terminate only that block; continue other queued blocks.

Do not call `disassembleNdsRange()` recursively because its per-window SHA/read lifecycle would be wasteful. Factor the one-instruction normalization helper from Task 3 as a package-private/exported helper if needed, and wrap the whole CFG operation in one `withValidatedNdsRomReader()` call.

- [ ] **Step 4: Enforce all four global traversal counters before queue/decode growth**

Maintain:

```ts
let totalInstructions = 0;
let totalBytes = 0;
let totalEdges = 0;
const reasons = new Set<"block-limit" | "instruction-limit" | "byte-limit" | "edge-limit">();
```

Never exceed the configured maximum. When additional work would cross a cap, add the corresponding reason, skip that work, keep already produced data, and finish processing only work that can still be represented without violating another cap. Final status is `reasons.size === 0 ? "complete" : "truncated"`.

Sort `truncationReasons` in fixed order: block, instruction, byte, edge. Preserve FIFO block order and instruction order for deterministic JSON.

- [ ] **Step 5: Run CFG + linear regression tests**

Run:

```bash
node --test --import tsx tests/nds-control-flow.test.ts tests/nds-disassembly.test.ts tests/nds-disassembly-source.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/services/nds/control-flow.ts tests/nds-control-flow.test.ts src/services/nds/disassembly.ts
git commit -m "feat: add bounded NDS control flow analysis"
```

---

### Task 5: Expose exactly two bounded NDS disassembly MCP tools

**Files:**
- Modify: `src/tools/nds.ts`
- Modify/Test: `tests/nds-tools.test.ts`
- Modify: `src/index.ts`

**Interfaces:**
- Consumes: `createCapstoneArmBackend()`, `disassembleNdsRange()`, `analyzeNdsControlFlow()`, existing `readNdsRomMap()`, `resolveInside()`, `boundedTextResult()`.
- Produces public tools:
  - `nds_disassemble_range`
  - `nds_analyze_control_flow`

- [ ] **Step 1: Extend the failing MCP registration/schema tests**

Update `EXPECTED_TOOLS` in `tests/nds-tools.test.ts` to contain all nine NDS tools, including the two new names, and rename the registration test to `registers exactly the nine approved NDS static-analysis tools`.

Add schema assertions:

```ts
assert.deepEqual(server.parse("nds_disassemble_range", {
  rom: "game.nds",
  processor: "arm9",
  runtimeAddress: 0x02000000,
}), {
  rom: "game.nds",
  processor: "arm9",
  runtimeAddress: 0x02000000,
  mode: "auto",
  maxInstructions: 32,
  maxBytes: 128,
});

assert.deepEqual(server.parse("nds_analyze_control_flow", {
  rom: "game.nds",
  processor: "arm9",
  runtimeAddress: 0x02000000,
}), {
  rom: "game.nds",
  processor: "arm9",
  runtimeAddress: 0x02000000,
  mode: "auto",
  maxBlocks: 64,
  maxInstructions: 512,
  maxBytes: 2048,
  maxEdges: 128,
});
```

Assert rejection above every approved maximum and assert both schemas lack `binary`, `bytes`, `baseAddress`, `output`, `path`, `offset`, and generic `length` fields. `romOffset` is the only ROM-offset field; `runtimeAddress` is the only runtime-address field.

Add a handler test asserting supplying neither or both `runtimeAddress`/`romOffset` returns a structured error rather than guessing.

- [ ] **Step 2: Run MCP test to verify RED**

Run:

```bash
node --test --import tsx tests/nds-tools.test.ts
```

Expected: FAIL because only the existing seven NDS tools are registered.

- [ ] **Step 3: Add exact schemas and request normalization**

In `src/tools/nds.ts` add:

```ts
const disassemblyModeSchema = z.enum(["arm", "thumb", "auto"]);
const linearInstructionLimitSchema = z.number().int().min(1).max(256).default(32);
const linearByteLimitSchema = z.number().int().min(2).max(1024).default(128);
const cfgBlockLimitSchema = z.number().int().min(1).max(256).default(64);
const cfgInstructionLimitSchema = z.number().int().min(1).max(4096).default(512);
const cfgByteLimitSchema = z.number().int().min(2).max(16384).default(2048);
const cfgEdgeLimitSchema = z.number().int().min(1).max(1024).default(128);
```

Normalize exactly one location selector:

```ts
function normalizeDisassemblyLocation(input: {
  readonly processor: "arm9" | "arm7";
  readonly mode: "arm" | "thumb" | "auto";
  readonly runtimeAddress?: number;
  readonly romOffset?: number;
  readonly overlayId?: number;
}): NdsDisassemblyLocation {
  const runtime = input.runtimeAddress !== undefined;
  const rom = input.romOffset !== undefined;
  if (runtime === rom) {
    throw new NdsError("range-out-of-bounds", "Disassembly requires exactly one of runtimeAddress or romOffset");
  }
  return {
    processor: input.processor,
    mode: input.mode,
    ...(runtime ? { runtimeAddress: input.runtimeAddress! } : { romOffset: input.romOffset! }),
    ...(input.overlayId === undefined ? {} : { overlayId: input.overlayId }),
  };
}
```

- [ ] **Step 4: Add backend-aware structured error mapping**

Define a local tool error category union rather than pretending the backend is an NDS parser error:

```ts
type NdsToolErrorCategory = NdsErrorCategory | "disassembly-backend-failure";
```

Add a corrective action:

```ts
case "disassembly-backend-failure":
  return "Verify the packaged @alexaltea/capstone-js JavaScript/WASM assets and Node.js runtime, then retry the static disassembly request.";
```

In `ndsErrorResult`, prefer `DisassemblyBackendError.category`, then `NdsError.category`, then the supplied fallback.

- [ ] **Step 5: Register `nds_disassemble_range`**

Handler sequence:

```ts
const map = await readNdsRomMap(resolveRom(config, rom));
const location = normalizeDisassemblyLocation({ processor, mode, runtimeAddress, romOffset, overlayId });
const backend = await createCapstoneArmBackend();
try {
  const result = await disassembleNdsRange(
    map,
    location,
    { maxInstructions, maxBytes },
    backend,
  );
  return boundedTextResult(config, operation, result);
} finally {
  backend.close();
}
```

Static statuses such as ambiguity, BSS, compression, mode ambiguity, decode stop, and component boundary are returned with `isError: false`. Operational exceptions use `ndsErrorResult`.

- [ ] **Step 6: Register `nds_analyze_control_flow`**

Use the same location/backend lifecycle and call:

```ts
await analyzeNdsControlFlow(map, location, {
  maxBlocks,
  maxInstructions,
  maxBytes,
  maxEdges,
}, backend);
```

A truncated CFG is a successful structured result with `status: "truncated"` and explicit reasons.

- [ ] **Step 7: Update capability metadata**

In `src/index.ts` add both tool names after the existing seven NDS names and update `ndsStaticAnalysisPolicy` to state that bounded ARM/Thumb disassembly and direct-control-flow analysis are read-only, NDS-mapped, and do not infer runtime overlay state or mutate ROMs.

- [ ] **Step 8: Run MCP and full static-analysis tests**

Run:

```bash
node --test --import tsx tests/nds-tools.test.ts tests/nds-control-flow.test.ts tests/nds-disassembly.test.ts tests/nds-disassembly-source.test.ts tests/disassembly-backend.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/tools/nds.ts tests/nds-tools.test.ts src/index.ts
git commit -m "feat: expose NDS static disassembly tools"
```

---

### Task 6: Prove the Capstone WASM backend survives self-contained packaging

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `.github/workflows/package.yml`
- Test indirectly: package workflow plus local `npm run build && node scripts/check-install.mjs .`

**Interfaces:**
- Consumes packaged `dist/services/disassembly/capstone.js`, production `node_modules/@alexaltea/capstone-js/dist/capstone.js`, and `capstone.wasm`.
- Produces a package-install contract that fails if either WASM loading or known ARM/Thumb decoding fails in the isolated production bundle.

- [ ] **Step 1: Make install verification fail until Capstone assets and smoke decoding are checked**

Extend the `required` list in `scripts/check-install.mjs`:

```js
"node_modules/@alexaltea/capstone-js/package.json",
"node_modules/@alexaltea/capstone-js/dist/capstone.js",
"node_modules/@alexaltea/capstone-js/dist/capstone.wasm",
```

Then add, after the Node-version check:

```js
const { createCapstoneArmBackend } = await import(
  new URL("./dist/services/disassembly/capstone.js", `file://${root.replaceAll("\\", "/")}/`).href
);
const backend = await createCapstoneArmBackend();
try {
  const arm = backend.decodeOne(Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]), 0x02000000, "arm");
  const thumb = backend.decodeOne(Uint8Array.from([0x70, 0x47]), 0x02000010, "thumb");
  if (arm?.mnemonic !== "bx" || arm.size !== 4) {
    throw new Error("Packaged Capstone ARM smoke decode failed");
  }
  if (thumb?.mnemonic !== "bx" || thumb.size !== 2) {
    throw new Error("Packaged Capstone Thumb smoke decode failed");
  }
} finally {
  backend.close();
}
```

Prefer `pathToFileURL(path.join(root, "dist/services/disassembly/capstone.js"))` from `node:url` over hand-building the URL when implementing; the required behavior is an import from the supplied install root, not the source checkout.

- [ ] **Step 2: Run source-root check to expose any path assumptions**

Run:

```bash
npm run build
node scripts/check-install.mjs .
```

Expected before the script/path adjustments are correct: FAIL if it imports from the wrong location or cannot locate WASM. After the minimal fix: PASS and print the existing `{ ok: true, ... }` JSON only after both decodes succeed.

- [ ] **Step 3: Make package workflow expose decoder smoke verification explicitly**

Keep the existing isolated `npm install --omit=dev --ignore-scripts` inside `/tmp/re-mcp-${version}`. Rename that portion of `.github/workflows/package.yml` or split it so the log has an explicit step/command showing:

```bash
node scripts/check-install.mjs .
```

executed from the assembled bundle after production dependency installation. Do not add network fetches after production installation and do not copy Capstone artifacts manually from the source checkout; they must arrive through the pinned production dependency.

- [ ] **Step 4: Reproduce the package assembly locally**

Run:

```bash
set -euo pipefail
npm install
npm run check
npm run build
version="$(node -p "require('./package.json').version")"
root="/tmp/re-mcp-${version}-disassembly-smoke"
rm -rf "$root"
mkdir -p "$root/dist"
cp package.json README.md mcp-config.example.json "$root/"
cp -R scripts "$root/"
cp -R dist/src/. "$root/dist/"
(
  cd "$root"
  npm install --omit=dev --ignore-scripts
  node scripts/check-install.mjs .
)
```

Expected: PASS; production bundle initializes WebAssembly and decodes ARM + Thumb without an external executable.

- [ ] **Step 5: Commit**

```bash
git add scripts/check-install.mjs .github/workflows/package.yml
git commit -m "test: verify packaged Capstone WASM decoder"
```

---

### Task 7: Document the static-disassembly workflow and run final regression

**Files:**
- Modify: `README.md`
- Test: all `tests/*.test.ts`
- Verify: `package.json`, `.github/workflows/package.yml`, `src/index.ts`

**Interfaces:**
- Consumes all previous tasks.
- Produces user-facing documentation matching the implemented two-tool contract and a fully verified branch suitable for PR review.

- [ ] **Step 1: Add README documentation matching the implemented contract**

Document this sequence:

```text
nds_inspect_rom
  -> nds_list_overlays / address resolvers as needed
  -> nds_disassemble_range
  -> nds_analyze_control_flow
```

State explicitly:

- `arm`, `thumb`, and conservative `auto` are accepted;
- initial `auto` only trusts ARM9/ARM7 header entry points;
- direct CFG edges propagate proven ARM/Thumb mode;
- ambiguity is returned, not guessed;
- `overlayId` disambiguates a static source but never means the overlay is loaded;
- BSS has no ROM bytes;
- compressed overlays are rejected until a separate decompression milestone;
- linear limits are 32/256 instructions and 128/1024 bytes default/max;
- CFG limits are 64/256 blocks, 512/4096 instructions, 2/16 KiB bytes, and 128/1024 edges default/max;
- calls are annotated but not traversed;
- indirect targets are never guessed;
- `truncated` CFG output is partial and names the exhausted limits;
- static disassembly is independent of pending physical Catalina/DeSmuME acceptance;
- no generic binary disassembly, ROM mutation, rebuild, or patch generation is added.

- [ ] **Step 2: Run focused disassembly suite**

Run:

```bash
node --test --import tsx \
  tests/disassembly-backend.test.ts \
  tests/nds-disassembly-source.test.ts \
  tests/nds-disassembly.test.ts \
  tests/nds-control-flow.test.ts \
  tests/nds-tools.test.ts
```

Expected: PASS.

- [ ] **Step 3: Run complete quality suite**

Run:

```bash
npm run check
npm run build
```

Expected: typecheck PASS, all tests PASS, build PASS.

- [ ] **Step 4: Run production-install smoke check again**

Run the same isolated bundle sequence from Task 6. Expected: `scripts/check-install.mjs` reports `ok: true` only after ARM and Thumb fixture decoding succeeds.

- [ ] **Step 5: Audit public/security surface**

Run:

```bash
grep -R "nds_disassemble_range\|nds_analyze_control_flow" -n src README.md tests
grep -R "baseAddress\|caller-controlled\|generic binary" -n src/services/nds src/tools/nds.ts README.md || true
```

Manually verify:

- exactly nine NDS tools are registered total, exactly two of them new;
- neither new schema accepts a generic binary path, bytes, base address, raw range, or output path;
- no DeSmuME GDB transport/controller/runtime files changed;
- no ROM write/rebuild capability was introduced;
- no static result claims an overlay is loaded;
- package dependency is exactly `5.0.9`.

- [ ] **Step 6: Commit documentation**

```bash
git add README.md
git commit -m "docs: document NDS static disassembly"
```

- [ ] **Step 7: Final branch verification before PR**

Run:

```bash
git status --short
git log --oneline --decorate -8
npm run check
npm run build
```

Expected: clean worktree, all verification PASS. Push the implementation branch and use GitHub Actions CI + Package as the authoritative remote regression gate. Do not claim Catalina/DeSmuME native acceptance from these jobs.

---

## Recommended Review / PR Boundaries

Keep reviewer scope small while preserving runnable increments:

1. **PR A — Decoder + NDS linear disassembly:** Tasks 1–3. Proves the pinned WASM backend, canonical source policy, and bounded linear output.
2. **PR B — Direct CFG analysis:** Task 4. Adds only basic-block traversal on top of the already reviewed canonical decoder/source layer.
3. **PR C — MCP surface + packaging + docs:** Tasks 5–7. Adds the two public tools, isolated package smoke acceptance, capability metadata, and README.

Each PR must pass `npm run check` and `npm run build`; PR C must additionally pass the Package workflow's isolated production/WASM smoke check before merge.
