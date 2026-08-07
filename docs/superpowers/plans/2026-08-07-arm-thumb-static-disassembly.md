# ARM/Thumb Static Disassembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded, read-only Nintendo DS ARM/Thumb linear disassembly and direct-control-flow analysis backed by `@alexaltea/capstone-js` 5.0.9 while preserving RE-MCP's canonical NDS mapping, ambiguity, and packaging guarantees.

**Architecture:** Keep Capstone behind one narrow RE-MCP-owned decoder interface. Build a separate NDS code-source policy layer over the existing canonical resolver, normalize decoder output into canonical instructions, then reuse that instruction normalizer for both bounded linear decoding and a FIFO basic-block worklist. All code bytes come from uniquely mapped ARM9/ARM7 main code or uncompressed overlays in the validated `.nds`; calls are annotated but not traversed, indirect targets are never guessed, and compressed overlays/BSS remain non-decodable.

**Tech Stack:** TypeScript ES2022 + NodeNext, Node.js >=20, `node:test`, Zod, existing RE-MCP NDS parser/resolver, `@alexaltea/capstone-js` 5.0.9, GitHub Actions package workflow.

## Global Constraints

- Pin `@alexaltea/capstone-js` exactly at `5.0.9`.
- Node.js runtime floor remains `>=20`; CI/package verification continues on Node 20.
- Public tools added by this milestone are exactly `nds_disassemble_range` and `nds_analyze_control_flow`.
- No generic binary path, caller-provided bytes, arbitrary base address, arbitrary raw byte-range extraction, or caller-controlled output path.
- Decode sources are ARM9 main, ARM7 main, uncompressed ARM9 overlays, and uncompressed ARM7 overlays only.
- Compressed overlays return `compressed-overlay-not-decodable`; do not decompress or decode stored compressed bytes.
- BSS returns `runtime-only-bss`; it has no ROM source bytes.
- Ambiguous mappings return `ambiguous-code-source`; never infer runtime overlay loaded state.
- Initial `auto` mode succeeds only when the resolved runtime address equals the matching ARM9/ARM7 header entry point, which is an ARM seed. CFG-propagated mode comes only from a deterministic decoded edge.
- ARM starts require 4-byte alignment; Thumb starts require 2-byte alignment. Never round or silently adjust.
- Linear limits: instructions default/max `32/256`; source bytes default/max `128/1024`.
- CFG limits: blocks default/max `64/256`; total instructions `512/4096`; total bytes `2048/16384`; traversal edges `128/1024`.
- CFG follows deterministic non-call direct branches and conditional fall-through. Direct calls are annotated but not traversed. Indirect branch/call targets are never guessed.
- Cross-component traversal is same-processor only and requires a unique, uncompressed, file-backed target with proven mode.
- ROM SHA-256 identity is checked immediately before and after each top-level static disassembly operation.
- WebAssembly/decoder initialization failures are operational `disassembly-backend-failure` errors, not malformed-ROM results.
- The assembled production bundle must initialize Capstone.js and decode known ARM and Thumb fixtures without runtime network access or an external disassembler.
- Physical Catalina/DeSmuME dynamic-debugging acceptance remains separate and is not claimed by this milestone.

---

## File Map

### New files

- `src/types/alexaltea-capstone-js.d.ts` — minimal declaration of only the Capstone.js 5.0.9 API used by RE-MCP.
- `src/services/disassembly/backend.ts` — RE-MCP-owned ARM decoder types and backend error.
- `src/services/disassembly/capstone.ts` — sole production import of `@alexaltea/capstone-js`; WASM loader + ARM/Thumb adapter.
- `src/services/nds/disassembly-source.ts` — deterministic NDS code-source resolution, mode/alignment policy, exact file-backed ranges, and SHA-validated reads.
- `src/services/nds/disassembly.ts` — canonical instruction model, semantic control-flow normalization, target annotation, bounded linear decoding.
- `src/services/nds/control-flow.ts` — bounded FIFO basic-block traversal.
- `tests/disassembly-backend.test.ts` — real Capstone adapter tests.
- `tests/nds-disassembly-source.test.ts` — NDS source/mode/identity tests.
- `tests/nds-disassembly.test.ts` — canonical instruction + linear decoding tests.
- `tests/nds-control-flow.test.ts` — CFG traversal tests.

### Existing files modified

- `package.json`, `package-lock.json` — exact Capstone.js production dependency.
- `src/tools/nds.ts` — two schemas/handlers and backend-error mapping.
- `tests/nds-tools.test.ts` — registration/schema/security/handler tests.
- `src/index.ts` — capability names and static-analysis policy.
- `scripts/check-install.mjs` — packaged Capstone asset + ARM/Thumb smoke verification.
- `.github/workflows/package.yml` — explicit isolated decoder smoke acceptance.
- `README.md` — user-facing workflow and limits.

---

### Task 1: Pin Capstone.js and establish the decoder adapter

**Files:**
- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `src/types/alexaltea-capstone-js.d.ts`
- Create: `src/services/disassembly/backend.ts`
- Create: `src/services/disassembly/capstone.ts`
- Create/Test: `tests/disassembly-backend.test.ts`

**Interfaces:**

Produces:

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
  constructor(message: string, readonly causeValue?: unknown);
}

export async function createCapstoneArmBackend(): Promise<ArmDisassemblyBackend>;
```

- [ ] **Step 1: Install the exact production dependency**

Run:

```bash
npm install --save-exact @alexaltea/capstone-js@5.0.9
```

Expected: `package.json` contains exactly `"@alexaltea/capstone-js": "5.0.9"`; lockfile records the same version.

- [ ] **Step 2: Write the failing real-backend tests**

Create `tests/disassembly-backend.test.ts`:

```ts
import assert from "node:assert/strict";
import test from "node:test";

import { createCapstoneArmBackend } from "../src/services/disassembly/capstone.js";

test("Capstone adapter decodes known ARM and Thumb instructions", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    const arm = backend.decodeOne(
      Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]), // ARM: bx lr
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
      Uint8Array.from([0x70, 0x47]), // Thumb: bx lr
      0x02000010,
      "thumb",
    );
    assert.ok(thumb);
    assert.equal(thumb.address, 0x02000010);
    assert.equal(thumb.size, 2);
    assert.deepEqual(thumb.bytes, [0x70, 0x47]);
    assert.equal(thumb.mnemonic, "bx");
    assert.equal(thumb.operandsText, "lr");
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

- [ ] **Step 3: Run the tests to prove RED**

Run:

```bash
node --test --import tsx tests/disassembly-backend.test.ts
```

Expected: FAIL because `src/services/disassembly/capstone.ts` does not exist.

- [ ] **Step 4: Add the local Capstone.js declaration and backend-owned types**

Create `src/types/alexaltea-capstone-js.d.ts`:

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

Create `src/services/disassembly/backend.ts` with the interfaces above plus:

```ts
export class DisassemblyBackendError extends Error {
  readonly category = "disassembly-backend-failure" as const;

  constructor(message: string, readonly causeValue?: unknown) {
    super(message);
    this.name = "DisassemblyBackendError";
  }
}
```

- [ ] **Step 5: Implement the Capstone adapter**

Create `src/services/disassembly/capstone.ts` using the 5.0.9 default factory, detail mode, and `disasm_iter()`:

```ts
import type {
  CapstoneFactory,
  CapstoneHandle,
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
      .then(async (loaded) => await (loaded.default as CapstoneFactory)())
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
  decoder: CapstoneHandle,
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
  decoder: CapstoneHandle,
  instruction: CapstoneInstruction,
): DecodedArmInstruction {
  if (instruction.size !== 2 && instruction.size !== 4) {
    throw new DisassemblyBackendError(`Unexpected ARM instruction size ${instruction.size}`);
  }
  const cc = instruction.detail.cc;
  return {
    address: instruction.address >>> 0,
    size: instruction.size,
    bytes: [...instruction.bytes],
    mnemonic: instruction.mnemonic,
    operandsText: instruction.op_str,
    operands: (instruction.detail.op ?? []).map((operand) => normalizeOperand(cs, decoder, operand)),
    isJump: hasGroup(instruction, cs.GRP_JUMP),
    isCall: hasGroup(instruction, cs.GRP_CALL),
    isReturn: hasGroup(instruction, cs.GRP_RET),
    isConditional:
      instruction.id === cs.ARM_INS_CBZ
      || instruction.id === cs.ARM_INS_CBNZ
      || (cc !== undefined && cc !== cs.ARM_CC_INVALID && cc !== cs.ARM_CC_AL),
    switchesMode: instruction.id === cs.ARM_INS_BLX,
  };
}

export async function createCapstoneArmBackend(): Promise<ArmDisassemblyBackend> {
  const cs = await loadCapstone();
  let arm: CapstoneHandle | undefined;
  let thumb: CapstoneHandle | undefined;
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

  const armDecoder = arm;
  const thumbDecoder = thumb;
  return {
    decodeOne(bytes: Uint8Array, address: number, mode: ArmMode) {
      const decoder = mode === "arm" ? armDecoder : thumbDecoder;
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
        armDecoder.close();
        thumbDecoder.close();
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

- [ ] **Step 6: Verify adapter + typecheck**

Run:

```bash
node --test --import tsx tests/disassembly-backend.test.ts
npm run typecheck
```

Expected: PASS. Any mismatch between the local declaration and actual 5.0.9 runtime API is a Task 1 failure and must be corrected inside `alexaltea-capstone-js.d.ts` / `capstone.ts` before continuing; later layers must not depend directly on package-specific types.

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
- Reuse unchanged: `src/services/nds/resolver.ts`, `src/services/nds/rom-map.ts`, `src/services/nds/io.ts`, `src/services/nds/overlays.ts`

**Interfaces:**

Produces:

```ts
export type NdsDisassemblyMode = ArmMode | "auto";

export interface NdsDisassemblyLocation {
  readonly processor: NdsProcessor;
  readonly mode: NdsDisassemblyMode;
  readonly runtimeAddress?: number;
  readonly romOffset?: number;
  readonly overlayId?: number;
}

export interface NdsCodeSourceCandidate {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number | null;
  readonly romOffset: number | null;
  readonly runtimeStart: number;
  readonly runtimeEnd: number;
  readonly romStart: number;
  readonly romEnd: number;
  readonly compressed: boolean;
  readonly bss: boolean;
}

export interface NdsCodeSource {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number;
  readonly romOffset: number;
  readonly runtimeStart: number;
  readonly runtimeEnd: number;
  readonly romStart: number;
  readonly romEnd: number;
  readonly mode: ArmMode;
}

export type NdsCodeSourceResolution =
  | { readonly status: "resolved"; readonly source: NdsCodeSource }
  | { readonly status: "ambiguous-code-source"; readonly candidates: readonly NdsCodeSourceCandidate[] }
  | { readonly status: "compressed-overlay-not-decodable"; readonly candidate: NdsCodeSourceCandidate }
  | { readonly status: "runtime-only-bss"; readonly candidate: NdsCodeSourceCandidate }
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

export function codeSourceAt(source: NdsCodeSource, runtimeAddress: number): NdsCodeSource;

export async function withValidatedNdsRomReader<T>(
  map: NdsRomMap,
  callback: (
    read: (source: NdsCodeSource, maxBytes: number) => Promise<Buffer>,
  ) => Promise<T>,
): Promise<T>;
```

- [ ] **Step 1: Write failing source-policy tests**

Create `tests/nds-disassembly-source.test.ts`. At minimum include these concrete tests:

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
```

Add overlapping overlays:

```ts
test("preserves overlap ambiguity unless overlayId selects one static source", async () => {
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

Also cover: ARM7 main, explicit ARM and Thumb, bad ARM/Thumb alignment, compressed overlay, BSS, uncompressed overlay with `romSize < ramSize`, ROM offset matching the wrong processor, ambiguous ROM offset, SHA mismatch before callback, SHA mutation during callback, and `codeSourceAt()` bounds.

Add this regression for the self-review issue that must not be reintroduced:

```ts
test("a backward branch inside the selected overlapping overlay preserves that overlay identity", async () => {
  // Build overlapping overlays 7 and 8 covering 0x02200000..0x02200080.
  // Resolve entry 0x02200040 with overlayId 7, then target 0x02200010.
  const target = resolveNdsControlFlowTarget(map, sourceForOverlay7, 0x02200010, "arm");
  assert.equal(target.status, "resolved");
  if (target.status === "resolved") assert.equal(target.source.overlayId, 7);
});
```

- [ ] **Step 2: Run source tests to prove RED**

Run:

```bash
node --test --import tsx tests/nds-disassembly-source.test.ts
```

Expected: FAIL because `disassembly-source.ts` does not exist.

- [ ] **Step 3: Implement candidate construction and exactly-one-location validation**

Use existing `resolveRuntimeAddress()` / `resolveRomOffset()` as the structural truth. Do not duplicate header/FAT/overlay parsing.

Use:

```ts
function requireOneLocation(location: NdsDisassemblyLocation): "runtime" | "rom" {
  const hasRuntime = location.runtimeAddress !== undefined;
  const hasRom = location.romOffset !== undefined;
  if (hasRuntime === hasRom) {
    throw new NdsError(
      "range-out-of-bounds",
      "Disassembly requires exactly one of runtimeAddress or romOffset",
    );
  }
  return hasRuntime ? "runtime" : "rom";
}
```

For main code candidate ranges:

```ts
runtimeStart = executable.ramAddress;
runtimeEnd = executable.ramEnd;
romStart = executable.romOffset;
romEnd = executable.romEnd;
```

For an uncompressed overlay, only file-backed initialized bytes are eligible:

```ts
const fileBackedSize = Math.min(overlay.ramSize, overlay.romSize);
runtimeStart = overlay.ramAddress;
runtimeEnd = overlay.ramAddress + fileBackedSize;
romStart = overlay.romOffset;
romEnd = overlay.romOffset + fileBackedSize;
```

A compressed overlay candidate retains its backing metadata but never becomes `resolved`.

- [ ] **Step 4: Resolve runtime/ROM location first, then resolve mode**

The ordering is mandatory:

1. resolve runtime or ROM selector into one canonical code candidate/runtime address;
2. apply `overlayId` only as a static candidate filter;
3. reject ambiguous/compressed/BSS/unmapped conditions;
4. only then resolve `arm`/`thumb`/`auto` against the resolved runtime address;
5. enforce alignment for the resolved mode.

Use:

```ts
function resolveMode(
  map: NdsRomMap,
  processor: NdsProcessor,
  resolvedRuntimeAddress: number,
  requested: NdsDisassemblyMode,
): ArmMode | null {
  if (requested !== "auto") return requested;
  const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
  return resolvedRuntimeAddress === executable.entryAddress ? "arm" : null;
}

function requireAlignment(address: number, mode: ArmMode): void {
  const alignment = mode === "arm" ? 4 : 2;
  if (address % alignment !== 0) {
    throw new NdsError(
      "range-out-of-bounds",
      `${mode.toUpperCase()} disassembly address must be ${alignment}-byte aligned`,
    );
  }
}
```

Do not compare a raw ROM offset to a runtime entry address.

- [ ] **Step 5: Implement same-component target preservation correctly**

`NdsCodeSource.runtimeStart/runtimeEnd` describe the full file-backed range of its chosen component, not merely the original request window.

Implement:

```ts
export function codeSourceAt(source: NdsCodeSource, runtimeAddress: number): NdsCodeSource {
  if (runtimeAddress < source.runtimeStart || runtimeAddress >= source.runtimeEnd) {
    throw new NdsError("range-out-of-bounds", "Runtime address lies outside the selected code source");
  }
  const relative = runtimeAddress - source.runtimeStart;
  return {
    ...source,
    runtimeAddress,
    romOffset: source.romStart + relative,
  };
}
```

`resolveNdsControlFlowTarget()` must first test whether `runtimeAddress` lies inside `current.runtimeStart <= target < current.runtimeEnd`. If yes, preserve `current.component` and `current.overlayId` with `codeSourceAt(current, target)` even if another static overlay overlaps that address. This is deterministic continuation within the caller-selected static source and is **not** a loaded-overlay claim.

If the target is outside the current component's full file-backed range, call normal runtime resolution with no overlay hint. Cross-component overlap must remain ambiguous.

- [ ] **Step 6: Implement SHA-validated bounded ROM reads**

Use `open` from `node:fs/promises`, existing `hashFileSha256`, and `readExact`:

```ts
export async function withValidatedNdsRomReader<T>(
  map: NdsRomMap,
  callback: (
    read: (source: NdsCodeSource, maxBytes: number) => Promise<Buffer>,
  ) => Promise<T>,
): Promise<T> {
  if (await hashFileSha256(map.romPath) !== map.sha256) {
    throw new NdsError("invalid-rom", "Source ROM no longer matches the canonical map identity");
  }

  const handle = await open(map.romPath, "r");
  let result: T;
  try {
    result = await callback(async (source, maxBytes) => {
      if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
        throw new NdsError("range-out-of-bounds", "Disassembly read size is invalid");
      }
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

- [ ] **Step 7: Run source + resolver regression**

Run:

```bash
node --test --import tsx tests/nds-disassembly-source.test.ts tests/nds-resolver.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/services/nds/disassembly-source.ts tests/nds-disassembly-source.test.ts
git commit -m "feat: resolve NDS disassembly sources"
```

---

### Task 3: Build canonical instruction semantics and bounded linear disassembly

**Files:**
- Create: `src/services/nds/disassembly.ts`
- Create/Test: `tests/nds-disassembly.test.ts`

**Interfaces:**

Produces:

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

export function decodeNdsInstruction(
  map: NdsRomMap,
  source: NdsCodeSource,
  bytes: Uint8Array,
  backend: ArmDisassemblyBackend,
): StaticInstruction | null;

export async function disassembleNdsRange(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  options: LinearDisassemblyOptions,
  backend: ArmDisassemblyBackend,
): Promise<LinearDisassemblyResult>;
```

Task 4 consumes `decodeNdsInstruction()` exactly; do not create a second CFG-specific instruction classifier.

- [ ] **Step 1: Write failing flow-normalization tests with a fake backend**

Create `tests/nds-disassembly.test.ts`:

```ts
class FakeBackend implements ArmDisassemblyBackend {
  constructor(private readonly decoded: ReadonlyMap<number, DecodedArmInstruction | null>) {}
  decodeOne(_bytes: Uint8Array, address: number): DecodedArmInstruction | null {
    return this.decoded.get(address) ?? null;
  }
  close(): void {}
}
```

Use explicit `DecodedArmInstruction` fixtures for: fall-through, conditional direct branch, unconditional direct branch, direct call, indirect call, indirect branch, return, mode-preserving target, and mode-switching immediate target.

Example direct call:

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

Assert `kind === "call"`, direct target `0x02000008`, target mode `arm`, and fall-through `0x02000004`.

- [ ] **Step 2: Run linear tests to prove RED**

Run:

```bash
node --test --import tsx tests/nds-disassembly.test.ts
```

Expected: FAIL because `src/services/nds/disassembly.ts` does not exist.

- [ ] **Step 3: Implement one canonical instruction normalizer**

Use typed operands for targets, never parse target addresses from `operandsText`:

```ts
function firstImmediate(decoded: DecodedArmInstruction): number | null {
  for (const operand of decoded.operands) {
    if (operand.kind === "immediate") return operand.value >>> 0;
  }
  return null;
}

function isLinkRegisterReturn(decoded: DecodedArmInstruction): boolean {
  return decoded.mnemonic.toLowerCase() === "bx"
    && decoded.operands.some(
      (operand) => operand.kind === "register" && operand.name === "lr",
    );
}

function opposite(mode: ArmMode): ArmMode {
  return mode === "arm" ? "thumb" : "arm";
}

function normalizeFlow(
  decoded: DecodedArmInstruction,
  mode: ArmMode,
): StaticInstruction["flow"] {
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

`decodeNdsInstruction()` must:

1. call `backend.decodeOne(bytes, source.runtimeAddress, source.mode)`;
2. return `null` if the backend decodes nothing;
3. reject an instruction whose reported size would exceed `source.romEnd`;
4. normalize bytes to lowercase two-digit hex;
5. call `resolveNdsControlFlowTarget()` for a direct target with known target mode;
6. populate the canonical `source` identity.

- [ ] **Step 4: Implement bounded linear decoding with one SHA lifecycle**

`disassembleNdsRange()` sequence:

```ts
const resolved = resolveNdsCodeSource(map, location);
if (resolved.status !== "resolved") return resolved;

return await withValidatedNdsRomReader(map, async (read) => {
  const bytes = await read(resolved.source, options.maxBytes);
  const instructions: StaticInstruction[] = [];
  let cursor = 0;

  while (instructions.length < options.maxInstructions && cursor < bytes.length) {
    const source = codeSourceAt(resolved.source, resolved.source.runtimeAddress + cursor);
    const instruction = decodeNdsInstruction(map, source, bytes.subarray(cursor), backend);
    if (instruction === null) {
      return {
        status: "decode-stopped" as const,
        source: resolved.source,
        instructions,
        decodedBytes: cursor,
        stopAddress: source.runtimeAddress,
      };
    }
    if (cursor + instruction.size > bytes.length || source.romOffset + instruction.size > source.romEnd) {
      return {
        status: "component-boundary" as const,
        source: resolved.source,
        instructions,
        decodedBytes: cursor,
        stopAddress: source.runtimeAddress,
      };
    }
    instructions.push(instruction);
    cursor += instruction.size;
  }

  const atBoundary = resolved.source.romOffset + cursor >= resolved.source.romEnd;
  return {
    status: atBoundary ? "component-boundary" as const : "complete" as const,
    source: resolved.source,
    instructions,
    decodedBytes: cursor,
    stopAddress: (resolved.source.runtimeAddress + cursor) >>> 0,
  };
});
```

The `complete` status means the requested bounded window completed; it does not claim a function or component is fully decoded.

- [ ] **Step 5: Add real Capstone + NDS integration tests**

Create an ARM9 fixture containing ARM `BX LR` at its header entry and assert exact runtime address, ROM offset, `1eff2fe1`, mnemonic, `arm`, main source, and `return` flow.

Create a second fixture with Thumb `BX LR` at a 2-byte-aligned explicit Thumb address and assert `7047`, `thumb`, and `return` flow.

Add decode-stop and component-boundary tests.

- [ ] **Step 6: Run adapter/source/linear tests**

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
- Reuse: `decodeNdsInstruction()` from Task 3 and the source-reader helpers from Task 2.

**Interfaces:**

Produces:

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
  readonly stopReason:
    | "branch"
    | "return"
    | "indirect"
    | "decode-stopped"
    | "component-boundary"
    | "limit";
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
  readonly kind:
    | "indirect-branch"
    | "indirect-call"
    | "return"
    | "ambiguous-code-source"
    | "compressed-overlay-not-decodable"
    | "runtime-only-bss"
    | "unmapped-address";
}

export interface StaticControlFlowGraph {
  readonly entry: NdsCodeSource;
  readonly status: "complete" | "truncated";
  readonly truncationReasons: readonly (
    | "block-limit"
    | "instruction-limit"
    | "byte-limit"
    | "edge-limit"
  )[];
  readonly blocks: readonly StaticBasicBlock[];
  readonly edges: readonly StaticControlFlowEdge[];
  readonly calls: readonly StaticCallEdge[];
  readonly unresolvedEdges: readonly StaticUnresolvedEdge[];
  readonly totals: {
    readonly blocks: number;
    readonly instructions: number;
    readonly bytes: number;
    readonly edges: number;
  };
}

export async function analyzeNdsControlFlow(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  limits: ControlFlowLimits,
  backend: ArmDisassemblyBackend,
): Promise<NdsCodeSourceResolution | StaticControlFlowGraph>;
```

- [ ] **Step 1: Write failing CFG tests**

Create `tests/nds-control-flow.test.ts` with deterministic fake-backend graphs covering all of these:

1. conditional branch creates taken and fall-through blocks;
2. unconditional branch creates only its branch target;
3. direct call is added to `calls`, callee is not queued, and decoding continues at call fall-through in the same block;
4. indirect call is recorded and decoding continues at fall-through;
5. indirect branch terminates the block;
6. return terminates the block;
7. a cycle discovers each block once;
8. a backward branch inside a selected overlapping overlay preserves that overlay identity;
9. a unique cross-component same-processor branch is traversed;
10. ambiguous/compressed/BSS/unmapped branch targets are recorded and not queued;
11. a deterministic mode-switching immediate edge queues the opposite mode;
12. block limit returns only `block-limit`;
13. instruction limit returns only `instruction-limit`;
14. byte limit returns only `byte-limit`;
15. edge limit returns only `edge-limit`;
16. simultaneous caps yield a deduplicated fixed-order reason list;
17. decode failure terminates only its block while already queued blocks continue.

Use the exact identity function:

```ts
function blockKey(source: NdsCodeSource): string {
  return [
    source.processor,
    source.component,
    source.overlayId ?? "main",
    source.runtimeAddress.toString(16),
    source.mode,
  ].join(":");
}
```

- [ ] **Step 2: Run CFG tests to prove RED**

Run:

```bash
node --test --import tsx tests/nds-control-flow.test.ts
```

Expected: FAIL because `control-flow.ts` does not exist.

- [ ] **Step 3: Implement FIFO worklist and one-reader lifecycle**

Resolve the entry once. If unresolved, return the structured source result. Otherwise wrap the entire traversal in one `withValidatedNdsRomReader()` call.

Use:

```ts
const queue: NdsCodeSource[] = [entry];
const queued = new Set<string>([blockKey(entry)]);
const visited = new Set<string>();
```

For each dequeued source:

- skip if already visited;
- refuse to create another block when `blocks.length >= maxBlocks`, add `block-limit`;
- read at most the bytes still available under both source boundary and global byte budget;
- decode sequentially with **Task 3's `decodeNdsInstruction()`**;
- increment global instruction/byte counters only after accepting an instruction;
- keep calls inside the current block and continue to their fall-through;
- terminate blocks on conditional branch, unconditional branch, indirect branch, return, decode stop, component boundary, or a global limit.

- [ ] **Step 4: Implement branch/call edge policy exactly**

For `call`:

```ts
calls.push({
  fromBlockId,
  instructionAddress: instruction.address,
  targetAddress: instruction.flow.directTarget,
  targetMode: instruction.flow.targetMode,
  resolution: instruction.targetResolution,
});
```

Do **not** enqueue the call target. Continue at `instruction.flow.fallthrough` in the same block.

For `indirect-call`, record both a `calls` entry with null target and an `unresolvedEdges` entry of `indirect-call`; continue at fall-through.

For conditional branch, terminate the block and attempt two edges: `conditional-taken` and `conditional-fallthrough`.

For unconditional branch, terminate and attempt one `branch` edge.

For indirect branch/return, terminate and add the corresponding unresolved/terminal event.

A target source resolution with `status: "resolved"` may be queued. Any other static status is recorded in `unresolvedEdges`; it is never guessed through.

- [ ] **Step 5: Enforce all four caps before growth**

Maintain:

```ts
let totalInstructions = 0;
let totalBytes = 0;
let totalEdges = 0;
const reasons = new Set<
  "block-limit" | "instruction-limit" | "byte-limit" | "edge-limit"
>();
```

Rules:

- never append instruction `N+1` when it would exceed `maxInstructions`;
- never read/accept bytes that would exceed `maxBytes`;
- never append edge `N+1` when it would exceed `maxEdges`;
- never append block `N+1` when it would exceed `maxBlocks`;
- each refused growth adds exactly its corresponding reason;
- no counter may exceed the configured cap.

Final reason order is always:

```ts
["block-limit", "instruction-limit", "byte-limit", "edge-limit"]
```

filtered to reasons present. Final status is `complete` only when no reason was recorded.

- [ ] **Step 6: Run CFG + linear regression**

Run:

```bash
node --test --import tsx tests/nds-control-flow.test.ts tests/nds-disassembly.test.ts tests/nds-disassembly-source.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/control-flow.ts tests/nds-control-flow.test.ts
git commit -m "feat: add bounded NDS control flow analysis"
```

---

### Task 5: Expose exactly two bounded NDS disassembly MCP tools

**Files:**
- Modify: `src/tools/nds.ts`
- Modify/Test: `tests/nds-tools.test.ts`
- Modify: `src/index.ts`

**Interfaces:**

Public tools added:

1. `nds_disassemble_range`
2. `nds_analyze_control_flow`

- [ ] **Step 1: Extend failing registration/schema tests**

Update `EXPECTED_TOOLS` in `tests/nds-tools.test.ts` to exactly nine total NDS tools and rename the existing test to:

```ts
test("registers exactly the nine approved NDS static-analysis tools", () => {
  const server = register("/workspace");
  assert.deepEqual([...server.tools.keys()].sort(), [...EXPECTED_TOOLS].sort());
});
```

Add default assertions:

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

Assert rejection above each approved maximum.

Assert both schemas lack these fields:

```ts
for (const forbidden of ["binary", "bytes", "baseAddress", "output", "path", "length"]) {
  assert.equal(Object.hasOwn(server.schema("nds_disassemble_range"), forbidden), false);
  assert.equal(Object.hasOwn(server.schema("nds_analyze_control_flow"), forbidden), false);
}
```

`romOffset` and `runtimeAddress` are the only location selectors.

- [ ] **Step 2: Run MCP tests to prove RED**

Run:

```bash
node --test --import tsx tests/nds-tools.test.ts
```

Expected: FAIL because only seven NDS tools exist.

- [ ] **Step 3: Add exact schemas and one-location normalization**

Add to `src/tools/nds.ts`:

```ts
const disassemblyModeSchema = z.enum(["arm", "thumb", "auto"]);
const linearInstructionLimitSchema = z.number().int().min(1).max(256).default(32);
const linearByteLimitSchema = z.number().int().min(2).max(1024).default(128);
const cfgBlockLimitSchema = z.number().int().min(1).max(256).default(64);
const cfgInstructionLimitSchema = z.number().int().min(1).max(4096).default(512);
const cfgByteLimitSchema = z.number().int().min(2).max(16384).default(2048);
const cfgEdgeLimitSchema = z.number().int().min(1).max(1024).default(128);
```

Normalize handler input with:

```ts
function normalizeDisassemblyLocation(input: {
  readonly processor: "arm9" | "arm7";
  readonly mode: "arm" | "thumb" | "auto";
  readonly runtimeAddress?: number;
  readonly romOffset?: number;
  readonly overlayId?: number;
}): NdsDisassemblyLocation {
  const hasRuntime = input.runtimeAddress !== undefined;
  const hasRom = input.romOffset !== undefined;
  if (hasRuntime === hasRom) {
    throw new NdsError(
      "range-out-of-bounds",
      "Disassembly requires exactly one of runtimeAddress or romOffset",
    );
  }
  return {
    processor: input.processor,
    mode: input.mode,
    ...(hasRuntime
      ? { runtimeAddress: input.runtimeAddress! }
      : { romOffset: input.romOffset! }),
    ...(input.overlayId === undefined ? {} : { overlayId: input.overlayId }),
  };
}
```

Add handler tests proving neither/both selectors return a structured `range-out-of-bounds` error.

- [ ] **Step 4: Add backend-aware operational error category**

Use:

```ts
type NdsToolErrorCategory = NdsErrorCategory | "disassembly-backend-failure";
```

Change `correctiveAction` to accept `NdsToolErrorCategory` and add:

```ts
case "disassembly-backend-failure":
  return "Verify the packaged @alexaltea/capstone-js JavaScript/WASM assets and Node.js runtime, then retry the static disassembly request.";
```

Change `ndsErrorResult` category selection to:

```ts
const category: NdsToolErrorCategory = error instanceof DisassemblyBackendError
  ? error.category
  : error instanceof NdsError
    ? error.category
    : fallbackCategory;
```

- [ ] **Step 5: Register `nds_disassemble_range`**

Schema:

```ts
{
  rom: romSchema,
  processor: processorSchema,
  runtimeAddress: uint32Schema.optional(),
  romOffset: uint32Schema.optional(),
  overlayId: uint32Schema.optional(),
  mode: disassemblyModeSchema.default("auto"),
  maxInstructions: linearInstructionLimitSchema,
  maxBytes: linearByteLimitSchema,
}
```

Handler lifecycle:

```ts
const map = await readNdsRomMap(resolveRom(config, rom));
const location = normalizeDisassemblyLocation({
  processor, mode, runtimeAddress, romOffset, overlayId,
});
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

Ambiguity/BSS/compression/mode ambiguity/decode stop/component boundary are successful structured results. Thrown parser/backend failures use `ndsErrorResult`.

- [ ] **Step 6: Register `nds_analyze_control_flow`**

Schema uses the same location/mode fields plus:

```ts
maxBlocks: cfgBlockLimitSchema,
maxInstructions: cfgInstructionLimitSchema,
maxBytes: cfgByteLimitSchema,
maxEdges: cfgEdgeLimitSchema,
```

Handler calls:

```ts
await analyzeNdsControlFlow(
  map,
  location,
  { maxBlocks, maxInstructions, maxBytes, maxEdges },
  backend,
);
```

A `truncated` CFG is `isError: false`.

- [ ] **Step 7: Update `src/index.ts` capability metadata**

Add both tool names immediately after the existing seven NDS static tools. Update `ndsStaticAnalysisPolicy` to state that bounded ARM/Thumb disassembly and direct-control-flow analysis are NDS-mapped, read-only, do not infer overlay loaded state, and do not mutate/rebuild ROMs.

- [ ] **Step 8: Run MCP + static suite**

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

### Task 6: Prove Capstone WASM survives self-contained packaging

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `.github/workflows/package.yml`

**Interfaces:**

Consumes the assembled production tree where `dist/src/.` has already been copied to bundle `dist/`, so the built adapter path is `dist/services/disassembly/capstone.js`.

- [ ] **Step 1: Require Capstone package/WASM assets in install verification**

Extend `required` in `scripts/check-install.mjs` with:

```js
"node_modules/@alexaltea/capstone-js/package.json",
"node_modules/@alexaltea/capstone-js/dist/capstone.js",
"node_modules/@alexaltea/capstone-js/dist/capstone.wasm",
```

Also import:

```js
import { pathToFileURL } from "node:url";
```

- [ ] **Step 2: Add exact packaged decoder smoke test**

After the Node-major check and before printing `{ ok: true }`:

```js
const adapterUrl = pathToFileURL(
  path.join(root, "dist/services/disassembly/capstone.js"),
).href;
const { createCapstoneArmBackend } = await import(adapterUrl);
const backend = await createCapstoneArmBackend();
try {
  const arm = backend.decodeOne(
    Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]),
    0x02000000,
    "arm",
  );
  const thumb = backend.decodeOne(
    Uint8Array.from([0x70, 0x47]),
    0x02000010,
    "thumb",
  );
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

The existing success JSON is printed only after both decodes succeed.

- [ ] **Step 3: Verify source-root install check**

Run:

```bash
npm run build
node scripts/check-install.mjs .
```

Expected: PASS and `ok: true` after both decoder smoke checks.

- [ ] **Step 4: Keep the package workflow isolated and make smoke acceptance explicit**

In `.github/workflows/package.yml`, retain:

```bash
npm install --omit=dev --ignore-scripts
```

inside `/tmp/re-mcp-${version}`. Add a separately visible command/step from that assembled root:

```bash
node scripts/check-install.mjs .
```

Do not copy Capstone assets manually from the source checkout and do not fetch runtime artifacts from the network. Production `npm install` must provide all required JS/WASM files.

- [ ] **Step 5: Reproduce the exact production bundle locally**

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

Expected: PASS; packaged production dependency initializes WebAssembly and decodes both fixtures with no external executable.

- [ ] **Step 6: Commit**

```bash
git add scripts/check-install.mjs .github/workflows/package.yml
git commit -m "test: verify packaged Capstone WASM decoder"
```

---

### Task 7: Document the workflow and run final regression

**Files:**
- Modify: `README.md`
- Verify: all tests, build, package smoke, capability/security surface.

- [ ] **Step 1: Document the user workflow**

Add:

```text
nds_inspect_rom
  -> nds_list_overlays / address resolvers as needed
  -> nds_disassemble_range
  -> nds_analyze_control_flow
```

README must state all of these exact semantics:

- modes are `arm`, `thumb`, conservative `auto`;
- initial `auto` trusts only resolved ARM9/ARM7 header entry points;
- direct CFG edges propagate deterministic target mode;
- ambiguity is returned, never guessed;
- `overlayId` selects a static source but never means it is loaded;
- BSS has no ROM bytes;
- compressed overlays are rejected pending a separate decompression milestone;
- linear limits are 32/256 instructions and 128/1024 bytes default/max;
- CFG limits are 64/256 blocks, 512/4096 instructions, 2/16 KiB bytes, 128/1024 edges default/max;
- calls are annotated but not traversed;
- indirect targets are never guessed;
- `truncated` means a valid partial graph and lists exhausted limits;
- static disassembly is independent of pending physical Catalina/DeSmuME acceptance;
- generic binary disassembly, ROM mutation, rebuild, and patch generation remain out of scope.

- [ ] **Step 2: Run focused static-disassembly suite**

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

- [ ] **Step 4: Repeat the isolated production-install smoke sequence from Task 6**

Run the Task 6 production bundle commands exactly. Expected: `scripts/check-install.mjs` prints `ok: true` only after known ARM and Thumb decodes succeed.

- [ ] **Step 5: Audit the public/security surface**

Run:

```bash
grep -R "nds_disassemble_range\|nds_analyze_control_flow" -n src README.md tests
grep -R "baseAddress\|generic binary" -n src/services/nds src/tools/nds.ts README.md || true
git diff --name-only main...HEAD
```

Verify from the diff:

- exactly nine NDS tools total, exactly two new;
- neither new schema accepts generic binary input, raw caller bytes, arbitrary base address, arbitrary raw range, or output path;
- no DeSmuME GDB transport/controller/runtime source file changed;
- no ROM write/rebuild capability was introduced;
- no static result claims an overlay is loaded;
- `@alexaltea/capstone-js` is exactly `5.0.9`.

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

Expected: clean worktree, all verification PASS. Push the branch and use GitHub Actions CI + Package as the authoritative remote regression gate. These jobs do not constitute physical Catalina/DeSmuME acceptance.

---

## Recommended PR Boundaries

1. **PR A — Decoder + NDS linear disassembly:** Tasks 1–3. Proves the pinned WASM backend, deterministic code-source policy, and bounded canonical linear output.
2. **PR B — Direct CFG analysis:** Task 4. Adds only basic-block traversal over the already reviewed decoder/source layer.
3. **PR C — MCP surface + package acceptance + docs:** Tasks 5–7. Adds the two public tools, isolated packaged WASM smoke check, capability metadata, and README.

Each PR must pass `npm run check` and `npm run build`. PR C must also pass the Package workflow's isolated production/WASM smoke check before merge.
