# ARM/Thumb Static Disassembly Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded, read-only Nintendo DS ARM/Thumb linear disassembly and direct-control-flow analysis backed by `@alexaltea/capstone-js` 5.0.9 while preserving RE-MCP's canonical NDS mapping, ambiguity, and packaging guarantees.

**Architecture:** Capstone is isolated behind one RE-MCP-owned decoder interface. A separate NDS code-source layer resolves only deterministic file-backed ARM9/ARM7 main or uncompressed-overlay bytes, canonical instruction normalization is shared by linear decoding and CFG traversal, and a FIFO CFG worklist follows only deterministic non-call edges. Calls are annotated but not traversed; indirect targets, ambiguous overlays, compressed overlays, and BSS are never guessed through.

**Tech Stack:** TypeScript ES2022/NodeNext, Node.js >=20, Node `node:test`, Zod, existing RE-MCP NDS parser/resolver, `@alexaltea/capstone-js` 5.0.9, GitHub Actions.

## Global Constraints

- Pin `@alexaltea/capstone-js` exactly at `5.0.9`.
- Keep Node.js runtime floor `>=20`; CI/package verification remains Node 20.
- Add exactly two public tools: `nds_disassemble_range` and `nds_analyze_control_flow`.
- No generic binary path, raw caller bytes, arbitrary base address, arbitrary byte-range extraction, or caller-controlled output path.
- Decode only ARM9 main, ARM7 main, uncompressed ARM9 overlays, and uncompressed ARM7 overlays.
- Compressed overlays return `compressed-overlay-not-decodable`; do not decompress or decode compressed storage bytes.
- BSS returns `runtime-only-bss`.
- Ambiguous code mappings return `ambiguous-code-source`; never infer runtime overlay loaded state.
- Initial `auto` mode succeeds only after source resolution proves the runtime address equals the matching ARM9/ARM7 header entry point; that seed is ARM.
- CFG-propagated mode comes only from deterministic decoded control-flow semantics.
- ARM starts/targets require 4-byte alignment; Thumb starts/targets require 2-byte alignment.
- Linear limits: instructions default/max `32/256`; source bytes `128/1024`.
- CFG limits: blocks `64/256`; total instructions `512/4096`; total decoded bytes `2048/16384`; traversal edges `128/1024`.
- CFG follows deterministic direct non-call branches plus conditional fall-through. Direct calls are recorded but not traversed. Indirect targets are never guessed.
- Cross-component branch traversal is same-processor only and requires a unique, uncompressed, file-backed target with proven mode.
- Verify ROM SHA-256 immediately before and after every top-level linear/CFG operation, including operations whose decode callback throws.
- WebAssembly/backend failures are operational `disassembly-backend-failure` errors, not malformed-ROM results.
- The assembled production bundle must initialize Capstone.js and decode known ARM and Thumb fixtures without runtime network access or an external disassembler.
- Physical Catalina/DeSmuME dynamic-debugging acceptance remains a separate unresolved gate.

---

## File Map

**Create**
- `src/types/alexaltea-capstone-js.d.ts` — minimal Capstone.js 5.0.9 declaration.
- `src/services/disassembly/backend.ts` — RE-MCP decoder types/error.
- `src/services/disassembly/capstone.ts` — sole production Capstone.js import and WASM adapter.
- `src/services/nds/disassembly-source.ts` — deterministic NDS source/mode/range/SHA policy.
- `src/services/nds/disassembly.ts` — canonical instruction semantics + linear decoding.
- `src/services/nds/control-flow.ts` — bounded CFG traversal.
- `tests/disassembly-backend.test.ts`
- `tests/nds-disassembly-source.test.ts`
- `tests/nds-disassembly.test.ts`
- `tests/nds-control-flow.test.ts`

**Modify**
- `package.json`, `package-lock.json`
- `src/tools/nds.ts`
- `tests/nds-tools.test.ts`
- `src/index.ts`
- `scripts/check-install.mjs`
- `.github/workflows/package.yml`
- `README.md`

---

### Task 1: Pin Capstone.js and add the isolated ARM/Thumb backend

**Files:**
- Modify: `package.json`, `package-lock.json`
- Create: `src/types/alexaltea-capstone-js.d.ts`
- Create: `src/services/disassembly/backend.ts`
- Create: `src/services/disassembly/capstone.ts`
- Test: `tests/disassembly-backend.test.ts`

**Produces:**

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

- [ ] **Step 1: Install exact dependency**

```bash
npm install --save-exact @alexaltea/capstone-js@5.0.9
```

Expected: exact `5.0.9` in package and lockfile.

- [ ] **Step 2: Write failing real-backend tests**

Create `tests/disassembly-backend.test.ts`:

```ts
import assert from "node:assert/strict";
import test from "node:test";
import { createCapstoneArmBackend } from "../src/services/disassembly/capstone.js";

test("decodes known ARM and Thumb instructions", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    const arm = backend.decodeOne(
      Uint8Array.from([0x1e, 0xff, 0x2f, 0xe1]), // ARM bx lr
      0x02000000,
      "arm",
    );
    assert.ok(arm);
    assert.equal(arm.size, 4);
    assert.equal(arm.mnemonic, "bx");
    assert.equal(arm.operandsText, "lr");
    assert.deepEqual(arm.operands[0], { kind: "register", name: "lr" });

    const thumb = backend.decodeOne(
      Uint8Array.from([0x70, 0x47]), // Thumb bx lr
      0x02000010,
      "thumb",
    );
    assert.ok(thumb);
    assert.equal(thumb.size, 2);
    assert.equal(thumb.mnemonic, "bx");
    assert.equal(thumb.operandsText, "lr");
  } finally {
    backend.close();
  }
});

test("returns null for an incomplete instruction", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    assert.equal(backend.decodeOne(Uint8Array.from([0x00]), 0x02000000, "arm"), null);
  } finally {
    backend.close();
  }
});
```

- [ ] **Step 3: Prove RED**

```bash
node --test --import tsx tests/disassembly-backend.test.ts
```

Expected: FAIL because adapter file does not exist.

- [ ] **Step 4: Add minimal local declaration and backend types**

`src/types/alexaltea-capstone-js.d.ts` must declare only the 5.0.9 fields used by RE-MCP: default async factory, `Capstone`, `ARCH_ARM`, `MODE_ARM`, `MODE_THUMB`, `OPT_DETAIL`, `OPT_ON`, `GRP_JUMP`, `GRP_CALL`, `GRP_RET`, `ARM_OP_IMM`, `ARM_OP_REG`, `ARM_CC_INVALID`, `ARM_CC_AL`, `ARM_INS_BLX`, `ARM_INS_CBZ`, `ARM_INS_CBNZ`, `option`, `disasm_iter`, `reg_name`, `close`, instruction `id/address/size/bytes/mnemonic/op_str`, detail `groups/cc/op`, and operand `type/imm/reg`.

Implement `backend.ts` interfaces exactly as in **Produces**, including:

```ts
export class DisassemblyBackendError extends Error {
  readonly category = "disassembly-backend-failure" as const;
  constructor(message: string, readonly causeValue?: unknown) {
    super(message);
    this.name = "DisassemblyBackendError";
  }
}
```

- [ ] **Step 5: Implement `createCapstoneArmBackend()`**

`capstone.ts` must:

```ts
let modulePromise: Promise<CapstoneModule> | null = null;
```

Load the package once with dynamic import + default factory; reset `modulePromise` and throw `DisassemblyBackendError` if WASM initialization fails.

Construct two `CapstoneHandle`s:

```ts
const armDecoder = new cs.Capstone(cs.ARCH_ARM, cs.MODE_ARM);
const thumbDecoder = new cs.Capstone(cs.ARCH_ARM, cs.MODE_THUMB);
armDecoder.option(cs.OPT_DETAIL, cs.OPT_ON);
thumbDecoder.option(cs.OPT_DETAIL, cs.OPT_ON);
```

Use `disasm_iter()` to decode at most the first instruction. Normalize typed operands with `ARM_OP_IMM` / `ARM_OP_REG`, groups with `GRP_JUMP/CALL/RET`, conditions from `detail.cc` plus CBZ/CBNZ IDs, and `switchesMode` from `ARM_INS_BLX`. A zero-instruction decode returns `null`. Adapter/runtime exceptions become `DisassemblyBackendError`. `close()` closes both handles.

- [ ] **Step 6: Verify GREEN and strict typing**

```bash
node --test --import tsx tests/disassembly-backend.test.ts
npm run typecheck
```

Expected: PASS. If the actual installed 5.0.9 runtime shape disagrees with the local declaration, Task 1 is not complete: correct only the declaration/adapter to the observed package API, rerun these commands, and do not leak package-specific types into NDS services.

- [ ] **Step 7: Commit**

```bash
git add package.json package-lock.json src/types/alexaltea-capstone-js.d.ts src/services/disassembly/backend.ts src/services/disassembly/capstone.ts tests/disassembly-backend.test.ts
git commit -m "feat: add ARM Thumb disassembly backend"
```

---

### Task 2: Add deterministic NDS code-source, mode, and SHA policy

**Files:**
- Create: `src/services/nds/disassembly-source.ts`
- Test: `tests/nds-disassembly-source.test.ts`
- Reuse unchanged: `resolver.ts`, `rom-map.ts`, `io.ts`, `overlays.ts`

**Produces:**

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

export function resolveNdsCodeSource(map: NdsRomMap, location: NdsDisassemblyLocation): NdsCodeSourceResolution;
export function resolveNdsControlFlowTarget(map: NdsRomMap, current: NdsCodeSource, runtimeAddress: number, mode: ArmMode): NdsCodeSourceResolution;
export function codeSourceAt(source: NdsCodeSource, runtimeAddress: number): NdsCodeSource;
export async function withValidatedNdsRomReader<T>(map: NdsRomMap, callback: (read: (source: NdsCodeSource, maxBytes: number) => Promise<Buffer>) => Promise<T>): Promise<T>;
```

- [ ] **Step 1: Write failing source-policy tests**

Create fixtures with existing `createNdsFixture`, `writeFatEntry`, and `writeOverlayRecord`. Tests must prove:

```ts
// Auto is ARM only at resolved header entry.
assert.equal(resolveNdsCodeSource(map, {
  processor: "arm9", runtimeAddress: map.header.arm9.entryAddress, mode: "auto",
}).status, "resolved");

assert.equal(resolveNdsCodeSource(map, {
  processor: "arm9", runtimeAddress: map.header.arm9.entryAddress + 4, mode: "auto",
}).status, "mode-ambiguous");
```

For a ROM-offset request, first map to runtime identity, then test the seed:

```ts
const result = resolveNdsCodeSource(map, {
  processor: "arm9",
  romOffset: map.header.arm9.romOffset + 0x20,
  mode: "auto",
});
// When ARM9 entryAddress === ramAddress + 0x20, expect resolved ARM.
```

Also test:
- ARM7 main;
- explicit ARM/Thumb;
- ARM/Thumb alignment rejection;
- compressed overlay status;
- BSS status;
- uncompressed overlay where `romSize < ramSize` rejects the unbacked suffix;
- overlapping overlays return ambiguity unless `overlayId` selects one;
- wrong-processor ROM offset is not accepted as code for the requested processor;
- SHA mismatch before callback;
- mutation during callback is detected after callback;
- same selected overlapping overlay is preserved by a backward CFG target.

The last regression uses entry `0x02200040` in overlay 7 and target `0x02200010` while overlay 8 overlaps the same range. `resolveNdsControlFlowTarget()` must still return overlay 7 because the edge remains inside the full file-backed range of the already selected static component.

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-disassembly-source.test.ts
```

Expected: FAIL because source service does not exist.

- [ ] **Step 3: Build candidates from existing canonical resolvers**

Use `resolveRuntimeAddress()` for runtime selectors and `resolveRomOffset()` for ROM selectors. Do not reparse headers/FAT/overlays.

Require exactly one of `runtimeAddress` or `romOffset`:

```ts
const hasRuntime = location.runtimeAddress !== undefined;
const hasRom = location.romOffset !== undefined;
if (hasRuntime === hasRom) {
  throw new NdsError("range-out-of-bounds", "Disassembly requires exactly one of runtimeAddress or romOffset");
}
```

Main candidate ranges are exact header RAM/ROM ranges. For an uncompressed overlay, file-backed size is:

```ts
const fileBackedSize = Math.min(overlay.ramSize, overlay.romSize);
```

and eligible ranges are `[ramAddress, ramAddress + fileBackedSize)` / `[romOffset, romOffset + fileBackedSize)` only. BSS and the unbacked initialized suffix do not resolve to decodable bytes. Compressed overlays retain metadata but never become `resolved`.

Apply `overlayId` only as a candidate filter; it never means loaded state.

- [ ] **Step 4: Resolve source before mode**

Mandatory order:
1. map runtime/ROM selector to code candidate(s);
2. apply optional overlay disambiguator;
3. return ambiguity/compression/BSS/unmapped status when applicable;
4. obtain the resolved runtime address;
5. resolve requested mode;
6. enforce alignment.

For `auto`:

```ts
const executable = processor === "arm9" ? map.header.arm9 : map.header.arm7;
const mode = resolvedRuntimeAddress === executable.entryAddress ? "arm" : null;
```

Never compare a raw ROM offset to `entryAddress`.

- [ ] **Step 5: Preserve same-component control-flow identity and apply target mode**

`codeSourceAt()` maps any address inside `source.runtimeStart <= address < source.runtimeEnd` to the same canonical component and exact ROM byte.

Inside `resolveNdsControlFlowTarget()`:

```ts
if (runtimeAddress >= current.runtimeStart && runtimeAddress < current.runtimeEnd) {
  requireAlignment(runtimeAddress, mode);
  return {
    status: "resolved",
    source: { ...codeSourceAt(current, runtimeAddress), mode },
  };
}
return resolveNdsCodeSource(map, {
  processor: current.processor,
  runtimeAddress,
  mode,
});
```

Thus a same-overlay backward edge preserves the selected overlay even when another static overlay overlaps it; a target outside the current component is re-resolved without an overlay hint and can become ambiguous. Explicit target mode is always alignment-checked.

- [ ] **Step 6: Implement pre/post SHA reader even when callback throws**

Use existing `hashFileSha256()` and `readExact()`. Capture callback outcome, close the handle, perform the post-hash, then return/rethrow:

```ts
if (await hashFileSha256(map.romPath) !== map.sha256) {
  throw new NdsError("invalid-rom", "Source ROM no longer matches the canonical map identity");
}
const handle = await open(map.romPath, "r");
let outcome: { ok: true; value: T } | { ok: false; error: unknown };
try {
  const value = await callback(async (source, maxBytes) => {
    const length = Math.min(maxBytes, source.romEnd - source.romOffset);
    return await readExact(handle, source.romOffset, length, "NDS disassembly source");
  });
  outcome = { ok: true, value };
} catch (error) {
  outcome = { ok: false, error };
} finally {
  await handle.close();
}
if (await hashFileSha256(map.romPath) !== map.sha256) {
  throw new NdsError("invalid-rom", "Source ROM changed during disassembly");
}
if (!outcome.ok) throw outcome.error;
return outcome.value;
```

Validate `maxBytes` is a non-negative safe integer before reading.

- [ ] **Step 7: Verify GREEN + resolver regression**

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

### Task 3: Add canonical instruction semantics and bounded linear decoding

**Files:**
- Create: `src/services/nds/disassembly.ts`
- Test: `tests/nds-disassembly.test.ts`

**Produces:**

```ts
export type StaticFlowKind = "fallthrough" | "conditional-branch" | "unconditional-branch" | "call" | "return" | "indirect-branch" | "indirect-call";

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
  readonly source: { readonly processor: NdsProcessor; readonly component: "main" | "overlay"; readonly overlayId: number | null };
  readonly targetResolution: NdsCodeSourceResolution | null;
}

export interface LinearDisassemblyOptions { readonly maxInstructions: number; readonly maxBytes: number; }

export type LinearDisassemblyResult =
  | Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>
  | { readonly status: "complete" | "decode-stopped" | "component-boundary"; readonly source: NdsCodeSource; readonly instructions: readonly StaticInstruction[]; readonly decodedBytes: number; readonly stopAddress: number };

export function decodeNdsInstruction(map: NdsRomMap, source: NdsCodeSource, bytes: Uint8Array, backend: ArmDisassemblyBackend): StaticInstruction | null;
export async function disassembleNdsRange(map: NdsRomMap, location: NdsDisassemblyLocation, options: LinearDisassemblyOptions, backend: ArmDisassemblyBackend): Promise<LinearDisassemblyResult>;
```

Task 4 must consume `decodeNdsInstruction()` exactly; no second CFG-specific classifier.

- [ ] **Step 1: Write failing semantic tests using a fake backend**

Create a `FakeBackend` keyed by runtime address and test all seven flow kinds. Typed immediate operands determine direct targets; do not parse target addresses from `operandsText`.

For a direct BL fixture, assert:

```ts
instruction.flow.kind === "call";
instruction.flow.directTarget === 0x02000008;
instruction.flow.targetMode === "arm";
instruction.flow.fallthrough === 0x02000004;
```

Also test an immediate `switchesMode: true` instruction returns the opposite target mode, and a register-indirect call/branch returns null direct target.

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-disassembly.test.ts
```

Expected: FAIL because `disassembly.ts` does not exist.

- [ ] **Step 3: Implement one semantic normalizer**

Use backend groups/typed operands as primary evidence. The only mnemonic fallback is narrow return recognition for `BX LR` if Capstone does not place that instruction in the return group:

```ts
const isBxLr = decoded.mnemonic.toLowerCase() === "bx"
  && decoded.operands.some((operand) => operand.kind === "register" && operand.name === "lr");
```

Flow rules:
- return / `BX LR` => `return`, no fall-through;
- call + immediate => `call`, target + target mode, fall-through;
- call + no immediate => `indirect-call`, null target, fall-through;
- jump + immediate + conditional => `conditional-branch`, target + fall-through;
- jump + immediate + unconditional => `unconditional-branch`, target, no fall-through;
- jump + no immediate => `indirect-branch`, no fall-through;
- otherwise => `fallthrough` to `address + size`.

For a direct target, call `resolveNdsControlFlowTarget()` and place that result in `targetResolution`.

`bytesHex` is lowercase two-digit bytes joined without separators.

- [ ] **Step 4: Implement bounded linear decoding**

Resolve the starting source once. Unresolved static statuses return directly. Wrap the full decode in one `withValidatedNdsRomReader()` call. Read at most `maxBytes`, decode sequentially, and call `codeSourceAt()` for each instruction address.

Stop rules:
- backend returns no instruction => `decode-stopped` with decoded prefix;
- next instruction would exceed read bytes/component ROM end => `component-boundary`;
- instruction or byte request bound reached before component end => `complete`;
- exact component end => `component-boundary`.

`complete` means the requested bounded window completed; it does not claim function/component completeness.

- [ ] **Step 5: Add real adapter integration tests**

Write ARM `1e ff 2f e1` at ARM9 header entry and assert exact runtime address, ROM offset, `bytesHex === "1eff2fe1"`, `mode === "arm"`, main source, and return flow.

Write Thumb `70 47` at an explicitly Thumb, 2-byte-aligned address and assert `bytesHex === "7047"`, Thumb mode, and return flow.

Add explicit decode-stop and component-boundary tests.

- [ ] **Step 6: Verify GREEN**

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
- Test: `tests/nds-control-flow.test.ts`

**Produces:**

```ts
export interface ControlFlowLimits { readonly maxBlocks: number; readonly maxInstructions: number; readonly maxBytes: number; readonly maxEdges: number; }
export interface StaticBasicBlock { readonly id: string; readonly source: NdsCodeSource; readonly startAddress: number; readonly mode: ArmMode; readonly instructions: readonly StaticInstruction[]; readonly stopReason: "branch" | "return" | "indirect" | "decode-stopped" | "component-boundary" | "limit"; }
export interface StaticControlFlowEdge { readonly fromBlockId: string; readonly type: "fallthrough" | "branch" | "conditional-taken" | "conditional-fallthrough"; readonly targetAddress: number; readonly targetMode: ArmMode; readonly targetBlockId: string | null; }
export interface StaticCallEdge { readonly fromBlockId: string; readonly instructionAddress: number; readonly targetAddress: number | null; readonly targetMode: ArmMode | null; readonly resolution: NdsCodeSourceResolution | null; }
export interface StaticUnresolvedEdge { readonly fromBlockId: string; readonly instructionAddress: number; readonly kind: "indirect-branch" | "indirect-call" | "return" | "ambiguous-code-source" | "compressed-overlay-not-decodable" | "runtime-only-bss" | "unmapped-address"; }
export interface StaticControlFlowGraph { readonly entry: NdsCodeSource; readonly status: "complete" | "truncated"; readonly truncationReasons: readonly ("block-limit" | "instruction-limit" | "byte-limit" | "edge-limit")[]; readonly blocks: readonly StaticBasicBlock[]; readonly edges: readonly StaticControlFlowEdge[]; readonly calls: readonly StaticCallEdge[]; readonly unresolvedEdges: readonly StaticUnresolvedEdge[]; readonly totals: { readonly blocks: number; readonly instructions: number; readonly bytes: number; readonly edges: number }; }
export async function analyzeNdsControlFlow(map: NdsRomMap, location: NdsDisassemblyLocation, limits: ControlFlowLimits, backend: ArmDisassemblyBackend): Promise<Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }> | StaticControlFlowGraph>;
```

- [ ] **Step 1: Write failing CFG tests**

Use deterministic fake instructions to test:
1. conditional taken + conditional fall-through blocks;
2. unconditional branch only;
3. direct call recorded, not queued, same block continues at return address;
4. indirect call recorded, same block continues;
5. indirect branch terminates;
6. return terminates;
7. cycles decode each block once;
8. backward edge inside selected overlapping overlay preserves source identity;
9. unique same-processor cross-component branch traverses;
10. ambiguous/compressed/BSS/unmapped target records unresolved edge and stops that path;
11. deterministic ARM↔Thumb edge queues propagated target mode;
12. each cap independently truncates with only its own reason;
13. simultaneous caps produce deduplicated fixed-order reasons;
14. one block's decode stop does not prevent already queued blocks from completing.

Block identity is exactly:

```ts
[processor, component, overlayId ?? "main", runtimeAddress.toString(16), mode].join(":")
```

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-control-flow.test.ts
```

Expected: FAIL because `control-flow.ts` does not exist.

- [ ] **Step 3: Implement deterministic FIFO worklist**

Resolve entry once and wrap the entire graph build in one SHA-validated reader. Maintain `queue`, `queued`, and `visited` keyed by the exact block identity above.

Decode each block sequentially with **Task 3's `decodeNdsInstruction()`**; never duplicate its semantic classification.

Behavior:
- ordinary instruction stays in block;
- direct call => append `calls`, do not queue callee, continue at call fall-through in the current component;
- indirect call => append call + unresolved event, continue at fall-through;
- conditional direct branch => terminate block, emit/resolve taken and fall-through paths;
- unconditional direct branch => terminate block, emit/resolve branch target;
- indirect branch/return => terminate block;
- decode stop/component boundary => terminate only that block.

Conditional/call fall-through may continue only when the next runtime address is inside the current file-backed component (`codeSourceAt`). Do not cross a component boundary by fall-through. Direct branch targets may use `resolveNdsControlFlowTarget()` and therefore may cross components when uniquely resolvable.

- [ ] **Step 4: Keep calls separate from traversal edges**

Direct calls populate `calls` with their canonical `targetResolution` but never enter `queue`. Calls do not consume the traversal-edge counter. `edges` counts only CFG traversal edges (`branch`, conditional taken/fall-through, and any explicit non-call fall-through edge represented by the graph).

Unresolved indirect calls also populate `unresolvedEdges` as `indirect-call` while decoding continues at valid same-component fall-through.

- [ ] **Step 5: Enforce all four global caps before growth**

Maintain counters for accepted blocks, decoded instructions, decoded instruction bytes, and traversal edges. Never let a counter exceed its configured limit. When the next operation would exceed a limit, skip that growth and add the matching reason.

Fixed truncation-reason order:

```ts
["block-limit", "instruction-limit", "byte-limit", "edge-limit"]
```

Final status is `complete` only when the reason set is empty.

- [ ] **Step 6: Verify GREEN + linear regression**

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

### Task 5: Expose exactly two bounded MCP tools

**Files:**
- Modify: `src/tools/nds.ts`
- Modify/Test: `tests/nds-tools.test.ts`
- Modify: `src/index.ts`

- [ ] **Step 1: Write failing tool-registration/schema tests**

Update `EXPECTED_TOOLS` to exactly nine total NDS tools, adding:

```ts
"nds_disassemble_range",
"nds_analyze_control_flow",
```

Assert default parses:

```ts
nds_disassemble_range => mode "auto", maxInstructions 32, maxBytes 128
nds_analyze_control_flow => mode "auto", maxBlocks 64, maxInstructions 512, maxBytes 2048, maxEdges 128
```

Assert every approved maximum is enforced.

For both schemas assert absence of:

```ts
"binary", "bytes", "baseAddress", "output", "path", "length"
```

`runtimeAddress` and `romOffset` are the only location selectors. Handler tests must prove neither/both selectors return a structured `range-out-of-bounds` error.

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-tools.test.ts
```

Expected: FAIL because only seven NDS tools are registered.

- [ ] **Step 3: Add exact Zod bounds and location normalizer**

```ts
const disassemblyModeSchema = z.enum(["arm", "thumb", "auto"]);
const linearInstructionLimitSchema = z.number().int().min(1).max(256).default(32);
const linearByteLimitSchema = z.number().int().min(2).max(1024).default(128);
const cfgBlockLimitSchema = z.number().int().min(1).max(256).default(64);
const cfgInstructionLimitSchema = z.number().int().min(1).max(4096).default(512);
const cfgByteLimitSchema = z.number().int().min(2).max(16384).default(2048);
const cfgEdgeLimitSchema = z.number().int().min(1).max(1024).default(128);
```

Normalize exactly one of `runtimeAddress`/`romOffset`; throw `NdsError("range-out-of-bounds", ...)` otherwise. Carry optional `overlayId` only as the static disambiguator.

- [ ] **Step 4: Add backend-error category without weakening NDS errors**

```ts
type NdsToolErrorCategory = NdsErrorCategory | "disassembly-backend-failure";
```

Add corrective action for the backend category and choose category in this order:

```ts
error instanceof DisassemblyBackendError
  ? error.category
  : error instanceof NdsError
    ? error.category
    : fallbackCategory
```

- [ ] **Step 5: Register `nds_disassemble_range`**

Schema fields:

```ts
rom, processor, runtimeAddress?, romOffset?, overlayId?, mode="auto", maxInstructions=32, maxBytes=128
```

Handler: resolve workspace ROM, build `NdsRomMap`, normalize location, create backend, call `disassembleNdsRange()`, close backend in `finally`, and return through existing `boundedTextResult`. Static statuses are successful results; thrown operational failures use `ndsErrorResult`.

- [ ] **Step 6: Register `nds_analyze_control_flow`**

Same location fields plus CFG limits. Use the same backend lifecycle and call `analyzeNdsControlFlow()`. `status: "truncated"` is successful, not an MCP error.

- [ ] **Step 7: Update `server_capabilities`**

Add both names after the existing seven NDS tools. Update `ndsStaticAnalysisPolicy` to mention bounded ARM/Thumb disassembly/direct CFG analysis, no overlay-loaded inference, no generic binary input, and no ROM mutation/rebuild.

- [ ] **Step 8: Verify GREEN**

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

### Task 6: Prove the WASM backend in the assembled production bundle

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `.github/workflows/package.yml`

**Important existing path contract:** source build output is under `dist/src/`; the package workflow copies `dist/src/.` into bundle `dist/`. `scripts/check-install.mjs` is therefore a **bundle-root verifier** and must be tested against an assembled bundle, not directly against the source checkout.

- [ ] **Step 1: Extend bundle requirements**

In `scripts/check-install.mjs`, require:

```js
"node_modules/@alexaltea/capstone-js/package.json",
"node_modules/@alexaltea/capstone-js/dist/capstone.js",
"node_modules/@alexaltea/capstone-js/dist/capstone.wasm",
```

Import `pathToFileURL` from `node:url`.

- [ ] **Step 2: Add packaged ARM/Thumb smoke decode**

After Node-version validation and before success JSON:

```js
const adapterUrl = pathToFileURL(
  path.join(root, "dist/services/disassembly/capstone.js"),
).href;
const { createCapstoneArmBackend } = await import(adapterUrl);
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

Only then print the existing `{ ok: true, ... }` result.

- [ ] **Step 3: Keep package workflow isolated and explicit**

Retain production install inside `/tmp/re-mcp-${version}`:

```bash
npm install --omit=dev --ignore-scripts
node scripts/check-install.mjs .
```

Rename the workflow step from `Assemble self-contained bundle` to `Assemble and smoke-test self-contained bundle` so logs clearly expose this acceptance. Do not copy Capstone assets from the source checkout and do not download decoder assets at runtime.

- [ ] **Step 4: Reproduce exact package assembly locally**

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

Expected: PASS; the assembled production bundle initializes WASM and decodes both fixtures without an external tool.

- [ ] **Step 5: Commit**

```bash
git add scripts/check-install.mjs .github/workflows/package.yml
git commit -m "test: verify packaged Capstone WASM decoder"
```

---

### Task 7: Document the workflow and run final regression

**Files:**
- Modify: `README.md`
- Verify: all tests/build/package smoke/security surface.

- [ ] **Step 1: Document exact static workflow**

```text
nds_inspect_rom
  -> nds_list_overlays / address resolvers as needed
  -> nds_disassemble_range
  -> nds_analyze_control_flow
```

README must state:
- `arm`, `thumb`, conservative `auto`;
- initial `auto` trusts only a resolved ARM9/ARM7 header entry;
- CFG direct edges propagate deterministic mode;
- ambiguity is returned, never guessed;
- `overlayId` selects a static source but never means loaded;
- BSS has no ROM bytes;
- compressed overlays are rejected pending a separate decompression milestone;
- linear defaults/maxima: 32/256 instructions, 128/1024 bytes;
- CFG defaults/maxima: 64/256 blocks, 512/4096 instructions, 2/16 KiB decoded bytes, 128/1024 traversal edges;
- calls are annotated but not traversed;
- indirect targets are never guessed;
- `truncated` is a valid partial graph with named exhausted limits;
- static disassembly is independent of pending physical Catalina/DeSmuME acceptance;
- no generic binary disassembly, ROM mutation, rebuild, or patch generation.

- [ ] **Step 2: Run focused suite**

```bash
node --test --import tsx \
  tests/disassembly-backend.test.ts \
  tests/nds-disassembly-source.test.ts \
  tests/nds-disassembly.test.ts \
  tests/nds-control-flow.test.ts \
  tests/nds-tools.test.ts
```

Expected: PASS.

- [ ] **Step 3: Run complete quality/build**

```bash
npm run check
npm run build
```

Expected: PASS.

- [ ] **Step 4: Repeat Task 6 isolated bundle smoke**

Run the exact Task 6 assembly commands. Expected: bundle verifier prints `ok: true` after both ARM and Thumb decodes.

- [ ] **Step 5: Audit public/security surface**

```bash
grep -R "nds_disassemble_range\|nds_analyze_control_flow" -n src README.md tests
grep -R "baseAddress\|generic binary" -n src/services/nds src/tools/nds.ts README.md || true
git diff --name-only main...HEAD
```

Verify:
- exactly nine NDS tools total, exactly two new;
- no new generic binary/raw byte/base-address/output-path schema;
- no DeSmuME GDB transport/controller/runtime source change;
- no ROM write/rebuild capability;
- no loaded-overlay claim;
- exact Capstone.js version `5.0.9`.

- [ ] **Step 6: Commit docs**

```bash
git add README.md
git commit -m "docs: document NDS static disassembly"
```

- [ ] **Step 7: Final verification**

```bash
git status --short
git log --oneline --decorate -8
npm run check
npm run build
```

Expected: clean worktree and all checks PASS. Push the implementation branch; GitHub Actions CI + Package are the authoritative remote regression gates. They do not constitute physical Catalina/DeSmuME acceptance.

---

## Recommended PR Boundaries

1. **PR A — Decoder + NDS linear disassembly:** Tasks 1–3.
2. **PR B — Direct CFG analysis:** Task 4.
3. **PR C — MCP surface + package acceptance + docs:** Tasks 5–7.

Each PR must pass `npm run check` and `npm run build`. PR C must also pass the Package workflow's isolated production/WASM smoke check before merge.
