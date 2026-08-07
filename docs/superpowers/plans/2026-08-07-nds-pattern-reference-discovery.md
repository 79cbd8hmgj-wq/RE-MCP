# NDS Pattern + Reference Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded, read-only Nintendo DS proven-reference discovery in both source-to-reference and target-to-xref directions without heuristic pointer inference or changes to existing CFG call-traversal semantics.

**Architecture:** Extend the existing Capstone adapter only with normalized structured operand/PC-relative semantics, then preserve the current public `StaticInstruction` shape through an internal detailed-decode wrapper. A shared NDS reference classifier converts one detailed instruction into deterministic `StaticReference` records using canonical `RuntimeResolution`; a bounded source-window service reuses the detailed linear decoder, while a separate FIFO reverse-xref scanner follows proven direct branches and calls inside caller-selected same-processor scope and reports explicit coverage/truncation.

**Tech Stack:** TypeScript ES2022/NodeNext, Node.js >=20, Node `node:test`, Zod, existing RE-MCP `NdsRomMap`/resolver/disassembly services, exact `@alexaltea/capstone-js` 5.0.9 JavaScript/WASM, GitHub Actions package verification.

## Global Constraints

- Keep `@alexaltea/capstone-js` pinned exactly at `5.0.9`; do not add or upgrade disassembly dependencies.
- Keep Node.js runtime floor `>=20`; CI/package verification remains Node 20.
- Add exactly two public NDS tools: `nds_list_references` and `nds_find_xrefs`; the NDS static tool surface becomes exactly eleven tools.
- Emit only deterministic single-instruction reference kinds: `direct-branch`, `direct-call`, `literal-pool`, and `pc-relative-address`.
- Never treat an ordinary immediate as a pointer merely because it resembles a mapped RAM/ROM address.
- Never interpret literal-pool contents as secondary references in this milestone.
- Never infer targets from register state, stack state, prior instructions, pointer arrays, jump tables, or general data flow.
- Source-to-reference uses the existing NDS disassembly source policy: uniquely mapped file-backed main/uncompressed-overlay code only; compressed overlays/BSS are not decoded; conservative `auto` mode is unchanged.
- ARM architectural PC for supported PC-relative forms is `instructionAddress + 8`.
- Thumb architectural PC for supported literal/address forms is `Align(instructionAddress + 4, 4)`.
- Reverse-xref target accepts exactly one runtime address or ROM offset. A ROM offset must map to exactly one unique runtime address for the selected processor or return `ambiguous-reference-target` / `reference-target-not-runtime-addressable`.
- Reverse-xref scope is one processor plus `main`, explicit overlay IDs, `main-and-overlays`, or `all-executable-components`; scope never implies runtime loaded-overlay state.
- Overlay code is scanned only from a valid explicit mode-tagged seed or a proven direct branch/call target with deterministic mode.
- Reverse-xref traversal follows proven direct call targets for coverage only. Existing `nds_analyze_control_flow` continues to record calls without traversing callees.
- Reverse-xref limits default/max: components `32/128`; blocks `128/512`; instructions `2048/16384`; bytes `8192/65536`; traversal edges `512/4096`; returned xrefs `256/2048`.
- Reverse-xref truncation reasons are exactly `component-limit`, `block-limit`, `instruction-limit`, `byte-limit`, `edge-limit`, `result-limit`.
- Reverse-xref status is `complete`, `partial-coverage`, or `truncated`; `truncated` takes precedence over independent coverage gaps.
- Coverage statuses are `scanned`, `no-proven-seed`, `compressed-overlay-not-decodable`, `out-of-limit`.
- Preserve exact existing `RuntimeResolution` statuses on reference targets: `resolved`, `unmapped`, `ambiguous-runtime-address`, `runtime-only-bss`, `compressed-no-direct-rom-mapping`.
- Both top-level reference operations verify the ROM SHA before and after analysis, including when analysis throws.
- No generic binary input, caller-provided executable bytes, arbitrary base address, caller-controlled output path, ROM mutation, ROM rebuild, or raw byte-range extraction.
- The assembled production bundle must initialize packaged Capstone.js/WASM and prove one direct ARM reference plus one Thumb PC-relative reference without source-tree fallback, native addon, external disassembler, or runtime network download.
- Physical Intel Catalina/DeSmuME acceptance remains a separate unresolved gate and must not be claimed by this milestone.

---

## File Map

### Modify

- `src/types/alexaltea-capstone-js.d.ts` — add only the Capstone 5.0.9 ARM memory/instruction constants and fields actually required by normalized PC-relative semantics.
- `src/services/disassembly/backend.ts` — add normalized memory operands and deterministic PC-relative semantic metadata.
- `src/services/disassembly/capstone.ts` — normalize structured Capstone details into the RE-MCP backend model; remain the sole production Capstone import.
- `src/services/nds/disassembly.ts` — add an internal detailed decode/window result while preserving existing public `StaticInstruction`/`disassembleNdsRange` output.
- `src/services/nds/errors.ts` — add reference-specific NDS error categories.
- `src/tools/nds.ts` — schemas/handlers/error actions for the two new tools.
- `src/index.ts` — capabilities text and tool list.
- `scripts/check-install.mjs` — assembled-package reference-classification smoke acceptance.
- `tests/disassembly-backend.test.ts` — real Capstone operand/PC-relative normalization.
- `tests/nds-disassembly.test.ts` — detailed internal decode compatibility tests.
- `tests/nds-tools.test.ts` — exactly eleven tools, schemas, handler integration, safety surface.
- `tests/package-capstone-install.test.ts` — require packaged reference-service smoke acceptance.
- `README.md` — user-facing tool/reference/coverage/limit documentation.

### Create

- `src/services/nds/references.ts` — canonical `StaticReference` model, runtime target normalization, and deterministic single-instruction classifier.
- `src/services/nds/reference-list.ts` — bounded source-to-reference service.
- `src/services/nds/xref-source.ts` — reverse-target canonicalization, component-scope expansion, and explicit-seed validation.
- `src/services/nds/xrefs.ts` — bounded FIFO reverse-xref traversal and coverage/truncation accounting.
- `tests/nds-references.test.ts` — classifier/reference-target tests.
- `tests/nds-reference-list.test.ts` — bounded list/SHA behavior.
- `tests/nds-xref-source.test.ts` — target/scope/seed policy.
- `tests/nds-xrefs.test.ts` — traversal, call-following, limits, ordering, coverage.

### Reuse unchanged unless a failing test proves a required compatibility fix

- `src/services/nds/resolver.ts`
- `src/services/nds/disassembly-source.ts`
- `src/services/nds/control-flow.ts`
- `src/services/nds/rom-map.ts`
- `tests/helpers/nds-fixture.ts`
- `.github/workflows/package.yml` (its existing assembled-bundle step already executes `scripts/check-install.mjs`)
- `package.json` dependency versions

---

### Task 1: Normalize ARM memory operands and deterministic PC-relative semantics

**Files:**
- Modify: `src/types/alexaltea-capstone-js.d.ts`
- Modify: `src/services/disassembly/backend.ts`
- Modify: `src/services/disassembly/capstone.ts`
- Test: `tests/disassembly-backend.test.ts`

**Consumes:** existing `ArmMode`, `DecodedArmInstruction`, Capstone 5.0.9 detailed ARM operands.

**Produces:**

```ts
export interface DecodedArmMemoryOperand {
  readonly baseRegister: string | null;
  readonly indexRegister: string | null;
  readonly displacement: number;
}

export type DecodedArmOperand =
  | { readonly kind: "immediate"; readonly value: number }
  | { readonly kind: "register"; readonly name: string }
  | { readonly kind: "memory"; readonly value: DecodedArmMemoryOperand }
  | { readonly kind: "other" };

export type DecodedArmPcRelativeSemantics =
  | { readonly kind: "literal-load"; readonly displacement: number }
  | { readonly kind: "address-add"; readonly immediate: number }
  | { readonly kind: "address-sub"; readonly immediate: number }
  | null;

export interface DecodedArmInstruction {
  // existing fields unchanged
  readonly pcRelative: DecodedArmPcRelativeSemantics;
}
```

The adapter must set `pcRelative` from structured instruction identity/operand detail, never by parsing a numeric target out of `op_str`.

- [ ] **Step 1: Extend the real-backend tests first**

Append exact fixtures to `tests/disassembly-backend.test.ts`:

```ts
test("normalizes ARM and Thumb PC-relative operands from structured detail", async () => {
  const backend = await createCapstoneArmBackend();
  try {
    const armLiteral = backend.decodeOne(
      Uint8Array.from([0x00, 0x00, 0x9f, 0xe5]), // ldr r0, [pc, #0]
      0x02000000,
      "arm",
    );
    assert.ok(armLiteral);
    assert.deepEqual(armLiteral.pcRelative, {
      kind: "literal-load",
      displacement: 0,
    });
    assert.equal(
      armLiteral.operands.some(
        (operand) => operand.kind === "memory"
          && operand.value.baseRegister === "pc"
          && operand.value.displacement === 0,
      ),
      true,
    );

    const thumbLiteral = backend.decodeOne(
      Uint8Array.from([0x00, 0x48]), // ldr r0, [pc, #0]
      0x02000002,
      "thumb",
    );
    assert.ok(thumbLiteral);
    assert.deepEqual(thumbLiteral.pcRelative, {
      kind: "literal-load",
      displacement: 0,
    });

    const armAdd = backend.decodeOne(
      Uint8Array.from([0x10, 0x00, 0x8f, 0xe2]), // add r0, pc, #0x10 (ADR form may be printed)
      0x02000000,
      "arm",
    );
    assert.ok(armAdd);
    assert.deepEqual(armAdd.pcRelative, {
      kind: "address-add",
      immediate: 0x10,
    });

    const thumbAdr = backend.decodeOne(
      Uint8Array.from([0x00, 0xa0]), // adr r0, #0
      0x02000002,
      "thumb",
    );
    assert.ok(thumbAdr);
    assert.deepEqual(thumbAdr.pcRelative, {
      kind: "address-add",
      immediate: 0,
    });
  } finally {
    backend.close();
  }
});
```

Also update every locally constructed `DecodedArmInstruction` fixture in tests to include:

```ts
pcRelative: null,
```

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/disassembly-backend.test.ts tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts
```

Expected: FAIL because `DecodedArmInstruction.pcRelative`, memory operand support, and the Capstone declaration fields/constants do not exist yet.

- [ ] **Step 3: Extend the RE-MCP backend types minimally**

In `src/services/disassembly/backend.ts`, add the interfaces/unions from **Produces** and add:

```ts
readonly pcRelative: DecodedArmPcRelativeSemantics;
```

to `DecodedArmInstruction` without changing existing flow fields.

- [ ] **Step 4: Extend only the required Capstone declaration surface**

In `src/types/alexaltea-capstone-js.d.ts`, extend `CapstoneOperand` with the actual 5.0.9 structured memory fields used by the adapter:

```ts
readonly mem?: {
  readonly base?: number;
  readonly index?: number;
  readonly disp?: number;
};
```

Add constants used by the implementation:

```ts
readonly ARM_OP_MEM: number;
readonly ARM_INS_LDR: number;
readonly ARM_INS_ADR: number;
readonly ARM_INS_ADD: number;
readonly ARM_INS_SUB: number;
```

If the real 5.0.9 object names differ, correct this declaration and the adapter to the observed package API during this task; do not add `any`, parse display strings, or leak Capstone types beyond `capstone.ts`.

- [ ] **Step 5: Normalize memory operands**

Extend `normalizeOperand()` in `src/services/disassembly/capstone.ts`:

```ts
if (operand.type === cs.ARM_OP_MEM && operand.mem !== undefined) {
  const base = operand.mem.base;
  const index = operand.mem.index;
  return {
    kind: "memory",
    value: {
      baseRegister: base === undefined || base === 0
        ? null
        : decoder.reg_name(base).toLowerCase(),
      indexRegister: index === undefined || index === 0
        ? null
        : decoder.reg_name(index).toLowerCase(),
      displacement: operand.mem.disp ?? 0,
    },
  };
}
```

Preserve the existing narrow register-only fallback for `BX`/register `BLX`; do not broaden it into numeric operand parsing.

- [ ] **Step 6: Normalize deterministic PC-relative forms**

Pass `mode` into instruction normalization so the adapter can normalize exact instruction forms. Implement helpers with these rules:

```ts
function registerOperand(
  operands: readonly DecodedArmOperand[],
  index: number,
): string | null {
  const operand = operands[index];
  return operand?.kind === "register" ? operand.name : null;
}

function immediateOperand(
  operands: readonly DecodedArmOperand[],
  index: number,
): number | null {
  const operand = operands[index];
  return operand?.kind === "immediate" ? operand.value >>> 0 : null;
}
```

Classification requirements:

```ts
// LDR literal: exact LDR identity + memory operand with base pc + no index register.
{ kind: "literal-load", displacement: memory.displacement }

// ADD dest, pc, #imm.
{ kind: "address-add", immediate: imm }

// SUB dest, pc, #imm.
{ kind: "address-sub", immediate: imm }
```

For `ARM_INS_ADR`, normalize the structured ADR target into `address-add` or `address-sub` relative to that mode's architectural PC; use only typed Capstone target metadata plus `instruction.address`/`mode`, never `op_str` numeric parsing. ARM PC is `address + 8`; Thumb PC is `(address + 4) & ~3`.

All other instructions set:

```ts
pcRelative: null
```

- [ ] **Step 7: Verify GREEN and regression compatibility**

```bash
node --test --import tsx tests/disassembly-backend.test.ts tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts
npm run typecheck
```

Expected: PASS. Existing `BX LR`, branch, call, condition, and mode-switch behavior must remain unchanged.

- [ ] **Step 8: Commit**

```bash
git add src/types/alexaltea-capstone-js.d.ts src/services/disassembly/backend.ts src/services/disassembly/capstone.ts tests/disassembly-backend.test.ts tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts
git commit -m "feat: normalize ARM PC relative semantics"
```

---

### Task 2: Add detailed internal NDS decoding without changing existing public disassembly output

**Files:**
- Modify: `src/services/nds/disassembly.ts`
- Test: `tests/nds-disassembly.test.ts`

**Consumes:** `DecodedArmInstruction` with normalized `pcRelative` metadata, existing `NdsCodeSource`, `withValidatedNdsRomReader()`.

**Produces:**

```ts
export interface DetailedStaticInstruction {
  readonly instruction: StaticInstruction;
  readonly decoded: DecodedArmInstruction;
}

export type DetailedLinearDisassemblyResult =
  | Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>
  | {
      readonly status: "complete" | "decode-stopped" | "component-boundary";
      readonly source: NdsCodeSource;
      readonly instructions: readonly DetailedStaticInstruction[];
      readonly decodedBytes: number;
      readonly stopAddress: number;
    };

export function decodeNdsInstructionDetailed(
  map: NdsRomMap,
  source: NdsCodeSource,
  bytes: Uint8Array,
  backend: ArmDisassemblyBackend,
): DetailedStaticInstruction | null;

export async function disassembleNdsRangeDetailed(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  options: LinearDisassemblyOptions,
  backend: ArmDisassemblyBackend,
): Promise<DetailedLinearDisassemblyResult>;
```

The existing exports remain source-compatible:

```ts
export function decodeNdsInstruction(...): StaticInstruction | null;
export async function disassembleNdsRange(...): Promise<LinearDisassemblyResult>;
```

- [ ] **Step 1: Write failing detailed-decode tests**

Add to `tests/nds-disassembly.test.ts`:

```ts
test("detailed decode retains normalized backend semantics without changing StaticInstruction", async () => {
  const fixture = await createNdsFixture();
  const map = await readNdsRomMap(fixture.romPath);
  const source = await mainSource(map);
  const backend = new FakeBackend(new Map([
    [0x02000000, decoded(0x02000000, {
      mnemonic: "ldr",
      operandsText: "r0, [pc]",
      operands: [
        { kind: "register", name: "r0" },
        {
          kind: "memory",
          value: { baseRegister: "pc", indexRegister: null, displacement: 0 },
        },
      ],
      pcRelative: { kind: "literal-load", displacement: 0 },
    })],
  ]));

  const detailed = decodeNdsInstructionDetailed(
    map,
    source,
    Uint8Array.from([0x00, 0x00, 0x9f, 0xe5]),
    backend,
  );
  assert.ok(detailed);
  assert.equal(detailed.instruction.mnemonic, "ldr");
  assert.deepEqual(detailed.decoded.pcRelative, {
    kind: "literal-load",
    displacement: 0,
  });
  assert.equal(Object.hasOwn(detailed.instruction, "decoded"), false);
  assert.equal(Object.hasOwn(detailed.instruction, "pcRelative"), false);
});
```

Add a compatibility test around `disassembleNdsRange()`:

```ts
const publicResult = await disassembleNdsRange(...);
if (publicResult.status === "complete") {
  assert.equal(Object.hasOwn(publicResult.instructions[0]!, "decoded"), false);
  assert.equal(Object.hasOwn(publicResult.instructions[0]!, "pcRelative"), false);
}
```

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/nds-disassembly.test.ts
```

Expected: FAIL because detailed decode/window exports do not exist.

- [ ] **Step 3: Extract the existing instruction normalization into the detailed wrapper**

Refactor the current `decodeNdsInstruction()` body so it creates the same `StaticInstruction` as today and returns:

```ts
return {
  instruction: {
    address: source.runtimeAddress,
    romOffset: source.romOffset,
    size: decoded.size,
    bytesHex: Buffer.from(bytes.subarray(0, decoded.size)).toString("hex"),
    mode: source.mode,
    mnemonic: decoded.mnemonic,
    operands: decoded.operandsText,
    flow,
    source: {
      processor: source.processor,
      component: source.component,
      overlayId: source.overlayId,
    },
    targetResolution,
  },
  decoded,
};
```

Then implement the compatibility wrapper:

```ts
export function decodeNdsInstruction(...): StaticInstruction | null {
  return decodeNdsInstructionDetailed(...)?.instruction ?? null;
}
```

Do not add normalized backend fields to `StaticInstruction`.

- [ ] **Step 4: Move the current bounded linear loop into `disassembleNdsRangeDetailed()`**

Keep the current source resolution, byte-boundary, decode-stop, instruction/byte limits, and `withValidatedNdsRomReader()` behavior. The only semantic change is that the detailed loop stores:

```ts
DetailedStaticInstruction[]
```

instead of `StaticInstruction[]`.

- [ ] **Step 5: Make `disassembleNdsRange()` strip internal detail**

Implement:

```ts
export async function disassembleNdsRange(...): Promise<LinearDisassemblyResult> {
  const result = await disassembleNdsRangeDetailed(map, location, options, backend);
  if (
    result.status === "ambiguous-code-source"
    || result.status === "compressed-overlay-not-decodable"
    || result.status === "runtime-only-bss"
    || result.status === "unmapped-address"
    || result.status === "mode-ambiguous"
  ) {
    return result;
  }
  return {
    ...result,
    instructions: result.instructions.map((entry) => entry.instruction),
  };
}
```

- [ ] **Step 6: Verify GREEN including existing CFG behavior**

```bash
node --test --import tsx tests/nds-disassembly.test.ts tests/nds-control-flow.test.ts tests/nds-tools.test.ts
npm run typecheck
```

Expected: PASS with no changed public `nds_disassemble_range` or CFG contract.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/disassembly.ts tests/nds-disassembly.test.ts
git commit -m "refactor: expose detailed NDS instruction decoding"
```

---

### Task 3: Add the canonical proven-reference classifier

**Files:**
- Create: `src/services/nds/references.ts`
- Create: `tests/nds-references.test.ts`

**Consumes:** `DetailedStaticInstruction`, `NdsRomMap`, existing `resolveRuntimeAddress()` and `RuntimeResolution`.

**Produces:**

```ts
export type StaticReferenceKind =
  | "direct-branch"
  | "direct-call"
  | "literal-pool"
  | "pc-relative-address";

export type StaticReferenceMechanism =
  | "direct-control-flow"
  | "pc-relative-literal-address"
  | "pc-relative-address-construction";

export interface StaticReference {
  readonly kind: StaticReferenceKind;
  readonly source: {
    readonly processor: NdsProcessor;
    readonly component: "main" | "overlay";
    readonly overlayId: number | null;
    readonly instructionAddress: number;
    readonly instructionRomOffset: number;
    readonly mode: ArmMode;
  };
  readonly target: {
    readonly runtimeAddress: number;
    readonly romOffset: number | null;
    readonly resolution: RuntimeResolution;
  };
  readonly evidence: {
    readonly instructionMnemonic: string;
    readonly mechanism: StaticReferenceMechanism;
  };
}

export function classifyNdsInstructionReferences(
  map: NdsRomMap,
  detailed: DetailedStaticInstruction,
): readonly StaticReference[];

export function compareStaticReferences(
  left: StaticReference,
  right: StaticReference,
): number;
```

- [ ] **Step 1: Write failing classifier tests with fake backend metadata**

Create `tests/nds-references.test.ts` using `createNdsFixture()`, `readNdsRomMap()`, `resolveNdsCodeSource()`, and `decodeNdsInstructionDetailed()`.

Direct call assertion:

```ts
assert.deepEqual(
  classifyNdsInstructionReferences(map, directCall).map((ref) => ({
    kind: ref.kind,
    target: ref.target.runtimeAddress,
    status: ref.target.resolution.status,
  })),
  [{ kind: "direct-call", target: 0x02000008, status: "resolved" }],
);
```

Indirect call/branch assertions:

```ts
assert.deepEqual(classifyNdsInstructionReferences(map, indirectCall), []);
assert.deepEqual(classifyNdsInstructionReferences(map, indirectBranch), []);
```

ARM literal assertion at `0x02000000` with displacement `0`:

```ts
assert.equal(reference.kind, "literal-pool");
assert.equal(reference.target.runtimeAddress, 0x02000008);
```

Thumb literal assertion at `0x02000002` with displacement `0`:

```ts
assert.equal(reference.target.runtimeAddress, 0x02000004);
```

ARM add/sub and Thumb ADR assertions:

```ts
// ARM +8 PC + 0x10
assert.equal(armAddReference.target.runtimeAddress, 0x02000018);

// Align(0x02000002 + 4, 4) + 0
assert.equal(thumbAdrReference.target.runtimeAddress, 0x02000004);
```

Unknown register contribution must already have `pcRelative: null` and produce no reference.

- [ ] **Step 2: Add explicit target-resolution fixtures**

Use `writeFatEntry()` / `writeOverlayRecord()` to construct overlapping/uncompressed, BSS, and compressed overlay target cases. Assert exact resolver vocabulary:

```ts
assert.equal(ambiguous.target.resolution.status, "ambiguous-runtime-address");
assert.equal(bss.target.resolution.status, "runtime-only-bss");
assert.equal(compressed.target.resolution.status, "compressed-no-direct-rom-mapping");
```

The reference itself must still exist in all three cases.

- [ ] **Step 3: Prove RED**

```bash
node --test --import tsx tests/nds-references.test.ts
```

Expected: FAIL because the reference service does not exist.

- [ ] **Step 4: Implement architectural PC math with explicit 32-bit bounds**

In `references.ts`:

```ts
function alignWord(address: number): number {
  return address & ~3;
}

function architecturalPc(address: number, mode: ArmMode): number {
  return mode === "arm"
    ? (address + 8) >>> 0
    : alignWord((address + 4) >>> 0) >>> 0;
}

function addUint32(base: number, delta: number): number {
  return Number((BigInt(base >>> 0) + BigInt(delta)) & 0xffff_ffffn);
}

function subUint32(base: number, delta: number): number {
  return Number((BigInt(base >>> 0) - BigInt(delta)) & 0xffff_ffffn);
}
```

Use `addUint32()` for signed literal displacement as well; negative displacement naturally subtracts under the mask.

- [ ] **Step 5: Implement one canonical target normalizer**

```ts
function referenceTarget(
  map: NdsRomMap,
  processor: NdsProcessor,
  runtimeAddress: number,
): StaticReference["target"] {
  const resolution = resolveRuntimeAddress(map, runtimeAddress, processor);
  return {
    runtimeAddress,
    romOffset: resolution.status === "resolved"
      ? resolution.candidate.romOffset
      : null,
    resolution,
  };
}
```

Do not convert `RuntimeResolution` into `NdsCodeSourceResolution`; target ownership ambiguity/BSS/compression must preserve the exact resolver status.

- [ ] **Step 6: Implement classification from only one detailed instruction**

Direct flow:

```ts
if (
  (instruction.flow.kind === "conditional-branch"
    || instruction.flow.kind === "unconditional-branch")
  && instruction.flow.directTarget !== null
) {
  // direct-branch
}

if (
  instruction.flow.kind === "call"
  && instruction.flow.directTarget !== null
) {
  // direct-call
}
```

PC-relative semantics:

```ts
switch (decoded.pcRelative?.kind) {
  case "literal-load":
    target = addUint32(
      architecturalPc(instruction.address, instruction.mode),
      decoded.pcRelative.displacement,
    );
    kind = "literal-pool";
    mechanism = "pc-relative-literal-address";
    break;
  case "address-add":
    target = addUint32(
      architecturalPc(instruction.address, instruction.mode),
      decoded.pcRelative.immediate,
    );
    kind = "pc-relative-address";
    mechanism = "pc-relative-address-construction";
    break;
  case "address-sub":
    target = subUint32(
      architecturalPc(instruction.address, instruction.mode),
      decoded.pcRelative.immediate,
    );
    kind = "pc-relative-address";
    mechanism = "pc-relative-address-construction";
    break;
}
```

Never inspect literal memory contents or arbitrary immediates.

- [ ] **Step 7: Implement deterministic comparator**

Comparator order:

```text
processor arm9 before arm7
component main before overlay
overlay ID ascending
source instruction runtime address ascending
mode arm before thumb
reference kind lexical/stable explicit order
target runtime address ascending
```

Use an explicit reference-kind order array rather than relying on locale behavior.

- [ ] **Step 8: Verify GREEN**

```bash
node --test --import tsx tests/nds-references.test.ts tests/nds-disassembly.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/services/nds/references.ts tests/nds-references.test.ts
git commit -m "feat: classify proven NDS references"
```

---

### Task 4: Add bounded source-to-reference analysis

**Files:**
- Create: `src/services/nds/reference-list.ts`
- Create: `tests/nds-reference-list.test.ts`

**Consumes:** `disassembleNdsRangeDetailed()`, `classifyNdsInstructionReferences()`.

**Produces:**

```ts
export interface ListReferencesOptions {
  readonly maxInstructions: number;
  readonly maxBytes: number;
}

export type ListNdsReferencesResult =
  | Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>
  | {
      readonly status: "complete" | "decode-stopped" | "component-boundary";
      readonly source: NdsCodeSource;
      readonly instructionsExamined: number;
      readonly decodedBytes: number;
      readonly references: readonly StaticReference[];
    };

export async function listNdsReferences(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  options: ListReferencesOptions,
  backend: ArmDisassemblyBackend,
): Promise<ListNdsReferencesResult>;
```

- [ ] **Step 1: Write failing bounded-window tests**

Create a fixture with fake decoded instructions:

```text
0x02000000 direct call -> 0x02000010
0x02000004 ordinary MOV
0x02000008 ARM literal load -> pool slot 0x02000010
```

Assert:

```ts
const result = await listNdsReferences(
  map,
  { processor: "arm9", runtimeAddress: 0x02000000, mode: "arm" },
  { maxInstructions: 3, maxBytes: 12 },
  backend,
);
assert.equal(result.status, "complete");
if (result.status === "complete") {
  assert.equal(result.instructionsExamined, 3);
  assert.equal(result.decodedBytes, 12);
  assert.deepEqual(result.references.map((ref) => ref.kind), [
    "direct-call",
    "literal-pool",
  ]);
}
```

Add a one-instruction limit case proving the third instruction is not classified.

- [ ] **Step 2: Add source-policy propagation tests**

Use existing fixture patterns to assert that `listNdsReferences()` returns unchanged structured conditions for:

```text
mode-ambiguous
compressed-overlay-not-decodable
runtime-only-bss
ambiguous-code-source
```

without creating a backend-derived error.

- [ ] **Step 3: Add ROM-identity mutation test**

Use a fake backend whose first `decodeOne()` synchronously mutates one byte of `map.romPath` using `writeFileSync`/`readFileSync`, then returns a valid instruction. Assert:

```ts
await assert.rejects(
  () => listNdsReferences(...),
  (error: unknown) => error instanceof NdsError && error.category === "invalid-rom",
);
```

This proves the post-operation SHA check still occurs through the detailed linear reader.

- [ ] **Step 4: Prove RED**

```bash
node --test --import tsx tests/nds-reference-list.test.ts
```

Expected: FAIL because the service does not exist.

- [ ] **Step 5: Implement the service as a thin projection over detailed disassembly**

```ts
export async function listNdsReferences(...) {
  const result = await disassembleNdsRangeDetailed(map, location, options, backend);
  if (
    result.status === "ambiguous-code-source"
    || result.status === "compressed-overlay-not-decodable"
    || result.status === "runtime-only-bss"
    || result.status === "unmapped-address"
    || result.status === "mode-ambiguous"
  ) {
    return result;
  }

  const references = result.instructions.flatMap(
    (detailed) => [...classifyNdsInstructionReferences(map, detailed)],
  );
  return {
    status: result.status,
    source: result.source,
    instructionsExamined: result.instructions.length,
    decodedBytes: result.decodedBytes,
    references,
  };
}
```

Do not follow control-flow edges and do not re-open/re-hash the ROM outside `disassembleNdsRangeDetailed()`.

- [ ] **Step 6: Verify GREEN**

```bash
node --test --import tsx tests/nds-reference-list.test.ts tests/nds-references.test.ts tests/nds-disassembly.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/services/nds/reference-list.ts tests/nds-reference-list.test.ts
git commit -m "feat: add bounded NDS reference listing"
```

---

### Task 5: Canonicalize reverse-xref target, scope, and explicit seeds

**Files:**
- Modify: `src/services/nds/errors.ts`
- Create: `src/services/nds/xref-source.ts`
- Create: `tests/nds-xref-source.test.ts`

**Consumes:** `resolveRomOffset()`, `resolveRuntimeAddress()`, `resolveNdsCodeSource()`, `NdsRomMap` overlay metadata.

**Produces:**

```ts
export type NdsReferenceTargetSelector =
  | { readonly targetRuntimeAddress: number; readonly targetRomOffset?: never }
  | { readonly targetRomOffset: number; readonly targetRuntimeAddress?: never };

export type ReferenceSearchScope =
  | { readonly kind: "main" }
  | { readonly kind: "overlay"; readonly overlayIds: readonly number[] }
  | { readonly kind: "main-and-overlays"; readonly overlayIds: readonly number[] }
  | { readonly kind: "all-executable-components" };

export interface ReferenceSearchSeed {
  readonly runtimeAddress: number;
  readonly mode: ArmMode;
  readonly overlayId?: number;
}

export interface ReferenceComponentIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly compressed: boolean;
}

export interface CanonicalReferenceTarget {
  readonly requestedBy: "runtime-address" | "rom-offset";
  readonly runtimeAddress: number;
  readonly romOffset: number | null;
  readonly resolution: RuntimeResolution;
}

export interface PreparedReferenceSearch {
  readonly processor: NdsProcessor;
  readonly target: CanonicalReferenceTarget;
  readonly components: readonly ReferenceComponentIdentity[];
  readonly explicitSeeds: readonly NdsCodeSource[];
}

export function prepareNdsReferenceSearch(
  map: NdsRomMap,
  processor: NdsProcessor,
  target: NdsReferenceTargetSelector,
  scope: ReferenceSearchScope,
  seeds: readonly ReferenceSearchSeed[],
): PreparedReferenceSearch;
```

Add exact categories to `NdsErrorCategory`:

```text
ambiguous-reference-target
reference-target-not-runtime-addressable
invalid-reference-scope
invalid-reference-seed
reference-scan-limit-exceeded
```

- [ ] **Step 1: Write failing target canonicalization tests**

Runtime target:

```ts
const prepared = prepareNdsReferenceSearch(
  map,
  "arm9",
  { targetRuntimeAddress: 0x02000008 },
  { kind: "main" },
  [],
);
assert.equal(prepared.target.requestedBy, "runtime-address");
assert.equal(prepared.target.runtimeAddress, 0x02000008);
```

ROM offset with one unique ARM9 runtime mapping:

```ts
assert.equal(prepared.target.requestedBy, "rom-offset");
assert.equal(prepared.target.runtimeAddress, 0x02000008);
assert.equal(prepared.target.romOffset, 0x208);
```

Create overlapping ROM relationships that produce two distinct ARM9 runtime addresses and assert `NdsError.category === "ambiguous-reference-target"`.

Use a NitroFS-only/structural offset and assert `reference-target-not-runtime-addressable`.

- [ ] **Step 2: Write failing deterministic scope tests**

Construct overlays IDs 9, 3, and 7. Assert exact order:

```ts
assert.deepEqual(
  prepared.components.map((component) => [component.component, component.overlayId]),
  [["main", null], ["overlay", 3], ["overlay", 7], ["overlay", 9]],
);
```

For explicit overlay scopes, reject:

```text
duplicate overlay IDs
unknown overlay ID for selected processor
empty overlayIds for kind=overlay
empty overlayIds for kind=main-and-overlays (main-only must use kind=main)
```

with `invalid-reference-scope` except an existing more-specific parser invariant that is demonstrably preferable.

- [ ] **Step 3: Write failing explicit-seed tests**

Valid overlay seed:

```ts
{
  runtimeAddress: 0x02200000,
  mode: "thumb",
  overlayId: 7,
}
```

must resolve to one `NdsCodeSource` in selected scope.

Reject with `invalid-reference-seed` when the seed is:

```text
outside selected scope
other processor
wrong overlayId
BSS
compressed overlay
misaligned for mode
ambiguous without sufficient overlay disambiguation
```

Duplicate identical valid seeds should be canonicalized/deduplicated by code-source identity, not treated as an error.

- [ ] **Step 4: Prove RED**

```bash
node --test --import tsx tests/nds-xref-source.test.ts
```

Expected: FAIL because reference error categories and preparation service do not exist.

- [ ] **Step 5: Add the exact reference error categories**

Extend `src/services/nds/errors.ts` union with the five categories from **Produces**. Do not replace established categories such as `unknown-overlay-id`; this task's service chooses the reference-specific category at its public policy boundary.

- [ ] **Step 6: Implement target canonicalization**

Runtime selector:

```ts
const resolution = resolveRuntimeAddress(map, targetRuntimeAddress, processor);
return {
  requestedBy: "runtime-address",
  runtimeAddress: targetRuntimeAddress,
  romOffset: resolution.status === "resolved" ? resolution.candidate.romOffset : null,
  resolution,
};
```

ROM selector:

```ts
const matches = resolveRomOffset(map, targetRomOffset).matches.filter((match) => {
  if (match.runtimeAddress === null) return false;
  return processor === "arm9"
    ? match.kind === "arm9-main" || match.kind === "arm9-overlay"
    : match.kind === "arm7-main" || match.kind === "arm7-overlay";
});
const addresses = [...new Set(matches.map((match) => match.runtimeAddress!))].sort(
  (left, right) => left - right,
);
```

- zero addresses => `reference-target-not-runtime-addressable`;
- more than one => `ambiguous-reference-target`;
- exactly one => call `resolveRuntimeAddress(map, address, processor)` and preserve that `RuntimeResolution`.

- [ ] **Step 7: Implement deterministic scope expansion**

Use main first when included. Sort overlay IDs numerically ascending. Validate uniqueness/existence before producing components. Store each overlay's actual `compressed` flag.

- [ ] **Step 8: Validate explicit seeds through existing code-source policy**

For each seed call:

```ts
resolveNdsCodeSource(map, {
  processor,
  runtimeAddress: seed.runtimeAddress,
  mode: seed.mode,
  ...(seed.overlayId === undefined ? {} : { overlayId: seed.overlayId }),
});
```

Require `status === "resolved"` and component membership in selected scope. Any non-resolved status at this explicit-seed boundary becomes `invalid-reference-seed` with the original status named in the message. Deduplicate resolved seed sources by:

```text
processor:component:overlayId-or-main:runtimeAddressHex:mode
```

- [ ] **Step 9: Verify GREEN**

```bash
node --test --import tsx tests/nds-xref-source.test.ts tests/nds-disassembly-source.test.ts tests/nds-resolver.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/services/nds/errors.ts src/services/nds/xref-source.ts tests/nds-xref-source.test.ts
git commit -m "feat: prepare bounded NDS xref searches"
```

---

### Task 6: Implement bounded reverse-xref traversal with call-following and coverage accounting

**Files:**
- Create: `src/services/nds/xrefs.ts`
- Create: `tests/nds-xrefs.test.ts`

**Consumes:** `prepareNdsReferenceSearch()`, `decodeNdsInstructionDetailed()`, `classifyNdsInstructionReferences()`, `withValidatedNdsRomReader()`, `codeSourceAt()`.

**Produces:**

```ts
export interface ReferenceScanLimits {
  readonly maxComponents: number;
  readonly maxBlocks: number;
  readonly maxInstructions: number;
  readonly maxBytes: number;
  readonly maxEdges: number;
  readonly maxXrefs: number;
}

export type ReferenceTruncationReason =
  | "component-limit"
  | "block-limit"
  | "instruction-limit"
  | "byte-limit"
  | "edge-limit"
  | "result-limit";

export type ComponentCoverageStatus =
  | "scanned"
  | "no-proven-seed"
  | "compressed-overlay-not-decodable"
  | "out-of-limit";

export interface ReferenceComponentCoverage {
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly status: ComponentCoverageStatus;
}

export interface FindNdsXrefsRequest {
  readonly processor: NdsProcessor;
  readonly target: NdsReferenceTargetSelector;
  readonly scope: ReferenceSearchScope;
  readonly seeds: readonly ReferenceSearchSeed[];
}

export interface FindNdsXrefsResult {
  readonly status: "complete" | "partial-coverage" | "truncated";
  readonly target: CanonicalReferenceTarget;
  readonly scan: {
    readonly processor: NdsProcessor;
    readonly componentsRequested: number;
    readonly componentsScanned: number;
    readonly blocksDecoded: number;
    readonly instructionsDecoded: number;
    readonly decodedBytes: number;
    readonly traversalEdges: number;
  };
  readonly coverage: readonly ReferenceComponentCoverage[];
  readonly truncationReasons: readonly ReferenceTruncationReason[];
  readonly xrefs: readonly StaticReference[];
}

export async function findNdsXrefs(
  map: NdsRomMap,
  request: FindNdsXrefsRequest,
  limits: ReferenceScanLimits,
  backend: ArmDisassemblyBackend,
): Promise<FindNdsXrefsResult>;
```

- [ ] **Step 1: Write failing direct-flow and call-following traversal tests**

Use a fake backend and ARM9 main fixture with this graph:

```text
0x02000000: BL  0x02000010
0x02000004: BNE 0x0200000c
0x02000008: BX  LR       (conditional fallthrough block)
0x0200000c: BX  LR       (taken block)
0x02000010: B   0x02000018 (callee reached only because direct calls are followed)
0x02000018: BX  LR
```

Search for target `0x02000010` and assert one `direct-call` xref from `0x02000000`.

Search for target `0x02000018` and assert one `direct-branch` xref from `0x02000010`, proving the callee was scanned.

- [ ] **Step 2: Prove existing CFG call policy is unchanged in a companion regression assertion**

In `tests/nds-xrefs.test.ts`, call existing `analyzeNdsControlFlow()` on the same direct-call fixture and assert the call target is **not** present as a discovered block solely because of the call:

```ts
assert.equal(
  cfg.blocks.some((block) => block.startAddress === 0x02000010),
  false,
);
```

This test must remain green after `findNdsXrefs()` is implemented; do not modify `control-flow.ts` to make the xref scanner work.

- [ ] **Step 3: Write failing indirect/scope/overlay tests**

Assert:

```text
BLX r3: no target xref and unknown callee not queued; caller fallthrough continues
BX r3 / BX lr: terminate current block
proven direct target outside selected scope: reference can match requested target but target block is not queued
explicitly seeded uncompressed overlay: scanned
selected overlay without any proven seed: no-proven-seed
selected compressed overlay: compressed-overlay-not-decodable
same proven block reached twice: decoded once
cycle A -> B -> A: terminates deterministically
```

- [ ] **Step 4: Write failing component-limit and global budget tests**

Component ordering must be main then overlay IDs ascending. With four requested components and `maxComponents: 2`, assert:

```ts
assert.equal(result.status, "truncated");
assert.deepEqual(result.truncationReasons, ["component-limit"]);
assert.deepEqual(result.coverage.slice(2).map((entry) => entry.status), [
  "out-of-limit",
  "out-of-limit",
]);
```

Add separate fixtures for:

```text
block-limit
instruction-limit
byte-limit
edge-limit
```

and assert each returns valid already-proven xrefs plus the exact ordered reason list.

Reason order is fixed:

```ts
const TRUNCATION_REASON_ORDER = [
  "component-limit",
  "block-limit",
  "instruction-limit",
  "byte-limit",
  "edge-limit",
  "result-limit",
] as const;
```

- [ ] **Step 5: Write failing result-limit ordering test**

Construct at least four xrefs whose discovery order is not the same as `compareStaticReferences()` order. Run with `maxXrefs: 2` and assert:

```ts
assert.equal(result.status, "truncated");
assert.equal(result.truncationReasons.includes("result-limit"), true);
assert.deepEqual(result.xrefs, allReferences.sort(compareStaticReferences).slice(0, 2));
```

The implementation therefore must **not** stop at the first `maxXrefs` discoveries. It must continue bounded scanning and retain the smallest deterministic `maxXrefs` references while counting whether additional matches existed.

- [ ] **Step 6: Write failing status/coverage precedence tests**

Assert:

```text
all selected components explored + no truncation => complete
one selected overlay no-proven-seed + no truncation => partial-coverage
compressed selected overlay + no truncation => partial-coverage
coverage gap + any truncation reason => truncated
zero xrefs + complete => valid complete negative for selected scope
zero xrefs + partial/truncated => result metadata remains explicitly incomplete
```

- [ ] **Step 7: Write failing ROM-identity mutation test**

Use a fake backend that mutates `map.romPath` during the first decode. Assert `findNdsXrefs()` rejects with `NdsError("invalid-rom", ...)` rather than returning accumulated xrefs.

- [ ] **Step 8: Prove RED**

```bash
node --test --import tsx tests/nds-xrefs.test.ts
```

Expected: FAIL because `findNdsXrefs()` does not exist.

- [ ] **Step 9: Implement strict limit validation**

Use positive safe-integer validation for all six limits. Invalid internal/service limits throw `NdsError("reference-scan-limit-exceeded", ...)`; public Zod max/default enforcement is added in Task 7.

- [ ] **Step 10: Apply component budget deterministically**

After `prepareNdsReferenceSearch()`:

```ts
const considered = prepared.components.slice(0, limits.maxComponents);
const excluded = prepared.components.slice(limits.maxComponents);
```

If `excluded.length > 0`, add `component-limit` and initialize those coverage entries as `out-of-limit`.

Compressed components inside `considered` initialize as `compressed-overlay-not-decodable` and are never queued.

- [ ] **Step 11: Build the initial FIFO seed queue**

When selected/considered main exists, resolve its header entry as an ARM source:

```ts
resolveNdsCodeSource(map, {
  processor: request.processor,
  runtimeAddress: request.processor === "arm9"
    ? map.header.arm9.entryAddress
    : map.header.arm7.entryAddress,
  mode: "arm",
});
```

Add valid prepared explicit seeds whose component is considered. Deduplicate with the existing block identity:

```text
processor:component:overlayId-or-main:runtimeAddressHex:mode
```

- [ ] **Step 12: Implement FIFO block traversal under one `withValidatedNdsRomReader()`**

Use `queue`, `scheduled`, and `visited` sets analogous to the existing CFG implementation but in the new file.

Per instruction:

```ts
const detailed = decodeNdsInstructionDetailed(map, currentSource, bytes.subarray(cursor), backend);
const references = detailed === null
  ? []
  : classifyNdsInstructionReferences(map, detailed);
```

Feed only references whose `target.runtimeAddress === prepared.target.runtimeAddress` into the bounded result collector.

Traversal policy:

```text
fallthrough -> continue sequentially
call -> count one traversal edge and schedule resolved in-scope call target; continue caller
indirect-call -> continue caller, no target edge
conditional-branch -> taken edge first, then valid same-component fallthrough edge; terminate block
unconditional-branch -> one target edge; terminate block
return/indirect-branch -> terminate block
```

A direct target is schedulable only if `detailed.instruction.targetResolution?.status === "resolved"`, its source component is selected+considered, and it is same processor. No target ownership is guessed from `StaticReference.target.resolution`.

- [ ] **Step 13: Enforce edge and block caps independently**

Before recording/scheduling a traversal edge:

```ts
if (totalEdges >= limits.maxEdges) {
  reasons.add("edge-limit");
  return false;
}
```

Count the edge once accepted even when the target block was already scheduled. Before scheduling a new block identity:

```ts
if (scheduled.size >= limits.maxBlocks) {
  reasons.add("block-limit");
  return null;
}
```

A direct call whose target cannot be scheduled due a cap still allows valid caller fallthrough.

- [ ] **Step 14: Enforce global instruction/byte budgets without discarding queued evidence**

Before decoding each next instruction, stop that block when the corresponding budget is exhausted and add the reason. Once no instruction/byte budget remains globally, stop processing further queue entries and mark any component with scheduled-but-unvisited work as `out-of-limit`.

Components whose complete reachable work was processed remain `scanned` even if another component caused truncation.

- [ ] **Step 15: Implement bounded deterministic xref collection**

Track:

```ts
let totalMatchingReferences = 0;
const retained: StaticReference[] = [];
```

For each matching reference:

```ts
totalMatchingReferences += 1;
retained.push(reference);
retained.sort(compareStaticReferences);
if (retained.length > limits.maxXrefs) {
  retained.pop();
}
```

After scanning:

```ts
if (totalMatchingReferences > limits.maxXrefs) {
  reasons.add("result-limit");
}
```

This guarantees the returned list is the deterministic sorted prefix without unbounded xref storage.

- [ ] **Step 16: Finalize component coverage**

For each considered non-compressed component:

- if no valid seed was ever scheduled for it => `no-proven-seed`;
- if it had unvisited scheduled work or a block in it stopped due a global cap => `out-of-limit`;
- otherwise, if its seeded reachable work completed => `scanned`.

Do not convert an unseeded overlay into `scanned` merely because it was selected.

- [ ] **Step 17: Finalize result status and totals**

```ts
const truncationReasons = TRUNCATION_REASON_ORDER.filter((reason) => reasons.has(reason));
const hasCoverageGap = coverage.some((entry) => entry.status !== "scanned");
const status = truncationReasons.length > 0
  ? "truncated"
  : hasCoverageGap
    ? "partial-coverage"
    : "complete";
```

`componentsScanned` counts only `status === "scanned"`.

- [ ] **Step 18: Verify GREEN and existing CFG regression**

```bash
node --test --import tsx tests/nds-xrefs.test.ts tests/nds-control-flow.test.ts tests/nds-references.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 19: Commit**

```bash
git add src/services/nds/xrefs.ts tests/nds-xrefs.test.ts
git commit -m "feat: add bounded NDS xref scanning"
```

---

### Task 7: Expose the two reference MCP tools and eleven-tool capability surface

**Files:**
- Modify: `src/tools/nds.ts`
- Modify: `src/index.ts`
- Modify: `tests/nds-tools.test.ts`

**Consumes:** `listNdsReferences()`, `findNdsXrefs()`, new `NdsErrorCategory` values.

**Produces:** public tools:

```text
nds_list_references
nds_find_xrefs
```

Public schema constants:

```ts
const xrefComponentLimitSchema = z.number().int().min(1).max(128).default(32);
const xrefBlockLimitSchema = z.number().int().min(1).max(512).default(128);
const xrefInstructionLimitSchema = z.number().int().min(1).max(16384).default(2048);
const xrefByteLimitSchema = z.number().int().min(2).max(65536).default(8192);
const xrefEdgeLimitSchema = z.number().int().min(1).max(4096).default(512);
const xrefResultLimitSchema = z.number().int().min(1).max(2048).default(256);
```

- [ ] **Step 1: Update tool-registration expectations first**

Change `EXPECTED_TOOLS` in `tests/nds-tools.test.ts` to include the two new names and rename the test to:

```ts
test("registers exactly the eleven approved NDS static-analysis tools", () => {
  const server = register("/workspace");
  assert.deepEqual([...server.tools.keys()].sort(), [...EXPECTED_TOOLS].sort());
});
```

- [ ] **Step 2: Add failing schema/default/safety assertions**

`nds_list_references` default parse:

```ts
assert.deepEqual(server.parse("nds_list_references", {
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
```

`nds_find_xrefs` default parse:

```ts
assert.deepEqual(server.parse("nds_find_xrefs", {
  rom: "game.nds",
  processor: "arm9",
  targetRuntimeAddress: 0x02000008,
  scope: { kind: "main" },
}), {
  rom: "game.nds",
  processor: "arm9",
  targetRuntimeAddress: 0x02000008,
  scope: { kind: "main" },
  seeds: [],
  maxComponents: 32,
  maxBlocks: 128,
  maxInstructions: 2048,
  maxBytes: 8192,
  maxEdges: 512,
  maxXrefs: 256,
});
```

For both schemas assert absence of:

```text
binary
bytes
baseAddress
output
path
length
```

Also assert xref max+1 values fail Zod validation.

- [ ] **Step 3: Add failing exact target-selector and scope schemas**

Define xref target inputs with two optional public fields and normalize in the handler/service, then test that providing both or neither returns a structured `range-out-of-bounds`/validation error before scanning.

Scope schema:

```ts
const referenceScopeSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("main") }),
  z.object({
    kind: z.literal("overlay"),
    overlayIds: z.array(uint32Schema).min(1).max(128),
  }),
  z.object({
    kind: z.literal("main-and-overlays"),
    overlayIds: z.array(uint32Schema).min(1).max(128),
  }),
  z.object({ kind: z.literal("all-executable-components") }),
]);
```

Seed schema:

```ts
const referenceSeedSchema = z.object({
  runtimeAddress: uint32Schema,
  mode: z.enum(["arm", "thumb"]),
  overlayId: uint32Schema.optional(),
});
```

Use:

```ts
seeds: z.array(referenceSeedSchema).max(512).default([])
```

so caller input itself is bounded by the maximum block budget.

- [ ] **Step 4: Add failing real-handler integration fixture**

Change/create `buildReferenceRom()`:

```ts
fixture.buffer.set([0x00, 0x00, 0x00, 0xeb], 0x200); // ARM BL from 0x02000000 to 0x02000008
fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x204); // BX LR caller fallthrough
fixture.buffer.set([0x1e, 0xff, 0x2f, 0xe1], 0x208); // BX LR callee
```

Invoke:

```ts
const listed = resultBody(await server.invoke("nds_list_references", {
  rom,
  processor: "arm9",
  runtimeAddress: 0x02000000,
  mode: "arm",
  maxInstructions: 1,
  maxBytes: 4,
}));
assert.equal((listed.references as Array<Record<string, unknown>>)[0]?.kind, "direct-call");

const xrefs = resultBody(await server.invoke("nds_find_xrefs", {
  rom,
  processor: "arm9",
  targetRuntimeAddress: 0x02000008,
  scope: { kind: "main" },
  maxComponents: 1,
  maxBlocks: 8,
  maxInstructions: 16,
  maxBytes: 64,
  maxEdges: 16,
  maxXrefs: 8,
}));
assert.equal(xrefs.status, "complete");
assert.equal((xrefs.xrefs as Array<Record<string, unknown>>).length, 1);
```

- [ ] **Step 5: Prove RED**

```bash
node --test --import tsx tests/nds-tools.test.ts
```

Expected: FAIL because only nine NDS tools are registered.

- [ ] **Step 6: Add schemas/imports and normalize xref target**

Import the two services/types. Add the exact limit/scope/seed schemas above.

Normalize target in the handler:

```ts
const hasRuntimeTarget = targetRuntimeAddress !== undefined;
const hasRomTarget = targetRomOffset !== undefined;
if (hasRuntimeTarget === hasRomTarget) {
  throw new NdsError(
    "range-out-of-bounds",
    "Reference search requires exactly one of targetRuntimeAddress or targetRomOffset",
  );
}
const target = hasRuntimeTarget
  ? { targetRuntimeAddress: targetRuntimeAddress! }
  : { targetRomOffset: targetRomOffset! };
```

- [ ] **Step 7: Register `nds_list_references`**

Description must say bounded, deterministic/proven, NDS-mapped references.

Handler pattern:

```ts
const map = await readNdsRomMap(resolveRom(config, rom));
const backend = await createCapstoneArmBackend();
try {
  const result = await listNdsReferences(
    map,
    normalizeDisassemblyLocation(...),
    { maxInstructions, maxBytes },
    backend,
  );
  return boundedTextResult(config, operation, result);
} finally {
  backend.close();
}
```

- [ ] **Step 8: Register `nds_find_xrefs`**

Description must mention caller-selected static scope, proven seeds, bounded coverage, and no loaded-overlay inference.

Handler:

```ts
const result = await findNdsXrefs(
  map,
  {
    processor,
    target,
    scope,
    seeds,
  },
  {
    maxComponents,
    maxBlocks,
    maxInstructions,
    maxBytes,
    maxEdges,
    maxXrefs,
  },
  backend,
);
```

Close backend in `finally` exactly like existing disassembly tools.

- [ ] **Step 9: Add corrective actions for reference-specific categories**

Extend `correctiveAction()` with exact guidance:

```ts
case "ambiguous-reference-target":
  return "Use a runtime address or a ROM offset that maps to exactly one runtime address for the selected processor.";
case "reference-target-not-runtime-addressable":
  return "Choose a runtime-mapped ARM9/ARM7 target; ordinary structural/NitroFS ROM bytes are not reverse-xref targets in this milestone.";
case "invalid-reference-scope":
  return "Choose main, existing overlay IDs for the selected processor, or all executable components without duplicate overlay IDs.";
case "invalid-reference-seed":
  return "Use an aligned ARM/Thumb seed that resolves uniquely to selected uncompressed file-backed code.";
case "reference-scan-limit-exceeded":
  return "Use valid positive bounded scan limits; internal reference-scan limit invariants must not be bypassed.";
```

- [ ] **Step 10: Update `server_capabilities`**

Change `ndsStaticAnalysisPolicy` so it explicitly includes bounded deterministic instruction-aware reference/xref analysis and says:

```text
only deterministic single-instruction references
bounded reverse-xref search may report partial coverage
direct calls may expand xref coverage without changing CFG call traversal
no loaded-overlay inference
generic binary/pattern search and heuristic pointer discovery are not provided
```

Insert the two tool names in the NDS tool section of `tools`.

- [ ] **Step 11: Verify GREEN**

```bash
node --test --import tsx tests/nds-tools.test.ts tests/nds-reference-list.test.ts tests/nds-xrefs.test.ts
npm run typecheck
```

Expected: PASS.

- [ ] **Step 12: Commit**

```bash
git add src/tools/nds.ts src/index.ts tests/nds-tools.test.ts
git commit -m "feat: expose NDS reference discovery tools"
```

---

### Task 8: Extend assembled-package acceptance to the reference classifier

**Files:**
- Modify: `scripts/check-install.mjs`
- Modify: `tests/package-capstone-install.test.ts`
- Verify unchanged: `.github/workflows/package.yml`

**Consumes:** packaged `createCapstoneArmBackend()`, `decodeNdsInstructionDetailed()`, `classifyNdsInstructionReferences()`.

**Produces:** assembled-bundle smoke proof for one ARM direct reference and one Thumb PC-relative reference.

- [ ] **Step 1: Write failing package-verifier source assertions**

Add to `tests/package-capstone-install.test.ts`:

```ts
test("install verifier smoke-classifies packaged ARM and Thumb references", async () => {
  const source = await readFile(path.resolve("scripts/check-install.mjs"), "utf8");
  assert.equal(source.includes("dist/services/nds/disassembly.js"), true);
  assert.equal(source.includes("dist/services/nds/references.js"), true);
  assert.equal(source.includes("Packaged ARM direct reference smoke failed"), true);
  assert.equal(source.includes("Packaged Thumb PC-relative reference smoke failed"), true);
});
```

Also assert the existing package workflow still contains:

```text
Assemble and smoke-test self-contained bundle
npm install --omit=dev --ignore-scripts
node scripts/check-install.mjs .
```

- [ ] **Step 2: Prove RED**

```bash
node --test --import tsx tests/package-capstone-install.test.ts
```

Expected: FAIL because `check-install.mjs` does not import/classify reference services.

- [ ] **Step 3: Require built reference service files**

Add:

```js
"dist/services/nds/disassembly.js",
"dist/services/nds/references.js",
```

to `required` in `scripts/check-install.mjs`.

- [ ] **Step 4: Import built detailed decode and reference classifier from the assembled root**

```js
const disassemblyUrl = pathToFileURL(
  path.join(root, "dist/services/nds/disassembly.js"),
).href;
const referencesUrl = pathToFileURL(
  path.join(root, "dist/services/nds/references.js"),
).href;
const { decodeNdsInstructionDetailed } = await import(disassemblyUrl);
const { classifyNdsInstructionReferences } = await import(referencesUrl);
```

- [ ] **Step 5: Build the minimal synthetic canonical map/source required for pure decode/classification**

Inside `check-install.mjs` use plain runtime objects:

```js
const arm9 = {
  ramAddress: 0x02000000,
  ramEnd: 0x02000100,
  romOffset: 0x200,
  romEnd: 0x300,
};
const map = {
  header: {
    arm9,
    arm7: {
      ramAddress: 0x03800000,
      ramEnd: 0x03800100,
      romOffset: 0x600,
      romEnd: 0x700,
    },
  },
  overlays: { arm9: [], arm7: [] },
};
function sourceAt(runtimeAddress, mode) {
  return {
    processor: "arm9",
    component: "main",
    overlayId: null,
    runtimeAddress,
    romOffset: 0x200 + (runtimeAddress - 0x02000000),
    runtimeStart: 0x02000000,
    runtimeEnd: 0x02000100,
    romStart: 0x200,
    romEnd: 0x300,
    mode,
  };
}
```

Only fields actually consumed by `decodeNdsInstructionDetailed()`/`resolveRuntimeAddress()` are required; do not import source-tree fixtures.

- [ ] **Step 6: Smoke-classify a real packaged ARM direct call**

```js
const armDetailed = decodeNdsInstructionDetailed(
  map,
  sourceAt(0x02000000, "arm"),
  Uint8Array.from([0x00, 0x00, 0x00, 0xeb]),
  backend,
);
const armRefs = armDetailed === null
  ? []
  : classifyNdsInstructionReferences(map, armDetailed);
if (
  armRefs.length !== 1
  || armRefs[0]?.kind !== "direct-call"
  || armRefs[0]?.target.runtimeAddress !== 0x02000008
) {
  throw new Error("Packaged ARM direct reference smoke failed");
}
```

- [ ] **Step 7: Smoke-classify a real packaged Thumb literal reference with alignment**

```js
const thumbDetailed = decodeNdsInstructionDetailed(
  map,
  sourceAt(0x02000002, "thumb"),
  Uint8Array.from([0x00, 0x48]),
  backend,
);
const thumbRefs = thumbDetailed === null
  ? []
  : classifyNdsInstructionReferences(map, thumbDetailed);
if (
  thumbRefs.length !== 1
  || thumbRefs[0]?.kind !== "literal-pool"
  || thumbRefs[0]?.target.runtimeAddress !== 0x02000004
) {
  throw new Error("Packaged Thumb PC-relative reference smoke failed");
}
```

Keep the existing packaged `BX LR` ARM/Thumb decoder smoke checks as well.

- [ ] **Step 8: Verify GREEN locally at source-test level**

```bash
node --test --import tsx tests/package-capstone-install.test.ts
npm run build
```

Expected: PASS.

- [ ] **Step 9: Verify the real assembled-package command**

Run the same sequence as `.github/workflows/package.yml` in a clean temporary bundle directory:

```bash
npm run build
rm -rf /tmp/re-mcp-package-smoke
mkdir -p /tmp/re-mcp-package-smoke/dist
cp -R dist/src/. /tmp/re-mcp-package-smoke/dist/
cp package.json /tmp/re-mcp-package-smoke/package.json
mkdir -p /tmp/re-mcp-package-smoke/scripts
cp scripts/check-install.mjs /tmp/re-mcp-package-smoke/scripts/check-install.mjs
cd /tmp/re-mcp-package-smoke
npm install --omit=dev --ignore-scripts
node scripts/check-install.mjs .
```

Expected: JSON with `"ok": true`; no network/runtime decoder download after installation and no source-checkout import path.

If the workflow's exact assembly copy list differs, follow `.github/workflows/package.yml` literally; the acceptance condition is that the **assembled artifact** passes `node scripts/check-install.mjs .`.

- [ ] **Step 10: Commit**

```bash
git add scripts/check-install.mjs tests/package-capstone-install.test.ts
git commit -m "test: smoke-classify packaged NDS references"
```

---

### Task 9: Document the feature and run the full final audit

**Files:**
- Modify: `README.md`
- Verify: `src/index.ts`
- Verify: all new/modified tests and production files

**Consumes:** completed eleven-tool implementation and package acceptance.

**Produces:** documentation consistent with the approved design and verified final branch.

- [ ] **Step 1: Update README tool inventory**

Document exactly eleven NDS static tools, adding:

```text
nds_list_references
nds_find_xrefs
```

Do not describe raw pattern/signature search as implemented.

- [ ] **Step 2: Add the proven-reference semantics section**

README must explicitly name all four kinds:

```text
direct-branch
direct-call
literal-pool
pc-relative-address
```

State:

```text
literal-pool means the architecturally computed pool-slot address only
literal contents are not interpreted as pointers
ordinary pointer-looking immediates are not references
register/data-flow inference is not performed
```

- [ ] **Step 3: Document source-to-reference versus target-to-xref behavior**

Include:

```text
nds_list_references = bounded sequential window, no branch/call traversal
nds_find_xrefs = bounded proven-code traversal inside explicit same-processor static scope
```

State that reverse-xref calls may be followed for coverage even though `nds_analyze_control_flow` still does not traverse calls.

- [ ] **Step 4: Document reverse-search scope/seeds/coverage**

Explain:

```text
main has a deterministic ARM header-entry seed
overlays require explicit ARM/Thumb seed or proven direct branch/call seed
all-executable-components is static scope, not loaded-overlay state
compressed overlays are never decoded
```

Document status meanings:

```text
complete
partial-coverage
truncated
```

and coverage statuses:

```text
scanned
no-proven-seed
compressed-overlay-not-decodable
out-of-limit
```

State that zero xrefs is definitive for selected scope only when `status === "complete"`.

- [ ] **Step 5: Document exact bounds**

Source window:

```text
instructions 32 default / 256 max
bytes 128 / 1024
```

Reverse xref:

```text
components 32 / 128
blocks 128 / 512
instructions 2048 / 16384
bytes 8192 / 65536
edges 512 / 4096
xrefs 256 / 2048
```

- [ ] **Step 6: Document target and safety semantics**

State:

```text
runtime target may retain ambiguous/BSS/compressed/unmapped ownership metadata
ROM-offset target must resolve to one unique runtime address for the selected processor
no persistent xref index
generic binary/pattern search is deferred
no ROM mutation/rebuild/output-path surface
physical Catalina/DeSmuME acceptance remains separate
```

- [ ] **Step 7: Run focused feature tests**

```bash
node --test --import tsx \
  tests/disassembly-backend.test.ts \
  tests/nds-disassembly.test.ts \
  tests/nds-references.test.ts \
  tests/nds-reference-list.test.ts \
  tests/nds-xref-source.test.ts \
  tests/nds-xrefs.test.ts \
  tests/nds-tools.test.ts \
  tests/package-capstone-install.test.ts
```

Expected: PASS.

- [ ] **Step 8: Run the complete repository verification**

```bash
npm run typecheck
npm test
npm run build
```

Expected: all commands exit `0`.

- [ ] **Step 9: Re-run assembled production package acceptance**

Run the exact package assembly/smoke sequence from Task 8 / `.github/workflows/package.yml` and require:

```text
node scripts/check-install.mjs . => success / { ok: true }
```

- [ ] **Step 10: Audit the public NDS tool surface and dependency pin**

```bash
grep -n 'nds_list_references\|nds_find_xrefs\|nds_analyze_control_flow' src/tools/nds.ts src/index.ts README.md
grep -n '"@alexaltea/capstone-js": "5.0.9"' package.json
```

Expected: both new tools documented/registered, existing CFG still present, dependency remains exact `5.0.9`.

- [ ] **Step 11: Audit forbidden scope drift**

```bash
git diff --check main...HEAD
git diff --name-only main...HEAD
```

Review the diff and confirm no implementation adds:

```text
generic binary/path input
raw caller byte input
literal-value pointer inference
arbitrary immediate pointer inference
function discovery
persistent xref index
compressed-overlay decompression
ROM mutation/rebuild
DeSmuME acceptance claims
```

- [ ] **Step 12: Commit documentation**

```bash
git add README.md
git commit -m "docs: document NDS reference discovery"
```

- [ ] **Step 13: Final verification after the documentation commit**

```bash
npm run typecheck
npm test
npm run build
git status --short
```

Expected: all verification commands pass and working tree is clean.

---

## Final Review Checklist

Before declaring the milestone complete, verify each approved design requirement has direct evidence:

- [ ] only proven single-instruction references are emitted;
- [ ] direct branch/call reference classification is shared;
- [ ] ARM literal PC uses `address + 8`;
- [ ] Thumb literal/address PC uses word-aligned `address + 4`;
- [ ] deterministic PC-relative address construction works;
- [ ] literal contents and pointer-looking immediates are ignored;
- [ ] `RuntimeResolution` ambiguity/BSS/compression/unmapped statuses are preserved on reference targets;
- [ ] source listing is bounded and sequential only;
- [ ] reverse target supports runtime address or uniquely runtime-mapped ROM offset;
- [ ] reverse scope is caller-selected and processor-separated;
- [ ] overlay decoding requires proven/explicit mode seed;
- [ ] reverse scanner follows direct calls but existing CFG does not;
- [ ] indirect targets are never guessed;
- [ ] component, block, instruction, byte, edge, and result limits are deterministic;
- [ ] result-limit returns the sorted deterministic prefix rather than discovery-order prefix;
- [ ] `complete` / `partial-coverage` / `truncated` and per-component coverage are correct;
- [ ] ROM identity is checked before and after both top-level operations;
- [ ] NDS MCP surface is exactly eleven tools;
- [ ] package artifact initializes bundled Capstone.js/WASM and classifies ARM + Thumb reference fixtures;
- [ ] README/server capabilities match implementation;
- [ ] no physical Catalina/DeSmuME acceptance claim is added.
