# NDS Controlled Ghidra Inspection Design

Date: 2026-08-07
Status: approved-by-direction; recommended choices selected without repeated option gates
Base: `main` after controlled NDS Ghidra integration (PR #25)

## Goal

Add a narrow, strictly read-only inspection layer over an already-current RE-MCP-owned Ghidra project so callers can retrieve Ghidra-derived function metadata, decompiler output, symbols, references, and direct call relationships without exposing arbitrary Ghidra commands or allowing Ghidra inferences to become canonical RE-MCP facts.

This milestone remains independent of the pending physical Catalina/DeSmuME debugger acceptance gate.

## Selected architecture

Use the existing validated `support/analyzeHeadless` installation and SHA-scoped persistent project, but invoke inspection only in Ghidra **read-only** and **no-analysis** processing mode.

Every inspection invocation must include:

```text
-process <canonical RE-MCP program name>
-readOnly
-noanalysis
-scriptPath <RE-MCP-owned resource directory>
-postScript ReMcpInspectProgram.java <request.json> <result.json>
```

The inspection script is RE-MCP-owned and purpose-built. It receives no caller-selected script name, project path, program name, address-space name, executable, CLI argument vector, environment variable map, or output path.

Ghidra's read-only processing contract discards program changes when headless processing exits. `-noanalysis` additionally prevents a new auto-analysis pass. The Java inspection script is itself constrained to read APIs and may only write one bounded result artifact outside the persistent Ghidra project.

Official API references used for this design:

- `HeadlessOptions.enableReadOnlyProcessing(boolean)` — read-only processing discards changes on exit.
- `HeadlessOptions.enableAnalysis(boolean)` — auto-analysis can be disabled.
- `HeadlessAnalyzer.processLocal(...)` — processes existing project programs with pre/post scripts.
- `HeadlessScript` — headless script lifecycle and read-only support.

## Strict readiness gate

Inspection never bootstraps or reconciles Ghidra implicitly.

Before Ghidra is launched, RE-MCP must verify all of the following:

1. the ROM path resolves inside `RE_MCP_WORKSPACE_ROOT`;
2. the current source ROM SHA-256 matches the canonical NDS map;
3. the full-SHA Ghidra project has both `.gpr` and `.rep` markers;
4. `latest-success.json` exists, belongs to the same full ROM SHA, and contains both ARM9 and ARM7 completed processors;
5. `latest-run.json` also represents a complete matching success rather than an interrupted/reconciling run;
6. no later `latest-failure.json` indicates a failed reconciliation after the last trusted success;
7. the generated Ghidra bridge manifest exists and its actual SHA-256 matches the trusted success state's `manifestSha256`;
8. the configured Ghidra installation validates successfully;
9. the configured Ghidra version exactly matches the version recorded by the trusted project state.

If any requirement fails, inspection returns `ghidra-project-not-current` or a more specific existing Ghidra configuration/state error. The corrective action is to run `nds_ghidra_bootstrap`; inspection does not do that automatically.

This intentionally prefers a false refusal over inspecting uncertain or partially reconciled project state.

## Canonical selector model

Callers never address raw Ghidra internals.

Address-oriented tools accept:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  runtimeAddress: number;
  overlayId?: number;
}
```

RE-MCP resolves the selector against the canonical NDS model before invoking Ghidra.

Rules:

- main executable addresses map to the canonical default program address space;
- an uncompressed overlay maps to its deterministic RE-MCP Ghidra overlay space name derived internally from processor + overlay ID;
- overlapping overlay runtime ranges without sufficient identity remain ambiguous and fail closed;
- compressed overlays return `compressed-overlay-not-imported` because this milestone does not decompress them;
- runtime-only BSS may be inspected for address-level symbols/references when the corresponding overlay space exists, but it is not decompilable code merely because Ghidra can address it;
- function/decompiler operations require a Ghidra-present executable main or uncompressed-overlay code identity;
- callers cannot supply an arbitrary Ghidra address-space string.

## Public MCP surface

Add exactly five public tools.

### 1. `nds_ghidra_inspect_function`

Purpose: inspect the Ghidra function containing or beginning at one canonical NDS runtime address.

Input:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  runtimeAddress: number;
  overlayId?: number;
}
```

Output includes:

- canonical source ROM SHA-256;
- processor/component/overlay identity;
- canonical requested runtime address;
- Ghidra address-space name selected internally;
- whether a Ghidra function exists at/containing the address;
- Ghidra function entry;
- function name and namespace;
- signature text;
- calling convention;
- thunk/external/varargs flags when available;
- bounded discontiguous function-body ranges;
- Ghidra symbol/source metadata for the function entry;
- separate RE-MCP-owned metadata found at the entry (`function-id`, proof, mode, overlay ID) when present;
- explicit authority labels distinguishing canonical selector facts, RE-MCP-owned proof metadata, and Ghidra-derived function information.

A Ghidra function body/end remains non-authoritative to RE-MCP.

Body range output is capped at 256 address ranges. If more exist, return truncation metadata instead of silently dropping information.

### 2. `nds_ghidra_decompile_function`

Purpose: retrieve bounded C-like decompiler output for the Ghidra function selected by one canonical NDS address.

Input uses the same canonical selector plus optional bounded presentation control:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  runtimeAddress: number;
  overlayId?: number;
  maxCharacters?: number; // default 20000, maximum 100000
}
```

Behavior:

- requires an existing Ghidra function containing the selected address;
- invokes Ghidra's decompiler only for that function;
- uses a fixed per-function decompile timeout of 30 seconds, still bounded by the outer configured Ghidra subprocess timeout;
- returns decompiler completion/error status;
- returns C text clipped only at the caller's bounded `maxCharacters` or the global MCP output bound;
- reports `truncated: true` when clipped;
- includes the same canonical/Ghidra/RE-MCP authority separation as function inspection.

Decompiler text is explicitly `authority: "ghidra-derived"` and is never stored into canonical RE-MCP function evidence.

### 3. `nds_ghidra_search_symbols`

Purpose: find Ghidra/analyst symbols in one processor program without exposing generic Ghidra queries.

Input:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  query: string;               // 1..128 Unicode characters
  match?: "exact" | "prefix" | "contains"; // default prefix
  limit?: number;              // default 100, max 1000
  offset?: number;             // default 0, max 100000
}
```

No regex or arbitrary expression language is accepted.

Results are deterministically sorted by:

1. address-space name;
2. unsigned address offset;
3. namespace;
4. symbol name;
5. symbol type.

Each result includes name, namespace, symbol type, address identity, primary/dynamic flags when available, source type, and whether the address carries RE-MCP-owned proof metadata.

Symbols may be analyst-created or Ghidra-derived; they are not promoted into canonical RE-MCP facts.

### 4. `nds_ghidra_list_references`

Purpose: inspect Ghidra references to/from one canonical address.

Input:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  runtimeAddress: number;
  overlayId?: number;
  direction?: "from" | "to" | "both"; // default both
  limit?: number;                       // default 100, max 1000
  offset?: number;                      // default 0, max 100000
}
```

Output records Ghidra's reference type/source/operand information plus exact from/to address-space identities. When an endpoint maps back to canonical NDS ownership, RE-MCP adds that canonical classification separately.

A Ghidra reference remains Ghidra-derived unless the address also carries an independent RE-MCP-owned canonical direct-call record.

### 5. `nds_ghidra_list_calls`

Purpose: retrieve direct caller/callee relationships for one Ghidra function.

Input:

```ts
{
  rom: string;
  processor: "arm9" | "arm7";
  runtimeAddress: number;
  overlayId?: number;
  direction?: "callers" | "callees" | "both"; // default both
  limit?: number;                                // default 100, max 1000
  offset?: number;                               // default 0, max 100000
}
```

This milestone is intentionally depth-1 only. It does not expose arbitrary recursive graph traversal.

Each edge includes:

- source and target function identities when Ghidra has them;
- call-site address when available;
- Ghidra reference type/source;
- canonical NDS ownership for endpoints when resolvable;
- whether the edge matches an RE-MCP-owned direct-call evidence record;
- authority labels.

## Deliberately omitted public tools

### No Ghidra disassembly tool

RE-MCP already has canonical bounded ARM/Thumb disassembly and CFG tools whose proof/source model is stronger than Ghidra-derived listing output. Duplicating them would create two similar surfaces with different authority semantics.

Ghidra listing/disassembly details needed by future work may be included inside function inspection later if a concrete use case requires them.

### No generic Ghidra query tool

There is no generic script runner, command line, Java expression, symbol regex, database query, arbitrary project/program selector, or arbitrary address-space selector.

### No Ghidra-to-RE-MCP promotion

Inspection returns Ghidra results. It never updates:

- canonical function proof;
- canonical xref/reference databases;
- ROM structure/address maps;
- static ARM/Thumb proof;
- analyst evidence state outside the Ghidra project.

A separate future evidence-promotion design would require explicit provenance and review rules.

## Request/result transport

Add one RE-MCP-owned Java script:

```text
resources/ghidra/ReMcpInspectProgram.java
```

Node creates a validated request JSON inside:

```text
analysis/generated/nds/<sha-prefix>/ghidra-inspection/
```

The caller never chooses that path.

The request contains a fixed format/version, ROM SHA, processor, canonical program name, one operation enum, resolved internal address-space identity, bounded parameters, and one server-generated request ID.

The Java script accepts exactly two arguments:

```text
<request-json-path> <result-json-path>
```

It must:

1. validate request format/version;
2. validate current program name;
3. validate RE-MCP Program Information ownership keys against the request ROM SHA and processor;
4. execute exactly one allowlisted inspection operation;
5. write one versioned result JSON atomically beside the request;
6. never change the Ghidra program/project.

Node validates the result schema, ROM SHA, processor, program name, request ID, and operation before returning it.

Temporary request/result files are removed after validation on success and best-effort on failure. These generated transport files are not analyst state and are never written beneath `analysis/ghidra/...`.

## Read-only Java contract

`ReMcpInspectProgram.java` may read from:

- `Program` / Program Information;
- `Listing`;
- `FunctionManager` / `Function`;
- `SymbolTable` / `Symbol`;
- `ReferenceManager` / `Reference`;
- address spaces/memory blocks;
- RE-MCP-owned property maps;
- Ghidra decompiler APIs.

Source-contract tests must reject mutating calls such as:

- `createFunction` / `removeFunction` / `setBody`;
- symbol creation, deletion, rename, or namespace mutation;
- comment/bookmark mutation;
- `addMemoryReference` / reference deletion;
- memory block creation/deletion/write;
- program-context `setValue`;
- RE-MCP property-map `add`/`remove` calls;
- project/file save/delete operations;
- arbitrary process/network APIs.

The headless invocation's `-readOnly` flag is a second safety layer, not a substitute for the source-level read-only contract.

## Authority model

Every inspection response explicitly separates three classes of information.

### `canonical`

Facts produced by the native RE-MCP NDS model before Ghidra invocation, such as:

- ROM SHA;
- processor;
- component/overlay identity;
- requested runtime address;
- canonical file-backed/BSS/compression classification.

### `reMcpEvidence`

RE-MCP-owned metadata previously imported into Ghidra, such as:

- canonical proven function ID;
- proof records;
- proven ARM/Thumb mode;
- canonical overlay ID;
- exact direct-call evidence.

### `ghidraDerived`

Information produced by Ghidra or an analyst, including:

- Ghidra function body/end;
- names/signatures not owned by RE-MCP;
- symbols;
- references inferred by Ghidra;
- caller/callee relationships derived from those references;
- decompiler output.

No response shape may flatten these into one undifferentiated truth object.

## Error model

Add structured categories where existing categories are insufficient:

```text
ghidra-project-not-current
ghidra-version-mismatch
ghidra-address-not-inspectable
ghidra-inspection-failed
ghidra-inspection-timeout
ghidra-inspection-result-invalid
```

Continue reusing existing categories when applicable:

```text
ghidra-not-configured
invalid-ghidra-installation
unsupported-ghidra-version
ghidra-language-unavailable
ghidra-project-locked
project-state-mismatch
compressed-overlay-not-decodable / compressed-overlay-not-imported equivalent at tool boundary
invalid-rom
output-bound-exceeded
ghidra-output-limit
```

Corrective actions must tell the caller when `nds_ghidra_bootstrap` is required rather than performing it implicitly.

## Process and output bounds

- one processor program per inspection invocation;
- `-readOnly` always present;
- `-noanalysis` always present;
- no `-import` invocation;
- no bootstrap pre/post scripts;
- fixed `ReMcpInspectProgram.java` only;
- existing `RE_MCP_GHIDRA_TIMEOUT_MS` remains the subprocess maximum;
- decompiler per-function timeout: 30 seconds;
- stdout/stderr remain capped by `RE_MCP_MAX_OUTPUT_BYTES` and terminate on overflow;
- serialized MCP response must also fit `RE_MCP_MAX_OUTPUT_BYTES`;
- function body ranges: max 256;
- symbol/reference/call page limit: default 100, max 1000;
- pagination offset: max 100000;
- decompiler text: default 20000 characters, max 100000 before global output-bound enforcement;
- symbol query: 1..128 characters.

## Testing strategy

### Node/unit tests without Ghidra

Add focused tests for:

- strict inspection-ready state validation;
- refusal when project/bridge/state is missing or stale;
- refusal after a later failed reconciliation;
- exact configured-Ghidra-version match;
- canonical main/overlay address-space selection;
- ambiguity rejection;
- compressed-overlay rejection for code inspection;
- BSS behavior by operation;
- request path containment and caller path denial;
- request/result schema validation;
- deterministic result sorting;
- pagination/truncation;
- decompiler character bounds;
- MCP output bounds;
- exact tool schemas and registration.

### Invocation contract tests

Require inspection argv to contain:

```text
-process
<canonical program>
-readOnly
-noanalysis
-scriptPath
<RE-MCP resource path>
-postScript
ReMcpInspectProgram.java
```

Reject any inspection invocation containing:

```text
-import
-preScript ReMcpPrepareProgram.java
-preScript ReMcpImportEvidence.java
-postScript ReMcpRecordAnalysis.java
```

### Java source-contract tests

Static source tests enforce:

- exactly two script args;
- fixed request format/version;
- ownership validation;
- allowlisted operation enum;
- atomic result write;
- no mutator APIs listed in the read-only contract;
- no arbitrary process/network access.

### Real Ghidra acceptance

Use official Ghidra 12.1.2 + JDK 21 and the existing synthetic NDS fixture.

Acceptance must:

1. bootstrap the fixture normally;
2. add/preserve an analyst marker as the existing acceptance already does;
3. hash persistent project files before inspection, excluding only transient lock files;
4. run all five inspection operations in read-only/no-analysis mode;
5. verify function metadata on the known fixture entry/direct-call targets;
6. verify bounded decompiler output succeeds for a known analyzed function;
7. verify symbol search returns at least the known program/function symbols created by normal analysis;
8. verify reference/call inspection returns the fixture's known call relationship;
9. verify overlapping overlay address-space identity is preserved;
10. verify the analyst marker remains present;
11. hash persistent project files again and require byte-for-byte equality for non-transient files;
12. reject hidden `REPORT SCRIPT ERROR` / unexpected exceptions.

The real-Ghidra workflow remains manual/workflow-dispatch or temporary PR-trigger acceptance only. Normal CI must not download Ghidra.

## File map

### Create

- `src/services/nds/ghidra-inspection-model.ts`
- `src/services/nds/ghidra-inspection.ts`
- `tests/nds-ghidra-inspection-model.test.ts`
- `tests/nds-ghidra-inspection.test.ts`
- `tests/nds-ghidra-inspection-tools.test.ts`
- `resources/ghidra/ReMcpInspectProgram.java`

### Modify

- `src/services/nds/ghidra-project.ts` — expose/reuse strict trusted-success/readiness validation without making status mutating.
- `src/services/nds/ghidra-runner.ts` — add fixed read-only inspection invocation builder and inspection error mapping.
- `src/services/nds/errors.ts` — add inspection-specific categories.
- `src/tools/nds-ghidra.ts` — register the five bounded inspection tools.
- `src/index.ts` — capability reporting as needed.
- `scripts/check-install.mjs` — require packaged inspection script.
- `scripts/ghidra-acceptance.mjs` — real read-only inspection acceptance.
- `.github/workflows/package.yml` — package smoke contract for the inspection resource/tool surface without requiring Ghidra.
- `README.md`
- `docs/nds-ghidra-integration.md`

## Non-goals

This milestone does not add:

- hidden/automatic Ghidra bootstrap;
- Ghidra auto-analysis during inspection;
- any Ghidra project mutation;
- Ghidra-derived evidence promotion into canonical RE-MCP models;
- generic Ghidra commands/scripts/queries;
- raw project/program/address-space selectors;
- generic recursive call-graph traversal;
- duplicate Ghidra disassembly/CFG tools;
- compressed-overlay decompression;
- ROM mutation or patch generation;
- new DeSmuME/GDB behavior.

## Acceptance criteria

Complete when:

1. all five inspection tools operate only on a strictly trusted already-current full-SHA project;
2. every Ghidra inspection process uses `-readOnly` and `-noanalysis`;
3. no tool silently invokes bootstrap or auto-analysis;
4. canonical NDS selectors are resolved before Ghidra and raw Ghidra paths/spaces are not caller-controlled;
5. function, decompiler, symbol, reference, and call outputs explicitly preserve Ghidra-vs-RE-MCP authority boundaries;
6. decompiler/symbol/reference/call outputs are bounded and deterministically serialized;
7. compressed/ambiguous/non-inspectable addresses fail closed;
8. Java source-contract tests reject project/program mutation APIs;
9. normal CI/package verification passes without Ghidra installed;
10. real Ghidra 12.1.2 acceptance proves useful inspection results while persistent project bytes and analyst markers remain unchanged;
11. the source ROM remains read-only;
12. native Catalina/DeSmuME debugger behavior remains unchanged.
