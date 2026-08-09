# Controlled NDS Ghidra Integration

RE-MCP exposes seven optional Ghidra-facing MCP tools:

- `nds_ghidra_bootstrap`
- `nds_ghidra_status`
- `nds_ghidra_inspect_function`
- `nds_ghidra_decompile_function`
- `nds_ghidra_search_symbols`
- `nds_ghidra_list_references`
- `nds_ghidra_list_calls`

The Ghidra surface is intentionally split into one explicit mutating bootstrap operation, one non-mutating status operation, and five **strictly read-only inspection** operations. There is no generic Ghidra command/script runner.

## Requirements

The rest of RE-MCP does not require Ghidra. To use Ghidra integration, install a supported Ghidra 12.x release and configure:

```text
RE_MCP_GHIDRA_HOME=/absolute/path/to/ghidra_12.1.2_PUBLIC
RE_MCP_GHIDRA_TIMEOUT_MS=900000
```

The reference acceptance release is Ghidra 12.1.2 with JDK 21. `RE_MCP_GHIDRA_TIMEOUT_MS` defaults to 900000 ms and is capped at 3600000 ms per headless subprocess.

RE-MCP derives the exact `support/analyzeHeadless` executable from `RE_MCP_GHIDRA_HOME` and validates the required languages:

- ARM9: `ARM:LE:32:v5t`
- ARM7: `ARM:LE:32:v4t`

## Project and bridge layout

The canonical analysis bundle keeps physical ROM bytes and decoded runtime bytes separate:

```text
analysis/generated/nds/<sha-prefix>/
├── arm9.bin
├── arm7.bin
├── overlays/
│   ├── arm9/                 # exact FAT-backed stored overlay bytes
│   └── arm7/
├── runtime/
│   └── overlays/
│       ├── arm9/             # decoded initialized runtime bytes, compressed overlays only
│       └── arm7/
└── ghidra-bridge/
    ├── manifest.json
    ├── evidence/
    │   ├── functions.json
    │   └── calls.json
    ├── results/
    │   ├── arm9.json
    │   └── arm7.json
    └── scripts/
```

The bridge manifest is version 2. Each overlay records its canonical runtime geometry and distinct storage/runtime provenance, including `representation`, `initializedSize`, `storedRomOffset`, `storedSize`, `storedSha256`, and `runtimeSha256`.

For compressed overlays, the Ghidra import artifact points to the canonical Node-generated decoded runtime image under `runtime/overlays/...`. That artifact has no physical ROM offset. The original compressed FAT-backed bytes and their hash remain separately recorded; RE-MCP never pretends decoded bytes are stored contiguously in the ROM.

Read-only inspection transport uses a separate generated directory:

```text
analysis/generated/nds/<sha-prefix>/ghidra-inspection/
```

Request/result files in that directory are server-selected, versioned, validated, and removed after each inspection on success or best-effort on failure.

Persistent analyst state is keyed by the **full** source ROM SHA-256:

```text
analysis/ghidra/nds/<full-sha256>/
├── project/
└── state/
    ├── latest-run.json
    ├── latest-success.json
    └── latest-failure.json
```

Generated bridge/inspection artifacts can be replaced without erasing the persistent Ghidra project.

## Program model

Each SHA-scoped project contains:

- `RE-MCP_ARM9`
- `RE-MCP_ARM7`

ARM9 and ARM7 main executables are imported at canonical runtime bases. Every overlay with initialized runtime code is represented as a true Ghidra overlay address space, such as:

```text
RE_MCP_ARM9_OVL_7
RE_MCP_ARM7_OVL_3
```

Overlays can therefore retain identical numeric runtime addresses without being flattened into one identity.

Uncompressed overlays use their exact stored artifact, but Ghidra imports only the canonical `initializedSize` prefix when physical backing is larger than initialized runtime memory. Compressed overlays use the validated `derived-blz` runtime artifact produced by RE-MCP's bounded native BLZ decoder. Ghidra/Java never performs BLZ decompression itself.

BSS is always separate uninitialized memory in the same overlay address space. It is never zero-appended to a decoded artifact and never receives fabricated ROM backing.

## Stored bytes versus runtime bytes

For an uncompressed overlay, stored and runtime bytes may share one physical artifact, but RE-MCP still records the exact initialized prefix hash separately when the FAT backing is larger than runtime initialization.

For a compressed overlay:

```text
stored FAT backing
        │
        ├── storedRomOffset / storedSize / storedSha256
        │
        └── bounded canonical BLZ decode
                    │
                    └── decoded runtime artifact
                        runtimeAddress / initializedSize / runtimeSha256
                        romOffset = null
```

This distinction is preserved through static analysis, the generated bundle, the Ghidra bridge, Ghidra ownership metadata, inspection responses, and real-tool acceptance.

## Evidence and authority

RE-MCP remains authoritative for:

- source ROM SHA-256;
- processor/component/overlay ownership;
- physical stored-byte provenance;
- decoded runtime-image provenance;
- exact runtime mapping and explicit absence of a direct ROM offset for decoded bytes;
- ARM/Thumb mode when proven;
- function-entry proof from program entry or exact deterministic direct call;
- exact RE-MCP direct-call evidence.

RE-MCP does **not** prove a function end or exclusive function body. Ghidra may infer function bodies, symbols, references, strings, types, signatures, call relationships, and decompiler output, but those remain non-authoritative.

Inspection responses preserve this boundary explicitly:

- `canonical` — facts from the native RE-MCP NDS model;
- `reMcpEvidence` — RE-MCP-owned metadata imported into Ghidra;
- `ghidraDerived` — Ghidra/analyst function, symbol, reference, call, or decompiler results.

Inspection never silently promotes `ghidraDerived` information into canonical RE-MCP evidence.

## Bootstrap and status

### `nds_ghidra_bootstrap`

Bootstrap explicitly creates or safely reconciles the full-SHA project. It validates the ROM and analysis bundle, validates the bridge and every imported artifact, validates the configured Ghidra installation, imports/processes ARM9 and ARM7, establishes overlay spaces and RE-MCP-owned evidence, runs normal auto-analysis, validates processor results, rechecks source ROM identity, and only then updates persistent success/failure state.

For every imported overlay, Java validates the manifest-declared geometry and SHA-256 of the actual initialized bytes in Ghidra memory before recording successful v2 ownership.

Subprocesses use argument arrays with `shell: false`, bounded environment, timeout enforcement, and bounded stdout/stderr.

### Safe bridge-v1 to bridge-v2 reconciliation

Existing RE-MCP-owned bridge-v1 projects are migrated in place rather than destroyed or recreated.

Migration is allowed only when the existing project has matching full ROM SHA-256 and processor ownership. Existing overlay blocks must match canonical overlay-space identity, geometry, initialization state, and the expected runtime-byte SHA-256. A compressed overlay that was absent under v1 may then be added from the validated decoded runtime artifact. Existing BSS must match exactly or is created only when safely absent.

Any conflicting block, address space, per-overlay ownership value, or runtime byte hash fails closed. Production reconciliation never removes or replaces the conflicting object. Bridge-v2 ownership is written only after the complete overlay reconciliation and proven-mode pass succeeds, preserving analyst-created state.

### `nds_ghidra_status`

Status is non-mutating. It does not launch Ghidra or regenerate the bridge and does not require `RE_MCP_GHIDRA_HOME` just to read existing deterministic state.

Processor status counts compressed overlays as imported after v2 bootstrap. `compressedOverlayIds` separately identifies which imported overlays use compressed storage provenance.

## Strict inspection readiness

The five inspection tools **never bootstrap or reconcile automatically**.

Before inspection launches Ghidra, RE-MCP requires:

1. the current ROM SHA-256 to match the canonical map;
2. both `.gpr` and `.rep` SHA-scoped project markers;
3. matching complete `latest-run.json` and `latest-success.json` state;
4. both ARM9 and ARM7 completed processors;
5. no `latest-failure.json`;
6. the generated bridge manifest hash to match the trusted success state;
7. a valid configured Ghidra installation;
8. the configured Ghidra version to exactly match the trusted project version.

Failure returns `ghidra-project-not-current`, `ghidra-version-mismatch`, or another specific structured error. The corrective action may tell the caller to run `nds_ghidra_bootstrap`; inspection never does that itself.

## Read-only inspection execution

Every inspection invocation processes exactly one canonical ARM9 or ARM7 program using:

```text
-process <RE-MCP_ARM9|RE-MCP_ARM7>
-readOnly
-noanalysis
-scriptPath <RE-MCP-owned resources>
-postScript ReMcpInspectProgram.java <request.json> <result.json>
```

Inspection therefore:

- never uses `-import`;
- never runs the bootstrap mutation scripts;
- never runs normal auto-analysis;
- never saves program/project changes;
- exposes no caller-selected Ghidra program, project path, address-space name, script, output path, CLI argument list, or environment map.

The Java inspection resource itself is additionally guarded by source-contract tests that reject known mutator, process, and network APIs.

## Canonical selectors and overlay ambiguity

Address-oriented inspection tools accept only:

```text
rom
processor: arm9 | arm7
runtimeAddress: uint32
overlayId?: uint32
```

RE-MCP resolves the address through the canonical NDS model before Ghidra is invoked.

- Main code uses the actual Ghidra program default address space; its name is not caller-controlled or hard-coded.
- Overlays use internally derived `RE_MCP_ARM*_OVL_<id>` spaces regardless of whether their initialized representation is physical or derived.
- Overlapping static overlay ownership without `overlayId` fails closed.
- An explicit `overlayId` must actually own the requested address.
- Initialized compressed-overlay code is inspectable after successful bridge-v2 bootstrap. Canonical output remains `compressed: true` and `fileBacked: false`; the decoded runtime bytes never acquire fabricated physical-ROM provenance.
- Function, decompiler, and call inspection require exact imported executable code. This includes physical file-backed code and validated `derived-overlay` initialized code.
- BSS remains runtime-only and may be used for address-level reference inspection when its overlay exists, but it is not valid function/decompiler/call code.

## Inspection tools

### `nds_ghidra_inspect_function`

Returns bounded Ghidra function metadata for the function containing one canonical address, including entry, name, namespace, signature, calling convention, flags, up to 256 discontiguous body ranges, entry-symbol metadata, and separate RE-MCP-owned entry evidence.

The Ghidra body remains `ghidraDerived` and is not function-boundary proof.

### `nds_ghidra_decompile_function`

Runs the Ghidra decompiler for exactly one existing function with a fixed 30-second per-function bound. C-like output defaults to 20000 characters and caps at 100000 characters before the global MCP output bound. Truncation is explicit.

### `nds_ghidra_search_symbols`

Searches one processor program with only:

- `exact`
- `prefix` (default)
- `contains`

No regex or arbitrary expression language is accepted. Query length is 1–128 Unicode characters. Results default to 100 and cap at 1000 with offset capped at 100000.

### `nds_ghidra_list_references`

Returns bounded Ghidra references `from`, `to`, or `both` for one canonical address. Reference type/source/operand information remains Ghidra-derived unless independent RE-MCP evidence exists.

Returned canonical endpoints preserve derived-overlay provenance independently of the Ghidra reference type.

### `nds_ghidra_list_calls`

Returns bounded **depth-one only** callers, callees, or both for one Ghidra function. It does not expose arbitrary recursive graph traversal. Each call site may also report the independent RE-MCP call-evidence property present at that source address.

Direct-call evidence originating in decoded compressed-overlay code retains `instructionRomOffset: null` because the instruction has no direct physical ROM-byte identity.

## Errors specific to inspection

Inspection adds:

```text
ghidra-project-not-current
ghidra-version-mismatch
ghidra-address-not-inspectable
ghidra-inspection-failed
ghidra-inspection-timeout
ghidra-inspection-result-invalid
```

Existing installation, project-lock, output-limit, ROM, decompression/runtime-image, and project-state categories remain in use where applicable.

## Output and safety bounds

- one processor program per inspection invocation;
- function body ranges: max 256;
- list page: default 100, max 1000;
- list offset: max 100000;
- symbol query: 1–128 Unicode characters;
- decompiler output: default 20000, max 100000 characters;
- decompiler function timeout: 30 seconds;
- subprocess timeout: existing bounded `RE_MCP_GHIDRA_TIMEOUT_MS`;
- subprocess stdout/stderr and final MCP response: existing `RE_MCP_MAX_OUTPUT_BYTES`.

The source ROM SHA-256 is checked again before an inspection result is returned. Temporary request/result transport is cleaned on every exit path.

## Analyst-work preservation

Bootstrap reconciliation modifies only RE-MCP-owned state and preserves analyst-created labels, comments, bookmarks, types, namespaces, names/signatures, and Ghidra-only discoveries whenever safe.

Inspection is stricter: it runs Ghidra with `-readOnly -noanalysis`. Real-Ghidra acceptance must prove that inspection of main, overlapping uncompressed overlays, and derived compressed overlays returns useful information while persistent project bytes and analyst markers remain unchanged.

## Relationship to dynamic debugging

Ghidra integration is independent of the DeSmuME ARM9 GDB acceptance gate. Successful bootstrap or inspection does not constitute physical Catalina/DeSmuME debugger acceptance and adds no debugger/watchpoint/runtime-tracing behavior.

## Security boundary

The Ghidra integration does not expose:

- arbitrary shell execution;
- arbitrary Ghidra commands or scripts;
- caller-selected `analyzeHeadless` paths;
- caller-selected project/program/address-space names;
- arbitrary loaders/languages;
- raw Ghidra CLI arguments;
- caller-defined environment variables;
- arbitrary binary imports;
- arbitrary decompression input;
- Java/Ghidra-side BLZ decoding;
- automatic bootstrap from inspection;
- auto-analysis during inspection;
- Ghidra-to-RE-MCP evidence promotion;
- fabricated ROM offsets for decoded runtime bytes;
- ROM mutation.
