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

Replaceable bridge inputs remain under:

```text
analysis/generated/nds/<sha-prefix>/ghidra-bridge/
├── manifest.json
├── evidence/
│   ├── functions.json
│   └── calls.json
├── results/
│   ├── arm9.json
│   └── arm7.json
└── scripts/
```

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

ARM9 and ARM7 main executables are imported at canonical runtime bases. Every **uncompressed** overlay is represented as a true Ghidra overlay address space, such as:

```text
RE_MCP_ARM9_OVL_7
RE_MCP_ARM7_OVL_3
```

Overlays can therefore retain identical numeric runtime addresses without being flattened into one identity.

Compressed overlays remain `not-imported-compressed`; their stored compressed bytes are never treated as executable runtime code. BSS may exist only as uninitialized runtime-only memory and never receives fabricated ROM backing.

## Evidence and authority

RE-MCP remains authoritative for:

- source ROM SHA-256;
- processor/component/overlay ownership;
- exact runtime/file-backed mappings;
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

Bootstrap explicitly creates or safely reconciles the full-SHA project. It validates the ROM and bridge, validates the configured Ghidra installation, imports/processes ARM9 and ARM7, establishes overlays and RE-MCP-owned evidence, runs normal auto-analysis, validates processor results, rechecks source ROM identity, and only then updates persistent success/failure state.

Subprocesses use argument arrays with `shell: false`, bounded environment, timeout enforcement, and bounded stdout/stderr.

### `nds_ghidra_status`

Status is non-mutating. It does not launch Ghidra or regenerate the bridge and does not require `RE_MCP_GHIDRA_HOME` just to read existing deterministic state.

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
- Uncompressed overlays use internally derived `RE_MCP_ARM*_OVL_<id>` spaces.
- Overlapping static overlay ownership without `overlayId` fails closed.
- An explicit `overlayId` must actually own the requested address.
- Compressed overlays return `ghidra-address-not-inspectable` because they are intentionally absent from the Ghidra project.
- BSS may be used for address-level reference inspection when its overlay exists, but function/decompiler/call inspection requires exact file-backed executable code.

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

### `nds_ghidra_list_calls`

Returns bounded **depth-one only** callers, callees, or both for one Ghidra function. It does not expose arbitrary recursive graph traversal. Each call site may also report the independent RE-MCP call-evidence property present at that source address.

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

Existing installation, project-lock, output-limit, ROM, and project-state categories remain in use where applicable.

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

Inspection is stricter: it runs Ghidra with `-readOnly -noanalysis`. Real-Ghidra acceptance must prove that inspection returns useful information while persistent project bytes and analyst markers remain unchanged.

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
- automatic bootstrap from inspection;
- auto-analysis during inspection;
- Ghidra-to-RE-MCP evidence promotion;
- compressed-overlay decompression;
- ROM mutation.
