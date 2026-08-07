# RE-MCP

A safety-first local Model Context Protocol server for ROM reverse-engineering workflows.

RE-MCP uses **stdio** and exposes narrow, tested tools rather than an unrestricted shell.

## Current capabilities

### General

- Project Git status
- Allowlisted npm verification
- SHA-256 file verification
- Capability and policy reporting

### Bakugan DS

- Compile, Ruff, mypy, pytest, or full quality suite
- Regenerate Milestone 6E contracts
- Run the Milestone 6E installer in dry-run mode
- Generate the Milestone 6E roster analysis

### Nintendo DS static analysis

- Parse one canonical ROM identity using SHA-256
- Read ARM9 and ARM7 executable metadata
- Parse FAT physical file ranges
- Reconstruct FNT/NitroFS paths while retaining unnamed FAT entries
- Parse ARM9 and ARM7 overlay tables, including initialized range, BSS, file backing, compression metadata, and flags
- Resolve ARM9/ARM7 runtime addresses against main executables and static overlay candidates
- Reverse-map ROM offsets to structural, NitroFS, executable, and overlay relationships
- Decode bounded ARM/Thumb instruction windows from deterministic file-backed NDS code sources
- Build bounded direct-control-flow graphs across deterministic same-processor branch targets without recursively traversing calls
- Classify deterministic single-instruction direct branch/call, literal-pool-slot, and PC-relative address references
- Find bounded reverse cross-references through proven code seeds with explicit component coverage and truncation status
- Discover bounded ARM9/ARM7 function-entry call graphs using only program-entry and deterministic resolved direct-call proof
- Prove one requested function entry and distinguish complete negative evidence from incomplete proof coverage before analyzing its CFG
- Search validated NDS bytes for exact/wildcard signatures, typed integers, ASCII strings, and UTF-16LE strings using canonical component or explicit whole-ROM scope
- Extract validated ARM9, ARM7, overlay, or NitroFS components to a deterministic generated-analysis tree
- Build a transactional static-analysis bundle without dumping every NitroFS asset
- Optionally bootstrap and inspect a full-ROM-SHA-scoped Ghidra project through a configured local Ghidra 12.x installation

The source ROM is read-only. Generated NDS artifacts are restricted to `analysis/generated/nds/<sha-prefix>/` under the configured workspace. RE-MCP does not accept generic binary inputs, caller-selected output paths, arbitrary ROM offset/length extraction requests, or caller-defined raw search ranges.

### DeSmuME and ARM9 GDB

- Start, inspect, and stop one server-owned DeSmuME process
- Probe and wait for the owned ARM9 GDB port
- Read the raw ARM9 register packet
- Read up to 4096 bytes of ARM9 memory
- Derive the main ARM9 executable range from the NDS ROM header before launch
- Maintain an allowlist of the main ARM9 range plus up to 64 explicit or overlay executable ranges
- Add, remove, and list controlled ARM9 software breakpoints
- Continue execution, wait for a stop, interrupt/pause, and single-step up to 100 instructions
- Decode DeSmuME ARM9 registers into `r0`-`r12`, `sp`, `lr`, `pc`, and `cpsr`
- Capture structured stop context with bounded PC, stack, and optional memory windows
- Match breakpoint hits, track hit counts, and retain ARM/Thumb execution history
- Atomically capture raw registers plus labeled memory regions
- Reset debugger state automatically when the owned emulator exits or its process generation changes

RE-MCP does **not** expose register writes, general memory writes, watchpoints, or an arbitrary GDB-command tool.

## NDS Static Analysis

The canonical static-analysis surface consists of fourteen MCP tools:

- `nds_inspect_rom`
- `nds_list_files`
- `nds_list_overlays`
- `nds_resolve_runtime_address`
- `nds_resolve_rom_offset`
- `nds_extract_component`
- `nds_extract_analysis_bundle`
- `nds_disassemble_range`
- `nds_analyze_control_flow`
- `nds_list_references`
- `nds_find_xrefs`
- `nds_search_pattern`
- `nds_discover_functions`
- `nds_analyze_function`

These canonical static tools are native-independent and have no DeSmuME, GDB, or Ghidra dependency. The optional Ghidra bridge described below consumes their canonical evidence but does not change their proof rules.

### Canonical ROM model

`nds_inspect_rom` parses the ROM into one validated model containing:

- full source SHA-256 and file size
- game title, game code, maker code, unit code, capacity, and ROM version
- ARM9 and ARM7 ROM offsets, entry addresses, RAM/load addresses, sizes, and runtime ranges
- FNT and FAT regions
- ARM9 and ARM7 overlay-table regions
- NitroFS file count
- ARM9 and ARM7 overlay counts
- validated static executable/runtime candidate ranges

FAT remains authoritative for physical file byte ranges. FNT remains authoritative for names and directory hierarchy. Overlay records keep file-backed bytes, initialized runtime bytes, and BSS/runtime-only bytes distinct.

### Address-resolution rules

`nds_resolve_runtime_address` does not guess when static overlay ranges overlap. If more than one main/overlay candidate contains an address, every candidate is returned with an ambiguity status.

BSS has no source ROM bytes, so BSS results return no ROM offset.

Compressed overlay bytes also require special handling. The stored FAT-backed overlay file may be compressed, so a decompressed runtime byte does **not** receive a fabricated direct ROM-byte mapping. The resolver still reports the overlay ID, file ID, runtime-relative offset, and backing-file metadata. Exact compressed-ROM ↔ decompressed-runtime correlation is deferred until controlled decompression support exists.

`nds_resolve_rom_offset` performs the reverse classification and may return multiple valid relationships for one ROM byte, such as a NitroFS file plus an ARM9 overlay backing file. Compressed overlay backing bytes do not receive fabricated runtime addresses.

### ARM/Thumb static disassembly

`nds_disassemble_range` and `nds_analyze_control_flow` use `@alexaltea/capstone-js` 5.0.9 through a narrow RE-MCP-owned ARM decoder interface. The backend is JavaScript + WebAssembly and is bundled with RE-MCP; no external Capstone, Ghidra, or radare2 executable is required.

Both tools accept only Nintendo DS sources resolved through the canonical ROM model. A request identifies `arm9` or `arm7`, exactly one runtime address or ROM offset, an optional overlay ID used only as a static disambiguator, and an ARM/Thumb mode.

Supported modes are:

- `arm`
- `thumb`
- conservative `auto`

Initial `auto` mode succeeds only when the resolved source is the matching ARM9 or ARM7 main header entry point, which is an ARM seed. Merely being in an executable range or overlay is not sufficient evidence. During CFG traversal, a deterministic direct edge may propagate its statically proven target mode. RE-MCP never decodes both modes and chooses the more plausible stream, and it does not use address bit 0 as a general-purpose mode guess.

ARM starts and deterministic ARM targets must be 4-byte aligned. Thumb starts and deterministic Thumb targets must be 2-byte aligned. Invalid alignment is rejected rather than rounded.

Only exact file-backed code bytes are decodable:

- ARM9 main
- ARM7 main
- uncompressed ARM9 overlays
- uncompressed ARM7 overlays

BSS returns `runtime-only-bss`. Compressed overlays return `compressed-overlay-not-decodable`; the stored compressed bytes are never decoded as if they were runtime instructions. If an uncompressed overlay's runtime initialized extent is larger than its physical backing file, only the exact file-backed prefix is eligible.

If multiple static code mappings contain a requested address or branch target, RE-MCP returns or records `ambiguous-code-source` rather than guessing which overlay is loaded. Supplying `overlayId` can select one starting static source, but it never claims that overlay is loaded at runtime. A deterministic branch that stays within that already selected component preserves its static component identity; a cross-component branch is re-resolved and traversed only when the same processor, source bytes, and target mode are all deterministic.

The ROM SHA-256 used to construct the canonical map is checked immediately before and after each top-level linear or CFG operation. A modified ROM invalidates the operation even if a decode callback also fails.

#### Linear disassembly limits

`nds_disassemble_range` decodes sequentially and classifies control flow without changing linear traversal based on branch instructions.

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Instructions | 32 | 256 |
| Source bytes | 128 | 1,024 |

Decoding stops at the first instruction limit, byte limit, component boundary, instruction that would cross a component boundary, or undecodable instruction. A local decode failure returns the successfully decoded prefix with `decode-stopped`; RE-MCP never skips bytes and silently resumes. `complete` means the requested bounded window completed, not that a whole function or component was discovered.

#### Direct-control-flow limits and semantics

`nds_analyze_control_flow` builds basic blocks using a deterministic FIFO worklist. Block identity includes processor, component, overlay ID, runtime address, and mode, preventing cycles from repeatedly decoding the same block identity.

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Basic blocks | 64 | 256 |
| Total instructions | 512 | 4,096 |
| Total decoded source bytes | 2 KiB | 16 KiB |
| Traversal edges | 128 | 1,024 |

All limits apply simultaneously. If any cap prevents further exploration, the graph returns `status: "truncated"` with explicit reasons chosen from `block-limit`, `instruction-limit`, `byte-limit`, and `edge-limit`. A truncated graph is a valid partial result and is never presented as complete.

Deterministic non-call direct branches may be traversed. Conditional branches may create both taken and valid same-component fall-through edges. Direct calls are fully annotated but their callees are not queued as CFG blocks. Indirect call targets are recorded as unresolved rather than guessed; caller-side sequential decoding can continue at the valid fall-through. Indirect branches and returns terminate the current block. Register-indirect targets never receive invented addresses or modes.

Static disassembly is independent of physical Catalina/DeSmuME Dynamic Debugging acceptance. Passing the Capstone.js tests or package smoke check does not constitute native emulator-debugger acceptance.

### Proven reference discovery

Reference discovery is deliberately narrower than generic pattern or pointer searching. RE-MCP emits only deterministic single-instruction references in four classes:

- `direct-branch`
- `direct-call`
- `literal-pool`
- `pc-relative-address`

Direct branch/call references also retain the canonical ARM/Thumb target mode when control-flow decoding proves it. Data/address references such as literal-pool slots do not receive an invented target mode.

`literal-pool` means the architecturally computed literal-pool **slot address**. The word stored in that slot is not automatically interpreted as another pointer or reference. Ordinary immediates are not references merely because their numeric value looks like a ROM/RAM address, and this milestone performs no register-value or broader data-flow inference.

`nds_list_references` is source → reference analysis. It decodes one bounded sequential ARM/Thumb window using the same source policy as `nds_disassemble_range`, classifies each decoded instruction, and does not follow branches or calls. Its bounds are therefore the same:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Instructions | 32 | 256 |
| Source bytes | 128 | 1,024 |

`nds_find_xrefs` is target → cross-reference analysis. It scans only caller-selected static scope for one processor, using deterministic FIFO traversal from proven code seeds. Main code has one implicit ARM seed at the processor's NDS header entry point. Overlays are scanned only when the caller supplies an explicit aligned ARM/Thumb seed for that uncompressed overlay or a proven direct branch/call from already scanned code reaches it. Selecting an overlay does not imply that it is loaded at runtime.

A direct call may expand **xref search coverage** because the purpose of this tool is to discover references in proven reachable code. This does not change `nds_analyze_control_flow`: the CFG tool still records direct calls without traversing their callees.

Reverse-xref search bounds are:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Components | 32 | 128 |
| Basic blocks | 128 | 512 |
| Instructions | 2,048 | 16,384 |
| Decoded source bytes | 8 KiB | 64 KiB |
| Traversal edges | 512 | 4,096 |
| Returned xrefs | 256 | 2,048 |

The result status is one of:

- `complete`: all selected/considered components had proven seeds and their bounded reachable work completed;
- `partial-coverage`: at least one selected component could not be proven/scanned, but no global scan limit truncated explored work;
- `truncated`: one or more scan/result limits prevented complete bounded exploration.

Per-component coverage is explicit:

- `scanned`
- `no-proven-seed`
- `compressed-overlay-not-decodable`
- `out-of-limit`

A result containing zero xrefs is definitive for the selected static scope only when `status === "complete"`. A zero-result `partial-coverage` or `truncated` response is intentionally not presented as proof that no xref exists.

Runtime targets may preserve `resolved`, ambiguous-overlay, BSS, compressed-overlay, or unmapped ownership metadata; reference matching still uses the exact requested runtime address. A ROM-offset target is accepted only when that offset maps to exactly one runtime address for the selected processor. Structural/NitroFS-only bytes are not reverse-xref targets in this milestone.

Reference searches are on-demand only. RE-MCP does not create a persistent whole-ROM xref database or index. Raw pattern search is a separate exact byte-level facility and does not change or broaden the deterministic reference classifier. Heuristic pointer discovery and arbitrary immediate-pointer inference remain deferred.

### Proven function-entry discovery

`nds_discover_functions` and `nds_analyze_function` add a higher-level static layer without broadening the evidence model. A function **entry** is proven only by one of two sources:

- the selected processor's NDS main executable entry address in ARM mode (`program-entry`); or
- a deterministic resolved direct call whose target address, target ARM/Thumb mode, processor, component, and overlay ownership are exact (`direct-call`).

The following are explicitly **not** function proof: direct or conditional branch targets, indirect calls, returns, alignment, prologue-looking bytes, pointer-like constants, selected overlay IDs, or caller-supplied seeds. Explicit seeds provide bounded code-search coverage only.

A proven function identity is deterministic across:

```text
processor + component + overlay ID + runtime address + ARM/Thumb mode
```

`nds_discover_functions` starts from the selected main program entry plus any validated coverage-only seeds, analyzes bounded CFGs, and follows deterministic resolved direct calls as function-to-function proof. Recursion and mutual recursion terminate through canonical function identity. Distinct direct call sites remain distinct evidence, while duplicate observations of the same site/target are deduplicated.

Direct branches remain intrafunction CFG edges and do not create functions. Indirect calls remain unresolved. The tool does not infer tail calls, shared epilogues, function ends, or exclusive byte ownership.

Whole-operation discovery bounds are:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Components considered | 32 | 128 |
| Proven functions | 128 | 1,024 |
| Direct call sites | 512 | 8,192 |
| Total basic blocks | 512 | 4,096 |
| Total instructions | 4,096 | 32,768 |
| Total decoded source bytes | 32 KiB | 256 KiB |
| Total traversal edges | 2,048 | 16,384 |

Each individual function CFG is also capped independently:

| Per-function CFG limit | Default | Maximum |
| --- | ---: | ---: |
| Basic blocks | 64 | 256 |
| Instructions | 512 | 4,096 |
| Decoded bytes | 2 KiB | 16 KiB |
| Traversal edges | 128 | 1,024 |

Aggregate budgets always dominate. Before a CFG is analyzed, its local limits are clipped to the remaining whole-operation budget so one function cannot overshoot a global cap before returning control.

Discovery status is `complete`, `partial-coverage`, or `truncated`. Component coverage uses the same explicit vocabulary as xref search: `scanned`, `no-proven-seed`, `compressed-overlay-not-decodable`, and `out-of-limit`. Selecting an overlay does not disambiguate overlapping runtime ownership by itself. A call target becomes a proven function only when the canonical control-flow resolver actually produces one exact source.

`nds_analyze_function` focuses on one requested processor/address/mode/optional overlay identity. It first requires that identity to resolve uniquely to exact initialized, uncompressed file-backed code. It then returns one proof status:

- `proven`: program-entry or at least one exact direct-call proof exists;
- `not-proven-function-entry`: the selected proof search completed with no qualifying proof;
- `proof-inconclusive`: no proof was found, but truncation or a coverage gap means a negative conclusion would be unsafe.

A positive proof remains `proven` even when unrelated selected coverage is incomplete; the coverage metadata still reports that incompleteness.

Focused proof-search bounds are:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Components considered | 32 | 128 |
| Blocks decoded | 128 | 512 |
| Instructions decoded | 2,048 | 16,384 |
| Decoded bytes | 8 KiB | 64 KiB |
| Traversal edges | 512 | 4,096 |
| Direct-call proof sites | 256 | 2,048 |

A full target CFG is returned only when the entry is proven, using the standard CFG bounds of 64/256 blocks, 512/4,096 instructions, 2 KiB/16 KiB decoded bytes, and 128/1,024 traversal edges.

Neither function tool claims an end address. Multiple returns, shared epilogues, jump tables, tail branches, interleaved data, and unreachable code make such a claim unsafe under this milestone. Heuristic function discovery and function-boundary ownership inference remain deferred.

This function layer is fully static and does not depend on physical Catalina/DeSmuME Dynamic Debugging acceptance.

### Raw pattern and signature discovery

`nds_search_pattern` searches one validated `.nds` ROM for one deterministic byte-level pattern. It accepts exactly four pattern kinds:

- `byte-signature`
- `integer`
- `ascii`
- `utf16le`

Byte signatures use whitespace-separated exact bytes plus the whole-byte wildcard `??`:

```text
12 34 56 78
12 34 ?? 78
AA ?? ?? FF
```

Concrete bytes must contain exactly two hexadecimal digits. `??` is the only wildcard syntax. Nibble wildcards such as `A?`, regular expressions, alternation, repetition, fuzzy matching, and all-wildcard signatures are rejected.

Typed integers require an explicit width of 8, 16, or 32 bits, explicit little- or big-endian encoding, and explicit signedness. Alignment defaults to 1 byte and may be set explicitly to 1, 2, or 4 bytes. Alignment is checked against the absolute ROM offset; width never silently implies alignment.

ASCII search is exact and case-sensitive and rejects non-ASCII input. UTF-16LE search is also exact and case-sensitive. Neither string mode appends a null terminator, performs Unicode normalization, folds case, or tries alternate encodings.

Every encoded pattern must contain between 1 and 4,096 bytes.

The search scope is either:

- `whole-rom`, which treats the validated ROM file as one physical matching domain; or
- `components`, selecting any bounded combination of ARM9 main, ARM7 main, explicit ARM9/ARM7 overlay IDs, NitroFS file IDs, and exact NitroFS paths.

Component selections retain their canonical boundaries even when physical ranges overlap or are adjacent. Overlapping selected physical bytes are scanned once, but a component-scoped match is valid only when its complete byte span lies inside at least one selected canonical component. A signature cannot begin in one adjacent component and finish in another unless one selected component contains the entire span. `whole-rom` is the explicit mode that permits matches across structural/component boundaries.

Compressed overlays are searchable because this tool operates on physical ROM bytes. RE-MCP searches the exact stored FAT-backed compressed representation and marks the overlay ownership as compressed; it never decompresses the overlay or fabricates a decompressed runtime mapping.

Each physical hit is emitted once in ascending ROM-offset order and preserves every deterministic canonical owner known for the complete hit span. Ownership may include main executable, overlay storage, NitroFS/FAT file, parsed header metadata, FNT, FAT, overlay tables, or `unmapped`. An owner receives a runtime address only when the **entire hit** has a deterministic direct file-backed runtime mapping. For an uncompressed overlay this mapping is limited to the initialized prefix `min(ramSize, romSize)`. Compressed overlay storage never receives a runtime address. `bannerOffset` alone does not define a validated banner extent, so the search tool does not invent banner ownership.

Overlapping matches are preserved. For example, searching `AA AA` in `AA AA AA` returns starts at offsets 0 and 1 relative to that region.

Search limits are:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Returned page size | 100 | 1,000 |
| Match-index `offset` | 0 | 99,999 |
| Physical bytes scanned | 64 MiB | 512 MiB |
| Context bytes per side | 0 | 64 |
| Encoded pattern bytes | — | 4,096 |
| Discovered matches | — | 100,000 |

`offset` is a **match index**, not a ROM-byte offset and not a scan-resume cursor. Increasing `offset` does not extend coverage after a scan-byte truncation. To inspect beyond a `maxScanBytes` boundary, raise the scan budget or narrow/change the selected scope.

A result is `complete` only when the selected physical scope was fully examined. Otherwise it is `truncated`, with explicit reasons chosen from:

- `scan-byte-limit`
- `match-count-limit`

`discoveredMatches` counts only matches actually established before completion or truncation. `nextOffset` is non-null only when the current scan has already discovered later matches beyond the returned page; it does not speculate about unscanned bytes. Therefore a zero-hit result is definitive only when `status === "complete"`.

Optional context bytes are informational only and do not affect matching or the physical scan-byte counter. Whole-ROM context is clipped only to ROM bounds. Component-scoped context remains inside a deterministic selected component that fully contains the hit, so it never leaks across an adjacent component boundary.

Pattern hits are byte-level facts only. RE-MCP does **not** promote a matching integer or byte sequence into a pointer, reference, function, table, or other semantic claim. There is no generic binary search input, caller-supplied byte buffer, arbitrary caller-defined ROM range, output path, persistent signature database, decompression path, or ROM mutation surface.

### Controlled extraction

`nds_extract_component` accepts only canonical component selectors:

- ARM9 main
- ARM7 main
- ARM9 overlay ID
- ARM7 overlay ID
- NitroFS file ID or exact parsed NitroFS path

The caller cannot provide a raw ROM offset, byte length, or output destination. RE-MCP chooses the deterministic location below:

```text
analysis/generated/nds/<first-16-sha256-hex>/
```

Before extraction, RE-MCP verifies that the source ROM still matches the SHA-256 used to construct the canonical map. Extracted artifacts record both the source ROM SHA-256 and their own SHA-256. Compressed overlays are extracted exactly as their stored FAT-backed bytes and remain compressed.

`nds_extract_analysis_bundle` builds the complete static-analysis package transactionally:

```text
analysis/generated/nds/<sha-prefix>/
├── manifest.json
├── address-map.json
├── filesystem.json
├── overlays.json
├── arm9.bin
├── arm7.bin
└── overlays/
    ├── arm9/
    └── arm7/
```

The bundle is assembled in a temporary sibling directory and promoted only when complete. If replacement of an existing completed bundle fails, RE-MCP attempts to restore the previous complete bundle. The bundle intentionally does not extract every NitroFS asset; individual assets remain opt-in through `nds_extract_component`.

### Example static-analysis workflow

1. Call `nds_inspect_rom` to validate the ROM and obtain the canonical structural summary.
2. Use `nds_list_files`, `nds_list_overlays`, and the address resolvers to identify deterministic code/file relationships.
3. Call `nds_search_pattern` to locate an exact/wildcard byte signature, typed constant, or exact string within explicit canonical components or the whole validated ROM.
4. Call `nds_disassemble_range` for a bounded ARM/Thumb instruction window at a validated runtime address or ROM offset.
5. Call `nds_list_references` when you want deterministic references from a bounded sequential source window without traversal.
6. Call `nds_analyze_control_flow` when deterministic non-call direct branch traversal is useful.
7. Call `nds_find_xrefs` to search for references to one runtime target within an explicit same-processor static scope; inspect `status` and component coverage before treating a negative result as definitive.
8. Call `nds_discover_functions` to turn program-entry/direct-call evidence into a bounded proven-function call graph, or `nds_analyze_function` to prove and inspect one exact entry.
9. Extract a specific validated component with `nds_extract_component`, or generate the executable/metadata bundle with `nds_extract_analysis_bundle`, when an external artifact is actually needed.

The canonical static layer still does **not** implement heuristic function discovery, function-end or exclusive-boundary ownership inference, heuristic pointer discovery, persistent pattern/xref/function indexing, symbol recovery, generic binary disassembly/search, broad code/data heuristics, overlay decompression, graphics decoding, runtime overlay-loaded-state detection, Ghidra-to-RE-MCP evidence promotion, watchpoints, ROM mutation, NitroFS rebuilding, or patch generation.

## Controlled Ghidra Integration

Ghidra support is optional and deliberately sits **on top of** the canonical static-analysis layer. It exposes exactly two MCP tools:

- `nds_ghidra_bootstrap`
- `nds_ghidra_status`

Both accept only `{ "rom": "..." }`. There is no generic Ghidra command, arbitrary script runner, caller-selected project path, loader/language selector, raw Ghidra argument list, arbitrary environment map, or caller-selected output path.

### Configuration

`RE_MCP_GHIDRA_HOME` points to a supported local Ghidra 12.x installation. The reference acceptance release is Ghidra 12.1.2. `RE_MCP_GHIDRA_TIMEOUT_MS` defaults to 900000 ms (15 minutes) and is capped at 3600000 ms (60 minutes) per headless invocation.

These settings are optional at server startup. All non-Ghidra tools continue to work without them. Calling `nds_ghidra_bootstrap` without `RE_MCP_GHIDRA_HOME` returns `ghidra-not-configured`; `nds_ghidra_status` only reads deterministic ROM/project state and does not invoke Ghidra.

Example:

```text
RE_MCP_WORKSPACE_ROOT=/absolute/path/to/rom-modding
RE_MCP_GHIDRA_HOME=/absolute/path/to/ghidra_12.1.2_PUBLIC
RE_MCP_GHIDRA_TIMEOUT_MS=900000
```

RE-MCP derives `support/analyzeHeadless` beneath `RE_MCP_GHIDRA_HOME`, requires the installation to expose both `ARM:LE:32:v5t` and `ARM:LE:32:v4t`, invokes with an argument array and `shell: false`, and terminates a headless process if the timeout or `RE_MCP_MAX_OUTPUT_BYTES` bound is exceeded.

### Project and bridge layout

Every full ROM SHA-256 receives an isolated persistent project/state root:

```text
analysis/ghidra/nds/<full-sha256>/
├── project/
└── state/
```

Replaceable bridge inputs stay separate:

```text
analysis/generated/nds/<sha-prefix>/ghidra-bridge/
├── manifest.json
├── evidence/
├── results/
└── scripts/
```

The ARM9 program uses `ARM:LE:32:v5t`; ARM7 uses `ARM:LE:32:v4t`. Uncompressed NDS overlays are represented as true Ghidra overlay address spaces at their canonical runtime offsets, so overlapping overlay addresses remain distinct. Compressed overlays are reported as `not-imported-compressed` and are never decoded or imported as executable runtime bytes.

### Evidence and analyst-work rules

RE-MCP imports only facts it has already established: canonical mappings, exact ARM/Thumb proven entries, program-entry/direct-call proof, and deterministic direct-call evidence. It does **not** invent function-body or function-end boundaries for Ghidra. Normal Ghidra auto-analysis runs after RE-MCP evidence is installed; functions, labels, strings, types, references, switch recovery, decompiler output, and other analysis that Ghidra derives remain non-authoritative to RE-MCP.

Reruns reconcile only RE-MCP-owned metadata and evidence. Analyst-created labels, comments, bookmarks, types, namespaces, function names/signatures, and Ghidra-only discoveries are preserved. If project ownership/state cannot be reconciled safely, RE-MCP returns `project-state-mismatch` instead of overwriting the project.

`nds_ghidra_status` is non-mutating: it does not validate/install Ghidra, regenerate the bridge, run `analyzeHeadless`, or modify project state.

The packaged RE-MCP bundle includes its three Ghidra Java scripts, but it does **not** bundle Ghidra itself. Normal CI/package smoke verifies the bridge, resources, runner, state model, and tool registration without downloading Ghidra. Real Ghidra 12.1.2 acceptance is a separate manual workflow and is also separate from the physical Intel Catalina/DeSmuME debugger acceptance gate.

## Dynamic-debugging tools

The controlled debugger surface consists of nine MCP tools:

- `desmume_breakpoint_add`
- `desmume_breakpoint_remove`
- `desmume_breakpoint_list`
- `desmume_continue`
- `desmume_step_instruction`
- `desmume_pause`
- `desmume_wait_for_stop`
- `desmume_capture_stop_context`
- `desmume_executable_ranges_replace`

The existing `desmume_read_register_packet`, `desmume_read_memory`, `desmume_probe_gdb`, and `desmume_wait_for_gdb` tools share the same owned debugger session rather than opening a competing GDB connection.

### Dynamic-debugging limits

- GDB host is fixed to `127.0.0.1` and the ARM9 port recorded for the current owned DeSmuME process.
- At most 32 active breakpoints are allowed.
- Breakpoints must resolve inside the main ARM9 executable range or an explicitly allowlisted executable range.
- ARM breakpoints must be 4-byte aligned; Thumb breakpoints must be 2-byte aligned.
- `auto` execution mode fails when ARM versus Thumb remains ambiguous.
- Continue and stop-wait requests are bounded to at most 30000 ms.
- Single-step requests allow 1 through 100 instructions, with a bounded wait for every step.
- Stop context captures 64 bytes around PC and up to 64 bytes from SP, clamped at address-space boundaries.
- A stop-context request may add at most eight labeled regions, each from 1 through 4096 bytes.
- Additional executable ranges are capped at 64.
- Stop-context output is bounded by the configured `maxOutputBytes` value.
- Emulator exit, explicit stop, or a new process generation invalidates the old debugger session and session-scoped state.

### Example debugger workflow

1. Call `desmume_start` with a verified launcher, the intended `.nds` ROM, and an ARM9 GDB port. RE-MCP parses the ROM header before launch and initializes the debugger with the derived main ARM9 range.
2. Use `desmume_wait_for_gdb` or `desmume_probe_gdb` to confirm the owned stub is reachable.
3. Add a validated breakpoint with `desmume_breakpoint_add`. Specify `arm` or `thumb` when mode is not already unambiguous.
4. Call `desmume_continue`, optionally supplying `expectedBreakpointId`. Context capture is enabled by default.
5. Inspect the returned stop reason, decoded `pc`/`cpsr`, matched breakpoint, hit count, and bounded memory windows.
6. Use `desmume_step_instruction` for a bounded instruction sequence while stopped.
7. If execution is running after a timeout, use `desmume_wait_for_stop` or `desmume_pause` rather than issuing a stopped-state command.
8. Remove the breakpoint with `desmume_breakpoint_remove` when finished.
9. Call `desmume_stop` or restart the emulator. Session-scoped breakpoints, executable ranges, stop state, and the old GDB connection are invalidated.

## Requirements

- Node.js 20 or newer
- An MCP host that can launch local stdio servers
- A dedicated workspace containing the intended repositories and private ROM-development inputs
- For Ghidra bootstrap, a supported local Ghidra 12.x installation; Ghidra 12.1.2 is the reference acceptance release
- For emulator tools, a verified DeSmuME debug bundle

## Downloadable RE-MCP bundle

The `Package` GitHub Actions workflow publishes a `re-mcp-downloadable-bundle` artifact containing:

- Compiled JavaScript
- Production dependencies, including the pinned Capstone.js WebAssembly backend
- RE-MCP-owned Ghidra Java bridge scripts
- Configuration template
- Installation self-check
- SHA-256 checksum

Before publishing the artifact, the package workflow performs a production-only install inside the assembled bundle, verifies the packaged Ghidra Java resources and controlled tool registration, initializes the packaged Capstone.js runtime, decodes known ARM and Thumb instructions, smoke-classifies an ARM direct call plus a Thumb PC-relative literal-slot reference, smoke-searches a temporary valid NDS ROM through the compiled pattern-search service to verify wildcard overlap and canonical ARM9 ownership, and runs a packaged ARM9 `BL` fixture through proven-function discovery to verify program-entry/direct-call proof and call-edge construction. The package check does not require a Ghidra installation or external disassembler download.

After downloading and extracting the archive:

```bash
cd re-mcp-0.6.0
node scripts/check-install.mjs .
```

The same self-check verifies the required package files, assembled function/Ghidra-tool registration, Ghidra bridge resources, ARM/Thumb decoder fixtures, deterministic reference classifier, packaged NDS pattern-search path, and packaged proven-function discovery path before reporting `ok: true`.

Copy `mcp-config.example.json`, replace the required workspace/server paths, and either set the optional Ghidra paths for Ghidra bootstrap or remove those optional environment entries when Ghidra tools are not needed.

## Build the Catalina-native DeSmuME debugger bundle

The manual **Build Catalina-Native DeSmuME Debug Bundle** workflow builds the DeSmuME 0.9.13 Cocoa dev+ application for Intel `x86_64` Macs with a macOS 10.15 deployment target. It applies a narrow patch that starts the existing ARM9 GDB stub when `RE_MCP_ARM9_GDB_PORT` is supplied.

To run it:

1. Open the repository's **Actions** tab.
2. Select **Build Catalina-Native DeSmuME Debug Bundle**.
3. Select branch `feature/catalina-native-desmume`.
4. Choose **Run workflow**.
5. Download `desmume-catalina-native-debug-bundle` after the job finishes.
6. Verify `desmume-catalina-native-debug.zip` against the accompanying `.zip.sha256` file before extraction.

After extraction on the Catalina Mac:

```bash
xattr -dr com.apple.quarantine desmume-catalina-native-debug
chmod +x desmume-catalina-native-debug/run-desmume-debug.command
./desmume-catalina-native-debug/run-desmume-debug.command \
  /absolute/path/to/Bakugan.nds 20000
```

Only remove quarantine after verifying the checksum and confirming that the artifact came from the expected workflow run.

### Catalina dynamic-debugging acceptance

Automated CI verifies packet framing, breakpoint lifecycle, execution state, timeout behavior, register decoding, context capture, lifecycle reset, and MCP validation. Final acceptance still requires the verified native DeSmuME bundle on the target Intel macOS Catalina system.

Follow [`docs/dynamic-debugging-catalina-acceptance.md`](docs/dynamic-debugging-catalina-acceptance.md) to verify breakpoint installation, continue/stop, PC and CPSR capture, single stepping, pause, breakpoint removal, and debugger-state reset after emulator restart.

## Build RE-MCP from source

```bash
npm install
npm run check
npm run build
```

Run directly without Ghidra integration:

```bash
RE_MCP_WORKSPACE_ROOT=/absolute/path/to/rom-modding \
node dist/index.js
```

Run with the optional controlled Ghidra integration enabled:

```bash
RE_MCP_WORKSPACE_ROOT=/absolute/path/to/rom-modding \
RE_MCP_GHIDRA_HOME=/absolute/path/to/ghidra_12.1.2_PUBLIC \
RE_MCP_GHIDRA_TIMEOUT_MS=900000 \
node dist/index.js
```

The server refuses to start without an explicit workspace root. A Ghidra home is not required unless a Ghidra bootstrap is requested.

## DeSmuME launcher contract
