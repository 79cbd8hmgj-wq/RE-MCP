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
- Extract validated ARM9, ARM7, overlay, or NitroFS components to a deterministic generated-analysis tree
- Build a transactional static-analysis bundle without dumping every NitroFS asset

The source ROM is read-only. Generated NDS artifacts are restricted to `analysis/generated/nds/<sha-prefix>/` under the configured workspace. RE-MCP does not accept generic binary inputs, caller-selected output paths, or arbitrary ROM offset/length extraction requests.

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

The static-analysis surface consists of eleven MCP tools:

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

These tools are native-independent and have no DeSmuME or GDB dependency.

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

Reference searches are on-demand only. RE-MCP does not create a persistent whole-ROM xref database or index. Generic byte signatures, string/pattern searching, heuristic pointer discovery, and arbitrary immediate-pointer inference remain deferred.

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
3. Call `nds_disassemble_range` for a bounded ARM/Thumb instruction window at a validated runtime address or ROM offset.
4. Call `nds_list_references` when you want deterministic references from a bounded sequential source window without traversal.
5. Call `nds_analyze_control_flow` when deterministic non-call direct branch traversal is useful.
6. Call `nds_find_xrefs` to search for references to one runtime target within an explicit same-processor static scope; inspect `status` and component coverage before treating a negative result as definitive.
7. Extract a specific validated component with `nds_extract_component`, or generate the executable/metadata bundle with `nds_extract_analysis_bundle`, when an external artifact is actually needed.

This milestone still does **not** implement heuristic function discovery or function-boundary claims, generic byte/string/signature pattern search, heuristic pointer discovery, persistent xref indexing, symbol recovery, generic binary disassembly, broad code/data heuristics, overlay decompression, graphics decoding, runtime overlay-loaded-state detection, Ghidra/radare2 integration, watchpoints, ROM mutation, NitroFS rebuilding, or patch generation.

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
- For emulator tools, a verified DeSmuME debug bundle

## Downloadable RE-MCP bundle

The `Package` GitHub Actions workflow publishes a `re-mcp-downloadable-bundle` artifact containing:

- Compiled JavaScript
- Production dependencies, including the pinned Capstone.js WebAssembly backend
- Configuration template
- Installation self-check
- SHA-256 checksum

Before publishing the artifact, the package workflow performs a production-only install inside the assembled bundle, initializes the packaged Capstone.js runtime, decodes known ARM and Thumb instructions, and smoke-classifies an ARM direct call plus a Thumb PC-relative literal-slot reference. The check requires no external disassembler or runtime asset download.

After downloading and extracting the archive:

```bash
cd re-mcp-0.6.0
node scripts/check-install.mjs .
```

The same self-check verifies the required package files, ARM/Thumb decoder fixtures, and packaged deterministic reference classifier before reporting `ok: true`.

Copy `mcp-config.example.json`, replace both absolute paths, and add the resulting configuration to your MCP host.

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

Run directly:

```bash
RE_MCP_WORKSPACE_ROOT=/absolute/path/to/rom-modding \
node dist/index.js
```

The server refuses to start without an explicit workspace root.

## DeSmuME launcher contract

The currently verified Linux launcher contract is:

```bash
run-desmume-debug.sh --arm9gdb=20000 /path/to/game.nds
```

The Catalina-native bundle uses:

```bash
run-desmume-debug.command /path/to/game.nds 20000
```

RE-MCP owns at most one emulator child process per server instance. It rejects duplicate starts, captures bounded logs, resets session-scoped debugger state when that process exits, and terminates the owned emulator during MCP shutdown.

## Security model

- No arbitrary shell tool
- No shell interpolation
- Fixed executable and argument construction
- Workspace path containment
- Process timeouts and bounded output
- Minimal child-process environment
- Milestone 6E installation restricted to dry-run mode
- One server-owned DeSmuME process
- GDB restricted to the owned localhost ARM9 port
- Breakpoints restricted to validated executable ranges
- Maximum 32 active breakpoints and 100 instructions per single-step request
- Bounded continue, wait, pause, register, memory, and stop-context operations
- Controlled GDB packets only: software breakpoint insert/remove, continue, single-step, interrupt, register read, bounded memory read, and stop-status query
- No arbitrary GDB packet tool
- No register writes, general memory writes, or watchpoints
- Runtime evidence restricted to project `analysis/generated`
- NDS source ROMs are read-only; generated static-analysis artifacts are restricted to `analysis/generated/nds/<sha-prefix>/`
- NDS extraction accepts canonical component selectors only; no raw offset/length extraction or caller-controlled output path
- NDS disassembly and reference listing accept canonical NDS code mappings only; no generic binary path, caller-provided byte buffer, arbitrary base address, or arbitrary raw byte range
- ARM/Thumb linear decoding and source-reference listing are bounded to 256 instructions and 1,024 bytes per request
- CFG traversal is bounded to 256 blocks, 4,096 instructions, 16 KiB decoded bytes, and 1,024 traversal edges
- Reverse-xref traversal is bounded to 128 components, 512 blocks, 16,384 instructions, 64 KiB decoded bytes, 4,096 traversal edges, and 2,048 returned xrefs
- Only deterministic single-instruction direct branch/call, literal-pool-slot, and PC-relative address-construction references are emitted
- Literal-pool contents and pointer-looking ordinary immediates are not interpreted as references
- `nds_find_xrefs` may follow proven direct calls for search coverage, while `nds_analyze_control_flow` continues to annotate calls without traversing them
- Reverse-xref coverage gaps and truncation are explicit; a zero-xref result is definitive for selected scope only when status is `complete`
- No persistent xref index, generic pattern/signature search, or heuristic pointer discovery
- Indirect targets are never guessed
- Compressed overlay runtime bytes and BSS are never disassembled and never receive fabricated direct ROM offsets
- Overlapping static overlay ranges are reported as ambiguous candidates rather than guessed
- Static overlay selection/disassembly/reference search never claims that an overlay is loaded at runtime
- Static operations revalidate the source ROM SHA-256 before and after decoding/searching
- Debugger session, breakpoint registry, executable ranges, and stop state reset with emulator lifecycle
- No attachment to unrelated emulator processes

Do not use your general home directory as `RE_MCP_WORKSPACE_ROOT`. Create a dedicated directory containing only the repositories and private inputs intended for RE-MCP.