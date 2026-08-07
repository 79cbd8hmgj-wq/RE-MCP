# NDS Ghidra Integration Design

Date: 2026-08-07
Status: approved design, pending written-spec review
Base: `main` after Proven Function Discovery

## 1. Goal

Add a controlled Ghidra bootstrap path for canonical Nintendo DS ROMs so RE-MCP can create and maintain a useful Ghidra project without weakening RE-MCP's evidence model or exposing arbitrary shell/Ghidra execution.

The integration is intentionally asymmetric:

- RE-MCP remains authoritative for canonical ROM structure, exact source ownership, ARM/Thumb mode evidence, and proven function-entry/direct-call evidence.
- Ghidra may add heuristic analysis such as additional functions, labels, strings, data types, switch recovery, references, and decompiler output.
- Ghidra-derived analysis does not silently become RE-MCP evidence in this milestone.
- Dynamic DeSmuME/GDB work remains separately gated by physical Catalina acceptance and is not extended here.

## 2. Selected approach

Use a versioned RE-MCP bridge manifest plus RE-MCP-owned Ghidra scripts, executed only through a configured `analyzeHeadless` installation.

RE-MCP does not install a custom Ghidra extension and does not embed Ghidra as a Java service. This keeps Ghidra replaceable, preserves RE-MCP ownership of the evidence contract, avoids a plugin-distribution problem, and keeps normal CI independent of a Ghidra installation.

## 3. Ghidra compatibility target

Initial compatibility target: official Ghidra 12.x releases.

As of 2026-08-07, Ghidra 12.1 is the latest official release. The implementation must not assume every future 12.x build is compatible merely from its version string. Bootstrap validates the required installation structure, languages, and script/API behavior, records the observed version, and rejects installations outside the explicitly supported policy.

Ghidra 12.x provides the primitives used by this design:

- local headless project creation/opening;
- ordered pre-scripts, auto-analysis, and post-scripts;
- BinaryLoader import controls;
- initialized overlay memory blocks/address spaces;
- program information options;
- address-indexed property maps.

Nintendo DS processor programs use explicit Ghidra languages:

- ARM9: `ARM:LE:32:v5t`;
- ARM7: `ARM:LE:32:v4t`.

The bridge fails closed if either required language is unavailable.

## 4. Trust boundary

The canonical contract is a deterministic RE-MCP bridge manifest, not the Ghidra database.

The manifest records:

- full source ROM SHA-256 and existing SHA prefix;
- game/header identity metadata needed to identify the source;
- ARM9 and ARM7 ROM offsets, runtime bases, sizes, and header entrypoints;
- exact initialized file-backed executable extents;
- overlay processor, overlay ID, file ID, runtime address, RAM size, file-backed size, BSS size, compression state, and backing artifact identity;
- proven function-entry identities using RE-MCP's canonical identity:
  `processor + component + overlayId + runtimeAddress + ARM/Thumb mode`;
- proof records (`program-entry` and exact `direct-call` only);
- deterministic direct-call edges and evidence sites;
- component coverage and truncation metadata needed to distinguish established facts from incomplete search coverage;
- bridge format version and generated artifact hashes.

Ghidra may enrich analysis, but nothing inferred by Ghidra is promoted into the RE-MCP static model by this milestone.

## 5. Filesystem layout

Replaceable bridge inputs remain under the generated static-analysis tree. Persistent analyst state lives separately and is keyed by the full ROM SHA-256.

```text
analysis/
├── generated/nds/<sha-prefix>/
│   ├── ...existing static bundle...
│   └── ghidra-bridge/
│       ├── manifest.json
│       ├── evidence/
│       │   ├── functions.json
│       │   └── calls.json
│       └── scripts/
│           ├── ReMcpPrepareProgram.java
│           ├── ReMcpImportEvidence.java
│           └── ReMcpRecordAnalysis.java
│
└── ghidra/nds/<full-sha256>/
    └── project/
        └── <deterministic Ghidra project files>
```

The existing `extractNdsAnalysisBundle()` transactionally replaces `analysis/generated/nds/<sha-prefix>/`; therefore the persistent Ghidra project must never be placed inside that root.

The generated bridge manifest always carries the full SHA-256 and rejects any prefix collision or project/manifest identity mismatch.

Both roots are RE-MCP-derived, workspace-contained paths. The caller cannot supply an output directory or project location.

## 6. Project model

There is one deterministic local Ghidra project per full ROM SHA-256.

The project contains two primary programs:

- ARM9 program;
- ARM7 program.

Each program contains its processor's main executable at the exact canonical runtime base.

Every uncompressed overlay is represented as a true Ghidra overlay memory block/address space at its canonical runtime offset. Overlay spaces use deterministic names containing processor and overlay ID so two overlays that reuse the same runtime address remain distinct identities instead of being flattened or guessed to coexist.

Compressed overlays are not imported as executable code. They remain represented in the bridge manifest with `not-imported-compressed` status and exact stored backing metadata. Decompressed runtime mapping remains deferred to the overlay-decompression milestone.

BSS has no ROM backing. Where useful for program context, an uninitialized BSS block may be created only from canonical BSS metadata and is marked runtime-only; it is never presented as file-backed evidence.

## 7. Proven entries, ARM/Thumb mode, and function bodies

RE-MCP proves **function entries**, not exclusive function bodies or end addresses. The Ghidra bridge must preserve that distinction.

Before normal Ghidra auto-analysis:

- the main NDS header entry is imported as an ARM proven-entry seed;
- every RE-MCP-proven function entry is tagged with its exact canonical identity, proof, and ARM/Thumb mode;
- processor context is established only where RE-MCP has exact mode evidence;
- RE-MCP initiates/marks analysis from the proven entry without inventing a function end or body range;
- deterministic direct-call evidence may be imported as exact references to the corresponding physical or overlay address space when the target identity is exact.

RE-MCP does **not** fabricate a Ghidra function body from a proven entry. If Ghidra creates or expands a function body during auto-analysis, that body is Ghidra-derived. RE-MCP's property metadata remains attached to the proven entry and must not be interpreted as proof of Ghidra's inferred body extent.

No unproven address receives an invented ARM/Thumb mode merely to improve analysis.

## 8. Headless execution flow

`nds_ghidra_bootstrap` performs these stages:

1. Resolve the requested `.nds` path inside the configured workspace.
2. Parse the canonical NDS map and establish the full ROM SHA-256.
3. Generate or refresh deterministic static/bridge artifacts transactionally.
4. Validate every bridge artifact hash before invoking Ghidra.
5. Resolve `RE_MCP_GHIDRA_HOME` and derive the exact `support/analyzeHeadless` path beneath it.
6. Validate installation structure, supported version, and required ARM languages.
7. Create or open the deterministic full-SHA-scoped local project.
8. Import/reconcile ARM9 with BinaryLoader, `ARM:LE:32:v5t`, the canonical base address, and RE-MCP pre-analysis scripts.
9. Import/reconcile ARM7 with BinaryLoader, `ARM:LE:32:v4t`, the canonical base address, and RE-MCP pre-analysis scripts.
10. For each processor, the pre-analysis scripts reconcile overlay spaces and import RE-MCP proven-entry/direct-call evidence.
11. Run normal Ghidra auto-analysis.
12. Run a post-analysis RE-MCP script that records completion/version/manifest metadata without promoting Ghidra inferences into RE-MCP.
13. Re-check source ROM SHA-256 before reporting success.
14. Return a bounded structured result.

One headless invocation has one selected import language/configuration, so a single bootstrap may invoke the same validated `analyzeHeadless` entrypoint more than once, such as once for ARM9 and once for ARM7. This does not broaden the executable allowlist.

The design relies on Ghidra's documented processing order: import, ordered pre-scripts, auto-analysis unless disabled, then ordered post-scripts.

## 9. Persistent-project ownership

RE-MCP ownership must not depend on symbol names, comments, or Ghidra-generated function names.

Program-level metadata is stored in Ghidra Program Information/options under RE-MCP-prefixed keys such as:

```text
re-mcp.bridge-format
re-mcp.rom-sha256
re-mcp.manifest-sha256
re-mcp.processor
re-mcp.last-import
re-mcp.last-analysis-status
re-mcp.ghidra-version
```

Address-specific evidence uses dedicated RE-MCP property maps, for example:

```text
re-mcp.function-id
re-mcp.function-proof
re-mcp.function-mode
re-mcp.overlay-id
re-mcp.call-evidence
```

Stable metadata identifies the bridge-owned evidence even if an analyst renames a Ghidra function, changes its signature, or adds comments/bookmarks/types.

## 10. Rerun and reconciliation semantics

Rerunning bootstrap for the same ROM SHA must preserve analyst work.

Reconciliation rules:

1. Validate the bridge manifest and artifact hashes before project mutation.
2. Verify the existing project/program metadata matches the exact ROM SHA and expected processor identity.
3. If manifest identity and RE-MCP-owned evidence already match, avoid rebuilding/replacing programs or owned objects unnecessarily.
4. Add newly available RE-MCP-owned overlay/evidence records.
5. Update only RE-MCP-owned metadata/evidence.
6. Do not overwrite analyst-created labels, comments, bookmarks, types, namespaces, function names, signatures, or unrelated Ghidra analysis.
7. Do not delete a Ghidra-discovered object merely because RE-MCP does not independently prove it.
8. If existing state conflicts with RE-MCP ownership metadata in a way that cannot be reconciled without risking analyst data, stop with `project-state-mismatch`.

"Idempotent" in this milestone means **RE-MCP-owned bridge state is unchanged for identical inputs and no unnecessary destructive reconstruction occurs**. It does not require the entire Ghidra project database to be byte-identical after repeated auto-analysis, because Ghidra may maintain or refine its own derived analysis state.

If an RE-MCP-owned program must be replaced, replacement is prepared and validated before the old owned program is removed/replaced. A failure never authorizes deletion of unrelated project contents.

## 11. Auto-analysis authority

Normal Ghidra auto-analysis runs after RE-MCP facts have been imported.

Useful Ghidra discoveries may include:

- additional candidate functions;
- inferred references;
- strings/data objects;
- switch/jump-table recovery;
- signatures/types;
- decompiler output.

These are non-authoritative to RE-MCP. No Ghidra-to-RE-MCP feedback/import tool is included in this milestone.

A later Static ↔ Runtime Correlation or evidence-promotion milestone may define how external observations are independently validated before becoming RE-MCP evidence.

## 12. MCP tools

### `nds_ghidra_bootstrap`

Purpose: generate/reconcile the deterministic Ghidra project for one validated workspace ROM.

The caller supplies the ROM path plus only bounded bootstrap options that cannot alter command/project/script identity. The caller cannot supply:

- executable path;
- project directory or project name;
- arbitrary processor/language;
- loader class;
- pre/post script path;
- shell string;
- raw Ghidra arguments;
- arbitrary environment variables;
- output path.

The result includes at least:

- ROM SHA-256;
- project path relative to workspace;
- Ghidra version;
- bridge format and manifest SHA-256;
- ARM9/ARM7 import/reconcile status;
- imported overlay counts;
- compressed-overlay omission counts/IDs;
- imported proven-entry/direct-call evidence counts;
- auto-analysis completion state;
- whether bridge-owned state was initial, reconciled, or already current;
- warnings/coverage gaps/truncation inherited from RE-MCP evidence;
- bounded diagnostic excerpts.

### `nds_ghidra_status`

Purpose: inspect the SHA-scoped project and latest bridge/run metadata without invoking analysis or mutating Ghidra.

Status reports project existence/identity, bridge identity, Ghidra version recorded at last run, imported program/overlay/evidence counts, latest analysis state, compressed omissions, and last structured failure metadata if present.

There is no generic Ghidra command or arbitrary Ghidra-script tool.

## 13. Configuration and subprocess safety

Add server-side Ghidra configuration:

```text
RE_MCP_GHIDRA_HOME=/absolute/path/to/ghidra
RE_MCP_GHIDRA_TIMEOUT_MS=<positive bounded integer>
```

`RE_MCP_GHIDRA_HOME` is optional for server startup so non-Ghidra tools continue to work. Calling a Ghidra tool without it returns `ghidra-not-configured`.

`RE_MCP_GHIDRA_TIMEOUT_MS` defaults to 900,000 ms (15 minutes) and is capped at 3,600,000 ms (60 minutes). The cap applies to each headless subprocess invocation; the top-level bootstrap also stops launching further stages after a failure or exhausted operation budget.

The implementation derives `support/analyzeHeadless` from the configured root and validates that it is contained by that root and has the expected installation structure.

Subprocess requirements:

- argument-array invocation only;
- `shell: false`;
- no caller-controlled executable or script path;
- bounded environment;
- dedicated timeout;
- bounded stdout/stderr under `RE_MCP_MAX_OUTPUT_BYTES`;
- termination on timeout or output overflow;
- exit-code and stage-aware error mapping;
- no network requirement during bootstrap;
- no ROM mutation.

The source ROM SHA-256 is checked before generation, immediately before Ghidra execution, and after the top-level operation. A changing ROM invalidates the result.

## 14. Failure model

Structured categories include:

```text
ghidra-not-configured
invalid-ghidra-installation
unsupported-ghidra-version
ghidra-language-unavailable
ghidra-project-locked
bridge-generation-failed
ghidra-import-failed
ghidra-analysis-failed
ghidra-analysis-timeout
ghidra-output-limit
project-state-mismatch
invalid-rom
```

A failure identifies the stage and provides corrective action through the existing NDS tool-error pattern.

A failed rerun never implies the previous usable project should be deleted.

## 15. Determinism and bounds

Bridge JSON uses deterministic ordering for processors, overlays, proven entries, proofs, and call edges.

Generated names are derived from stable processor/overlay/SHA identities, not timestamps or caller labels.

The bridge does not export an unbounded whole-ROM semantic database. It serializes canonical structure plus the bounded proven-entry/call evidence already available from RE-MCP. Existing discovery/xref coverage and truncation fields remain visible rather than being erased by Ghidra's broader analysis.

`RE_MCP_MAX_OUTPUT_BYTES` still governs captured/returned output. Ghidra execution has the dedicated timeout described above.

## 16. Verification strategy

### 16.1 Manifest/unit tests

Cover:

- deterministic ordering and hashes;
- full-SHA project identity and prefix-collision rejection;
- ARM9/ARM7 language selection;
- exact runtime bases/entrypoints;
- overlay identity/address mapping;
- overlapping overlays remaining distinct;
- compressed-overlay omission;
- BSS runtime-only semantics;
- proven ARM/Thumb entry evidence without invented body boundaries;
- direct-call evidence;
- incomplete coverage/truncation preservation;
- malformed manifest/artifact rejection.

### 16.2 Runner tests

Use a fake `analyzeHeadless` fixture to verify:

- exact executable derivation;
- exact argument arrays;
- `shell: false`;
- no caller-controlled command injection;
- 15-minute default and 60-minute maximum timeout policy;
- timeout termination;
- output cap behavior;
- nonzero exit handling;
- missing/invalid installation handling;
- language/version validation;
- project-lock/error classification.

### 16.3 Reconciliation contract tests

Model/fixture tests cover:

- first import;
- identical bridge-state rerun;
- newly proven evidence;
- changed RE-MCP-owned metadata;
- analyst-renamed functions;
- analyst comments/bookmarks/types;
- Ghidra-only discovered functions;
- project lock;
- interrupted/failed update;
- ROM SHA mismatch;
- ownership conflict returning `project-state-mismatch` rather than destructive repair.

### 16.4 Real-Ghidra acceptance

A dedicated/manual integration workflow uses a supported official Ghidra 12.x installation (current reference release: 12.1) and a synthetic valid NDS fixture to verify:

- project creation;
- ARM9 `ARM:LE:32:v5t` program;
- ARM7 `ARM:LE:32:v4t` program;
- exact main runtime bases;
- overlapping Ghidra overlay spaces;
- imported ARM/Thumb proven-entry evidence;
- no RE-MCP-invented function-body boundary;
- RE-MCP property metadata;
- normal auto-analysis;
- identical bridge-state rerun without destructive reconstruction;
- analyst-work preservation.

Normal repository CI must not download Ghidra or require Ghidra to be installed. Bridge-format, runner, safety, and script-contract behavior remains testable using fixtures/mocks.

### 16.5 Package smoke

The downloadable RE-MCP bundle must contain all bridge schemas/resources and RE-MCP-owned Ghidra scripts. Package self-check verifies their presence and integrity without requiring Ghidra.

## 17. Non-goals

This milestone does not add:

- Ghidra-to-RE-MCP evidence promotion;
- arbitrary Ghidra script execution;
- arbitrary command execution;
- arbitrary binary import;
- custom output/project paths;
- Ghidra GUI automation;
- custom Ghidra extension installation;
- Ghidra server/shared-repository support;
- overlay decompression;
- heuristic RE-MCP function discovery;
- function-end/exclusive-boundary proof;
- symbols/debug-info recovery beyond what Ghidra independently infers;
- ROM mutation or patch generation;
- any new DeSmuME/GDB capability.

## 18. Acceptance criteria

The milestone is complete when:

1. `nds_ghidra_bootstrap` creates or safely reconciles a full-SHA-scoped local Ghidra project through only the configured `analyzeHeadless` executable.
2. ARM9 and ARM7 are imported at canonical runtime addresses with explicit v5t/v4t languages.
3. Every importable uncompressed overlay is represented as a distinct Ghidra overlay space at its canonical runtime offset.
4. Compressed overlays are never decoded/imported as executable bytes and are reported explicitly.
5. RE-MCP-proven entry modes/proofs and deterministic direct-call evidence are present before auto-analysis without inventing function-body boundaries.
6. Normal Ghidra auto-analysis runs without promoting its inferences into RE-MCP.
7. Re-running identical bridge inputs leaves RE-MCP-owned state unchanged, avoids unnecessary destructive reconstruction, and preserves analyst work.
8. Conflicting ownership/project state fails closed instead of destructively repairing the project.
9. Subprocess invocation is bounded, shell-free, allowlisted, timeout-limited, and output-capped.
10. `nds_ghidra_status` reports project/bridge/analysis state without mutation.
11. Unit/runner/reconciliation tests pass in normal CI without Ghidra.
12. Package smoke confirms all required bridge resources/scripts are shipped.
13. Real-Ghidra acceptance passes against the supported 12.x reference installation.
14. No native-debugger-dependent production code is changed.

## 19. Upstream assumptions verified for this design

Verified against current Ghidra documentation/source on 2026-08-07:

- `HeadlessAnalyzer.processLocal` opens an existing local project or creates one and executes pre-scripts, auto-analysis, then post-scripts.
- BinaryLoader exposes explicit base-address loader options.
- `Memory.createInitializedBlock(..., overlay=true)` creates a distinct overlay address space at the corresponding physical offset.
- Program Information/options and address property maps can carry RE-MCP ownership metadata.
- Ghidra ARM language definitions include `ARM:LE:32:v5t` and `ARM:LE:32:v4t`.
- Ghidra 12.1 is the current official release as of the design date.

Primary upstream references:

- `https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessAnalyzer.html`
- `https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessOptions.html`
- `https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html`
- `https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html`
- `https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Processors/ARM/data/languages/ARM.ldefs`
- `https://github.com/NationalSecurityAgency/ghidra/releases`

These are implementation dependencies and must be covered by compatibility/acceptance tests rather than assumed permanently stable.