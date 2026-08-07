# NDS Ghidra Integration Design

Date: 2026-08-07
Status: approved design; factual compatibility correction applied after self-review
Base: `main` after Proven Function Discovery

## Goal

Add a controlled Ghidra bootstrap path for canonical Nintendo DS ROMs. RE-MCP remains authoritative for ROM structure, exact source ownership, ARM/Thumb mode evidence, and proven function-entry/direct-call evidence. Ghidra may add heuristic analysis, but those inferences do not silently become RE-MCP facts.

Dynamic DeSmuME/GDB work remains separately gated by physical Catalina acceptance and is not extended by this milestone.

## Selected architecture

Use a versioned RE-MCP bridge manifest plus RE-MCP-owned Ghidra Java scripts, executed only through a server-configured `support/analyzeHeadless` installation.

RE-MCP does not install a custom Ghidra extension and does not embed Ghidra as a Java service. The caller receives no generic Ghidra command/script surface.

## Compatibility target

Initial compatibility target: official Ghidra 12.x releases.

The current reference acceptance release as of 2026-08-07 is **Ghidra 12.1.2**, tag `Ghidra_12.1.2_build`, runnable asset `ghidra_12.1.2_PUBLIC_20260605.zip`, published SHA-256:

```text
b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
```

The implementation must still validate the installed version and required APIs/languages instead of assuming all future 12.x versions are compatible.

Required processor languages:

- ARM9: `ARM:LE:32:v5t`
- ARM7: `ARM:LE:32:v4t`

The bridge fails closed if either language is unavailable.

## Trust boundary and canonical contract

The canonical contract is a deterministic RE-MCP bridge manifest, not the Ghidra project database.

The manifest records:

- full ROM SHA-256 and existing SHA prefix;
- canonical ARM9/ARM7 ROM offsets, runtime bases, sizes, and entrypoints;
- exact initialized file-backed extents;
- overlay processor, overlay ID, file ID, runtime address, RAM size, file-backed size, BSS size, compression state, and backing artifact identity;
- proven function-entry identities using `processor + component + overlayId + runtimeAddress + ARM/Thumb mode`;
- proof records (`program-entry` and exact `direct-call` only);
- deterministic direct-call edges/evidence sites;
- component coverage and truncation metadata;
- bridge-format version and generated artifact hashes.

No Ghidra inference is promoted into the RE-MCP static model by this milestone.

## Filesystem layout

Replaceable bridge inputs remain beneath the existing generated-analysis tree, while persistent analyst state is keyed by the full ROM SHA-256 and stored separately:

```text
analysis/
├── generated/nds/<sha-prefix>/
│   ├── ...existing static bundle...
│   └── ghidra-bridge/
│       ├── manifest.json
│       ├── evidence/
│       │   ├── functions.json
│       │   └── calls.json
│       ├── results/
│       │   ├── arm9.json
│       │   └── arm7.json
│       └── scripts/   # copied RE-MCP scripts for bridge provenance
│
└── ghidra/nds/<full-sha256>/
    ├── project/
    └── state/
        ├── latest-run.json
        ├── latest-success.json
        └── latest-failure.json
```

The persistent project must never live under `analysis/generated/nds/<sha-prefix>/` because `extractNdsAnalysisBundle()` transactionally replaces that root.

The caller cannot supply output/project paths.

## Project model

There is one deterministic local Ghidra project per full ROM SHA-256.

The project contains two primary programs:

- `RE-MCP_ARM9`
- `RE-MCP_ARM7`

Each main executable is imported at its canonical runtime base.

Each **uncompressed** overlay is represented as a true Ghidra overlay memory block/address space at its canonical runtime address. Deterministic names contain processor and overlay ID, for example `RE_MCP_ARM9_OVL_7`, so overlapping runtime ranges remain distinct identities.

Compressed overlays remain explicit manifest records with `not-imported-compressed`; their stored compressed bytes are never decoded/imported as executable runtime code in this milestone.

BSS may be represented only as canonical uninitialized runtime-only memory. It never receives fabricated ROM backing.

## ARM/Thumb and function-entry semantics

RE-MCP proves function **entries**, not exclusive function bodies or function ends.

Before normal auto-analysis:

- the NDS main header entry is imported as ARM proof;
- each RE-MCP-proven entry is tagged with exact identity, proof, and mode;
- processor context is established only where RE-MCP has exact mode evidence;
- deterministic direct-call evidence may be imported as exact references when both caller and target identity are exact.

RE-MCP does **not** fabricate a Ghidra function-body range. If Ghidra later creates/expands a function body, that body is Ghidra-derived and not RE-MCP proof.

## Execution flow

`nds_ghidra_bootstrap`:

1. resolves one `.nds` path inside `RE_MCP_WORKSPACE_ROOT`;
2. parses the canonical NDS map and full SHA-256;
3. regenerates deterministic static/bridge artifacts transactionally;
4. validates all bridge artifact hashes;
5. validates `RE_MCP_GHIDRA_HOME` and derives exact `support/analyzeHeadless`;
6. validates supported version and required ARM languages;
7. creates or opens the full-SHA-scoped local project;
8. imports or processes ARM9 with BinaryLoader, `ARM:LE:32:v5t`, and exact base address;
9. imports or processes ARM7 with BinaryLoader, `ARM:LE:32:v4t`, and exact base address;
10. runs RE-MCP pre-scripts to validate ownership, create/reconcile overlay spaces, establish exact mode context, and import proven-entry/direct-call evidence;
11. runs normal Ghidra auto-analysis;
12. runs an RE-MCP post-script that emits a deterministic processor result into the generated bridge `results/` directory;
13. Node validates the result and only then updates persistent `analysis/ghidra/.../state/` sidecars;
14. re-checks source ROM SHA-256 before reporting success.

A bootstrap may invoke the same validated `analyzeHeadless` executable more than once, for example once for ARM9 and once for ARM7. This does not broaden the executable allowlist.

The RE-MCP script directory is resolved from the RE-MCP installation itself (for source and packaged builds), **not** from `GHIDRA_HOME` and not from caller input.

## Persistent ownership and analyst-work preservation

RE-MCP ownership must not depend on names/comments.

Program Information/options use RE-MCP-prefixed keys such as:

```text
re-mcp.bridge-format
re-mcp.rom-sha256
re-mcp.manifest-sha256
re-mcp.processor
re-mcp.last-import
re-mcp.last-analysis-status
re-mcp.ghidra-version
```

Address-specific property maps use names such as:

```text
re-mcp.function-id
re-mcp.function-proof
re-mcp.function-mode
re-mcp.overlay-id
re-mcp.call-evidence
```

Rerun rules:

1. validate manifest/artifact hashes before project mutation;
2. verify exact ROM SHA and processor ownership metadata;
3. avoid unnecessary program reconstruction when RE-MCP-owned state already matches;
4. add/update only RE-MCP-owned metadata/evidence;
5. preserve analyst labels, comments, bookmarks, types, namespaces, names, signatures, and Ghidra-only discoveries;
6. do not delete Ghidra-derived objects merely because RE-MCP does not prove them;
7. fail `project-state-mismatch` when reconciliation would risk analyst data.

“Idempotent” means identical bridge inputs leave RE-MCP-owned state unchanged and avoid destructive reconstruction. It does not require the entire Ghidra database to be byte-identical after repeated auto-analysis.

## MCP surface

Exactly two public Ghidra-facing tools:

- `nds_ghidra_bootstrap`
- `nds_ghidra_status`

Both accept only the ROM path plus any future bounded non-command options explicitly added to schema. This milestone should initially use only `{ rom }`.

There is no generic Ghidra command, arbitrary script runner, arbitrary project path, arbitrary loader/language, raw CLI argument list, arbitrary environment map, or caller-selected output path.

`nds_ghidra_status` performs no Ghidra invocation and no mutation. It reads canonical ROM identity plus deterministic bridge/project state metadata.

## Configuration and subprocess safety

Server-side configuration:

```text
RE_MCP_GHIDRA_HOME=/absolute/path/to/ghidra
RE_MCP_GHIDRA_TIMEOUT_MS=<positive integer>
```

`RE_MCP_GHIDRA_HOME` is optional at server startup. Calling a Ghidra tool without it returns `ghidra-not-configured`.

`RE_MCP_GHIDRA_TIMEOUT_MS` defaults to **900,000 ms (15 minutes)** and is capped at **3,600,000 ms (60 minutes)** per headless subprocess invocation.

Subprocess requirements:

- exact `analyzeHeadless` derived beneath configured home;
- argument-array invocation only;
- `shell: false`;
- no caller-controlled executable/script path;
- bounded environment;
- timeout termination;
- stdout/stderr bounded by `RE_MCP_MAX_OUTPUT_BYTES`;
- process termination on output overflow;
- stage-aware exit/error mapping;
- no network requirement during bootstrap;
- no ROM mutation.

## Failure model

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

A failed rerun never authorizes deletion of the previous usable project.

## Verification

Normal CI, without Ghidra installed, covers:

- deterministic manifest/path/identity rules;
- full-SHA separation/prefix-collision behavior;
- bridge generation and artifact hashes;
- compressed-overlay omission;
- proven-entry/direct-call evidence without invented bodies;
- installation/version/language validation against fixtures;
- exact command construction;
- `shell: false`, timeout and output-limit behavior;
- reconciliation/analyst-preservation contract tests;
- MCP schemas/error mapping;
- packaged Java resource presence/integrity.

A **manual-only** real-Ghidra workflow uses official **Ghidra 12.1.2** plus a synthetic NDS fixture to verify:

- ARM9 v5t and ARM7 v4t program creation;
- exact main runtime bases;
- overlapping true overlay spaces;
- compressed-overlay omission;
- ARM/Thumb proven-entry metadata;
- no RE-MCP-invented body boundary;
- normal auto-analysis;
- rerun preservation of analyst markers.

Normal `push`/`pull_request` CI must not download Ghidra.

## Non-goals

This milestone does not add:

- Ghidra-to-RE-MCP evidence promotion;
- arbitrary command/script execution;
- arbitrary binary import;
- custom output/project paths;
- GUI automation;
- custom Ghidra extension installation;
- shared/server Ghidra projects;
- overlay decompression;
- heuristic RE-MCP function discovery;
- function-end/exclusive-body proof;
- ROM mutation/patch generation;
- new DeSmuME/GDB capability.

## Acceptance criteria

Complete when:

1. `nds_ghidra_bootstrap` safely creates/reconciles a full-SHA local project through only configured `analyzeHeadless`.
2. ARM9/ARM7 use explicit v5t/v4t languages and canonical bases.
3. Every importable uncompressed overlay uses a distinct Ghidra overlay space.
4. Compressed overlays are never imported as executable runtime bytes.
5. Proven entry/mode/proof/direct-call evidence exists before auto-analysis without fabricated bodies.
6. Ghidra auto-analysis remains non-authoritative to RE-MCP.
7. Identical reruns preserve analyst work and avoid unnecessary destructive reconstruction.
8. Ownership conflicts fail closed.
9. Subprocess execution is shell-free, bounded, timeout-limited, and output-capped.
10. `nds_ghidra_status` is non-mutating and does not invoke Ghidra.
11. Normal unit/runner/reconciliation/package checks pass without Ghidra.
12. Manual Ghidra 12.1.2 acceptance passes.
13. Native debugger production behavior remains unchanged.

## Upstream references verified 2026-08-07

- Ghidra latest release page: `https://github.com/NationalSecurityAgency/ghidra/releases/latest`
- Ghidra 12.1.2 release tag: `https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build`
- Headless API: `https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessAnalyzer.html`
- Headless options: `https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessOptions.html`
- Memory overlays: `https://ghidra.re/ghidra_docs/api/ghidra/program/model/mem/Memory.html`
- Program/options/property maps: `https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/Program.html`
- ARM language definitions: `https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/Processors/ARM/data/languages/ARM.ldefs`
