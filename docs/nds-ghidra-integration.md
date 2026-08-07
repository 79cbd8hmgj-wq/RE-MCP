# Controlled NDS Ghidra Integration

RE-MCP exposes two optional Ghidra-facing MCP tools:

- `nds_ghidra_bootstrap`
- `nds_ghidra_status`

Both accept only a workspace-contained Nintendo DS ROM path. The caller cannot provide a Ghidra executable, project path/name, processor language, loader, script path, raw Ghidra arguments, environment variables, or output path.

## Requirements

The rest of RE-MCP does not require Ghidra. To use these two tools, install a supported Ghidra 12.x release and configure:

```text
RE_MCP_GHIDRA_HOME=/absolute/path/to/ghidra_12.1.2_PUBLIC
RE_MCP_GHIDRA_TIMEOUT_MS=900000
```

The current reference acceptance release is Ghidra 12.1.2 and requires JDK 21. `RE_MCP_GHIDRA_TIMEOUT_MS` defaults to 900000 ms (15 minutes) and is capped at 3600000 ms (60 minutes) per headless subprocess.

RE-MCP derives the exact `support/analyzeHeadless` executable from `RE_MCP_GHIDRA_HOME` and validates the Ghidra version plus the required ARM language IDs before execution:

- ARM9: `ARM:LE:32:v5t`
- ARM7: `ARM:LE:32:v4t`

## Project and bridge layout

Replaceable bridge inputs remain under the existing generated-analysis tree:

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

Persistent analyst state is separate and keyed by the **full** source ROM SHA-256:

```text
analysis/ghidra/nds/<full-sha256>/
├── project/
└── state/
    ├── latest-run.json
    ├── latest-success.json
    └── latest-failure.json
```

This separation is intentional. The generated static bundle may be replaced transactionally; the persistent Ghidra project must not be erased with it.

## Program model

Each SHA-scoped project contains two RE-MCP-owned programs:

- `RE-MCP_ARM9`
- `RE-MCP_ARM7`

ARM9 and ARM7 main executables are imported at their canonical runtime bases using their exact language IDs.

Every **uncompressed** NDS overlay is represented as a true Ghidra overlay address space inside the corresponding processor program. Deterministic names include processor and overlay ID, for example:

```text
RE_MCP_ARM9_OVL_7
RE_MCP_ARM7_OVL_3
```

Two overlays may therefore retain the same physical runtime address without being flattened into one false identity.

Compressed overlays are recorded in the bridge as `not-imported-compressed` and are never decoded or imported as executable runtime bytes. Overlay decompression is a separate future milestone.

Canonical BSS may be represented only as uninitialized runtime-only memory. It never receives fabricated ROM backing.

## Evidence and Ghidra authority

RE-MCP remains authoritative for:

- canonical source ROM SHA-256;
- processor/component/overlay ownership;
- exact runtime/file-backed mappings;
- ARM/Thumb mode when proven;
- function **entry** proof from NDS program entry or exact deterministic direct call;
- exact deterministic direct-call evidence.

RE-MCP does **not** claim a function end or exclusive function body. A proven function entry is imported as an entry seed plus RE-MCP-owned metadata. If Ghidra later creates or expands a function body, that body is Ghidra-derived rather than RE-MCP proof.

Normal Ghidra auto-analysis runs after RE-MCP imports its exact evidence. Ghidra may infer additional functions, references, strings, switch tables, data types, signatures, and decompiler output. Those results remain **non-authoritative** to RE-MCP in this milestone and are not silently promoted into the canonical evidence model.

## Analyst-work preservation

Rerunning `nds_ghidra_bootstrap` for the same ROM SHA reconciles only RE-MCP-owned state. It does not intentionally delete or rename analyst-created labels, comments, bookmarks, types, namespaces, function names/signatures, or Ghidra-only discoveries.

RE-MCP ownership is tracked through dedicated Program Information keys and address property maps rather than symbol names. If existing project state conflicts with that ownership contract in a way that cannot be reconciled safely, bootstrap returns `project-state-mismatch` instead of overwriting the project.

A partial run is also preserved. For example, if ARM9 succeeds and ARM7 fails, a retry processes the already-owned ARM9 program and imports ARM7 rather than assuming project-directory existence proves both programs are present.

## Tool behavior

### `nds_ghidra_bootstrap`

The tool:

1. validates the canonical ROM and full SHA-256;
2. regenerates/validates the deterministic bridge;
3. validates the configured Ghidra installation;
4. imports or processes ARM9 and ARM7 through the fixed `analyzeHeadless` executable;
5. runs RE-MCP-owned pre/post scripts around normal auto-analysis;
6. validates each generated processor result;
7. rechecks source ROM identity;
8. writes persistent success/failure state only after validation.

Subprocess execution uses argument arrays with `shell: false`, a minimal environment, timeout enforcement, and bounded stdout/stderr. Output overflow terminates the Ghidra subprocess rather than allowing unbounded capture.

### `nds_ghidra_status`

`nds_ghidra_status` is non-mutating. It does **not** launch Ghidra, regenerate the bridge, or require `RE_MCP_GHIDRA_HOME` to be usable. It reads the canonical ROM identity plus deterministic bridge/project state and reports the latest known status.

## Relationship to dynamic debugging

Ghidra integration is a static/external-analysis capability and is independent of the DeSmuME ARM9 GDB acceptance gate. A successful Ghidra bootstrap does not constitute physical Catalina/DeSmuME debugger acceptance, and this milestone does not add or modify native debugger behavior.

## Security boundary

The Ghidra integration does not expose:

- an arbitrary shell command;
- an arbitrary Ghidra command or script runner;
- caller-selected `analyzeHeadless` paths;
- caller-selected project paths or names;
- arbitrary loaders or processor IDs;
- arbitrary pre/post scripts;
- raw Ghidra CLI arguments;
- caller-defined environment variables;
- arbitrary binary imports;
- Ghidra-to-RE-MCP evidence promotion;
- compressed-overlay execution/decompression;
- ROM mutation.
