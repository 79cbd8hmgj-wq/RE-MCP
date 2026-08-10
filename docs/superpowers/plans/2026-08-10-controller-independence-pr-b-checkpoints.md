# Controller Independence 1.0 — PR B Checkpoint Protocol Implementation Plan

> Execute TDD-first on `agent/controller-independence-pr-b-checkpoints`. The user's standing authorization covers this recommended PR sequence.

**Goal:** Add exact-ROM-SHA-scoped, provider-neutral controller handoff checkpoints without creating a generic filesystem or evidence-authority surface.

**Architecture:** A controller checkpoint service owns validation, path derivation, revision conflicts, evidence-reference hashing, integrity hashing, locking, and atomic persistence. Two MCP tools parse the requested ROM through the canonical NDS model, then call the service. The checkpoint lives only under `analysis/generated/nds/<sha-prefix>/controller/checkpoint.json`.

## Task 1 — Core checkpoint schema, path, integrity, and atomic revision writes

**Create:**
- `src/services/controller-checkpoint.ts`
- `tests/controller-checkpoint.test.ts`

### RED
Add service tests proving:
- controlled path derives only from workspace root + source SHA prefix;
- first write requires `expectedRevision: 0` and yields revision 1;
- matching update yields revision N+1;
- stale revision fails closed;
- same logical state produces stable content hash for the same revision;
- tampered checkpoint fails read integrity;
- IDs are bounded/simple and unique across all entry collections;
- objective/collections/evidence refs are bounded;
- caller cannot influence output path.

Run full `npm run check`; require only new checkpoint tests to fail before implementation.

### GREEN
Implement:
- `ControllerCheckpointError` and categories;
- strict state/checkpoint Zod schemas;
- deterministic JSON payload field order;
- `controllerCheckpointPath(map, workspaceRoot)`;
- `readControllerCheckpoint(map, workspaceRoot)`;
- `writeControllerCheckpoint(map, workspaceRoot, expectedRevision, state)`;
- lock file using exclusive create (`wx`), fail closed on conflict;
- temp write + fsync + atomic rename;
- 1 MiB serialized bound;
- content SHA-256 verification on read/read-back.

No timestamps/provider/model/conversation metadata.

## Task 2 — Controlled evidence references

**Modify:**
- `src/services/controller-checkpoint.ts`
- `tests/controller-checkpoint.test.ts`

### RED
Tests require evidence refs to:
- accept existing regular files only under exact `analysis/generated/nds/<prefix>/...` or `output/nds/<prefix>/...` roots;
- reject sibling ROM SHA roots;
- reject workspace escapes/absolute escapes;
- reject directories;
- reject the checkpoint/lock/temp namespace as evidence;
- hash accepted refs and persist the actual SHA-256;
- fail when caller-provided expected SHA mismatches;
- enforce 16 refs per entry / 256 total.

### GREEN
Add normalized evidence-reference resolver/hash binder. Evidence is checked at write time only; checkpoint read verifies checkpoint integrity but does not silently promote/reinterpret or automatically rehash evidence artifacts.

## Task 3 — MCP read/write tools and server capabilities

**Create:**
- `src/tools/controller-checkpoint.ts`
- `tests/controller-checkpoint-tools.test.ts`

**Modify:**
- `src/index.ts`

### RED
Tests require:
- registration of `controller_checkpoint_read` and `controller_checkpoint_write`;
- ROM input resolved inside workspace and parsed by `readNdsRomMap` before service use;
- write schema has no output/path parameter;
- read absent checkpoint returns `exists: false` + expectedRevision 0;
- service categories map to bounded structured tool errors/corrective actions;
- `server_capabilities` lists both tools and states checkpoint authority is controller-state-only.

### GREEN
Implement tool registration with bounded text results and narrow error responses. Update `src/index.ts` registration/capabilities. Do not expose generic read/write/delete/list tools.

## Task 4 — Copilot handoff policy and documentation

**Modify:**
- `.github/copilot-instructions.md`
- `docs/github-copilot-agent.md`
- `tests/copilot-controller-integration.test.ts`

### RED
Require instructions/guide to state:
- checkpoint read before continuing pre-existing ROM work when a checkpoint exists;
- checkpoint write before planned controller handoff;
- checkpoint prose is controller state, not authoritative evidence;
- consequential facts must be revalidated before mutation/build decisions;
- no chain-of-thought/transcript/API secrets in checkpoint state.

### GREEN
Update instructions and guide without weakening PR A safety rules.

## Task 5 — Package acceptance

**Create:**
- `scripts/check-controller-checkpoint-install.mjs`

**Modify:**
- `.github/workflows/package.yml`
- `tests/controller-checkpoint-package.test.ts`

### RED
Require assembled package to contain compiled checkpoint service/tool modules, register tools, and invoke the new smoke script.

### GREEN
Smoke compiled modules using a temporary workspace and deterministic fake canonical map identity:
- first write/read succeeds;
- evidence ref hashes are bound;
- stale expected revision fails;
- tampered checkpoint fails integrity;
- output remains in exact controlled SHA namespace;
- source fixture remains unchanged.

Package workflow runs smoke against assembled bundle after existing checks.

## Task 6 — Exact-head review and merge

1. Run/rely on exact-head CI and Package GitHub Actions.
2. Require full tests/typecheck/build/package smoke success.
3. Review full diff for generic filesystem APIs, caller-controlled paths, evidence-authority overclaim, secrets, and ROM mutation changes.
4. Require zero unresolved review threads and mergeable current head.
5. Update PR body with exact-head evidence; mark ready.
6. Merge with `expected_head_sha` protection under the user's standing authorization.
7. Verify merge on `main`, then begin Controller Independence fallback-routing PR.
