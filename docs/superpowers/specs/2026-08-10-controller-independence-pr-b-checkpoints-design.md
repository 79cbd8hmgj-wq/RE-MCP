# Controller Independence 1.0 — PR B: Provider-Neutral Controller Checkpoints

Date: 2026-08-10
Status: approved under the user's standing authorization for the Controller Independence PR sequence

## Goal

Give any RE-MCP controller a deterministic, provider-neutral handoff artifact so work can move between GitHub Copilot, Continue, Groq, OpenRouter, Ollama, or later controllers without depending on proprietary conversation memory.

The checkpoint is **controller state, not a new RE-MCP evidence authority**. RE-MCP validates checkpoint structure, source-ROM identity, path ownership, revisions, integrity, and referenced artifact identity. It does not promote controller-written prose into authoritative ROM facts.

## Selected architecture

For an exact parsed NDS ROM, RE-MCP owns one current checkpoint at:

```text
analysis/generated/nds/<source-sha-prefix>/controller/checkpoint.json
```

The caller never chooses this output path.

Two narrow MCP tools are added:

- `controller_checkpoint_read`
- `controller_checkpoint_write`

Both take a ROM path inside `RE_MCP_WORKSPACE_ROOT`. The tools parse the ROM through the canonical NDS model first, so the checkpoint namespace is derived from the ROM's current exact SHA-256 rather than caller-supplied identity.

No generic file read/write/list/delete API is added.

## Checkpoint format

Format version 1 contains:

```json
{
  "formatVersion": 1,
  "authority": "controller-state-only",
  "sourceRomSha256": "<64 hex>",
  "sourceRomSha256Prefix": "<canonical prefix>",
  "revision": 1,
  "objective": "...",
  "confirmedFacts": [
    {
      "id": "fact-id",
      "statement": "controller-reported statement",
      "evidenceRefs": [
        {
          "path": "analysis/generated/nds/<prefix>/...",
          "sha256": "<actual hash when checkpoint was written>"
        }
      ]
    }
  ],
  "hypotheses": [
    {
      "id": "hypothesis-id",
      "statement": "...",
      "evidenceRefs": []
    }
  ],
  "completedActions": [
    {
      "id": "action-id",
      "description": "...",
      "outcome": "completed",
      "evidenceRefs": []
    }
  ],
  "nextActions": [
    {
      "id": "next-id",
      "description": "..."
    }
  ],
  "contentSha256": "<hash of canonical checkpoint payload excluding contentSha256>"
}
```

No timestamp, provider name, model name, conversation ID, or controller-specific metadata is required. This keeps the artifact portable and deterministic.

## Semantic boundary

`confirmedFacts` means **the previous controller reported the statement as confirmed**. It does not mean RE-MCP independently proved the prose.

Consequential facts must still be revalidated through the appropriate deterministic RE-MCP tools before mutation/build decisions. The controller instructions will explicitly state this.

When an entry includes `evidenceRefs`, RE-MCP validates each referenced artifact when the checkpoint is written and records the actual SHA-256. This proves what artifact the previous controller was referring to, not that its prose interpretation of that artifact is correct.

## Evidence-reference policy

Evidence paths are workspace-relative and may point only inside the exact source-ROM namespace under either:

```text
analysis/generated/nds/<source-sha-prefix>/
output/nds/<source-sha-prefix>/
```

The checkpoint file itself and controller lock/temp files may not be referenced as evidence.

For every evidence reference, RE-MCP:

1. resolves the path inside the configured workspace;
2. checks that it is beneath one of the exact allowed source-SHA roots;
3. requires an existing regular file;
4. hashes it with SHA-256;
5. if the controller supplied an expected SHA-256, requires an exact match;
6. stores the actual SHA-256 in the checkpoint.

References are bounded in count and path length. RE-MCP does not recursively scan directories.

## Revision and conflict model

`controller_checkpoint_write` requires `expectedRevision`.

- no existing checkpoint + `expectedRevision: 0` → writes revision 1;
- existing revision N + `expectedRevision: N` → writes revision N+1;
- any other combination → fail closed with `checkpoint-revision-conflict`.

This prevents a stale controller from silently overwriting newer handoff state.

Writes use a controller-owned lock file plus temporary file, file sync, and atomic rename. A concurrent/stale lock fails closed rather than bypassing revision protection.

## Integrity model

The checkpoint stores `contentSha256`, computed from a canonical JSON payload with fixed field ordering and without the hash field itself.

`controller_checkpoint_read` validates:

- JSON/schema;
- format version and authority marker;
- exact source SHA/prefix against the currently parsed ROM;
- revision bounds;
- entry/ID uniqueness rules;
- `contentSha256`.

A malformed or tampered checkpoint fails closed with `checkpoint-integrity-failure` rather than being silently repaired.

Evidence artifacts are not automatically rehashed during every read. Their recorded hashes are handoff references; a resumed controller must revalidate evidence that matters to the next consequential action.

## Input bounds

To keep controller state bounded:

- objective: 1–4,000 UTF-8 characters;
- each statement/description: 1–4,000 characters;
- IDs: 1–64 characters, `[A-Za-z0-9._-]+`, unique across the checkpoint;
- each collection: max 128 entries;
- evidence refs per entry: max 16;
- total evidence refs: max 256;
- evidence path: max 512 characters;
- serialized checkpoint: max 1 MiB.

No raw binary blobs, model transcripts, chain-of-thought, API keys, or arbitrary metadata maps are accepted.

## MCP tool behavior

### `controller_checkpoint_read`

Input:

```json
{ "rom": "relative/or/workspace-contained/path.nds" }
```

Behavior:

1. resolve ROM inside workspace;
2. parse canonical NDS map/current SHA;
3. derive controlled checkpoint path;
4. if absent, return `exists: false`, source identity, and expected revision 0;
5. if present, validate checkpoint integrity/source identity and return the state plus workspace-relative checkpoint path.

### `controller_checkpoint_write`

Input:

```json
{
  "rom": "...",
  "expectedRevision": 0,
  "state": {
    "objective": "...",
    "confirmedFacts": [],
    "hypotheses": [],
    "completedActions": [],
    "nextActions": []
  }
}
```

Behavior:

1. resolve/parse exact ROM;
2. validate bounded state;
3. validate/hash evidence refs;
4. acquire checkpoint lock;
5. re-read current revision under lock;
6. fail closed on stale expected revision;
7. construct revision N+1 checkpoint;
8. write/sync/rename atomically;
9. read back and verify integrity;
10. return revision, source identity, checkpoint relative path, and content hash.

The tool cannot select another output path.

## Error categories

Controller checkpoint tools return narrow categories:

- `invalid-rom`
- `checkpoint-invalid-state`
- `checkpoint-evidence-path-invalid`
- `checkpoint-evidence-missing`
- `checkpoint-evidence-sha-mismatch`
- `checkpoint-revision-conflict`
- `checkpoint-lock-conflict`
- `checkpoint-integrity-failure`
- `checkpoint-io-failure`

Each includes a corrective action. Ordinary controller errors do not justify bypassing the checkpoint contract.

## Packaging and controller instructions

PR B will:

- register both tools in `src/index.ts` and `server_capabilities`;
- add deterministic service/tool tests;
- add package smoke coverage against compiled modules;
- update `.github/copilot-instructions.md` so Copilot reads a checkpoint before continuing existing ROM work, writes one before a planned controller handoff, treats checkpoint prose as controller state, and revalidates consequential facts;
- update `docs/github-copilot-agent.md` with checkpoint/handoff usage;
- include all compiled checkpoint code through the existing package build path.

The package smoke proves the checkpoint implementation ships and behaves correctly. It does not claim a real provider-to-provider handoff occurred in CI.

## Out of scope

- Continue/LiteLLM/Groq/OpenRouter/Ollama configuration or routing;
- provider credentials or API calls;
- automatic switching after HTTP 429/credit exhaustion;
- conversation transcript storage;
- chain-of-thought storage;
- generic workspace notes/filesystem APIs;
- promotion of controller prose into authoritative RE-MCP evidence;
- physical VS Code/Copilot or DeSmuME acceptance.

## Acceptance criteria

PR B is complete when:

1. exact-ROM-SHA-scoped checkpoints can be read/written through narrow MCP tools;
2. stale writers fail closed through expected-revision checks;
3. checkpoint tampering fails integrity validation;
4. caller-selected output paths are impossible;
5. evidence refs cannot escape exact controlled source-SHA roots and are hash-bound when written;
6. source ROM changes naturally select a different checkpoint namespace;
7. source ROM remains untouched;
8. package acceptance exercises compiled checkpoint write/read/conflict/tamper behavior;
9. Copilot instructions/documentation encode the controller-state-only trust boundary;
10. full CI/package acceptance is green on the exact PR head.
