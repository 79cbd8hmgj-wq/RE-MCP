# Controlled NDS Mutation Core Implementation Plan Errata

**Date:** 2026-08-09  
**Applies to:** `docs/superpowers/plans/2026-08-09-controlled-nds-mutation-core.md`  
**Normative source:** `docs/superpowers/specs/2026-08-09-controlled-nds-mutation-core-design.md`

This file records plan-writing contradictions discovered while executing PR A. It does **not** change the approved product design or milestone scope. The approved design specification is normative. Where the implementation plan conflicts with this errata or the design specification, this errata and the design specification govern.

## 1. Canonical JSON preserves semantic array order

The original plan incorrectly instructed Task 1 to sort normalized mutation operations lexicographically.

Correct rule:

- object keys are sorted lexicographically at every level;
- arrays are preserved in semantic/input order;
- normalized byte hex is lowercase;
- no insignificant whitespace is emitted.

Therefore reversing two manifest operations changes the canonical manifest bytes, `manifestSha256`, and `buildId` even when the two physical operations are otherwise independent.

## 2. Exact build-ID algorithm

The original plan incorrectly described a NUL-joined string identity.

The correct `buildId` is the lowercase SHA-256 of canonical UTF-8 JSON for exactly:

```json
{
  "format": "re-mcp-nds-build-identity",
  "formatVersion": 1,
  "sourceSha256": "...",
  "manifestSha256": "...",
  "replacementArtifactSha256": ["...", "..."]
}
```

`replacementArtifactSha256` contains the **verified actual** replacement artifact SHA-256 values in manifest operation order. Byte-only manifests use `[]`.

## 3. Overlay-backed NitroFS aliases are never mutation selectors

The original plan had examples that allowed a generic NitroFS selector to reach overlay backing bytes in some cases.

Correct rule:

- if a FAT/NitroFS file backs any ARM9 or ARM7 overlay, generic `nitrofs-file` and `nitrofs-path` mutation selectors reject it;
- the caller must use an explicit `arm9-overlay` or `arm7-overlay` selector with the exact overlay ID;
- this rule applies to both compressed and uncompressed overlays;
- byte edits also fail closed if the selected physical backing is shared with any compressed overlay owner.

For conflict testing, use two ordinary non-overlay NitroFS selectors (file ID and exact path) that resolve to the same physical file rather than an overlay-vs-NitroFS alias.

## 4. Mutation error taxonomy

The complete mutation error union includes the two categories omitted from the original plan task text:

```ts
| "mutation-no-op"
| "publish-collision"
```

Use `mutation-no-op` for both normalized byte no-ops and whole-component replacements whose verified replacement SHA-256 equals the original component SHA-256.

Use `publish-collision` when the deterministic final build directory already exists but fresh revalidation cannot prove it is the exact valid build for the same lineage. Do not silently map that case to `publish-failed`.

## 5. Replacement artifact reserved identities

Whole-component replacement artifacts must not alias:

- the immutable source ROM;
- the mutation manifest;
- the staged ROM;
- the deterministic final output ROM.

PR A can prove source/manifest/final-output identity where those paths are known. Staging must preserve this rule when the temporary staged ROM exists. Path equality is not sufficient when filesystem identity can be checked; hard-link identity must also fail closed.

## 6. Compressed-overlay guard tests

A malformed compressed replacement test must target the explicit canonical overlay selector, for example:

```ts
{
  component: "arm9-overlay",
  overlayId: 7
}
```

Do not use a NitroFS alias to reach compressed overlay backing bytes; that alias is rejected earlier by the selector contract.

## 7. Existing-build collision behavior in Task 8

When a deterministic final build directory already exists:

- full current source/manifest/artifact preflight is repeated;
- the published ROM is freshly verified;
- deterministic evidence is regenerated and byte-compared;
- exact success returns `reused: true`;
- any mismatch throws `publish-collision` and leaves the directory untouched.

The original Task 8 example expecting `publish-failed` for corrupt same-ID content is superseded by `publish-collision`.

## 8. Execution rule for remaining tasks

Tasks 5–10 continue with the same PR decomposition and TDD workflow already approved:

```text
PR B — Tasks 5–8: staging, sole writer, verification, publication/reuse
PR C — Tasks 9–10: MCP tools, capabilities, packaging, docs, final regression
```

Before implementing any remaining task, read:

1. the approved design specification;
2. this errata;
3. the task text in the original implementation plan.

If they differ, the design specification and this errata govern. No additional mutation capability is authorized by this errata.
