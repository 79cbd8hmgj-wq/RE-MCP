# Controller Efficiency / High-Level RE Orchestration Design

## Status

Design proposal for the next RE-MCP milestone after Controller Independence and local Continue acceptance.

## Problem

RE-MCP currently exposes 52 MCP tools from one server. This gives capable controllers maximum flexibility, but it also creates a large tool-schema payload and forces weaker/free-tier controllers to perform too much mechanical orchestration themselves.

Observed failure modes include:

- provider TPM rejection before useful work begins;
- free-tier quota exhaustion caused partly by repeatedly transmitting a large tool surface;
- provider capacity failures during multi-step investigations;
- controllers spending calls rediscovering known ROM facts;
- controllers failing to preserve successful partial work before provider exhaustion;
- simple controller benchmarks passing even though arbitrary reverse-engineering investigations remain too difficult.

The current Controller Independence benchmark intentionally proves deterministic workflow compliance, not arbitrary ROM reverse-engineering ability. This milestone closes that gap without weakening the existing fail-closed safety model.

## Goal

Make RE-MCP practical for weaker, rate-limited, and free-tier controllers by moving deterministic mechanical orchestration into RE-MCP while leaving semantic hypothesis selection to the external model.

The target interaction becomes:

```text
controller
   ↓
small task-specific MCP surface
   ↓
high-level bounded RE operation
   ↓
RE-MCP internally composes existing deterministic primitives
   ↓
compact evidence result + persisted progress
   ↓
controller decides the next hypothesis
```

This milestone does **not** add autonomous semantic reasoning inside RE-MCP. RE-MCP remains an evidence-producing deterministic instrument layer.

## Core principles

1. **No loss of low-level capability.** Existing 52 tools remain available for expert/debug use.
2. **Small controller-facing surfaces.** Normal controller sessions should receive only tools relevant to the active phase.
3. **Deterministic composition.** High-level operations may call existing RE-MCP services internally, but may not invent facts or silently broaden scope.
4. **Evidence over prose.** Consequential claims remain bound to deterministic RE-MCP artifacts/results.
5. **Automatic progress preservation.** Successful consequential operations persist compact resumable state before returning success.
6. **Fail closed.** Provider failure, partial analysis, ambiguous overlays, stale ROM identity, or Ghidra mismatch must never become a guessed answer.
7. **Source ROM immutability.** This milestone is read-only except for RE-MCP-owned evidence/checkpoint files.
8. **No hidden mutation path.** High-level RE tools cannot invoke mutation/build tools.
9. **Bounded outputs and work.** Every high-level operation has explicit limits on depth, candidates, instructions, bytes, and optional Ghidra escalation.
10. **Provider-neutral resume.** A new controller can continue from the exact-ROM-SHA state without replaying completed deterministic work.

## Architecture

### 1. Tool profiles

Introduce named MCP exposure profiles. The server continues to implement the full tool set, but a controller configuration may expose only a selected profile.

Initial profiles:

- `re-static-core`
- `re-ghidra-escalation`
- `re-runtime`
- `re-build`
- `re-project`
- `re-full`

Profiles are allowlists, not denylists. Unknown tools fail closed.

`re-static-core` should expose only the small set needed for ordinary read-only reverse engineering plus the new high-level orchestration tools and checkpoint/resume tools.

Profile selection must not change service semantics. It changes only what schemas are advertised to the controller.

### 2. High-level deterministic RE operations

Add a small agent-facing orchestration surface. Initial operations:

#### `re_trace_function`

Purpose: starting from a known canonical runtime address/component, produce a bounded caller/reference/function-context report.

Internally composes existing deterministic services for:

- address/component resolution;
- proven function context;
- direct xrefs/callers;
- bounded references;
- bounded disassembly around relevant call sites;
- optional CFG summary when required.

It returns compact structured evidence rather than full raw dumps.

It must preserve uncertainty. For example, overlapping overlay ownership remains multiple candidates unless separately proven.

#### `re_investigate_data_usage`

Purpose: starting from a known data/runtime address or deterministic pattern hit, identify bounded direct code/data users and rank no semantic conclusion automatically.

It may compose:

- canonical address resolution;
- direct references/xrefs;
- proven containing functions;
- small disassembly windows;
- bounded candidate list.

#### `re_decompile_candidate`

Purpose: perform controlled Ghidra enrichment for one already-identified candidate.

Rules:

- requires an already-current exact-ROM-SHA Ghidra project;
- never bootstraps or reconciles automatically;
- bounded to one candidate/function per call;
- returns compact decompilation plus deterministic RE-MCP provenance;
- Ghidra inference remains non-authoritative.

#### `re_resume_investigation`

Purpose: return the current exact-ROM-SHA controller state plus the smallest unresolved deterministic next actions and referenced evidence metadata.

It must not reinterpret checkpoint prose as ROM truth.

### 3. Compact evidence envelopes

High-level operations return a common bounded envelope:

```text
operation
sourceRomSha256
component
subject
confirmedDeterministicEvidence[]
candidates[]
ambiguities[]
completedPrimitiveStages[]
artifacts[]
recommendedNextPrimitiveOrHighLevelAction
checkpointRevision
```

The `recommendedNext...` field is mechanical guidance only. It may say, for example, "decompile candidate function X" or "runtime evidence required to distinguish overlay candidates". It may not claim gameplay semantics that the deterministic evidence does not establish.

Large raw disassembly/decompiler text remains available through existing low-level tools when explicitly requested.

### 4. Automatic evidence journal and checkpoint

The current provider-neutral checkpoint mechanism remains authoritative only as `controller-state-only`.

Add an RE-MCP-owned append-only/atomic investigation journal scoped to the exact ROM SHA. A successful high-level operation records, before returning:

- operation ID;
- normalized inputs;
- ROM SHA;
- deterministic stages completed;
- generated artifact hashes;
- bounded result digest;
- completion status;
- timestamp/sequence metadata needed for ordering, not semantic authority.

Then update a compact resumable checkpoint projection.

If persistence fails, the high-level operation must fail closed rather than return a success that cannot be resumed.

No chain-of-thought, full prompts, secrets, or arbitrary model transcript are stored.

### 5. Resume behavior

A replacement provider should need only:

1. the exact ROM path;
2. `re_resume_investigation`;
3. the current user objective/next hypothesis.

It should not need to replay prior xrefs, disassembly, or Ghidra calls whose deterministic results are already journaled and integrity-bound.

## Tool-profile behavior

Profile filtering should occur before MCP tool advertisement so excluded tool schemas are never sent to the model.

Required properties:

- deterministic allowlist definitions in source control;
- `re-full` preserves current 52-tool compatibility;
- profile name optionally selected by environment/configuration;
- invalid profile prevents startup;
- benchmark/package tests verify exact advertised names for each profile;
- server capabilities report the active profile without re-advertising hidden schemas;
- Continue/Copilot documentation includes small-profile examples.

No profile may expose a high-level tool whose internal service path violates the profile's safety class. In particular, static profiles cannot invoke mutation or debugger execution internally.

## Token-efficiency requirement

The milestone must measure the serialized MCP tool-schema payload for each profile.

Acceptance target for `re-static-core`:

- at least 70% smaller serialized tool-schema payload than `re-full`;
- small enough that the existing Groq 8K-TPM controller path can attempt the static RE acceptance prompt without immediate request-size rejection, subject to provider-side overhead outside RE-MCP's control.

The benchmark must report schema bytes/tokens estimate separately from model-provider usage.

## Reverse-engineering acceptance benchmark

Extend the current deterministic controller benchmark with a new scenario that is materially harder than analysis handoff.

### `targeted-function-investigation`

Synthetic ROM fixture contains:

- a known helper function;
- multiple direct callers;
- one caller that applies an identity-dependent restriction;
- distractor callers that perform only generic bounds validation;
- deterministic symbols/evidence sufficient for static resolution;
- no mutation requirement.

Controller prompt provides only the helper address and asks where identity-specific eligibility/restriction is enforced.

Expected behavior:

1. use a small static profile;
2. invoke high-level tracing rather than manually chaining the full low-level suite;
3. distinguish generic bounds checks from the identity-specific caller;
4. persist the successful investigation automatically;
5. return/reach a machine-verifiable evidence state identifying the correct candidate;
6. source ROM remains unchanged.

Scoring must use deterministic artifacts/state, not prose quality.

### Live weak/free-controller gate

CI cannot prove provider/model competence. Therefore release acceptance additionally requires at least one live constrained controller run using a free-tier or deliberately limited controller configuration.

The live gate records:

- provider/model label as non-authoritative metadata;
- active RE-MCP profile;
- prompt size;
- advertised tool-schema size;
- whether the request was accepted;
- number of model turns/tool calls;
- deterministic benchmark score.

A provider failure does not invalidate RE-MCP correctness, but the milestone is not considered practically accepted until at least one constrained controller completes the scenario without manual repair.

## Proposed PR sequence

### PR A — MCP profile/filtering foundation

- deterministic profile definitions;
- filtered tool advertisement;
- full-profile backward compatibility;
- schema-size measurement;
- tests and Continue documentation.

### PR B — High-level static RE orchestration

- `re_trace_function`;
- `re_investigate_data_usage`;
- compact evidence envelope;
- bounded deterministic internal composition;
- no Ghidra/runtime/mutation side effects.

### PR C — Ghidra escalation + automatic persistence/resume

- `re_decompile_candidate`;
- exact-ROM-SHA investigation journal;
- automatic checkpoint projection;
- `re_resume_investigation`;
- failure-atomic persistence and integrity tests.

### PR D — Controller efficiency benchmark and acceptance

- `targeted-function-investigation` fixture/scorer;
- schema-size reporting;
- constrained-controller runbook;
- package/CI coverage;
- live free/weak-controller acceptance checklist.

## Explicitly deferred

This milestone does not add:

- autonomous model selection;
- provider billing/quota management;
- semantic AI inside RE-MCP;
- watchpoints or new debugger execution primitives;
- runtime overlay-state inference;
- new mutation/rebuild capability;
- automatic Ghidra bootstrap/reconciliation;
- arbitrary shell/file-write access;
- heuristic promotion of candidate evidence to confirmed fact.

## Success criterion

The milestone succeeds when RE-MCP no longer requires a controller to reason directly over all 52 low-level schemas for ordinary targeted reverse engineering, successful partial work survives provider death automatically, and a constrained/free controller can complete the new targeted-function benchmark through a small profile without manual repair.
