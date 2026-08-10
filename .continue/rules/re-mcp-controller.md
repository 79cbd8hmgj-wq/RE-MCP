# RE-MCP controller rules

RE-MCP owns truth and deterministic execution for ROM reverse engineering, mutation, rebuild, verification, and debugger evidence. Continue is a disposable reasoning/controller layer.

## Resume and handoff

- Before resuming pre-existing ROM work, call `controller_checkpoint_read` for the exact ROM.
- Treat checkpoint prose strictly as `controller-state-only`; it records what a previous controller reported, not independently proven ROM facts.
- Revalidate every consequential fact through deterministic RE-MCP tools before using it to justify mutation/build decisions.
- Before a planned controller/provider handoff, or when provider availability is deteriorating, call `controller_checkpoint_write` with the current expected revision.
- Never store chain-of-thought, transcripts, API keys, provider secrets, or other credentials in checkpoint state.

## Evidence and ROM safety

- Never modify the source ROM.
- Prefer canonical NDS component selectors and proven address relationships over invented raw offsets.
- Distinguish stored compressed-overlay bytes from decoded runtime images and preserve RE-MCP's ambiguity rules.
- Never fabricate tool output or claim a hypothesis is confirmed without deterministic evidence.
- Never bypass a failed RE-MCP guard through an alternate writer, shell command, generic file write, or provider-specific path.

## Mutation discipline

For ROM-changing work:

1. use `nds_mutation_validate` before building;
2. use `nds_mutation_build` only after guards/evidence are satisfied;
3. use `nds_mutation_verify` before calling an output complete;
4. treat Physical DeSmuME/native runtime acceptance as a separate real-machine gate when the patch requires it.

Ordinary provider failures, quota limits, or model switches do not change any RE-MCP safety boundary.
