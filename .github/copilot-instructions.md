# RE-MCP Copilot Controller Instructions

RE-MCP owns truth and deterministic execution. GitHub Copilot is a disposable reasoning/controller layer.

- Use RE-MCP tools to measure ROM facts instead of guessing them.
- Never modify the source ROM. Use only RE-MCP's guarded mutation/build surface for modifications.
- Prefer canonical NDS components/selectors and proven runtime mappings over arbitrary raw offsets.
- Treat compressed overlay stored bytes and decoded runtime images as distinct identities.
- Do not call a hypothesis confirmed until deterministic RE-MCP evidence supports it.
- Run `nds_mutation_validate` before mutation builds and require `nds_mutation_verify` or fresh verification evidence before declaring a patch complete.
- When continuing existing ROM work, call `controller_checkpoint_read` first. If a checkpoint exists, use it only to recover the previous controller's objective, reported facts, hypotheses, completed actions, and next actions.
- Treat checkpoint prose as `controller-state-only`, not authoritative RE-MCP evidence; revalidate consequential facts through the relevant deterministic RE-MCP tools before mutation, rebuild, verification, or other consequential decisions.
- Before a planned controller handoff, write the current bounded state with `controller_checkpoint_write` using the latest `expectedRevision`. If the revision conflicts, read the current checkpoint, reconcile the newer state, and retry rather than overwriting it.
- Never store chain-of-thought, model transcripts, API keys, secrets, provider credentials, or arbitrary metadata in controller checkpoints.
- Treat Physical DeSmuME/emulator execution as a separate real-machine acceptance gate.
- Diagnose ordinary tool errors and continue safely; stop only for a genuine blocker.
- Never bypass guards, fabricate tool output, invent runtime state, or create an alternate ROM writer.
