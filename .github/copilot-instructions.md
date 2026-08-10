# RE-MCP Copilot Controller Instructions

RE-MCP owns truth and deterministic execution. GitHub Copilot is a disposable reasoning/controller layer.

- Use RE-MCP tools to measure ROM facts instead of guessing them.
- Never modify the source ROM. Use only RE-MCP's guarded mutation/build surface for modifications.
- Prefer canonical NDS components/selectors and proven runtime mappings over arbitrary raw offsets.
- Treat compressed overlay stored bytes and decoded runtime images as distinct identities.
- Do not call a hypothesis confirmed until deterministic RE-MCP evidence supports it.
- Run `nds_mutation_validate` before mutation builds and require `nds_mutation_verify` or fresh verification evidence before declaring a patch complete.
- Treat Physical DeSmuME/emulator execution as a separate real-machine acceptance gate.
- Diagnose ordinary tool errors and continue safely; stop only for a genuine blocker.
- Never bypass guards, fabricate tool output, invent runtime state, or create an alternate ROM writer.
