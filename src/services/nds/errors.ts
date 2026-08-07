export type NdsErrorCategory =
  | "invalid-rom"
  | "malformed-header"
  | "range-out-of-bounds"
  | "malformed-fat"
  | "malformed-fnt"
  | "malformed-overlay-table"
  | "unknown-file-id"
  | "unknown-overlay-id"
  | "output-bound-exceeded"
  | "generated-path-failure";

export type NdsReferenceErrorCategory =
  | "ambiguous-reference-target"
  | "reference-target-not-runtime-addressable"
  | "invalid-reference-scope"
  | "invalid-reference-seed"
  | "reference-scan-limit-exceeded";

export type AnyNdsErrorCategory = NdsErrorCategory | NdsReferenceErrorCategory;

export class NdsError extends Error {
  readonly category: NdsErrorCategory;

  constructor(
    category: AnyNdsErrorCategory,
    message: string,
  ) {
    super(message);
    this.name = "NdsError";
    // Reference-specific categories become part of the public tool error union in
    // the dedicated MCP-surface task. Until then, keep the existing tool switch
    // source-compatible while preserving the exact runtime category string.
    this.category = category as NdsErrorCategory;
  }
}
