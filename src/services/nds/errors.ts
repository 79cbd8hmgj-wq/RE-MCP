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
  | "generated-path-failure"
  | "ambiguous-reference-target"
  | "reference-target-not-runtime-addressable"
  | "invalid-reference-scope"
  | "invalid-reference-seed"
  | "reference-scan-limit-exceeded";

export class NdsError extends Error {
  constructor(
    readonly category: NdsErrorCategory,
    message: string,
  ) {
    super(message);
    this.name = "NdsError";
  }
}
