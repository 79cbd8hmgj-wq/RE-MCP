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

export type NdsPatternSearchErrorCategory =
  | "invalid-pattern"
  | "invalid-pattern-scope"
  | "pattern-search-limit-exceeded";

export type AnyNdsErrorCategory = NdsErrorCategory | NdsReferenceErrorCategory;

type AllNdsErrorCategory = AnyNdsErrorCategory | NdsPatternSearchErrorCategory;

export class NdsError<
  Category extends AllNdsErrorCategory = NdsErrorCategory,
> extends Error {
  constructor(
    readonly category: Category,
    message: string,
  ) {
    super(message);
    this.name = "NdsError";
  }
}
