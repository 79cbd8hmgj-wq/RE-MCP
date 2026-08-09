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

export type NdsFunctionErrorCategory =
  | "invalid-function-scope"
  | "invalid-function-seed"
  | "function-entry-not-uniquely-resolved"
  | "function-discovery-limit-exceeded";

export type NdsBlzErrorCategory =
  | "malformed-blz"
  | "blz-output-size-mismatch"
  | "blz-output-limit";

export type NdsCompressedOverlayErrorCategory =
  | "compressed-overlay-runtime-unavailable";

export type NdsGhidraErrorCategory =
  | "ghidra-not-configured"
  | "invalid-ghidra-installation"
  | "unsupported-ghidra-version"
  | "ghidra-language-unavailable"
  | "ghidra-project-locked"
  | "bridge-generation-failed"
  | "ghidra-import-failed"
  | "ghidra-analysis-failed"
  | "ghidra-analysis-timeout"
  | "ghidra-output-limit"
  | "project-state-mismatch";

export type NdsGhidraInspectionErrorCategory =
  | "ghidra-project-not-current"
  | "ghidra-version-mismatch"
  | "ghidra-address-not-inspectable"
  | "ghidra-inspection-failed"
  | "ghidra-inspection-timeout"
  | "ghidra-inspection-result-invalid";

/** Error categories handled by the current pre-Ghidra NDS tool surfaces. */
export type AnyNdsErrorCategory =
  | NdsErrorCategory
  | NdsReferenceErrorCategory
  | NdsPatternSearchErrorCategory
  | NdsFunctionErrorCategory
  | NdsBlzErrorCategory
  | NdsCompressedOverlayErrorCategory;

/** Complete service-layer category set, including compressed overlays and optional Ghidra integration. */
export type NdsServiceErrorCategory =
  | AnyNdsErrorCategory
  | NdsGhidraErrorCategory
  | NdsGhidraInspectionErrorCategory;

export class NdsError<
  Category extends NdsServiceErrorCategory = NdsErrorCategory,
> extends Error {
  constructor(
    readonly category: Category,
    message: string,
  ) {
    super(message);
    this.name = "NdsError";
  }
}
