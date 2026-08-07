import type { ArmDisassemblyBackend } from "../disassembly/backend.js";
import {
  disassembleNdsRangeDetailed,
  type LinearDisassemblyOptions,
} from "./disassembly.js";
import type {
  NdsCodeSourceResolution,
  NdsDisassemblyLocation,
} from "./disassembly-source.js";
import {
  classifyNdsInstructionReferences,
  type StaticReference,
} from "./references.js";
import type { NdsRomMap } from "./rom-map.js";

export interface ListReferencesOptions extends LinearDisassemblyOptions {}

export type ListNdsReferencesResult =
  | Exclude<NdsCodeSourceResolution, { readonly status: "resolved" }>
  | {
      readonly status: "complete" | "decode-stopped" | "component-boundary";
      readonly source: Extract<NdsCodeSourceResolution, { readonly status: "resolved" }>["source"];
      readonly instructionsExamined: number;
      readonly decodedBytes: number;
      readonly references: readonly StaticReference[];
    };

export async function listNdsReferences(
  map: NdsRomMap,
  location: NdsDisassemblyLocation,
  options: ListReferencesOptions,
  backend: ArmDisassemblyBackend,
): Promise<ListNdsReferencesResult> {
  const result = await disassembleNdsRangeDetailed(
    map,
    location,
    options,
    backend,
  );
  if (!("instructions" in result)) {
    return result;
  }

  const references: StaticReference[] = [];
  for (const detailed of result.instructions) {
    references.push(...classifyNdsInstructionReferences(map, detailed));
  }

  return {
    status: result.status,
    source: result.source,
    instructionsExamined: result.instructions.length,
    decodedBytes: result.decodedBytes,
    references,
  };
}
