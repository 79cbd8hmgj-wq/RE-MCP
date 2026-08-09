import type { ServerConfig } from "../../config.js";
import { NdsError } from "./errors.js";
import {
  decompileNdsGhidraFunction,
  inspectNdsGhidraFunction,
  type GhidraAddressSelector,
  type GhidraInspectionAuthorityResult,
} from "./ghidra-inspection-service.js";
import type { RuntimeCandidate } from "./resolver.js";

export type RuntimeGhidraEnrichment =
  | { readonly status: "not-requested" }
  | { readonly status: "not-ready"; readonly reason: string }
  | {
      readonly status: "available";
      readonly function: GhidraInspectionAuthorityResult;
      readonly decompilation: GhidraInspectionAuthorityResult | null;
    }
  | {
      readonly status: "failed";
      readonly category: string;
      readonly message: string;
    };

export interface RuntimeGhidraEnrichmentRequest {
  readonly romPath: string;
  readonly candidate: RuntimeCandidate;
  readonly decompileFunction: boolean;
}

export type RuntimeGhidraEnricher = (
  request: RuntimeGhidraEnrichmentRequest,
) => Promise<RuntimeGhidraEnrichment>;

type InspectFunction = (
  romPath: string,
  selector: GhidraAddressSelector,
  config: ServerConfig,
) => Promise<GhidraInspectionAuthorityResult>;

type DecompileFunction = (
  romPath: string,
  input: GhidraAddressSelector & { readonly maxCharacters?: number },
  config: ServerConfig,
) => Promise<GhidraInspectionAuthorityResult>;

export interface RuntimeGhidraAdapterDependencies {
  readonly inspectFunction: InspectFunction;
  readonly decompileFunction: DecompileFunction;
}

const DEFAULT_DEPENDENCIES: RuntimeGhidraAdapterDependencies = {
  inspectFunction: inspectNdsGhidraFunction,
  decompileFunction: decompileNdsGhidraFunction,
};

function selectorForCandidate(candidate: RuntimeCandidate): GhidraAddressSelector {
  return {
    processor: "arm9",
    runtimeAddress: candidate.runtimeAddress,
    ...(candidate.overlayId === null ? {} : { overlayId: candidate.overlayId }),
  };
}

function failed(error: unknown): RuntimeGhidraEnrichment {
  const message = error instanceof Error ? error.message : String(error);
  if (error instanceof NdsError) {
    if (error.category === "ghidra-project-not-current") {
      return { status: "not-ready", reason: message };
    }
    return {
      status: "failed",
      category: error.category,
      message,
    };
  }
  return {
    status: "failed",
    category: "ghidra-inspection-failed",
    message,
  };
}

export function createRuntimeGhidraEnricher(
  config: ServerConfig,
  dependencies: RuntimeGhidraAdapterDependencies = DEFAULT_DEPENDENCIES,
): RuntimeGhidraEnricher {
  return async (request) => {
    const selector = selectorForCandidate(request.candidate);
    try {
      const functionResult = await dependencies.inspectFunction(
        request.romPath,
        selector,
        config,
      );
      let decompilation: GhidraInspectionAuthorityResult | null = null;
      if (
        request.decompileFunction
        && functionResult.ghidraDerived.found === true
      ) {
        decompilation = await dependencies.decompileFunction(
          request.romPath,
          selector,
          config,
        );
      }
      return {
        status: "available",
        function: functionResult,
        decompilation,
      };
    } catch (error) {
      return failed(error);
    }
  };
}
