import type { ArmMode } from "../disassembly/backend.js";
import type { NdsProcessor } from "./overlays.js";

export interface ProvenFunctionIdentity {
  readonly processor: NdsProcessor;
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly runtimeAddress: number;
  readonly romOffset: number;
  readonly mode: ArmMode;
}

export type FunctionProof =
  | {
    readonly kind: "program-entry";
    readonly processor: NdsProcessor;
    readonly headerEntryAddress: number;
  }
  | {
    readonly kind: "direct-call";
    readonly caller: {
      readonly functionId: string | null;
      readonly component: "main" | "overlay";
      readonly overlayId: number | null;
      readonly instructionAddress: number;
      readonly instructionRomOffset: number;
      readonly mode: ArmMode;
    };
    readonly target: ProvenFunctionIdentity;
  };

export interface ProvenFunctionCallEdge {
  readonly callerFunctionId: string;
  readonly instructionAddress: number;
  readonly instructionRomOffset: number;
  readonly calleeFunctionId: string;
}

export type FunctionComponentCoverageStatus =
  | "scanned"
  | "no-proven-seed"
  | "compressed-overlay-not-decodable"
  | "out-of-limit";

const PROCESSOR_ORDER: Record<NdsProcessor, number> = {
  arm9: 0,
  arm7: 1,
};

const MODE_ORDER: Record<ArmMode, number> = {
  arm: 0,
  thumb: 1,
};

function compareNumber(left: number, right: number): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareString(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function componentOrder(component: "main" | "overlay"): number {
  return component === "main" ? 0 : 1;
}

function hex32(value: number): string {
  return (value >>> 0).toString(16).padStart(8, "0");
}

export function provenFunctionId(identity: ProvenFunctionIdentity): string {
  const owner = identity.component === "main"
    ? "main"
    : `overlay:${identity.overlayId}`;
  return [
    identity.processor,
    owner,
    hex32(identity.runtimeAddress),
    identity.mode,
  ].join(":");
}

export function compareProvenFunctionIdentity(
  left: ProvenFunctionIdentity,
  right: ProvenFunctionIdentity,
): number {
  let compared = compareNumber(
    PROCESSOR_ORDER[left.processor],
    PROCESSOR_ORDER[right.processor],
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    componentOrder(left.component),
    componentOrder(right.component),
  );
  if (compared !== 0) return compared;

  compared = compareNumber(left.overlayId ?? -1, right.overlayId ?? -1);
  if (compared !== 0) return compared;

  compared = compareNumber(left.runtimeAddress, right.runtimeAddress);
  if (compared !== 0) return compared;

  return compareNumber(MODE_ORDER[left.mode], MODE_ORDER[right.mode]);
}

export function compareFunctionProof(
  left: FunctionProof,
  right: FunctionProof,
): number {
  if (left.kind !== right.kind) {
    return left.kind === "program-entry" ? -1 : 1;
  }

  if (left.kind === "program-entry" && right.kind === "program-entry") {
    let compared = compareNumber(
      PROCESSOR_ORDER[left.processor],
      PROCESSOR_ORDER[right.processor],
    );
    if (compared !== 0) return compared;
    return compareNumber(left.headerEntryAddress, right.headerEntryAddress);
  }

  if (left.kind !== "direct-call" || right.kind !== "direct-call") {
    return 0;
  }

  let compared = compareNumber(
    componentOrder(left.caller.component),
    componentOrder(right.caller.component),
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    left.caller.overlayId ?? -1,
    right.caller.overlayId ?? -1,
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    left.caller.instructionAddress,
    right.caller.instructionAddress,
  );
  if (compared !== 0) return compared;

  compared = compareNumber(
    MODE_ORDER[left.caller.mode],
    MODE_ORDER[right.caller.mode],
  );
  if (compared !== 0) return compared;

  compared = compareString(
    left.caller.functionId ?? "",
    right.caller.functionId ?? "",
  );
  if (compared !== 0) return compared;

  return compareProvenFunctionIdentity(left.target, right.target);
}

export function compareFunctionCallEdge(
  left: ProvenFunctionCallEdge,
  right: ProvenFunctionCallEdge,
): number {
  let compared = compareString(left.callerFunctionId, right.callerFunctionId);
  if (compared !== 0) return compared;

  compared = compareNumber(left.instructionAddress, right.instructionAddress);
  if (compared !== 0) return compared;

  return compareString(left.calleeFunctionId, right.calleeFunctionId);
}
