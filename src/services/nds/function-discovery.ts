import type { ArmDisassemblyBackend } from "../disassembly/backend.js";
import {
  analyzeNdsControlFlow,
  type ControlFlowLimits,
  type StaticControlFlowGraph,
} from "./control-flow.js";
import type { NdsCodeSource } from "./disassembly-source.js";
import {
  NdsError,
  type AnyNdsErrorCategory,
  type NdsFunctionErrorCategory,
} from "./errors.js";
import {
  compareFunctionCallEdge,
  compareFunctionProof,
  compareProvenFunctionIdentity,
  provenFunctionId,
  type FunctionComponentCoverageStatus,
  type FunctionProof,
  type ProvenFunctionCallEdge,
  type ProvenFunctionIdentity,
} from "./function-model.js";
import {
  functionComponentKey,
  prepareFunctionSearch,
  type FunctionComponentIdentity,
  type FunctionSearchScope,
  type FunctionSearchSeed,
} from "./function-source.js";
import type { NdsProcessor } from "./overlays.js";
import type { NdsRomMap } from "./rom-map.js";

export interface FunctionDiscoveryLimits {
  readonly maxComponents: number;
  readonly maxFunctions: number;
  readonly maxCallSites: number;
  readonly maxTotalBlocks: number;
  readonly maxTotalInstructions: number;
  readonly maxTotalBytes: number;
  readonly maxTotalEdges: number;
  readonly perFunctionCfg: ControlFlowLimits;
}

export type FunctionDiscoveryTruncationReason =
  | "component-limit"
  | "function-limit"
  | "call-site-limit"
  | "block-limit"
  | "instruction-limit"
  | "byte-limit"
  | "edge-limit";

export interface FunctionComponentCoverage {
  readonly component: "main" | "overlay";
  readonly overlayId: number | null;
  readonly status: FunctionComponentCoverageStatus;
}

export interface DiscoveredFunction {
  readonly id: string;
  readonly entry: ProvenFunctionIdentity;
  readonly evidence: readonly FunctionProof[];
  readonly directCallerCount: number;
  readonly directCallSiteCount: number;
  readonly cfg: {
    readonly status: "complete" | "truncated";
    readonly truncationReasons: readonly string[];
    readonly blocks: number;
    readonly instructions: number;
    readonly decodedBytes: number;
    readonly traversalEdges: number;
    readonly returnSites: number;
    readonly unresolvedEdges: number;
  };
}

export interface DiscoverNdsFunctionsRequest {
  readonly processor: NdsProcessor;
  readonly scope: FunctionSearchScope;
  readonly seeds: readonly FunctionSearchSeed[];
}

export interface DiscoverNdsFunctionsResult {
  readonly status: "complete" | "partial-coverage" | "truncated";
  readonly processor: NdsProcessor;
  readonly functions: readonly DiscoveredFunction[];
  readonly calls: readonly ProvenFunctionCallEdge[];
  readonly coverage: readonly FunctionComponentCoverage[];
  readonly truncationReasons: readonly FunctionDiscoveryTruncationReason[];
  readonly totals: {
    readonly functions: number;
    readonly callSites: number;
    readonly blocks: number;
    readonly instructions: number;
    readonly decodedBytes: number;
    readonly traversalEdges: number;
  };
}

interface MutableFunctionRecord {
  readonly identity: ProvenFunctionIdentity;
  readonly source: NdsCodeSource;
  readonly evidence: FunctionProof[];
  cfg: DiscoveredFunction["cfg"] | null;
}

type ScheduledWork =
  | {
    readonly kind: "function";
    readonly functionId: string;
    readonly source: NdsCodeSource;
  }
  | {
    readonly kind: "coverage";
    readonly source: NdsCodeSource;
  };

interface EffectiveCfgLimits {
  readonly limits: ControlFlowLimits;
  readonly globalTightening: ReadonlySet<Exclude<
    FunctionDiscoveryTruncationReason,
    "component-limit" | "function-limit" | "call-site-limit"
  >>;
}

const TRUNCATION_REASON_ORDER: readonly FunctionDiscoveryTruncationReason[] = [
  "component-limit",
  "function-limit",
  "call-site-limit",
  "block-limit",
  "instruction-limit",
  "byte-limit",
  "edge-limit",
];

function functionError(
  category: NdsFunctionErrorCategory,
  message: string,
): NdsError<AnyNdsErrorCategory> {
  return new NdsError(category as AnyNdsErrorCategory, message);
}

function validatePositiveSafeInteger(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw functionError(
      "function-discovery-limit-exceeded",
      `${label} must be a positive safe integer`,
    );
  }
}

function validateLimits(limits: FunctionDiscoveryLimits): void {
  validatePositiveSafeInteger(limits.maxComponents, "Maximum component count");
  validatePositiveSafeInteger(limits.maxFunctions, "Maximum function count");
  validatePositiveSafeInteger(limits.maxCallSites, "Maximum direct call-site count");
  validatePositiveSafeInteger(limits.maxTotalBlocks, "Maximum total block count");
  validatePositiveSafeInteger(
    limits.maxTotalInstructions,
    "Maximum total instruction count",
  );
  validatePositiveSafeInteger(limits.maxTotalBytes, "Maximum total decoded byte count");
  validatePositiveSafeInteger(limits.maxTotalEdges, "Maximum total traversal edge count");
  validatePositiveSafeInteger(limits.perFunctionCfg.maxBlocks, "Per-function block count");
  validatePositiveSafeInteger(
    limits.perFunctionCfg.maxInstructions,
    "Per-function instruction count",
  );
  validatePositiveSafeInteger(limits.perFunctionCfg.maxBytes, "Per-function decoded byte count");
  validatePositiveSafeInteger(limits.perFunctionCfg.maxEdges, "Per-function traversal edge count");
}

function sourceKey(source: NdsCodeSource): string {
  return [
    functionComponentKey(source),
    source.runtimeAddress.toString(16),
    source.mode,
  ].join(":");
}

function identityFromSource(source: NdsCodeSource): ProvenFunctionIdentity {
  return {
    processor: source.processor,
    component: source.component,
    overlayId: source.overlayId,
    runtimeAddress: source.runtimeAddress,
    romOffset: source.romOffset,
    mode: source.mode,
  };
}

function directProofKey(proof: Extract<FunctionProof, { readonly kind: "direct-call" }>): string {
  return [
    proof.caller.component,
    proof.caller.overlayId ?? "main",
    proof.caller.instructionAddress.toString(16),
    proof.caller.mode,
    provenFunctionId(proof.target),
  ].join(":");
}

function addProof(record: MutableFunctionRecord, proof: FunctionProof): void {
  if (proof.kind === "program-entry") {
    if (!record.evidence.some((entry) => entry.kind === "program-entry")) {
      record.evidence.push(proof);
      record.evidence.sort(compareFunctionProof);
    }
    return;
  }

  const key = directProofKey(proof);
  const existingIndex = record.evidence.findIndex(
    (entry) => entry.kind === "direct-call" && directProofKey(entry) === key,
  );
  if (existingIndex < 0) {
    record.evidence.push(proof);
    record.evidence.sort(compareFunctionProof);
    return;
  }

  const existing = record.evidence[existingIndex];
  if (
    existing?.kind === "direct-call"
    && existing.caller.functionId === null
    && proof.caller.functionId !== null
  ) {
    record.evidence[existingIndex] = proof;
    record.evidence.sort(compareFunctionProof);
  }
}

function graphForResult(
  result: Awaited<ReturnType<typeof analyzeNdsControlFlow>>,
): StaticControlFlowGraph {
  if (!("blocks" in result)) {
    throw functionError(
      "function-entry-not-uniquely-resolved",
      `Previously resolved function source became unavailable: ${result.status}`,
    );
  }
  return result;
}

function summarizeCfg(graph: StaticControlFlowGraph): DiscoveredFunction["cfg"] {
  return {
    status: graph.status,
    truncationReasons: graph.truncationReasons,
    blocks: graph.totals.blocks,
    instructions: graph.totals.instructions,
    decodedBytes: graph.totals.bytes,
    traversalEdges: graph.totals.edges,
    returnSites: graph.unresolvedEdges.filter((edge) => edge.kind === "return").length,
    unresolvedEdges: graph.unresolvedEdges.length,
  };
}

function emptyTruncatedCfg(
  reasons: ReadonlySet<FunctionDiscoveryTruncationReason>,
): DiscoveredFunction["cfg"] {
  const cfgReasons = ["block-limit", "instruction-limit", "byte-limit", "edge-limit"]
    .filter((reason) => reasons.has(reason as FunctionDiscoveryTruncationReason));
  return {
    status: "truncated",
    truncationReasons: cfgReasons.length > 0 ? cfgReasons : ["block-limit"],
    blocks: 0,
    instructions: 0,
    decodedBytes: 0,
    traversalEdges: 0,
    returnSites: 0,
    unresolvedEdges: 0,
  };
}

function compareCoverageSeed(left: NdsCodeSource, right: NdsCodeSource): number {
  const leftComponent = functionComponentKey(left);
  const rightComponent = functionComponentKey(right);
  if (leftComponent !== rightComponent) {
    return leftComponent < rightComponent ? -1 : 1;
  }
  if (left.runtimeAddress !== right.runtimeAddress) {
    return left.runtimeAddress - right.runtimeAddress;
  }
  if (left.mode !== right.mode) {
    return left.mode === "arm" ? -1 : 1;
  }
  return 0;
}

export async function discoverNdsFunctions(
  map: NdsRomMap,
  request: DiscoverNdsFunctionsRequest,
  limits: FunctionDiscoveryLimits,
  backend: ArmDisassemblyBackend,
): Promise<DiscoverNdsFunctionsResult> {
  validateLimits(limits);

  const prepared = prepareFunctionSearch(
    map,
    request.processor,
    request.scope,
    request.seeds,
  );
  const considered = prepared.components.slice(0, limits.maxComponents);
  const excluded = prepared.components.slice(limits.maxComponents);
  const selectedKeys = new Set(considered.map(functionComponentKey));
  const reasons = new Set<FunctionDiscoveryTruncationReason>();
  if (excluded.length > 0) {
    reasons.add("component-limit");
  }

  const functions = new Map<string, MutableFunctionRecord>();
  const queue: ScheduledWork[] = [];
  const scheduledFunctions = new Set<string>();
  const analyzedFunctions = new Set<string>();
  const scheduledCoverage = new Set<string>();
  const analyzedCoverage = new Set<string>();
  const scannedComponents = new Set<string>();
  const limitedComponents = new Set<string>();
  const retainedCallSites = new Set<string>();
  const retainedCallEdges = new Map<string, ProvenFunctionCallEdge>();
  const seenBlocks = new Set<string>();
  const seenInstructions = new Set<string>();
  const seenTraversalEdges = new Set<string>();
  let decodedBytes = 0;

  function scheduleFunction(record: MutableFunctionRecord): void {
    const id = provenFunctionId(record.identity);
    if (scheduledFunctions.has(id) || analyzedFunctions.has(id)) {
      return;
    }
    scheduledFunctions.add(id);
    queue.push({ kind: "function", functionId: id, source: record.source });
  }

  function ensureFunction(
    identity: ProvenFunctionIdentity,
    source: NdsCodeSource,
    proof: FunctionProof,
  ): MutableFunctionRecord | null {
    const id = provenFunctionId(identity);
    const existing = functions.get(id);
    if (existing !== undefined) {
      addProof(existing, proof);
      return existing;
    }
    if (functions.size >= limits.maxFunctions) {
      reasons.add("function-limit");
      limitedComponents.add(functionComponentKey(identity));
      return null;
    }

    const record: MutableFunctionRecord = {
      identity,
      source,
      evidence: [proof],
      cfg: null,
    };
    functions.set(id, record);
    scheduleFunction(record);
    return record;
  }

  if (
    prepared.programEntry !== null
    && selectedKeys.has(functionComponentKey(prepared.programEntry.identity))
  ) {
    ensureFunction(
      prepared.programEntry.identity,
      prepared.programEntry.source,
      prepared.programEntry.proof,
    );
  }

  const coverageSeeds = [...prepared.explicitSeeds]
    .filter((source) => selectedKeys.has(functionComponentKey(source)))
    .sort(compareCoverageSeed);
  for (const source of coverageSeeds) {
    const key = sourceKey(source);
    if (!scheduledCoverage.has(key)) {
      scheduledCoverage.add(key);
      queue.push({ kind: "coverage", source });
    }
  }

  function remainingCfgLimits(): EffectiveCfgLimits | null {
    const remainingBlocks = limits.maxTotalBlocks - seenBlocks.size;
    const remainingInstructions = limits.maxTotalInstructions - seenInstructions.size;
    const remainingBytes = limits.maxTotalBytes - decodedBytes;
    const remainingEdges = limits.maxTotalEdges - seenTraversalEdges.size;

    if (remainingBlocks <= 0) reasons.add("block-limit");
    if (remainingInstructions <= 0) reasons.add("instruction-limit");
    if (remainingBytes <= 0) reasons.add("byte-limit");
    if (remainingEdges <= 0) reasons.add("edge-limit");
    if (
      remainingBlocks <= 0
      || remainingInstructions <= 0
      || remainingBytes <= 0
      || remainingEdges <= 0
    ) {
      return null;
    }

    const globalTightening = new Set<
      Exclude<FunctionDiscoveryTruncationReason, "component-limit" | "function-limit" | "call-site-limit">
    >();
    if (remainingBlocks <= limits.perFunctionCfg.maxBlocks) globalTightening.add("block-limit");
    if (remainingInstructions <= limits.perFunctionCfg.maxInstructions) globalTightening.add("instruction-limit");
    if (remainingBytes <= limits.perFunctionCfg.maxBytes) globalTightening.add("byte-limit");
    if (remainingEdges <= limits.perFunctionCfg.maxEdges) globalTightening.add("edge-limit");

    return {
      limits: {
        maxBlocks: Math.min(limits.perFunctionCfg.maxBlocks, remainingBlocks),
        maxInstructions: Math.min(
          limits.perFunctionCfg.maxInstructions,
          remainingInstructions,
        ),
        maxBytes: Math.min(limits.perFunctionCfg.maxBytes, remainingBytes),
        maxEdges: Math.min(limits.perFunctionCfg.maxEdges, remainingEdges),
      },
      globalTightening,
    };
  }

  function collectGraphTotals(graph: StaticControlFlowGraph): void {
    for (const block of graph.blocks) {
      seenBlocks.add(block.id);
      scannedComponents.add(functionComponentKey(block.source));
      for (const instruction of block.instructions) {
        const key = `${block.id}:${instruction.address.toString(16)}:${instruction.mode}`;
        if (!seenInstructions.has(key)) {
          seenInstructions.add(key);
          decodedBytes += instruction.size;
        }
      }
    }
    for (const edge of graph.edges) {
      seenTraversalEdges.add([
        edge.fromBlockId,
        edge.type,
        edge.targetAddress.toString(16),
        edge.targetMode,
      ].join(":"));
    }
  }

  function mapGlobalGraphTruncation(
    graph: StaticControlFlowGraph,
    effective: EffectiveCfgLimits,
  ): void {
    for (const reason of graph.truncationReasons) {
      if (effective.globalTightening.has(reason)) {
        reasons.add(reason);
      }
    }
  }

  function markGraphLimited(graph: StaticControlFlowGraph, start: NdsCodeSource): void {
    if (graph.status !== "truncated") {
      return;
    }
    limitedComponents.add(functionComponentKey(start));
    for (const block of graph.blocks) {
      limitedComponents.add(functionComponentKey(block.source));
    }
  }

  function callSiteInstruction(
    graph: StaticControlFlowGraph,
    fromBlockId: string,
    instructionAddress: number,
  ) {
    const block = graph.blocks.find((entry) => entry.id === fromBlockId);
    const instruction = block?.instructions.find(
      (entry) => entry.address === instructionAddress,
    );
    if (block === undefined || instruction === undefined) {
      throw functionError(
        "function-entry-not-uniquely-resolved",
        `CFG call at 0x${instructionAddress.toString(16)} lacks its source instruction`,
      );
    }
    return { block, instruction };
  }

  function processCalls(
    graph: StaticControlFlowGraph,
    callerFunctionId: string | null,
  ): void {
    for (const call of graph.calls) {
      if (
        call.targetAddress === null
        || call.targetMode === null
        || call.resolution?.status !== "resolved"
      ) {
        continue;
      }
      const targetSource = call.resolution.source;
      const targetComponent = functionComponentKey(targetSource);
      if (
        targetSource.processor !== request.processor
        || !selectedKeys.has(targetComponent)
      ) {
        continue;
      }

      const target = identityFromSource(targetSource);
      const { instruction } = callSiteInstruction(
        graph,
        call.fromBlockId,
        call.instructionAddress,
      );
      const proof: Extract<FunctionProof, { readonly kind: "direct-call" }> = {
        kind: "direct-call",
        caller: {
          functionId: callerFunctionId,
          component: instruction.source.component,
          overlayId: instruction.source.overlayId,
          instructionAddress: instruction.address,
          instructionRomOffset: instruction.romOffset,
          mode: instruction.mode,
        },
        target,
      };
      const siteKey = directProofKey(proof);
      const isNewSite = !retainedCallSites.has(siteKey);
      if (isNewSite && retainedCallSites.size >= limits.maxCallSites) {
        reasons.add("call-site-limit");
        limitedComponents.add(targetComponent);
        continue;
      }
      if (isNewSite) {
        retainedCallSites.add(siteKey);
      }

      const targetRecord = ensureFunction(target, targetSource, proof);
      if (targetRecord === null) {
        continue;
      }

      if (callerFunctionId !== null) {
        const edge: ProvenFunctionCallEdge = {
          callerFunctionId,
          instructionAddress: instruction.address,
          instructionRomOffset: instruction.romOffset,
          calleeFunctionId: provenFunctionId(targetRecord.identity),
        };
        const edgeKey = [
          edge.callerFunctionId,
          edge.instructionAddress.toString(16),
          edge.instructionRomOffset.toString(16),
          edge.calleeFunctionId,
        ].join(":");
        retainedCallEdges.set(edgeKey, edge);
      }
    }
  }

  while (queue.length > 0) {
    const work = queue.shift();
    if (work === undefined) {
      break;
    }

    if (work.kind === "function") {
      if (analyzedFunctions.has(work.functionId)) {
        continue;
      }
      analyzedFunctions.add(work.functionId);
    } else {
      const key = sourceKey(work.source);
      if (analyzedCoverage.has(key)) {
        continue;
      }
      analyzedCoverage.add(key);
      const sourceIdentity = provenFunctionId(identityFromSource(work.source));
      if (functions.has(sourceIdentity)) {
        continue;
      }
    }

    const effective = remainingCfgLimits();
    if (effective === null) {
      limitedComponents.add(functionComponentKey(work.source));
      if (work.kind === "function") {
        const record = functions.get(work.functionId);
        if (record !== undefined && record.cfg === null) {
          record.cfg = emptyTruncatedCfg(reasons);
        }
      }
      continue;
    }

    const graph = graphForResult(await analyzeNdsControlFlow(
      map,
      {
        processor: work.source.processor,
        runtimeAddress: work.source.runtimeAddress,
        mode: work.source.mode,
        ...(work.source.overlayId === null
          ? {}
          : { overlayId: work.source.overlayId }),
      },
      effective.limits,
      backend,
    ));

    collectGraphTotals(graph);
    mapGlobalGraphTruncation(graph, effective);
    markGraphLimited(graph, work.source);

    if (work.kind === "function") {
      const record = functions.get(work.functionId);
      if (record !== undefined) {
        record.cfg = summarizeCfg(graph);
      }
      processCalls(graph, work.functionId);
    } else {
      processCalls(graph, null);
    }
  }

  const functionResults: DiscoveredFunction[] = [...functions.values()]
    .sort((left, right) => compareProvenFunctionIdentity(left.identity, right.identity))
    .map((record) => {
      record.evidence.sort(compareFunctionProof);
      const callerIds = new Set<string>();
      let directCallSiteCount = 0;
      for (const proof of record.evidence) {
        if (proof.kind !== "direct-call") {
          continue;
        }
        directCallSiteCount += 1;
        if (proof.caller.functionId !== null) {
          callerIds.add(proof.caller.functionId);
        }
      }
      return {
        id: provenFunctionId(record.identity),
        entry: record.identity,
        evidence: record.evidence,
        directCallerCount: callerIds.size,
        directCallSiteCount,
        cfg: record.cfg ?? emptyTruncatedCfg(reasons),
      };
    });

  const coverage: FunctionComponentCoverage[] = prepared.components.map(
    (component: FunctionComponentIdentity, index: number) => {
      const key = functionComponentKey(component);
      let status: FunctionComponentCoverageStatus;
      if (index >= limits.maxComponents) {
        status = "out-of-limit";
      } else if (component.compressed) {
        status = "compressed-overlay-not-decodable";
      } else if (limitedComponents.has(key)) {
        status = "out-of-limit";
      } else if (scannedComponents.has(key)) {
        status = "scanned";
      } else {
        status = "no-proven-seed";
      }
      return {
        component: component.component,
        overlayId: component.overlayId,
        status,
      };
    },
  );

  const truncationReasons = TRUNCATION_REASON_ORDER.filter(
    (reason) => reasons.has(reason),
  );
  const hasCoverageGap = coverage.some((entry) => entry.status !== "scanned");
  const status: DiscoverNdsFunctionsResult["status"] = truncationReasons.length > 0
    ? "truncated"
    : hasCoverageGap
      ? "partial-coverage"
      : "complete";

  const calls = [...retainedCallEdges.values()].sort(compareFunctionCallEdge);
  return {
    status,
    processor: request.processor,
    functions: functionResults,
    calls,
    coverage,
    truncationReasons,
    totals: {
      functions: functionResults.length,
      callSites: retainedCallSites.size,
      blocks: seenBlocks.size,
      instructions: seenInstructions.size,
      decodedBytes,
      traversalEdges: seenTraversalEdges.size,
    },
  };
}
