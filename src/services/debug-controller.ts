import { decodeArm9RegisterPacket } from "./arm9-registers.js";
import {
  BreakpointRegistry,
  type BreakpointRecord,
} from "./breakpoint-registry.js";
import {
  ExecutableRangeRegistry,
  type BreakpointMode,
  type ExecutableRangeInput,
} from "./executable-ranges.js";
import {
  GdbSession,
  type ExecutionResult,
  type StepSequenceResult,
} from "./gdb-session.js";
import type { GdbStopReply } from "./gdb-stop.js";
import type { Arm9ExecutableRange } from "./nds-arm9.js";
import {
  captureStopContext,
  type StopContext,
  type StopContextRegionRequest,
} from "./stop-context.js";

export interface AddBreakpointRequest {
  readonly address: number;
  readonly mode: BreakpointMode;
  readonly symbol?: string;
  readonly rangeId?: string;
  readonly timeoutMs: number;
}

export interface StopCaptureOptions {
  readonly captureContext?: boolean | undefined;
  readonly maxOutputBytes?: number | undefined;
  readonly additionalRegions?: readonly StopContextRegionRequest[] | undefined;
}

export interface ContinueRequest extends StopCaptureOptions {
  readonly timeoutMs: number;
  readonly expectedBreakpointId?: string | undefined;
}

export interface StepRequest extends StopCaptureOptions {
  readonly count: number;
  readonly perStepTimeoutMs: number;
}

export interface PauseRequest extends StopCaptureOptions {
  readonly timeoutMs: number;
}

export interface WaitForStopRequest extends StopCaptureOptions {
  readonly timeoutMs: number;
}

export type DebugExecutionResult =
  | {
      readonly kind: "timeout";
      readonly state: "running";
    }
  | {
      readonly kind: "stop";
      readonly stop: GdbStopReply;
      readonly state: "stopped" | "unavailable";
      readonly stoppedAt: string;
      readonly emulatorRunning: boolean;
      readonly matchedBreakpoint?: BreakpointRecord;
      readonly expectedBreakpointMatched?: boolean;
      readonly context?: StopContext;
    };

export interface DebugStepSequenceResult {
  readonly requested: number;
  readonly completed: number;
  readonly completedAll: boolean;
  readonly result: DebugExecutionResult;
}

interface EnrichmentOptions extends StopCaptureOptions {
  readonly timeoutMs: number;
  readonly expectedBreakpointId?: string | undefined;
}

export type GdbSessionFactory = (sessionIdentity: string) => GdbSession;

const DEFAULT_CONTEXT_OUTPUT_BYTES = 64 * 1024;

export class DebugController {
  readonly #createSession: GdbSessionFactory;
  #sessionIdentity: string | null = null;
  #session: GdbSession | null = null;
  #ranges: ExecutableRangeRegistry | null = null;
  #breakpoints = new BreakpointRegistry();
  #lastStop: GdbStopReply | null = null;
  #lastMatchedBreakpointId: string | null = null;

  constructor(createSession: GdbSessionFactory) {
    this.#createSession = createSession;
  }

  initialize(sessionIdentity: string, arm9Range: Arm9ExecutableRange): void {
    if (sessionIdentity.trim().length === 0) {
      throw new Error("Debugger session identity must not be empty");
    }

    const ranges = new ExecutableRangeRegistry(arm9Range);
    if (this.#sessionIdentity === sessionIdentity && this.#sameMainRange(ranges)) {
      return;
    }

    const session = this.#createSession(sessionIdentity);
    this.#session?.reset("Debugger session identity changed");
    this.#breakpoints.clear();
    this.#lastStop = null;
    this.#lastMatchedBreakpointId = null;
    this.#sessionIdentity = sessionIdentity;
    this.#session = session;
    this.#ranges = ranges;
  }

  replaceAdditionalRanges(ranges: readonly ExecutableRangeInput[]): void {
    if (this.#breakpoints.list().length > 0) {
      throw new Error("Cannot replace executable ranges while breakpoints are active");
    }
    this.#requireRanges().replaceAdditionalRanges(ranges);
  }

  async addBreakpoint(input: AddBreakpointRequest): Promise<BreakpointRecord> {
    const location = this.#requireRanges().resolve({
      address: input.address,
      mode: input.mode,
      ...(input.symbol === undefined ? {} : { symbol: input.symbol }),
      ...(input.rangeId === undefined ? {} : { rangeId: input.rangeId }),
    });
    const record = this.#breakpoints.add({
      address: location.address,
      requestedMode: input.mode,
      resolvedMode: location.mode,
      kind: location.kind,
      range: location.range,
      ...(input.symbol === undefined ? {} : { symbol: input.symbol }),
    });

    try {
      await this.#requireSession().insertSoftwareBreakpoint(
        record.address,
        record.kind,
        input.timeoutMs,
      );
      this.#breakpoints.markInstalled(record.id);
      return this.#breakpoints.get(record.id);
    } catch (error) {
      this.#breakpoints.remove(record.id);
      throw error;
    }
  }

  async removeBreakpoint(
    id: string,
    timeoutMs = 3_000,
  ): Promise<BreakpointRecord> {
    const record = this.#breakpoints.get(id);
    await this.#requireSession().removeSoftwareBreakpoint(
      record.address,
      record.kind,
      timeoutMs,
    );
    this.#breakpoints.markRemoved(id);
    const removed = this.#breakpoints.get(id);
    this.#breakpoints.remove(id);
    return removed;
  }

  async continueExecution(input: ContinueRequest): Promise<DebugExecutionResult> {
    if (input.expectedBreakpointId !== undefined) {
      this.#breakpoints.get(input.expectedBreakpointId);
    }
    const result = await this.#requireSession().continueExecution(input.timeoutMs);
    return await this.#enrichExecutionResult(result, {
      timeoutMs: input.timeoutMs,
      captureContext: input.captureContext,
      maxOutputBytes: input.maxOutputBytes,
      additionalRegions: input.additionalRegions,
      expectedBreakpointId: input.expectedBreakpointId,
    });
  }

  async step(input: StepRequest): Promise<DebugStepSequenceResult> {
    const sequence: StepSequenceResult = await this.#requireSession().stepInstructions(
      input.count,
      input.perStepTimeoutMs,
    );
    const result = await this.#enrichExecutionResult(sequence.result, {
      timeoutMs: input.perStepTimeoutMs,
      captureContext: input.captureContext,
      maxOutputBytes: input.maxOutputBytes,
      additionalRegions: input.additionalRegions,
    });
    return {
      requested: sequence.requested,
      completed: sequence.completed,
      completedAll: sequence.completedAll,
      result,
    };
  }

  async pause(input: number | PauseRequest): Promise<DebugExecutionResult> {
    const request: PauseRequest = typeof input === "number"
      ? { timeoutMs: input }
      : input;
    const result = await this.#requireSession().interruptAndWait(request.timeoutMs);
    return await this.#enrichExecutionResult(result, {
      timeoutMs: request.timeoutMs,
      captureContext: request.captureContext,
      maxOutputBytes: request.maxOutputBytes,
      additionalRegions: request.additionalRegions,
    });
  }

  async waitForStop(input: number | WaitForStopRequest): Promise<DebugExecutionResult> {
    const request: WaitForStopRequest = typeof input === "number"
      ? { timeoutMs: input }
      : input;
    const result = await this.#requireSession().waitForStop(request.timeoutMs);
    return await this.#enrichExecutionResult(result, {
      timeoutMs: request.timeoutMs,
      captureContext: request.captureContext,
      maxOutputBytes: request.maxOutputBytes,
      additionalRegions: request.additionalRegions,
    });
  }

  async reset(reason: string): Promise<void> {
    this.#session?.reset(reason);
    this.#sessionIdentity = null;
    this.#session = null;
    this.#ranges = null;
    this.#breakpoints.clear();
    this.#lastStop = null;
    this.#lastMatchedBreakpointId = null;
  }

  async #enrichExecutionResult(
    result: ExecutionResult,
    options: EnrichmentOptions,
  ): Promise<DebugExecutionResult> {
    if (result.kind === "timeout") return result;

    const stoppedAt = new Date().toISOString();
    this.#lastStop = result.stop;
    if (result.stop.kind !== "signal") {
      this.#lastMatchedBreakpointId = null;
      return {
        ...result,
        stoppedAt,
        emulatorRunning: false,
        ...(options.expectedBreakpointId === undefined
          ? {}
          : { expectedBreakpointMatched: false }),
      };
    }

    if (!this.#shouldInspectSignalStop(options)) {
      this.#lastMatchedBreakpointId = null;
      return {
        ...result,
        stoppedAt,
        emulatorRunning: true,
      };
    }

    const session = this.#requireSession();
    const registers = decodeArm9RegisterPacket(
      await session.sendStoppedCommand("g", options.timeoutMs),
    );
    const ranges = this.#requireRanges();
    ranges.recordExecution(registers.pc, registers.mode);
    const matchedBreakpoint = this.#breakpoints.recordHit(registers.pc, registers.mode);
    this.#lastMatchedBreakpointId = matchedBreakpoint?.id ?? null;

    const context = options.captureContext === true
      ? await captureStopContext({
          session,
          stop: result.stop,
          timeoutMs: options.timeoutMs,
          maxOutputBytes: options.maxOutputBytes ?? DEFAULT_CONTEXT_OUTPUT_BYTES,
          registers,
          ...(matchedBreakpoint === null ? {} : { breakpoint: matchedBreakpoint }),
          additionalRegions: options.additionalRegions,
        })
      : undefined;

    return {
      ...result,
      stoppedAt,
      emulatorRunning: true,
      ...(matchedBreakpoint === null ? {} : { matchedBreakpoint }),
      ...(options.expectedBreakpointId === undefined
        ? {}
        : { expectedBreakpointMatched: matchedBreakpoint?.id === options.expectedBreakpointId }),
      ...(context === undefined ? {} : { context }),
    };
  }

  #shouldInspectSignalStop(options: EnrichmentOptions): boolean {
    return options.captureContext !== undefined
      || options.expectedBreakpointId !== undefined
      || options.additionalRegions !== undefined
      || options.maxOutputBytes !== undefined
      || this.#breakpoints.list().length > 0;
  }

  #requireSession(): GdbSession {
    const session = this.#session;
    if (session === null) {
      throw new Error("Debug controller is not initialized");
    }
    return session;
  }

  #requireRanges(): ExecutableRangeRegistry {
    const ranges = this.#ranges;
    if (ranges === null) {
      throw new Error("Debug controller is not initialized");
    }
    return ranges;
  }

  #sameMainRange(candidate: ExecutableRangeRegistry): boolean {
    const current = this.#ranges?.list()[0];
    const next = candidate.list()[0];
    if (current === undefined || next === undefined) return false;
    return current.start === next.start && current.end === next.end;
  }
}
