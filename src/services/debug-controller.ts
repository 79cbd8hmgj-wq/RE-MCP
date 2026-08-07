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
import type { Arm9ExecutableRange } from "./nds-arm9.js";

export interface AddBreakpointRequest {
  readonly address: number;
  readonly mode: BreakpointMode;
  readonly symbol?: string;
  readonly rangeId?: string;
  readonly timeoutMs: number;
}

export interface ContinueRequest {
  readonly timeoutMs: number;
}

export interface StepRequest {
  readonly count: number;
  readonly perStepTimeoutMs: number;
}

export type GdbSessionFactory = (sessionIdentity: string) => GdbSession;

export class DebugController {
  readonly #createSession: GdbSessionFactory;
  #sessionIdentity: string | null = null;
  #session: GdbSession | null = null;
  #ranges: ExecutableRangeRegistry | null = null;
  #breakpoints = new BreakpointRegistry();

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

  async continueExecution(input: ContinueRequest): Promise<ExecutionResult> {
    return await this.#requireSession().continueExecution(input.timeoutMs);
  }

  async step(input: StepRequest): Promise<StepSequenceResult> {
    return await this.#requireSession().stepInstructions(
      input.count,
      input.perStepTimeoutMs,
    );
  }

  async pause(timeoutMs: number): Promise<ExecutionResult> {
    return await this.#requireSession().interruptAndWait(timeoutMs);
  }

  async waitForStop(timeoutMs: number): Promise<ExecutionResult> {
    return await this.#requireSession().waitForStop(timeoutMs);
  }

  async reset(reason: string): Promise<void> {
    this.#session?.reset(reason);
    this.#sessionIdentity = null;
    this.#session = null;
    this.#ranges = null;
    this.#breakpoints.clear();
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
