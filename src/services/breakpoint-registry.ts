import type {
  BreakpointMode,
  ExecutableRangeRecord,
  ResolvedExecutionMode,
} from "./executable-ranges.js";

export interface AddBreakpointInput {
  readonly address: number;
  readonly requestedMode: BreakpointMode;
  readonly resolvedMode: ResolvedExecutionMode;
  readonly kind: 2 | 4;
  readonly range: ExecutableRangeRecord;
  readonly symbol?: string;
}

export interface BreakpointRecord {
  readonly id: string;
  readonly address: number;
  readonly requestedMode: BreakpointMode;
  readonly resolvedMode: ResolvedExecutionMode;
  readonly kind: 2 | 4;
  readonly rangeId: string;
  readonly source: ExecutableRangeRecord["source"];
  readonly overlayId?: number;
  readonly symbol?: string;
  readonly createdAt: string;
  readonly enabled: boolean;
  readonly hitCount: number;
}

const MAX_BREAKPOINTS = 32;

export class BreakpointRegistry {
  #nextId = 1;
  readonly #records = new Map<string, BreakpointRecord>();

  add(input: AddBreakpointInput): BreakpointRecord {
    if (this.#records.size >= MAX_BREAKPOINTS) {
      throw new Error(`At most ${MAX_BREAKPOINTS} active breakpoints are allowed`);
    }
    const duplicate = this.list().find(
      (record) =>
        record.address === input.address && record.resolvedMode === input.resolvedMode,
    );
    if (duplicate !== undefined) {
      throw new Error(`Duplicate breakpoint at 0x${input.address.toString(16)} (${input.resolvedMode})`);
    }

    const record: BreakpointRecord = {
      id: `bp-${this.#nextId}`,
      address: input.address,
      requestedMode: input.requestedMode,
      resolvedMode: input.resolvedMode,
      kind: input.kind,
      rangeId: input.range.id,
      source: input.range.source,
      ...(input.range.overlayId === undefined ? {} : { overlayId: input.range.overlayId }),
      ...(input.symbol === undefined ? {} : { symbol: input.symbol }),
      createdAt: new Date().toISOString(),
      enabled: false,
      hitCount: 0,
    };
    this.#nextId += 1;
    this.#records.set(record.id, record);
    return record;
  }

  remove(id: string): BreakpointRecord {
    const record = this.#require(id);
    this.#records.delete(id);
    return record;
  }

  markInstalled(id: string): void {
    this.#replace(id, { enabled: true });
  }

  markRemoved(id: string): void {
    this.#replace(id, { enabled: false });
  }

  recordHit(
    address: number,
    mode: ResolvedExecutionMode,
  ): BreakpointRecord | null {
    const record = this.list().find(
      (candidate) =>
        candidate.enabled && candidate.address === address && candidate.resolvedMode === mode,
    );
    if (record === undefined) return null;
    const updated = { ...record, hitCount: record.hitCount + 1 };
    this.#records.set(record.id, updated);
    return updated;
  }

  get(id: string): BreakpointRecord {
    return this.#require(id);
  }

  list(): readonly BreakpointRecord[] {
    return [...this.#records.values()];
  }

  clear(): void {
    this.#records.clear();
    this.#nextId = 1;
  }

  maximum(): number {
    return MAX_BREAKPOINTS;
  }

  #require(id: string): BreakpointRecord {
    const record = this.#records.get(id);
    if (record === undefined) throw new Error(`Unknown breakpoint ID: ${id}`);
    return record;
  }

  #replace(
    id: string,
    changes: Partial<Pick<BreakpointRecord, "enabled" | "hitCount">>,
  ): void {
    const record = this.#require(id);
    this.#records.set(id, { ...record, ...changes });
  }
}
