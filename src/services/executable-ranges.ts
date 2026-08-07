import type { Arm9ExecutableRange } from "./nds-arm9.js";

export type BreakpointMode = "arm" | "thumb" | "auto";
export type ResolvedExecutionMode = "arm" | "thumb";
export type RangeSource = "arm9-header" | "overlay" | "explicit";

export interface ExecutableRangeInput {
  readonly id: string;
  readonly label: string;
  readonly start: number;
  readonly end: number;
  readonly source: Exclude<RangeSource, "arm9-header">;
  readonly overlayId?: number;
  readonly defaultMode?: ResolvedExecutionMode;
  readonly symbolModes?: Readonly<Record<string, ResolvedExecutionMode>>;
}

export interface ExecutableRangeRecord {
  readonly id: string;
  readonly label: string;
  readonly start: number;
  readonly end: number;
  readonly source: RangeSource;
  readonly overlayId?: number;
  readonly defaultMode?: ResolvedExecutionMode;
  readonly symbolModes: Readonly<Record<string, ResolvedExecutionMode>>;
}

export interface ResolveModeInput {
  readonly address: number;
  readonly mode: BreakpointMode;
  readonly symbol?: string;
  readonly rangeId?: string;
}

export interface ResolvedBreakpointLocation {
  readonly address: number;
  readonly mode: ResolvedExecutionMode;
  readonly kind: 2 | 4;
  readonly range: ExecutableRangeRecord;
}

const MAIN_RAM_START = 0x02000000;
const MAIN_RAM_END = 0x02400000;
const MAX_ADDITIONAL_RANGES = 64;

function validateU32(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`${label} must be an unsigned 32-bit integer`);
  }
}

function validateRange(range: ExecutableRangeRecord): void {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(range.id)) {
    throw new Error("Executable range ID must use 1-64 safe identifier characters");
  }
  if (range.label.trim().length === 0 || range.label.length > 128) {
    throw new Error("Executable range label must contain 1-128 characters");
  }
  validateU32(range.start, "Executable range start");
  validateU32(range.end, "Executable range end");
  if (range.end <= range.start) throw new Error("Executable range must be non-empty");
  if (range.start < MAIN_RAM_START || range.end > MAIN_RAM_END) {
    throw new Error("Executable range is outside DS ARM9 main RAM");
  }
  if (range.overlayId !== undefined && (!Number.isInteger(range.overlayId) || range.overlayId < 0)) {
    throw new Error("Overlay ID must be a non-negative integer");
  }
}

export function normalizeBreakpointAddress(
  address: number,
  mode: BreakpointMode,
): number {
  validateU32(address, "Breakpoint address");
  if (mode === "thumb" || (mode === "auto" && (address & 1) === 1)) {
    return address & 0xfffffffe;
  }
  return address;
}

export class ExecutableRangeRegistry {
  readonly #main: ExecutableRangeRecord;
  #additional: readonly ExecutableRangeRecord[] = [];
  readonly #executionHistory = new Map<number, ResolvedExecutionMode>();

  constructor(main: Arm9ExecutableRange) {
    this.#main = {
      id: "arm9-main",
      label: main.label,
      start: main.start,
      end: main.end,
      source: main.source,
      symbolModes: {},
    };
    validateRange(this.#main);
  }

  replaceAdditionalRanges(inputs: readonly ExecutableRangeInput[]): void {
    if (inputs.length > MAX_ADDITIONAL_RANGES) {
      throw new Error(`At most ${MAX_ADDITIONAL_RANGES} additional executable ranges are allowed`);
    }

    const records = inputs.map<ExecutableRangeRecord>((input) => ({
      id: input.id,
      label: input.label,
      start: input.start,
      end: input.end,
      source: input.source,
      ...(input.overlayId === undefined ? {} : { overlayId: input.overlayId }),
      ...(input.defaultMode === undefined ? {} : { defaultMode: input.defaultMode }),
      symbolModes: { ...(input.symbolModes ?? {}) },
    }));

    const all = [this.#main, ...records];
    const ids = new Set<string>();
    for (const range of all) {
      validateRange(range);
      if (ids.has(range.id)) throw new Error(`Duplicate executable range ID: ${range.id}`);
      ids.add(range.id);
    }

    for (let leftIndex = 0; leftIndex < all.length; leftIndex += 1) {
      const left = all[leftIndex]!;
      for (let rightIndex = leftIndex + 1; rightIndex < all.length; rightIndex += 1) {
        const right = all[rightIndex]!;
        const overlaps = left.start < right.end && right.start < left.end;
        const identical = left.start === right.start && left.end === right.end;
        if (overlaps && !identical) {
          throw new Error(`Executable ranges overlap: ${left.id} and ${right.id}`);
        }
      }
    }

    this.#additional = records;
  }

  list(): readonly ExecutableRangeRecord[] {
    return [this.#main, ...this.#additional];
  }

  recordExecution(address: number, mode: ResolvedExecutionMode): void {
    const normalized = normalizeBreakpointAddress(address, mode);
    this.#executionHistory.set(normalized, mode);
  }

  resolve(input: ResolveModeInput): ResolvedBreakpointLocation {
    const normalized = normalizeBreakpointAddress(input.address, input.mode);
    const matches = this.list().filter(
      (range) => normalized >= range.start && normalized < range.end,
    );
    const candidates = input.rangeId === undefined
      ? matches
      : matches.filter((range) => range.id === input.rangeId);
    if (candidates.length === 0) {
      throw new Error("Breakpoint address is outside all allowlisted executable ranges");
    }
    if (candidates.length > 1) {
      throw new Error("Breakpoint address matches multiple executable ranges; provide rangeId");
    }

    const range = candidates[0]!;
    const mode = this.#resolveMode(input, normalized, range);
    if (mode === "arm" && normalized % 4 !== 0) {
      throw new Error("ARM breakpoint addresses must be 4-byte aligned");
    }
    if (mode === "thumb" && normalized % 2 !== 0) {
      throw new Error("Thumb breakpoint addresses must be 2-byte aligned");
    }

    return { address: normalized, mode, kind: mode === "arm" ? 4 : 2, range };
  }

  #resolveMode(
    input: ResolveModeInput,
    normalized: number,
    range: ExecutableRangeRecord,
  ): ResolvedExecutionMode {
    if (input.mode === "arm" || input.mode === "thumb") return input.mode;

    if (input.symbol !== undefined) {
      const symbolMode = range.symbolModes[input.symbol];
      if (symbolMode !== undefined) return symbolMode;
    }
    if (range.defaultMode !== undefined) return range.defaultMode;

    const historical = this.#executionHistory.get(normalized);
    if (historical !== undefined) return historical;
    if ((input.address & 1) === 1) return "thumb";
    if (normalized % 4 === 2) return "thumb";

    throw new Error("Breakpoint execution mode is ambiguous; specify arm or thumb");
  }
}
