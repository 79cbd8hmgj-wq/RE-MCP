import { decodeArm9RegisterPacket, type Arm9RegisterContext } from "./arm9-registers.js";
import type { BreakpointRecord } from "./breakpoint-registry.js";
import { validateMemoryRead } from "./gdb-rsp.js";
import type { GdbSession } from "./gdb-session.js";
import type { GdbStopReply } from "./gdb-stop.js";

export interface StopContextRegionRequest {
  readonly label: string;
  readonly address: number;
  readonly length: number;
}

export interface StopContextMemoryRegion {
  readonly address: number;
  readonly length: number;
  readonly dataHex: string;
}

export interface LabeledStopContextMemoryRegion extends StopContextMemoryRegion {
  readonly label: string;
}

export interface CaptureStopContextInput {
  readonly session: Pick<GdbSession, "sendStoppedCommand">;
  readonly stop: GdbStopReply;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  readonly registers?: Arm9RegisterContext | undefined;
  readonly breakpoint?: BreakpointRecord | undefined;
  readonly additionalRegions?: readonly StopContextRegionRequest[] | undefined;
}

export interface StopContext {
  readonly capturedAt: string;
  readonly stop: GdbStopReply;
  readonly breakpoint?: BreakpointRecord;
  readonly registers: Arm9RegisterContext;
  readonly pcWindow: StopContextMemoryRegion;
  readonly stackWindow: StopContextMemoryRegion;
  readonly additionalRegions: readonly LabeledStopContextMemoryRegion[];
}

const ADDRESS_SPACE_END = 0x1_0000_0000;
const PC_WINDOW_BYTES = 64;
const STACK_WINDOW_BYTES = 64;
const MAX_ADDITIONAL_REGIONS = 8;

function validateTimeout(timeoutMs: number): void {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
    throw new Error("Stop-context timeout must be from 1 through 30000 ms");
  }
}

function validateOutputLimit(maxOutputBytes: number): void {
  if (!Number.isSafeInteger(maxOutputBytes) || maxOutputBytes < 1) {
    throw new Error("Stop-context output limit must be a positive integer");
  }
}

function validateAdditionalRegions(regions: readonly StopContextRegionRequest[]): void {
  if (regions.length > MAX_ADDITIONAL_REGIONS) {
    throw new Error(`Stop context may contain at most ${MAX_ADDITIONAL_REGIONS} additional memory regions`);
  }

  const labels = new Set<string>();
  for (const region of regions) {
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(region.label)) {
      throw new Error(`Invalid stop-context region label: ${region.label}`);
    }
    if (labels.has(region.label)) {
      throw new Error(`Duplicate stop-context region label: ${region.label}`);
    }
    labels.add(region.label);
    validateMemoryRead(region.address, region.length);
  }
}

function pcWindow(pc: number): { address: number; length: number } {
  const address = Math.max(0, pc - PC_WINDOW_BYTES / 2);
  const end = Math.min(ADDRESS_SPACE_END, pc + PC_WINDOW_BYTES / 2);
  return { address, length: end - address };
}

function stackWindow(sp: number): { address: number; length: number } {
  const end = Math.min(ADDRESS_SPACE_END, sp + STACK_WINDOW_BYTES);
  return { address: sp, length: end - sp };
}

async function readMemory(
  session: Pick<GdbSession, "sendStoppedCommand">,
  label: string,
  address: number,
  length: number,
  timeoutMs: number,
): Promise<StopContextMemoryRegion> {
  validateMemoryRead(address, length);
  const reply = await session.sendStoppedCommand(
    `m${address.toString(16)},${length.toString(16)}`,
    timeoutMs,
  );
  if (reply.startsWith("E")) {
    throw new Error(`GDB memory read failed for ${label}: ${reply}`);
  }
  if (!/^[0-9a-fA-F]*$/.test(reply)) {
    throw new Error(`GDB memory read for ${label} returned non-hexadecimal data`);
  }
  const returnedBytes = reply.length / 2;
  if (reply.length !== length * 2) {
    throw new Error(`${label} returned ${returnedBytes} byte${returnedBytes === 1 ? "" : "s"}; expected ${length}`);
  }
  return { address, length, dataHex: reply };
}

export async function captureStopContext(
  input: CaptureStopContextInput,
): Promise<StopContext> {
  validateTimeout(input.timeoutMs);
  validateOutputLimit(input.maxOutputBytes);
  const additional = input.additionalRegions ?? [];
  validateAdditionalRegions(additional);

  const registers = input.registers ?? decodeArm9RegisterPacket(
    await input.session.sendStoppedCommand("g", input.timeoutMs),
  );

  const pc = pcWindow(registers.pc);
  const stack = stackWindow(registers.sp);
  const pcRegion = await readMemory(
    input.session,
    "PC window",
    pc.address,
    pc.length,
    input.timeoutMs,
  );
  const stackRegion = await readMemory(
    input.session,
    "stack window",
    stack.address,
    stack.length,
    input.timeoutMs,
  );

  const additionalRegions: LabeledStopContextMemoryRegion[] = [];
  for (const region of additional) {
    const captured = await readMemory(
      input.session,
      region.label,
      region.address,
      region.length,
      input.timeoutMs,
    );
    additionalRegions.push({ label: region.label, ...captured });
  }

  const context: StopContext = {
    capturedAt: new Date().toISOString(),
    stop: input.stop,
    ...(input.breakpoint === undefined ? {} : { breakpoint: input.breakpoint }),
    registers,
    pcWindow: pcRegion,
    stackWindow: stackRegion,
    additionalRegions,
  };
  if (Buffer.byteLength(JSON.stringify(context), "utf8") > input.maxOutputBytes) {
    throw new Error("Stop context exceeds configured output limit");
  }
  return context;
}
