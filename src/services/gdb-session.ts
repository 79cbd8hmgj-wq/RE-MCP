import net from "node:net";

import { encodeRspPacket, parseRspPacket } from "./gdb-rsp.js";
import { parseGdbStopReply, type GdbStopReply } from "./gdb-stop.js";

export type DebuggerState = "unavailable" | "stopped" | "running" | "waiting";

export type ExecutionResult =
  | {
      readonly kind: "stop";
      readonly stop: GdbStopReply;
      readonly state: "stopped" | "unavailable";
    }
  | {
      readonly kind: "timeout";
      readonly state: "running";
    };

export interface StepSequenceResult {
  readonly requested: number;
  readonly completed: number;
  readonly completedAll: boolean;
  readonly result: ExecutionResult;
}

export interface GdbSessionOptions {
  readonly host: "127.0.0.1";
  readonly port: number;
  readonly maxReplyBytes: number;
  readonly connectTimeoutMs: number;
}

interface PendingReply {
  readonly resolve: (payload: string) => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
}

class ExecutionWaitTimeoutError extends Error {}

export class GdbSession {
  readonly #options: GdbSessionOptions;
  #socket: net.Socket | null = null;
  #state: DebuggerState = "unavailable";
  #buffer = "";
  #pending: PendingReply | null = null;
  #queuedStop: GdbStopReply | null = null;
  #queue: Promise<void> = Promise.resolve();

  constructor(options: GdbSessionOptions) {
    if (options.host !== "127.0.0.1") {
      throw new Error("GDB sessions are restricted to 127.0.0.1");
    }
    if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) {
      throw new Error("GDB session port must be from 1 through 65535");
    }
    if (!Number.isInteger(options.maxReplyBytes) || options.maxReplyBytes < 64) {
      throw new Error("GDB reply limit must be at least 64 bytes");
    }
    if (!Number.isInteger(options.connectTimeoutMs) || options.connectTimeoutMs < 1) {
      throw new Error("GDB connection timeout must be positive");
    }
    this.#options = options;
  }

  state(): DebuggerState {
    return this.#state;
  }

  async connect(): Promise<void> {
    if (this.#socket !== null && !this.#socket.destroyed) return;

    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({
        host: this.#options.host,
        port: this.#options.port,
      });
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(new Error("GDB RSP connection timed out"));
      }, this.#options.connectTimeoutMs);

      socket.once("connect", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.#socket = socket;
        this.#state = "stopped";
        resolve();
      });
      socket.on("data", (chunk: Buffer) => this.#handleData(chunk));
      socket.on("error", (error) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(error);
        }
        this.#failPending(error);
        this.#state = "unavailable";
      });
      socket.on("close", () => {
        this.#failPending(new Error("GDB RSP connection closed"));
        this.#socket = null;
        this.#state = "unavailable";
      });
    });
  }

  async close(): Promise<void> {
    const socket = this.#socket;
    this.#socket = null;
    this.#buffer = "";
    this.#queuedStop = null;
    this.#state = "unavailable";
    this.#failPending(new Error("GDB RSP session closed"));
    if (socket === null || socket.destroyed) return;
    await new Promise<void>((resolve) => {
      socket.once("close", resolve);
      socket.end();
    });
  }

  reset(reason: string): void {
    const socket = this.#socket;
    this.#socket = null;
    this.#buffer = "";
    this.#queuedStop = null;
    this.#state = "unavailable";
    this.#failPending(new Error(`GDB RSP session reset: ${reason}`));
    socket?.destroy();
  }

  async sendStoppedCommand(payload: string, timeoutMs: number): Promise<string> {
    if (payload.length === 0) throw new Error("GDB command must not be empty");
    this.#validateTimeout(timeoutMs, "GDB command timeout");

    return await this.#runExclusive(async () => {
      await this.connect();
      if (this.#state !== "stopped") {
        throw new Error(`GDB command requires stopped state; current state is ${this.#state}`);
      }
      const socket = this.#requireSocket();
      const reply = this.#waitForPacket(timeoutMs, false);
      socket.write(encodeRspPacket(payload), "ascii");
      return await reply;
    });
  }

  async insertSoftwareBreakpoint(
    address: number,
    kind: 2 | 4,
    timeoutMs: number,
  ): Promise<void> {
    await this.#softwareBreakpoint("insert", "Z", address, kind, timeoutMs);
  }

  async removeSoftwareBreakpoint(
    address: number,
    kind: 2 | 4,
    timeoutMs: number,
  ): Promise<void> {
    await this.#softwareBreakpoint("remove", "z", address, kind, timeoutMs);
  }

  async continueExecution(timeoutMs: number): Promise<ExecutionResult> {
    this.#validateTimeout(timeoutMs, "GDB continue timeout");
    return await this.#runExclusive(async () => {
      await this.connect();
      if (this.#state !== "stopped") {
        throw new Error(`GDB continue requires stopped state; current state is ${this.#state}`);
      }
      this.#queuedStop = null;
      const socket = this.#requireSocket();
      this.#state = "waiting";
      const reply = this.#waitForPacket(timeoutMs, true);
      socket.write(encodeRspPacket("c"), "ascii");
      return await this.#finishExecutionWait(reply);
    });
  }

  async waitForStop(timeoutMs: number): Promise<ExecutionResult> {
    this.#validateTimeout(timeoutMs, "GDB wait timeout");
    return await this.#runExclusive(async () => {
      if (this.#queuedStop !== null) {
        const stop = this.#queuedStop;
        this.#queuedStop = null;
        return this.#executionStopResult(stop);
      }
      if (this.#state !== "running") {
        throw new Error(`GDB wait requires running state; current state is ${this.#state}`);
      }
      this.#requireSocket();
      this.#state = "waiting";
      return await this.#finishExecutionWait(this.#waitForPacket(timeoutMs, true));
    });
  }

  async interruptAndWait(timeoutMs: number): Promise<ExecutionResult> {
    this.#validateTimeout(timeoutMs, "GDB interrupt timeout");
    return await this.#runExclusive(async () => {
      if (this.#state !== "running") {
        throw new Error(`GDB interrupt requires running state; current state is ${this.#state}`);
      }
      const socket = this.#requireSocket();
      this.#state = "waiting";
      const reply = this.#waitForPacket(timeoutMs, true);
      socket.write(Buffer.from([0x03]));
      return await this.#finishExecutionWait(reply);
    });
  }

  async stepInstructions(
    count: number,
    perStepTimeoutMs: number,
  ): Promise<StepSequenceResult> {
    if (!Number.isInteger(count) || count < 1 || count > 100) {
      throw new Error("GDB single-step count must be from 1 through 100");
    }
    this.#validateTimeout(perStepTimeoutMs, "GDB single-step timeout");

    return await this.#runExclusive(async () => {
      await this.connect();
      if (this.#state !== "stopped") {
        throw new Error(`GDB single-step requires stopped state; current state is ${this.#state}`);
      }
      this.#queuedStop = null;
      const socket = this.#requireSocket();

      let completed = 0;
      let finalResult: ExecutionResult | null = null;
      for (let index = 0; index < count; index += 1) {
        this.#state = "waiting";
        const reply = this.#waitForPacket(perStepTimeoutMs, true);
        socket.write(encodeRspPacket("s"), "ascii");
        const result = await this.#finishExecutionWait(reply);
        finalResult = result;

        if (result.kind === "timeout") {
          return {
            requested: count,
            completed,
            completedAll: false,
            result,
          };
        }

        completed += 1;
        if (!this.#isNormalSingleStepStop(result.stop)) {
          return {
            requested: count,
            completed,
            completedAll: false,
            result,
          };
        }
      }

      if (finalResult === null) {
        throw new Error("GDB single-step sequence completed without a stop result");
      }
      return {
        requested: count,
        completed,
        completedAll: true,
        result: finalResult,
      };
    });
  }

  async #softwareBreakpoint(
    operation: "insert" | "remove",
    command: "Z" | "z",
    address: number,
    kind: 2 | 4,
    timeoutMs: number,
  ): Promise<void> {
    const reply = await this.sendStoppedCommand(
      `${command}0,${address.toString(16)},${kind}`,
      timeoutMs,
    );
    if (reply === "OK") return;
    if (reply.startsWith("E")) {
      throw new Error(`GDB software breakpoint ${operation} failed: ${reply}`);
    }
    throw new Error(`Unsupported GDB software breakpoint ${operation} reply: ${reply}`);
  }

  #isNormalSingleStepStop(stop: GdbStopReply): boolean {
    if (stop.kind !== "signal" || stop.signal !== 5) return false;
    const reason = stop.fields.reason?.toLowerCase();
    if (reason === "breakpoint" || reason === "swbreak") return false;
    if ("swbreak" in stop.fields) return false;
    return true;
  }

  async #runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.#queue;
    let release!: () => void;
    this.#queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  #validateTimeout(timeoutMs: number, label: string): void {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
      throw new Error(`${label} must be from 1 through 30000 ms`);
    }
  }

  #requireSocket(): net.Socket {
    const socket = this.#socket;
    if (socket === null || socket.destroyed) {
      throw new Error("GDB RSP session is unavailable");
    }
    return socket;
  }

  #waitForPacket(timeoutMs: number, executionWait: boolean): Promise<string> {
    if (this.#pending !== null) {
      throw new Error("A GDB RSP reply is already pending");
    }
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (this.#pending?.timer !== timer) return;
        this.#pending = null;
        reject(
          executionWait
            ? new ExecutionWaitTimeoutError("GDB execution wait timed out")
            : new Error("GDB RSP request timed out"),
        );
      }, timeoutMs);
      this.#pending = { resolve, reject, timer };
    });
  }

  async #finishExecutionWait(reply: Promise<string>): Promise<ExecutionResult> {
    try {
      const payload = await reply;
      let stop: GdbStopReply;
      try {
        stop = parseGdbStopReply(payload);
      } catch (error) {
        const parsedError = error instanceof Error ? error : new Error(String(error));
        this.reset(parsedError.message);
        throw parsedError;
      }
      return this.#executionStopResult(stop);
    } catch (error) {
      if (error instanceof ExecutionWaitTimeoutError) {
        this.#state = "running";
        return { kind: "timeout", state: "running" };
      }
      throw error;
    }
  }

  #executionStopResult(stop: GdbStopReply): ExecutionResult {
    const state = stop.kind === "signal" ? "stopped" : "unavailable";
    this.#state = state;
    return { kind: "stop", stop, state };
  }

  #handleData(chunk: Buffer): void {
    this.#buffer += chunk.toString("ascii");
    if (Buffer.byteLength(this.#buffer, "ascii") > this.#options.maxReplyBytes) {
      const error = new Error("GDB RSP reply exceeded configured limit");
      this.#failPending(error);
      this.reset(error.message);
      return;
    }

    for (;;) {
      let packet;
      try {
        packet = parseRspPacket(this.#buffer);
      } catch (error) {
        const parsedError = error instanceof Error ? error : new Error(String(error));
        this.#failPending(parsedError);
        this.reset(parsedError.message);
        return;
      }
      if (packet === null) return;

      this.#buffer = this.#buffer.slice(packet.consumed);
      this.#socket?.write("+", "ascii");
      const pending = this.#pending;
      if (pending !== null) {
        this.#pending = null;
        clearTimeout(pending.timer);
        pending.resolve(packet.payload);
        continue;
      }

      if (this.#state === "running") {
        try {
          const stop = parseGdbStopReply(packet.payload);
          this.#queuedStop = stop;
          this.#state = stop.kind === "signal" ? "stopped" : "unavailable";
        } catch (error) {
          const parsedError = error instanceof Error ? error : new Error(String(error));
          this.reset(parsedError.message);
          return;
        }
      }
    }
  }

  #failPending(error: Error): void {
    const pending = this.#pending;
    if (pending === null) return;
    this.#pending = null;
    clearTimeout(pending.timer);
    pending.reject(error);
  }
}
