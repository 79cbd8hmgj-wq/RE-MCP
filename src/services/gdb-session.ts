import net from "node:net";

import { encodeRspPacket, parseRspPacket } from "./gdb-rsp.js";

export type DebuggerState = "unavailable" | "stopped" | "running" | "waiting";

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

export class GdbSession {
  readonly #options: GdbSessionOptions;
  #socket: net.Socket | null = null;
  #state: DebuggerState = "unavailable";
  #buffer = "";
  #pending: PendingReply | null = null;
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
    this.#state = "unavailable";
    this.#failPending(new Error(`GDB RSP session reset: ${reason}`));
    socket?.destroy();
  }

  async sendStoppedCommand(payload: string, timeoutMs: number): Promise<string> {
    if (payload.length === 0) throw new Error("GDB command must not be empty");
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
      throw new Error("GDB command timeout must be from 1 through 30000 ms");
    }

    let result = "";
    let failure: unknown;
    const previous = this.#queue;
    let release!: () => void;
    this.#queue = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;

    try {
      await this.connect();
      if (this.#state !== "stopped") {
        throw new Error(`GDB command requires stopped state; current state is ${this.#state}`);
      }
      const socket = this.#socket;
      if (socket === null || socket.destroyed) {
        throw new Error("GDB RSP session is unavailable");
      }
      result = await new Promise<string>((resolve, reject) => {
        const timer = setTimeout(() => {
          if (this.#pending?.timer !== timer) return;
          this.#pending = null;
          reject(new Error("GDB RSP request timed out"));
        }, timeoutMs);
        this.#pending = { resolve, reject, timer };
        socket.write(encodeRspPacket(payload), "ascii");
      });
    } catch (error) {
      failure = error;
    } finally {
      release();
    }

    if (failure !== undefined) throw failure;
    return result;
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

  #handleData(chunk: Buffer): void {
    this.#buffer += chunk.toString("ascii");
    if (Buffer.byteLength(this.#buffer, "ascii") > this.#options.maxReplyBytes) {
      const error = new Error("GDB RSP reply exceeded configured limit");
      this.#failPending(error);
      this.reset(error.message);
      return;
    }

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
    if (pending === null) return;
    this.#pending = null;
    clearTimeout(pending.timer);
    pending.resolve(packet.payload);
  }

  #failPending(error: Error): void {
    const pending = this.#pending;
    if (pending === null) return;
    this.#pending = null;
    clearTimeout(pending.timer);
    pending.reject(error);
  }
}
