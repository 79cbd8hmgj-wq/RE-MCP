import {
  spawn,
  type ChildProcessByStdio,
} from "node:child_process";
import type { Readable } from "node:stream";

export interface OwnedProcessStart {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly maxOutputBytes: number;
  readonly metadata: Readonly<Record<string, string | number | boolean>>;
}

export interface OwnedProcessStatus {
  readonly running: boolean;
  readonly pid: number | null;
  readonly startedAt: string | null;
  readonly executable: string | null;
  readonly args: readonly string[];
  readonly metadata: Readonly<Record<string, string | number | boolean>>;
  readonly stdout: string;
  readonly stderr: string;
  readonly outputTruncated: boolean;
  readonly lastExitCode: number | null;
  readonly lastSignal: NodeJS.Signals | null;
}

type OwnedChild = ChildProcessByStdio<null, Readable, Readable>;

interface ActiveProcess {
  readonly child: OwnedChild;
  readonly startedAt: string;
  readonly executable: string;
  readonly args: readonly string[];
  readonly metadata: Readonly<Record<string, string | number | boolean>>;
  readonly maxOutputBytes: number;
  stdout: Buffer<ArrayBufferLike>;
  stderr: Buffer<ArrayBufferLike>;
  outputTruncated: boolean;
}

export class OwnedProcessManager {
  private active: ActiveProcess | null = null;
  private lastExitCode: number | null = null;
  private lastSignal: NodeJS.Signals | null = null;

  async start(request: OwnedProcessStart): Promise<OwnedProcessStatus> {
    if (this.active !== null) {
      throw new Error("An owned process is already running");
    }

    const child = spawn(request.executable, [...request.args], {
      cwd: request.cwd,
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        LANG: "C.UTF-8",
        LC_ALL: "C.UTF-8",
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const active: ActiveProcess = {
      child,
      startedAt: new Date().toISOString(),
      executable: request.executable,
      args: [...request.args],
      metadata: { ...request.metadata },
      maxOutputBytes: request.maxOutputBytes,
      stdout: Buffer.alloc(0),
      stderr: Buffer.alloc(0),
      outputTruncated: false,
    };
    this.active = active;
    this.lastExitCode = null;
    this.lastSignal = null;

    const append = (
      current: Buffer<ArrayBufferLike>,
      chunk: Buffer<ArrayBufferLike>,
    ): Buffer<ArrayBufferLike> => {
      if (current.length >= active.maxOutputBytes) {
        active.outputTruncated = true;
        return current;
      }
      const remaining = active.maxOutputBytes - current.length;
      if (chunk.length > remaining) {
        active.outputTruncated = true;
      }
      return Buffer.concat([current, chunk.subarray(0, remaining)]);
    };

    child.stdout.on("data", (chunk: Buffer<ArrayBufferLike>) => {
      active.stdout = append(active.stdout, chunk);
    });
    child.stderr.on("data", (chunk: Buffer<ArrayBufferLike>) => {
      active.stderr = append(active.stderr, chunk);
    });

    child.once("close", (code, signal) => {
      if (this.active === active) {
        this.lastExitCode = code;
        this.lastSignal = signal;
        this.active = null;
      }
    });

    try {
      await new Promise<void>((resolve, reject) => {
        child.once("spawn", resolve);
        child.once("error", reject);
      });
    } catch (error) {
      if (this.active === active) {
        this.active = null;
      }
      throw error;
    }

    return this.status();
  }

  status(): OwnedProcessStatus {
    const active = this.active;
    return {
      running: active !== null,
      pid: active?.child.pid ?? null,
      startedAt: active?.startedAt ?? null,
      executable: active?.executable ?? null,
      args: active?.args ?? [],
      metadata: active?.metadata ?? {},
      stdout: active?.stdout.toString("utf8") ?? "",
      stderr: active?.stderr.toString("utf8") ?? "",
      outputTruncated: active?.outputTruncated ?? false,
      lastExitCode: this.lastExitCode,
      lastSignal: this.lastSignal,
    };
  }

  async stop(graceMs = 5_000): Promise<OwnedProcessStatus> {
    const active = this.active;
    if (active === null) {
      return this.status();
    }

    const closed = new Promise<void>((resolve) => {
      active.child.once("close", () => resolve());
    });
    active.child.kill("SIGTERM");

    const timedOut = await Promise.race([
      closed.then(() => false),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(true), graceMs)),
    ]);
    if (timedOut && this.active === active) {
      active.child.kill("SIGKILL");
      await closed;
    }
    return this.status();
  }
}
