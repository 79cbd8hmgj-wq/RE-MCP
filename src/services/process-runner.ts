import { spawn } from "node:child_process";

export interface RunRequest {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd: string;
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
}

export interface RunResult {
  readonly exitCode: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly timedOut: boolean;
  readonly outputTruncated: boolean;
}

type AnyBuffer = Buffer<ArrayBufferLike>;

export async function runProcess(request: RunRequest): Promise<RunResult> {
  return await new Promise<RunResult>((resolve, reject) => {
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

    let stdout: AnyBuffer = Buffer.alloc(0);
    let stderr: AnyBuffer = Buffer.alloc(0);
    let outputTruncated = false;
    let timedOut = false;

    const append = (current: AnyBuffer, chunk: AnyBuffer): AnyBuffer => {
      if (current.length >= request.maxOutputBytes) {
        outputTruncated = true;
        return current;
      }
      const remaining = request.maxOutputBytes - current.length;
      if (chunk.length > remaining) {
        outputTruncated = true;
      }
      return Buffer.concat([current, chunk.subarray(0, remaining)]);
    };

    child.stdout.on("data", (chunk: AnyBuffer) => {
      stdout = append(stdout, chunk);
    });
    child.stderr.on("data", (chunk: AnyBuffer) => {
      stderr = append(stderr, chunk);
    });
    child.on("error", reject);

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => child.kill("SIGKILL"), 2_000).unref();
    }, request.timeoutMs);
    timer.unref();

    child.on("close", (exitCode, signal) => {
      clearTimeout(timer);
      resolve({
        exitCode,
        signal,
        stdout: stdout.toString("utf8"),
        stderr: stderr.toString("utf8"),
        timedOut,
        outputTruncated,
      });
    });
  });
}
