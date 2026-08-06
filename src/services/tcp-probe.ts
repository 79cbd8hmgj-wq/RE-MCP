import net from "node:net";

export interface TcpProbeResult {
  readonly host: string;
  readonly port: number;
  readonly reachable: boolean;
  readonly elapsedMs: number;
  readonly error: string | null;
}

export async function probeTcpPort(
  host: string,
  port: number,
  timeoutMs: number,
): Promise<TcpProbeResult> {
  const started = Date.now();
  return await new Promise<TcpProbeResult>((resolve) => {
    const socket = net.createConnection({ host, port });
    let settled = false;

    const finish = (reachable: boolean, error: string | null): void => {
      if (settled) {
        return;
      }
      settled = true;
      socket.destroy();
      resolve({
        host,
        port,
        reachable,
        elapsedMs: Date.now() - started,
        error,
      });
    };

    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true, null));
    socket.once("timeout", () => finish(false, "timeout"));
    socket.once("error", (error) => finish(false, error.message));
  });
}

export async function waitForTcpPort(
  host: string,
  port: number,
  timeoutMs: number,
  intervalMs = 100,
): Promise<TcpProbeResult> {
  const deadline = Date.now() + timeoutMs;
  let last = await probeTcpPort(host, port, Math.min(intervalMs, timeoutMs));
  while (!last.reachable && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
    const remaining = Math.max(1, deadline - Date.now());
    last = await probeTcpPort(host, port, Math.min(intervalMs, remaining));
  }
  return last;
}
