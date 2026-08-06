import net from "node:net";

function checksum(payload: string): string {
  let sum = 0;
  for (const byte of Buffer.from(payload, "ascii")) {
    sum = (sum + byte) & 0xff;
  }
  return sum.toString(16).padStart(2, "0");
}

export function encodeRspPacket(payload: string): string {
  return `$${payload}#${checksum(payload)}`;
}

export interface RspReply {
  readonly payload: string;
  readonly raw: string;
}

export async function sendRspCommand(
  host: string,
  port: number,
  command: string,
  timeoutMs: number,
  maxReplyBytes: number,
): Promise<RspReply> {
  return await new Promise<RspReply>((resolve, reject) => {
    const socket = net.createConnection({ host, port });
    let buffer = "";
    let settled = false;

    const finishError = (error: Error): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };

    socket.setTimeout(timeoutMs);
    socket.once("timeout", () => finishError(new Error("GDB RSP request timed out")));
    socket.once("error", finishError);
    socket.once("connect", () => socket.write(encodeRspPacket(command), "ascii"));
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("ascii");
      if (Buffer.byteLength(buffer, "ascii") > maxReplyBytes) {
        finishError(new Error("GDB RSP reply exceeded configured limit"));
        return;
      }
      const start = buffer.indexOf("$");
      const marker = start >= 0 ? buffer.indexOf("#", start + 1) : -1;
      if (start < 0 || marker < 0 || buffer.length < marker + 3) return;

      const payload = buffer.slice(start + 1, marker);
      const expected = buffer.slice(marker + 1, marker + 3).toLowerCase();
      if (checksum(payload) !== expected) {
        finishError(new Error("GDB RSP reply checksum mismatch"));
        return;
      }
      settled = true;
      socket.write("+", "ascii", () => socket.end());
      resolve({ payload, raw: buffer.slice(0, marker + 3) });
    });
  });
}

export function validateMemoryRead(address: number, length: number): void {
  if (!Number.isSafeInteger(address) || address < 0 || address > 0xffffffff) {
    throw new Error("Address must be an unsigned 32-bit integer");
  }
  if (!Number.isSafeInteger(length) || length < 1 || length > 4096) {
    throw new Error("Memory read length must be from 1 through 4096 bytes");
  }
}
