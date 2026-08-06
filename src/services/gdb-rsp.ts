import net from "node:net";

export function rspChecksum(payload: string): string {
  let sum = 0;
  for (const byte of Buffer.from(payload, "ascii")) {
    sum = (sum + byte) & 0xff;
  }
  return sum.toString(16).padStart(2, "0");
}

export function encodeRspPacket(payload: string): string {
  return `$${payload}#${rspChecksum(payload)}`;
}

export interface ParsedRspPacket {
  readonly payload: string;
  readonly raw: string;
  readonly consumed: number;
}

export function parseRspPacket(buffer: string): ParsedRspPacket | null {
  const start = buffer.indexOf("$");
  if (start < 0) return null;

  const marker = buffer.indexOf("#", start + 1);
  if (marker < 0 || buffer.length < marker + 3) return null;

  const payload = buffer.slice(start + 1, marker);
  const expected = buffer.slice(marker + 1, marker + 3).toLowerCase();
  if (!/^[0-9a-f]{2}$/.test(expected) || rspChecksum(payload) !== expected) {
    throw new Error("GDB RSP reply checksum mismatch");
  }

  const end = marker + 3;
  return {
    payload,
    raw: buffer.slice(start, end),
    consumed: end,
  };
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

      let packet: ParsedRspPacket | null;
      try {
        packet = parseRspPacket(buffer);
      } catch (error) {
        finishError(error instanceof Error ? error : new Error(String(error)));
        return;
      }
      if (packet === null) return;

      settled = true;
      socket.write("+", "ascii", () => socket.end());
      resolve({ payload: packet.payload, raw: buffer.slice(0, packet.consumed) });
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
