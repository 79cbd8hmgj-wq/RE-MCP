import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { FileHandle } from "node:fs/promises";

import { NdsError } from "./errors.js";

export async function hashFileSha256(filePath: string): Promise<string> {
  const hash = createHash("sha256");
  const stream = createReadStream(filePath);
  for await (const chunk of stream) {
    hash.update(chunk);
  }
  return hash.digest("hex");
}

export async function readExact(
  handle: FileHandle,
  offset: number,
  length: number,
  label: string,
): Promise<Buffer> {
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 0) {
    throw new NdsError("range-out-of-bounds", `${label} requested an invalid file range`);
  }

  const buffer = Buffer.alloc(length);
  let total = 0;
  while (total < length) {
    const { bytesRead } = await handle.read(buffer, total, length - total, offset + total);
    if (bytesRead === 0) {
      throw new NdsError("range-out-of-bounds", `${label} extends beyond the ROM file`);
    }
    total += bytesRead;
  }
  return buffer;
}
