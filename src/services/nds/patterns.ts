import { NdsError } from "./errors.js";

export type NdsSearchPattern =
  | { readonly kind: "byte-signature"; readonly signature: string }
  | {
      readonly kind: "integer";
      readonly value: number;
      readonly width: 8 | 16 | 32;
      readonly endian: "little" | "big";
      readonly signed: boolean;
      readonly alignment?: 1 | 2 | 4;
    }
  | { readonly kind: "ascii"; readonly text: string }
  | { readonly kind: "utf16le"; readonly text: string };

export interface CompiledNdsPattern {
  readonly bytes: Uint8Array;
  readonly mask: Uint8Array;
  readonly alignment: 1 | 2 | 4;
  readonly sourceKind: NdsSearchPattern["kind"];
}

export const NDS_PATTERN_MAX_BYTES = 4096;

const EXACT_BYTE = /^[0-9a-fA-F]{2}$/u;
const WILDCARD = "??";

function invalidPattern(message: string): never {
  throw new NdsError("invalid-pattern", message);
}

function validateEncodedLength(length: number): void {
  if (length < 1 || length > NDS_PATTERN_MAX_BYTES) {
    invalidPattern(`Encoded pattern length must be between 1 and ${NDS_PATTERN_MAX_BYTES} bytes`);
  }
}

function exactMask(length: number): Uint8Array {
  const mask = new Uint8Array(length);
  mask.fill(0xff);
  return mask;
}

function compileByteSignature(signature: string): CompiledNdsPattern {
  const trimmed = signature.trim();
  if (trimmed.length === 0) {
    invalidPattern("Byte signature must contain at least one token");
  }

  const tokens = trimmed.split(/\s+/u);
  validateEncodedLength(tokens.length);
  const bytes = new Uint8Array(tokens.length);
  const mask = new Uint8Array(tokens.length);
  let exactCount = 0;

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]!;
    if (token === WILDCARD) {
      bytes[index] = 0;
      mask[index] = 0;
      continue;
    }
    if (!EXACT_BYTE.test(token)) {
      invalidPattern(`Invalid byte-signature token: ${token}`);
    }
    bytes[index] = Number.parseInt(token, 16);
    mask[index] = 0xff;
    exactCount += 1;
  }

  if (exactCount === 0) {
    invalidPattern("Byte signature must contain at least one exact byte");
  }

  return {
    bytes,
    mask,
    alignment: 1,
    sourceKind: "byte-signature",
  };
}

function integerBounds(
  width: 8 | 16 | 32,
  signed: boolean,
): readonly [bigint, bigint] {
  const bits = BigInt(width);
  return signed
    ? [-(1n << (bits - 1n)), (1n << (bits - 1n)) - 1n]
    : [0n, (1n << bits) - 1n];
}

function compileInteger(
  pattern: Extract<NdsSearchPattern, { readonly kind: "integer" }>,
): CompiledNdsPattern {
  if (!Number.isSafeInteger(pattern.value)) {
    invalidPattern("Integer pattern value must be a safe integer");
  }

  const value = BigInt(pattern.value);
  const [minimum, maximum] = integerBounds(pattern.width, pattern.signed);
  if (value < minimum || value > maximum) {
    invalidPattern(
      `Integer value does not fit ${pattern.signed ? "signed" : "unsigned"} ${pattern.width}-bit range`,
    );
  }

  const byteLength = pattern.width / 8;
  const modulus = 1n << BigInt(pattern.width);
  let encoded = value < 0n ? modulus + value : value;
  const bytes = new Uint8Array(byteLength);

  for (let index = 0; index < byteLength; index += 1) {
    const byte = Number(encoded & 0xffn);
    const targetIndex = pattern.endian === "little"
      ? index
      : byteLength - 1 - index;
    bytes[targetIndex] = byte;
    encoded >>= 8n;
  }

  return {
    bytes,
    mask: exactMask(byteLength),
    alignment: pattern.alignment ?? 1,
    sourceKind: "integer",
  };
}

function compileAscii(text: string): CompiledNdsPattern {
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) > 0x7f) {
      invalidPattern("ASCII pattern contains a non-ASCII character");
    }
  }
  const encoded = Buffer.from(text, "ascii");
  validateEncodedLength(encoded.length);
  const bytes = Uint8Array.from(encoded);
  return {
    bytes,
    mask: exactMask(bytes.length),
    alignment: 1,
    sourceKind: "ascii",
  };
}

function compileUtf16Le(text: string): CompiledNdsPattern {
  const encoded = Buffer.from(text, "utf16le");
  validateEncodedLength(encoded.length);
  const bytes = Uint8Array.from(encoded);
  return {
    bytes,
    mask: exactMask(bytes.length),
    alignment: 1,
    sourceKind: "utf16le",
  };
}

export function compileNdsPattern(pattern: NdsSearchPattern): CompiledNdsPattern {
  switch (pattern.kind) {
    case "byte-signature":
      return compileByteSignature(pattern.signature);
    case "integer":
      return compileInteger(pattern);
    case "ascii":
      return compileAscii(pattern.text);
    case "utf16le":
      return compileUtf16Le(pattern.text);
  }
}
