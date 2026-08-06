export type GdbStopReply =
  | {
      readonly kind: "signal";
      readonly signal: number;
      readonly fields: Readonly<Record<string, string>>;
      readonly raw: string;
    }
  | { readonly kind: "exited"; readonly status: number; readonly raw: string }
  | { readonly kind: "terminated"; readonly signal: number; readonly raw: string };

function parseHexByte(value: string, label: string): number {
  if (!/^[0-9a-fA-F]{2}$/.test(value)) {
    throw new Error(`Malformed ${label} byte: ${value}`);
  }
  return Number.parseInt(value, 16);
}

function parseFields(value: string): Readonly<Record<string, string>> {
  const fields: Record<string, string> = {};
  if (value.length === 0) return fields;

  for (const segment of value.split(";")) {
    if (segment.length === 0) continue;
    const separator = segment.indexOf(":");
    if (separator <= 0 || separator === segment.length - 1) {
      throw new Error(`Malformed GDB stop field: ${segment}`);
    }
    fields[segment.slice(0, separator)] = segment.slice(separator + 1);
  }
  return fields;
}

export function parseGdbStopReply(payload: string): GdbStopReply {
  if (payload.length < 3) {
    throw new Error(`Unsupported GDB stop reply: ${payload}`);
  }

  const prefix = payload[0];
  const value = parseHexByte(payload.slice(1, 3), "GDB stop");

  if (prefix === "S") {
    if (payload.length !== 3) {
      throw new Error(`Unsupported GDB stop reply: ${payload}`);
    }
    return { kind: "signal", signal: value, fields: {}, raw: payload };
  }
  if (prefix === "T") {
    return {
      kind: "signal",
      signal: value,
      fields: parseFields(payload.slice(3)),
      raw: payload,
    };
  }
  if (prefix === "W") {
    if (payload.length !== 3) {
      throw new Error(`Unsupported GDB stop reply: ${payload}`);
    }
    return { kind: "exited", status: value, raw: payload };
  }
  if (prefix === "X") {
    if (payload.length !== 3) {
      throw new Error(`Unsupported GDB stop reply: ${payload}`);
    }
    return { kind: "terminated", signal: value, raw: payload };
  }

  throw new Error(`Unsupported GDB stop reply: ${payload}`);
}
