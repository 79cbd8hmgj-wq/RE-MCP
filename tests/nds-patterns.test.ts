import assert from "node:assert/strict";
import test from "node:test";

import { NdsError, type AnyNdsErrorCategory } from "../src/services/nds/errors.js";
import { compileNdsPattern } from "../src/services/nds/patterns.js";

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

test("AnyNdsErrorCategory includes pattern-search categories", () => {
  const category: AnyNdsErrorCategory = "invalid-pattern";
  assert.equal(category, "invalid-pattern");
});

test("compiles exact and wildcard byte signatures", () => {
  const compiled = compileNdsPattern({
    kind: "byte-signature",
    signature: "12 34 ?? 78",
  });
  assert.equal(hex(compiled.bytes), "12340078");
  assert.equal(hex(compiled.mask), "ffff00ff");
  assert.equal(compiled.alignment, 1);
});

test("rejects malformed and non-identifying byte signatures", () => {
  for (const signature of ["", "12 GG", "A? 12", "??", "?? ??"] as const) {
    assert.throws(
      () => compileNdsPattern({ kind: "byte-signature", signature }),
      (error) => error instanceof NdsError && error.category === "invalid-pattern",
    );
  }
});

test("encodes integer width, endian, signedness, and alignment exactly", () => {
  assert.equal(hex(compileNdsPattern({
    kind: "integer",
    value: 0x1234,
    width: 16,
    endian: "little",
    signed: false,
  }).bytes), "3412");
  assert.equal(hex(compileNdsPattern({
    kind: "integer",
    value: 0x1234,
    width: 16,
    endian: "big",
    signed: false,
  }).bytes), "1234");
  const signed = compileNdsPattern({
    kind: "integer",
    value: -1,
    width: 32,
    endian: "little",
    signed: true,
    alignment: 4,
  });
  assert.equal(hex(signed.bytes), "ffffffff");
  assert.equal(signed.alignment, 4);
  assert.equal(compileNdsPattern({
    kind: "integer",
    value: 1,
    width: 32,
    endian: "little",
    signed: false,
  }).alignment, 1);
});

test("rejects integer values outside requested range", () => {
  for (const pattern of [
    { kind: "integer", value: 256, width: 8, endian: "little", signed: false },
    { kind: "integer", value: -129, width: 8, endian: "little", signed: true },
  ] as const) {
    assert.throws(
      () => compileNdsPattern(pattern),
      (error) => error instanceof NdsError && error.category === "invalid-pattern",
    );
  }
});

test("encodes ASCII and UTF-16LE exactly without terminators", () => {
  assert.equal(hex(compileNdsPattern({ kind: "ascii", text: "Ab" }).bytes), "4162");
  assert.equal(hex(compileNdsPattern({ kind: "utf16le", text: "AΩ" }).bytes), "4100a903");
  assert.throws(
    () => compileNdsPattern({ kind: "ascii", text: "Ω" }),
    (error) => error instanceof NdsError && error.category === "invalid-pattern",
  );
  assert.throws(
    () => compileNdsPattern({ kind: "utf16le", text: "" }),
    (error) => error instanceof NdsError && error.category === "invalid-pattern",
  );
});

test("enforces 4096 encoded-byte maximum", () => {
  assert.equal(
    compileNdsPattern({ kind: "ascii", text: "A".repeat(4096) }).bytes.length,
    4096,
  );
  assert.throws(
    () => compileNdsPattern({ kind: "ascii", text: "A".repeat(4097) }),
    (error) => error instanceof NdsError && error.category === "invalid-pattern",
  );
});