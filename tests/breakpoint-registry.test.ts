import assert from "node:assert/strict";
import test from "node:test";

import { BreakpointRegistry } from "../src/services/breakpoint-registry.js";
import type { ExecutableRangeRecord } from "../src/services/executable-ranges.js";

const range: ExecutableRangeRecord = {
  id: "arm9-main",
  label: "ARM9 main",
  start: 0x02000000,
  end: 0x02010000,
  source: "arm9-header",
  symbolModes: {},
};

function add(registry: BreakpointRegistry, address = 0x02000000) {
  return registry.add({
    address,
    requestedMode: "arm",
    resolvedMode: "arm",
    kind: 4,
    range,
  });
}

test("assigns deterministic IDs and preserves insertion order", () => {
  const registry = new BreakpointRegistry();
  const first = add(registry, 0x02000000);
  const second = add(registry, 0x02000004);
  assert.equal(first.id, "bp-1");
  assert.equal(second.id, "bp-2");
  assert.deepEqual(registry.list().map((record) => record.id), ["bp-1", "bp-2"]);
});

test("tracks installation and breakpoint hits", () => {
  const registry = new BreakpointRegistry();
  const record = add(registry);
  assert.equal(record.enabled, false);
  registry.markInstalled(record.id);
  const hit = registry.recordHit(record.address, "arm");
  assert.equal(hit?.hitCount, 1);
  assert.equal(registry.get(record.id).enabled, true);
  registry.markRemoved(record.id);
  assert.equal(registry.get(record.id).enabled, false);
});

test("rejects duplicates and unknown removals", () => {
  const registry = new BreakpointRegistry();
  add(registry);
  assert.throws(() => add(registry), /Duplicate breakpoint/);
  assert.throws(() => registry.remove("bp-999"), /Unknown breakpoint ID/);
});

test("caps active breakpoints at 32", () => {
  const registry = new BreakpointRegistry();
  for (let index = 0; index < 32; index += 1) {
    add(registry, 0x02000000 + index * 4);
  }
  assert.equal(registry.maximum(), 32);
  assert.throws(() => add(registry, 0x02000100), /At most 32/);
});

test("remove and clear reset registry state", () => {
  const registry = new BreakpointRegistry();
  const record = add(registry);
  assert.equal(registry.remove(record.id).id, record.id);
  assert.equal(registry.list().length, 0);
  add(registry);
  registry.clear();
  assert.equal(registry.list().length, 0);
  assert.equal(add(registry).id, "bp-1");
});
