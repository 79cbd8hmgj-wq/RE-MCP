import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import { DebugController } from "../src/services/debug-controller.js";
import { encodeRspPacket, parseRspPacket } from "../src/services/gdb-rsp.js";
import { GdbSession } from "../src/services/gdb-session.js";
import type { Arm9ExecutableRange } from "../src/services/nds-arm9.js";

const ARM9_RANGE: Arm9ExecutableRange = {
  start: 0x02000000,
  end: 0x02001000,
  size: 0x1000,
  source: "arm9-header",
  label: "ARM9 main",
};

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected TCP address");
  return address.port;
}

async function close(server: net.Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function sessionFactory(ports: Readonly<Record<string, number>>) {
  return (identity: string): GdbSession => {
    const port = ports[identity];
    if (port === undefined) throw new Error(`Unknown test identity: ${identity}`);
    return new GdbSession({
      host: "127.0.0.1",
      port,
      maxReplyBytes: 4096,
      connectTimeoutMs: 1000,
    });
  };
}

function queuedRspServer(
  replies: readonly (string | null)[],
  received: string[],
  onSocketClose?: () => void,
): net.Server {
  const remaining = [...replies];
  return net.createServer((socket) => {
    let buffer = "";
    socket.on("close", () => onSocketClose?.());
    socket.on("data", (chunk) => {
      buffer += chunk.toString("ascii");
      for (;;) {
        const parsed = parseRspPacket(buffer);
        if (parsed === null) return;
        buffer = buffer.slice(parsed.consumed);
        received.push(parsed.payload);
        const reply = remaining.shift();
        if (reply === undefined) throw new Error("Unexpected GDB command");
        socket.write("+", "ascii");
        if (reply !== null) socket.write(encodeRspPacket(reply), "ascii");
      }
    });
  });
}

test("controller installs and removes a validated software breakpoint", async () => {
  const received: string[] = [];
  const server = queuedRspServer(["OK", "OK"], received);
  const port = await listen(server);
  const controller = new DebugController(sessionFactory({ first: port }));

  try {
    controller.initialize("first", ARM9_RANGE);
    const added = await controller.addBreakpoint({
      address: 0x02000000,
      mode: "arm",
      timeoutMs: 1000,
    });
    assert.equal(added.id, "bp-1");
    assert.equal(added.enabled, true);
    assert.equal(added.kind, 4);

    const removed = await controller.removeBreakpoint(added.id, 1000);
    assert.equal(removed.id, added.id);
    assert.equal(removed.enabled, false);
    assert.deepEqual(received, ["Z0,2000000,4", "z0,2000000,4"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("failed breakpoint installation rolls registry state back", async () => {
  const received: string[] = [];
  const server = queuedRspServer(["E01", "OK"], received);
  const port = await listen(server);
  const controller = new DebugController(sessionFactory({ first: port }));

  try {
    controller.initialize("first", ARM9_RANGE);
    const request = {
      address: 0x02000000,
      mode: "arm" as const,
      timeoutMs: 1000,
    };
    await assert.rejects(
      controller.addBreakpoint(request),
      /GDB software breakpoint insert failed: E01/,
    );

    const retry = await controller.addBreakpoint(request);
    assert.equal(retry.enabled, true);
    assert.deepEqual(received, ["Z0,2000000,4", "Z0,2000000,4"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("failed breakpoint removal preserves the registered breakpoint", async () => {
  const received: string[] = [];
  const server = queuedRspServer(["OK", "E02", "OK"], received);
  const port = await listen(server);
  const controller = new DebugController(sessionFactory({ first: port }));

  try {
    controller.initialize("first", ARM9_RANGE);
    const added = await controller.addBreakpoint({
      address: 0x02000000,
      mode: "arm",
      timeoutMs: 1000,
    });
    await assert.rejects(
      controller.removeBreakpoint(added.id, 1000),
      /GDB software breakpoint remove failed: E02/,
    );
    const removed = await controller.removeBreakpoint(added.id, 1000);
    assert.equal(removed.id, added.id);
    assert.deepEqual(received, [
      "Z0,2000000,4",
      "z0,2000000,4",
      "z0,2000000,4",
    ]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("controller resolves additional executable ranges and Thumb mode", async () => {
  const received: string[] = [];
  const server = queuedRspServer(["OK"], received);
  const port = await listen(server);
  const controller = new DebugController(sessionFactory({ first: port }));

  try {
    controller.initialize("first", ARM9_RANGE);
    controller.replaceAdditionalRanges([
      {
        id: "overlay-7",
        label: "Battle overlay",
        start: 0x02002000,
        end: 0x02002100,
        source: "overlay",
        overlayId: 7,
        defaultMode: "thumb",
      },
    ]);
    const added = await controller.addBreakpoint({
      address: 0x02002002,
      mode: "auto",
      rangeId: "overlay-7",
      timeoutMs: 1000,
    });
    assert.equal(added.resolvedMode, "thumb");
    assert.equal(added.kind, 2);
    assert.equal(added.overlayId, 7);
    assert.deepEqual(received, ["Z0,2002002,2"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("session identity changes clear breakpoint state and close the old connection", async () => {
  const firstReceived: string[] = [];
  const secondReceived: string[] = [];
  let firstClosedResolve!: () => void;
  const firstClosed = new Promise<void>((resolve) => {
    firstClosedResolve = resolve;
  });
  const firstServer = queuedRspServer(["OK"], firstReceived, firstClosedResolve);
  const secondServer = queuedRspServer(["OK"], secondReceived);
  const firstPort = await listen(firstServer);
  const secondPort = await listen(secondServer);
  const controller = new DebugController(
    sessionFactory({ first: firstPort, second: secondPort }),
  );

  try {
    controller.initialize("first", ARM9_RANGE);
    const first = await controller.addBreakpoint({
      address: 0x02000000,
      mode: "arm",
      timeoutMs: 1000,
    });
    assert.equal(first.id, "bp-1");

    controller.initialize("second", ARM9_RANGE);
    await Promise.race([
      firstClosed,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("Old GDB socket did not close")), 1000),
      ),
    ]);

    const second = await controller.addBreakpoint({
      address: 0x02000000,
      mode: "arm",
      timeoutMs: 1000,
    });
    assert.equal(second.id, "bp-1");
    assert.deepEqual(firstReceived, ["Z0,2000000,4"]);
    assert.deepEqual(secondReceived, ["Z0,2000000,4"]);
  } finally {
    await controller.reset("test cleanup");
    await close(firstServer);
    await close(secondServer);
  }
});

test("controller delegates bounded continue and step execution", async () => {
  const received: string[] = [];
  const server = queuedRspServer(["S05", "S05", "S05"], received);
  const port = await listen(server);
  const controller = new DebugController(sessionFactory({ first: port }));

  try {
    controller.initialize("first", ARM9_RANGE);
    assert.equal((await controller.continueExecution({ timeoutMs: 1000 })).kind, "stop");
    const stepped = await controller.step({ count: 2, perStepTimeoutMs: 1000 });
    assert.equal(stepped.completed, 2);
    assert.equal(stepped.completedAll, true);
    assert.deepEqual(received, ["c", "s", "s"]);
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("controller delegates wait and pause while execution is running", async () => {
  let commandCount = 0;
  let buffer = "";
  const server = net.createServer((socket) => {
    socket.on("data", (chunk) => {
      if (chunk.includes(0x03)) {
        socket.write(encodeRspPacket("S02"), "ascii");
        return;
      }
      buffer += chunk.toString("ascii");
      for (;;) {
        const parsed = parseRspPacket(buffer);
        if (parsed === null) return;
        buffer = buffer.slice(parsed.consumed);
        if (parsed.payload !== "c") continue;
        commandCount += 1;
        socket.write("+", "ascii");
        if (commandCount === 1) {
          setTimeout(() => socket.write(encodeRspPacket("S05"), "ascii"), 60);
        }
      }
    });
  });
  const port = await listen(server);
  const controller = new DebugController(sessionFactory({ first: port }));

  try {
    controller.initialize("first", ARM9_RANGE);
    assert.deepEqual(await controller.continueExecution({ timeoutMs: 20 }), {
      kind: "timeout",
      state: "running",
    });
    assert.equal((await controller.waitForStop(1000)).kind, "stop");

    assert.deepEqual(await controller.continueExecution({ timeoutMs: 20 }), {
      kind: "timeout",
      state: "running",
    });
    const paused = await controller.pause(1000);
    assert.equal(paused.kind, "stop");
  } finally {
    await controller.reset("test cleanup");
    await close(server);
  }
});

test("reset invalidates controller state", async () => {
  const server = queuedRspServer([], []);
  const port = await listen(server);
  const controller = new DebugController(sessionFactory({ first: port }));

  try {
    controller.initialize("first", ARM9_RANGE);
    await controller.reset("manual reset");
    await assert.rejects(
      controller.addBreakpoint({
        address: 0x02000000,
        mode: "arm",
        timeoutMs: 1000,
      }),
      /Debug controller is not initialized/,
    );
  } finally {
    await close(server);
  }
});
