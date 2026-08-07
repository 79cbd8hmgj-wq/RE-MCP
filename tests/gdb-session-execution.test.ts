import assert from "node:assert/strict";
import net from "node:net";
import test from "node:test";

import { encodeRspPacket, parseRspPacket } from "../src/services/gdb-rsp.js";
import { GdbSession } from "../src/services/gdb-session.js";

async function listen(server: net.Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Expected TCP address");
  return address.port;
}

async function close(server: net.Server): Promise<void> {
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function createSession(port: number): GdbSession {
  return new GdbSession({
    host: "127.0.0.1",
    port,
    maxReplyBytes: 4096,
    connectTimeoutMs: 1000,
  });
}

function breakpointServer(
  replies: readonly (string | null)[],
  received: string[],
): net.Server {
  const remaining = [...replies];
  return net.createServer((socket) => {
    let buffer = "";
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

test("inserts and removes ARM and Thumb software breakpoints", async () => {
  const received: string[] = [];
  const server = breakpointServer(["OK", "OK", "OK", "OK"], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    await session.insertSoftwareBreakpoint(0x02000000, 4, 1000);
    await session.insertSoftwareBreakpoint(0x02000002, 2, 1000);
    await session.removeSoftwareBreakpoint(0x02000000, 4, 1000);
    await session.removeSoftwareBreakpoint(0x02000002, 2, 1000);

    assert.deepEqual(received, [
      "Z0,2000000,4",
      "Z0,2000002,2",
      "z0,2000000,4",
      "z0,2000002,2",
    ]);
  } finally {
    await session.close();
    await close(server);
  }
});

test("rejects GDB breakpoint errors and unsupported acknowledgements", async () => {
  const received: string[] = [];
  const server = breakpointServer(["E01", ""], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    await assert.rejects(
      session.insertSoftwareBreakpoint(0x02000000, 4, 1000),
      /GDB software breakpoint insert failed: E01/,
    );
    await assert.rejects(
      session.removeSoftwareBreakpoint(0x02000000, 4, 1000),
      /Unsupported GDB software breakpoint remove reply/,
    );
  } finally {
    await session.close();
    await close(server);
  }
});

test("continue waits for an asynchronous stop reply", async () => {
  const received: string[] = [];
  const server = net.createServer((socket) => {
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("ascii");
      const parsed = parseRspPacket(buffer);
      if (parsed === null) return;
      buffer = buffer.slice(parsed.consumed);
      received.push(parsed.payload);
      socket.write("+", "ascii");
      setTimeout(() => socket.write(encodeRspPacket("S05"), "ascii"), 10);
    });
  });
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.continueExecution(1000), {
      kind: "stop",
      stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
      state: "stopped",
    });
    assert.equal(session.state(), "stopped");
    assert.deepEqual(received, ["c"]);
  } finally {
    await session.close();
    await close(server);
  }
});

test("continue timeout leaves execution running and wait observes a later stop", async () => {
  const server = net.createServer((socket) => {
    let buffer = "";
    let scheduled = false;
    socket.on("data", (chunk) => {
      buffer += chunk.toString("ascii");
      const parsed = parseRspPacket(buffer);
      if (parsed === null) return;
      buffer = buffer.slice(parsed.consumed);
      if (parsed.payload !== "c" || scheduled) return;
      scheduled = true;
      socket.write("+", "ascii");
      setTimeout(() => socket.write(encodeRspPacket("S05"), "ascii"), 60);
    });
  });
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.continueExecution(20), {
      kind: "timeout",
      state: "running",
    });
    assert.equal(session.state(), "running");
    assert.deepEqual(await session.waitForStop(1000), {
      kind: "stop",
      stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
      state: "stopped",
    });
  } finally {
    await session.close();
    await close(server);
  }
});

test("pause sends the raw GDB interrupt byte and waits for stop", async () => {
  let sawInterrupt = false;
  const server = net.createServer((socket) => {
    socket.on("data", (chunk) => {
      const text = chunk.toString("ascii");
      const parsed = parseRspPacket(text);
      if (parsed?.payload === "c") {
        socket.write("+", "ascii");
        return;
      }
      if (chunk.includes(0x03)) {
        sawInterrupt = true;
        socket.write(encodeRspPacket("S02"), "ascii");
      }
    });
  });
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.equal((await session.continueExecution(20)).kind, "timeout");
    assert.deepEqual(await session.interruptAndWait(1000), {
      kind: "stop",
      stop: { kind: "signal", signal: 2, fields: {}, raw: "S02" },
      state: "stopped",
    });
    assert.equal(sawInterrupt, true);
  } finally {
    await session.close();
    await close(server);
  }
});

test("execution reports target exit and invalidates the session", async () => {
  const server = net.createServer((socket) => {
    socket.once("data", () => socket.write(`+${encodeRspPacket("W00")}`, "ascii"));
  });
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.continueExecution(1000), {
      kind: "stop",
      stop: { kind: "exited", status: 0, raw: "W00" },
      state: "unavailable",
    });
    assert.equal(session.state(), "unavailable");
  } finally {
    await session.close();
    await close(server);
  }
});

test("execution rejects connection loss and marks the session unavailable", async () => {
  const server = net.createServer((socket) => {
    socket.once("data", () => socket.destroy());
  });
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    await assert.rejects(session.continueExecution(1000), /connection closed/);
    assert.equal(session.state(), "unavailable");
  } finally {
    await session.close();
    await close(server);
  }
});

test("single stepping completes one instruction and supports the 100-step limit", async () => {
  const received: string[] = [];
  const server = breakpointServer(Array.from({ length: 101 }, () => "S05"), received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.stepInstructions(1, 1000), {
      requested: 1,
      completed: 1,
      completedAll: true,
      result: {
        kind: "stop",
        stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
        state: "stopped",
      },
    });
    assert.deepEqual(await session.stepInstructions(100, 1000), {
      requested: 100,
      completed: 100,
      completedAll: true,
      result: {
        kind: "stop",
        stop: { kind: "signal", signal: 5, fields: {}, raw: "S05" },
        state: "stopped",
      },
    });
    assert.equal(received.length, 101);
    assert.equal(received.every((payload) => payload === "s"), true);
  } finally {
    await session.close();
    await close(server);
  }
});

test("single stepping rejects counts outside 1 through 100", async () => {
  const session = createSession(1);
  await assert.rejects(session.stepInstructions(0, 1000), /count must be from 1 through 100/);
  await assert.rejects(session.stepInstructions(101, 1000), /count must be from 1 through 100/);
});

test("single stepping stops early on a non-trap signal", async () => {
  const received: string[] = [];
  const server = breakpointServer(["S05", "S0b", "S05"], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.stepInstructions(3, 1000), {
      requested: 3,
      completed: 2,
      completedAll: false,
      result: {
        kind: "stop",
        stop: { kind: "signal", signal: 11, fields: {}, raw: "S0b" },
        state: "stopped",
      },
    });
    assert.deepEqual(received, ["s", "s"]);
  } finally {
    await session.close();
    await close(server);
  }
});

test("single stepping stops early on an explicit breakpoint stop", async () => {
  const received: string[] = [];
  const server = breakpointServer(["S05", "T05reason:breakpoint;", "S05"], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.stepInstructions(3, 1000), {
      requested: 3,
      completed: 2,
      completedAll: false,
      result: {
        kind: "stop",
        stop: {
          kind: "signal",
          signal: 5,
          fields: { reason: "breakpoint" },
          raw: "T05reason:breakpoint;",
        },
        state: "stopped",
      },
    });
    assert.deepEqual(received, ["s", "s"]);
  } finally {
    await session.close();
    await close(server);
  }
});

test("single stepping stops early on target exit", async () => {
  const received: string[] = [];
  const server = breakpointServer(["S05", "W00", "S05"], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.stepInstructions(3, 1000), {
      requested: 3,
      completed: 2,
      completedAll: false,
      result: {
        kind: "stop",
        stop: { kind: "exited", status: 0, raw: "W00" },
        state: "unavailable",
      },
    });
    assert.deepEqual(received, ["s", "s"]);
  } finally {
    await session.close();
    await close(server);
  }
});

test("single stepping stops early on timeout and leaves execution running", async () => {
  const received: string[] = [];
  const server = breakpointServer(["S05", null], received);
  const port = await listen(server);
  const session = createSession(port);

  try {
    await session.connect();
    assert.deepEqual(await session.stepInstructions(3, 100), {
      requested: 3,
      completed: 1,
      completedAll: false,
      result: { kind: "timeout", state: "running" },
    });
    assert.equal(session.state(), "running");
    assert.deepEqual(received, ["s", "s"]);
  } finally {
    await session.close();
    await close(server);
  }
});
