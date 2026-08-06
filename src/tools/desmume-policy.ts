export type DesmumeLauncherMode = "linux-cli" | "macos-cocoa";

export function validateGdbPort(port: number): number {
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw new Error("ARM9 GDB port must be an integer from 1024 through 65535");
  }
  return port;
}

export function buildDesmumeArguments(
  mode: DesmumeLauncherMode,
  port: number,
  romPath: string,
): readonly string[] {
  validateGdbPort(port);
  if (mode === "macos-cocoa") {
    return [romPath, port.toString(10)];
  }
  return [`--arm9gdb=${port}`, romPath];
}
