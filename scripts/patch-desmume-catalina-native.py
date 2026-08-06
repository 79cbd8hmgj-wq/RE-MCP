from __future__ import annotations

import pathlib
import sys

TARGET = pathlib.Path("desmume/src/frontend/cocoa/userinterface/appDelegate.mm")
MARKER = "RE_MCP_ARM9_GDB_PORT"
INCLUDE_ANCHOR = '#import "cocoa_util.h"\n'
INCLUDE_INSERTION = '#import "cocoa_util.h"\n\n#include <stdlib.h>\n'
STARTUP_ANCHOR = "\t[emuControl appInit];\n\t[prefWindowDelegate markUnsupportedOpenGLMSAAMenuItems];"
STARTUP_INSERTION = r'''	[emuControl appInit];

#ifdef GDB_STUB
	const char *reMcpArm9GdbPort = getenv("RE_MCP_ARM9_GDB_PORT");
	if (reMcpArm9GdbPort != NULL && reMcpArm9GdbPort[0] != '\0')
	{
		char *end = NULL;
		const long parsedPort = strtol(reMcpArm9GdbPort, &end, 10);
		if (end != reMcpArm9GdbPort && *end == '\0' && parsedPort >= 1024 && parsedPort <= 65535)
		{
			[newCore setEnableGdbStubARM9:YES];
			[newCore setGdbStubPortARM9:(NSUInteger)parsedPort];
			[emuControl toggleGDBStubActivate:nil];
		}
	}
#endif

	[prefWindowDelegate markUnsupportedOpenGLMSAAMenuItems];'''


def replace_exactly_once(source: str, anchor: str, replacement: str, label: str) -> str:
    if source.count(anchor) != 1:
        raise ValueError(f"expected exactly one DeSmuME 0.9.13 {label} anchor; source layout changed")
    return source.replace(anchor, replacement, 1)


def apply_patch(source: str) -> str:
    if MARKER in source:
        return source

    patched = replace_exactly_once(
        source,
        INCLUDE_ANCHOR,
        INCLUDE_INSERTION,
        "include",
    )
    return replace_exactly_once(
        patched,
        STARTUP_ANCHOR,
        STARTUP_INSERTION,
        "appInit",
    )


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} /path/to/desmume-source", file=sys.stderr)
        return 64

    root = pathlib.Path(sys.argv[1]).resolve()
    target = root / TARGET
    if not target.is_file():
        print(f"missing expected DeSmuME source file: {target}", file=sys.stderr)
        return 1

    source = target.read_text(encoding="utf-8")
    if MARKER in source:
        print(f"Catalina ARM9 GDB patch already present: {target}")
        return 0

    try:
        patched = apply_patch(source)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1

    target.write_text(patched, encoding="utf-8")
    print(f"Patched Catalina ARM9 GDB startup: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
