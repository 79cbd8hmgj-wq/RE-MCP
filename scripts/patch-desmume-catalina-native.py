from __future__ import annotations

import pathlib
import sys
from collections.abc import Callable

APP_DELEGATE = pathlib.Path("desmume/src/frontend/cocoa/userinterface/appDelegate.mm")
PREFIX_HEADER = pathlib.Path("desmume/src/frontend/cocoa/DeSmuME_Prefix.pch")
TARGETED_OPENGL_FILES = (
    pathlib.Path("desmume/src/frontend/cocoa/userinterface/DisplayWindowController.mm"),
    pathlib.Path("desmume/src/frontend/cocoa/cocoa_GPU.mm"),
    pathlib.Path("desmume/src/frontend/cocoa/userinterface/MacScreenshotCaptureTool.mm"),
)
GDB_MARKER = "RE_MCP_ARM9_GDB_PORT"
OPENGL_MARKER = "RE_MCP_FORCE_OPENGL"
TARGETED_METAL_MARKER = "RE_MCP_CATALINA_USE_METAL"
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
OPENGL_ANCHOR = "#define GL_SILENCE_DEPRECATION\n"
OPENGL_INSERTION = """#define GL_SILENCE_DEPRECATION

// RE_MCP_FORCE_OPENGL: The Catalina debugger bundle intentionally disables
// DeSmuME's Metal frontend and uses its existing OpenGL implementation.
#ifdef ENABLE_APPLE_METAL
#undef ENABLE_APPLE_METAL
#endif
"""


def replace_exactly_once(source: str, anchor: str, replacement: str, label: str) -> str:
    if source.count(anchor) != 1:
        raise ValueError(
            f"expected exactly one DeSmuME 0.9.13 {label} anchor; source layout changed"
        )
    return source.replace(anchor, replacement, 1)


def patch_app_delegate(source: str) -> str:
    if GDB_MARKER in source:
        return source
    patched = replace_exactly_once(source, INCLUDE_ANCHOR, INCLUDE_INSERTION, "include")
    return replace_exactly_once(patched, STARTUP_ANCHOR, STARTUP_INSERTION, "appInit")


def patch_prefix_header(source: str) -> str:
    if OPENGL_MARKER in source:
        return source
    return replace_exactly_once(source, OPENGL_ANCHOR, OPENGL_INSERTION, "OpenGL")


def replace_metal_guards(source: str) -> str:
    if TARGETED_METAL_MARKER in source:
        return source

    guard_count = source.count("ENABLE_APPLE_METAL")
    if guard_count < 1:
        raise ValueError("expected at least one ENABLE_APPLE_METAL guard")

    return source.replace("ENABLE_APPLE_METAL", TARGETED_METAL_MARKER)


def patch_file(path: pathlib.Path, transform: Callable[[str], str]) -> None:
    if not path.is_file():
        raise ValueError(f"missing expected DeSmuME source file: {path}")
    source = path.read_text(encoding="utf-8")
    patched = transform(source)
    path.write_text(patched, encoding="utf-8")
    print(f"Patched: {path}")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} /path/to/desmume-source", file=sys.stderr)
        return 64

    root = pathlib.Path(sys.argv[1]).resolve()
    try:
        patch_file(root / APP_DELEGATE, patch_app_delegate)
        patch_file(root / PREFIX_HEADER, patch_prefix_header)
        for relative_path in TARGETED_OPENGL_FILES:
            patch_file(root / relative_path, replace_metal_guards)
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
