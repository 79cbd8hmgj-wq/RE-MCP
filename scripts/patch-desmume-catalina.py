#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def patch(source_root: Path) -> None:
    path = source_root / "desmume/src/frontend/cocoa/userinterface/appDelegate.mm"
    text = path.read_text(encoding="utf-8")
    marker = "RE_MCP_ARM9_GDB_PORT"
    if marker in text:
        return

    signature = "- (void)applicationDidFinishLaunching:(NSNotification *)aNotification\n{"
    start = text.index(signature)
    anchor = (
        "\tEmuControllerDelegate *emuControl = "
        "(EmuControllerDelegate *)[emuControlController content];\n"
    )
    position = text.index(anchor, start) + len(anchor)
    hook = r'''
#if defined(GDB_STUB)
	NSString *reMcpPortString = [[[NSProcessInfo processInfo] environment] objectForKey:@"RE_MCP_ARM9_GDB_PORT"];
	if (reMcpPortString != nil && [reMcpPortString length] > 0)
	{
		const NSInteger reMcpPort = [reMcpPortString integerValue];
		if (reMcpPort >= 1024 && reMcpPort <= 65535)
		{
			CocoaDSCore *reMcpCore = (CocoaDSCore *)[cdsCoreController content];
			ClientExecutionControl *reMcpExecControl = [reMcpCore execControl];
			reMcpExecControl->SetGDBStubARM9Enabled(true);
			reMcpExecControl->SetGDBStubARM9Port((uint16_t)reMcpPort);
			reMcpExecControl->SetIsGDBStubStarted(true);
		}
	}
#endif
'''
    path.write_text(text[:position] + hook + text[position:], encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch-desmume-catalina.py SOURCE_ROOT")
    patch(Path(sys.argv[1]).resolve())
