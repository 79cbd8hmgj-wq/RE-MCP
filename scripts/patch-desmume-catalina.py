#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path


def patch_gdb_autostart(source_root: Path) -> None:
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


def patch_metal_feature_sets(source_root: Path) -> None:
    path = source_root / "desmume/src/frontend/cocoa/userinterface/MacMetalDisplayView.mm"
    text = path.read_text(encoding="utf-8")
    replacements = {
        "supportsFeatureSet:10001": "supportsFeatureSet:(MTLFeatureSet)10001",
        "supportsFeatureSet:10002": "supportsFeatureSet:(MTLFeatureSet)10002",
        "supportsFeatureSet:10003": "supportsFeatureSet:(MTLFeatureSet)10003",
        "supportsFeatureSet:10004": "supportsFeatureSet:(MTLFeatureSet)10004",
        "supportsFeatureSet:10005": "supportsFeatureSet:(MTLFeatureSet)10005",
    }
    for old, new in replacements.items():
        if old not in text and new not in text:
            raise RuntimeError(f"expected Metal feature-set call not found: {old}")
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def patch(source_root: Path) -> None:
    patch_gdb_autostart(source_root)
    patch_metal_feature_sets(source_root)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch-desmume-catalina.py SOURCE_ROOT")
    patch(Path(sys.argv[1]).resolve())
