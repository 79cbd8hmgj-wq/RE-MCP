# Catalina-Native DeSmuME Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a manually triggered GitHub Actions workflow that builds, validates, and packages an Intel `x86_64` DeSmuME Cocoa debugger bundle compatible with macOS Catalina 10.15.

**Architecture:** Keep RE-MCP runtime code unchanged for this milestone. Add one repository-owned source patcher, one static policy test, and one manual-only GitHub Actions workflow that fetches pinned DeSmuME source, applies the patch, builds the Cocoa dev+ target, validates the resulting Mach-O binary, assembles the launcher bundle, and uploads both the bundle and diagnostics.

**Tech Stack:** GitHub Actions YAML, Bash, Python 3, Xcode/xcodebuild, DeSmuME 0.9.13 source, Node.js test runner.

## Global Constraints

- Branch: `feature/catalina-native-desmume`, based on `main`.
- Workflow trigger: `workflow_dispatch` only.
- Target architecture: `x86_64` only.
- Minimum deployment target: macOS `10.15` or earlier.
- Code signing: disabled in CI.
- DeSmuME source must be pinned to `release_0_9_13` or a fixed commit derived from it.
- The launcher must execute the inner Cocoa binary directly with `exec`; it must not use `open`.
- ARM9 GDB startup is enabled only when `RE_MCP_ARM9_GDB_PORT` is present and valid.
- GDB port range: 1024 through 65535.
- No RE-MCP tool schema or runtime-process changes are included in this milestone.
- Native acceptance requires a manual smoke test on the target Catalina Mac.

---

## File Map

- Create `.github/workflows/build-desmume-catalina-native.yml`: manual native build, validation, packaging, diagnostics, artifact upload.
- Create `scripts/patch-desmume-catalina-native.py`: narrowly patch DeSmuME Cocoa startup for environment-driven ARM9 GDB autostart.
- Create `tests/catalina-workflow.test.ts`: static policy tests for trigger, pinning, architecture, deployment target, launcher behavior, and patch scope.
- Modify `README.md`: document how to run the workflow, download the artifact, and perform the Catalina smoke test.

---

### Task 1: Lock the Manual Workflow Policy in Tests

**Files:**
- Create: `tests/catalina-workflow.test.ts`

**Interfaces:**
- Consumes: repository files loaded with `readFile`.
- Produces: test cases that later workflow and patch files must satisfy.

- [ ] **Step 1: Add failing tests for the workflow contract**

Create `tests/catalina-workflow.test.ts` with tests that read `.github/workflows/build-desmume-catalina-native.yml` and assert:

```ts
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const workflowPath = new URL(
  "../.github/workflows/build-desmume-catalina-native.yml",
  import.meta.url,
);
const patchPath = new URL(
  "../scripts/patch-desmume-catalina-native.py",
  import.meta.url,
);

async function read(path: URL): Promise<string> {
  return await readFile(path, "utf8");
}

test("Catalina workflow is manual-only", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /workflow_dispatch:/);
  assert.doesNotMatch(workflow, /pull_request:/);
  assert.doesNotMatch(workflow, /\bpush:/);
});

test("Catalina workflow pins source and target", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /release_0_9_13/);
  assert.match(workflow, /ARCHS=x86_64/);
  assert.match(workflow, /MACOSX_DEPLOYMENT_TARGET=10\.15/);
  assert.match(workflow, /CODE_SIGNING_ALLOWED=NO/);
});

test("Catalina launcher validates and directly execs the app binary", async () => {
  const workflow = await read(workflowPath);
  assert.match(workflow, /\$# -ne 2/);
  assert.match(workflow, /-r \"\$1\"/);
  assert.match(workflow, /1024/);
  assert.match(workflow, /65535/);
  assert.match(workflow, /CFBundleExecutable/);
  assert.match(workflow, /exec env RE_MCP_ARM9_GDB_PORT/);
  assert.doesNotMatch(workflow, /\bopen\s+-a\b/);
});

test("Catalina patch is limited to environment-driven ARM9 GDB startup", async () => {
  const patch = await read(patchPath);
  assert.match(patch, /RE_MCP_ARM9_GDB_PORT/);
  assert.match(patch, /1024/);
  assert.match(patch, /65535/);
  assert.doesNotMatch(patch, /system\(/);
  assert.doesNotMatch(patch, /subprocess/);
});
```

- [ ] **Step 2: Run the new test and confirm it fails because files are absent**

Run:

```bash
npm test -- tests/catalina-workflow.test.ts
```

Expected: FAIL with `ENOENT` for the workflow or patch file.

- [ ] **Step 3: Commit the failing policy tests**

```bash
git add tests/catalina-workflow.test.ts
git commit -m "test: define Catalina workflow policy"
```

---

### Task 2: Implement the Narrow DeSmuME Source Patcher

**Files:**
- Create: `scripts/patch-desmume-catalina-native.py`
- Test: `tests/catalina-workflow.test.ts`

**Interfaces:**
- Consumes: one DeSmuME source-root path argument.
- Produces: an idempotent patch to `desmume/src/frontend/cocoa/userinterface/appDelegate.mm` that reads `RE_MCP_ARM9_GDB_PORT`, validates it, and starts the ARM9 GDB stub.

- [ ] **Step 1: Implement source-root validation and deterministic target lookup**

The script must:

```python
from __future__ import annotations

import pathlib
import sys

TARGET = pathlib.Path("desmume/src/frontend/cocoa/userinterface/appDelegate.mm")
MARKER = "RE_MCP_ARM9_GDB_PORT"


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

    patched = apply_patch(source)
    target.write_text(patched, encoding="utf-8")
    print(f"Patched Catalina ARM9 GDB startup: {target}")
    return 0
```

- [ ] **Step 2: Add a narrowly anchored `apply_patch` implementation**

Use exact source anchors from DeSmuME 0.9.13 rather than broad replacements. The inserted Objective-C++ block must:

```cpp
const char *reMcpArm9GdbPort = getenv("RE_MCP_ARM9_GDB_PORT");
if (reMcpArm9GdbPort != NULL && reMcpArm9GdbPort[0] != '\0') {
    char *end = NULL;
    const long parsedPort = strtol(reMcpArm9GdbPort, &end, 10);
    if (end != reMcpArm9GdbPort && *end == '\0' && parsedPort >= 1024 && parsedPort <= 65535) {
        // Call the existing DeSmuME ARM9 GDB-stub start path here using the
        // concrete function or controller API present in release_0_9_13.
    }
}
```

The implementation must fail with a clear error if either expected anchor is absent, rather than silently writing an incomplete patch.

- [ ] **Step 3: Verify Python syntax**

Run:

```bash
python3 -m py_compile scripts/patch-desmume-catalina-native.py
```

Expected: exit code 0.

- [ ] **Step 4: Run static policy tests**

Run:

```bash
npm test -- tests/catalina-workflow.test.ts
```

Expected: workflow-related tests still fail because the YAML file does not exist; patch-scope assertions pass.

- [ ] **Step 5: Commit the patcher**

```bash
git add scripts/patch-desmume-catalina-native.py tests/catalina-workflow.test.ts
git commit -m "feat: add Catalina DeSmuME GDB patcher"
```

---

### Task 3: Add the Manual Catalina-Native Build Workflow

**Files:**
- Create: `.github/workflows/build-desmume-catalina-native.yml`
- Test: `tests/catalina-workflow.test.ts`

**Interfaces:**
- Consumes: `scripts/patch-desmume-catalina-native.py` and pinned DeSmuME source.
- Produces: `desmume-catalina-native-debug-bundle` artifact containing the ZIP, checksum, and diagnostics.

- [ ] **Step 1: Add a manual-only workflow skeleton**

Create the file with:

```yaml
name: Build Catalina-Native DeSmuME Debug Bundle

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: macos-15-intel
    timeout-minutes: 60
```

- [ ] **Step 2: Clone pinned source and apply the repository patch**

Add steps that run:

```bash
git clone --depth 1 --branch release_0_9_13 \
  https://github.com/TASEmulators/desmume.git /tmp/desmume
python3 scripts/patch-desmume-catalina-native.py /tmp/desmume
```

Capture the resolved DeSmuME commit with:

```bash
git -C /tmp/desmume rev-parse HEAD | tee /tmp/desmume-source-commit.txt
```

- [ ] **Step 3: Discover the Xcode project and debug-capable dev+ scheme**

Enumerate `.xcodeproj` files, run `xcodebuild -list`, save all output to `/tmp/xcode-discovery.txt`, and write the selected `PROJECT` and `SCHEME` to `/tmp/desmume-selection.env`. Fail if no scheme matching `dev+` or `Dev+` is found.

- [ ] **Step 4: Build the Intel Cocoa app for Catalina**

Run:

```bash
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Release \
  -derivedDataPath /tmp/desmume-derived \
  ARCHS=x86_64 \
  ONLY_ACTIVE_ARCH=YES \
  MACOSX_DEPLOYMENT_TARGET=10.15 \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Pipe complete output to `/tmp/desmume-build.log`, preserve the xcodebuild exit status through `PIPESTATUS[0]`, and create `/tmp/desmume-build-errors.txt` from the final 250 matching error/build-failure lines.

- [ ] **Step 5: Assemble the bundle and launcher**

Find the built `DeSmuME*.app`, copy it to:

```text
/tmp/desmume-catalina-native-debug/DeSmuME Debug.app
```

Generate `run-desmume-debug.command` with these exact behaviors:

```bash
#!/bin/bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 /absolute/path/to/game.nds ARM9_GDB_PORT" >&2
  exit 64
fi
if [[ ! -r "$1" ]]; then
  echo "ROM is not readable: $1" >&2
  exit 66
fi
if [[ ! "$2" =~ ^[0-9]+$ ]] || (( "$2" < 1024 || "$2" > 65535 )); then
  echo "ARM9_GDB_PORT must be an integer from 1024 through 65535" >&2
  exit 64
fi

bundle_root="$(cd "$(dirname "$0")" && pwd)"
plist="$bundle_root/DeSmuME Debug.app/Contents/Info.plist"
executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$plist")"
binary="$bundle_root/DeSmuME Debug.app/Contents/MacOS/$executable"
if [[ ! -x "$binary" ]]; then
  echo "DeSmuME executable is missing or not executable: $binary" >&2
  exit 69
fi

exec env RE_MCP_ARM9_GDB_PORT="$2" "$binary" "$1"
```

- [ ] **Step 6: Validate architecture, minimum OS, dependencies, and patch presence**

The workflow must:

```bash
file "$binary" | tee /tmp/desmume-binary.txt
lipo -archs "$binary" | tee /tmp/desmume-architectures.txt
otool -L "$binary" | tee /tmp/desmume-dependencies.txt
otool -l "$binary" > /tmp/desmume-load-commands.txt
```

Fail unless `lipo -archs` equals `x86_64`.

Parse `LC_BUILD_VERSION` or `LC_VERSION_MIN_MACOSX` with Python and fail if the minimum version is greater than `(10, 15)`. Save parsed output to `/tmp/desmume-minos.txt`.

Use `grep` to confirm `RE_MCP_ARM9_GDB_PORT` is present in both the patched source and launcher.

- [ ] **Step 7: Generate documentation, compatibility report, ZIP, and checksum**

Create:

```text
README.txt
compatibility-report.txt
SHA256SUMS.txt
```

The compatibility report must include the resolved DeSmuME commit, selected Xcode project, selected scheme, `file` output, architectures, parsed minimum macOS version, and `otool -L` dependencies.

Package with:

```bash
ditto -c -k --sequesterRsrc --keepParent \
  /tmp/desmume-catalina-native-debug \
  /tmp/desmume-catalina-native-debug.zip
shasum -a 256 /tmp/desmume-catalina-native-debug.zip \
  | tee /tmp/desmume-catalina-native-debug.zip.sha256
```

Copy the checksum line into the bundle's `SHA256SUMS.txt` before producing the final ZIP, then regenerate the outer `.zip.sha256` after the final ZIP is complete.

- [ ] **Step 8: Upload outputs and diagnostics even on failure**

Use `actions/upload-artifact@v4` with `if: always()`, artifact name `desmume-catalina-native-debug-bundle`, retention 30 days, and paths for the ZIP, checksum, source commit, discovery output, selection file, full build log, error summary, architecture output, dependency output, load commands, and minimum-version report.

- [ ] **Step 9: Run policy tests**

Run:

```bash
npm test -- tests/catalina-workflow.test.ts
```

Expected: PASS.

- [ ] **Step 10: Run the full repository verification suite**

Run:

```bash
npm run check
```

Expected: typecheck and all tests pass.

- [ ] **Step 11: Commit the workflow**

```bash
git add .github/workflows/build-desmume-catalina-native.yml tests/catalina-workflow.test.ts
git commit -m "ci: build Catalina-native DeSmuME bundle"
```

---

### Task 4: Document Manual Build and Catalina Smoke Test

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: workflow and artifact contracts from Task 3.
- Produces: operator instructions for manually running and validating the bundle.

- [ ] **Step 1: Add a Catalina-native build section**

Document:

1. Open the repository's **Actions** tab.
2. Select **Build Catalina-Native DeSmuME Debug Bundle**.
3. Select branch `feature/catalina-native-desmume`.
4. Choose **Run workflow**.
5. Download `desmume-catalina-native-debug-bundle` after completion.
6. Verify the outer SHA-256 checksum before extraction.

- [ ] **Step 2: Add Catalina installation and launch instructions**

Include:

```bash
xattr -dr com.apple.quarantine desmume-catalina-native-debug
chmod +x desmume-catalina-native-debug/run-desmume-debug.command
./desmume-catalina-native-debug/run-desmume-debug.command \
  /absolute/path/to/Bakugan.nds 20000
```

State that quarantine removal should only be used after verifying the checksum and trusting the artifact source.

- [ ] **Step 3: Add the manual acceptance checklist**

Document the required checks:

- Cocoa app opens on macOS Catalina 10.15.
- ROM boots.
- `lsof -nP -iTCP:20000 -sTCP:LISTEN` shows a localhost listener.
- RE-MCP `desmume_probe_gdb` succeeds after integration.
- Raw register read succeeds.
- One bounded ARM9 memory read succeeds.

Clarify that RE-MCP integration is the next milestone and is not part of this branch until this smoke test passes.

- [ ] **Step 4: Run full verification**

Run:

```bash
npm run check
```

Expected: PASS.

- [ ] **Step 5: Commit documentation**

```bash
git add README.md
git commit -m "docs: add Catalina-native bundle instructions"
```

---

### Task 5: Final Review and Pull Request Preparation

**Files:**
- Review all files changed on `feature/catalina-native-desmume`.

**Interfaces:**
- Consumes: completed implementation from Tasks 1-4.
- Produces: a review-ready branch and manual workflow ready for the user to run.

- [ ] **Step 1: Verify branch diff is limited to approved scope**

Run:

```bash
git diff --stat main...HEAD
git diff --name-only main...HEAD
```

Expected changed implementation files:

```text
.github/workflows/build-desmume-catalina-native.yml
README.md
scripts/patch-desmume-catalina-native.py
tests/catalina-workflow.test.ts
docs/superpowers/specs/2026-08-06-catalina-native-desmume-design.md
docs/superpowers/plans/2026-08-06-catalina-native-desmume.md
```

- [ ] **Step 2: Run final verification**

```bash
python3 -m py_compile scripts/patch-desmume-catalina-native.py
npm run check
```

Expected: both commands exit 0.

- [ ] **Step 3: Review workflow trigger and artifact policy directly**

Confirm:

```bash
grep -nE 'workflow_dispatch|pull_request|push:' \
  .github/workflows/build-desmume-catalina-native.yml
grep -nE 'ARCHS=x86_64|MACOSX_DEPLOYMENT_TARGET=10.15|CODE_SIGNING_ALLOWED=NO' \
  .github/workflows/build-desmume-catalina-native.yml
```

Expected: `workflow_dispatch` appears; `pull_request` and `push` do not; all three build constraints appear.

- [ ] **Step 4: Open a pull request without merging**

Create a PR from `feature/catalina-native-desmume` to `main` titled:

```text
Build Catalina-native DeSmuME debugger bundle
```

The body must summarize the manual workflow, source patch boundary, compatibility checks, artifact contents, and required on-device Catalina smoke test.

- [ ] **Step 5: Manually run the workflow from the feature branch**

Use the GitHub Actions UI to start **Build Catalina-Native DeSmuME Debug Bundle** on `feature/catalina-native-desmume`. Do not merge until the artifact builds and passes the target-Mac smoke test.
