#!/bin/bash
set -euo pipefail

SOURCE_TAG="${DESMUME_SOURCE_TAG:-release_0_9_13}"
WORK_ROOT="${DESMUME_BUILD_ROOT:-$PWD/.build/desmume-catalina}"
SOURCE_ROOT="$WORK_ROOT/source"
DERIVED_ROOT="$WORK_ROOT/derived"
OUTPUT_ROOT="$WORK_ROOT/output"
PROJECT_LIST="$WORK_ROOT/xcode-projects.txt"
SCRIPT_ROOT="$(cd "$(dirname "$0")" && pwd)"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This builder must run on macOS." >&2
  exit 69
fi
if ! command -v xcodebuild >/dev/null 2>&1; then
  echo "xcodebuild is required. Install or select Xcode first." >&2
  exit 69
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required. Xcode's command-line tools normally provide it." >&2
  exit 69
fi

rm -rf "$WORK_ROOT"
mkdir -p "$WORK_ROOT" "$OUTPUT_ROOT"
git clone --depth 1 --branch "$SOURCE_TAG" \
  https://github.com/TASEmulators/desmume.git "$SOURCE_ROOT"
python3 "$SCRIPT_ROOT/patch-desmume-catalina.py" "$SOURCE_ROOT"

find "$SOURCE_ROOT" -name '*.xcodeproj' -print > "$PROJECT_LIST"
if [[ ! -s "$PROJECT_LIST" ]]; then
  echo "No Xcode projects discovered in DeSmuME source." >&2
  exit 1
fi

project=""
scheme=""
while IFS= read -r candidate; do
  listing="$(xcodebuild -project "$candidate" -list 2>/dev/null || true)"
  candidate_scheme="$(printf '%s\n' "$listing" | sed -n '/Schemes:/,$p' | grep -E 'dev\+|Dev\+' | sed 's/^[[:space:]]*//' | head -n1 || true)"
  if [[ -n "$candidate_scheme" ]]; then
    project="$candidate"
    scheme="$candidate_scheme"
    break
  fi
done < "$PROJECT_LIST"

if [[ -z "$project" || -z "$scheme" ]]; then
  echo "No DeSmuME dev+ scheme was discovered." >&2
  while IFS= read -r candidate; do
    echo "===== $candidate =====" >&2
    xcodebuild -project "$candidate" -list >&2 || true
  done < "$PROJECT_LIST"
  exit 1
fi

echo "Building project: $project"
echo "Using scheme: $scheme"
xcodebuild \
  -project "$project" \
  -scheme "$scheme" \
  -configuration Release \
  -derivedDataPath "$DERIVED_ROOT" \
  ARCHS=x86_64 \
  ONLY_ACTIVE_ARCH=YES \
  MACOSX_DEPLOYMENT_TARGET=10.15 \
  CODE_SIGNING_ALLOWED=NO \
  build

app="$(find "$DERIVED_ROOT" -type d -name 'DeSmuME*.app' | head -n1)"
if [[ -z "$app" ]]; then
  echo "Build completed but no DeSmuME application was found." >&2
  exit 1
fi

bundle="$OUTPUT_ROOT/desmume-catalina-debug"
mkdir -p "$bundle"
cp -R "$app" "$bundle/DeSmuME Debug.app"
cat > "$bundle/run-desmume-debug.command" <<'LAUNCHER'
#!/bin/bash
set -euo pipefail
if [[ $# -ne 2 ]]; then
  echo "usage: $0 /absolute/path/to/game.nds ARM9_GDB_PORT" >&2
  exit 64
fi
app_dir="$(cd "$(dirname "$0")" && pwd)"
executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app_dir/DeSmuME Debug.app/Contents/Info.plist")"
exec env RE_MCP_ARM9_GDB_PORT="$2" \
  "$app_dir/DeSmuME Debug.app/Contents/MacOS/$executable" "$1"
LAUNCHER
chmod +x "$bundle/run-desmume-debug.command"

printf '%s\n' \
  'Intel x86_64 DeSmuME dev+ build targeting macOS 10.15.' \
  'The launcher automatically starts the ARM9 GDB stub.' \
  'Use RE-MCP desmume_start with mode macos-cocoa.' \
  > "$bundle/README.txt"

archive="$OUTPUT_ROOT/desmume-catalina-debug.zip"
ditto -c -k --sequesterRsrc --keepParent "$bundle" "$archive"
shasum -a 256 "$archive" > "$archive.sha256"
echo "Built: $archive"
cat "$archive.sha256"
