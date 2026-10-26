#!/usr/bin/env bash
# Auto-detecting headless import (no forced language) of a Game Boy ROM, full analysis, then a
# postScript from test/.
#   test/ghidra-rom.sh <file> <Script.java> [script args...]
set -euo pipefail
BIN=$(readlink -f "$1"); SCRIPT=$2; shift 2
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/sm83-rom.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
cd "$PROJ"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$BIN" \
	-scriptPath "$HERE" -postScript "$SCRIPT" "$@" -deleteProject >"$PROJ/log.txt" 2>&1 ||
	{ tail -40 "$PROJ/log.txt" >&2; exit 1; }
if grep -qE "SCRIPT ERROR" "$PROJ/log.txt"; then
	grep -E -A8 "SCRIPT ERROR" "$PROJ/log.txt" | head -40 >&2
	exit 1
fi
