#!/usr/bin/env bash
# GameBoySymbolImport.java on a Mooneye ROM and its WLA-DX .sym file, verified by SymbolCheck.java;
# and on a GBDK .noi file (labels, functions, C names).
#   test/symbol-check.sh <rom.gb> <rom.sym>
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
ROM=$(readlink -f "$1"); SYM=$(readlink -f "$2")
PROJ=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/sm83-sym.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$ROM" -scriptPath "$HERE;$HERE/../ghidra_scripts" \
	-postScript SymbolCheck.java "$SYM" -deleteProject >"$PROJ/log.txt" 2>&1 || { tail -30 "$PROJ/log.txt" >&2; exit 1; }
grep -E "SymbolCheck.java> (SYMCHECK|MISSING)|GameBoySymbolImport.java>" "$PROJ/log.txt" | sed 's/.*java> //; s/ (GhidraScript)//'
grep -q "SYMCHECK .* 0 missing" "$PROJ/log.txt"
