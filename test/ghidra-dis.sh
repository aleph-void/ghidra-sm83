#!/usr/bin/env bash
# Slot disassembly of a raw SM83 image with Ghidra (DumpDisasm.java).
#   test/ghidra-dis.sh <raw.bin> <out.txt> [stride] [dis|pcode|src]
set -euo pipefail
BIN=$(readlink -f "$1"); OUT=$(readlink -m "$2"); STRIDE=${3:-8}; MODE=${4:-dis}
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/sm83-dis.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
cd "$PROJ"
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p \
	-import "$BIN" -loader BinaryLoader -loader-baseAddr 0 -processor SM83:LE:16:default \
	-noanalysis -scriptPath "$HERE" -postScript DumpDisasm.java "$OUT" "$STRIDE" "$MODE" \
	-deleteProject >"$PROJ/log.txt" 2>&1 || { tail -40 "$PROJ/log.txt" >&2; exit 1; }
[[ -s $OUT ]] || { grep -E "ERROR|Exception" "$PROJ/log.txt" | head -40 >&2; exit 1; }
