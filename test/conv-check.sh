#!/usr/bin/env bash
# SDCC (GBDK-2020) calling convention: sets __sdcccall1 on the C functions of an SDCC-built ROM
# (test/c/conv.c, built by fetch-samples.sh) and checks the decompiler's signatures for the
# parameter and result placement the SDCC manual (4.3.5.1) gives: 8-bit arguments in A then E,
# 16-bit in DE then BC, 8-bit results in A, 16-bit in BC.
#   test/conv-check.sh <conv.gb> <conv.noi>
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
ROM=$(readlink -f "$1"); NOI=$(readlink -f "$2")
PROJ=$(mktemp -d "${PROJ_DIR:-${TMPDIR:-/tmp}}/sm83-conv.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ" p -import "$ROM" -scriptPath "$HERE;$HERE/../ghidra_scripts" \
	-postScript ConvCheck.java "$NOI" __sdcccall1 -deleteProject >"$PROJ/log.txt" 2>&1 || { tail -30 "$PROJ/log.txt" >&2; exit 1; }
grep "ConvCheck.java> SIG" "$PROJ/log.txt" | sed 's/.*SIG //; s/ (GhidraScript)//' | grep -E "^_(add8|add16|first_plus|store|many|mix)" 
rc=0
expect() { grep -qF "$1" "$PROJ/log.txt" || { echo "MISSING: $1"; rc=1; }; }
expect "char __sdcccall1 _add8(char param_1,char param_2);"
expect "int __sdcccall1 _add16(int param_1,int param_2);"
expect "undefined4 __sdcccall1 _mix("
exit $rc
