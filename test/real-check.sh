#!/usr/bin/env bash
# Real-code check for a Game Boy ROM: auto-detecting headless import (no forced language) with
# full analysis, decompile every function, and compare every analysed instruction run with MAME's
# unidasm at the same addresses.
#   test/real-check.sh <rom.gb> <outdir> [decompile-timeout-seconds (0: skip)]
# Output: <outdir>/<name>.{summary,dis,c,cmp}; prints the summary and the comparison line.
# Exit 1 on a wrong language, an unexplained MAME difference, or a bad-instruction bookmark in
# an executable block (other than Ghidra's repeated-NOP-run limit).
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
ROM=$(readlink -f "$1"); OUTD=$(readlink -m "$2"); TMO=${3:-60}
N=$(basename "$ROM")
mkdir -p "$OUTD"
P="$OUTD/$N"
rm -f "$P".{summary,dis,c,cmp}
"$HERE/ghidra-rom.sh" "$ROM" RealCheck.java "$P.summary" "$P.dis" "$P.c" "$TMO"
grep -v "^  Warning\|^  Error" "$P.summary"
rc=0
grep -q "^language: SM83:LE:16:default " "$P.summary" || { echo "wrong language"; rc=1; }
# Explained bad-instruction bookmarks in executable blocks (counted, not failures):
#  - Ghidra stops disassembling a long run of identical instructions ("Maximum run of repeated byte
#    instructions exceeded"): NOP-padded test ROMs, the binary and not the module;
#  - a call or jump into the switchable window 4000-7FFF whose ROM bank no constant bank-register
#    write (or the power-up state) determines: the analyzer cannot choose an overlay, the README's
#    "cross-bank calls still need manual resolution";
#  - flow running past the end of a RAM routine mapped from a ROM copy (the program writes the rest of
#    the routine to RAM by other means, so the ROM holds only a prefix).
nops=$(grep -c "bad in executable block.*Maximum run of repeated byte" "$P.summary" || true)
banked=$(grep -cE "bad in executable block.*non-existing memory at [4-7][0-9a-f]{3} " "$P.summary" || true)
ramend=$(grep -cE "bad in executable block.*(non-existing memory at [wh]ram_code_|flow from 7fff)" "$P.summary" || true)
other=$({ grep "bad in executable block" "$P.summary" || true; } | { grep -v "Maximum run of repeated byte" || true; } |
	{ grep -vE "non-existing memory at ([4-7][0-9a-f]{3}|[wh]ram_code_)|flow from 7fff" || true; } | wc -l)
echo "explained bad-instruction bookmarks: $nops repeated-NOP limit, $banked unresolved bank flows, $ramend past the end of a copied RAM routine or of the ROM; unexplained: $other"
(( other == 0 )) || { echo "bad instruction in an executable block"; rc=1; }
python3 "$HERE/real_compare.py" "$P.dis" "$N" >"$P.cmp" || rc=1
tail -3 "$P.cmp"
exit $rc
