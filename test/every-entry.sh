#!/usr/bin/env bash
# Every-entry test: test/every-entry.sh <out.txt>
# Decodes the table, pairs, imm16 and fuzz corpora of gen_corpus.py and lists the SLEIGH
# constructors (in every subtable) that no instruction used.  Fails if any was missed.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(readlink -m "$1")
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/sm83-ee.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT
python3 "$HERE/gen_corpus.py" "$PROJ" 20000 5 >/dev/null
n=0
for img in "$PROJ"/table*.bin "$PROJ"/pairs*.bin "$PROJ"/imm16*.bin "$PROJ"/fuzz*.bin; do
	n=$((n + 1))
	mkdir "$PROJ/p$n"
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$PROJ/p$n" p -import "$img" -loader BinaryLoader \
		-loader-baseAddr 0 -processor SM83:LE:16:default -noanalysis -scriptPath "$HERE" \
		-postScript EveryEntry.java "$PROJ/seen$n.txt" 6 - -deleteProject >"$PROJ/log$n.txt" 2>&1 \
		|| { tail -40 "$PROJ/log$n.txt" >&2; exit 1; } &
	while (( $(jobs -r | wc -l) >= 4 )); do sleep 1; done
done
wait
python3 "$HERE/every_merge.py" "$PROJ"/seen*.txt | tee "$OUT"
grep -q " 0 not reached" "$OUT"
