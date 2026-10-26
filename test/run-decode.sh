#!/usr/bin/env bash
# Decode differential against MAME's lr35902 disassembler (unidasm):
#   test/run-decode.sh <workdir> [nfuzz] [seed]
# Corpora: table, pairs, imm16, fuzz (see gen_corpus.py).  Exits non-zero when any difference
# is unexplained.
set -euo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
W=$(readlink -m "$1"); NFUZZ=${2:-65536}; SEED=${3:-1}
UNIDASM=${UNIDASM:-unidasm}
mkdir -p "$W"
python3 "$HERE/gen_corpus.py" "$W" "$NFUZZ" "$SEED"
rc=0
for img in "$W"/table*.bin "$W"/pairs*.bin "$W"/imm16*.bin "$W"/fuzz*.bin; do
	b=${img%.bin}
	"$HERE/ghidra-dis.sh" "$img" "$b.ghidra.txt" 6 &
	"$UNIDASM" "$img" -arch lr35902 -basepc 0 >"$b.mame.txt"
	# at most four Ghidra instances at a time
	while (( $(jobs -r | wc -l) >= 4 )); do sleep 1; done
done
wait
tot=0
for kind in table pairs imm16 fuzz; do
	cat "$W"/${kind}[0-9]*.ghidra.txt >"$W/$kind.ghidra.all"
	: >"$W/$kind.mame.all"
	# rebase each image's offsets (images are 64 KB-limited, so offsets restart at 0)
	python3 - "$W" "$kind" <<'PY'
import glob, sys
w, kind = sys.argv[1:3]
n = len(glob.glob('%s/%s[0-9]*.bin' % (w, kind)))
g = open('%s/%s.ghidra.all' % (w, kind), 'w'); m = open('%s/%s.mame.all' % (w, kind), 'w')
for i in range(n):
    base = i * 65400
    for l in open('%s/%s%d.ghidra.txt' % (w, kind, i)):
        a, r = l.split(' ', 1); g.write('%08x %s' % (int(a, 16) + base, r))
    for l in open('%s/%s%d.mame.txt' % (w, kind, i)):
        a, r = l.split(':', 1); m.write('%06x: %s' % (int(a, 16) + base, r))
PY
	echo "== $kind"
	python3 "$HERE/compare.py" "$W/$kind.ghidra.all" "$W/$kind.mame.all" 6 >"$W/$kind.cmp.txt" || rc=1
	head -1 "$W/$kind.cmp.txt"
done

# Second oracle: the RGBDS assembler.  Ghidra's own text for every decodable slot must assemble
# back to the same bytes (STOP's ignored second byte aside).
if command -v "${RGBASM:-rgbasm}" >/dev/null && command -v "${RGBLINK:-rgblink}" >/dev/null; then
	echo "== assembler round trip (RGBDS $(${RGBASM:-rgbasm} --version))"
	: >"$W/rt.lines"
	for img in "$W"/table*.bin "$W"/pairs*.bin "$W"/imm16*.bin "$W"/fuzz*.bin; do
		python3 "$HERE/asm_roundtrip.py" "${img%.bin}.ghidra.txt" "$W/rt" | tail -1 >>"$W/rt.lines" || rc=1
	done
	read -r n same stops bad < <(sed -E 's/[^0-9]+/ /g' "$W/rt.lines" | awk '{n+=$1; s+=$2; t+=$3; b+=$4} END {print n, s, t, b}')
	echo "assembler round trip: $n instructions, $same identical, $stops STOP with a nonzero second byte (assembler writes 00), $bad mismatches"
	(( bad == 0 )) || rc=1
else
	echo "skipped assembler round trip: no rgbasm/rgblink on PATH"
fi
exit $rc
