#!/usr/bin/env bash
# SM83 module test suite.  Exits non-zero on any failure.
#   GHIDRA_INSTALL_DIR=<ghidra with this module installed> test/run-tests.sh [--upstream] [--real <workdir>]
# Steps: 1 the SLEIGH spec compiles; 2 the Java builds; 3 hand-computed emulator cases pass and a
# broken expectation is reported; 4 every SLEIGH constructor is reached; 5 decode differential
# against MAME's lr35902 disassembler (0 unexplained) and an RGBDS assembler round trip;
# --upstream: 6 the upstream JUnit suite (gradle; needs network access for its plugins the first time);
# --real <workdir>: 7 fetch/build the real-code samples (Mooneye test suite ROMs, GBDK-2020 programs),
# import each with auto-detection, analyse, decompile, compare with MAME; 8 symbol import and the
# SDCC calling convention check.
# Tools: unidasm (MAME), rgbasm/rgblink (RGBDS; --real builds them), JAVA_HOME with javac.
set -uo pipefail
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
UPSTREAM=0; REAL=""
while [[ ${1:-} == --* ]]; do
	case $1 in
	--upstream) UPSTREAM=1; shift ;;
	--real) REAL=$(readlink -m "${2:?--real needs a workdir}"); shift 2 ;;
	*) echo "unknown option $1" >&2; exit 2 ;;
	esac
done
W=$(mktemp -d "${TMPDIR:-/tmp}/sm83-tests.XXXXXX")
trap 'rm -rf "$W"' EXIT
fail=0
step() { echo; echo "### $*"; }
check() { if "$@"; then echo "ok"; else echo "FAILED: $*"; fail=1; fi; }

step "1 SLEIGH compile"
check "$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/sm83.slaspec" "$W/sm83.sla"
ls -l "$W/sm83.sla" | awk '{print "sm83.sla " $5 " bytes"}'

step "2 Java (loader, analyzers, userop library)"
check "$HERE/build-jar.sh"

step "3 emulator cases"
check "$HERE/emu-test.sh" "$W/emu"
check "$HERE/emu-test.sh" --broken "$W/emu"

step "4 every constructor reached"
check "$HERE/every-entry.sh" "$W/every.txt"

step "5 decode differential vs MAME, assembler round trip vs RGBDS"
[[ -n $REAL && -x $REAL/rgbds/bin/rgbasm ]] && export PATH=$REAL/rgbds/bin:$PATH
check "$HERE/run-decode.sh" "$W/dec" 65536 1

if (( UPSTREAM )); then
	step "6 upstream JUnit suite (gradle test)"
	check bash -c "cd '$MOD' && ./gradlew test --no-daemon -q"
fi

if [[ -n $REAL ]]; then
	step "7 real code"
	check "$HERE/fetch-samples.sh" "$REAL"
	export PATH=$REAL/rgbds/bin:$PATH
	# JOBS=<n> real-code imports at a time (default 2)
	mkdir -p "$W/real"
	find "$REAL/mooneye" "$REAL/gbdk" \( -name '*.gb' -o -name '*.gbc' \) | sort >"$W/roms.txt"
	xargs -a "$W/roms.txt" -P "${JOBS:-2}" -I{} sh -c \
		'"$1/real-check.sh" "$2" "$3/real" 30 >"$3/real/$(basename "$2").log" 2>&1 || echo "FAILED: $(basename "$2")"' _ "$HERE" {} "$W"
	tot=$(wc -l <"$W/roms.txt"); bad=$(grep -l "^bad instruction in an executable\|^wrong language\|^UNEXPLAINED" "$W"/real/*.log 2>/dev/null | wc -l)
	missing=$(for r in $(cat "$W/roms.txt"); do [[ -f $W/real/$(basename "$r").summary ]] || echo "$r"; done | wc -l)
	unexpl=$(cat "$W"/real/*.cmp | grep -c "^UNEXPLAINED" || true)
	echo "real code: $tot ROMs, $bad failed, $missing without a result, $unexpl instructions unexplained vs MAME"
	(( bad == 0 && missing == 0 && unexpl == 0 )) || fail=1
	cat "$W"/real/*.summary | awk '/^functions:/ {f+=$2} /^instructions:/ {i+=$2} /^bad-instruction bookmarks:/ {b+=$3} /^error bookmarks:/ {e+=$3} /^decompile:/ {ok+=$2; fl+=$4; to+=$6} END {print "totals: " i " instructions, " f " functions, " b " bad-instruction bookmarks (explained or not), " e " error bookmarks, decompile " ok " ok / " fl " failed / " to " timed out"}'
	cat "$W"/real/*.log | grep -h "^explained bad-instruction" | awk '{n+=$4; b+=$7; r+=$11; u+=$NF} END {print "bad-instruction bookmarks: " n " repeated-NOP limit, " b " unresolved bank flows, " r " past the end of a copied RAM routine, " u " unexplained"}'
	cat "$W"/real/*.cmp | grep -h " vs MAME:" | sed -E 's/.*instructions in [0-9]+ runs vs MAME: //' | tr -d ',' | awk '{e+=$2; s+=$4; u+=$8} END {print "vs MAME: " e " exact, " s " semantic, " u " unexplained"}'
	step "8 symbol import, SDCC calling convention"
	check "$HERE/symbol-check.sh" "$REAL/mooneye-src/build/acceptance/instr/daa.gb" "$REAL/mooneye-src/build/acceptance/instr/daa.sym"
	check "$HERE/conv-check.sh" "$REAL/gbdk/conv.gb" "$REAL/gbdk/conv.noi"
fi

echo
if (( fail )); then echo "SOME TESTS FAILED"; exit 1; fi
echo "all tests passed"
