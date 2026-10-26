#!/usr/bin/env bash
# Fetch and build the real-code samples (never committed).  Everything is pinned by URL and
# SHA-256, built from public source with free toolchains:
#   RGBDS 1.0.1            (MIT)     assembler for the round-trip oracle
#   WLA-DX 10.5            (GPL-2)   assembler the Mooneye suite uses
#   Mooneye test suite     (MIT)     115 hardware test ROMs, assembled from source
#   GBDK-2020 4.5.0        (MIT/GPL mix; ships SDCC) C compiler, example programs + test/c/conv.c
# needs: curl, cmake, a C/C++ compiler, make, bison and libpng-dev (for RGBDS), tar.
#   test/fetch-samples.sh <workdir>   -> <workdir>/{rgbds/bin,wla-dx/bin,mooneye/*.gb,gbdk/*.gb}
set -euo pipefail
W=$(readlink -m "$1")
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$W/src"
fetch() {   # <url> <file> <sha256>
	local url=$1 f=$W/src/$2 sum=$3
	if [[ ! -f $f ]] || ! echo "$sum  $f" | sha256sum -c --status; then
		curl -fsSL -o "$f.part" "$url"
		echo "$sum  $f.part" | sha256sum -c --status || { echo "SHA-256 mismatch: $2" >&2; exit 1; }
		mv "$f.part" "$f"
	fi
}
unpack() {  # <file> <dir>
	[[ -d $W/$2 ]] || { mkdir -p "$W/$2.part" && tar xzf "$W/src/$1" -C "$W/$2.part" --strip-components=1 && mv "$W/$2.part" "$W/$2"; }
}
fetch https://github.com/gbdev/rgbds/archive/refs/tags/v1.0.1.tar.gz rgbds-1.0.1.tar.gz \
	193469d38229a653bb33a25ebb73fd0ae33da4be80191d83bce8d427d23b7704
fetch https://github.com/vhelin/wla-dx/archive/refs/tags/v10.5.tar.gz wla-dx-10.5.tar.gz \
	b2d093c3c46caa399ed3a8e5f18f1f0eb7aefa958755bec752f2806bad3af802
fetch https://github.com/Gekkio/mooneye-test-suite/archive/31510e12eea6286d36eea060a6adde755e1067aa.tar.gz mooneye.tar.gz \
	07a253c65320abdefaf0da4290562c7318309d1945e3a2fb282292660e635674
fetch https://github.com/gbdk-2020/gbdk-2020/releases/download/4.5.0/gbdk-linux64.tar.gz gbdk-linux64.tar.gz \
	d7857a5f6d135ee4c249043ca26aad9f2ec8ab5d4106d97720d404114f42605c

if [[ ! -x $W/rgbds/bin/rgbasm ]]; then
	unpack rgbds-1.0.1.tar.gz rgbds-src
	cmake -S "$W/rgbds-src" -B "$W/rgbds-src/build" -DCMAKE_INSTALL_PREFIX="$W/rgbds" -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null
	cmake --build "$W/rgbds-src/build" -j"$(nproc)" >/dev/null
	cmake --install "$W/rgbds-src/build" >/dev/null
fi
if [[ ! -x $W/wla-dx/bin/wla-gb ]]; then
	unpack wla-dx-10.5.tar.gz wla-src
	cmake -S "$W/wla-src" -B "$W/wla-src/build" -DCMAKE_INSTALL_PREFIX="$W/wla-dx" -DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_POLICY_VERSION_MINIMUM=3.5 >/dev/null
	cmake --build "$W/wla-src/build" -j"$(nproc)" >/dev/null
	cmake --install "$W/wla-src/build" >/dev/null
fi
if [[ ! -d $W/mooneye ]]; then
	unpack mooneye.tar.gz mooneye-src
	(cd "$W/mooneye-src" && PATH=$W/wla-dx/bin:$PATH make -j"$(nproc)" >/dev/null)
	mkdir -p "$W/mooneye.part"
	# flatten build/<dir>/<name>.gb to <dir>_<name>.gb
	(cd "$W/mooneye-src/build" && find . -name '*.gb' | sort | while read -r f; do
		cp "$f" "$W/mooneye.part/$(echo "${f#./}" | tr / _)"
	done)
	mv "$W/mooneye.part" "$W/mooneye"
fi
if [[ ! -d $W/gbdk ]]; then
	unpack gbdk-linux64.tar.gz gbdk-dist
	export GBDK_HOME=$W/gbdk-dist
	mkdir -p "$W/gbdk.part"
	# single-directory examples (lcc compiles all their C files) and the cross-platform ones (make)
	for e in comm crash filltest galaxy gbtype hram lcd_isr_wobble linkerfile mbc3_rtc mbc5_rumble \
		mbc7_accelerometer paint rand rpn sgb_pong sgb_sfx sound template_minimal template_subfolders; do
		d=$GBDK_HOME/examples/gb/$e
		srcs=$(find "$d" -maxdepth 2 -name '*.c' -not -path '*/obj/*' -not -path '*/build/*' | sort)
		"$GBDK_HOME/bin/lcc" -I"$d" -I"$d/src" -Wl-m -Wl-j -o "$W/gbdk.part/$e.gb" $srcs >/dev/null 2>&1 || echo "skipped example $e"
	done
	"$GBDK_HOME/bin/lcc" -Wl-m -Wl-j -o "$W/gbdk.part/conv.gb" "$HERE/c/conv.c" >/dev/null
	for e in banks banks_autobank banks_farptr banks_nonintrinsic bcd emu_debug fonts irq joytest large_map \
		libc_memcpy libc_string metasprites pong platformer_template randtest rle_map scroller simple_physics \
		sram_banks text_advanced_dialogue text_basic; do
		rm -rf "$W/gbdk-xp-$e" && cp -r "$GBDK_HOME/examples/cross-platform/$e" "$W/gbdk-xp-$e"
		(cd "$W/gbdk-xp-$e" && rm -rf build obj && make gb gbc >/dev/null 2>&1) || { echo "skipped example $e"; rm -rf "$W/gbdk-xp-$e"; continue; }
		for f in "$W/gbdk-xp-$e"/build/gb/*.gb; do cp "$f" "$W/gbdk.part/xp_$e.gb"; done
		for f in "$W/gbdk-xp-$e"/build/gbc/*.gbc; do cp "$f" "$W/gbdk.part/xp_$e.gbc"; done
		rm -rf "$W/gbdk-xp-$e"
	done
	mv "$W/gbdk.part" "$W/gbdk"
fi
echo "samples ready in $W: $(ls "$W/mooneye"/*.gb | wc -l) Mooneye ROMs, $(ls "$W/gbdk" | wc -l) GBDK ROMs"
