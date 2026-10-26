#!/usr/bin/env python3
"""Assemble Ghidra's own disassembly text with RGBDS and compare the bytes with the original.
usage: asm_roundtrip.py <ghidra-slot-listing> <workdir>
The listing is DumpDisasm.java output for a gen_corpus.py image (stride 6).  Every decodable slot's
text is turned into RGBDS syntax (square-bracket indirection), assembled into a ROM0 section at
the slot's own address (so relative jumps and absolute targets mean the same), linked flat, and
the bytes at each slot compared with the instruction bytes.  Exit 1 on any mismatch."""
import os, re, subprocess, sys
lst, work = sys.argv[1], sys.argv[2]
RGBASM = os.environ.get('RGBASM', 'rgbasm'); RGBLINK = os.environ.get('RGBLINK', 'rgblink')
os.makedirs(work, exist_ok=True)
rows = []
for l in open(lst):
    off, hexs, text = l.rstrip('\n').split(' ', 2)
    if hexs == '-':
        continue
    rows.append((int(off, 16), hexs, text))
def rgbds(t):
    t = re.sub(r'\(([^()]*)\)', r'[\1]', t)
    # Ghidra writes JR targets as absolute addresses, RGBDS wants the same absolute label
    return t.lower()
seen = {}
for off, hexs, text in rows:
    seen.setdefault(off, (hexs, text))
src = ['SECTION "slot%d", %s[$%04x]\n    %s\n' % (i, 'ROM0' if off < 0x4000 else 'ROMX', off, rgbds(text))
       for i, (off, (hexs, text)) in enumerate(sorted(seen.items())) if off + 3 <= 0x8000]
# ROM0 and bank 1 hold 5461 slots of 6 bytes
a, o, b = (os.path.join(work, n) for n in ('rt.asm', 'rt.o', 'rt.bin'))
open(a, 'w').write(''.join(src))
r = subprocess.run([RGBASM, '-o', o, a], capture_output=True, text=True)
if r.returncode:
    print(r.stderr[:3000]); sys.exit(1)
r = subprocess.run([RGBLINK, '-x', '-o', b, o], capture_output=True, text=True)
if r.returncode:
    print(r.stderr[:2000]); sys.exit(1)
img = open(b, 'rb').read()
bad = 0; n = 0; stop = 0
for off, (hexs, text) in sorted(seen.items()):
    if off + 3 > 0x8000:
        continue
    want = bytes.fromhex(hexs)
    got = img[off:off + len(want)]
    n += 1
    # STOP ignores its second byte; the assembler always writes 00 (explained)
    if text == 'STOP' and got[:1] == want[:1] and got[1:] == b'\x00':
        stop += 1
        continue
    if got != want:
        bad += 1
        if bad <= 20:
            print('MISMATCH %04x %s: assembled %s, original %s' % (off, text, got.hex(), want.hex()))
print('assembler round trip: %d instructions, %d identical, %d STOP with a nonzero second byte (assembler writes 00), %d mismatches' % (n, n - bad - stop, stop, bad))
sys.exit(1 if bad else 0)
