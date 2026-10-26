#!/usr/bin/env python3
"""Decode corpora for the SM83 differential.  Slot = 6 bytes: up to 3 instruction bytes then
zeros (NOPs), so a contiguous MAME disassembly resynchronises at every slot start even when a
stray operand byte looks like a 3-byte instruction.  The 16-bit address space holds 10,900 slots
per image, so large corpora are written as several images (<name>N.bin).
  table  : every first byte x 7 operand patterns, plus every CB-prefixed second byte x 2
  pairs  : every (first byte, second byte) with a third byte derived from both
  imm16  : the 3-byte load/store/jump forms with every high operand byte
  fuzz   : N random 3-byte slots
usage: gen_corpus.py <outdir> [nfuzz] [seed]"""
import os, random, sys
STRIDE = 6
PER = 10900
out = sys.argv[1]
nfuzz = int(sys.argv[2]) if len(sys.argv) > 2 else 65536
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
os.makedirs(out, exist_ok=True)
def slot(*b):
    return bytes(b).ljust(STRIDE, b'\0')
def write(name, slots):
    n = 0
    for i in range(0, len(slots), PER):
        open(os.path.join(out, '%s%d.bin' % (name, n)), 'wb').write(b''.join(slots[i:i + PER]))
        n += 1
    return n
pats = [(0x00, 0x00), (0x01, 0x02), (0x7f, 0x80), (0x80, 0xff), (0xff, 0xfe), (0x0f, 0xf0), (0xa5, 0x5a)]
t = [slot(op, x, y) for op in range(256) for x, y in pats]
t += [slot(0xcb, sub, x) for sub in range(256) for x in (0x00, 0xff)]
pairs = [slot(op, b1, (op * 7 + b1 * 13) & 0xff) for op in range(256) for b1 in range(256)]
imm = [slot(op, lo, hi) for op in (0x01, 0x11, 0x21, 0x31, 0x08, 0xc2, 0xc3, 0xc4, 0xca, 0xcc, 0xcd,
                                   0xd2, 0xd4, 0xda, 0xdc, 0xea, 0xfa)
       for hi in range(256) for lo in (0x00, 0x5a, 0xff)]
r = random.Random(seed)
fuzz = [slot(r.randrange(256), r.randrange(256), r.randrange(256)) for _ in range(nfuzz)]
counts = {k: write(k, v) for k, v in (('table', t), ('pairs', pairs), ('imm16', imm), ('fuzz', fuzz))}
print(' '.join('%s=%d' % kv for kv in counts.items()))
