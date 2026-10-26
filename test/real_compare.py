#!/usr/bin/env python3
"""Compare Ghidra's analysed instruction stream with MAME's unidasm (lr35902).
usage: real_compare.py <listing> <name>
<listing> is RealCheck.java's "<block> <addr> <bytes> <text>" file.  Each maximal run of
contiguous instructions is written to a file, disassembled linearly by unidasm at the same base
address, and compared instruction by instruction (compare.classify), so a length or decoding
disagreement shows as a desynchronised run.  Prints one summary line last; exit 1 if anything
is unexplained."""
import os, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import compare
listing, name = sys.argv[1], sys.argv[2]
UNIDASM = os.environ.get('UNIDASM', 'unidasm')
rows = []
for l in open(listing):
    blk, addr, hexs, text = l.rstrip('\n').split(' ', 3)
    rows.append((blk, int(addr, 16), bytes.fromhex(hexs), text))
runs, cur = [], []
for r in rows:
    if cur and (r[0] != cur[-1][0] or r[1] != cur[-1][1] + len(cur[-1][2])):
        runs.append(cur); cur = []
    cur.append(r)
if cur:
    runs.append(cur)
res = {'exact': 0, 'semantic': 0, 'both-invalid': 0, 'unexplained': 0}
unexp = []
with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as td:
    for i, run in enumerate(runs):
        f = os.path.join(td, 'r.bin')
        open(f, 'wb').write(b''.join(r[2] for r in run))
        out = subprocess.run([UNIDASM, f, '-arch', 'lr35902', '-basepc', '%x' % run[0][1]],
                             capture_output=True, text=True).stdout.splitlines()
        mame = {}
        for l in out:
            a, rest = l.split(':', 1)
            mame[int(a, 16)] = rest
        for blk, addr, b, text in run:
            if addr not in mame:
                res['unexplained'] += 1; unexp.append((blk, addr, text, 'MAME desynchronised'))
                continue
            cls, _ = compare.classify(text, len(b), mame[addr])
            res[cls] += 1
            if cls == 'unexplained':
                unexp.append((blk, addr, text, mame[addr].strip()))
for u in unexp[:30]:
    print('UNEXPLAINED %s:%04x ghidra: %s | mame: %s' % u)
print('%s: %d instructions in %d runs vs MAME: exact %d, semantic %d, both-invalid %d, unexplained %d' % (
    name, len(rows), len(runs), res['exact'], res['semantic'], res['both-invalid'], res['unexplained']))
sys.exit(1 if res['unexplained'] else 0)
