#!/usr/bin/env python3
"""Compare Ghidra's slot disassembly with MAME's `unidasm -arch lr35902` on a slot corpus.
usage: compare.py <ghidra.txt> <mame.txt> [stride=6]
Classes: exact (same text apart from case/spacing/number base), semantic (same instruction,
different spelling: implicit 'a,' operand, LDH vs LD, signed vs unsigned SP offsets, ...),
both-invalid (MAME 'db', Ghidra no constructor), unexplained.  Exits 1 on any unexplained.
Also used as a library by real_compare.py (classify)."""
import re, sys

def canon(t):
    t = t.strip().lower()
    t = re.sub(r'\s+', ' ', t)
    t = re.sub(r'\s*,\s*', ',', t)
    return re.sub(r'\$[0-9a-f]+|0x[0-9a-f]+', lambda m: str(int(m.group(0).replace('$', '0x'), 16)), t)

def parse_mame(line):
    m = re.match(r'((?:[0-9a-f]{2} )+)\s*(.*)', line.strip())
    return len(m.group(1).split()), m.group(2)

def semantic(t):
    """Rewrite one of the two spellings of the same instruction into the other's."""
    t = re.sub(r'^(add|adc|sbc) a,', r'\1 ', t)          # MAME writes the accumulator out
    t = re.sub(r'^ldh ', 'ld ', t)                       # LDH is LD with an 0xFF00-page operand
    t = re.sub(r'^jp hl$', 'jp (hl)', t)
    t = re.sub(r'^stop \d+$', 'stop', t)                 # STOP's padding byte is shown by MAME
    t = t.replace('(65280+c)', '(c)')                    # MAME spells ($FF00+C) out
    # MAME prints JR targets unwrapped (a backward jump near 0 gives $FFFFFFxx); the CPU wraps at 16 bits
    t = re.sub(r'^(jr (?:n?[zc],)?)(\d+)$', lambda m: m.group(1) + str(int(m.group(2)) & 0xffff), t)
    # SP offsets: Ghidra shows them signed, MAME as the unsigned byte
    m = re.match(r'(add sp,|ld hl,sp\+)(-?\d+)$', t)
    if m:
        t = m.group(1) + str(int(m.group(2)) & 0xff)
    m = re.match(r'ld hl,sp-(\d+)$', t)
    if m:
        t = 'ld hl,sp+%d' % ((-int(m.group(1))) & 0xff)
    return t

def classify(gtext, glen, mline):
    """'exact', 'semantic', 'both-invalid' or 'unexplained' for one instruction.
    gtext: Ghidra's text (None when undecodable); mline: MAME's output line after the address."""
    mlen, mt = parse_mame(mline)
    minv = mt.startswith('db ')
    if gtext is None and minv:
        return 'both-invalid', None
    if gtext is None or minv or glen != mlen:
        return 'unexplained', None
    g, m = canon(gtext), canon(mt)
    if g == m:
        return 'exact', None
    if semantic(g) == semantic(m):
        key = tuple(re.sub(r'(?<=[ ,(])(?:[abcdehl]|bc|de|hl)(?=$|[,)])', 'R', re.sub(r'\d+', 'N', x))
                    for x in (g, m))
        return 'semantic', key
    return 'unexplained', None

if __name__ == '__main__':
    gfile, mfile = sys.argv[1], sys.argv[2]
    stride = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    mame = {}
    for l in open(mfile):
        a, rest = l.split(':', 1)
        mame[int(a, 16)] = rest.rstrip('\n')
    res = {'exact': 0, 'semantic': 0, 'both-invalid': 0, 'unexplained': 0}
    unexp, sem_classes = [], {}
    for l in open(gfile):
        off_s, rest = l.rstrip('\n').split(' ', 1)
        off = int(off_s, 16)
        if off % stride:
            continue
        bad = rest.startswith('- BAD')
        gt = None if bad else rest.split(' ', 1)
        cls, key = classify(None if bad else gt[1], 0 if bad else len(gt[0]) // 2, mame[off])
        res[cls] += 1
        if cls == 'semantic':
            sem_classes[key] = sem_classes.get(key, 0) + 1
        elif cls == 'unexplained':
            unexp.append((off, rest, mame[off]))
    print('slots %d: exact %d, semantic %d, both-invalid %d, unexplained %d' % (
        sum(res.values()), res['exact'], res['semantic'], res['both-invalid'], res['unexplained']))
    for (g, m), n in sorted(sem_classes.items(), key=lambda x: -x[1])[:40]:
        print('  semantic class %-26s ~ %-26s %d' % (g, m, n))
    for u in unexp[:40]:
        print('UNEXPLAINED %06x  ghidra: %s | mame: %s' % u)
    sys.exit(1 if unexp else 0)
