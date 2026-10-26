#!/usr/bin/env python3
"""Union of several EveryEntry.java outputs: prints the constructors no run reached and
the reached/total line.   every_merge.py <out1> [out2 ...]"""
import sys
allk, seen, n = set(), set(), 0
for p in sys.argv[1:]:
    for line in open(p):
        if line.startswith("ALL "):
            allk.add(line[4:].strip())
        elif line.startswith("SEEN "):
            seen.add(line[5:].strip())
        elif line.startswith("every-entry:"):
            n += int(line.split()[1])
miss = sorted(allk - seen)
for k in miss:
    print("NOT REACHED " + k)
print("every-entry: %d decodes, %d/%d constructors reached, %d not reached"
      % (n, len(allk) - len(miss), len(allk), len(miss)))
