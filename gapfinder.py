#!/usr/bin/env python3
"""Probe every objdump instruction boundary and report undecodable ones."""
import re, subprocess, sys
from collections import Counter

SPEC = "sleigh/x86-64.slaspec"
BIN = r"C:\Windows\System32\kernel32.dll"
REF = r"%s" % sys.argv[1] if len(sys.argv) > 1 else None
GHR = "./build/centrifuge.exe"

ref = []
for line in open(REF, errors='replace'):
    line = line.rstrip()
    m = re.match(r'\s*([0-9a-f]+):\t(.*)$', line)
    if not m:
        continue
    addr = int(m.group(1), 16)
    bts = []
    for field in m.group(2).split('\t'):
        f = field.strip()
        if f and re.fullmatch(r'(?:[0-9a-f]{2} )*[0-9a-f]{2}', f):
            bts.extend(f.split())
        else:
            break
    ref.append((addr, bts))

gaps = []
ok = 0
for addr, bts in ref:
    r = subprocess.run([GHR, "spec", SPEC, BIN, "disasm", hex(addr), "1"],
                       capture_output=True, text=True)
    if "undecodable" in r.stdout or "no constructors" in r.stdout:
        gaps.append((addr, bts))
    else:
        ok += 1
print("decodable: %d/%d (%.1f%%)" % (ok, len(ref), 100.0 * ok / len(ref)))
print("--- first 40 gaps ---")
for addr, bts in gaps[:40]:
    print("%#x: %s" % (addr, " ".join(bts)))
# mnemonic frequency of gaps (objdump's text)
mn = Counter()
for line in open(REF, errors='replace'):
    m = re.match(r'\s*([0-9a-f]+):\t.*\t(\S+)', line)
    if m and int(m.group(1), 16) in [g[0] for g in gaps]:
        mn[m.group(2)] += 1
print("--- gap mnemonics ---")
for name, c in mn.most_common(25):
    print("  %-12s %d" % (name, c))
