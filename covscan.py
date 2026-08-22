#!/usr/bin/env python3
"""Full coverage scan of a binary's .text vs objdump, with byte-exactness check."""
import re, subprocess, sys, os
from collections import Counter

BIN = sys.argv[1]
SPEC = "sleigh/x86-64.slaspec"
GHR = os.environ.get("CENTRIFUGE", "./build/centrifuge.exe")

r = subprocess.run(["objdump", "-d", BIN], capture_output=True, text=True, errors='replace')
lines = r.stdout.splitlines()

def parse(lines):
    ref = []
    i = 0
    while i < len(lines):
        m = re.match(r'\s*([0-9a-f]+):\t(.*)$', lines[i])
        if not m:
            i += 1
            continue
        addr = int(m.group(1), 16)
        # data bytes objdump itself cannot decode: not part of the oracle
        if '(bad)' in m.group(2):
            i += 1
            continue
        bts = []
        for field in m.group(2).split('\t'):
            f = field.strip()
            if f and re.fullmatch(r'(?:[0-9a-f]{2} )*[0-9a-f]{2}', f):
                bts.extend(f.split())
            else:
                break
        j = i + 1
        while j < len(lines):
            # objdump continuation: a bare address + bytes line with no
            # mnemonic text (first line shows at most 7 bytes)
            cm = re.match(r'\s*[0-9a-f]+:\t+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s*$', lines[j])
            if cm:
                bts.extend(cm.group(1).split())
                j += 1
            else:
                break
        ref.append((addr, bts, m.group(2)))
        i = j
    return ref

ref = parse(lines)
if not ref:
    print("no code found"); sys.exit(0)
start = ref[0][0]
end = ref[-1][0] + len(ref[-1][1])
print("%s: %d insns, %#x-%#x" % (os.path.basename(BIN), len(ref), start, end))

r = subprocess.run([GHR, "spec", SPEC, BIN, "disasm", hex(start), str(end - start), "--resume"],
                   capture_output=True, text=True)
dec = {}
gaps = []
for line in r.stdout.splitlines():
    if line.startswith('; GAP'):
        gaps.append(int(line.split()[2], 16))
        continue
    m = re.match(r'0x([0-9A-F]+)\s+((?:[0-9a-f]{2} )*)(.*)$', line)
    if m:
        dec[int(m.group(1), 16)] = (m.group(2).split(), m.group(3))

refset = set(a for a, _, _ in ref)
real_gaps = [a for a in gaps if a in refset]
mismatch = 0
checked = 0
for a, b, txt in ref:
    if a in dec:
        checked += 1
        if dec[a][0] != b:
            mismatch += 1
            if mismatch <= 3:
                print("  MISMATCH %#x: ours=%s ref=%s  %s" % (a, ' '.join(dec[a][0]), ' '.join(b), txt.strip().split('\t')[-1]))
cov = 100.0 * (len(ref) - len(real_gaps)) / len(ref)
print("coverage: %.4f%% (%d gaps), byte-mismatch: %d/%d" % (cov, len(real_gaps), mismatch, checked))
if real_gaps:
    mn = Counter()
    for a, b, txt in ref:
        if a in set(real_gaps):
            fields = txt.split('\t')
            mn[fields[-1].strip().split()[0]] += 1
    print("  gap mnemonics:", dict(mn.most_common(15)))
    if len(sys.argv) > 2 and sys.argv[2] == "--gaps":
        seen = set()
        for a, b, txt in ref:
            if a in set(real_gaps) and txt.split('\t')[-1].strip().split()[0] != '(bad)':
                key = ' '.join(b)
                if key in seen:
                    continue
                seen.add(key)
                print("  GAPBYTE %#x: %-34s %s" % (a, ' '.join(b), txt.split('\t')[-1].strip()))
