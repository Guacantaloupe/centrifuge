import re, subprocess, sys

def scan(BIN):
    r = subprocess.run(['objdump', '-d', BIN], capture_output=True, text=True, errors='replace')
    lines = r.stdout.splitlines()
    ref = []
    i = 0
    while i < len(lines):
        m = re.match(r'\s*([0-9a-f]+):\t(.*)$', lines[i])
        if not m:
            i += 1
            continue
        addr = int(m.group(1), 16)
        bts = []
        for field in m.group(2).split('\t'):
            f = field.strip()
            if f and re.fullmatch(r'(?:[0-9a-f]{2} )*[0-9a-f]{2}', f):
                bts.extend(f.split())
            else:
                break
        j = i + 1
        while j < len(lines):
            cm = re.match(r'\t+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s*$', lines[j])
            if cm:
                bts.extend(cm.group(1).split())
                j += 1
            else:
                break
        ref.append((addr, bts, m.group(2).split('\t')[-1].strip()))
        i = j
    ref = [(a, b, t) for a, b, t in ref if '(bad)' not in t and not t.startswith('rex')]
    if not ref:
        return
    start = ref[0][0]
    end = ref[-1][0] + len(ref[-1][1])
    rr = subprocess.run(['./build/centrifuge.exe', 'spec', 'sleigh/x86-64.slaspec', BIN,
                         'disasm', hex(start), str(end - start), '--resume'],
                        capture_output=True, text=True)
    gaps = set(int(l.split()[2], 16) for l in rr.stdout.splitlines() if l.startswith('; GAP'))
    seen = set()
    for a, b, t in ref:
        if a in gaps:
            key = ' '.join(b)
            if key in seen:
                continue
            seen.add(key)
            print('%s %#x: %-38s %s' % (BIN.split('\\')[-1], a, ' '.join(b), t))

for b in [r'C:\Windows\System32\ntdll.dll', r'C:\Windows\System32\msvcrt.dll']:
    scan(b)
