import re, subprocess, sys

BIN = sys.argv[1]
GHR = "./build/centrifuge.exe"
SPEC = "sleigh/x86-64.slaspec"

# objdump refset
r = subprocess.run(["objdump", "-d", BIN], capture_output=True, text=True, errors='replace')
refset = set()
cur = None
for line in r.stdout.splitlines():
    m = re.match(r'\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s+(\S+)', line)
    if m:
        addr = int(m.group(1), 16)
        refset.add(addr)

# find all .text ranges from our own disasm run
r2 = subprocess.run([GHR, "spec", SPEC, BIN, "disasm", "0x0", "0xffffffff", "--resume"],
                    capture_output=True, text=True, errors='replace')
gaps = []
for line in r2.stdout.splitlines():
    m = re.match(r'; GAP\s+0x([0-9a-fA-F]+)', line)
    if m:
        gaps.append(int(m.group(1), 16))

real = [a for a in gaps if a in refset]
print("total gaps:", len(gaps), "real gaps:", len(real))
for a in real:
    print("GAP 0x%x" % a)
