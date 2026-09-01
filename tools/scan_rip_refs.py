"""Fast rip-relative scan: single pass over .text, candidate modrm check, numpy-free."""
import struct, sys, time

blob = open(r'build-recheck52\data\image.bin', 'rb').read()
pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
coff = pe_off + 4
nsec = struct.unpack_from('<H', blob, coff+2)[0]
opt = coff + 20
magic = struct.unpack_from('<H', blob, opt)[0]
is64 = magic == 0x20B
sec_off = opt + (240 if is64 else 208)
sections = []
for i in range(nsec):
    off = sec_off + i*40
    name = blob[off:off+8].rstrip(b'\0').decode('latin1')
    vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', blob, off+8)
    sections.append((name, vaddr, roff, rsize))
text = next(s for s in sections if s[0] == '.text')
vaddr, roff, rsize = text[1], text[2], text[3]
code = blob[roff:roff+rsize]

targets = [int(a, 16) for a in sys.argv[1:]]
t0 = time.time()
# code VA = img_base + section.vaddr + i (code starts at file offset roff == section start)
img_base = struct.unpack_from('<Q', blob, opt+24)[0] if is64 else struct.unpack_from('<I', blob, opt+28)[0]
base_va = img_base + vaddr
# build a set of (disp32 signed int) -> for each target, allowed disps depend on next_rip,
# so instead: for each candidate byte offset, compute ea for len 6 and 7 and test membership.
tset = set(targets)
hits = {t: [] for t in targets}
n = len(code)
for i in range(n - 7):
    b0 = code[i]
    # len6 candidate: opcode at i, modrm at i+1 (only if i not a REX prefix byte)
    modrm = code[i+1]
    if (modrm & 0xC7) == 0x05 and not (0x40 <= b0 <= 0x4F):
        disp = struct.unpack_from('<i', code, i+2)[0]
        ea = (base_va + i + 6 + disp) & 0xFFFFFFFFFFFFFFFF
        if ea in tset:
            hits[ea].append((vaddr + i, 6, b0, 0))
    # len7 candidate: REX at i, opcode at i+1, modrm at i+2
    if 0x40 <= b0 <= 0x4F:
        modrm = code[i+2]
        if (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from('<i', code, i+3)[0]
            ea = (base_va + i + 7 + disp) & 0xFFFFFFFFFFFFFFFF
            if ea in tset:
                hits[ea].append((vaddr + i, 7, code[i+1], b0))
for t in targets:
    print(f'refs to {t:#x}: {len(hits[t])}')
    for h, ln, op, rex in hits[t][:60]:
        print(f'  {h:#x} len={ln} op={op:02x} rex={rex:02x}')
print(f'scanned {n} bytes in {time.time()-t0:.1f}s')
