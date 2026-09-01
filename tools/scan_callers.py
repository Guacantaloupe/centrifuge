"""Find direct E8/E9 callers of a target VA in .text."""
import struct, sys

blob = open(r'build-recheck52\data\image.bin', 'rb').read()
pe_off = struct.unpack_from('<I', blob, 0x3C)[0]
coff = pe_off + 4
nsec = struct.unpack_from('<H', blob, coff+2)[0]
opt = coff + 20
magic = struct.unpack_from('<H', blob, opt)[0]
is64 = magic == 0x20B
img_base = struct.unpack_from('<Q', blob, opt+24)[0] if is64 else struct.unpack_from('<I', blob, opt+28)[0]
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
base_va = img_base + vaddr

target = int(sys.argv[1], 16)
hits = []
for i in range(len(code) - 5):
    b0 = code[i]
    if b0 in (0xE8, 0xE9):  # call/jmp rel32
        rel = struct.unpack_from('<i', code, i+1)[0]
        dest = (base_va + i + 5 + rel) & 0xFFFFFFFFFFFFFFFF
        if dest == target:
            hits.append(base_va + i)
print(f'callers of {target:#x}: {len(hits)}')
for h in hits:
    kind = 'call' if (code[h - base_va + roff - 1] == 0xE8) else 'jmp'
    print(f'  {h:#x} ({kind})')
