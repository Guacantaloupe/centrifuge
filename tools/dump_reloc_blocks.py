import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'C:\Program Files\Blender Foundation\Blender 5.2\blender.exe','rb').read()
pe_off = struct.unpack_from('<I', img, 0x3C)[0]
opt_off = pe_off + 24
num_dd = struct.unpack_from('<I', img, opt_off + 108)[0]
dd_off = opt_off + 112
num_sections = struct.unpack_from('<H', img, pe_off + 6)[0]
sec_off = opt_off + 112 + num_dd*8
sections = []
for i in range(num_sections):
    s = img[sec_off + i*40: sec_off + (i+1)*40]
    name = s[:8].decode('ascii', errors='replace').strip('\x00')
    vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', s, 8)
    sections.append((name, vaddr, vsize, roff, rsize))
reloc_rva, reloc_size = struct.unpack_from('<II', img, dd_off + 5*8)
reloc_off = None
for name, vaddr, vsize, roff, rsize in sections:
    if vaddr <= reloc_rva < vaddr + max(vsize, rsize):
        reloc_off = roff + (reloc_rva - vaddr)
print('reloc rva', hex(reloc_rva), 'size', hex(reloc_size), 'off', hex(reloc_off))
pos = 0
for block_idx in range(3):
    page, bsize = struct.unpack_from('<II', img, reloc_off + pos)
    n = (bsize - 8) // 2
    # page 落在哪个节
    in_sec = 'NONE'
    for name, vaddr, vsize, roff, rsize in sections:
        if vaddr <= page < vaddr + max(vsize, rsize):
            in_sec = name
            break
    print('block', block_idx, 'page', hex(page), 'size', bsize, 'entries', n, '->', in_sec)
    # 第一条目目标
    e = struct.unpack_from('<H', img, reloc_off + pos + 8)[0]
    print('   first entry type', e >> 12, 'delta', hex(e & 0xFFF), 'target rva', hex(page + (e & 0xFFF)))
    pos += bsize
