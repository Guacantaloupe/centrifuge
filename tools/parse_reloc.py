import sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck53\data\image.bin','rb').read()
# 手写 PE 解析: DOS header -> PE header -> optional header -> data directories
assert img[:2] == b'MZ'
pe_off = struct.unpack_from('<I', img, 0x3C)[0]
assert img[pe_off:pe_off+4] == b'PE\x00\x00'
opt_off = pe_off + 24
magic = struct.unpack_from('<H', img, opt_off)[0]
print('opt magic', hex(magic))
if magic == 0x20B:  # PE32+
    num_dd = struct.unpack_from('<I', img, opt_off + 108)[0]
    dd_off = opt_off + 112
else:
    num_dd = struct.unpack_from('<I', img, opt_off + 92)[0]
    dd_off = opt_off + 96
print('data directories:', num_dd)
# 目录 5 = reloc, 12 = IAT, 1 = import
for idx in [1, 5, 12]:
    rva, size = struct.unpack_from('<II', img, dd_off + idx*8)
    print(f'dir {idx}: rva={hex(rva)} size={hex(size)}')
# 节表
num_sections = struct.unpack_from('<H', img, pe_off + 6)[0]
sec_off = opt_off + (112 if magic == 0x20B else 96) + num_dd*8
print('sections:', num_sections)
sections = []
for i in range(num_sections):
    s = img[sec_off + i*40: sec_off + (i+1)*40]
    name = s[:8].decode('ascii', errors='replace').strip('\x00')
    vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', s, 8)
    sections.append((name, vaddr, vsize, roff, rsize))
    print(f'  {name}: vaddr={hex(vaddr)} vsize={hex(vsize)} roff={hex(roff)} rsize={hex(rsize)}')

def rva_to_off(rva):
    for name, vaddr, vsize, roff, rsize in sections:
        if vaddr <= rva < vaddr + max(vsize, rsize):
            return roff + (rva - vaddr)
    return None

reloc_rva = struct.unpack_from('<II', img, dd_off + 5*8)[0]
reloc_size = struct.unpack_from('<II', img, dd_off + 5*8 + 4)[0]
off = rva_to_off(reloc_rva)
print('reloc file off', hex(off) if off else None)
pos = 0
total = 0
blocks = 0
while pos < reloc_size:
    page_rva, block_size = struct.unpack_from('<II', img, off + pos)
    if block_size == 0 or block_size < 8:
        print('bad block at pos', hex(pos), 'page', hex(page_rva), 'size', block_size)
        break
    n = (block_size - 8) // 2
    total += n
    blocks += 1
    pos += block_size
print('blocks:', blocks, 'total entries:', total)
# 打印前 6 个条目
pos = 0
shown = 0
while pos < reloc_size and shown < 6:
    page_rva, block_size = struct.unpack_from('<II', img, off + pos)
    n = (block_size - 8) // 2
    for i in range(min(n, 3)):
        e = struct.unpack_from('<H', img, off + pos + 8 + i*2)[0]
        typ = e >> 12
        delta = e & 0xFFF
        print('  page', hex(page_rva), 'type', typ, 'delta', hex(delta), 'target', hex(page_rva + delta))
        shown += 1
    pos += block_size
