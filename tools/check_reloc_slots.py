import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck54\data\image.bin','rb').read()
# reloc 表在 image.bin 的 .reloc 区 (blob offset 125028416)
off = 125028416
size = 284672
chunk = img[off:off+size]
# 找包含 0x5d40858 或 0x5d418c0 的条目
pos = 0
found = {}
while pos + 8 <= size:
    page, bsize = struct.unpack_from('<II', chunk, pos)
    if bsize < 8 or pos + bsize > size: break
    n = (bsize - 8) // 2
    for i in range(n):
        e = struct.unpack_from('<H', chunk, pos + 8 + i*2)[0]
        typ = e >> 12
        delta = e & 0xFFF
        target = page + delta
        if target in (0x5d40858, 0x5d418c0, 0x5d418c8):
            found[target] = (typ, page)
    pos += bsize
print('reloc entries for our slots:', {hex(k): v for k, v in found.items()})
# 也找 page 范围
pages = set()
pos = 0
while pos + 8 <= size:
    page, bsize = struct.unpack_from('<II', chunk, pos)
    if bsize < 8 or pos + bsize > size: break
    pages.add(page)
    pos += bsize
print('pages:', len(pages), 'min', hex(min(pages)), 'max', hex(max(pages)))
