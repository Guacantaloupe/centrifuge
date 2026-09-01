import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck54\data\image.bin','rb').read()
off = 125028416
size = 284672
chunk = img[off:off+size]
nz = sum(1 for b in chunk if b != 0)
print('image.bin .reloc nonzero:', nz, 'of', size)
print('first 32:', chunk[:32].hex())
# 解析 reloc 表
pos = 0
total = 0
while pos < size:
    page_rva, block_size = struct.unpack_from('<II', chunk, pos)
    if block_size == 0 or block_size < 8:
        print('bad block at', pos, hex(page_rva), block_size)
        break
    n = (block_size - 8) // 2
    total += n
    pos += block_size
print('blocks total entries:', total)
