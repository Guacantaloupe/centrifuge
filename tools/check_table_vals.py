import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck54\data\image.bin','rb').read()
# 0x145d418d0 相对 .rdata (vaddr 0x4c11000, blob_offset 79755264)
rel = 0x145d418d0 - 0x144c11000
print('rel', hex(rel))
print('value:', hex(struct.unpack_from('<Q', img, 79755264 + rel)[0]))
# 0x145d418c0
rel2 = 0x145d418c0 - 0x144c11000
print('0x145d418c0 value:', hex(struct.unpack_from('<Q', img, 79755264 + rel2)[0]))
# 0x145d418c8
rel3 = 0x145d418c8 - 0x144c11000
print('0x145d418c8 value:', hex(struct.unpack_from('<Q', img, 79755264 + rel3)[0]))
# 0x145d40858 (guard)
rel4 = 0x145d40858 - 0x144c11000
print('0x145d40858 value:', hex(struct.unpack_from('<Q', img, 79755264 + rel4)[0]))
