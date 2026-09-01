import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck54\data\image.bin','rb').read()
# 0x145d40858 文件偏移 (image.bin 是完整 PE, roff = rva)
rva = 0x5d40858
print('0x145d40858 file val:', hex(struct.unpack_from('<Q', img, rva)[0]))
print('0x144bfc3b0 bytes:', img[0x4bfc3b0:0x4bfc3b8].hex())
# guard 槽指向 0x144bfc3b0 是 ff e0?
print('0x145d40858 -> target 0x144bfc3b0:', img[0x4bfc3b0:0x4bfc3b2].hex())
