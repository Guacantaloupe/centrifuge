import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck54\data\image.bin','rb').read()
# 0x5d51bd6 (未对齐) 内容
off = 0x5d51bd6
print('0x145d51bd6 bytes:', img[off:off+16].hex())
# 对齐到 8
aligned = (off // 8) * 8
print('aligned 0x%x:' % (0x140000000 + aligned), hex(struct.unpack_from('<Q', img, aligned)[0]))
# 0x5d51bd6 是哪个导入槽? 查 metadata imports iat 范围
import re
src = open(r'build-recheck54\src\recovered_metadata.cpp', encoding='utf-8').read()
for m in re.finditer(r'\{"([^"]+)", "([^"]+)"[^}]*?(\d+)ULL', src):
    dll, name, iat = m.group(1), m.group(2), int(m.group(3))
    if abs(iat - (0x140000000 + 0x5d51bd6)) < 0x100:
        print('near', hex(iat), dll, name)
