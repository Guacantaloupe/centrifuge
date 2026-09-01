import struct, sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
img = open(r'build-recheck53\data\image.bin','rb').read()
off = 0x145d564c4 - 0x140000000
print('0x145d564c4 content:', hex(struct.unpack_from('<Q', img, off)[0]))
print('0x145d564c4 +8:', hex(struct.unpack_from('<Q', img, off+8)[0]))
src = open(r'build-recheck53\src\recovered_metadata.cpp', encoding='utf-8').read()
for m in re.finditer(r'\{"([^"]+)", "([^"]+)"[^}]*?(\d+)ULL', src):
    dll, name, iat = m.group(1), m.group(2), int(m.group(3))
    if abs(iat - 0x145d564c4) < 0x100:
        print('near', hex(iat), dll, name)
# 也检查 0x145d418c0 是否在 .rdata (检查 PE 节)
import pefile
pe = pefile.PE(r'build-recheck53\data\image.bin', fast_load=True)
for va in [0x145d418c0, 0x145d564c4, 0x145d51518]:
    rva = va - 0x140000000
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.Misc_VirtualSize:
            print(hex(va), 'in', s.Name.decode().strip('\x00'), 'rva', hex(rva))
            break
pe.close()
