import struct

code = bytes.fromhex('0f01d08bc0c390')
elf = bytearray(0x400)
elf[0:4] = b'\x7fELF'
elf[4] = 2
elf[5] = 1
elf[6] = 1
struct.pack_into('<H', elf, 0x10, 2)  # e_type = ET_EXEC
elf[0x12] = 0x3e
struct.pack_into('<Q', elf, 0x18, 0x400078)
struct.pack_into('<Q', elf, 0x28, 0x40)
elf[0x36] = 1
elf[0x38] = 0x38
ph = 0x40
struct.pack_into('<I', elf, ph, 1)
struct.pack_into('<I', elf, ph + 4, 5)
struct.pack_into('<Q', elf, ph + 8, 0)
struct.pack_into('<Q', elf, ph + 16, 0x400000)
struct.pack_into('<Q', elf, ph + 24, 0x400)
struct.pack_into('<Q', elf, ph + 32, 0x400)
struct.pack_into('<Q', elf, ph + 40, 0x1000)
elf[0x100:0x100 + len(code)] = code
open('t.bin', 'wb').write(elf)
print('ok')
