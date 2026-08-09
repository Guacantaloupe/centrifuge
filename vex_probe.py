import struct, subprocess

def make_elf(code: bytes, path='t2.bin'):
    elf = bytearray(0x800)
    elf[0:4] = b'\x7fELF'
    elf[4] = 2; elf[5] = 1; elf[6] = 1
    struct.pack_into('<H', elf, 0x10, 2)
    struct.pack_into('<H', elf, 0x12, 0x3e)
    struct.pack_into('<I', elf, 0x14, 1)
    struct.pack_into('<Q', elf, 0x18, 0x400078)
    struct.pack_into('<Q', elf, 0x20, 0x40)
    struct.pack_into('<Q', elf, 0x28, 0x200)
    struct.pack_into('<I', elf, 0x30, 0)
    struct.pack_into('<H', elf, 0x34, 0x40)
    struct.pack_into('<H', elf, 0x36, 0x38)
    struct.pack_into('<H', elf, 0x38, 1)
    struct.pack_into('<H', elf, 0x3a, 0x40)
    struct.pack_into('<H', elf, 0x3c, 3)
    struct.pack_into('<H', elf, 0x3e, 2)
    ph = 0x40
    struct.pack_into('<I', elf, ph, 1)
    struct.pack_into('<I', elf, ph + 4, 5)
    struct.pack_into('<Q', elf, ph + 8, 0)
    struct.pack_into('<Q', elf, ph + 16, 0x400000)
    struct.pack_into('<Q', elf, ph + 24, 0x400)
    struct.pack_into('<Q', elf, ph + 32, 0x400)
    struct.pack_into('<Q', elf, ph + 40, 0x1000)
    sh = 0x200
    # shdr[1] .text
    struct.pack_into('<I', elf, sh + 0x40, 1)
    struct.pack_into('<I', elf, sh + 0x44, 1)
    struct.pack_into('<Q', elf, sh + 0x48, 6)
    struct.pack_into('<Q', elf, sh + 0x50, 0x400000)
    struct.pack_into('<Q', elf, sh + 0x58, 0x100)
    struct.pack_into('<Q', elf, sh + 0x60, len(code))
    struct.pack_into('<I', elf, sh + 0x6c, 16)
    # shdr[2] .shstrtab
    struct.pack_into('<I', elf, sh + 0x80, 7)
    struct.pack_into('<I', elf, sh + 0x84, 3)
    struct.pack_into('<Q', elf, sh + 0x90, 0x300)
    struct.pack_into('<Q', elf, sh + 0x98, 0x100)
    struct.pack_into('<Q', elf, sh + 0xa0, 4)
    elf[0x100:0x100 + len(code)] = code
    elf[0x300:0x310] = b'.text\x00.shstrtab\x00'
    open(path, 'wb').write(elf)

tests = [
    ('c4 e2 f9 f7 c6', 'obs pp=01'),
    ('c4 e2 f8 f7 c6', 'pp=00'),
    ('c4 e2 fa f7 c6', 'pp=10'),
    ('c4 e2 fb f7 c6', 'pp=11'),
    ('c4 e2 71 f7 c6', 'vvvv=1 W=0 L=1'),
    ('c4 e2 f1 f7 c6', 'vvvv=1 W=1 L=0'),
    ('c5 f8 f7 c6',    'VEX2 pp=00'),
    ('c5 f9 f7 c6',    'VEX2 pp=01'),
    ('c4 e2 f9 f5 c6', 'obs pdep'),
    ('c4 e2 f8 f5 c6', 'pdep pp=00'),
    ('c4 e2 fa f5 c6', 'pdep pp=10'),
    ('c4 e2 fb f5 c6', 'pdep pp=11'),
    ('c4 e2 f9 58 c6', 'addps map2 pp01'),
    ('c4 e2 7d 58 c6', 'vaddps 66-0F W0 L1 pp01'),
    ('c4 e2 7c 58 c6', 'vaddps 66-0F W0 L1 pp00'),
    ('c4 e1 7e 6f 01', 'vmovdqu pp=10'),
    ('c4 e1 7f 6f 01', 'vmovdqu pp=11'),
    ('c4 e1 7c 6f 01', 'vmovdqa pp=01'),
]
code = bytes.fromhex('90'.join(t[0].replace(' ', '') for t in tests))
make_elf(code)
r = subprocess.run(['objdump', '-d', 't2.bin'], capture_output=True, text=True)
for line in r.stdout.splitlines():
    if ':' in line and '\t' in line and 'file format' not in line:
        print(line)
