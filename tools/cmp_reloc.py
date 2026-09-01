import struct, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
exe = open(r'C:\Program Files\Blender Foundation\Blender 5.2\blender.exe','rb').read()
img = open(r'build-recheck54\data\image.bin','rb').read()
# reloc: roff 0x6b74c00, size 0x4578c (blender.exe 节表)
for name, data in [('blender.exe', exe), ('image.bin', img)]:
    chunk = data[0x6b74c00:0x6b74c00+0x4578c]
    nz = sum(1 for b in chunk if b != 0)
    print(name, 'reloc nonzero bytes:', nz, 'of', len(chunk))
    print('  first 32:', chunk[:32].hex())
# 也检查 .rdata 的 0x145d418c0 槽在两个文件里
for name, data in [('blender.exe', exe), ('image.bin', img)]:
    val = struct.unpack_from('<Q', data, 0x5d418c0)[0]
    print(name, '0x145d418c0 =', hex(val))
    val2 = struct.unpack_from('<Q', data, 0x5d40858)[0]
    print(name, '0x145d40858 =', hex(val2))
