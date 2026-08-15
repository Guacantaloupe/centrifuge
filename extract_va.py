import struct, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
path = r'C:\Users\m4a1_\.openclaw\workspace\centrifuge\build-blender52\project\build\data\image.bin'
data = open(path, 'rb').read()
pe = struct.unpack_from('<I', data, 0x3c)[0]
nsec = struct.unpack_from('<H', data, pe + 6)[0]
opt = pe + 24
imgbase = struct.unpack_from('<Q', data, opt + 24)[0]
sects = []
for i in range(nsec):
    s = pe + 24 + 40 * 2 + 40 * i
    name = data[s:s+8].rstrip(b'\x00')
    vsz, vaddr, rsz, roff = struct.unpack_from('<IIII', data, s + 8)
    sects.append((vaddr, vsz, roff, rsz))
    print('section %d: vaddr=0x%x vsz=0x%x raw=0x%x rsz=0x%x' % (i, vaddr, vsz, roff, rsz))

def va2off(va):
    rva = va - imgbase
    for vaddr, vsz, roff, rsz in sects:
        if vaddr <= rva < vaddr + max(vsz, rsz):
            return roff + (rva - vaddr)
    return None

start = int(sys.argv[1], 16)
stop = int(sys.argv[2], 16)
so = va2off(start)
eo = va2off(stop)
print('VA %#x -> file 0x%x; VA %#x -> file 0x%x' % (start, so, stop, eo))
with open(r'C:\Users\m4a1_\.openclaw\workspace\centrifuge\build-blender52\native_seg.bin', 'wb') as f:
    f.write(data[so:eo])
print('wrote native_seg.bin', eo - so, 'bytes')
