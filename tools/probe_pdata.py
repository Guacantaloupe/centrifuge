# 查 Blender 5.2 .pdata 是否覆盖 0x1400b1bb0 / 0x23264F0 / 0x2325D30 / 0x232B070
import struct
p = r'C:\Program Files\Blender Foundation\Blender 5.2\blender.exe'
d = open(p, 'rb').read()
e_lfanew = struct.unpack_from('<I', d, 0x3C)[0]
assert d[e_lfanew:e_lfanew+4] == b'PE\0\0'
nsec = struct.unpack_from('<H', d, e_lfanew+6)[0]
opt = struct.unpack_from('<H', d, e_lfanew+20)[0]
base = struct.unpack_from('<Q', d, e_lfanew+24+8)[0]
secs = []
off = e_lfanew + 24 + opt
for i in range(nsec):
    name = d[off:off+8].rstrip(b'\0').decode()
    vsz, vaddr, rsz, rptr = struct.unpack_from('<IIII', d, off+8)
    secs.append((name, vaddr, vsz, rptr, rsz))
    off += 40
pdata = None
for name, vaddr, vsz, rptr, rsz in secs:
    if name == '.pdata':
        pdata = (vaddr, vsz, rptr)
print('sections:', [(s[0], hex(s[1]), hex(s[2])) for s in secs])
if not pdata:
    print('NO .pdata'); raise SystemExit
vaddr, vsz, rptr = pdata
n = vsz // 12
print('.pdata entries:', n)
targets = [0x1400b1bb0, 0x23264F0, 0x2325D30, 0x232B070, 0x23258C0, 0x232B2E0, 0x143E4D3B0, 0x143E49DC0, 0x4468569C, 0x4C0FEA0]
def va2off(va):
    for name, sva, svs, srp, srs in secs:
        if sva <= va - base < sva + svs:
            return srp + (va - base - sva)
    return None
import bisect
starts = []
ends = []
for i in range(n):
    rva, sz, info = struct.unpack_from('<III', d, rptr + i*12)
    starts.append(base + rva)
    ends.append(base + rva + sz)
for t in targets:
    idx = bisect.bisect_right(starts, t) - 1
    hit = idx >= 0 and starts[idx] <= t < ends[idx]
    print('0x%X pdata=%s' % (t, 'YES end 0x%X' % ends[idx] if hit else 'NO'))
