import ctypes, sys, struct
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.LoadLibraryExW.restype = ctypes.c_void_p
LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20
h = k32.LoadLibraryExW(r'C:\Program Files\Blender Foundation\Blender 5.2\blender.exe', None, LOAD_LIBRARY_AS_IMAGE_RESOURCE)
print('base', hex(h or 0))
if not h:
    sys.exit(1)
# 文件里 0x4c10470a 处的值 (RVA 0x4c104000+0x70a)
img = open(r'C:\Program Files\Blender Foundation\Blender 5.2\blender.exe','rb').read()
# RVA 0x4c10470a -> 文件偏移 (节: .text vaddr 0x1000 roff 0x400)
# 0x4c10470a 在 .text? .text vaddr 0x1000 vsize 0x4c0f276 -> 0x4c10470a > 0x4c0f276+0x1000=0x4c10276 不在 .text
# 在 .rdata? vaddr 0x4c11000 -> 0x4c10470a < 0x4c11000 不在
print('0x4c10470a in gap between .text and .rdata!')
# 那真实加载后 0x14c10470a (ASLR 后) 的地址? 用 h + (0x14c10470a - 0x140000000) 不一定对
# AS_IMAGE_RESOURCE 的 h 就是映射基址? 打印实际 h
# 读 h + (0x4c10470a) 试
for off in [0x4c10470a, 0x4c104000, 0x4c10276, 0x4c11000]:
    try:
        val = ctypes.c_uint64.from_address(h + off).value
        print('h+%x = %x' % (off, val))
    except Exception as e:
        print('h+%x err %s' % (off, e))
