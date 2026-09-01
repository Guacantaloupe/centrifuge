import ctypes, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.LoadLibraryExW.restype = ctypes.c_void_p
LOAD_LIBRARY_AS_DATAFILE = 0x2
LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20
path = r'C:\Program Files\Blender Foundation\Blender 5.2\blender.exe'

def read_slot(h, target):
    delta = target - 0x140000000
    return ctypes.c_uint64.from_address(h + delta).value

# AS_DATAFILE: 按文件偏移映射 (可能不按 VA)
h1 = k32.LoadLibraryExW(path, None, LOAD_LIBRARY_AS_DATAFILE)
print('datafile base', hex(h1 or 0))
if h1:
    # 数据文件映射: 节按文件偏移? 这里直接读 RVA 偏移可能不对, 试试
    for t in [0x145d418c0, 0x145d40858]:
        try:
            print('  df', hex(t), '->', hex(read_slot(h1, t)))
        except Exception as e:
            print('  df err', e)
# AS_IMAGE_RESOURCE: 按 VA 映射 + 重定位
h2 = k32.LoadLibraryExW(path, None, LOAD_LIBRARY_AS_IMAGE_RESOURCE)
print('image base', hex(h2 or 0))
if h2:
    for t in [0x145d418c0, 0x145d418c8, 0x145d40858]:
        try:
            print('  img', hex(t), '->', hex(read_slot(h2, t)))
        except Exception as e:
            print('  img err', e)
