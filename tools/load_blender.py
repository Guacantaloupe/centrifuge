import ctypes, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
k32.LoadLibraryExW.restype = ctypes.c_void_p
LOAD_LIBRARY_AS_DATAFILE = 0x2
LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20
h = k32.LoadLibraryExW(r'C:\Program Files\Blender Foundation\Blender 5.2\blender.exe', None, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE)
if not h:
    print('LoadLibraryEx failed', ctypes.get_last_error())
    sys.exit(1)
print('base', hex(h))
for target in [0x145d418c0, 0x145d418c8, 0x145d41880, 0x145d41890, 0x145d40858]:
    delta = target - 0x140000000
    val = ctypes.c_uint64.from_address(h + delta).value
    print(hex(target), '->', hex(val))
