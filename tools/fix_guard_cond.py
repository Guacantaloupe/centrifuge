import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''        constexpr std::uintptr_t kGuardSlot = 0x145d40858ULL;
        if (recovered_image_executable(kGuardSlot)) {'''
new = '''        constexpr std::uintptr_t kGuardSlot = 0x145d40858ULL;
        if (kGuardSlot >= recovered_image_begin() &&
            kGuardSlot < recovered_image_end()) {'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('guard install condition widened')
