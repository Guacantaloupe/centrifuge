import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'include/recovered_runtime.hpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()

old = ('recovered_store(std::uintptr_t address, U value) {\n'
       '    std::uintptr_t imported = 0;')
new = ('recovered_store(std::uintptr_t address, U value) {\n'
       '    g_mem_caller = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));\n'
       '    std::uintptr_t imported = 0;')
assert old in s, 'store body anchor missing'
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('store template caller wired')
