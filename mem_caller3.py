import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'include/recovered_runtime.hpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()
old = 'thread_local std::uintptr_t g_mem_caller = 0;'
new = 'inline thread_local std::uintptr_t g_mem_caller = 0;'
assert old in s
s = s.replace(old, new, 1)
open(p, 'w', encoding='utf-8', newline='').write(s)
print('g_mem_caller -> inline thread_local')
