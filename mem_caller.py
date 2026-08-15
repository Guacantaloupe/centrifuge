import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'include/recovered_runtime.hpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()

# 检查是否已改过（幂等）
if 'g_mem_caller' in s:
    print('already wired; skipping')
else:
    anchor = 'template <typename T> T recovered_load(std::uintptr_t address) {'
    assert anchor in s, 'load template anchor missing'
    decl = ('// last memory-access caller (diagnostics; set by load/store templates)\n'
            'thread_local std::uintptr_t g_mem_caller = 0;\n\n')
    s = s.replace(anchor, decl + anchor, 1)
    old = ('template <typename T> T recovered_load(std::uintptr_t address) {\n'
           '    T value{};')
    new = ('template <typename T> T recovered_load(std::uintptr_t address) {\n'
           '    g_mem_caller = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));\n'
           '    T value{};')
    assert old in s, 'load body anchor missing'
    s = s.replace(old, new, 1)
    # store 模板（template <typename U> 前缀 + 可能 U 在别处声明）
    m = re.search(r'template[^\{]*recovered_store\(std::uintptr_t address, U value\) \{\n', s)
    if not m:
        m = re.search(r'recovered_store\(std::uintptr_t address, U value\) \{\n', s)
    assert m, 'store template anchor missing'
    old2 = m.group(0)
    new2 = old2 + '    g_mem_caller = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));\n'
    s = s.replace(old2, new2, 1)
    open(p, 'w', encoding='utf-8', newline='').write(s)
    print('g_mem_caller wired into load/store templates')
