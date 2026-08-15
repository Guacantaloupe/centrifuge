import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'src/recovered_runtime.cpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()

# 1. note_fault 签名加 caller 参数
old = ('static void recovered_note_fault(std::uintptr_t a) {\n'
       '    std::lock_guard<std::mutex> g(g_fault_hist_mutex);\n'
       '    auto& f = g_fault_hist[a];\n'
       '    ++f.count;\n'
       '    if (!f.rip) f.rip = reinterpret_cast<std::uintptr_t>(__builtin_return_address(0));\n'
       '}')
new = ('static void recovered_note_fault(std::uintptr_t a, std::uintptr_t caller) {\n'
       '    std::lock_guard<std::mutex> g(g_fault_hist_mutex);\n'
       '    auto& f = g_fault_hist[a];\n'
       '    ++f.count;\n'
       '    if (!f.rip) f.rip = caller;\n'
       '}')
assert old in s, 'signature anchor missing'
s = s.replace(old, new, 1)

# 2. 所有调用点传 caller（translate 内的 __builtin_return_address(0) = 恢复函数）
caller_expr = 'reinterpret_cast<std::uintptr_t>(__builtin_return_address(0))'
s = s.replace('recovered_note_fault(address);', 'recovered_note_fault(address, ' + caller_expr + ');')
s = s.replace('(recovered_note_fault(address), ++runtime_faults)',
              '(recovered_note_fault(address, ' + caller_expr + '), ++runtime_faults)')

open(p, 'w', encoding='utf-8', newline='').write(s)
print('caller capture updated; remaining bare calls:', s.count('recovered_note_fault(address);'))
