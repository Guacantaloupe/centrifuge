import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 在 trampoline 定义前加一个 C 包装, 打印 rax; 但 trampoline 是 naked asm, 不能直接调 fprintf
# 改方案: trampoline asm 里调用一个记录函数
old = '''extern "C" void recovered_guard_trampoline() {
    __asm__ __volatile__('''
new = '''extern "C" void recovered_guard_trace(std::uintptr_t target) {
    std::fprintf(stderr, "[GUARD] target=%p\\n", (void*)target);
}
extern "C" void recovered_guard_trampoline() {
    __asm__ __volatile__('''
assert old in src
src = src.replace(old, new)
# 在 asm 开头加 call recovered_guard_trace (保存寄存器)
old2 = '''        "movabs $0x140000000, %%r11\\n"'''
new2 = '''        "push %rax\\n"
        "push %rcx\\n"
        "push %rdx\\n"
        "push %r8\\n"
        "push %r9\\n"
        "push %r10\\n"
        "push %r11\\n"
        "mov %rax, %rcx\\n"
        "call recovered_guard_trace\\n"
        "pop %r11\\n"
        "pop %r10\\n"
        "pop %r9\\n"
        "pop %r8\\n"
        "pop %rdx\\n"
        "pop %rcx\\n"
        "pop %rax\\n"
        "movabs $0x140000000, %%r11\\n"'''
assert old2 in src
src = src.replace(old2, new2)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('guard trace added')
