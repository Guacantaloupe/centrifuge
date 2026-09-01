import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
old = '''        "push %rax\\n"
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
        "pop %rax\\n"'''
new = '''        "push %%rax\\n"
        "push %%rcx\\n"
        "push %%rdx\\n"
        "push %%r8\\n"
        "push %%r9\\n"
        "push %%r10\\n"
        "push %%r11\\n"
        "mov %%rax, %%rcx\\n"
        "call recovered_guard_trace\\n"
        "pop %%r11\\n"
        "pop %%r10\\n"
        "pop %%r9\\n"
        "pop %%r8\\n"
        "pop %%rdx\\n"
        "pop %%rcx\\n"
        "pop %%rax\\n"'''
assert old in src
src = src.replace(old, new)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('asm registers escaped')
