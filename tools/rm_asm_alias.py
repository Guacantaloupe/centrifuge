import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 删除 asm 别名行
old = 'extern "C" void recovered_guard_trampoline() __asm__("recovered_guard_trampoline");\n'
if old in src:
    src = src.replace(old, '')
    print('asm alias removed')
else:
    print('asm alias not found (already removed?)')
io.open(p, 'w', encoding='utf-8', newline='').write(src)
