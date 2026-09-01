import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 1) 删除函数体内的 extern 声明行
old = '            extern "C" void recovered_guard_trampoline();\n'
assert old in src
src = src.replace(old, '')
# 2) 在 #endif (windows.h include) 后加文件作用域声明
anchor = '#include <windows.h>\n#endif\n'
assert anchor in src
src = src.replace(anchor, anchor + '\nextern "C" void recovered_guard_trampoline();\n', 1)
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('decl moved to file scope')
