import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 删除 reloc 应用块 (从 '// Apply PE base relocations' 到 '    }' 之后)
start = src.find('// Apply PE base relocations')
if start < 0:
    print('reloc block not found')
    sys.exit(1)
# 找块结束: reloc 块后是 '// Write resolved import addresses'
end = src.find('// Write resolved import addresses', start)
if end < 0:
    print('end not found')
    sys.exit(1)
print('removing reloc block:', start, '->', end)
src = src[:start] + src[end:]
io.open(p, 'w', encoding='utf-8', newline='').write(src)
print('reloc application removed')
