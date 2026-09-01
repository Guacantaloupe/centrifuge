import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 找 reloc 应用块
start = src.find('// Apply PE base relocations')
if start < 0:
    print('reloc block not found')
    sys.exit(1)
end_marker = 'pos += blockSize;\n        }\n    }\n'
end = src.find(end_marker, start)
end += len(end_marker)
print('reloc block:', start, end)
print(src[start:end][:500])
