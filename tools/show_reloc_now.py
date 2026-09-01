import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 看 reloc 块现在的样子
start = src.find('// Apply PE base relocations')
end_marker = 'pos += blockSize;\n        }\n    }\n'
end = src.find(end_marker, start)
print(src[start:end+len(end_marker)][:2500])
