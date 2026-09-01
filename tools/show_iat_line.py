import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_main.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 找 [IAT] 打印行
i = src.find('std::fprintf(stderr, "[IAT]')
print(repr(src[i:i+150]))
