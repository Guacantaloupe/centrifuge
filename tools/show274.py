import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'build-recheck54\src\recovered_runtime.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 看 274 行附近
lines = src.splitlines()
for i in range(270, 280):
    print(i+1, repr(lines[i]))
