import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
src = io.open(r'build-recheck54\src\recovered_runtime.cpp', encoding='utf-8', errors='replace').read()
i = src.find('// Commit inter-region gaps')
print(src[i:i+1200])
