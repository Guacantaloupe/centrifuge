import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
src = io.open(r'build-recheck54\src\recovered_runtime.cpp', encoding='utf-8', errors='replace').read()
# 打印所有关键块的顺序
for marker in ['Apply PE base relocations', 'Write resolved import addresses', 'guard:cf indirect-call slot', 'Pre-construct the MSVC std::locale', 'neutralize the _Xout_of_range']:
    i = src.find(marker)
    print(marker, '->', i)
