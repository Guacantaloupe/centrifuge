import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
src = open(r'build-recheck54\src\recovered_runtime.cpp', encoding='utf-8').read()
# 找 IAT 写回循环
i = src.find('for (const auto& slot : runtime_iat_slots)')
print(src[i-200:i+900])
