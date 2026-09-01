import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
# 查 runtime.cpp 是否已 include 相关, 找插入点: recovered_runtime_initialize 之前
src = open(r'build-recheck54\src\recovered_runtime.cpp', encoding='utf-8').read()
i = src.find('std::uint64_t recovered_register_tls_atexit')
print('register_tls at', i)
# 找 recovered_register_tls_atexit 前一个函数结尾
print(src[i-400:i+100])
