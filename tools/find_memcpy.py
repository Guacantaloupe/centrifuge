import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
src = io.open(r'build-recheck54\src\recovered_runtime.cpp', encoding='utf-8', errors='replace').read()
# 找 memcpy 到固定地址的代码
import re
for m in re.finditer(r'.*memcpy.*', src):
    line = m.group(0)
    if 'fixed' in line or 'mapped' in line or 'region' in line:
        print(m.start(), line[:130])
