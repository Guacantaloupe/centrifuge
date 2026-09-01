import io, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
p = r'src\project_recovery.cpp'
src = io.open(p, encoding='utf-8', errors='replace').read()
# 在 guard 安装块内删除 extern 声明 (文件级已有)
old = '<< "            extern \\\\"C\\\\" void recovered_guard_trampoline();\\n"\n'
print('exact old found:', old in src)
# 尝试不同形态
import re
m = re.search(r'<< "            extern .*?recovered_guard_trampoline\(\);.*?"\n', src)
if m:
    print('regex found:', repr(m.group(0)))
    src = src[:m.start()] + src[m.end():]
    io.open(p, 'w', encoding='utf-8', newline='').write(src)
    print('removed')
else:
    print('not found via regex')
