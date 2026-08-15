import io, sys, re
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
p = 'src/recovered_runtime.cpp'
s = open(p, encoding='utf-8-sig', errors='replace').read()

# 修 = 后面的替换错误：const x = recovered_note_fault(address); ++runtime_faults
#  -> const x = (recovered_note_fault(address), ++runtime_faults)
pat = re.compile(r'(=\s*)(recovered_note_fault\(address\)); (\+\+runtime_faults)')
n = 0
def fix(m):
    global n
    n += 1
    return m.group(1) + '(' + m.group(2) + ', ' + m.group(3) + ')'
s = pat.sub(fix, s)
print('comma-expr fixes:', n)

# 补 include
if '#include <unordered_map>' not in s:
    s = s.replace('#include <map>', '#include <map>\n#include <unordered_map>', 1)
    print('added <unordered_map>')
open(p, 'w', encoding='utf-8', newline='').write(s)
print('done')
