import re, subprocess, sys

# collect EVEX instructions from objdump
r = subprocess.run(['objdump', '-d', r'C:\Windows\System32\ntdll.dll'],
                   capture_output=True, text=True, errors='replace')
lines = r.stdout.splitlines()
insns = []
i = 0
while i < len(lines):
    m = re.match(r'\s*([0-9a-f]+):\t(.*)$', lines[i])
    if not m:
        i += 1; continue
    addr = int(m.group(1), 16); bts = []; rest = None
    for field in m.group(2).split('\t'):
        f = field.strip()
        if f and re.fullmatch(r'(?:[0-9a-f]{2} )*[0-9a-f]{2}', f):
            bts.extend(f.split())
        else:
            rest = f; break
    j = i + 1
    while j < len(lines):
        cm = re.match(r'\t+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s*$', lines[j])
        if cm:
            bts.extend(cm.group(1).split()); j += 1
        else:
            break
    txt = rest if rest else ''
    if txt and not txt.startswith('.byte') and not txt.startswith('(bad)'):
        mn = txt.split()[0]
        if bts and bts[0] == '62':
            insns.append((addr, bts, txt))
    i = j

ZMM = ['zmm%d' % n for n in range(32)]
XMM = ['xmm%d' % n for n in range(32)]

def modrm_decode(modrm):
    return (modrm >> 6) & 3, (modrm >> 3) & 7, modrm & 7

def ours(bts):
    p0, p1, p2 = int(bts[1], 16), int(bts[2], 16), int(bts[3], 16)
    R, X, B, Rp = (p0 >> 7) & 1, (p0 >> 6) & 1, (p0 >> 5) & 1, (p0 >> 4) & 1
    mm = p0 & 7
    W = (p1 >> 7) & 1
    vvvv4 = (p1 >> 3) & 0xF
    pp = p1 & 3
    z, LL, b, Vp, aaa = (p2 >> 7) & 1, (p2 >> 5) & 3, (p2 >> 4) & 1, (p2 >> 3) & 1, p2 & 7
    op = int(bts[4], 16)
    mod, regf, rmf = modrm_decode(int(bts[5], 16))
    reg = ((~Rp) & 1) << 4 | ((~R) & 1) << 3 | regf
    rm = ((~B) & 1) << 3 | rmf
    vvvv = (~(((Vp) & 1) << 4 | vvvv4)) & 0x1F
    return dict(R=R, X=X, B=B, Rp=Rp, mm=mm, W=W, vvvv4=vvvv4, pp=pp,
                z=z, LL=LL, b=b, Vp=Vp, aaa=aaa, op=op, mod=mod, reg=reg,
                rm=rm, vvvv=vvvv, p0=p0, p1=p1, p2=p2)

ok = bad = 0
for addr, bts, txt in insns:
    d = ours(bts)
    # expected regs from AT&T text: zmmN / xmmN occurrences
    regs = re.findall(r'(zmm|xmm)(\d+)', txt)
    exp = {('%s%d' % (t, int(n))): int(n) for t, n in regs}
    name = txt.split()[0]
    # map: mm=1 -> 0F, 2 -> 0F38, 3 -> 0F3A
    maps = {1: '0F', 2: '0F38', 3: '0F3A'}
    pps = {0: 'None', 1: '66', 2: 'F3', 3: 'F2'}
    verdict = '?'
    if name == 'vmovdqu32':
        # F3 0F 6F: reg=dst zmm, rm=src mem
        exp_dst = exp.get('zmm%d' % d['reg'])
        okk = d['mm'] == 1 and d['pp'] == 2 and d['op'] == 0x6F and \
              exp_dst == d['reg'] and exp.get('rm') is None
        verdict = 'OK' if okk else 'FAIL'
    elif name == 'vpxord':
        exp_dst = exp.get('zmm%d' % d['reg'])
        exp_s1 = exp.get('zmm%d' % d['vvvv'])
        exp_s2 = exp.get('zmm%d' % d['rm'])
        okk = d['mm'] == 1 and d['pp'] == 1 and d['op'] == 0xEF and d['W'] == 0 and \
              exp_dst == d['reg'] and exp_s1 == d['vvvv'] and exp_s2 == d['rm']
        verdict = 'OK' if okk else 'FAIL'
    elif name.startswith('vpclmul'):
        exp_dst = exp.get('zmm%d' % d['reg'])
        exp_s1 = exp.get('zmm%d' % d['vvvv'])
        exp_s2 = exp.get('zmm%d' % d['rm'])
        imm = int(bts[6], 16) if len(bts) > 6 else None
        okk = d['mm'] == 3 and d['pp'] == 1 and d['op'] == 0x44 and \
              exp_dst == d['reg'] and exp_s1 == d['vvvv'] and exp_s2 == d['rm']
        verdict = 'OK' if okk else 'FAIL'
    elif name == 'vextracti32x4':
        exp_src = exp.get('zmm%d' % d['reg'])
        exp_dst = exp.get('xmm%d' % d['rm'])
        okk = d['mm'] == 3 and d['pp'] == 1 and d['op'] == 0x39 and \
              exp_src == d['reg'] and exp_dst == d['rm']
        verdict = 'OK' if okk else 'FAIL'
    else:
        verdict = 'UNKNOWN'
    if verdict == 'OK':
        ok += 1
    else:
        bad += 1
    if verdict != 'OK' or 'FAIL' in verdict:
        print('%#x %-40s %s  %s' % (addr, ' '.join(bts), txt, verdict))
        print('   p0=%02x mm=%d R=%d X=%d B=%d Rp=%d | p1=%02x W=%d vvvv4=%x pp=%d | p2=%02x z=%d LL=%d b=%d Vp=%d aaa=%d' %
              (d['p0'], d['mm'], d['R'], d['X'], d['B'], d['Rp'], d['p1'], d['W'], d['vvvv4'], d['pp'],
               d['p2'], d['z'], d['LL'], d['b'], d['Vp'], d['aaa']))
        print('   reg=%d rm=%d vvvv=%d mod=%d op=%02x' % (d['reg'], d['rm'], d['vvvv'], d['mod'], d['op']))
print('OK=%d FAIL/UNKNOWN=%d (total %d)' % (ok, bad, len(insns)))
