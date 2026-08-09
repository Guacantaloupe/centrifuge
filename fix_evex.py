import re

# ---------- 1. hpp: add requiresEvex flag ----------
h = open('include/centrifuge/sleigh.hpp', 'r', newline=None).read()
old = 'bool requiresVex = false; // pattern contains a vex* term'
new = ('bool requiresVex = false; // pattern contains a vex* term\n'
       '    bool requiresEvex = false; // pattern contains an evex* term')
assert old in h, 'hpp requiresVex'
h = h.replace(old, new)
open('include/centrifuge/sleigh.hpp', 'w', newline='\n').write(h)

# ---------- 2. sleigh.cpp ----------
s = open('src/sleigh.cpp', 'r', newline=None).read()

# A. X86Ctx: add EVEX fields
old = '''        bool vexW = false, vexL = false;
        int vexPP = 0;'''
new = '''        bool vexW = false, vexL = false;
        int vexPP = 0;
        bool evex = false;
        int evexMap = 1;   // 1=0F, 2=0F38, 3=0F3A
        int evexVvvv = -1; // 0-31, -1 = unused
        bool evexW = false;
        int evexL = 0;     // 0=xmm, 1=ymm, 2=zmm
        int evexPP = 0;
        bool evexZ = false, evexB = false;
        int evexAaa = 0;
        int evexRprime = 0; // ~R'<<4, extends reg field to 5 bits'''
assert old in s, 'ctx fields'
s = s.replace(old, new)

# B. prefix scan: EVEX (62) branch after VEX3
old = '''            else if (b >= 0x40 && b <= 0x4F) {'''
new = '''            else if (b == 0x62 && p + 3 < got) {
                // EVEX: P0=[R][X][B][R'][0][mm] P1=[W][vvvv][1][pp]
                //       P2=[z][LL][b][V'][aaa]
                const uint8_t p0 = raw[p + 1];
                const uint8_t p1 = raw[p + 2];
                const uint8_t p2 = raw[p + 3];
                xc.evex = true;
                xc.rexr = !((p0 >> 7) & 1);
                xc.rexx = !((p0 >> 6) & 1);
                xc.rexb = !((p0 >> 5) & 1);
                xc.evexRprime = (!((p0 >> 4) & 1)) ? 16 : 0;
                xc.evexMap = p0 & 7;
                xc.evexW = (p1 >> 7) & 1;
                xc.evexVvvv =
                    (~((((p2 >> 3) & 1) << 4) | ((p1 >> 3) & 0xF))) & 0x1F;
                xc.evexL = (p2 >> 5) & 3;
                xc.evexPP = p1 & 3;
                xc.evexZ = (p2 >> 7) & 1;
                xc.evexB = (p2 >> 4) & 1;
                xc.evexAaa = p2 & 7;
                p += 4;
                break; // EVEX is self-contained
            }
            else if (b >= 0x40 && b <= 0x4F) {'''
assert old in s, 'evex prefix'
s = s.replace(old, new)

# C. requiresVex calc -> also requiresEvex
old = '''        for (const auto& ct : c.terms)
            if (ct.field.rfind("vex", 0) == 0) c.requiresVex = true;'''
new = '''        for (const auto& ct : c.terms) {
            if (ct.field.rfind("evex", 0) == 0) c.requiresEvex = true;
            else if (ct.field.rfind("vex", 0) == 0) c.requiresVex = true;
        }'''
assert old in s, 'reqvex calc'
s = s.replace(old, new)

# D. match gate: three-way
old = '''        if (xc.vex != c.requiresVex) continue;'''
new = '''        if (c.requiresEvex) {
            if (!xc.evex) continue;
        } else if (c.requiresVex) {
            if (!xc.vex || xc.evex) continue;
        } else if (xc.vex || xc.evex) {
            continue;
        }'''
assert old in s, 'match gate'
s = s.replace(old, new)

# E. isMagic: add evex terms; rmmem -> prefix
old = '''               (n == "rregv" || n == "rmregv" || n == "acc" || n == "vex" ||
                n == "vexmap" ||
                n == "vexvvvv" || n.rfind("vexvvvv", 0) == 0 ||
                n == "vexw" || n == "vexL" || n == "vexpp" ||'''
new = '''               (n == "rregv" || n == "rmregv" || n == "acc" || n == "vex" ||
                n == "vexmap" ||
                n == "vexvvvv" || n.rfind("vexvvvv", 0) == 0 ||
                n == "vexw" || n == "vexL" || n == "vexpp" ||
                n == "evex" || n == "evexmap" || n == "evexw" ||
                n == "evexL" || n == "evexpp" || n == "evexvvvv" ||
                n.rfind("evexvvvv", 0) == 0 || n == "evexz" ||
                n == "evexb" || n == "evexaaa" ||'''
assert old in s, 'ismagic add'
s = s.replace(old, new)

old = '''                n.rfind("modrm", 0) == 0 || n == "rreg" ||
                n.rfind("rreg", 0) == 0 || n == "rmreg" ||
                n.rfind("rmreg", 0) == 0 || n == "rmmem" ||'''
new = '''                n.rfind("modrm", 0) == 0 || n == "rreg" ||
                n.rfind("rreg", 0) == 0 || n == "rmreg" ||
                n.rfind("rmreg", 0) == 0 || n.rfind("rmmem", 0) == 0 ||'''
assert old in s, 'ismagic rmmem'
s = s.replace(old, new)

# F. match-time magic handling: evex gate + evex map/w/L/pp/z/b/aaa
old = '''                if (fn == "pfxf2" || fn == "pfxf3" || fn == "pfx66" ||
                    fn == "pfxnone") {'''
new = '''                if (fn == "evex") {
                    if (!xc.evex) { ok = false; break; }
                    continue;
                }
                if (fn == "evexmap" || fn == "evexw" || fn == "evexL" ||
                    fn == "evexpp" || fn == "evexz" || fn == "evexb" ||
                    fn == "evexaaa") {
                    const uint64_t v = fn == "evexmap"
                                           ? static_cast<uint64_t>(xc.evexMap)
                                       : fn == "evexw"
                                           ? (xc.evexW ? 1 : 0)
                                       : fn == "evexL"
                                           ? static_cast<uint64_t>(xc.evexL)
                                       : fn == "evexpp"
                                           ? static_cast<uint64_t>(xc.evexPP)
                                       : fn == "evexz"
                                           ? (xc.evexZ ? 1 : 0)
                                       : fn == "evexb"
                                           ? (xc.evexB ? 1 : 0)
                                           : static_cast<uint64_t>(xc.evexAaa);
                    if (t.kind != SpecCtor::Term::FIELD_EQ || v != t.value) {
                        ok = false;
                        break;
                    }
                    continue;
                }
                if (fn == "pfxf2" || fn == "pfxf3" || fn == "pfx66" ||
                    fn == "pfxnone") {'''
assert old in s, 'match evex'
s = s.replace(old, new)

# G. rmmem match check: prefix
old = '''                if (fn == "rmmem" && (!xc.haveModrm || xc.mod == 3)) {'''
new = '''                if (fn.rfind("rmmem", 0) == 0 &&
                    (!xc.haveModrm || xc.mod == 3)) {'''
assert old in s, 'rmmem match'
s = s.replace(old, new)

# H. decodeModrm: EVEX reg field gets Rprime bit
old = '''        xc.regReg = xc.reg | (xc.rexr ? 8 : 0);'''
new = '''        xc.regReg = xc.reg | (xc.rexr ? 8 : 0) |
                    (xc.evex ? xc.evexRprime : 0);'''
assert old in s, 'decodeModrm reg'
s = s.replace(old, new)

# I. materialize: rregv/rmregv size honors evexL
old = '''        if (mname == "rregv" || mname == "rmregv") {
            const int sz = xc.vexL ? 32 : 16;
            out.named[opname] = x86RegVarnode(mname == "rregv" ? xc.regReg
                                                               : xc.rmReg,
                                              sz);
        } else if (mname == "vexvvvv" || mname.rfind("vexvvvv", 0) == 0) {'''
new = '''        if (mname == "rregv" || mname == "rmregv") {
            const int sz = xc.evex ? (xc.evexL == 2 ? 64
                                          : xc.evexL == 1 ? 32 : 16)
                                   : (xc.vexL ? 32 : 16);
            out.named[opname] = x86RegVarnode(mname == "rregv" ? xc.regReg
                                                               : xc.rmReg,
                                              sz);
        } else if (mname == "evexvvvv" || mname.rfind("evexvvvv", 0) == 0) {
            const int sz = mname.size() > 8 ? atoi(mname.c_str() + 8) / 8
                                            : (xc.evexL == 2 ? 64
                                               : xc.evexL == 1 ? 32 : 16);
            out.named[opname] = x86RegVarnode(xc.evexVvvv, sz);
        } else if (mname == "vexvvvv" || mname.rfind("vexvvvv", 0) == 0) {'''
assert old in s, 'mat evexvvvv'
s = s.replace(old, new)

# J. rmmem materialize: compressed disp8 (EVEX mod==1, disp8*N)
old = '''        } else if (mname == "rmmem") {
            const uint64_t ea = materializeAddr();'''
new = '''        } else if (mname.rfind("rmmem", 0) == 0) {
            if (mname.size() > 5 && xc.mod == 1) {
                // EVEX compressed disp8: disp8 * N
                xc.disp *= atoi(mname.c_str() + 5);
            }
            const uint64_t ea = materializeAddr();'''
assert old in s, 'mat rmmem'
s = s.replace(old, new)

# K. zmm register names (size 64)
old = '''        } else if (size == 32) {
            static const char* ymm[8] = {"ymm0", "ymm1", "ymm2", "ymm3",
                                         "ymm4", "ymm5", "ymm6", "ymm7"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "ymm%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", ymm[idx]);
        } else {'''
new = '''        } else if (size == 32) {
            static const char* ymm[8] = {"ymm0", "ymm1", "ymm2", "ymm3",
                                         "ymm4", "ymm5", "ymm6", "ymm7"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "ymm%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", ymm[idx]);
        } else if (size == 64) {
            static const char* zmm[8] = {"zmm0", "zmm1", "zmm2", "zmm3",
                                         "zmm4", "zmm5", "zmm6", "zmm7"};
            if (idx >= 8)
                std::snprintf(nm, sizeof(nm), "zmm%d", idx);
            else
                std::snprintf(nm, sizeof(nm), "%s", zmm[idx]);
        } else {'''
assert old in s, 'zmm names'
s = s.replace(old, new)

open('src/sleigh.cpp', 'w', newline='\n').write(s)
print('engine patches OK')
