#!/usr/bin/env python3
"""Verify Centrifuge's aarch64.slaspec against llvm-objdump ground truth.

Usage: verify_aarch64_spec.py <arm64-pe-or-elf> [--max-funcs N]

For every function in the binary (from llvm-objdump -d symbol boundaries):
  - disassemble the whole function with centrifuge spec disasm --resume
  - compare decoded coverage and mnemonic class against llvm-objdump
Prints per-function and overall coverage / mnemonic-match statistics.
"""
import re
import subprocess
import sys
import collections

LLVM_OBJDUMP = r"C:\msys64\clang64\bin\llvm-objdump.exe"
CENTRIFUGE = r"build\Release\centrifuge_dev.exe"
SPEC = r"sleigh\aarch64.slaspec"


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


def parse_objdump(text):
    """Return {func_name: [(addr, mnemonic), ...]} and ordered addr set."""
    funcs = {}
    cur = None
    insn_re = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(\S+)")
    func_re = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:")
    for line in text.splitlines():
        fm = func_re.match(line)
        if fm:
            cur = fm.group(2)
            funcs[cur] = []
            continue
        im = insn_re.match(line)
        if im and cur is not None:
            funcs[cur].append((int(im.group(1), 16), im.group(3).lower(),
                               im.group(2).strip()))
    return funcs


def canon(m):
    """Map a mnemonic (objdump truth OR our ctor name) to a family class."""
    m = m.lower()
    # our generated names: strip size/form suffixes first
    m = re.sub(r"^movz(64|32)_hw0$", "mov", m)
    m = re.sub(r"^movn(64|32)_hw\d+$", "mov", m)
    for suf in ("_lsl12", "_imm", "_lsl0", "_lsl2", "_lsl3", "_lsl4",
                "_lsr0", "_lsr2", "_lsr3", "_lsr4", "_asr0", "_asr2",
                "_lsl", "_lsr", "_asr"):
        if m.endswith(suf):
            m = m[:-len(suf)]
            break
    m = re.sub(r"_hw\d+$", "", m)
    m = re.sub(r"_(uxtw|sxtw|lsl|lsr|asr|uxtb|sxtb|uxth|sxth)\d+$", "", m)
    m = re.sub(r"_(so|pr|po|ui|uri|u|i)$", "", m)
    m = re.sub(r"(64|32)$", "", m)
    m = re.sub(r"_(u)x$", "", m)
    if m == "ldrswx":
        m = "ldrsw"
    if m in ("smaddl", "umaddl", "smsubl", "umsubl", "smull", "umull"):
        m = "mul"
    m = re.sub(r"^lsl(64|32)_a\d+$", "lsl", m)
    m = re.sub(r"_(eq|ne|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al|nv)$", "", m)
    m = re.sub(r"^tb([n]?)z\d+$", r"tb\1z", m)
    if m in ("ldw", "ldx", "ldnp"):
        m = "ldx"
    if m in ("stw", "stx", "stnp"):
        m = "stx"
    m = {"stur": "str", "ldur": "ldr", "sturb": "strb", "ldurb": "ldrb",
         "sturh": "strh", "ldurh": "ldrh"}.get(m, m)
    m = re.sub(r"_x[0-7][0-7]$", "", m)
    if m in ("beq", "bne", "bhs", "blo", "bmi", "bpl", "bvs", "bvc",
             "bhi", "bls", "bge", "blt", "bgt", "ble"):
        m = "b"
    if m == "ldaxrx":
        m = "ldaxr"
    if m == "stlxrx":
        m = "stlxr"
    FAM = ("add adds sub subs cmp cmn and orr eor ands andn orrn eorn andsn "
           "mov movz movn movk mul madd msub neg cbz cbnz tbz tbnz br blr ret "
           "nop brk b bl ldr str ldrb strb ldrh strh ldrsb ldrsh ldrsw ldx stx "
           "ldaxr stlxr adr adrp asr lsr lsl sxtw uxtw sxth uxth sxtb uxtb "
           "sbfm ubfm bfm csel csinc csinv csneg sdiv udiv").split()
    if m in FAM:
        return m
    table = [
        ("ldp", "ldx"), ("stp", "stx"),
        ("ret", "ret"), ("br", "br"), ("blr", "blr"),
        ("mov", "mov"), ("movz", "movz"), ("movn", "movn"), ("movk", "movk"),
        ("add", "add"), ("sub", "sub"), ("cmp", "cmp"), ("cmn", "cmn"),
        ("mul", "mul"), ("madd", "madd"), ("msub", "msub"), ("neg", "neg"),
        ("and", "and"), ("orr", "orr"), ("eor", "eor"), ("tst", "ands"),
        ("ldr", "ldr"), ("str", "str"), ("ldur", "ldru"), ("stur", "stru"),
        ("ldrb", "ldrb"), ("strb", "strb"), ("ldrh", "ldrh"), ("strh", "strh"),
        ("ldrsw", "ldrsw"), ("ldrsh", "ldrsh"), ("ldrsb", "ldrsb"),
        ("ldp", "ldx"), ("stp", "stx"),
        ("b.", "b"), ("cbz", "cbz"), ("cbnz", "cbnz"),
        ("tbz", "tbz"), ("tbnz", "tbnz"),
        ("movn", "mov"), ("sbfiz", "sbfm"), ("ubfiz", "ubfm"),
        ("mvn", "orrn"),
        ("bl", "bl"), ("b", "b"),
        ("nop", "nop"), ("adrp", "adrp"), ("adr", "adr"),
        ("lsl", "lsl"), ("lsr", "lsr"), ("asr", "asr"),
        ("sxtw", "sxtw"), ("uxtw", "uxtw"), ("sxth", "sxth"), ("sxtb", "sxtb"),
        ("uxth", "uxth"), ("uxtb", "uxtb"),
        ("csel", "csel"), ("csinc", "csel"), ("csinv", "csel"), ("csneg", "csel"),
        ("ccmp", "ccmp"), ("cinc", "csel"), ("cset", "csel"), ("cneg", "csel"),
        ("ubfm", "ubfm"), ("bfm", "bfm"), ("sbfm", "sbfm"),
        ("ubfx", "ubfm"), ("sbfx", "sbfm"), ("bfxil", "bfm"),
        ("umaddl", "madd"), ("smaddl", "madd"), ("umsubl", "msub"), ("smsubl", "msub"),
        ("umulh", "mul"), ("smulh", "mul"), ("umull", "mul"), ("smull", "mul"),
        ("mneg", "msub"), ("muls", "mul"),
        ("sdiv", "sdiv"), ("udiv", "udiv"), ("msub", "msub"),
        ("eon", "eorn"), ("bic", "andn"), ("orn", "orrn"), ("bics", "andsn"),
        ("rev", "rev"), ("clz", "clz"), ("rbit", "rbit"), ("cnt", "cnt"),
        ("extr", "extr"), ("ror", "extr"),
        ("mrs", "mrs"), ("msr", "msr"), ("sys", "sys"),
        ("fmov", "fmov"), ("fadd", "fadd"), ("fsub", "fsub"), ("fmul", "fmul"),
        ("fdiv", "fdiv"), ("fcmp", "fcmp"), ("scvtf", "scvtf"), ("fcvtzs", "fcvtzs"),
        ("ldrb", "ldrb"), ("sturb", "strbu"), ("ldurb", "ldrbu"),
        ("prfm", "prfm"), ("hint", "nop"), ("yield", "nop"), ("wfe", "nop"),
        ("wfi", "nop"), ("sev", "nop"), ("sevl", "nop"),
    ]
    for pref, cls in table:
        if m.startswith(pref):
            return cls
    return "OTHER:" + m


def main():
    binary = sys.argv[1]
    max_funcs = None
    if "--max-funcs" in sys.argv:
        max_funcs = int(sys.argv[sys.argv.index("--max-funcs") + 1])

    gt = parse_objdump(run([LLVM_OBJDUMP, "-d", binary]))
    if max_funcs:
        gt = dict(list(gt.items())[:max_funcs])

    total = covered = 0
    mn_total = mn_ok = 0
    missing = collections.Counter()
    mismatch = collections.Counter()
    examples = collections.defaultdict(list)
    fn_rows = []
    def read_dword(binary, addr):
        with open(binary, "rb") as f:
            # find the section containing addr via PE is overkill; use objdump later
            return None
    for name, insns in gt.items():
        if not insns:
            continue
        start = insns[0][0]
        got = {}
        n_insn = (insns[-1][0] + 4 - start) // 4
        out = run([CENTRIFUGE, "spec", SPEC, binary, "disasm",
                   hex(start), str(n_insn)])
        for line in out.splitlines():
            m = re.match(r"^(0x[0-9a-fA-F]+)\s+(?:[0-9a-fA-F]{2}\s+){4}(\S+)", line)
            if m:
                got[int(m.group(1), 16)] = m.group(2).lower()
        # per-insn fallback probe for addresses the batch missed
        for a, _mn, _raw in insns:
            if a not in got:
                out1 = run([CENTRIFUGE, "spec", SPEC, binary, "disasm",
                            hex(a), "1"])
                for line in out1.splitlines():
                    m = re.match(r"^(0x[0-9a-fA-F]+)\s+(?:[0-9a-fA-F]{2}\s+){4}(\S+)", line)
                    if m:
                        got[int(m.group(1), 16)] = m.group(2).lower()
                        break
        empty = 0
        f_total = len(insns)
        f_cov = sum(1 for a, _, _r in insns if a in got)
        f_mn = 0
        for a, mn, raw in insns:
            if a not in got:
                missing[canon(mn)] += 1
                if len(examples[("miss", canon(mn))]) < 4:
                    examples[("miss", canon(mn))].append((hex(a), mn, raw))
                continue
            if canon(mn) == canon(got[a]):
                f_mn += 1
            else:
                key = (canon(mn), canon(got[a]))
                mismatch[key] += 1
                if len(examples[("mis", key)]) < 4:
                    examples[("mis", key)].append((hex(a), mn, got[a], raw))
        total += f_total
        covered += f_cov
        mn_total += f_cov
        mn_ok += f_mn
        fn_rows.append((name, f_total, f_cov, f_mn))

    print(f"functions: {len(fn_rows)}")
    print(f"instruction coverage: {covered}/{total} = "
          f"{100.0*covered/max(total,1):.1f}%")
    print(f"mnemonic match (of covered): {mn_ok}/{mn_total} = "
          f"{100.0*mn_ok/max(mn_total,1):.1f}%")
    print("\nworst functions (coverage):")
    for name, t, c, m in sorted(fn_rows, key=lambda r: r[2]/max(r[1], 1))[:10]:
        print(f"  {name}: {c}/{t} cov, {m} mnemonic")
    print("\nmissing mnemonic classes (objdump truth):")
    for k, v in missing.most_common(25):
        print(f"  {v:5d}  {k}")
    print("\nmnemonic mismatches (truth -> ours):")
    for (a, b), v in mismatch.most_common(25):
        print(f"  {v:5d}  {a} -> {b}")
    print("\nexamples:")
    for k, vals in examples.items():
        print(f"  {k}:")
        for v in vals:
            print(f"    {v}")


if __name__ == "__main__":
    main()
