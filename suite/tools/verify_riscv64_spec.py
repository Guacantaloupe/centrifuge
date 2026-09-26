#!/usr/bin/env python3
"""Coverage/mnemonic verifier for sleigh/riscv64.slaspec.

Ground truth: riscv64-unknown-elf-objdump -d.  Compares canonical
mnemonic families over every instruction of every function.

Usage: verify_riscv64_spec.py <elf> [--max-funcs N]
"""
import collections
import re
import subprocess
import sys

OBJDUMP = r"C:\msys64\mingw64\bin\riscv64-unknown-elf-objdump.exe"
CENTRIFUGE = r"C:\Users\scree\kimi\workspace\centrifuge\build\Release\centrifuge.exe"
SPEC = r"C:\Users\scree\kimi\workspace\centrifuge\sleigh\riscv64.slaspec"


def run(cmd, timeout=120):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r.stdout + r.stderr


def parse_objdump(text):
    funcs = {}
    cur = None
    insn_re = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{4,8})\s+(\S+)")
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
                               im.group(2)))
    return funcs


def canon(m):
    """Canonical mnemonic family; objdump prints uncompressed aliases."""
    m = m.lower()
    if m.startswith("c."):
        m = m[2:]
    # our spec names are uppercase with optional C. prefix -> same map
    m = m.replace(".", "_")
    # aliases seen from gcc -O2 output
    m = {"mov": "add", "not": "xori", "neg": "sub", "negw": "subw",
         "seqz": "sltiu",
         "snez": "sltu", "sltz": "slt", "sgtz": "slt", "zext_b": "andi",
         "beqz": "beq", "bnez": "bne", "blez": "bge", "bgez": "bge",
         "bltz": "blt", "bgtz": "blt",
         "j": "jal", "jr": "jalr", "ret": "jalr", "call": "jal",
         "callr": "jalr", "tail": "auipc", "la": "auipc", "lla": "auipc",
         "nop": "addi", "li": "addi", "mv": "addi",
         # compressed-stack aliases printed by objdump
         "ldsp": "ld", "sdsp": "sd", "lwsp": "lw", "swsp": "sw",
         "addi16sp": "addi", "addi4spn": "addi",
         "sext_w": "addiw", "csrw": "csrrw"}.get(m, m)
    return m


def main():
    binary = sys.argv[1]
    max_funcs = None
    if "--max-funcs" in sys.argv:
        max_funcs = int(sys.argv[sys.argv.index("--max-funcs") + 1])

    gt = parse_objdump(run([OBJDUMP, "-d", binary]))
    if max_funcs:
        gt = dict(list(gt.items())[:max_funcs])

    total = covered = 0
    mn_total = mn_ok = 0
    missing = collections.Counter()
    mismatch = collections.Counter()
    examples = collections.defaultdict(list)
    fn_rows = []
    for name, insns in gt.items():
        if not insns:
            continue
        start = insns[0][0]
        got = {}
        out = run([CENTRIFUGE, "spec", SPEC, binary, "disasm",
                   hex(start), str(len(insns))])
        for line in out.splitlines():
            m = re.match(r"^(0x[0-9a-fA-F]+)\s+(?:[0-9a-fA-F]{2}\s+){2,4}(\S+)", line)
            if m:
                got[int(m.group(1), 16)] = m.group(2).lower()
        # per-insn fallback for addresses the batch missed
        for a, _mn, _raw in insns:
            if a not in got:
                out1 = run([CENTRIFUGE, "spec", SPEC, binary, "disasm",
                            hex(a), "1"])
                for line in out1.splitlines():
                    m = re.match(r"^(0x[0-9a-fA-F]+)\s+(?:[0-9a-fA-F]{2}\s+){2,4}(\S+)", line)
                    if m:
                        got[int(m.group(1), 16)] = m.group(2).lower()
                        break
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
