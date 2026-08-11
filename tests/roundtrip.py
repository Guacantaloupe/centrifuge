#!/usr/bin/env python3
"""Round-trip test: decompile functions from real compiler output, wrap the
output as C, compile it, and check it produces the same results as the
original C."""
import argparse
import atexit
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--centrifuge", default="build/centrifuge.exe")
parser.add_argument("--source-dir", default=str(Path(__file__).resolve().parents[1]))
parser.add_argument("--cc", default="gcc")
parser.add_argument("--work-dir")
parser.add_argument("--large", action="store_true",
                    help="run the deterministic high-volume differential corpus")
args = parser.parse_args()

ROOT = Path(args.source_dir).resolve()
SPEC = ROOT / "sleigh" / "riscv64.slaspec"
ELF = ROOT / "tests" / "real_riscv2.elf"
GHR = Path(args.centrifuge).resolve()
CC = args.cc
if args.work_dir:
    WORK = Path(args.work_dir).resolve()
    WORK.mkdir(parents=True, exist_ok=True)
else:
    WORK = Path(tempfile.mkdtemp(prefix="centrifuge-roundtrip-"))
    atexit.register(shutil.rmtree, WORK, ignore_errors=True)

FUNCS = [
    # name, addr, argc, kind ("plain" | "array"), vectors
    ("fib",       0x80000040, 1, "plain", list(range(0, 11))),
    ("sum_array", 0x800003E4, 2, "array", [[1, 2, 3, 4], [5], [], [7, -1, 3]]),
]
if args.large:
    # Keep the corpus deterministic so a mismatch is reproducible by vector
    # number alone.  Lengths cross cache-line and common unroll boundaries;
    # values include both signs and deliberately exercise signed overflow-free
    # accumulation over more than one thousand independently compiled calls.
    arrays = []
    for case in range(1024):
        length = (case * 37) % 65
        arrays.append([
            ((case * 131 + index * 977 + index * index * 17) % 2001) - 1000
            for index in range(length)
        ])
    FUNCS = [
        ("fib", 0x80000040, 1, "plain", list(range(-4, 21))),
        ("sum_array", 0x800003E4, 2, "array", arrays),
    ]

# all decompiled functions take 8 register args (calls pass a0..a7)
SIG = "int64_t %s(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7)"
REG_DECL = (
    "int64_t zero=0, ra, sp, gp, tp, t0, t1, t2, s0, s1, "
    "a0=p0, a1=p1, a2=p2, a3=p3, a4=p4, a5=p5, a6=p6, a7=p7, "
    "s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, t3, t4, t5, t6;"
)

def decompile(name, addr):
    r = subprocess.run([str(GHR), "spec", str(SPEC), str(ELF),
                        "decompile", hex(addr)],
                       capture_output=True, text=True, check=True)
    lines = [l for l in r.stdout.splitlines()
             if l.strip() and not l.startswith("// decompiled")]
    return "\n".join(lines)

body = {}
for name, addr, *_ in FUNCS:
    body[name] = decompile(name, addr)

harness = ["#include <stdint.h>", "#include <stdio.h>", ""]
# forward declarations (self-recursion)
harness.append("int64_t fib(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7);")
harness.append("int64_t sum_array(int64_t p0, int64_t p1, int64_t p2, int64_t p3, int64_t p4, int64_t p5, int64_t p6, int64_t p7);")
harness.append("")

for name, addr, argc, kind, vectors in FUNCS:
    decl = REG_DECL
    vers = sorted(set(re.findall(r'\b(?:local_m\d+|local_\d+|[a-z][a-z0-9]*_\d+)\b', body[name])))
    vers = [v for v in vers if not re.match(r'^(a0|a1|a2|zero|sp|ra)$', v)]
    vers_decl = ("    int64_t " + ", ".join(vers) + ";") if vers else ""
    harness.append(SIG % name + " {")
    harness.append("    " + decl)
    if vers_decl:
        harness.append(vers_decl)
    harness.append(body[name])
    harness.append("}")
    harness.append("")

harness.append("int main(void) {")
for name, addr, argc, kind, vectors in FUNCS:
    if kind == "array":
        for i, arr in enumerate(vectors):
            decl = "int a%d[%d] = {%s};" % (i, len(arr), ", ".join(str(x) for x in arr))
            harness.append("    " + decl)
            harness.append('    printf("%%lld\\n", (long long)sum_array((int64_t)a%d, %d, 0, 0, 0, 0, 0, 0));' % (i, len(arr)))
    else:
        for vec in vectors:
            vec = vec if isinstance(vec, tuple) else (vec,)
            args = ", ".join(str(v) for v in vec)
            pad = 8 - len(vec)
            if pad > 0:
                args += ", " + ", ".join(["0"] * pad)
            harness.append('    printf("%%lld\\n", (long long)%s(%s));' % (name, args))
harness.append("    return 0;")
harness.append("}")
dec_source = WORK / "dec_harness.c"
dec_source.write_text("\n".join(harness) + "\n", encoding="utf-8")

# original ground truth (drop the source's main - it has nested braces)
src = (ROOT / "tests" / "real_riscv2.c").read_text(encoding="utf-8")
i = src.find('int main')
if i >= 0:
    src = src[:i]
orig = ["#include <stdio.h>", ""] + src.splitlines()
orig.append("")
orig.append("int main(void) {")
for name, addr, argc, kind, vectors in FUNCS:
    if kind == "array":
        for i, arr in enumerate(vectors):
            decl = "int a%d[%d] = {%s};" % (i, len(arr), ", ".join(str(x) for x in arr))
            orig.append("    " + decl)
            orig.append('    printf("%%lld\\n", (long long)sum_array(a%d, %d));' % (i, len(arr)))
    else:
        for vec in vectors:
            vec = vec if isinstance(vec, tuple) else (vec,)
            args = ", ".join(str(v) for v in vec)
            orig.append('    printf("%%lld\\n", (long long)%s(%s));' % (name, args))
orig.append("    return 0;")
orig.append("}")
orig_source = WORK / "orig_harness.c"
orig_source.write_text("\n".join(orig) + "\n", encoding="utf-8")

exe_suffix = ".exe" if os.name == "nt" else ""
dec_exe = WORK / ("dec_test" + exe_suffix)
orig_exe = WORK / ("orig_test" + exe_suffix)
for source, exe in [(dec_source, dec_exe), (orig_source, orig_exe)]:
    r = subprocess.run([CC, "-O0", "-o", str(exe), str(source)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("COMPILE FAIL:", source)
        print(r.stderr)
        sys.exit(1)

d = subprocess.run([str(dec_exe)], capture_output=True, text=True, check=True).stdout
o = subprocess.run([str(orig_exe)], capture_output=True, text=True, check=True).stdout
dl, ol = d.splitlines(), o.splitlines()
if dl == ol:
    print("ROUND-TRIP OK: decompiled output matches original C on %d test vectors" % len(dl))
else:
    print("MISMATCH (%d vs %d lines)" % (len(dl), len(ol)))
    for i, (a, b) in enumerate(zip(dl, ol)):
        if a != b:
            print("  vector %d: decompiled=%s original=%s" % (i, a, b))
    sys.exit(1)
