#!/usr/bin/env python3
"""Centrifuge decompilation quality suite driver.

Compiles every suite/src family under every available compiler config,
runs `centrifuge analyze-all` on each binary, scores signature/return/CFG
recovery, and writes report/report.json + report/report.md.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
OUT = ROOT / "out"
REPORT = ROOT / "report"
CENTRIFUGE = REPO / "build" / "Release" / "centrifuge.exe"
SPEC_X64 = REPO / "sleigh" / "x86-64.slaspec"

CLANG = r"C:\msys64\clang64\bin\clang.exe"
CLANGXX = r"C:\msys64\clang64\bin\clang++.exe"
GCC = r"C:\msys64\mingw64\bin\gcc.exe"
GXX = r"C:\msys64\mingw64\bin\g++.exe"
VSDEV = (r'call "C:\Program Files\Microsoft Visual Studio\2022\Community'
         r'\Common7\Tools\VsDevCmd.bat" -arch=x64 >nul && ')

# name -> dict(lang tool per source suffix, opt levels, available)
CONFIGS = {
    "msvc-o0-x64":   {"kind": "msvc", "opt": "/Od"},
    "msvc-o2-x64":   {"kind": "msvc", "opt": "/O2"},
    "msvc-o3-x64":   {"kind": "msvc", "opt": "/O3"},
    "clang-o0-x64":  {"kind": "clang", "opt": "-O0"},
    "clang-o2-x64":  {"kind": "clang", "opt": "-O2"},
    "clang-o3-x64":  {"kind": "clang", "opt": "-O3"},
    "gcc-o0-x64":    {"kind": "gcc", "opt": "-O0"},
    "gcc-o2-x64":    {"kind": "gcc", "opt": "-O2"},
    "gcc-o3-x64":    {"kind": "gcc", "opt": "-O3"},
    "clang-o2-arm64": {"kind": "clang-arm64", "opt": "-O2", "available": False},
    "gcc-o2-riscv64": {"kind": "gcc-riscv64", "opt": "-O2", "available": False},
}

SIG_RE = re.compile(r"^(?P<decl>.+?) @ 0x(?P<addr>[0-9A-Fa-f]+)(?P<flags>.*)$")
STAT_RE = re.compile(
    r"cfg=(?P<cfg>\d+) phi=(?P<phi>\d+) ops=(?P<ops>\d+) "
    r"callers=(?P<callers>\d+) callees=(?P<callees>\d+)")
PARAM_DEFAULT_RE = re.compile(r"^(u?int64_t|uint64_t) arg\d+$")
DEF_RE = re.compile(
    r"^\s*(?:static\s+)?[A-Za-z_][\w\s\*]*?\b(\w+)\s*\([^;{}]*\)\s*(?:\{|$)")
CONTROL = {"if", "for", "while", "switch", "return", "sizeof"}


def defined_names(src: Path):
    names = set()
    for line in src.read_text(encoding="utf-8").splitlines():
        m = DEF_RE.match(line)
        if m and m.group(1) not in CONTROL:
            names.add(m.group(1))
    names.discard("main")
    return names


def run(cmd, cwd=None, shell=False, timeout=600, env=None):
    return subprocess.run(cmd, cwd=cwd, shell=shell, env=env,
                          capture_output=True, text=True, timeout=timeout)


def tool_env(bin_dir: str):
    env = os.environ.copy()
    env["PATH"] = bin_dir + os.pathsep + env.get("PATH", "")
    return env


def compile_one(src: Path, cfg_name: str, cfg: dict, exe: Path,
                suite_names=None):
    kind = cfg["kind"]
    opt = cfg["opt"]
    is_cpp = src.suffix == ".cpp"
    addr2name = {}
    if kind == "msvc":
        stdflag = "/std:c++17" if is_cpp else "/std:c11"
        map_file = exe.with_suffix(".map")
        obj_dir = OUT / "obj" / exe.stem
        obj_dir.mkdir(parents=True, exist_ok=True)
        # MSVC links strip the COFF symbol table, which both hides names
        # and (worse) leaves frameless switch-only functions undiscoverable
        # by the prologue scanner.  Exporting every suite function puts it
        # in the PE export directory: real names + guaranteed discovery.
        def_file = exe.with_suffix(".def")
        if suite_names:
            def_file.write_text(
                "LIBRARY {}\nEXPORTS\n{}\n".format(
                    exe.stem, "\n".join(sorted(suite_names))))
        bat = ROOT / "msvc_build.bat"
        res = run(["cmd", "/c", str(bat), opt, stdflag, str(exe),
                   str(obj_dir) + "\\", str(src), str(map_file),
                   str(def_file)])
        addr2name = parse_map(map_file)
    elif kind == "clang":
        compiler = CLANGXX if is_cpp else CLANG
        stdflag = "-std=c++17" if is_cpp else "-std=c11"
        res = run([compiler, opt, stdflag, "-w", "-o", str(exe), str(src)],
                  env=tool_env(str(Path(CLANG).parent)))
    elif kind == "gcc":
        compiler = GXX if is_cpp else GCC
        stdflag = "-std=c++17" if is_cpp else "-std=c11"
        res = run([compiler, opt, stdflag, "-w", "-o", str(exe), str(src)],
                  env=tool_env(str(Path(GCC).parent)))
    else:
        return "skip"
    if res.returncode != 0 or not exe.exists():
        return (res.stderr or res.stdout or "compile failed").strip()[-400:], {}
    return "", addr2name


MAP_RE = re.compile(r"^\s*\d+:[0-9a-fA-F]+\s+(\S+)\s+([0-9a-fA-F]{8,16})\s")


def parse_map(map_file: Path):
    """MSVC links strip the PE COFF symbol table; recover name->address
    from the linker .map instead (C symbols: leading underscore; C++:
    decorated, matched by substring later)."""
    addr2name = {}
    if not map_file.exists():
        return addr2name
    for line in map_file.read_text(errors="replace").splitlines():
        m = MAP_RE.match(line)
        if not m:
            continue
        sym, addr = m.group(1), int(m.group(2), 16)
        addr2name[addr] = sym
    return addr2name


def analyze(exe: Path, spec: Path, suite_names=None, addr2name=None) -> dict:
    res = run([str(CENTRIFUGE), "spec", str(spec), str(exe), "analyze-all"],
              timeout=900)
    text = res.stdout
    funcs = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = SIG_RE.match(line.strip())
        if not m:
            continue
        decl = m.group("decl").strip()
        if suite_names is not None:
            nm = re.search(r"\b(\w+)\s*\(", decl)
            name = nm.group(1) if nm else ""
            if name.startswith("FUN_") and addr2name:
                addr = int(m.group("addr"), 16)
                sym = addr2name.get(addr, "")
                if any(n in sym for n in suite_names):
                    name = sym
            if name not in suite_names:
                # MSVC C symbols carry a leading underscore
                if not any(name in s or s in name
                           for s in suite_names if len(s) > 4):
                    continue
        incomplete = "[incomplete]" in m.group("flags")
        # return type: everything before the last identifier before '('
        ret = "uint64_t"
        head = decl.split("(", 1)[0]
        mm = re.match(r"^(.*?)([A-Za-z_][A-Za-z0-9_]*)$", head)
        if mm:
            ret = mm.group(1).strip() or "uint64_t"
        params = ""
        pm = re.search(r"\((.*)\)\s*$", decl)
        if pm:
            params = pm.group(1).strip()
        plist = ([] if params in ("", "void")
                 else [p.strip() for p in params.split(",")])
        stat = {}
        if i + 1 < len(lines):
            sm = STAT_RE.search(lines[i + 1])
            if sm:
                stat = {k: int(v) for k, v in sm.groupdict().items()}
        funcs.append({"decl": decl, "return": ret, "params": plist,
                      "incomplete": incomplete, **stat})
    n = len(funcs)
    p_total = sum(len(f["params"]) for f in funcs)
    p_typed = sum(1 for f in funcs for p in f["params"]
                  if not PARAM_DEFAULT_RE.match(p))
    r_total = n
    r_typed = sum(1 for f in funcs
                  if f["return"] not in ("uint64_t", "int64_t"))
    complete = sum(1 for f in funcs if not f["incomplete"])
    return {
        "exit": res.returncode,
        "functions": n,
        "complete": complete,
        "params_total": p_total,
        "params_typed": p_typed,
        "params_score": round(p_typed / p_total, 3) if p_total else 0.0,
        "returns_typed": r_typed,
        "returns_score": round(r_typed / r_total, 3) if r_total else 0.0,
        "blocks": sum(f.get("cfg", 0) for f in funcs),
        "ops": sum(f.get("ops", 0) for f in funcs),
        "sample": funcs[:8],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--family", default="")
    ap.add_argument("--config", default="")
    ap.add_argument("--configs", action="store_true",
                    help="list configs and exit")
    args = ap.parse_args()
    if args.configs:
        for name, cfg in CONFIGS.items():
            print(name, "available" if cfg.get("available", True)
                  else "PENDING")
        return 0

    OUT.mkdir(exist_ok=True)
    REPORT.mkdir(exist_ok=True)
    families = sorted((ROOT / "src").glob("*.*"))
    if args.family:
        wanted_f = args.family.split(",")
        families = [f for f in families
                    if any(f.stem.startswith(w) for w in wanted_f)]
    if not families:
        sys.exit("no families matched")
    configs = list(CONFIGS)
    if args.config:
        wanted = args.config.split(",")
        configs = [c for c in configs if c in wanted]

    results = {}
    for src in families:
        results[src.stem] = {}
    jobs = [(src, cfg_name) for src in families for cfg_name in configs]
    import concurrent.futures as cf

    def run_job(job):
        src, cfg_name = job
        fam = src.stem
        cfg = CONFIGS[cfg_name]
        if not cfg.get("available", True):
            return fam, cfg_name, {"status": "pending"}
        exe = OUT / f"{fam}--{cfg_name}.exe"
        if exe.exists():
            exe.unlink()
        err, addr2name = compile_one(src, cfg_name, cfg, exe,
                                     defined_names(src))
        if err == "skip":
            return fam, cfg_name, {"status": "pending"}
        if err:
            return fam, cfg_name, {"status": "compile-error", "error": err}
        try:
            info = analyze(exe, SPEC_X64, defined_names(src), addr2name)
            info["status"] = "ok"
        except subprocess.TimeoutExpired:
            info = {"status": "analyze-timeout"}
        return fam, cfg_name, info

    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        for fam, cfg_name, info in pool.map(run_job, jobs):
            results[fam][cfg_name] = info
            print(f"{fam} {cfg_name}: {info.get('status')}", flush=True)

    (REPORT / "report.json").write_text(json.dumps(results, indent=1))

    cols = configs
    lines = ["# Decompilation quality report", "",
             "cell = params typed % (signature recovery)", "",
             "| family | " + " | ".join(cols) + " |",
             "|---|" + "---|" * len(cols)]
    for fam, per in results.items():
        row = [fam]
        for c in cols:
            r = per.get(c, {})
            if r.get("status") == "ok":
                row.append(f"{r['params_score']*100:.0f}% "
                           f"({r['params_typed']}/{r['params_total']})")
            else:
                row.append(r.get("status", "-"))
        lines.append("| " + " | ".join(row) + " |")
    (REPORT / "report.md").write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    print(f"\nreport -> {REPORT / 'report.md'}")


if __name__ == "__main__":
    main()
