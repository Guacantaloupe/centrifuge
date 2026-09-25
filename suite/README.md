# Centrifuge Decompilation Quality Suite

A near-complete corpus for judging Centrifuge's decompilation quality:
47 algorithm families, each compiled under up to 11 compiler configurations,
analyzed by Centrifuge, and scored on signature recovery, CFG coverage, and
output sanity.

## Compiler matrix

| Config | Toolchain | Status |
|---|---|---|
| msvc-o0/o2/o3-x64 | VS2022 Community (`cl`) | supported |
| clang-o0/o2/o3-x64 | msys2 clang64 | supported |
| gcc-o0/o2/o3-x64 | msys2 mingw64 | supported |
| clang-o2-arm64 | clang `--target=aarch64-windows` | pending (needs ARM64 spec) |
| gcc-o2-riscv64 | riscv64 cross gcc → ELF | pending (needs cross toolchain) |

## Layout

- `src/` — one translation unit per algorithm family (`NN_family.c` / `.cpp`);
  every bullet variant from the family spec is a separate entry function.
- `build.py` — compiles the matrix, runs `centrifuge analyze-all` per binary,
  scores, and writes `report/report.json` + `report/report.md`.
- `out/` — compiled binaries (gitignored).
- `report/` — scoring output (gitignored).

## Usage

```
python suite/build.py                 # all families x all available configs
python suite/build.py --family 01     # one family
python suite/build.py --config msvc-o2-x64,clang-o2-x64
```

## Scoring

Per binary, per config:
- **discovered / analyzed / complete** function counts
- **signature score**: fraction of parameters carrying a non-default type
  (pointer or narrow integer) instead of the `uint64_t` fallback
- **returns score**: fraction of returns with a recovered non-uint64 type
- **cfg coverage**: analyzed blocks vs. executable code size heuristic
- **decompile sanity** (optional, `--decompile-sample`): sampled functions
  must produce output without falling back to raw pcode dumps
