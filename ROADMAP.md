# Roadmap — reimplementing Ghidra in C++17

Ghidra's architecture maps cleanly onto layers. Each milestone is
independently testable.

## ✅ v0.1 — Foundation (done)
- Memory image model with per-block permissions
- ELF32/ELF64 loader (PT_LOAD image, sections, symtab/dynsym, entry)
- PE32/PE32+ loader (sections, export table)
- Disassembler abstraction; Capstone backend w/ branch-target resolution;
  raw-byte fallback so the pipeline never blocks on a missing decoder
- Function discovery: symbol seeds + recursive-descent scan
- CLI: `info`, `funcs`, `disasm`, `dump`

## 🎯 v0.2 — Deeper loading & first real analysis (next)
- Mach-O loader (fat/thin, LC_MAIN, dyld exports); raw/binary format; archives
- Better function discovery: follow conditional-branch targets (CFG build),
  BFS over basic blocks, call-graph view (`calls <fn>`), XREFs to data
  (`xrefs <addr>`)
- String discovery (ASCII/UTF-16) in data sections — Ghidra's "Defined Strings"
- Stack-referencing locals: mark `[rbp-0x8]`-style operands in listings
- ARM64/ARM/RISC-V smoke tests via generated samples

## 🎯 v0.3 — The Sleigh gap: spec-driven disassembly
Ghidra's disassembler is driven by `.sla` language specs. Reimplementing it is
the defining challenge of this project. Plan:
1. A **p-code engine**: varnodes, micro-ops (COPY, INT_ADD, BRANCH, CALL,
   LOAD/STORE, ...), a tiny interpreter + validator
2. A **SLEIGH parser** for a practical subset of `.slaspec` (constructor
   tables, operand fields, pattern matching, semantic sections emitting p-code)
3. Convert existing Capstone backend → p-code for testing parity, then switch
   the front end to real Sleigh specs (x86-64 first; add `-I sleigh/` spec dir)
4. `ghra <file> pcode <addr>` — dump p-code listings

## 🎯 v0.4 — Decompiler front end
- P-code → CFG (basic blocks, dominators)
- SSA construction, dead-code elimination, constant propagation,
  copy propagation, expression tree building
- `ghra <file> decompile <fn>` — first C-like output

## 🎯 v0.5 — Decompiler back end + types
- Calling conventions (cdecl/SystemV/Win64), stack-frame recovery, param/return
  typing, structure recovery (array/struct detection)
- High-quality C emitter (loops, switches, if-chains)
- Goal: decompile the v0.1 samples to *exactly* the C they were written from

## 🎯 v0.6 — GUI + scripting
- Dear ImGui (or Qt) listing window: navigation, function map, cross-refs
- Project model (multi-file workspace) — the "Ghidra project" concept
- Scripting API (Lua via sol2, or embedded Python) driving the core library

## 🎯 v0.7 — Breadth
- More formats: Mach-O, raw, Android boot images, archives, minidumps
- More ISAs: MIPS, PPC, 68K, AVR, MSP430 (pure Sleigh-spec wins once v0.3 lands)
- Analysis: calling-convention recovery, switch-table recovery, type
  propagation across functions, obfuscation-resistant passes

## Non-goals (for now)
- Binary patch/export round-trip (Ghidra's `Export`), diffing, debugger
  integration, headless scripting parity

## Guiding principle
Each layer is tested against *deterministic hand-built binaries*
(`tests/make_samples.py`), so a regression in the loader or analysis is always
reproducible without external toolchains.
