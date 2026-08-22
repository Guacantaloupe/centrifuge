#!/usr/bin/env python3
"""Locate the recovered function containing a VA (for crash analysis)."""
import glob, re, sys

def main():
    src_dir = sys.argv[1] if len(sys.argv) > 1 else 'build-recheck/src'
    target = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x14047F9AD
    rel = target - 0x140000000
    defs = []
    for path in sorted(glob.glob(src_dir + '/recovered_*.cpp')):
        for line_no, line in enumerate(open(path, encoding='utf-8-sig'), 1):
            m = re.match(r'^(?:uint64_t|void) (FUN_[0-9A-F]{16})\(',
                         line)
            if m:
                defs.append((int(m.group(1)[4:], 16), path, line_no))
    defs.sort()
    if defs:
        print(f'defs {len(defs)} min=0x{defs[0][0]:X} max=0x{defs[-1][0]:X}')
    nearest = None
    for d in defs:
        if d[0] <= target:
            nearest = d
        else:
            break
    if not nearest:
        print(f'no definition at or below 0x{target:X} ({len(defs)} defs)')
        return
    print(f'target 0x{target:X} (rel 0x{rel:X}) -> '
          f'FUN_000000014{nearest[0]:X} at {nearest[1]}:{nearest[2]}')
    lines = open(nearest[1], encoding='utf-8-sig').readlines()
    for line in lines[nearest[2]-1:nearest[2]+24]:
        print(line.rstrip())

if __name__ == '__main__':
    main()
