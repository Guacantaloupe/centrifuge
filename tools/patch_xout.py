#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Neutralize the _Xout_of_range throw helper in a recovered project's
runtime so run-entry can progress past out-of-range exceptions and reveal
the next fault.  Diagnostic tool only - not a fix.

Usage: python patch_xout.py [project-src-dir]
Default: build-recheck52/src (Blender recovery).
Patches recovered_runtime.cpp: after the IAT write-back loop, writes 0xC3
(ret) into the image at 0x140076810 (blender's _Xout_of_range helper).
Idempotent: replaces an existing TEMP block if present.
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "..", "build-recheck52", "src")
RUNTIME = os.path.join(SRC, "recovered_runtime.cpp")
TARGET = 0x140076810

MARK_BEGIN = "    // TEMP diagnostic: neutralize the _Xout_of_range throw helper"
MARK_END = "    *reinterpret_cast<unsigned char*>(0x%XULL) = 0xC3; // ret" % TARGET

with io.open(RUNTIME, "r", encoding="utf-8-sig") as f:
    text = f.read()

begin = text.find(MARK_BEGIN)
end = text.find(MARK_END)
if begin != -1 and end != -1 and begin < end:
    text = text[:begin] + text[end + len(MARK_END):]
    # strip the trailing newline left by the removed block
    text = text.replace("\n\n    // TEMP", "\n    // TEMP", 1) if "// TEMP" in text else text
    print("removed previous TEMP block")

needle = "    // Write resolved import addresses back into the fixed-image IAT"
pos = text.find(needle)
assert pos != -1, "IAT write-back block not found"
# insert after the closing of the write-back loop (first "    }\n" following the loop)
insert_at = text.find("    }\n", pos)
assert insert_at != -1
block = ("\n    // TEMP diagnostic: neutralize the _Xout_of_range throw helper so the\n"
         "    // run-entry chain can progress past the out-of-range exception and\n"
         "    // reveal the next fault.\n"
         "    *reinterpret_cast<unsigned char*>(0x%XULL) = 0xC3; // ret\n" % TARGET)
text = text[:insert_at + len("    }\n")] + block + text[insert_at + len("    }\n"):]

with io.open(RUNTIME, "w", encoding="utf-8-sig", newline="") as f:
    f.write(text)
print("patched %s -> ret at 0x%X" % (RUNTIME, TARGET))
