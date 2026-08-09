#!/usr/bin/env python3
"""Generate tiny, hand-crafted test binaries for ghra.

Produces (no assembler required, all bytes written explicitly):
  samples/sample_elf64   - ELF64 x86-64 ET_EXEC, 2 funcs + 1 data sym
  samples/sample_elf32   - ELF32 x86    ET_EXEC, same shape
  samples/sample_pe64.exe- PE32+ x86-64 with 2 exports + entry stub
"""
import struct
import os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples")
os.makedirs(OUT, exist_ok=True)


def align_up(n, a):
    return (n + a - 1) & ~(a - 1)


def cstr(s):
    return s.encode() + b"\0"


# ---------------------------------------------------------------- ELF
def build_elf(is64):
    if is64:
        ehdr_fmt = "<16sHHIQQQIHHHHHH"  # e_ident,type,machine,version,entry,phoff,shoff,flags,ehsize,phentsize,phnum,shentsize,shnum,shstrndx
        phdr_fmt = "<IIQQQQQQ"
        shdr_fmt = "<IIQQQQIIQQ"
        sym_fmt = "<IBBHQQ"
        ehsz, phsz, shsz, symsz = 64, 56, 64, 24
        machine = 62
    else:
        ehdr_fmt = "<16sHHIIIIIHHHHHH"
        phdr_fmt = "<IIIIIIII"
        shdr_fmt = "<IIIIIIIIII"
        sym_fmt = "<IIIBBH"
        ehsz, phsz, shsz, symsz = 52, 32, 40, 16
        machine = 3

    text_va = 0x401000 if is64 else 0x8048000
    data_va = 0x402000 if is64 else 0x8049000
    entry = text_va

    if is64:
        text = bytes.fromhex(
            "55 48 89 e5 e8 17 00 00 00 b8 00 00 00 00 5d c3"  # main 0x..0x10
            "55 48 89 e5 b8 2a 00 00 00 5d c3"                # helper 0x10..0x1c
        )
    else:
        text = bytes.fromhex(
            "55 89 e5 e8 18 00 00 00 b8 00 00 00 00 5d c3"  # main
            "55 89 e5 b8 2a 00 00 00 5d c3"                # helper
        )
    text = text + b"\xcc" * (0x30 - len(text))
    data = cstr("hello from ghra sample")

    # section name tables -------------------------------------------------
    shstr = b"\0" + b"\0".join([b".text", b".data", b".symtab",
                                b".strtab", b".shstrtab"]) + b"\0"
    strtab = b"\0" + b"\0".join([b"main", b"helper", b"msg"]) + b"\0"
    off_main = strtab.index(b"main")
    off_helper = strtab.index(b"helper")
    off_msg = strtab.index(b"msg")
    off_sec_text = shstr.index(b".text")
    off_sec_data = shstr.index(b".data")
    off_sec_sym = shstr.index(b".symtab")
    off_sec_str = shstr.index(b".strtab")
    off_sec_shstr = shstr.index(b".shstrtab")

    n_sh = 6
    shoff = ehsz + 2 * phsz
    shstr_off = shoff + n_sh * shsz
    str_off = shstr_off + len(shstr)
    sym_off = align_up(str_off + len(strtab), 8)
    text_off = 0x1000
    data_off = 0x2000

    if is64:
        # Sym64: name(I), info(B), other(B), shndx(H), value(Q), size(Q)
        syms = [
            (0, 0, 0, 0, 0, 0),
            (off_main, 0x12, 0, 1, text_va, 0x10),      # main  FUNC GLOBAL
            (off_helper, 0x12, 0, 1, text_va + 0x20, 0x0C),
            (off_msg, 0x11, 0, 2, data_va, 0x15),       # msg   OBJECT GLOBAL
        ]
    else:
        # Sym32: name(I), value(I), size(I), info(B), other(B), shndx(H)
        syms = [
            (0, 0, 0, 0, 0, 0),
            (off_main, text_va, 0x10, 0x12, 0, 1),
            (off_helper, text_va + 0x20, 0x0C, 0x12, 0, 1),
            (off_msg, data_va, 0x15, 0x11, 0, 2),
        ]

    def sh(name, typ, flags, addr, off, size, link=0, info=0, align=0, ents=0):
        if is64:
            return struct.pack(shdr_fmt, name, typ, flags, addr, off, size,
                               link, info, align, ents)
        return struct.pack(shdr_fmt, name, typ, flags, addr, off, size,
                           link, info, align, ents)

    shdrs = b""
    shdrs += sh(0, 0, 0, 0, 0, 0)
    shdrs += sh(off_sec_text, 1, 0x6, text_va, text_off, len(text),
                align=16)                            # .text
    shdrs += sh(off_sec_data, 1, 0x3, data_va, data_off, len(data))  # .data
    shdrs += sh(off_sec_sym, 2, 0, 0, sym_off, len(syms) * symsz,
                link=4, info=1, align=8, ents=symsz)  # .symtab
    shdrs += sh(off_sec_str, 3, 0, 0, str_off, len(strtab))  # .strtab
    shdrs += sh(off_sec_shstr, 3, 0, 0, shstr_off, len(shstr))  # .shstrtab

    ident = bytes([0x7F, ord("E"), ord("L"), ord("F")]) + bytes(
        [2 if is64 else 1, 1, 1, 0]) + b"\0" * 8
    ehdr = struct.pack(ehdr_fmt, ident, 2, machine, 1, entry,
                       ehsz, ehsz + 2 * phsz, 0,
                       ehsz, phsz, 2, shsz, n_sh, 5)

    if is64:
        ph1 = struct.pack(phdr_fmt, 1, 5, text_off, text_va, text_va,
                          len(text), len(text), 0x1000)
        ph2 = struct.pack(phdr_fmt, 1, 6, data_off, data_va, data_va,
                          len(data), len(data), 0x1000)
    else:
        ph1 = struct.pack(phdr_fmt, 1, text_off, text_va, text_va,
                          len(text), len(text), 5, 0x1000)
        ph2 = struct.pack(phdr_fmt, 1, data_off, data_va, data_va,
                          len(data), len(data), 6, 0x1000)
    phdrs = ph1 + ph2

    img = bytearray()
    img += ehdr + phdrs + shdrs
    img += shstr + strtab
    img += b"\0" * (sym_off - len(img))
    for s in syms:
        img += struct.pack(sym_fmt, *s)
    img += b"\0" * (text_off - len(img))
    img += text
    img += b"\0" * (data_off - len(img))
    img += data
    return bytes(img)


# ---------------------------------------------------------------- PE32+
def build_pe64():
    imgbase = 0x140000000
    entry_rva = 0x1009
    text = bytes.fromhex(
        "8d 04 11 c3"                       # sample_add: lea eax,[rcx+rdx]; ret
        "89 c8 29 d0 c3"                    # sample_sub: mov eax,ecx; sub eax,edx; ret
        "48 83 ec 28 b8 2a 00 00 00"        # entry stub
        "48 83 c4 28 c3"
    )
    text = text + b"\xcc" * (0x30 - len(text))

    exp_dir_rva = 0x2000
    # .rdata layout (rva offsets from 0x2000)
    dllname_off = 0x28
    funcs_off = 0x38
    names_off = 0x40
    name1_off = 0x48
    name2_off = 0x54
    ords_off = 0x60
    exp_size = 0x70

    rdata = bytearray(0x100)
    def put16(off, v): struct.pack_into("<H", rdata, off, v)
    def put32(off, v): struct.pack_into("<I", rdata, off, v)
    def put64(off, v): struct.pack_into("<Q", rdata, off, v)
    def putstr(off, s): rdata[off:off + len(s)] = s
    # IMAGE_EXPORT_DIRECTORY
    put32(0, 0)                       # Characteristics
    put32(4, 0)                       # TimeDateStamp
    put16(8, 0); put16(10, 0)         # version
    put32(12, exp_dir_rva + dllname_off)  # Name
    put32(16, 1)                      # Base
    put32(20, 2)                      # NumberOfFunctions
    put32(24, 2)                      # NumberOfNames
    put32(28, exp_dir_rva + funcs_off)   # AddressOfFunctions
    put32(32, exp_dir_rva + names_off)   # AddressOfNames
    put32(36, exp_dir_rva + ords_off)    # AddressOfNameOrdinals
    putstr(dllname_off, cstr("sample_pe64.dll"))
    put32(funcs_off + 0, 0x1000)      # sample_add rva
    put32(funcs_off + 4, 0x1004)      # sample_sub rva
    put32(names_off + 0, exp_dir_rva + name1_off)
    put32(names_off + 4, exp_dir_rva + name2_off)
    putstr(name1_off, cstr("sample_add"))
    putstr(name2_off, cstr("sample_sub"))
    put16(ords_off + 0, 0)
    put16(ords_off + 2, 1)

    # ---- headers ----
    dos = bytearray(0x40)
    struct.pack_into("<H", dos, 0, 0x5A4D)  # 'MZ'
    struct.pack_into("<I", dos, 0x3C, 0x40)  # e_lfanew

    opt = bytearray(240)
    def opt16(off, v): struct.pack_into("<H", opt, off, v)
    def opt32(off, v): struct.pack_into("<I", opt, off, v)
    def opt64(off, v): struct.pack_into("<Q", opt, off, v)
    opt16(0, 0x20B)                    # magic PE32+
    opt[2] = 0; opt[3] = 0             # linker version
    opt32(4, 0x40)                     # SizeOfCode
    opt32(8, 0x100)                    # SizeOfInitializedData
    opt32(12, 0)                       # SizeOfUninitializedData
    opt32(16, entry_rva)               # AddressOfEntryPoint
    opt32(20, 0x1000)                  # BaseOfCode
    opt64(24, imgbase)                 # ImageBase
    opt32(32, 0x1000)                  # SectionAlignment
    opt32(36, 0x200)                   # FileAlignment
    opt16(40, 6); opt16(42, 0)         # OS version
    opt16(44, 0); opt16(46, 0)         # image version
    opt16(48, 6); opt16(50, 0)         # subsystem version
    opt32(52, 0)                       # Win32VersionValue
    opt32(56, 0x3000)                  # SizeOfImage
    opt32(60, 0x200)                   # SizeOfHeaders
    opt32(64, 0)                       # CheckSum
    opt16(68, 3)                       # Subsystem = CUI
    opt16(70, 0x160)                   # DllCharacteristics
    opt64(72, 0x100000); opt64(80, 0x1000)   # stack reserve/commit
    opt64(88, 0x100000); opt64(96, 0x1000)   # heap reserve/commit
    opt32(104, 0)                      # LoaderFlags
    opt32(108, 16)                     # NumberOfRvaAndSizes
    opt32(112, exp_dir_rva)            # DataDirectory[0].VirtualAddress
    opt32(116, exp_size)               # DataDirectory[0].Size

    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, len(opt), 0x22)

    def sechdr(name, vsize, vaddr, rawsize, rawptr, chars):
        return struct.pack("<8sIIIIIIHHI", name, vsize, vaddr, rawsize,
                           rawptr, 0, 0, 0, 0, chars)

    secs = b""
    secs += sechdr(b".text", 0x30, 0x1000, 0x30, 0x200, 0x60000020)
    secs += sechdr(b".rdata", 0x100, 0x2000, 0x100, 0x300, 0x40000040)

    img = bytearray()
    img += dos
    img += b"PE\0\0" + coff + opt + secs
    img += b"\0" * (0x200 - len(img))
    img += text
    img += b"\0" * (0x300 - len(img))
    img += rdata
    return bytes(img)


elf64 = build_elf(True)
elf32 = build_elf(False)
pe64 = build_pe64()

with open(os.path.join(OUT, "sample_elf64"), "wb") as f:
    f.write(elf64)
with open(os.path.join(OUT, "sample_elf32"), "wb") as f:
    f.write(elf32)
with open(os.path.join(OUT, "sample_pe64.exe"), "wb") as f:
    f.write(pe64)

print("wrote %d bytes elf64, %d bytes elf32, %d bytes pe64 to %s"
      % (len(elf64), len(elf32), len(pe64), OUT))
