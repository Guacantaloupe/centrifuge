// centrifuge - semantic coverage auditing over executable memory blocks
#include "centrifuge/semantic_coverage.hpp"

#include <algorithm>
#include <set>

namespace centrifuge {

SemanticCoverageReport auditSemanticCoverage(const Program& program,
                                             const SleighEngine& engine,
                                             size_t maxInstructions) {
    SemanticCoverageReport report;
    auto read = [&](uint64_t address, void* output, size_t size) {
        return program.memory.read(address, output, size);
    };
    for (const MemoryBlock& block : program.memory.blocks()) {
        if (!(block.perm & static_cast<int>(Perm::X))) continue;
        report.executableBytes += block.data.size();
        uint64_t address = block.base;
        const uint64_t end = block.end();
        while (address < end && report.instructions < maxInstructions) {
            PcodeInsn instruction;
            std::string error;
            if (!engine.disassemble(read, address, instruction, error) ||
                instruction.size <= 0 ||
                static_cast<uint64_t>(instruction.size) > end - address) {
                ++report.decodeFailures;
                ++address;
                continue;
            }
            ++report.instructions;
            report.decodedBytes += static_cast<size_t>(instruction.size);
            const bool semanticNop = instruction.kind == Insn::NOP ||
                                     instruction.text == "nop" ||
                                     instruction.text == "wait";
            const bool meaningful = std::any_of(
                instruction.ops.begin(), instruction.ops.end(),
                [](const PcodeOp& operation) {
                    return operation.op != POp::X86_GUARD;
                });
            bool missing = !meaningful && !semanticNop;
            for (const PcodeOp& operation : instruction.ops)
                if (operation.op == POp::UNIMPLEMENTED) {
                    ++report.unimplementedOperations;
                    missing = true;
                }
            if (missing) {
                ++report.emptySemantics;
                const size_t separator = instruction.text.find(' ');
                const std::string mnemonic = instruction.text.substr(0, separator);
                ++report.missingByMnemonic[mnemonic];
            }
            address += static_cast<uint64_t>(instruction.size);
        }
    }
    return report;
}

ConstructorProofReport auditConstructorProof(const SleighEngine& engine) {
    ConstructorProofReport report;
    // Named shared providers with fixed hardware/reference vectors in the
    // x86 semantic tests.  New empty constructors remain unproven until they
    // are registered here together with executable evidence.
    static const std::set<std::string> verifiedShared = {
        "aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc",
        "aeskeygenassist", "vaesenc", "vaesenclast", "vaesdec",
        "vaesdeclast", "pclmulqdq", "vpclmulqdq", "vclmulhqhqdq",
        "vclmullqlqdq", "gf2p8mulb", "vgf2p8mulb", "gf2p8affineqb",
        "gf2p8affineinvqb", "vgf2p8affineqb", "vgf2p8affineinvqb",
        "sha1msg1", "sha1msg2", "sha1nexte", "sha1rnds4",
        "sha256msg1", "sha256msg2", "sha256rnds2",
        "add", "adc", "sub", "sbb", "cmp", "and", "or", "xor",
        "test", "inc", "dec", "neg", "xadd", "shl", "sal", "shr",
        "sar", "rol", "ror", "rcl", "rcr", "bt", "bts", "btr",
        "btc", "popcnt", "bsf", "bsr", "tzcnt", "lzcnt", "pdep",
        "pext", "shlx", "shrx", "sarx", "bextr", "andn",
        "bswap", "shld", "shrd", "crc32", "div", "idiv", "movd", "vmovd", "movq", "vmovq",
        "movss", "movsd",
        "pmovmskb", "vpmovmskb", "movmskps", "movmskpd", "pextrw",
        "extractps", "pextrb", "pextrd", "pextrq", "vpextrb",
        "vpextrw", "vpextrd", "vpextrq", "pinsrb", "pinsrw",
        "pinsrd", "pinsrq", "vpinsrb", "vpinsrw", "vpinsrd", "vpinsrq",
        "movups", "movupd", "movaps", "movapd", "movdqa", "movdqu",
        "vmovups", "vmovupd", "vmovaps", "vmovapd", "vmovdqa",
        "vmovdqu", "vmovdqu32", "vpaddb", "vpaddw", "vpaddd",
        "vpaddq", "vpsubb", "vpsubw", "vpsubd", "vpsubq", "paddb",
        "paddw", "paddd", "paddq", "psubb", "psubw", "psubd",
        "psubq", "paddsb", "paddsw", "paddusb", "paddusw", "psubsb",
        "psubsw", "psubusb", "psubusw", "packsswb", "packssdw",
        "packuswb", "packusdw", "punpcklbw", "punpcklwd", "punpckldq",
        "punpcklqdq", "punpckhbw", "punpckhwd", "punpckhdq",
        "punpckhqdq", "pshufb", "pshufd", "pshuflw", "pshufhw",
        "pavgb", "pavgw", "pminub", "pminsw", "pmaxub", "pmaxsw",
        "psadbw", "vpavgb", "vpavgw", "vpminub", "vpminsw", "vpmaxub",
        "vpmaxsw", "vpsadbw", "vpaddsb", "vpaddsw", "vpaddusb",
        "vpaddusw", "vpsubsb", "vpsubsw", "vpsubusb", "vpsubusw",
        "vpxord", "vpxorq", "vpandd", "vpandq", "vpord", "vporq",
        "andps", "andpd", "andnps", "andnpd", "orps", "orpd", "xorps",
        "xorpd", "vandps", "vandpd", "vandnps", "vandnpd", "vorps",
        "vorpd", "vxorps", "vxorpd", "pand", "pandn", "vpandn",
        "addsubps", "addsubpd", "blendps", "blendpd",
        "cmpps", "cmppd", "cmpss", "cmpsd",
        "comiss", "comisd", "ucomiss", "ucomisd", "vcomiss", "vcomisd",
        "vucomiss", "vucomisd",
        "cvtsi2ss", "cvtsi2sd", "cvtss2si", "cvtsd2si", "cvttss2si",
        "cvttsd2si", "cvtss2sd", "cvtsd2ss",
        "cvtdq2ps", "cvtdq2pd", "cvtps2dq", "cvttps2dq",
        "cvtpd2dq", "cvttpd2dq", "cvtps2pd", "cvtpd2ps",
        "dpps", "dppd",
        "pabsb", "pabsw", "pabsd", "pblendw", "palignr",
        "movsldup", "movshdup", "movddup",
        "phaddw", "phaddd", "phaddsw", "phsubw", "phsubd", "phsubsw",
        "pcmpistri", "pcmpistrm", "pcmpestri", "pcmpestrm",
        "pmaddwd", "pmaddubsw", "pmuldq", "pmulhrsw", "pmulld",
        "vpmaddwd", "vpmaddubsw", "vpmuldq", "vpmulhrsw", "vpmulld",
        "psignb", "psignw", "psignd", "vpsignb", "vpsignw", "vpsignd",
        "pslldq", "psrldq", "vpslldq", "vpsrldq", "ptest", "vptest",
        "rcpps", "rcpss", "rsqrtps", "rsqrtss", "vrcpps", "vrcpss",
        "vrsqrtps", "vrsqrtss", "roundps", "roundpd", "roundss",
        "roundsd", "vroundps", "vroundpd", "vroundss", "vroundsd",
        "movlps", "movlpd", "movhps", "movhpd",
        "movhlps", "movlhps", "movntdq", "movntps", "movntpd",
        "movnti", "vzeroall", "vzeroupper", "vinsertf128",
        "vextractf128", "vextracti32x4", "vperm2f128",
        "pmovsxbw", "pmovsxbd", "pmovsxbq", "pmovsxwd", "pmovsxwq",
        "pmovsxdq", "pmovzxbw", "pmovzxbd", "pmovzxbq", "pmovzxwd",
        "pmovzxwq", "pmovzxdq",
        "vpackssdw", "vpacksswb", "vpackuswb", "vpand", "vpor",
        "vpxor", "vpcmpeqb", "vpcmpeqw", "vpcmpeqd", "vpcmpgtb",
        "vpcmpgtw", "vpcmpgtd", "vpshufb", "vpunpcklbw",
        "vpunpcklwd", "vpunpckldq", "vpunpcklqdq", "vpunpckhbw",
        "vpunpckhwd", "vpunpckhdq", "vpunpckhqdq", "vunpcklps",
        "vunpcklpd", "vunpckhps", "vunpckhpd",
        "haddps", "haddpd", "hsubps", "hsubpd",
        "shufps", "shufpd", "pcmpeqb", "pcmpeqw", "pcmpeqd",
        "pcmpeqq", "pcmpgtb", "pcmpgtw", "pcmpgtd", "pcmpgtq",
        "psllw", "pslld", "psllq", "psrlw", "psrld", "psrlq",
        "psraw", "psrad", "vpsllw", "vpslld", "vpsllq", "vpsrlw",
        "vpsrld", "vpsrlq", "vpsraw", "vpsrad",
        "vpcmpd", "vpcmpq", "vpcmpud", "vpcmpuq", "vpgatherdd",
        "vpgatherdq", "vpgatherqd", "vpgatherqq", "vpscatterdd",
        "vpscatterdq", "vpscatterqd", "vpscatterqq", "addps", "addpd",
        "addss", "addsd", "subps", "subpd", "subss", "subsd",
        "mulps", "mulpd", "mulss", "mulsd", "divps", "divpd",
        "divss", "divsd", "sqrtps", "sqrtpd", "sqrtss", "sqrtsd",
        "minps", "minpd", "minss", "minsd", "maxps", "maxpd",
        "maxss", "maxsd", "vaddps", "vaddpd", "vsubps", "vsubpd",
        "vmulps", "vmulpd", "vdivps", "vdivpd", "vsqrtps", "vsqrtpd",
        "vminps", "vminpd", "vmaxps", "vmaxpd", "fxsave", "fxrstor",
        "vaddss", "vaddsd", "vsubss", "vsubsd", "vmulss", "vmulsd",
        "vdivss", "vdivsd", "vminss", "vminsd", "vmaxss", "vmaxsd",
        "vsqrtss", "vsqrtsd",
        "xsave", "xsavec", "xsaves", "xrstor", "xrstors", "cpuid",
        "rdmsr", "wrmsr", "xgetbv", "xsetbv", "clts", "swapgs",
        "cli", "sti", "hlt", "invd", "wbinvd", "invlpg", "sgdt",
        "sidt", "lgdt", "lidt", "sldt", "str", "lldt", "ltr",
        "movcr", "in", "out", "cld", "std", "movsb", "movsq", "cmpsb",
        "stosb", "stosd", "stosq", "lodsb", "lodsd", "lodsq", "scasb",
        "scasd", "rep", "repe", "repne", "lfence", "sfence", "mfence",
        "wait", "fninit",
        "fnclex", "fnstcw", "fnstsw", "fldcw", "fld", "fld1",
        "fldz", "fldl2t", "fldl2e", "fldpi", "fldlg2", "fldln2",
        "fst", "fstp", "fild", "filds", "fistp", "fisttp", "fistps",
        "ffree", "fxch", "fchs", "fabs", "ftst", "fxam", "fdecstp",
        "fincstp", "fadd", "faddp", "fiadd", "fmul", "fmulp", "fimul",
        "fsub", "fsubr", "fsubp", "fsubrp", "fisub", "fisubr", "fdiv",
        "fdivr", "fdivp", "fdivrp", "fidiv", "fidivr", "fcom", "fcomp",
        "fucom", "fucomp", "fcompp", "fucompp", "ficom", "ficomp",
        "fcomi", "fucomi", "fcomip", "fucomip", "frndint", "f2xm1",
        "fyl2x", "fptan", "fpatan", "fprem", "fprem1", "fyl2xp1",
        "fsqrt", "fsincos", "fscale", "fsin", "fcos",
        "cdq", "clac", "clflush", "clwb", "cmpxchg16b", "cmpxchg8b",
        "cqo", "cwd", "enter", "imul", "insb", "insd", "insq", "int",
        "int1", "int3", "iret", "lahf", "lar", "ldmxcsr", "lret", "lsl",
        "monitor", "monitorx", "mul", "mwait", "mwaitx", "nop", "outsb",
        "outsd", "outsq", "pause", "pop", "popf", "por", "prefetchnta",
        "prefetcht0", "prefetcht1", "prefetcht2", "prefetchw", "pushf",
        "pxor", "rdpid", "rdpmc", "rdrand", "rdseed", "rdsspd", "rdsspq",
        "rdtsc", "rdtscp", "sahf", "salc", "stac", "stmxcsr", "syscall",
        "sysret", "ud0", "ud2", "udb", "xlat"
    };
    for (const SpecCtor& constructor : engine.ctors()) {
        ++report.constructors;
        if (!constructor.stmts.empty()) {
            ++report.inlineSpecifications;
            continue;
        }
        if (verifiedShared.count(constructor.name)) {
            ++report.sharedSpecifications;
            continue;
        }
        ++report.unproven;
        ++report.unprovenByMnemonic[constructor.name];
    }
    return report;
}

} // namespace centrifuge
