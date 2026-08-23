// x86 flag, condition-code, and conditional-move semantic tests.
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <cmath>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "centrifuge/pcode.hpp"
#include "centrifuge/decompile.hpp"
#include "centrifuge/sleigh.hpp"
#include "centrifuge/semantic_coverage.hpp"

using namespace centrifuge;

namespace {

int failures = 0;

#define CHECK(cond, msg)                                            \
    do {                                                            \
        if (!(cond)) {                                              \
            std::printf("FAIL: %s\n", msg);                        \
            ++failures;                                             \
        }                                                           \
    } while (0)

constexpr uint64_t RAX = 0;
constexpr uint64_t RBX = 3 * 8;
constexpr uint64_t RCX = 1 * 8;
constexpr uint64_t RSI = 6 * 8;
constexpr uint64_t RDI = 7 * 8;
constexpr uint64_t R12 = 12 * 8;
constexpr uint64_t CF = 4096;
constexpr uint64_t PF = 4097;
constexpr uint64_t AF = 4098;
constexpr uint64_t ZF = 4099;
constexpr uint64_t SF = 4100;
constexpr uint64_t OF = 4101;
constexpr uint64_t DF = 4102;

void checkReg(PcodeEvaluator& ev, uint64_t offset, uint64_t want,
              const char* message) {
    const auto got = ev.regValue(offset);
    if (!got.has_value() || *got != want) {
        std::printf("FAIL: %s (got %s%llu, want %llu)\n", message,
                    got ? "" : "unknown/", static_cast<unsigned long long>(got.value_or(0)),
                    static_cast<unsigned long long>(want));
        ++failures;
    }
}

bool samePcode(const PcodeInsn& left, const PcodeInsn& right) {
    if (left.addr != right.addr || left.nextAddr != right.nextAddr ||
        left.text != right.text || left.size != right.size ||
        left.kind != right.kind || left.target != right.target ||
        left.targetKnown != right.targetKnown ||
        left.named != right.named || left.ops.size() != right.ops.size() ||
        left.varnodes.size() != right.varnodes.size())
        return false;
    for (size_t index = 0; index < left.ops.size(); ++index) {
        const PcodeOp& a = left.ops[index];
        const PcodeOp& b = right.ops[index];
        if (a.op != b.op || a.out != b.out || a.in0 != b.in0 ||
            a.in1 != b.in1 || a.in2 != b.in2 || a.aux != b.aux)
            return false;
    }
    auto a = left.varnodes.begin();
    auto b = right.varnodes.begin();
    for (; a != left.varnodes.end(); ++a, ++b) {
        const Varnode& av = a->second;
        const Varnode& bv = b->second;
        if (a->first != b->first || av.id != bv.id || av.kind != bv.kind ||
            av.offset != bv.offset || av.size != bv.size || av.name != bv.name)
            return false;
    }
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: test_x86_flags <x86-64.slaspec>\n");
        return 2;
    }

    std::ifstream spec(argv[1]);
    std::ostringstream source;
    source << spec.rdbuf();
    SleighEngine engine;
    std::string error;
    if (!spec || !engine.loadSpec(source.str(), error)) {
        std::fprintf(stderr, "x86 spec load failed: %s\n", error.c_str());
        return 2;
    }

    std::vector<uint8_t> image(5664, 0x90);
    auto put = [&](size_t at, std::initializer_list<uint8_t> bytes) {
        size_t i = at;
        for (uint8_t byte : bytes) image[i++] = byte;
    };
    put(0x00, {0x48, 0x39, 0xD8});       // cmp rax, rbx
    put(0x10, {0x48, 0x01, 0xD8});       // add rax, rbx
    put(0x20, {0x48, 0x31, 0xC0});       // xor rax, rax
    put(0x30, {0x74, 0x05});             // je +5
    put(0x40, {0x0F, 0x9C, 0xC0});       // setl al
    put(0x50, {0x48, 0x0F, 0x4F, 0xC3}); // cmovg rax, rbx
    put(0x60, {0x48, 0xFF, 0xC0});       // inc rax
    put(0x70, {0x48, 0xD1, 0xE0});       // shl rax, 1
    put(0x80, {0x0F, 0x85, 0x05, 0, 0, 0}); // jne +5 (near)
    put(0x90, {0x48, 0x39, 0x18});       // cmp [rax], rbx
    put(0xA0, {0x48, 0x11, 0xD8});       // adc rax, rbx
    put(0xB0, {0x48, 0x19, 0xD8});       // sbb rax, rbx
    put(0xC0, {0x48, 0xC1, 0xE0, 0x00}); // shl rax, 0
    put(0xD0, {0x0F, 0x58, 0xC1});       // addps xmm0, xmm1
    put(0xE0, {0x0F, 0x2E, 0xC1});       // ucomiss xmm0, xmm1
    put(0xF0, {0xF3, 0x0F, 0x58, 0xC1}); // addss xmm0, xmm1
    put(0x100, {0x48, 0xD1, 0xC0});      // rol rax, 1
    put(0x110, {0x48, 0xD1, 0xC8});      // ror rax, 1
    put(0x120, {0x48, 0x0F, 0xA3, 0xD8}); // bt rax, rbx
    put(0x130, {0x48, 0x0F, 0xB3, 0xD8}); // btr rax, rbx
    put(0x140, {0xF3, 0x48, 0x0F, 0xB8, 0xC3}); // popcnt rax, rbx
    put(0x150, {0x48, 0x0F, 0xBC, 0xC3}); // bsf rax, rbx
    put(0x160, {0x48, 0x0F, 0xAF, 0xC3}); // imul rax, rbx
    put(0x170, {0x48, 0x0F, 0xC1, 0xD8}); // xadd rax, rbx
    put(0x180, {0x66, 0x0F, 0x6F, 0xC1}); // movdqa xmm0, xmm1
    put(0x190, {0x66, 0x0F, 0xFE, 0xC1}); // paddd xmm0, xmm1
    put(0x1A0, {0x66, 0x0F, 0xEF, 0xC1}); // pxor xmm0, xmm1
    put(0x1B0, {0xF3, 0x0F, 0x2A, 0xC3}); // cvtsi2ss xmm0, ebx
    put(0x1C0, {0xF3, 0x48, 0x0F, 0x2C, 0xC1}); // cvttss2si rax, xmm1
    put(0x1D0, {0xF3, 0x0F, 0x5A, 0xC1}); // cvtss2sd xmm0, xmm1
    put(0x1E0, {0x48, 0x0F, 0xA4, 0xD8, 0x01}); // shld rax, rbx, 1
    put(0x1F0, {0x48, 0x0F, 0xAC, 0xD8, 0x01}); // shrd rax, rbx, 1
    put(0x200, {0xD9, 0xE8});             // fld1
    put(0x210, {0xD8, 0xC0});             // fadd st(0), st(0)
    put(0x220, {0x62, 0xF1, 0x7E, 0x49, 0x7F, 0x00}); // vmovdqu32 [rax]{k1}, zmm0
    put(0x230, {0xD8, 0x10});             // fcom dword ptr [rax]
    put(0x240, {0xD9, 0x28});             // fldcw word ptr [rax]
    put(0x250, {0xDF, 0xE0});             // fnstsw ax
    put(0x260, {0x66, 0x0F, 0x74, 0xC1}); // pcmpeqb xmm0, xmm1
    put(0x270, {0x66, 0x0F, 0xEC, 0xC1}); // paddsb xmm0, xmm1
    put(0x280, {0x66, 0x0F, 0x60, 0xC1}); // punpcklbw xmm0, xmm1
    put(0x290, {0x66, 0x0F, 0x63, 0xC1}); // packsswb xmm0, xmm1
    put(0x2A0, {0x66, 0x0F, 0x38, 0x00, 0xC1}); // pshufb xmm0, xmm1
    put(0x2B0, {0xC4, 0xE2, 0xE3, 0xF5, 0xC1}); // pdep rax, rbx, rcx
    put(0x2C0, {0xC4, 0xE2, 0xE2, 0xF5, 0xC1}); // pext rax, rbx, rcx
    put(0x2D0, {0xC4, 0xE2, 0xE1, 0xF7, 0xC1}); // shlx rax, rcx, rbx
    put(0x2E0, {0xC4, 0xE2, 0xE0, 0xF2, 0xC1}); // andn rax, rbx, rcx
    put(0x2F0, {0xC4, 0xE2, 0xE0, 0xF7, 0xC1}); // bextr rax, rcx, rbx
    put(0x300, {0x66, 0x0F, 0x70, 0xC1, 0x1B}); // pshufd xmm0, xmm1, 0x1b
    put(0x310, {0x0F, 0xC6, 0xC1, 0x1B});       // shufps xmm0, xmm1, 0x1b
    put(0x320, {0x66, 0x0F, 0xC6, 0xC1, 0x01}); // shufpd xmm0, xmm1, 1
    put(0x330, {0x62, 0xF1, 0x7D, 0x49, 0xFE, 0xC1}); // vpaddd zmm0{k1}, zmm0, zmm1
    put(0x340, {0x62, 0xF1, 0x7D, 0x49, 0xEC, 0xC1}); // vpaddsb zmm0{k1}, zmm0, zmm1
    put(0x350, {0x62, 0xF1, 0x7C, 0x48, 0x58, 0xC1}); // vaddps zmm0, zmm0, zmm1
    put(0x360, {0x66, 0x0F, 0x38, 0xDC, 0xC1}); // aesenc xmm0, xmm1
    put(0x370, {0xC4, 0xE2, 0x79, 0xDC, 0xC1}); // vaesenc xmm0, xmm0, xmm1
    put(0x380, {0xD9, 0xFC}); // frndint
    put(0x390, {0xD9, 0xFE}); // fsin
    put(0x3A0, {0xD9, 0xF0}); // f2xm1
    put(0x3B0, {0x0F, 0xAE, 0x00}); // fxsave [rax]
    put(0x3C0, {0x0F, 0xAE, 0x08}); // fxrstor [rax]
    put(0x3D0, {0x62, 0xF3, 0x7D, 0x48, 0x1F, 0xC1, 0x00}); // vpcmpd k0,zmm0,zmm1,eq
    put(0x3E0, {0x62, 0xF2, 0x7D, 0x49, 0x90, 0x04, 0x88}); // vpgatherdd zmm0{k1},[rax+zmm1*4]
    put(0x3F0, {0x62, 0xF2, 0x7D, 0x49, 0xA0, 0x04, 0x88}); // vpscatterdd [rax+zmm1*4]{k1},zmm0
    put(0x400, {0x66, 0x0F, 0x38, 0xCF, 0xC1}); // gf2p8mulb xmm0,xmm1
    put(0x410, {0x0F, 0x38, 0xC9, 0xC1}); // sha1msg1 xmm0,xmm1
    put(0x420, {0x0F, 0x38, 0xCA, 0xC1}); // sha1msg2 xmm0,xmm1
    put(0x430, {0x0F, 0x38, 0xCC, 0xC1}); // sha256msg1 xmm0,xmm1
    put(0x440, {0x0F, 0x38, 0xCD, 0xC1}); // sha256msg2 xmm0,xmm1
    put(0x450, {0x0F, 0x38, 0xCB, 0xC1}); // sha256rnds2 xmm0,xmm1,xmm0
    put(0x460, {0x0F, 0x3A, 0xCC, 0xC1, 0x00}); // sha1rnds4 xmm0,xmm1,0
    put(0x470, {0x66, 0x0F, 0x3A, 0xCE, 0xC1, 0xA5}); // gf2p8affineqb
    put(0x480, {0x66, 0x0F, 0x3A, 0xCF, 0xC1, 0x00}); // gf2p8affineinvqb
    put(0x490, {0x66, 0x0F, 0x3A, 0x44, 0xC1, 0x00}); // pclmulqdq low,low
    put(0x4A0, {0xC4, 0xE3, 0x79, 0x44, 0xC1, 0x11}); // vpclmulqdq xmm0,xmm0,xmm1,11
    put(0x4B0, {0x62, 0xF3, 0x7D, 0x48, 0x44, 0xC1, 0x10}); // EVEX VPCLMUL
    put(0x4C0, {0x62, 0xF2, 0x7D, 0x48, 0xDD, 0x00}); // vaesenclast zmm0,zmm0,[rax]
    put(0x4D0, {0xD9, 0xFA}); // fsqrt
    put(0x4E0, {0xD8, 0xC1}); // fadd st(0), st(1)
    put(0x4F0, {0x9B}); // wait/fwait
    put(0x500, {0x0F, 0xA2}); // cpuid
    put(0x510, {0x0F, 0x32}); // rdmsr
    put(0x520, {0x0F, 0x30}); // wrmsr
    put(0x530, {0x0F, 0x01, 0xD0}); // xgetbv
    put(0x540, {0x0F, 0x01, 0xD1}); // xsetbv
    put(0x550, {0x0F, 0x06}); // clts
    put(0x560, {0x0F, 0x01, 0xF8}); // swapgs
    put(0x570, {0xFA}); // cli
    put(0x580, {0xFB}); // sti
    put(0x590, {0xF4}); // hlt
    put(0x5A0, {0x0F, 0x20, 0xC0}); // mov rax,cr0
    put(0x5B0, {0x0F, 0x22, 0xC0}); // mov cr0,rax
    put(0x5C0, {0x0F, 0x01, 0x00}); // sgdt [rax]
    put(0x5D0, {0x0F, 0x01, 0x10}); // lgdt [rax]
    put(0x5E0, {0x0F, 0x01, 0x38}); // invlpg [rax]
    put(0x5F0, {0xDD, 0xC0}); // ffree st(0)
    put(0x600, {0xD9, 0xEB}); // fldpi
    put(0x610, {0xD9, 0xE5}); // fxam
    put(0x620, {0xD9, 0xE0}); // fchs
    put(0x630, {0xD9, 0xE1}); // fabs
    put(0x640, {0xD9, 0xE4}); // ftst
    put(0x650, {0xD9, 0xF6}); // fdecstp
    put(0x660, {0xD9, 0xF7}); // fincstp
    put(0x670, {0xD9, 0xF5}); // fprem1
    put(0x680, {0xDE, 0xC1}); // faddp st(1),st(0)
    put(0x690, {0xDE, 0xD9}); // fcompp
    put(0x6A0, {0xDA, 0xE9}); // fucompp
    put(0x6B0, {0xDF, 0xF1}); // fcomip st(0),st(1)
    put(0x6C0, {0xD9, 0xC1}); // fld st(1)
    put(0x6D0, {0xDD, 0xD9}); // fstp st(1)
    put(0x700, {0x48, 0x0F, 0xC8}); // bswap rax
    put(0x710, {0x66, 0x0F, 0xE0, 0xC1}); // pavgb xmm0,xmm1
    put(0x720, {0x66, 0x0F, 0xDE, 0xC1}); // pmaxub xmm0,xmm1
    put(0x730, {0x66, 0x0F, 0xEA, 0xC1}); // pminsw xmm0,xmm1
    put(0x740, {0x66, 0x0F, 0xF6, 0xC1}); // psadbw xmm0,xmm1
    put(0x750, {0x62, 0xF1, 0x7D, 0x48, 0xEF, 0xC1}); // vpxord zmm0,zmm0,zmm1
    put(0x760, {0x66, 0x0F, 0x71, 0xF0, 0x03}); // psllw xmm0,3
    put(0x770, {0x66, 0x0F, 0xF1, 0xC1}); // psllw xmm0,xmm1(count)
    put(0x780, {0xEC}); // in al,dx
    put(0x790, {0xEE}); // out dx,al
    put(0x7A0, {0x66, 0x0F, 0x6E, 0xC3}); // movd xmm0,ebx
    put(0x7B0, {0x66, 0x0F, 0x7E, 0xC3}); // movd ebx,xmm0
    put(0x7C0, {0xFC}); // cld
    put(0x7C8, {0xFD}); // std
    put(0x7D0, {0xF3, 0xA4}); // rep movsb
    put(0x7E0, {0xF2, 0xAE}); // repne scasb
    put(0x7F0, {0xF3, 0xA6}); // repe cmpsb
    put(0x800, {0x66, 0x48, 0x0F, 0x6E, 0xC3}); // movq xmm0,rbx
    put(0x810, {0x66, 0x48, 0x0F, 0x7E, 0xC3}); // movq rbx,xmm0
    put(0x820, {0x66, 0x0F, 0xD6, 0xC1}); // movq xmm1,xmm0
    put(0x830, {0xF3, 0x0F, 0x10, 0xC1}); // movss xmm0,xmm1
    put(0x840, {0xF3, 0x0F, 0x11, 0xC1}); // movss xmm1,xmm0
    put(0x850, {0x66, 0x0F, 0xD7, 0xC1}); // pmovmskb eax,xmm1
    put(0x860, {0x66, 0x0F, 0xC5, 0xC1, 0x02}); // pextrw eax,xmm1,2
    put(0x870, {0x66, 0x0F, 0x3A, 0x15, 0xC8, 0x03}); // pextrw eax,xmm1,3
    put(0x880, {0xF2, 0x0F, 0x38, 0xF0, 0xC3}); // crc32 eax,bl
    put(0x890, {0x48, 0xF7, 0xFB}); // idiv rbx
    put(0x8A0, {0xF6, 0xFB}); // idiv bl
    put(0x8B0, {0x0F, 0x54, 0xC1}); // andps xmm0,xmm1
    put(0x8C0, {0x0F, 0x55, 0xC1}); // andnps xmm0,xmm1
    put(0x8D0, {0xF2, 0x0F, 0xD0, 0xC1}); // addsubps xmm0,xmm1
    put(0x8E0, {0x66, 0x0F, 0x3A, 0x0C, 0xC1, 0x0A}); // blendps xmm0,xmm1,0xa
    put(0x8F0, {0x0F, 0xC2, 0xC1, 0x01}); // cmpps xmm0,xmm1,lt
    put(0x900, {0x0F, 0x2F, 0xC1}); // comiss xmm0,xmm1
    put(0x910, {0x0F, 0x2E, 0xC1}); // ucomiss xmm0,xmm1
    put(0x920, {0xF2, 0x0F, 0x7C, 0xC1}); // haddps xmm0,xmm1
    put(0x930, {0x48, 0xF7, 0xF3}); // div rbx
    put(0x940, {0x66, 0x0F, 0x3A, 0x17, 0xC8, 0x02}); // extractps eax,xmm1,2
    put(0x950, {0x0F, 0x5B, 0xC1}); // cvtdq2ps xmm0,xmm1
    put(0x960, {0x66, 0x0F, 0xE6, 0xC1}); // cvtpd2dq xmm0,xmm1
    put(0x970, {0xF3, 0x0F, 0x5B, 0xC1}); // cvttps2dq xmm0,xmm1
    put(0x980, {0x0F, 0x5A, 0xC1}); // cvtps2pd xmm0,xmm1
    put(0x990, {0x66, 0x0F, 0x5A, 0xC1}); // cvtpd2ps xmm0,xmm1
    put(0x9A0, {0x66, 0x0F, 0x3A, 0x40, 0xC1, 0xF1}); // dpps xmm0,xmm1,f1
    put(0x9B0, {0x66, 0x0F, 0x3A, 0x41, 0xC1, 0x33}); // dppd xmm0,xmm1,33
    put(0x9C0, {0x66, 0x0F, 0x38, 0x1C, 0xC1}); // pabsb xmm0,xmm1
    put(0x9D0, {0x66, 0x0F, 0x3A, 0x0E, 0xC1, 0xAA}); // pblendw xmm0,xmm1,aa
    put(0x9E0, {0x66, 0x0F, 0x3A, 0x0F, 0xC1, 0x08}); // palignr xmm0,xmm1,8
    put(0x9F0, {0xF3, 0x0F, 0x12, 0xC1}); // movsldup xmm0,xmm1
    put(0xA00, {0xF3, 0x0F, 0x16, 0xC1}); // movshdup xmm0,xmm1
    put(0xA10, {0xF2, 0x0F, 0x12, 0xC1}); // movddup xmm0,xmm1
    put(0xA20, {0x0F, 0x6F, 0xC1}); // movq mm0,mm1
    put(0xA30, {0x0F, 0x7F, 0xC1}); // movq mm1,mm0
    put(0xA40, {0x0F, 0x6F, 0x00}); // movq mm0,[rax]
    put(0xA50, {0x0F, 0x7F, 0x00}); // movq [rax],mm0
    put(0xA60, {0x66, 0x0F, 0x3A, 0x14, 0xCB, 0x1F}); // pextrb ebx,xmm1,31
    put(0xA70, {0x66, 0x0F, 0x3A, 0x16, 0xCB, 0x02}); // pextrd ebx,xmm1,2
    put(0xA80, {0x66, 0x48, 0x0F, 0x3A, 0x16, 0xCB, 0x03}); // pextrq rbx,xmm1,3
    put(0xA90, {0x66, 0x0F, 0x3A, 0x20, 0xC3, 0x12}); // pinsrb xmm0,ebx,18
    put(0xAA0, {0x66, 0x0F, 0xC4, 0xC3, 0x09}); // pinsrw xmm0,ebx,9
    put(0xAB0, {0x66, 0x0F, 0x3A, 0x22, 0xC3, 0x07}); // pinsrd xmm0,ebx,7
    put(0xAC0, {0x66, 0x48, 0x0F, 0x3A, 0x22, 0xC3, 0x03}); // pinsrq xmm0,rbx,3
    put(0xAD0, {0xC4, 0xE3, 0xF9, 0x16, 0xCB, 0x01}); // vpextrq rbx,xmm1,1
    put(0xAE0, {0xC4, 0xE3, 0x71, 0x22, 0xC3, 0x02}); // vpinsrd xmm0,xmm1,ebx,2
    put(0xAF0, {0x66, 0x0F, 0x38, 0x01, 0xC1}); // phaddw xmm0,xmm1
    put(0xB00, {0x66, 0x0F, 0x38, 0x06, 0xC1}); // phsubd xmm0,xmm1
    put(0xB10, {0x66, 0x0F, 0x38, 0x03, 0xC1}); // phaddsw xmm0,xmm1
    put(0xB20, {0x66, 0x0F, 0x3A, 0x63, 0xC1, 0x18}); // pcmpistri xmm0,xmm1,18
    put(0xB30, {0x66, 0x0F, 0x3A, 0x62, 0xD1, 0x00}); // pcmpistrm xmm2,xmm1,00
    put(0xB40, {0x66, 0x0F, 0x3A, 0x62, 0xD1, 0x40}); // pcmpistrm xmm2,xmm1,40
    put(0xB50, {0x66, 0x0F, 0x3A, 0x61, 0xC1, 0x04}); // pcmpestri xmm0,xmm1,04
    put(0xB60, {0x66, 0x0F, 0x3A, 0x60, 0xD1, 0x0C}); // pcmpestrm xmm2,xmm1,0c
    put(0xB70, {0x66, 0x0F, 0xF5, 0xC1}); // pmaddwd xmm0,xmm1
    put(0xB80, {0x66, 0x0F, 0x38, 0x04, 0xC1}); // pmaddubsw xmm0,xmm1
    put(0xB90, {0x66, 0x0F, 0x38, 0x28, 0xC1}); // pmuldq xmm0,xmm1
    put(0xBA0, {0x66, 0x0F, 0x38, 0x0B, 0xC1}); // pmulhrsw xmm0,xmm1
    put(0xBB0, {0x66, 0x0F, 0x38, 0x40, 0xC1}); // pmulld xmm0,xmm1
    put(0xBC0, {0x66, 0x0F, 0x38, 0x08, 0xC1}); // psignb xmm0,xmm1
    put(0xBD0, {0x66, 0x0F, 0x38, 0x09, 0xC1}); // psignw xmm0,xmm1
    put(0xBE0, {0x66, 0x0F, 0x38, 0x0A, 0xC1}); // psignd xmm0,xmm1
    put(0xBF0, {0x66, 0x0F, 0x73, 0xF8, 0x04}); // pslldq xmm0,4
    put(0xC00, {0x66, 0x0F, 0x73, 0xD8, 0x04}); // psrldq xmm0,4
    put(0xC10, {0x66, 0x0F, 0x38, 0x17, 0xC1}); // ptest xmm0,xmm1
    put(0xC20, {0xC4, 0xE1, 0x79, 0x73, 0xF9, 0x04}); // vpslldq xmm0,xmm1,4
    put(0xC30, {0xC4, 0xE1, 0x71, 0xF5, 0xC2}); // vpmaddwd xmm0,xmm1,xmm2
    put(0xC40, {0xC4, 0xE2, 0x71, 0x04, 0xC2}); // vpmaddubsw xmm0,xmm1,xmm2
    put(0xC50, {0xC4, 0xE2, 0x71, 0x0A, 0xC2}); // vpsignd xmm0,xmm1,xmm2
    put(0xC60, {0xC4, 0xE2, 0x71, 0x28, 0xC2}); // vpmuldq xmm0,xmm1,xmm2
    put(0xC70, {0xC4, 0xE2, 0x71, 0x40, 0xC2}); // vpmulld xmm0,xmm1,xmm2
    put(0xC80, {0xC4, 0xE2, 0x79, 0x17, 0xC1}); // vptest xmm0,xmm1
    put(0xC90, {0x66, 0x0F, 0x73, 0xF8, 0x14}); // pslldq xmm0,20
    put(0xCA0, {0x0F, 0x53, 0xC1}); // rcpps xmm0,xmm1
    put(0xCB0, {0xF3, 0x0F, 0x53, 0xC1}); // rcpss xmm0,xmm1
    put(0xCC0, {0x0F, 0x52, 0xC1}); // rsqrtps xmm0,xmm1
    put(0xCD0, {0xF3, 0x0F, 0x52, 0xC1}); // rsqrtss xmm0,xmm1
    put(0xCE0, {0x66, 0x0F, 0x3A, 0x08, 0xC1, 0x01}); // roundps xmm0,xmm1,floor
    put(0xCF0, {0x66, 0x0F, 0x3A, 0x09, 0xC1, 0x02}); // roundpd xmm0,xmm1,ceil
    put(0xD00, {0x66, 0x0F, 0x3A, 0x0A, 0xC1, 0x03}); // roundss xmm0,xmm1,trunc
    put(0xD10, {0x66, 0x0F, 0x3A, 0x0B, 0xC1, 0x08}); // roundsd xmm0,xmm1,nearest+sae
    put(0xD20, {0xC5, 0xF2, 0x58, 0xC2}); // vaddss xmm0,xmm1,xmm2
    put(0xD30, {0xC5, 0xF3, 0x5C, 0xC2}); // vsubsd xmm0,xmm1,xmm2
    put(0xD40, {0xC5, 0xF2, 0x59, 0xC2}); // vmulss xmm0,xmm1,xmm2
    put(0xD50, {0xC5, 0xF3, 0x5E, 0xC2}); // vdivsd xmm0,xmm1,xmm2
    put(0xD60, {0xC5, 0xF2, 0x5D, 0xC2}); // vminss xmm0,xmm1,xmm2
    put(0xD70, {0xC5, 0xF3, 0x5F, 0xC2}); // vmaxsd xmm0,xmm1,xmm2
    put(0xD80, {0x0F, 0x12, 0x00}); // movlps xmm0,[rax]
    put(0xD90, {0x0F, 0x13, 0x00}); // movlps [rax],xmm0
    put(0xDA0, {0x0F, 0x16, 0x00}); // movhps xmm0,[rax]
    put(0xDB0, {0x0F, 0x17, 0x00}); // movhps [rax],xmm0
    put(0xDC0, {0x66, 0x0F, 0x12, 0x00}); // movlpd xmm0,[rax]
    put(0xDD0, {0x66, 0x0F, 0x17, 0x00}); // movhpd [rax],xmm0
    put(0xDE0, {0xC5, 0xF8, 0x53, 0xC1}); // vrcpps xmm0,xmm1
    put(0xDF0, {0xC5, 0xF2, 0x52, 0xC2}); // vrsqrtss xmm0,xmm1,xmm2
    put(0xE00, {0xC4, 0xE3, 0x79, 0x08, 0xC1, 0x03}); // vroundps xmm0,xmm1,trunc
    put(0xE10, {0xC4, 0xE3, 0x71, 0x0A, 0xC2, 0x02}); // vroundss xmm0,xmm1,xmm2,ceil
    put(0xE20, {0xC5, 0xF4, 0x14, 0xC2}); // vunpcklps ymm0,ymm1,ymm2
    put(0xE30, {0xC5, 0xF5, 0x63, 0xC2}); // vpacksswb ymm0,ymm1,ymm2
    put(0xE40, {0xC5, 0xF5, 0x74, 0xC2}); // vpcmpeqb ymm0,ymm1,ymm2
    put(0xE50, {0xC5, 0xF5, 0xEF, 0xC2}); // vpxor ymm0,ymm1,ymm2
    put(0xE60, {0xC4, 0xE3, 0x75, 0x18, 0xC2, 0x01}); // vinsertf128 ymm0,ymm1,xmm2,1
    put(0xE70, {0xC4, 0xE3, 0x75, 0x06, 0xC2, 0x21}); // vperm2f128 ymm0,ymm1,ymm2,21
    put(0xE80, {0xC4, 0xE3, 0x7D, 0x19, 0xCB, 0x01}); // vextractf128 xmm3,ymm1,1
    put(0xE90, {0x66, 0x0F, 0x38, 0x20, 0x00}); // pmovsxbw xmm0,[rax]
    put(0xEA0, {0xC5, 0xF8, 0x77}); // vzeroupper
    put(0xEB0, {0xC5, 0xFC, 0x77}); // vzeroall
    put(0xEC0, {0x0F, 0x12, 0xC1}); // movhlps xmm0,xmm1
    put(0xED0, {0x0F, 0x16, 0xC1}); // movlhps xmm0,xmm1
    put(0xEE0, {0x66, 0x0F, 0xE7, 0x00}); // movntdq [rax],xmm0
    put(0xEF0, {0xC5, 0xF2, 0x53, 0xC2}); // vrcpss xmm0,xmm1,xmm2
    put(0xF00, {0xC5, 0xF8, 0x52, 0xC1}); // vrsqrtps xmm0,xmm1
    put(0xF10, {0xC4, 0xE3, 0x7D, 0x09, 0xC1, 0x02}); // vroundpd ymm0,ymm1,ceil
    put(0xF20, {0xC4, 0xE3, 0x71, 0x0B, 0xC2, 0x01}); // vroundsd xmm0,xmm1,xmm2,floor
    put(0xF30, {0xC5, 0xF3, 0x58, 0xC2}); // vaddsd xmm0,xmm1,xmm2
    put(0xF40, {0xC5, 0xF2, 0x5C, 0xC2}); // vsubss xmm0,xmm1,xmm2
    put(0xF50, {0xC5, 0xF3, 0x59, 0xC2}); // vmulsd xmm0,xmm1,xmm2
    put(0xF60, {0xC5, 0xF2, 0x5E, 0xC2}); // vdivss xmm0,xmm1,xmm2
    put(0xF70, {0xC5, 0xF3, 0x5D, 0xC2}); // vminsd xmm0,xmm1,xmm2
    put(0xF80, {0xC5, 0xF2, 0x5F, 0xC2}); // vmaxss xmm0,xmm1,xmm2
    put(0xF90, {0xC5, 0xF2, 0x51, 0xC2}); // vsqrtss xmm0,xmm1,xmm2
    put(0xFA0, {0xC5, 0xF3, 0x51, 0xC2}); // vsqrtsd xmm0,xmm1,xmm2
    put(0xFB0, {0xC5, 0xF2, 0x58, 0x00}); // vaddss xmm0,xmm1,[rax]
    put(0xFC0, {0x66, 0x0F, 0x13, 0x00}); // movlpd [rax],xmm0
    put(0xFD0, {0x66, 0x0F, 0x16, 0x00}); // movhpd xmm0,[rax]
    put(0xFE0, {0xC5, 0xF2, 0x53, 0x00}); // vrcpss xmm0,xmm1,[rax]
    put(0xFF0, {0xC4, 0xE3, 0x71, 0x0B, 0x00, 0x03}); // vroundsd xmm0,xmm1,[rax],trunc
    put(0x1000, {0xF3, 0x0F, 0x52, 0x00}); // rsqrtss xmm0,[rax]
    put(0x1010, {0x66, 0x99}); // cwd
    put(0x1020, {0x99}); // cdq
    put(0x1030, {0x48, 0x99}); // cqo
    put(0x1040, {0x48, 0xF7, 0x23}); // mul qword [rbx]
    put(0x1050, {0x48, 0xF7, 0x2B}); // imul qword [rbx]
    put(0x1060, {0x0F, 0xC7, 0x0E}); // cmpxchg8b [rsi]
    put(0x1070, {0x48, 0x0F, 0xC7, 0x0E}); // cmpxchg16b [rsi]
    put(0x1080, {0xC8, 0x10, 0x00, 0x02}); // enter 16,2
    put(0x1090, {0x8F, 0x00}); // pop [rax]
    put(0x10A0, {0x9C}); // pushf
    put(0x10B0, {0x9D}); // popf
    put(0x10C0, {0x9F}); // lahf
    put(0x10D0, {0x9E}); // sahf
    put(0x10E0, {0xD6}); // salc
    put(0x10F0, {0x0F, 0xAE, 0x10}); // ldmxcsr [rax]
    put(0x1100, {0x0F, 0xAE, 0x18}); // stmxcsr [rax]
    put(0x1110, {0x6C}); // insb
    put(0x1120, {0x6D}); // insd
    put(0x1130, {0x48, 0x6D}); // insq
    put(0x1140, {0x6E}); // outsb
    put(0x1150, {0x6F}); // outsd
    put(0x1160, {0x48, 0x6F}); // outsq
    put(0x1170, {0x0F, 0x31}); // rdtsc
    put(0x1180, {0x0F, 0x01, 0xF9}); // rdtscp
    put(0x1190, {0x0F, 0x33}); // rdpmc
    put(0x11A0, {0x48, 0x0F, 0xC7, 0xF0}); // rdrand rax
    put(0x11B0, {0x48, 0x0F, 0xC7, 0xF8}); // rdseed rax
    put(0x11C0, {0xF3, 0x48, 0x0F, 0xC7, 0xF8}); // rdpid rax
    put(0x11D0, {0xF3, 0x48, 0x0F, 0x1E, 0xC8}); // rdsspq rax
    put(0x11E0, {0xF3, 0x0F, 0x1E, 0xC8}); // rdsspd eax
    put(0x11F0, {0x0F, 0x01, 0xC8}); // monitor
    put(0x1200, {0x0F, 0x01, 0xFA}); // monitorx
    put(0x1210, {0x0F, 0x01, 0xC9}); // mwait
    put(0x1220, {0x0F, 0x01, 0xFB}); // mwaitx
    put(0x1230, {0x0F, 0x01, 0xCA}); // clac
    put(0x1240, {0x0F, 0x01, 0xCB}); // stac
    put(0x1250, {0x0F, 0x07}); // sysret
    put(0x1260, {0x48, 0xCF}); // iretq
    put(0x1270, {0xCB}); // lret
    put(0x1280, {0xCA, 0x08, 0x00}); // lret 8
    put(0x1290, {0x0F, 0x02, 0xC1}); // lar eax,cx
    put(0x12A0, {0x0F, 0x03, 0xC1}); // lsl eax,cx
    put(0x12B0, {0xD7}); // xlat
    put(0x12C0, {0xF1}); // int1
    put(0x12D0, {0xCC}); // int3
    put(0x12E0, {0xCD, 0x80}); // int 80h
    put(0x12F0, {0x0F, 0xFF, 0xC0}); // ud0
    put(0x1300, {0x0F, 0x0B}); // ud2
    put(0x1310, {0x0F, 0xB9, 0xC0}); // udb
    put(0x1320, {0x90}); // nop
    put(0x1330, {0x0F, 0x1F, 0x00}); // nop [rax]
    put(0x1340, {0xF3, 0x90}); // pause
    put(0x1350, {0x0F, 0x18, 0x00}); // prefetchnta [rax]
    put(0x1360, {0x0F, 0x18, 0x08}); // prefetcht0 [rax]
    put(0x1370, {0x0F, 0x18, 0x10}); // prefetcht1 [rax]
    put(0x1380, {0x0F, 0x18, 0x18}); // prefetcht2 [rax]
    put(0x1390, {0x0F, 0x0D, 0x08}); // prefetchw [rax]
    put(0x13A0, {0x0F, 0xAE, 0x38}); // clflush [rax]
    put(0x13B0, {0x66, 0x0F, 0xAE, 0x30}); // clwb [rax]
    put(0x13C0, {0x66, 0x0F, 0xEB, 0xC1}); // por xmm0,xmm1
    put(0x13D0, {0x66, 0x0F, 0xEF, 0xC1}); // pxor xmm0,xmm1
    put(0x13E0, {0xF7, 0x2B}); // imul dword [rbx]
    put(0x13F0, {0xF7, 0x23}); // mul dword [rbx]
    put(0x1400, {0x58}); // pop rax
    put(0x1410, {0x0F, 0x02, 0x00}); // lar eax,[rax]
    put(0x1420, {0x0F, 0x03, 0x00}); // lsl eax,[rax]
    put(0x1430, {0x66, 0x0F, 0xEB, 0x00}); // por xmm0,[rax]
    put(0x1440, {0x66, 0x0F, 0xEF, 0x00}); // pxor xmm0,[rax]
    put(0x1450, {0x0F, 0x05}); // syscall
    put(0x1460, {0x53}); // push rbx
    put(0x1470, {0x65, 0x48, 0x8B, 0x04, 0x25,
                 0x30, 0x00, 0x00, 0x00}); // mov rax,gs:[30h]
    put(0x1480, {0x66, 0xC7, 0x40, 0x18, 0x01, 0x01});
                                               // mov word ptr [rax+18h],101h
    put(0x1490, {0x4A, 0x8D, 0x0C, 0x23}); // lea rcx,[rbx+r12]
    put(0x14A0, {0x48, 0xF7, 0xE9}); // imul rcx -> rdx:rax
    put(0x14B0, {0x0F, 0x97, 0xC0, // seta al
                 0x84, 0xC0,       // test al,al
                 0x74, 0x02,       // je return
                 0xB0, 0x01,       // mov al,1
                 0xC3});            // return
    put(0x14C0, {0xB4, 0x34, 0xC3}); // mov ah,34h; return
    put(0x14D0, {0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3});
                                               // mov eax,ffffffffh; return
    put(0x14E0, {0xF3, 0x48, 0xAB, 0xC3}); // rep stosq; return

    auto read = [&](uint64_t address, void* dst, size_t size) {
        if (address > image.size() || size > image.size() - address) return false;
        std::memcpy(dst, image.data() + address, size);
        return true;
    };
    auto disassemble = [&](uint64_t address) {
        PcodeInsn insn;
        std::string err;
        if (!engine.disassemble(read, address, insn, err)) {
            std::printf("FAIL: disassembly at %#llx: %s\n",
                        static_cast<unsigned long long>(address), err.c_str());
            ++failures;
        }
        return insn;
    };

    {
        const std::string byteBoolean = decompile(
            engine, read, 0x14B0, 0x14BA, nullptr, nullptr, "x86-64");
        CHECK(byteBoolean.find("((uint8_t)(rax))") != std::string::npos,
              "decompiler tests only AL after a byte-sized Boolean return");
        CHECK(byteBoolean.find("rax = (rax &") != std::string::npos &&
                  byteBoolean.find("& 255ULL) << 0") != std::string::npos,
              "real x86 AL writes preserve the other RAX bits");

        const PcodeInsn highByte = disassemble(0x14C0);
        const Varnode* highByteOutput = highByte.ops.empty()
                                            ? nullptr
                                            : highByte.find(highByte.ops.back().out);
        CHECK(highByteOutput && highByteOutput->offset == 1 &&
                  highByteOutput->size == 1,
              "AH decodes as byte 1 of RAX storage");
        const std::string highByteSource = decompile(
            engine, read, 0x14C0, 0x14C3, nullptr, nullptr, "x86-64");
        CHECK(highByteSource.find("& 255ULL) << 8") != std::string::npos,
              "real x86 AH writes merge bits 8 through 15");

        const std::string dwordSource = decompile(
            engine, read, 0x14D0, 0x14D6, nullptr, nullptr, "x86-64");
        CHECK(dwordSource.find("rax = (uint32_t)(-1)") !=
                  std::string::npos,
              "real x86 EAX writes zero-extend into RAX");

        PcodeEvaluator fillQwords(disassemble(0x14E0));
        fillQwords.regs[RAX] = 0x1122334455667788ULL;
        fillQwords.regs[RCX] = 4;
        fillQwords.regs[RDI] = 0x6000;
        fillQwords.regs[DF] = 0;
        fillQwords.run();
        bool qwordsFilled = true;
        for (unsigned index = 0; index < 4; ++index)
            for (unsigned byte = 0; byte < 8; ++byte)
                qwordsFilled &= fillQwords.ram[0x6000 + index * 8 + byte] ==
                    static_cast<uint8_t>(0x1122334455667788ULL >> (byte * 8));
        CHECK(qwordsFilled && fillQwords.regValue(RCX).value_or(1) == 0 &&
                  fillQwords.regValue(RDI).value_or(0) == 0x6020,
              "REP STOSQ stores RCX qwords and advances RDI");

        const std::string fillSource = decompile(
            engine, read, 0x14E0, 0x14E4, nullptr, nullptr, "x86-64", true);
        CHECK(fillSource.find("while (recovered_string_count_") !=
                  std::string::npos &&
                  fillSource.find("recovered_store<uint64_t>(rdi") !=
                  std::string::npos &&
                  fillSource.find("rcx = recovered_string_count_") !=
                  std::string::npos,
              "decompiler preserves REP STOSQ bulk stores and register effects");
    }

    {
        const PcodeInsn store = disassemble(0x1480);
        CHECK(store.text.find("0x18") != std::string::npos &&
                  store.text.find("0x180") == std::string::npos,
              "legacy rmmem16 disp8 is not EVEX-compressed");
        PcodeEvaluator evaluated(store);
        evaluated.regs[RAX] = 0x2000;
        evaluated.run();
        CHECK(evaluated.ram[0x2018] == 1 &&
                  evaluated.ram[0x2019] == 1,
              "operand-size-prefixed C7 stores at the exact disp8 address");
        const std::string storeSource = decompile(
            engine, read, 0x1480, 0x1487, nullptr, nullptr, "x86-64", true);
        CHECK(storeSource.find("recovered_store<uint16_t>(rax + 24, 257)") !=
                  std::string::npos &&
                  storeSource.find("recovered_store<uint64_t>(rax + 24") ==
                  std::string::npos,
              "operand-size-prefixed C7 lowers to a two-byte recovered store");
        const std::string directStoreSource = decompile(
            engine, read, 0x1480, 0x1487, nullptr, nullptr, "x86-64");
        CHECK(directStoreSource.find("*((uint16_t *)(rax + 24)) = 257") !=
                  std::string::npos,
              "direct C lowering preserves operand-sized memory stores");
    }

    {
        const PcodeInsn lea = disassemble(0x1490);
        CHECK(lea.text.find("r12") != std::string::npos,
              "REX.X turns SIB index encoding 4 into r12");
        PcodeEvaluator evaluated(lea);
        evaluated.regs[RBX] = 0x1200;
        evaluated.regs[R12] = 0x34;
        evaluated.run();
        checkReg(evaluated, RCX, 0x1234,
                 "LEA preserves an extended r12 SIB index");
    }

    {
        const PcodeInsn multiply = disassemble(0x14A0);
        CHECK(std::none_of(multiply.ops.begin(), multiply.ops.end(),
                           [](const PcodeOp& operation) {
                               return operation.op == POp::X86_SYSTEM;
                           }),
              "register one-operand IMUL lowers to analyzable integer p-code");
        PcodeEvaluator evaluated(multiply);
        evaluated.regs[RAX] = static_cast<uint64_t>(-2LL);
        evaluated.regs[RCX] = 3;
        evaluated.run();
        CHECK(evaluated.regValue(RAX).value_or(0) ==
                  static_cast<uint64_t>(-6LL) &&
                  evaluated.regValue(16).value_or(0) == ~0ULL &&
                  evaluated.regValue(OF).value_or(1) == 0,
              "register IMUL preserves the complete signed RDX:RAX product");

        uint64_t seed = 0x9e3779b97f4a7c15ULL;
        bool exact = true;
        for (size_t iteration = 0; iteration < 2000 && exact; ++iteration) {
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            const uint64_t left = seed;
            seed = seed * 6364136223846793005ULL + 1442695040888963407ULL;
            const uint64_t right = seed;
            const __int128 expected =
                static_cast<__int128>(static_cast<int64_t>(left)) *
                static_cast<__int128>(static_cast<int64_t>(right));
            const uint64_t expectedLow = static_cast<uint64_t>(expected);
            const uint64_t expectedHigh = static_cast<uint64_t>(expected >> 64);
            const uint64_t expectedOverflow =
                expectedHigh != ((expectedLow >> 63) ? ~0ULL : 0ULL);
            PcodeEvaluator sample(multiply);
            sample.regs[RAX] = left;
            sample.regs[RCX] = right;
            sample.run();
            exact = sample.regValue(RAX).value_or(0) == expectedLow &&
                    sample.regValue(16).value_or(0) == expectedHigh &&
                    sample.regValue(OF).value_or(2) == expectedOverflow &&
                    sample.regValue(CF).value_or(2) == expectedOverflow;
        }
        CHECK(exact,
              "64-bit IMUL p-code matches signed 128-bit products across random inputs");
    }

    {
        // SleighEngine is shared by all analysis workers.  Exercise mixed
        // scalar/SIMD/x87/system encodings concurrently so operand width,
        // varnode ids and register caches cannot leak between threads.
        const std::vector<uint64_t> addresses = {
            0x00, 0x10, 0xD0, 0xF0, 0x370, 0x390, 0x3B0, 0x480,
            0x4C0, 0x1450, 0x1470, 0x1490, 0x14A0};
        std::vector<PcodeInsn> baseline;
        baseline.reserve(addresses.size());
        for (uint64_t address : addresses)
            baseline.push_back(disassemble(address));
        std::atomic<size_t> mismatches{0};
        std::vector<std::thread> decodeWorkers;
        for (size_t worker = 0; worker < 8; ++worker) {
            decodeWorkers.emplace_back([&, worker] {
                for (size_t iteration = 0; iteration < 400; ++iteration) {
                    const size_t index = (iteration + worker) % addresses.size();
                    PcodeInsn current;
                    std::string decodeError;
                    if (!engine.disassemble(read, addresses[index], current,
                                            decodeError) ||
                        !samePcode(current, baseline[index]))
                        mismatches.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }
        for (std::thread& worker : decodeWorkers) worker.join();
        CHECK(mismatches.load(std::memory_order_relaxed) == 0,
              "shared x86 Sleigh engine is deterministic under concurrent decoding");
    }

    {
        PcodeEvaluator ev(disassemble(0x00));
        ev.regs[RAX] = 5;
        ev.regs[RBX] = 5;
        ev.run();
        checkReg(ev, CF, 0, "cmp equal clears CF");
        checkReg(ev, PF, 1, "cmp zero result has even parity");
        checkReg(ev, AF, 0, "cmp equal clears AF");
        checkReg(ev, ZF, 1, "cmp equal sets ZF");
        checkReg(ev, SF, 0, "cmp equal clears SF");
        checkReg(ev, OF, 0, "cmp equal clears OF");
        checkReg(ev, RAX, 5, "cmp does not modify destination");
    }
    {
        PcodeEvaluator ev(disassemble(0x00));
        ev.regs[RAX] = 0;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, CF, 1, "cmp borrow sets CF");
        checkReg(ev, PF, 1, "0xff has even parity");
        checkReg(ev, AF, 1, "cmp low-nibble borrow sets AF");
        checkReg(ev, ZF, 0, "nonzero cmp clears ZF");
        checkReg(ev, SF, 1, "negative cmp sets SF");
        checkReg(ev, OF, 0, "zero minus one has no signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0x00));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, OF, 1, "signed subtraction overflow sets OF");
        checkReg(ev, SF, 0, "overflowed subtraction result is positive");
    }
    {
        PcodeEvaluator ev(disassemble(0x10));
        ev.regs[RAX] = ~0ULL;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, RAX, 0, "64-bit add wraps");
        checkReg(ev, CF, 1, "add carry sets CF");
        checkReg(ev, AF, 1, "add nibble carry sets AF");
        checkReg(ev, ZF, 1, "wrapped add sets ZF");
        checkReg(ev, PF, 1, "wrapped add sets PF");
    }
    {
        PcodeEvaluator ev(disassemble(0x20));
        ev.regs[RAX] = 0x1234;
        ev.run();
        checkReg(ev, RAX, 0, "xor self produces zero");
        checkReg(ev, CF, 0, "logical operation clears CF");
        checkReg(ev, OF, 0, "logical operation clears OF");
        checkReg(ev, ZF, 1, "xor zero sets ZF");
    }
    {
        PcodeInsn insn = disassemble(0x30);
        CHECK(insn.kind == Insn::JCC && insn.targetKnown && insn.target == 0x37,
              "short je target and classification");
        PcodeEvaluator yes(insn);
        yes.regs[ZF] = 1;
        yes.run();
        CHECK(yes.branchTaken(), "je is taken when ZF=1");
        PcodeEvaluator no(insn);
        no.regs[ZF] = 0;
        no.run();
        CHECK(!no.branchTaken(), "je is not taken when ZF=0");
    }
    {
        PcodeInsn insn = disassemble(0x80);
        CHECK(insn.kind == Insn::JCC && insn.targetKnown && insn.target == 0x8B,
              "near jne target and classification");
        PcodeEvaluator ev(insn);
        ev.regs[ZF] = 0;
        ev.run();
        CHECK(ev.branchTaken(), "near jne consumes ZF");
    }
    {
        PcodeEvaluator yes(disassemble(0x40));
        yes.regs[SF] = 1;
        yes.regs[OF] = 0;
        yes.run();
        checkReg(yes, RAX, 1, "setl writes one when SF differs from OF");
        PcodeEvaluator no(disassemble(0x40));
        no.regs[SF] = 1;
        no.regs[OF] = 1;
        no.run();
        checkReg(no, RAX, 0, "setl writes zero when SF equals OF");
    }
    {
        PcodeInsn insn = disassemble(0x50);
        PcodeEvaluator yes(insn);
        yes.regs[RAX] = 10;
        yes.regs[RBX] = 20;
        yes.regs[ZF] = 0;
        yes.regs[SF] = 0;
        yes.regs[OF] = 0;
        yes.run();
        checkReg(yes, RAX, 20, "cmovg copies source when condition is true");
        PcodeEvaluator no(insn);
        no.regs[RAX] = 10;
        no.regs[RBX] = 20;
        no.regs[ZF] = 1;
        no.regs[SF] = 0;
        no.regs[OF] = 0;
        no.run();
        checkReg(no, RAX, 10, "cmovg preserves destination when false");
    }
    {
        PcodeEvaluator ev(disassemble(0x60));
        ev.regs[RAX] = 0x7fffffffffffffffULL;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL, "inc updates destination");
        checkReg(ev, CF, 1, "inc preserves CF");
        checkReg(ev, OF, 1, "inc sets signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0x70));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[CF] = 0;
        ev.run();
        checkReg(ev, RAX, 0, "shl shifts destination");
        checkReg(ev, CF, 1, "shl exposes shifted-out bit in CF");
        checkReg(ev, OF, 1, "single-bit shl updates OF");
        checkReg(ev, ZF, 1, "shl zero result sets ZF");
    }
    {
        PcodeEvaluator ev(disassemble(0x90));
        ev.regs[RAX] = 0x120;
        ev.regs[RBX] = 7;
        for (int i = 0; i < 8; ++i)
            ev.ram[0x120 + i] = static_cast<uint8_t>(i == 0 ? 7 : 0);
        ev.run();
        checkReg(ev, ZF, 1, "memory cmp computes flags from loaded value");
        CHECK(ev.ram[0x120] == 7 && ev.ram[0x127] == 0,
              "memory cmp never writes its operand");
    }
    {
        PcodeEvaluator ev(disassemble(0xA0));
        ev.regs[RAX] = ~0ULL;
        ev.regs[RBX] = 0;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0, "adc includes incoming CF");
        checkReg(ev, CF, 1, "adc reports carry from incoming CF");
        checkReg(ev, ZF, 1, "adc result updates ZF");
    }
    {
        PcodeEvaluator ev(disassemble(0xA0));
        ev.regs[RAX] = 0;
        ev.regs[RBX] = 0x7fffffffffffffffULL;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "adc crosses the signed-positive boundary with carry-in");
        checkReg(ev, OF, 1, "adc includes carry-in in signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0xA0));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = ~0ULL;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "adc handles an overflowing intermediate add");
        checkReg(ev, OF, 0,
                 "adc cancels intermediate overflow when carry restores INT_MIN");
    }
    {
        PcodeEvaluator ev(disassemble(0xB0));
        ev.regs[RAX] = 0;
        ev.regs[RBX] = 0;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, ~0ULL, "sbb includes incoming CF");
        checkReg(ev, CF, 1, "sbb reports borrow from incoming CF");
        checkReg(ev, SF, 1, "sbb negative result updates SF");
    }
    {
        PcodeEvaluator ev(disassemble(0xB0));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = 0;
        ev.regs[CF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x7fffffffffffffffULL,
                 "sbb crosses the signed-negative boundary with borrow-in");
        checkReg(ev, OF, 1, "sbb includes borrow-in in signed overflow");
    }
    {
        PcodeEvaluator ev(disassemble(0xC0));
        ev.regs[RAX] = 0x1234;
        ev.regs[CF] = 1;
        ev.regs[PF] = 0;
        ev.regs[ZF] = 1;
        ev.regs[SF] = 1;
        ev.regs[OF] = 1;
        ev.run();
        checkReg(ev, RAX, 0x1234, "zero-count shift preserves destination");
        checkReg(ev, CF, 1, "zero-count shift preserves CF");
        checkReg(ev, PF, 0, "zero-count shift preserves PF");
        checkReg(ev, ZF, 1, "zero-count shift preserves ZF");
        checkReg(ev, SF, 1, "zero-count shift preserves SF");
        checkReg(ev, OF, 1, "zero-count shift preserves OF");
    }
    {
        PcodeInsn insn = disassemble(0xD0);
        PcodeEvaluator ev(insn);
        const float left[4] = {1, 2, 3, 4};
        const float right[4] = {10, 20, 30, 40};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, 16);
        std::memcpy(ev.wideRegs[8].data(), right, 16);
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        CHECK(result && result->size() == 16, "packed float result is 128 bits");
        float lanes[4] = {};
        if (result) std::memcpy(lanes, result->data(), 16);
        CHECK(lanes[0] == 11 && lanes[1] == 22 && lanes[2] == 33 && lanes[3] == 44,
              "addps evaluates every float lane");
    }
    {
        PcodeInsn insn = disassemble(0xE0);
        PcodeEvaluator ev(insn);
        const float left[4] = {1, 0, 0, 0};
        const float right[4] = {2, 0, 0, 0};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, 16);
        std::memcpy(ev.wideRegs[8].data(), right, 16);
        ev.run();
        checkReg(ev, CF, 1, "ucomiss less-than sets CF");
        checkReg(ev, PF, 0, "ordered ucomiss clears PF");
        checkReg(ev, ZF, 0, "unequal ucomiss clears ZF");
    }
    {
        PcodeInsn insn = disassemble(0xF0);
        PcodeEvaluator ev(insn);
        const float left[4] = {1, 7, 8, 9};
        const float right[4] = {2, 20, 30, 40};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, 16);
        std::memcpy(ev.wideRegs[8].data(), right, 16);
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        float lanes[4] = {};
        if (result) std::memcpy(lanes, result->data(), 16);
        CHECK(lanes[0] == 3 && lanes[1] == 7 && lanes[2] == 8 && lanes[3] == 9,
              "addss updates the low lane and preserves upper lanes");
    }
    {
        PcodeEvaluator ev(disassemble(0x100));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[CF] = 0;
        ev.regs[OF] = 0;
        ev.run();
        checkReg(ev, RAX, 1, "rol rotates the high bit into bit zero");
        checkReg(ev, CF, 1, "rol reports rotated-out bit in CF");
        checkReg(ev, OF, 1, "single-bit rol updates OF");
    }
    {
        PcodeEvaluator ev(disassemble(0x110));
        ev.regs[RAX] = 1;
        ev.regs[CF] = 0;
        ev.regs[OF] = 0;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "ror rotates bit zero into the high bit");
        checkReg(ev, CF, 1, "ror reports rotated-out bit in CF");
        checkReg(ev, OF, 1, "single-bit ror updates OF");
    }
    {
        PcodeEvaluator ev(disassemble(0x120));
        ev.regs[RAX] = 8;
        ev.regs[RBX] = 3;
        ev.run();
        checkReg(ev, CF, 1, "bt copies selected bit into CF");
        checkReg(ev, RAX, 8, "bt preserves its operand");
    }
    {
        PcodeEvaluator ev(disassemble(0x130));
        ev.regs[RAX] = 8;
        ev.regs[RBX] = 3;
        ev.run();
        checkReg(ev, CF, 1, "btr reports original selected bit");
        checkReg(ev, RAX, 0, "btr clears selected bit");
    }
    {
        PcodeEvaluator ev(disassemble(0x140));
        ev.regs[RBX] = 0xB;
        ev.run();
        checkReg(ev, RAX, 3, "popcnt counts set bits");
        checkReg(ev, ZF, 0, "popcnt clears ZF for nonzero input");
        checkReg(ev, CF, 0, "popcnt clears CF");
    }
    {
        PcodeEvaluator ev(disassemble(0x150));
        ev.regs[RAX] = 99;
        ev.regs[RBX] = 0x20;
        ev.run();
        checkReg(ev, RAX, 5, "bsf returns the least significant set-bit index");
        checkReg(ev, ZF, 0, "bsf clears ZF for nonzero input");
    }
    {
        PcodeEvaluator ev(disassemble(0x160));
        ev.regs[RAX] = 0x7fffffffffffffffULL;
        ev.regs[RBX] = 2;
        ev.run();
        checkReg(ev, RAX, 0xfffffffffffffffeULL, "imul writes truncated product");
        checkReg(ev, CF, 1, "overflowing imul sets CF");
        checkReg(ev, OF, 1, "overflowing imul sets OF");
    }
    {
        PcodeEvaluator ev(disassemble(0x170));
        ev.regs[RAX] = 3;
        ev.regs[RBX] = 4;
        ev.run();
        checkReg(ev, RAX, 7, "xadd writes sum to destination");
        checkReg(ev, RBX, 3, "xadd writes old destination to source");
        checkReg(ev, ZF, 0, "xadd updates arithmetic flags");
    }
    {
        PcodeInsn insn = disassemble(0x180);
        PcodeEvaluator ev(insn);
        const uint32_t source[4] = {1, 2, 3, 4};
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[8].data(), source, sizeof(source));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        CHECK(result && std::memcmp(result->data(), source, sizeof(source)) == 0,
              "movdqa copies the full SIMD register");
    }
    {
        PcodeInsn insn = disassemble(0x190);
        PcodeEvaluator ev(insn);
        const uint32_t left[4] = {0xffffffffU, 2, 0x80000000U, 9};
        const uint32_t right[4] = {2, 3, 0x80000000U, 4};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, sizeof(left));
        std::memcpy(ev.wideRegs[8].data(), right, sizeof(right));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        const uint32_t expected[4] = {1, 5, 0, 13};
        CHECK(result && std::memcmp(result->data(), expected, sizeof(expected)) == 0,
              "paddd wraps independently in every 32-bit lane");
    }
    {
        PcodeInsn insn = disassemble(0x1A0);
        PcodeEvaluator ev(insn);
        const uint64_t left[2] = {0xffff0000ffff0000ULL, 0xaaaaaaaaaaaaaaaaULL};
        const uint64_t right[2] = {0x00ff00ff00ff00ffULL, 0x5555555555555555ULL};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), left, sizeof(left));
        std::memcpy(ev.wideRegs[8].data(), right, sizeof(right));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        const uint64_t expected[2] = {left[0] ^ right[0], left[1] ^ right[1]};
        CHECK(result && std::memcmp(result->data(), expected, sizeof(expected)) == 0,
              "pxor applies to every SIMD bit");
    }
    {
        PcodeInsn insn = disassemble(0x1B0);
        PcodeEvaluator ev(insn);
        const float original[4] = {0, 7, 8, 9};
        ev.wideRegs[RAX].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), original, sizeof(original));
        ev.regs[RBX] = static_cast<uint32_t>(-7);
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        float lanes[4] = {};
        if (result) std::memcpy(lanes, result->data(), sizeof(lanes));
        CHECK(lanes[0] == -7 && lanes[1] == 7 && lanes[2] == 8 && lanes[3] == 9,
              "cvtsi2ss converts signed input and preserves upper lanes");
    }
    {
        PcodeInsn insn = disassemble(0x1C0);
        PcodeEvaluator ev(insn);
        const float source[4] = {3.9f, 0, 0, 0};
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[8].data(), source, sizeof(source));
        ev.run();
        checkReg(ev, RAX, 3, "cvttss2si truncates toward zero");
    }
    {
        PcodeInsn insn = disassemble(0x1D0);
        PcodeEvaluator ev(insn);
        const uint64_t original[2] = {0, 0x1122334455667788ULL};
        const float source[4] = {2.5f, 0, 0, 0};
        ev.wideRegs[RAX].resize(16);
        ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[RAX].data(), original, sizeof(original));
        std::memcpy(ev.wideRegs[8].data(), source, sizeof(source));
        ev.run();
        const auto result = ev.wideValue(insn.named.at("dst"));
        double low = 0;
        uint64_t high = 0;
        if (result) {
            std::memcpy(&low, result->data(), sizeof(low));
            std::memcpy(&high, result->data() + 8, sizeof(high));
        }
        CHECK(low == 2.5 && high == original[1],
              "cvtss2sd widens the low lane and preserves the upper half");
    }
    {
        PcodeEvaluator ev(disassemble(0x1E0));
        ev.regs[RAX] = 0x8000000000000000ULL;
        ev.regs[RBX] = 0;
        ev.run();
        checkReg(ev, RAX, 0, "shld shifts bits across the register pair");
        checkReg(ev, CF, 1, "shld reports the destination bit shifted out");
        checkReg(ev, OF, 1, "single-bit shld updates signed overflow");
        checkReg(ev, ZF, 1, "shld updates zero flag");
    }
    {
        PcodeEvaluator ev(disassemble(0x1F0));
        ev.regs[RAX] = 1;
        ev.regs[RBX] = 1;
        ev.run();
        checkReg(ev, RAX, 0x8000000000000000ULL,
                 "shrd shifts source bits into the destination high end");
        checkReg(ev, CF, 1, "shrd reports the destination bit shifted out");
        checkReg(ev, OF, 1, "single-bit shrd updates signed overflow");
        checkReg(ev, SF, 1, "shrd updates sign flag");
    }
    {
        PcodeInsn insn = disassemble(0x200);
        uint64_t st0 = 0;
        for (const auto& entry : insn.varnodes)
            if (entry.second.kind == Varnode::REGISTER &&
                entry.second.offset == 24576 && entry.second.size == 10)
                st0 = entry.first;
        PcodeEvaluator ev(insn);
        ev.run();
        const auto result = ev.wideValue(st0);
        uint64_t significand = 0;
        uint16_t signExponent = 0;
        if (result && result->size() >= 10) {
            std::memcpy(&significand, result->data(), 8);
            std::memcpy(&signExponent, result->data() + 8, 2);
        }
        CHECK(st0 && significand == 0x8000000000000000ULL &&
                  signExponent == 0x3fff,
              "fld1 pushes exact 80-bit extended precision 1.0");
    }
    {
        PcodeInsn insn = disassemble(0x210);
        uint64_t st0 = 0;
        for (const auto& entry : insn.varnodes)
            if (entry.second.kind == Varnode::REGISTER &&
                entry.second.offset == 24576 && entry.second.size == 10)
                st0 = entry.first;
        PcodeEvaluator ev(insn);
        ev.wideRegs[24576].resize(10);
        const uint64_t oneSignificand = 0x8000000000000000ULL;
        const uint16_t oneExponent = 0x3fff;
        std::memcpy(ev.wideRegs[24576].data(), &oneSignificand, 8);
        std::memcpy(ev.wideRegs[24576].data() + 8, &oneExponent, 2);
        ev.run();
        const auto result = ev.wideValue(st0);
        uint64_t significand = 0;
        uint16_t signExponent = 0;
        if (result && result->size() >= 10) {
            std::memcpy(&significand, result->data(), 8);
            std::memcpy(&signExponent, result->data() + 8, 2);
        }
        CHECK(st0 && significand == 0x8000000000000000ULL &&
                  signExponent == 0x4000,
              "x87 arithmetic preserves 80-bit precision and stack state");
    }
    {
        PcodeInsn insn;
        Varnode computed;
        computed.id = 1; computed.kind = Varnode::REGISTER;
        computed.offset = 0x100; computed.size = 16; computed.name = "computed";
        Varnode previous;
        previous.id = 2; previous.kind = Varnode::REGISTER;
        previous.offset = 0x110; previous.size = 16; previous.name = "previous";
        Varnode mask;
        mask.id = 3; mask.kind = Varnode::REGISTER;
        mask.offset = 8192 + 8; mask.size = 8; mask.name = "k1";
        Varnode output;
        output.id = 4; output.kind = Varnode::UNIQUE;
        output.offset = 1; output.size = 16; output.name = "masked";
        insn.varnodes.emplace(computed.id, computed);
        insn.varnodes.emplace(previous.id, previous);
        insn.varnodes.emplace(mask.id, mask);
        insn.varnodes.emplace(output.id, output);
        PcodeOp merge;
        merge.op = POp::SIMD_MASK; merge.out = output.id;
        merge.in0 = computed.id; merge.in1 = previous.id; merge.in2 = mask.id;
        merge.aux = 32;
        insn.ops.push_back(merge);

        PcodeEvaluator ev(insn);
        const uint32_t calculated[4] = {10, 20, 30, 40};
        const uint32_t oldValue[4] = {1, 2, 3, 4};
        ev.wideRegs[computed.offset].resize(16);
        ev.wideRegs[previous.offset].resize(16);
        std::memcpy(ev.wideRegs[computed.offset].data(), calculated,
                    sizeof(calculated));
        std::memcpy(ev.wideRegs[previous.offset].data(), oldValue,
                    sizeof(oldValue));
        ev.regs[mask.offset] = 0b0101;
        ev.run();
        const auto result = ev.wideValue(output.id);
        const uint32_t expected[4] = {10, 2, 30, 4};
        CHECK(result && std::memcmp(result->data(), expected, sizeof(expected)) == 0,
              "AVX-512 merge masking preserves disabled destination lanes");

        insn.ops[0].aux = static_cast<uint16_t>(0x8000U | 32U);
        PcodeEvaluator zeroing(insn);
        zeroing.wideRegs = ev.wideRegs;
        zeroing.regs[mask.offset] = 0b0101;
        zeroing.run();
        const auto zeroResult = zeroing.wideValue(output.id);
        const uint32_t zeroExpected[4] = {10, 0, 30, 0};
        CHECK(zeroResult &&
                  std::memcmp(zeroResult->data(), zeroExpected,
                              sizeof(zeroExpected)) == 0,
              "AVX-512 zero masking clears disabled destination lanes");
    }
    {
        PcodeInsn insn = disassemble(0x220);
        CHECK(std::any_of(insn.ops.begin(), insn.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::SIMD_MASK;
                          }),
              "masked AVX-512 stores lower through SIMD_MASK");
        PcodeEvaluator ev(insn);
        ev.regs[RAX] = 0x500;
        ev.regs[8192 + 8] = 0b0101;
        uint32_t source[16] = {};
        uint32_t previous[16] = {};
        for (size_t lane = 0; lane < 16; ++lane) {
            source[lane] = static_cast<uint32_t>(100 + lane);
            previous[lane] = static_cast<uint32_t>(10 + lane);
        }
        ev.wideRegs[RAX].resize(sizeof(source));
        std::memcpy(ev.wideRegs[RAX].data(), source, sizeof(source));
        for (size_t byte = 0; byte < sizeof(previous); ++byte)
            ev.ram[0x500 + byte] = reinterpret_cast<uint8_t*>(previous)[byte];
        ev.run();
        uint32_t stored[16] = {};
        for (size_t byte = 0; byte < sizeof(stored); ++byte)
            reinterpret_cast<uint8_t*>(stored)[byte] = ev.ram[0x500 + byte];
        CHECK(stored[0] == source[0] && stored[1] == previous[1] &&
                  stored[2] == source[2] && stored[3] == previous[3],
              "AVX-512 masked store preserves disabled memory lanes");
    }
    {
        PcodeInsn insn = disassemble(0x230);
        CHECK(std::any_of(insn.ops.begin(), insn.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::FLOAT_LESS;
                          }),
              "x87 FCOM emits executable 80-bit comparisons");
        PcodeEvaluator ev(insn);
        ev.regs[RAX] = 0x600;
        ev.regs[12418] = 0;
        ev.wideRegs[24576].resize(10);
        const uint64_t oneSignificand = 0x8000000000000000ULL;
        const uint16_t oneExponent = 0x3fff;
        std::memcpy(ev.wideRegs[24576].data(), &oneSignificand, 8);
        std::memcpy(ev.wideRegs[24576].data() + 8, &oneExponent, 2);
        const float two = 2.0f;
        const auto* bytes = reinterpret_cast<const uint8_t*>(&two);
        for (size_t i = 0; i < sizeof(two); ++i) ev.ram[0x600 + i] = bytes[i];
        ev.run();
        checkReg(ev, 12418, 0x0100,
                 "x87 FCOM sets C0 for an ordered less-than result");
    }
    {
        PcodeEvaluator ev(disassemble(0x240));
        ev.regs[RAX] = 0x620;
        ev.ram[0x620] = 0x7f;
        ev.ram[0x621] = 0x02;
        ev.run();
        checkReg(ev, 12416, 0x027f, "FLDCW restores the x87 control word");
    }
    {
        PcodeEvaluator ev(disassemble(0x250));
        ev.regs[12418] = 0x4500;
        ev.run();
        checkReg(ev, RAX, 0x4500, "FNSTSW AX exposes the x87 status word");
    }
    {
        struct VectorCase { uint64_t address; POp operation; const char* message; };
        const VectorCase cases[] = {
            {0x260, POp::SIMD_COMPARE, "PCMPEQ uses lane comparison p-code"},
            {0x270, POp::SIMD_SATURATE, "PADDS uses saturating lane p-code"},
            {0x280, POp::SIMD_UNPACK, "PUNPCK uses interleave p-code"},
            {0x290, POp::SIMD_PACK, "PACK uses narrowing saturation p-code"},
            {0x2A0, POp::SIMD_SHUFFLE, "PSHUFB uses lane-local shuffle p-code"},
            {0x300, POp::SIMD_SHUFFLE, "PSHUFD uses immediate shuffle p-code"},
            {0x310, POp::SIMD_SHUFFLE, "SHUFPS uses two-source shuffle p-code"},
            {0x320, POp::SIMD_SHUFFLE, "SHUFPD uses two-source shuffle p-code"},
        };
        for (const auto& vectorCase : cases) {
            const PcodeInsn insn = disassemble(vectorCase.address);
            CHECK(std::any_of(insn.ops.begin(), insn.ops.end(),
                              [&](const PcodeOp& operation) {
                                  return operation.op == vectorCase.operation;
                              }), vectorCase.message);
        }

        PcodeInsn compare = disassemble(0x260);
        const Varnode* dst = compare.find(compare.named["dst"]);
        const Varnode* src = compare.find(compare.named["src"]);
        PcodeEvaluator ev(compare);
        const uint8_t lhs[16] = {1, 2, 3, 4, 5, 6, 7, 8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
        const uint8_t rhs[16] = {1, 0, 3, 0, 5, 0, 7, 0,
                                 9, 0, 11, 0, 13, 0, 15, 0};
        if (dst && src) {
            ev.wideRegs[dst->offset].assign(lhs, lhs + 16);
            ev.wideRegs[src->offset].assign(rhs, rhs + 16);
            ev.run();
            const auto result = ev.wideValue(compare.named["dst"]);
            CHECK(result && (*result)[0] == 0xff && (*result)[1] == 0 &&
                      (*result)[14] == 0xff && (*result)[15] == 0,
                  "PCMPEQB evaluator produces all-one/all-zero byte lanes");
        } else {
            CHECK(false, "PCMPEQB exposes vector operands");
        }

        PcodeInsn shuffle = disassemble(0x300);
        const Varnode* shuffleSource = shuffle.find(shuffle.named["src"]);
        PcodeEvaluator shuffled(shuffle);
        const uint32_t ordered[4] = {10, 20, 30, 40};
        if (shuffleSource) {
            shuffled.wideRegs[shuffleSource->offset].resize(sizeof(ordered));
            std::memcpy(shuffled.wideRegs[shuffleSource->offset].data(), ordered,
                        sizeof(ordered));
            shuffled.run();
            const auto result = shuffled.wideValue(shuffle.named["dst"]);
            uint32_t actual[4] = {};
            if (result) std::memcpy(actual, result->data(), sizeof(actual));
            CHECK(result && actual[0] == 40 && actual[1] == 30 &&
                      actual[2] == 20 && actual[3] == 10,
                  "PSHUFD evaluator applies all immediate selector fields");
        } else {
            CHECK(false, "PSHUFD exposes its vector source");
        }
    }
    {
        PcodeInsn pdep = disassemble(0x2B0);
        CHECK(std::any_of(pdep.ops.begin(), pdep.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::INT_PDEP;
                          }), "PDEP lowers to an executable bit-deposit primitive");
        PcodeEvaluator deposit(pdep);
        deposit.regs[RBX] = 0x0b;
        deposit.regs[RCX] = 0x56;
        deposit.run();
        checkReg(deposit, RAX, 0x46, "PDEP deposits source bits into mask positions");

        PcodeEvaluator extract(disassemble(0x2C0));
        extract.regs[RBX] = 0x46;
        extract.regs[RCX] = 0x56;
        extract.run();
        checkReg(extract, RAX, 0x0b, "PEXT compacts selected source bits");

        PcodeEvaluator shlx(disassemble(0x2D0));
        shlx.regs[RBX] = 3;
        shlx.regs[RCX] = 5;
        shlx.run();
        checkReg(shlx, RAX, 40, "SHLX uses its independent count operand");

        PcodeEvaluator andn(disassemble(0x2E0));
        andn.regs[RBX] = 0xf0;
        andn.regs[RCX] = 0xff;
        andn.run();
        checkReg(andn, RAX, 0x0f, "ANDN computes complement(source1) AND source2");

        PcodeEvaluator bextr(disassemble(0x2F0));
        bextr.regs[RBX] = 0x0804; // start=4, length=8
        bextr.regs[RCX] = 0xabc;
        bextr.run();
        checkReg(bextr, RAX, 0xab, "BEXTR honors dynamic start and length fields");
    }
    {
        PcodeInsn add = disassemble(0x330);
        CHECK(std::any_of(add.ops.begin(), add.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::INT_ADD &&
                                     operation.aux == 32;
                          }) &&
                  std::any_of(add.ops.begin(), add.ops.end(),
                              [](const PcodeOp& operation) {
                                  return operation.op == POp::SIMD_MASK;
                              }),
              "EVEX VPADDD combines lane arithmetic with writemask semantics");
        const Varnode* dst = add.find(add.named["dst"]);
        const Varnode* src2 = add.find(add.named["src2"]);
        PcodeEvaluator ev(add);
        uint32_t lhs[16] = {}, rhs[16] = {};
        for (size_t lane = 0; lane < 16; ++lane) {
            lhs[lane] = static_cast<uint32_t>(lane + 1);
            rhs[lane] = 100;
        }
        if (dst && src2) {
            ev.wideRegs[dst->offset].resize(sizeof(lhs));
            ev.wideRegs[src2->offset].resize(sizeof(rhs));
            std::memcpy(ev.wideRegs[dst->offset].data(), lhs, sizeof(lhs));
            std::memcpy(ev.wideRegs[src2->offset].data(), rhs, sizeof(rhs));
            ev.regs[8192 + 8] = 0x5555;
            ev.run();
            const auto result = ev.wideValue(add.named["dst"]);
            uint32_t lanes[16] = {};
            if (result) std::memcpy(lanes, result->data(), sizeof(lanes));
            CHECK(result && lanes[0] == 101 && lanes[1] == 2 &&
                      lanes[2] == 103 && lanes[3] == 4,
                  "EVEX VPADDD preserves merge-masked destination lanes");
        } else {
            CHECK(false, "EVEX VPADDD exposes ZMM operands");
        }

        const PcodeInsn saturated = disassemble(0x340);
        CHECK(std::any_of(saturated.ops.begin(), saturated.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::SIMD_SATURATE;
                          }), "EVEX VPADDSB reuses exact signed saturation");
        const PcodeInsn floating = disassemble(0x350);
        CHECK(std::any_of(floating.ops.begin(), floating.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::FLOAT_ADD &&
                                     operation.aux == 32;
                          }), "EVEX VADDPS reuses packed IEEE-754 lane semantics");
    }
    {
        PcodeInsn aes = disassemble(0x360);
        CHECK(std::any_of(aes.ops.begin(), aes.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::AES_ENC;
                          }), "AESENC lowers to an executable AES round primitive");
        const Varnode* state = aes.find(aes.named["dst"]);
        const Varnode* key = aes.find(aes.named["src"]);
        const uint8_t input[16] = {
            0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70,
            0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0};
        const uint8_t expected[16] = {
            0x5f, 0x72, 0x64, 0x15, 0x57, 0xf5, 0xbc, 0x92,
            0xf7, 0xbe, 0x3b, 0x29, 0x1d, 0xb9, 0xf9, 0x1a};
        PcodeEvaluator ev(aes);
        if (state && key) {
            ev.wideRegs[state->offset].assign(input, input + 16);
            ev.wideRegs[key->offset].assign(16, 0);
            ev.run();
            const auto result = ev.wideValue(aes.named["dst"]);
            CHECK(result && std::memcmp(result->data(), expected, 16) == 0,
                  "AESENC matches the FIPS-197 SubBytes/ShiftRows/MixColumns state");
        } else {
            CHECK(false, "AESENC exposes state and round-key operands");
        }

        const PcodeInsn vaes = disassemble(0x370);
        CHECK(std::any_of(vaes.ops.begin(), vaes.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::AES_ENC;
                          }), "VAESENC reuses the exact lane-local AES primitive");
    }
    {
        PcodeInsn roundedInsn = disassemble(0x380);
        CHECK(std::any_of(roundedInsn.ops.begin(), roundedInsn.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::FLOAT_ROUND;
                          }), "FRNDINT lowers with the architectural control word");
        PcodeEvaluator rounded(roundedInsn);
        rounded.regs[12416] = 0x077f; // RC=01, round toward -infinity
        rounded.wideRegs[24576].resize(10);
        const uint64_t onePointSevenFive = 0xe000000000000000ULL;
        const uint16_t exponent = 0x3fff;
        std::memcpy(rounded.wideRegs[24576].data(), &onePointSevenFive, 8);
        std::memcpy(rounded.wideRegs[24576].data() + 8, &exponent, 2);
        rounded.run();
        uint64_t st0 = 0;
        for (const auto& entry : roundedInsn.varnodes)
            if (entry.second.kind == Varnode::REGISTER &&
                entry.second.offset == 24576 && entry.second.size == 10)
                st0 = entry.first;
        const auto result = rounded.wideValue(st0);
        uint64_t roundedSignificand = 0;
        uint16_t roundedExponent = 0;
        if (result && result->size() >= 10) {
            std::memcpy(&roundedSignificand, result->data(), 8);
            std::memcpy(&roundedExponent, result->data() + 8, 2);
        }
        CHECK(result && roundedSignificand == 0x8000000000000000ULL &&
                  roundedExponent == 0x3fff,
              "FRNDINT obeys the x87 RC round-down mode");
        const PcodeInsn sine = disassemble(0x390);
        const PcodeInsn exponential = disassemble(0x3A0);
        CHECK(std::any_of(sine.ops.begin(), sine.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::FLOAT_SIN;
                          }) &&
                  std::any_of(exponential.ops.begin(), exponential.ops.end(),
                              [](const PcodeOp& operation) {
                                  return operation.op == POp::FLOAT_EXP2;
                              }),
              "x87 transcendental opcodes emit executable 80-bit primitives");
    }
    {
        PcodeInsn saveInsn = disassemble(0x3B0);
        CHECK(std::any_of(saveInsn.ops.begin(), saveInsn.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::X86_XSTATE_SAVE;
                          }), "FXSAVE lowers to the architectural xstate layout");
        PcodeEvaluator save(saveInsn);
        save.regs[RAX] = 0x800;
        save.regs[12416] = 0x027f;
        save.regs[12424] = 0x1f40;
        save.wideRegs[0].resize(16);
        for (size_t byte = 0; byte < 16; ++byte)
            save.wideRegs[0][byte] = static_cast<uint8_t>(byte + 1);
        save.run();
        CHECK(save.ram[0x800] == 0x7f && save.ram[0x801] == 0x02 &&
                  save.ram[0x800 + 160] == 1 &&
                  save.ram[0x800 + 175] == 16,
              "FXSAVE writes FCW and XMM0 at Intel-defined legacy offsets");

        PcodeEvaluator restore(disassemble(0x3C0));
        restore.regs[RAX] = 0x800;
        restore.ram = save.ram;
        restore.run();
        CHECK(restore.regs[12416] == 0x027f &&
                  restore.wideRegs[0].size() >= 16 &&
                  restore.wideRegs[0][0] == 1 && restore.wideRegs[0][15] == 16,
              "FXRSTOR restores legacy x87 and SSE state components");
    }
    {
        PcodeInsn compare = disassemble(0x3D0);
        CHECK(std::any_of(compare.ops.begin(), compare.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::SIMD_COMPARE_MASK;
                          }), "VPCMPD lowers all imm8 predicates to a k mask");
        const Varnode* left = compare.find(compare.named["src1"]);
        const Varnode* right = compare.find(compare.named["src2"]);
        const Varnode* destination = compare.find(compare.named["dst"]);
        PcodeEvaluator ev(compare);
        uint32_t leftLanes[16] = {}, rightLanes[16] = {};
        for (size_t lane = 0; lane < 16; ++lane) {
            leftLanes[lane] = static_cast<uint32_t>(lane);
            rightLanes[lane] = static_cast<uint32_t>(lane + (lane & 1U));
        }
        if (left && right && destination) {
            ev.wideRegs[left->offset].resize(sizeof(leftLanes));
            ev.wideRegs[right->offset].resize(sizeof(rightLanes));
            std::memcpy(ev.wideRegs[left->offset].data(), leftLanes,
                        sizeof(leftLanes));
            std::memcpy(ev.wideRegs[right->offset].data(), rightLanes,
                        sizeof(rightLanes));
            ev.run();
            checkReg(ev, destination->offset, 0x5555,
                     "VPCMPD EQ emits one result bit per matching dword lane");
        } else {
            CHECK(false, "VPCMPD exposes vector sources and k destination");
        }
    }
    {
        PcodeInsn gather = disassemble(0x3E0);
        CHECK(std::any_of(gather.ops.begin(), gather.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::SIMD_GATHER;
                          }), "VPGATHERDD lowers VSIB addressing and k masking");
        const Varnode* destination = gather.find(gather.named["dst"]);
        PcodeEvaluator ev(gather);
        ev.regs[RAX] = 0x900;
        ev.regs[8192 + 8] = 0x5555;
        uint32_t oldLanes[16] = {}, indices[16] = {};
        for (size_t lane = 0; lane < 16; ++lane) {
            oldLanes[lane] = static_cast<uint32_t>(lane + 1);
            indices[lane] = static_cast<uint32_t>(lane);
            const uint32_t memoryValue = static_cast<uint32_t>(100 + lane);
            const auto* bytes = reinterpret_cast<const uint8_t*>(&memoryValue);
            for (size_t byte = 0; byte < 4; ++byte)
                ev.ram[0x900 + lane * 4 + byte] = bytes[byte];
        }
        if (destination) {
            ev.wideRegs[destination->offset].resize(sizeof(oldLanes));
            ev.wideRegs[8].resize(sizeof(indices)); // zmm1 VSIB index
            std::memcpy(ev.wideRegs[destination->offset].data(), oldLanes,
                        sizeof(oldLanes));
            std::memcpy(ev.wideRegs[8].data(), indices, sizeof(indices));
            ev.run();
            const auto result = ev.wideValue(gather.named["dst"]);
            uint32_t lanes[16] = {};
            if (result) std::memcpy(lanes, result->data(), sizeof(lanes));
            CHECK(result && lanes[0] == 100 && lanes[1] == 2 &&
                      lanes[2] == 102 && lanes[3] == 4 &&
                      ev.regs[8192 + 8] == 0,
                  "VPGATHERDD loads active VSIB lanes and clears completed mask bits");
        } else {
            CHECK(false, "VPGATHERDD exposes its vector destination");
        }
        const PcodeInsn scatter = disassemble(0x3F0);
        CHECK(std::any_of(scatter.ops.begin(), scatter.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::SIMD_SCATTER;
                          }), "VPSCATTERDD lowers lane-wise masked stores");
    }
    {
        PcodeInsn multiply = disassemble(0x400);
        CHECK(std::any_of(multiply.ops.begin(), multiply.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::GF2P8_MUL;
                          }), "GF2P8MULB lowers to Rijndael-field multiplication");
        const Varnode* left = multiply.find(multiply.named["dst"]);
        const Varnode* right = multiply.find(multiply.named["src"]);
        PcodeEvaluator ev(multiply);
        if (left && right) {
            ev.wideRegs[left->offset].assign(16, 0);
            ev.wideRegs[right->offset].assign(16, 0);
            ev.wideRegs[left->offset][0] = 0x57;
            ev.wideRegs[right->offset][0] = 0x13;
            ev.run();
            const auto result = ev.wideValue(multiply.named["dst"]);
            CHECK(result && (*result)[0] == 0xfe,
                  "GF2P8MULB matches the canonical 0x57*0x13=0xfe product");
        } else {
            CHECK(false, "GF2P8MULB exposes both vector operands");
        }
    }
    {
        const PcodeInsn sha = disassemble(0x410);
        CHECK(std::any_of(sha.ops.begin(), sha.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::SHA1_MSG1;
                          }), "SHA1MSG1 lowers to an executable SHA primitive");
        PcodeEvaluator ev(sha);
        const uint32_t left[4] = {1, 2, 3, 4};
        const uint32_t right[4] = {5, 6, 7, 8};
        ev.wideRegs[0].resize(16); ev.wideRegs[8].resize(16);
        std::memcpy(ev.wideRegs[0].data(), left, 16);
        std::memcpy(ev.wideRegs[8].data(), right, 16);
        ev.run();
        const auto result = ev.wideValue(sha.named.at("dst"));
        uint32_t words[4] = {};
        if (result) std::memcpy(words, result->data(), 16);
        CHECK(result && words[0] == 6 && words[1] == 10 &&
                         words[2] == 2 && words[3] == 6,
              "SHA1MSG1 follows Intel dword message-schedule ordering");
        for (uint64_t at : {0x420ULL, 0x430ULL, 0x440ULL, 0x450ULL,
                            0x460ULL}) {
            const PcodeInsn instruction = disassemble(at);
            CHECK(std::any_of(instruction.ops.begin(), instruction.ops.end(),
                              [](const PcodeOp& operation) {
                                  return operation.op >= POp::SHA1_MSG1 &&
                                         operation.op <= POp::SHA256_RNDS2;
                              }), "every Intel SHA instruction has executable semantics");
        }
        const PcodeInsn msg1Insn = disassemble(0x430);
        PcodeEvaluator sha256msg1(msg1Insn);
        sha256msg1.wideRegs[0].resize(16);
        sha256msg1.wideRegs[8].resize(16);
        std::memcpy(sha256msg1.wideRegs[0].data(), left, 16);
        std::memcpy(sha256msg1.wideRegs[8].data(), right, 16);
        sha256msg1.run();
        const auto msg1 = sha256msg1.wideValue(msg1Insn.named.at("dst"));
        const uint32_t msg1Hardware[4] = {
            0x04008001U, 0x0600c002U, 0x08010003U, 0x0a014004U};
        CHECK(msg1 && std::memcmp(msg1->data(), msg1Hardware, 16) == 0,
              "SHA256MSG1 matches an Intel hardware differential vector");
        const PcodeInsn msg2Insn = disassemble(0x440);
        PcodeEvaluator sha256msg2(msg2Insn);
        sha256msg2.wideRegs[0].resize(16);
        sha256msg2.wideRegs[8].resize(16);
        std::memcpy(sha256msg2.wideRegs[0].data(), left, 16);
        std::memcpy(sha256msg2.wideRegs[8].data(), right, 16);
        sha256msg2.run();
        const auto msg2 = sha256msg2.wideValue(msg2Insn.named.at("dst"));
        const uint32_t msg2Hardware[4] = {
            0x00036001U, 0x00050002U, 0xdc00a0dcU, 0x20014146U};
        CHECK(msg2 && std::memcmp(msg2->data(), msg2Hardware, 16) == 0,
              "SHA256MSG2 matches an Intel hardware differential vector");
        PcodeEvaluator unsupported(sha);
        unsupported.x86Features &= ~1ULL;
        unsupported.run();
        CHECK(unsupported.fault &&
                  unsupported.fault->vector ==
                      PcodeEvaluator::X86Fault::InvalidOpcode,
              "missing SHA CPUID feature raises #UD before state mutation");
        PcodeEvaluator unavailable(sha);
        unavailable.controlRegs[0] = 1ULL << 3; // CR0.TS
        unavailable.run();
        CHECK(unavailable.fault &&
                  unavailable.fault->vector ==
                      PcodeEvaluator::X86Fault::DeviceNotAvailable,
              "CR0.TS raises #NM before SHA/SSE state access");
        PcodeEvaluator emulated(sha);
        emulated.controlRegs[0] = 1ULL << 2; // CR0.EM
        emulated.run();
        CHECK(emulated.fault &&
                  emulated.fault->vector ==
                      PcodeEvaluator::X86Fault::InvalidOpcode,
              "CR0.EM raises #UD for SSE-class SHA instructions");
    }
    {
        const PcodeInsn affine = disassemble(0x470);
        CHECK(std::any_of(affine.ops.begin(), affine.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::GF2P8_AFFINE;
                          }), "GF2P8AFFINEQB lowers to an affine primitive");
        PcodeEvaluator ev(affine);
        ev.wideRegs[0].resize(16);
        ev.wideRegs[8].resize(16);
        for (size_t byte = 0; byte < 16; ++byte)
            ev.wideRegs[0][byte] = static_cast<uint8_t>(byte * 13 + 1);
        const uint64_t identity = 0x0102040810204080ULL;
        std::memcpy(ev.wideRegs[8].data(), &identity, 8);
        std::memcpy(ev.wideRegs[8].data() + 8, &identity, 8);
        ev.run();
        const auto result = ev.wideValue(affine.named.at("dst"));
        CHECK(result && (*result)[0] == static_cast<uint8_t>(1 ^ 0xA5) &&
                          (*result)[7] ==
                              static_cast<uint8_t>((7 * 13 + 1) ^ 0xA5),
              "GFNI identity matrix plus imm8 is evaluated bit-exactly");

        const PcodeInsn inverse = disassemble(0x480);
        PcodeEvaluator inverseEv(inverse);
        inverseEv.wideRegs[0].assign(16, 0x53);
        inverseEv.wideRegs[8] = ev.wideRegs[8];
        inverseEv.run();
        const auto inverseResult = inverseEv.wideValue(inverse.named.at("dst"));
        CHECK(inverseResult && (*inverseResult)[0] == 0xCA,
              "GF2P8AFFINEINVQB implements GF(2^8) multiplicative inverse");
    }
    {
        const PcodeInsn clmul = disassemble(0x490);
        CHECK(std::any_of(clmul.ops.begin(), clmul.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::CARRYLESS_MULT;
                          }), "PCLMULQDQ lowers to carry-less multiplication");
        PcodeEvaluator ev(clmul);
        ev.wideRegs[0].assign(16, 0);
        ev.wideRegs[8].assign(16, 0);
        ev.wideRegs[0][0] = 3;
        ev.wideRegs[8][0] = 5;
        ev.run();
        const auto result = ev.wideValue(clmul.named.at("dst"));
        CHECK(result && (*result)[0] == 0x0F,
              "PCLMULQDQ computes polynomial 3*5 == 0xf without carries");
        for (uint64_t at : {0x4A0ULL, 0x4B0ULL}) {
            const PcodeInsn vectorClmul = disassemble(at);
            CHECK(std::any_of(vectorClmul.ops.begin(), vectorClmul.ops.end(),
                              [](const PcodeOp& operation) {
                                  return operation.op == POp::CARRYLESS_MULT;
                              }), "VEX/EVEX VPCLMULQDQ encodings share exact semantics");
        }
        const PcodeInsn vaesMemory = disassemble(0x4C0);
        CHECK(std::any_of(vaesMemory.ops.begin(), vaesMemory.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::AES_ENC;
                          }), "EVEX VAESENCLAST memory encoding has executable semantics");
    }
    {
        PcodeInsn guarded;
        guarded.addr = 0xDEAD;
        guarded.ops.push_back(PcodeOp{POp::X86_GUARD, 0, 0, 0, 0, 1});
        PcodeEvaluator ev(guarded);
        ev.privilegeLevel = 3;
        ev.run();
        CHECK(ev.fault &&
                  ev.fault->vector ==
                      PcodeEvaluator::X86Fault::GeneralProtection,
              "ring-0 guard raises #GP(0) at CPL3");

        PcodeEvaluator pending(disassemble(0x390));
        pending.regs[12416] = 0x037e; // invalid-operation mask cleared
        pending.regs[12418] = 1;
        pending.run();
        CHECK(pending.fault &&
                  pending.fault->vector ==
                      PcodeEvaluator::X86Fault::X87FloatingPoint,
              "pending unmasked x87 status raises #MF before execution");
        PcodeEvaluator noWait(disassemble(0x250));
        noWait.regs[12416] = 0x037e;
        noWait.regs[12418] = 1;
        noWait.run();
        CHECK(!noWait.fault,
              "FNSTSW no-wait form does not deliver a pending #MF");
    }
    {
        auto ext80 = [](long double value) {
            std::vector<uint8_t> bytes(10, 0);
            if (value == 0) return bytes;
            const bool negative = value < 0;
            value = std::fabs(value);
            int exponent = 0;
            const long double fraction = std::frexp(value, &exponent);
            const uint64_t significand = static_cast<uint64_t>(
                std::ldexp(fraction, 64));
            const uint16_t signExponent = static_cast<uint16_t>(
                (negative ? 0x8000U : 0) | (exponent - 1 + 16383));
            std::memcpy(bytes.data(), &significand, 8);
            std::memcpy(bytes.data() + 8, &signExponent, 2);
            return bytes;
        };
        PcodeEvaluator invalid(disassemble(0x4D0));
        invalid.regs[12416] = 0x037f; // all exceptions masked
        invalid.wideRegs[24576] = ext80(-1.0L);
        invalid.run();
        CHECK((invalid.regValue(12418).value_or(0) & 1U) != 0,
              "FSQRT of a negative finite value records x87 invalid-operation");

        PcodeEvaluator precision(disassemble(0x4E0));
        precision.regs[12416] = 0x007f; // PC=24, round-to-nearest, masked
        precision.wideRegs[24576] = ext80(1.0L);
        precision.wideRegs[24576 + 16] = ext80(std::ldexp(1.0L, -30));
        precision.run();
        CHECK((precision.regValue(12418).value_or(0) & (1U << 5)) != 0,
              "24-bit x87 precision control rounds the significand and sets PE");
    }
    {
        PcodeInsn cpuid = disassemble(0x500);
        CHECK(std::any_of(cpuid.ops.begin(), cpuid.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::X86_SYSTEM;
                          }), "CPUID lowers to an executable system-state operation");
        PcodeEvaluator ev(cpuid);
        ev.regs[RAX] = 1; ev.regs[RCX] = 2;
        ev.cpuidLeaves[(1ULL << 32) | 2] = {0x11, 0x22, 0x33, 0x44};
        ev.run();
        CHECK(ev.regValue(RAX).value_or(0) == 0x11 &&
                  ev.regValue(RBX).value_or(0) == 0x22 &&
                  ev.regValue(RCX).value_or(0) == 0x33 &&
                  ev.regValue(16).value_or(0) == 0x44,
              "CPUID selects leaf/subleaf and writes EAX/EBX/ECX/EDX");

        PcodeEvaluator rdmsr(disassemble(0x510));
        rdmsr.privilegeLevel = 0;
        rdmsr.regs[RCX] = 0x10;
        rdmsr.modelSpecificRegs[0x10] = 0x1122334455667788ULL;
        rdmsr.run();
        CHECK(rdmsr.regValue(RAX).value_or(0) == 0x55667788 &&
                  rdmsr.regValue(16).value_or(0) == 0x11223344,
              "RDMSR splits a valid MSR into EDX:EAX");

        PcodeEvaluator wrmsr(disassemble(0x520));
        wrmsr.privilegeLevel = 0;
        wrmsr.regs[RCX] = 0x10; wrmsr.regs[RAX] = 0x89abcdef;
        wrmsr.regs[16] = 0x01234567;
        wrmsr.modelSpecificRegs[0x10] = 0;
        wrmsr.run();
        CHECK(wrmsr.modelSpecificRegs[0x10] == 0x0123456789abcdefULL,
              "WRMSR combines EDX:EAX for a modeled valid MSR");
    }
    {
        PcodeEvaluator get(disassemble(0x530));
        get.controlRegs[4] = 1ULL << 18;
        get.xcr0 = 0xe7; get.regs[RCX] = 0;
        get.run();
        CHECK(!get.fault && get.regValue(RAX).value_or(0) == 0xe7,
              "XGETBV reads XCR0 when CR4.OSXSAVE is enabled");

        PcodeEvaluator set(disassemble(0x540));
        set.privilegeLevel = 0; set.controlRegs[4] = 1ULL << 18;
        set.regs[RCX] = 0; set.regs[RAX] = 0xe7; set.regs[16] = 0;
        set.run();
        CHECK(!set.fault && set.xcr0 == 0xe7,
              "XSETBV accepts dependent x87/SSE/AVX/AVX-512 components");
        PcodeEvaluator invalid(disassemble(0x540));
        invalid.privilegeLevel = 0; invalid.controlRegs[4] = 1ULL << 18;
        invalid.regs[RCX] = 0; invalid.regs[RAX] = 4; invalid.regs[16] = 0;
        invalid.run();
        CHECK(invalid.fault && invalid.fault->vector ==
                  PcodeEvaluator::X86Fault::GeneralProtection,
              "XSETBV dependency violation raises #GP before changing XCR0");

        PcodeEvaluator clts(disassemble(0x550));
        clts.privilegeLevel = 0; clts.controlRegs[0] = 1ULL << 3;
        clts.run();
        CHECK(!clts.fault && (clts.controlRegs[0] & (1ULL << 3)) == 0,
              "CLTS clears CR0.TS");

        PcodeEvaluator swapgs(disassemble(0x560));
        swapgs.privilegeLevel = 0;
        swapgs.modelSpecificRegs[0xc0000101U] = 0x1111;
        swapgs.modelSpecificRegs[0xc0000102U] = 0x2222;
        swapgs.run();
        CHECK(!swapgs.fault &&
                  swapgs.modelSpecificRegs[0xc0000101U] == 0x2222 &&
                  swapgs.modelSpecificRegs[0xc0000102U] == 0x1111,
              "SWAPGS exchanges GS_BASE and KERNEL_GS_BASE");
    }
    {
        PcodeEvaluator deniedCli(disassemble(0x570));
        deniedCli.privilegeLevel = 3; deniedCli.iopl = 0;
        deniedCli.run();
        CHECK(deniedCli.fault && deniedCli.fault->vector ==
                  PcodeEvaluator::X86Fault::GeneralProtection,
              "CLI raises #GP when CPL exceeds IOPL");
        PcodeEvaluator cli(disassemble(0x570));
        cli.privilegeLevel = 3; cli.iopl = 3; cli.run();
        CHECK(!cli.fault && !cli.interruptsEnabled,
              "CLI clears IF when CPL is permitted by IOPL");
        PcodeEvaluator sti(disassemble(0x580));
        sti.privilegeLevel = 0; sti.run();
        CHECK(!sti.fault && sti.interruptsEnabled && sti.interruptShadow,
              "STI sets IF and records the one-instruction interrupt shadow");
        PcodeEvaluator hlt(disassemble(0x590));
        hlt.privilegeLevel = 0; hlt.run();
        CHECK(!hlt.fault && hlt.halted, "HLT enters the modeled halted state");
    }
    {
        PcodeEvaluator fromCr(disassemble(0x5A0));
        fromCr.privilegeLevel = 0; fromCr.controlRegs[0] = 0x80000011;
        fromCr.run();
        CHECK(!fromCr.fault && fromCr.regValue(RAX).value_or(0) == 0x80000011,
              "MOV from CR0 transfers modeled control state to a GPR");
        PcodeEvaluator toCr(disassemble(0x5B0));
        toCr.privilegeLevel = 0; toCr.regs[RAX] = 0x80000011;
        toCr.run();
        CHECK(!toCr.fault && toCr.controlRegs[0] == 0x80000011,
              "MOV to CR0 validates and commits architectural dependencies");

        PcodeEvaluator sgdt(disassemble(0x5C0));
        sgdt.regs[RAX] = 0x1000; sgdt.gdtr = {0x55aa, 0x1122334455667788ULL};
        sgdt.run();
        CHECK(!sgdt.fault && sgdt.ram[0x1000] == 0xaa &&
                  sgdt.ram[0x1001] == 0x55 && sgdt.ram[0x1002] == 0x88,
              "SGDT stores the 10-byte GDTR image");
        PcodeEvaluator umip(disassemble(0x5C0));
        umip.regs[RAX] = 0x1000; umip.controlRegs[4] = 1ULL << 11;
        umip.run();
        CHECK(umip.fault && umip.fault->vector ==
                  PcodeEvaluator::X86Fault::GeneralProtection,
              "CR4.UMIP makes SGDT raise #GP outside CPL0");

        PcodeEvaluator lgdt(disassemble(0x5D0));
        lgdt.privilegeLevel = 0; lgdt.regs[RAX] = 0x2000;
        const uint8_t descriptor[10] = {0x34,0x12,0x88,0x77,0x66,0x55,
                                        0x44,0x33,0x22,0x11};
        for (size_t byte = 0; byte < 10; ++byte)
            lgdt.ram[0x2000 + byte] = descriptor[byte];
        lgdt.run();
        CHECK(!lgdt.fault && lgdt.gdtr.limit == 0x1234 &&
                  lgdt.gdtr.base == 0x1122334455667788ULL,
              "LGDT restores limit and 64-bit base from memory");

        PcodeEvaluator invlpg(disassemble(0x5E0));
        invlpg.privilegeLevel = 0; invlpg.regs[RAX] = 0x3456;
        invlpg.run();
        CHECK(!invlpg.fault && invlpg.invalidatedPages.size() == 1 &&
                  invlpg.invalidatedPages[0] == 0x3000,
              "INVLPG records the invalidated linear page");
    }
    {
        PcodeEvaluator full(disassemble(0x200));
        full.regs[12416] = 0x037f; full.regs[12418] = 0;
        full.regs[12420] = 0x0000; // all eight x87 entries occupied
        full.run();
        const uint64_t fullStatus = full.regValue(12418).value_or(0);
        CHECK((fullStatus & ((1U << 0) | (1U << 6) | (1U << 9))) ==
                  ((1U << 0) | (1U << 6) | (1U << 9)) &&
                  (full.regValue(12420).value_or(0) & 3U) == 2,
              "masked x87 stack overflow sets IE/SF/C1 and pushes indefinite");

        PcodeEvaluator unmasked(disassemble(0x200));
        unmasked.regs[12416] = 0x037e; unmasked.regs[12418] = 0;
        unmasked.regs[12420] = 0x0000;
        unmasked.run();
        CHECK(!unmasked.fault &&
                  (unmasked.regValue(12418).value_or(0) &
                   ((1U << 7) | (1U << 15))) != 0 &&
                  ((unmasked.regValue(12418).value_or(0) >> 11) & 7U) == 0,
              "unmasked stack overflow is deferred and suppresses stack mutation");
        PcodeEvaluator wait(disassemble(0x4F0));
        wait.regs[12416] = unmasked.regValue(12416).value_or(0x037e);
        wait.regs[12418] = unmasked.regValue(12418).value_or(0);
        wait.run();
        CHECK(wait.fault && wait.fault->vector ==
                  PcodeEvaluator::X86Fault::X87FloatingPoint,
              "FWAIT delivers a previously deferred unmasked x87 exception");

        PcodeEvaluator empty(disassemble(0x4D0));
        empty.regs[12416] = 0x037f; empty.regs[12420] = 0xffff;
        empty.run();
        const uint64_t emptyStatus = empty.regValue(12418).value_or(0);
        CHECK((emptyStatus & ((1U << 0) | (1U << 6))) ==
                  ((1U << 0) | (1U << 6)) &&
                  (emptyStatus & (1U << 9)) == 0,
              "empty ST(0) produces masked x87 stack underflow with C1 cleared");

        PcodeEvaluator freeEntry(disassemble(0x5F0));
        freeEntry.regs[12420] = 0xfffc;
        freeEntry.run();
        CHECK((freeEntry.regValue(12420).value_or(0) & 3U) == 3,
              "FFREE marks the selected x87 tag empty without changing TOP");
    }
    {
        auto ext80 = [](long double value) {
            std::vector<uint8_t> bytes(10, 0);
            if (value == 0) return bytes;
            const bool negative = value < 0;
            value = std::fabs(value);
            int exponent = 0;
            const long double fraction = std::frexp(value, &exponent);
            const uint64_t significand = static_cast<uint64_t>(
                std::ldexp(fraction, 64));
            const uint16_t signExponent = static_cast<uint16_t>(
                (negative ? 0x8000U : 0) | (exponent - 1 + 16383));
            std::memcpy(bytes.data(), &significand, 8);
            std::memcpy(bytes.data() + 8, &signExponent, 2);
            return bytes;
        };
        auto decode80 = [](const std::vector<uint8_t>& bytes) {
            uint64_t significand = 0;
            uint16_t signExponent = 0;
            std::memcpy(&significand, bytes.data(), 8);
            std::memcpy(&signExponent, bytes.data() + 8, 2);
            long double value = std::ldexp(
                static_cast<long double>(significand),
                static_cast<int>(signExponent & 0x7fffU) - 16383 - 63);
            return (signExponent & 0x8000U) ? -value : value;
        };
        const PcodeInsn fldpi = disassemble(0x600);
        CHECK(std::any_of(fldpi.ops.begin(), fldpi.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::X87_CONSTANT;
                          }), "FLDPI uses a first-class 80-bit x87 constant");
        PcodeEvaluator pi(fldpi);
        pi.regs[12420] = 0xffff;
        pi.run();
        const auto piValue = pi.wideRegs.find(24576);
        CHECK(piValue != pi.wideRegs.end() &&
                  std::fabs(decode80(piValue->second) - std::acos(-1.0L)) < 1e-18L &&
                  (pi.regValue(12420).value_or(0) & 3U) == 0,
              "FLDPI pushes pi and classifies its tag as valid");

        PcodeEvaluator zero(disassemble(0x610));
        zero.regs[12420] = 0xfffd; // ST0 zero, remaining entries empty
        zero.wideRegs[24576] = ext80(0.0L);
        zero.run();
        const uint64_t zeroStatus = zero.regValue(12418).value_or(0);
        CHECK((zeroStatus & (1U << 14)) != 0 &&
                  (zeroStatus & ((1U << 10) | (1U << 8))) == 0,
              "FXAM classifies zero with C3:C2:C0 = 100");

        PcodeEvaluator rotateDown(disassemble(0x650));
        rotateDown.regs[12418] = 0;
        rotateDown.regs[12420] = 0x3ffc; // ST0/ST7 valid, middle empty
        rotateDown.wideRegs[24576] = ext80(1.0L);
        rotateDown.wideRegs[24576 + 7 * 16] = ext80(8.0L);
        rotateDown.run();
        CHECK(((rotateDown.regValue(12418).value_or(0) >> 11) & 7U) == 7 &&
                  std::fabs(decode80(rotateDown.wideRegs[24576]) - 8.0L) < 1e-18L,
              "FDECSTP rotates logical x87 values/tags and decrements TOP");
        PcodeEvaluator rotateUp(disassemble(0x660));
        rotateUp.regs = rotateDown.regs;
        rotateUp.wideRegs = rotateDown.wideRegs;
        rotateUp.run();
        CHECK(((rotateUp.regValue(12418).value_or(0) >> 11) & 7U) == 0 &&
                  std::fabs(decode80(rotateUp.wideRegs[24576]) - 1.0L) < 1e-18L,
              "FINCSTP reverses the logical stack rotation and increments TOP");

        PcodeEvaluator addPop(disassemble(0x680));
        addPop.regs[12416] = 0x037f; addPop.regs[12420] = 0xfff0;
        addPop.wideRegs[24576] = ext80(1.0L);
        addPop.wideRegs[24576 + 16] = ext80(2.0L);
        addPop.run();
        CHECK(std::fabs(decode80(addPop.wideRegs[24576]) - 3.0L) < 1e-18L &&
                  ((addPop.regValue(12418).value_or(0) >> 11) & 7U) == 1,
              "FADDP writes ST(i), updates its tag, and pops exactly once");

        std::vector<uint8_t> quietNan(10, 0);
        const uint64_t quietSig = 0xc000000000000001ULL;
        const uint16_t nanExponent = 0x7fff;
        std::memcpy(quietNan.data(), &quietSig, 8);
        std::memcpy(quietNan.data() + 8, &nanExponent, 2);
        PcodeEvaluator ordered(disassemble(0x690));
        ordered.regs[12416] = 0x037f; ordered.regs[12420] = 0xfffa;
        ordered.wideRegs[24576] = quietNan;
        ordered.wideRegs[24576 + 16] = ext80(1.0L);
        ordered.run();
        CHECK((ordered.regValue(12418).value_or(0) & 1U) != 0,
              "FCOMPP raises invalid-operation for a quiet NaN");
        PcodeEvaluator unordered(disassemble(0x6A0));
        unordered.regs[12416] = 0x037f; unordered.regs[12420] = 0xfffa;
        unordered.wideRegs[24576] = quietNan;
        unordered.wideRegs[24576 + 16] = ext80(1.0L);
        unordered.run();
        CHECK((unordered.regValue(12418).value_or(0) & 1U) == 0,
              "FUCOMPP accepts a quiet NaN without invalid-operation");

        for (uint64_t at : {0x620ULL, 0x630ULL, 0x640ULL, 0x670ULL,
                            0x6B0ULL, 0x6C0ULL, 0x6D0ULL}) {
            const PcodeInsn instruction = disassemble(at);
            CHECK(!instruction.ops.empty() &&
                      std::none_of(instruction.ops.begin(), instruction.ops.end(),
                                   [](const PcodeOp& operation) {
                                       return operation.op == POp::UNIMPLEMENTED;
                                   }),
                  "extended x87 long-tail encoding has executable semantics");
        }
    }
    {
        PcodeEvaluator swap(disassemble(0x700));
        swap.regs[RAX] = 0x0123456789abcdefULL;
        swap.run();
        CHECK(swap.regValue(RAX).value_or(0) == 0xefcdab8967452301ULL,
              "64-bit BSWAP reverses all eight bytes including REX.W forms");

        PcodeInsn average = disassemble(0x710);
        CHECK(std::any_of(average.ops.begin(), average.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::SIMD_AVERAGE;
                          }), "PAVGB lowers to unsigned rounded lane averages");
        PcodeEvaluator avg(average);
        avg.wideRegs[0].assign(16, 0);
        avg.wideRegs[8].assign(16, 0);
        avg.wideRegs[0][0] = 2; avg.wideRegs[8][0] = 5;
        avg.wideRegs[0][1] = 255; avg.wideRegs[8][1] = 254;
        avg.run();
        const auto avgResult = avg.wideValue(average.named.at("dst"));
        CHECK(avgResult && (*avgResult)[0] == 4 && (*avgResult)[1] == 255,
              "PAVGB computes (a+b+1)/2 without byte overflow");

        PcodeInsn maximum = disassemble(0x720);
        PcodeEvaluator max(maximum);
        max.wideRegs[0].assign(16, 0); max.wideRegs[8].assign(16, 0);
        max.wideRegs[0][0] = 250; max.wideRegs[8][0] = 7;
        max.run();
        const auto maxResult = max.wideValue(maximum.named.at("dst"));
        CHECK(maxResult && (*maxResult)[0] == 250,
              "PMAXUB performs unsigned byte comparison");

        PcodeInsn minimum = disassemble(0x730);
        PcodeEvaluator min(minimum);
        min.wideRegs[0].assign(16, 0); min.wideRegs[8].assign(16, 0);
        const int16_t negative = -5, positive = 2;
        std::memcpy(min.wideRegs[0].data(), &negative, 2);
        std::memcpy(min.wideRegs[8].data(), &positive, 2);
        min.run();
        const auto minResult = min.wideValue(minimum.named.at("dst"));
        int16_t minLane = 0;
        if (minResult) std::memcpy(&minLane, minResult->data(), 2);
        CHECK(minResult && minLane == -5,
              "PMINSW performs signed word comparison");

        PcodeInsn sad = disassemble(0x740);
        PcodeEvaluator sadEv(sad);
        sadEv.wideRegs[0].assign(16, 10);
        sadEv.wideRegs[8].assign(16, 3);
        sadEv.run();
        const auto sadResult = sadEv.wideValue(sad.named.at("dst"));
        uint64_t sadLow = 0, sadHigh = 0;
        if (sadResult) {
            std::memcpy(&sadLow, sadResult->data(), 8);
            std::memcpy(&sadHigh, sadResult->data() + 8, 8);
        }
        CHECK(sadResult && sadLow == 56 && sadHigh == 56,
              "PSADBW produces two independent eight-byte absolute sums");

        PcodeInsn xorVector = disassemble(0x750);
        CHECK(std::any_of(xorVector.ops.begin(), xorVector.ops.end(),
                          [](const PcodeOp& operation) {
                              return operation.op == POp::INT_XOR;
                          }), "EVEX VPXORD has full-width shared bitwise semantics");

        const uint16_t one = 1;
        PcodeInsn immediateShift = disassemble(0x760);
        PcodeEvaluator immediateShiftEv(immediateShift);
        immediateShiftEv.wideRegs[0].assign(16, 0);
        std::memcpy(immediateShiftEv.wideRegs[0].data(), &one, 2);
        immediateShiftEv.run();
        uint16_t shiftedWord = 0;
        std::memcpy(&shiftedWord, immediateShiftEv.wideRegs[0].data(), 2);
        CHECK(shiftedWord == 8,
              "PSLLW immediate shifts each word lane independently");

        PcodeInsn variableShift = disassemble(0x770);
        PcodeEvaluator variableShiftEv(variableShift);
        variableShiftEv.wideRegs[0].assign(16, 0);
        variableShiftEv.wideRegs[8].assign(16, 0);
        std::memcpy(variableShiftEv.wideRegs[0].data(), &one, 2);
        const uint64_t variableCount = 4;
        std::memcpy(variableShiftEv.wideRegs[8].data(), &variableCount, 8);
        variableShiftEv.run();
        shiftedWord = 0;
        std::memcpy(&shiftedWord, variableShiftEv.wideRegs[0].data(), 2);
        CHECK(shiftedWord == 16,
              "PSLLW variable form takes its count from the low 64 bits");

        PcodeEvaluator portRead(disassemble(0x780));
        portRead.privilegeLevel = 0;
        portRead.regs[16] = 0x3f8;
        portRead.ioPorts[0x3f8] = 0xa5;
        portRead.run();
        CHECK((portRead.regValue(RAX).value_or(0) & 0xffU) == 0xa5,
              "IN reads the selected DX port into AL");

        PcodeEvaluator portWrite(disassemble(0x790));
        portWrite.privilegeLevel = 0;
        portWrite.regs[16] = 0x3f8;
        portWrite.regs[RAX] = 0x5a;
        portWrite.run();
        CHECK(portWrite.ioPorts[0x3f8] == 0x5a,
              "OUT writes AL to the selected DX port");

        PcodeEvaluator deniedPort(disassemble(0x780));
        deniedPort.privilegeLevel = 3;
        deniedPort.iopl = 0;
        deniedPort.run();
        CHECK(deniedPort.fault && deniedPort.fault->vector ==
                  PcodeEvaluator::X86Fault::GeneralProtection,
              "port I/O checks CPL against IOPL before changing state");

        PcodeEvaluator movdToXmm(disassemble(0x7A0));
        movdToXmm.regs[RBX] = 0x1122334455667788ULL;
        movdToXmm.run();
        const auto xmm0 = movdToXmm.wideRegs.find(0);
        uint64_t movdLow = 0, movdHigh = ~0ULL;
        if (xmm0 != movdToXmm.wideRegs.end() && xmm0->second.size() >= 16) {
            std::memcpy(&movdLow, xmm0->second.data(), 8);
            std::memcpy(&movdHigh, xmm0->second.data() + 8, 8);
        }
        CHECK(xmm0 != movdToXmm.wideRegs.end() &&
                  movdLow == 0x55667788ULL && movdHigh == 0,
              "MOVD GPR-to-XMM copies 32 bits and zeroes upper 96 bits");

        PcodeEvaluator movdToGpr(disassemble(0x7B0));
        movdToGpr.wideRegs[0].assign(16, 0xff);
        const uint32_t dword = 0xa1b2c3d4U;
        std::memcpy(movdToGpr.wideRegs[0].data(), &dword, 4);
        movdToGpr.run();
        CHECK(movdToGpr.regValue(RBX).value_or(0) == dword,
              "MOVD XMM-to-GPR extracts the low dword and zero-extends it");

        PcodeEvaluator clearDirection(disassemble(0x7C0));
        clearDirection.regs[DF] = 1;
        clearDirection.run();
        CHECK(clearDirection.regValue(DF).value_or(1) == 0,
              "CLD clears the direction flag");
        PcodeEvaluator setDirection(disassemble(0x7C8));
        setDirection.regs[DF] = 0;
        setDirection.run();
        CHECK(setDirection.regValue(DF).value_or(0) == 1,
              "STD sets the direction flag");

        PcodeEvaluator moveString(disassemble(0x7D0));
        moveString.regs[RCX] = 3;
        moveString.regs[RSI] = 0x1000;
        moveString.regs[RDI] = 0x2000;
        moveString.regs[DF] = 0;
        moveString.ram[0x1000] = 0x11;
        moveString.ram[0x1001] = 0x22;
        moveString.ram[0x1002] = 0x33;
        moveString.run();
        CHECK(moveString.ram[0x2000] == 0x11 &&
                  moveString.ram[0x2001] == 0x22 &&
                  moveString.ram[0x2002] == 0x33 &&
                  moveString.regValue(RCX).value_or(1) == 0 &&
                  moveString.regValue(RSI).value_or(0) == 0x1003 &&
                  moveString.regValue(RDI).value_or(0) == 0x2003,
              "REP MOVSB copies RCX bytes and advances both indices");

        PcodeEvaluator scanString(disassemble(0x7E0));
        scanString.regs[RAX] = 3;
        scanString.regs[RCX] = 5;
        scanString.regs[RDI] = 0x3000;
        scanString.regs[DF] = 0;
        scanString.ram[0x3000] = 1;
        scanString.ram[0x3001] = 2;
        scanString.ram[0x3002] = 3;
        scanString.run();
        CHECK(scanString.regValue(RCX).value_or(0) == 2 &&
                  scanString.regValue(RDI).value_or(0) == 0x3003 &&
                  scanString.regValue(ZF).value_or(0) == 1,
              "REPNE SCASB stops on the first equal element");

        PcodeEvaluator compareString(disassemble(0x7F0));
        compareString.regs[RCX] = 4;
        compareString.regs[RSI] = 0x4000;
        compareString.regs[RDI] = 0x5000;
        compareString.regs[DF] = 0;
        compareString.ram[0x4000] = 7; compareString.ram[0x5000] = 7;
        compareString.ram[0x4001] = 8; compareString.ram[0x5001] = 8;
        compareString.ram[0x4002] = 9; compareString.ram[0x5002] = 1;
        compareString.run();
        CHECK(compareString.regValue(RCX).value_or(0) == 1 &&
                  compareString.regValue(RSI).value_or(0) == 0x4003 &&
                  compareString.regValue(RDI).value_or(0) == 0x5003 &&
                  compareString.regValue(ZF).value_or(1) == 0,
              "REPE CMPSB stops after the first unequal comparison");

        PcodeEvaluator movqToXmm(disassemble(0x800));
        movqToXmm.regs[RBX] = 0x8877665544332211ULL;
        movqToXmm.run();
        uint64_t movqLow = 0, movqHigh = ~0ULL;
        const auto movqXmm0 = movqToXmm.wideRegs.find(0);
        if (movqXmm0 != movqToXmm.wideRegs.end() &&
            movqXmm0->second.size() >= 16) {
            std::memcpy(&movqLow, movqXmm0->second.data(), 8);
            std::memcpy(&movqHigh, movqXmm0->second.data() + 8, 8);
        }
        CHECK(movqLow == 0x8877665544332211ULL && movqHigh == 0,
              "MOVQ GPR-to-XMM copies 64 bits and zeroes the upper qword");

        PcodeEvaluator movqToGpr(disassemble(0x810));
        movqToGpr.wideRegs[0].assign(16, 0xee);
        const uint64_t qword = 0x0123456789abcdefULL;
        std::memcpy(movqToGpr.wideRegs[0].data(), &qword, 8);
        movqToGpr.run();
        CHECK(movqToGpr.regValue(RBX).value_or(0) == qword,
              "MOVQ XMM-to-GPR extracts the complete low qword");

        PcodeEvaluator movqXmmToXmm(disassemble(0x820));
        movqXmmToXmm.wideRegs[0].assign(16, 0xaa);
        std::memcpy(movqXmmToXmm.wideRegs[0].data(), &qword, 8);
        movqXmmToXmm.run();
        uint64_t copiedLow = 0, copiedHigh = ~0ULL;
        const auto movqXmm1 = movqXmmToXmm.wideRegs.find(8);
        if (movqXmm1 != movqXmmToXmm.wideRegs.end() &&
            movqXmm1->second.size() >= 16) {
            std::memcpy(&copiedLow, movqXmm1->second.data(), 8);
            std::memcpy(&copiedHigh, movqXmm1->second.data() + 8, 8);
        }
        CHECK(copiedLow == qword && copiedHigh == 0,
              "legacy MOVQ XMM-to-XMM uses ModRM direction and clears high bits");

        PcodeEvaluator movssLoad(disassemble(0x830));
        movssLoad.wideRegs[0].assign(16, 0xaa);
        movssLoad.wideRegs[8].assign(16, 0xbb);
        const uint32_t scalar = 0x3f800000U;
        std::memcpy(movssLoad.wideRegs[8].data(), &scalar, 4);
        movssLoad.run();
        uint32_t scalarResult = 0;
        std::memcpy(&scalarResult, movssLoad.wideRegs[0].data(), 4);
        CHECK(scalarResult == scalar && movssLoad.wideRegs[0][4] == 0xaa,
              "MOVSS load replaces the low dword and preserves upper lanes");

        PcodeEvaluator movssStore(disassemble(0x840));
        movssStore.wideRegs[0].assign(16, 0xcc);
        movssStore.wideRegs[8].assign(16, 0xdd);
        std::memcpy(movssStore.wideRegs[0].data(), &scalar, 4);
        movssStore.run();
        scalarResult = 0;
        std::memcpy(&scalarResult, movssStore.wideRegs[8].data(), 4);
        CHECK(scalarResult == scalar && movssStore.wideRegs[8][4] == 0xdd,
              "MOVSS store encoding follows ModRM direction and preserves destination");

        PcodeEvaluator moveMask(disassemble(0x850));
        moveMask.wideRegs[8].assign(16, 0);
        moveMask.wideRegs[8][0] = 0x80;
        moveMask.wideRegs[8][3] = 0xff;
        moveMask.wideRegs[8][15] = 0x80;
        moveMask.run();
        CHECK(moveMask.regValue(RAX).value_or(0) == 0x8009,
              "PMOVMSKB packs every byte sign bit into the destination mask");

        PcodeEvaluator extractWordLegacy(disassemble(0x860));
        extractWordLegacy.wideRegs[8].assign(16, 0);
        const uint16_t word2 = 0xbeef;
        std::memcpy(extractWordLegacy.wideRegs[8].data() + 4, &word2, 2);
        extractWordLegacy.run();
        CHECK(extractWordLegacy.regValue(RAX).value_or(0) == word2,
              "legacy PEXTRW extracts and zero-extends the selected word");

        PcodeEvaluator extractWordSse41(disassemble(0x870));
        extractWordSse41.wideRegs[8].assign(16, 0);
        const uint16_t word3 = 0x1234;
        std::memcpy(extractWordSse41.wideRegs[8].data() + 6, &word3, 2);
        extractWordSse41.run();
        CHECK(extractWordSse41.regValue(RAX).value_or(0) == word3,
              "SSE4.1 PEXTRW follows the corrected ModRM source direction");

        PcodeEvaluator crc32(disassemble(0x880));
        crc32.regs[RAX] = 0;
        crc32.regs[RBX] = 1;
        crc32.run();
        CHECK(crc32.regValue(RAX).value_or(0) == 0xf26b8303U,
              "CRC32 byte form uses the reflected Castagnoli polynomial");

        PcodeEvaluator signedDivide(disassemble(0x890));
        signedDivide.regs[RAX] = 10;
        signedDivide.regs[16] = 0;
        signedDivide.regs[RBX] = 3;
        signedDivide.run();
        CHECK(!signedDivide.fault &&
                  signedDivide.regValue(RAX).value_or(0) == 3 &&
                  signedDivide.regValue(16).value_or(0) == 1,
              "64-bit IDIV writes the signed quotient and remainder");

        PcodeEvaluator byteDivide(disassemble(0x8A0));
        byteDivide.regs[RAX] = 0xfff9; // AX=-7
        byteDivide.regs[RBX] = 2;
        byteDivide.run();
        CHECK(!byteDivide.fault &&
                  (byteDivide.regValue(RAX).value_or(0) & 0xffffU) == 0xfffdU,
              "byte IDIV places quotient in AL and signed remainder in AH");

        PcodeEvaluator divideByZero(disassemble(0x890));
        divideByZero.regs[RAX] = 10;
        divideByZero.regs[16] = 0;
        divideByZero.regs[RBX] = 0;
        divideByZero.run();
        CHECK(divideByZero.fault && divideByZero.fault->vector ==
                  PcodeEvaluator::X86Fault::DivideError &&
                  divideByZero.regValue(RAX).value_or(0) == 10,
              "IDIV divide-by-zero raises #DE before modifying registers");

        PcodeEvaluator packedAnd(disassemble(0x8B0));
        packedAnd.wideRegs[0].assign(16, 0xf0);
        packedAnd.wideRegs[8].assign(16, 0x5a);
        packedAnd.run();
        CHECK(packedAnd.wideRegs[0][0] == 0x50 &&
                  packedAnd.wideRegs[0][15] == 0x50,
              "ANDPS performs full-width bitwise AND without FP conversion");

        PcodeEvaluator packedAndNot(disassemble(0x8C0));
        packedAndNot.wideRegs[0].assign(16, 0xf0);
        packedAndNot.wideRegs[8].assign(16, 0x5a);
        packedAndNot.run();
        CHECK(packedAndNot.wideRegs[0][0] == 0x0a &&
                  packedAndNot.wideRegs[0][15] == 0x0a,
              "ANDNPS complements the first operand before bitwise AND");

        PcodeEvaluator addSubtract(disassemble(0x8D0));
        addSubtract.wideRegs[0].resize(16);
        addSubtract.wideRegs[8].resize(16);
        const float addsubLeft[4] = {10, 10, 10, 10};
        const float addsubRight[4] = {1, 2, 3, 4};
        std::memcpy(addSubtract.wideRegs[0].data(), addsubLeft, 16);
        std::memcpy(addSubtract.wideRegs[8].data(), addsubRight, 16);
        addSubtract.run();
        float addsubResult[4] = {};
        std::memcpy(addsubResult, addSubtract.wideRegs[0].data(), 16);
        CHECK(addsubResult[0] == 9 && addsubResult[1] == 12 &&
                  addsubResult[2] == 7 && addsubResult[3] == 14,
              "ADDSUBPS subtracts even lanes and adds odd lanes");

        PcodeEvaluator blend(disassemble(0x8E0));
        blend.wideRegs[0].resize(16);
        blend.wideRegs[8].resize(16);
        const uint32_t blendLeft[4] = {1, 2, 3, 4};
        const uint32_t blendRight[4] = {10, 20, 30, 40};
        std::memcpy(blend.wideRegs[0].data(), blendLeft, 16);
        std::memcpy(blend.wideRegs[8].data(), blendRight, 16);
        blend.run();
        uint32_t blendResult[4] = {};
        std::memcpy(blendResult, blend.wideRegs[0].data(), 16);
        CHECK(blendResult[0] == 1 && blendResult[1] == 20 &&
                  blendResult[2] == 3 && blendResult[3] == 40,
              "BLENDPS selects source lanes using immediate mask bits");

        PcodeEvaluator comparePacked(disassemble(0x8F0));
        comparePacked.wideRegs[0].resize(16);
        comparePacked.wideRegs[8].resize(16);
        const float quietNan = std::numeric_limits<float>::quiet_NaN();
        const float compareLeft[4] = {1, 3, quietNan, 5};
        const float compareRight[4] = {2, 2, 0, quietNan};
        std::memcpy(comparePacked.wideRegs[0].data(), compareLeft, 16);
        std::memcpy(comparePacked.wideRegs[8].data(), compareRight, 16);
        comparePacked.run();
        uint32_t compareResult[4] = {};
        std::memcpy(compareResult, comparePacked.wideRegs[0].data(), 16);
        CHECK(compareResult[0] == 0xffffffffU && compareResult[1] == 0 &&
                  compareResult[2] == 0 && compareResult[3] == 0,
              "CMPPS ordered-less handles normal and unordered lanes");

        PcodeEvaluator orderedCompare(disassemble(0x900));
        orderedCompare.wideRegs[0].resize(16);
        orderedCompare.wideRegs[8].resize(16);
        std::memcpy(orderedCompare.wideRegs[0].data(), &quietNan, 4);
        const float oneFloat = 1.0f;
        std::memcpy(orderedCompare.wideRegs[8].data(), &oneFloat, 4);
        orderedCompare.run();
        CHECK((orderedCompare.mxcsr & 1U) != 0 && !orderedCompare.fault,
              "COMISS reports invalid-operation for a quiet NaN when masked");

        PcodeEvaluator quietCompare(disassemble(0x910));
        quietCompare.wideRegs = orderedCompare.wideRegs;
        quietCompare.run();
        CHECK((quietCompare.mxcsr & 1U) == 0,
              "UCOMISS accepts quiet NaN without setting MXCSR invalid");

        PcodeEvaluator unmaskedCompare(disassemble(0x900));
        unmaskedCompare.mxcsr = 0;
        unmaskedCompare.wideRegs = orderedCompare.wideRegs;
        unmaskedCompare.regs[ZF] = 0;
        unmaskedCompare.run();
        CHECK(unmaskedCompare.fault && unmaskedCompare.fault->vector ==
                  PcodeEvaluator::X86Fault::SimdFloatingPoint &&
                  unmaskedCompare.regValue(ZF).value_or(0) == 0,
              "unmasked COMISS invalid-operation raises #XM before flag writes");

        PcodeEvaluator horizontalAdd(disassemble(0x920));
        horizontalAdd.wideRegs[0].resize(16);
        horizontalAdd.wideRegs[8].resize(16);
        const float horizontalLeft[4] = {1, 2, 3, 4};
        const float horizontalRight[4] = {10, 20, 30, 40};
        std::memcpy(horizontalAdd.wideRegs[0].data(), horizontalLeft, 16);
        std::memcpy(horizontalAdd.wideRegs[8].data(), horizontalRight, 16);
        horizontalAdd.run();
        float horizontalResult[4] = {};
        std::memcpy(horizontalResult, horizontalAdd.wideRegs[0].data(), 16);
        CHECK(horizontalResult[0] == 3 && horizontalResult[1] == 7 &&
                  horizontalResult[2] == 30 && horizontalResult[3] == 70,
              "HADDPS reduces adjacent pairs from both source operands");

        PcodeEvaluator unsignedDivide(disassemble(0x930));
        unsignedDivide.regs[RAX] = 10;
        unsignedDivide.regs[16] = 0;
        unsignedDivide.regs[RBX] = 3;
        unsignedDivide.run();
        CHECK(!unsignedDivide.fault &&
                  unsignedDivide.regValue(RAX).value_or(0) == 3 &&
                  unsignedDivide.regValue(16).value_or(0) == 1,
              "64-bit DIV writes unsigned quotient and remainder");

        PcodeEvaluator overflowingDivide(disassemble(0x930));
        overflowingDivide.regs[RAX] = 0;
        overflowingDivide.regs[16] = 3;
        overflowingDivide.regs[RBX] = 3;
        overflowingDivide.run();
        CHECK(overflowingDivide.fault && overflowingDivide.fault->vector ==
                  PcodeEvaluator::X86Fault::DivideError &&
                  overflowingDivide.regValue(RAX).value_or(1) == 0,
              "DIV quotient overflow raises #DE without partial writes");

        PcodeEvaluator extractScalar(disassemble(0x940));
        extractScalar.wideRegs[8].assign(16, 0);
        const uint32_t scalarBits = 0xdeadbeefU;
        std::memcpy(extractScalar.wideRegs[8].data() + 8, &scalarBits, 4);
        extractScalar.run();
        CHECK(extractScalar.regValue(RAX).value_or(0) == scalarBits,
              "EXTRACTPS uses corrected ModRM direction and selected lane");

        PcodeEvaluator intToPackedFloat(disassemble(0x950));
        intToPackedFloat.wideRegs[8].resize(16);
        const int32_t integerLanes[4] = {1, -2, 16777216, -123456};
        std::memcpy(intToPackedFloat.wideRegs[8].data(), integerLanes, 16);
        intToPackedFloat.run();
        float convertedFloats[4] = {};
        std::memcpy(convertedFloats, intToPackedFloat.wideRegs[0].data(), 16);
        CHECK(convertedFloats[0] == 1.0f && convertedFloats[1] == -2.0f &&
                  convertedFloats[2] == 16777216.0f &&
                  convertedFloats[3] == -123456.0f,
              "CVTDQ2PS converts four signed dwords independently");

        PcodeEvaluator packedDoubleToInt(disassemble(0x960));
        packedDoubleToInt.wideRegs[8].resize(16);
        const double doubleLanes[2] = {2.5, -3.5};
        std::memcpy(packedDoubleToInt.wideRegs[8].data(), doubleLanes, 16);
        packedDoubleToInt.run();
        int32_t roundedIntegers[4] = {};
        std::memcpy(roundedIntegers, packedDoubleToInt.wideRegs[0].data(), 16);
        CHECK(roundedIntegers[0] == 2 && roundedIntegers[1] == -4 &&
                  roundedIntegers[2] == 0 && roundedIntegers[3] == 0,
              "CVTPD2DQ applies MXCSR round-to-nearest-even and clears upper lanes");

        PcodeEvaluator packedTruncate(disassemble(0x970));
        packedTruncate.wideRegs[8].resize(16);
        const float truncationLanes[4] = {
            1.9f, -2.9f, std::numeric_limits<float>::quiet_NaN(),
            std::numeric_limits<float>::infinity()};
        std::memcpy(packedTruncate.wideRegs[8].data(), truncationLanes, 16);
        packedTruncate.run();
        int32_t truncatedIntegers[4] = {};
        std::memcpy(truncatedIntegers, packedTruncate.wideRegs[0].data(), 16);
        CHECK(truncatedIntegers[0] == 1 && truncatedIntegers[1] == -2 &&
                  static_cast<uint32_t>(truncatedIntegers[2]) == 0x80000000U &&
                  static_cast<uint32_t>(truncatedIntegers[3]) == 0x80000000U &&
                  (packedTruncate.mxcsr & 1U) != 0,
              "CVTTPS2DQ truncates finite lanes and returns integer-indefinite for NaN/overflow");

        PcodeEvaluator widenPackedFloat(disassemble(0x980));
        widenPackedFloat.wideRegs[8].resize(16);
        const float narrowLanes[4] = {1.25f, -2.5f, 99.0f, 100.0f};
        std::memcpy(widenPackedFloat.wideRegs[8].data(), narrowLanes, 16);
        widenPackedFloat.run();
        double widenedLanes[2] = {};
        std::memcpy(widenedLanes, widenPackedFloat.wideRegs[0].data(), 16);
        CHECK(widenedLanes[0] == 1.25 && widenedLanes[1] == -2.5,
              "CVTPS2PD widens only the two low single-precision lanes");

        PcodeEvaluator packedDot(disassemble(0x9A0));
        packedDot.wideRegs[0].resize(16);
        packedDot.wideRegs[8].resize(16);
        const float dotLeft[4] = {1, 2, 3, 4};
        const float dotRight[4] = {10, 20, 30, 40};
        std::memcpy(packedDot.wideRegs[0].data(), dotLeft, 16);
        std::memcpy(packedDot.wideRegs[8].data(), dotRight, 16);
        packedDot.run();
        float dotResult[4] = {};
        std::memcpy(dotResult, packedDot.wideRegs[0].data(), 16);
        CHECK(dotResult[0] == 300 && dotResult[1] == 0 &&
                  dotResult[2] == 0 && dotResult[3] == 0,
              "DPPS source and destination masks independently select products and result lanes");

        PcodeEvaluator packedDoubleDot(disassemble(0x9B0));
        packedDoubleDot.wideRegs[0].resize(16);
        packedDoubleDot.wideRegs[8].resize(16);
        const double dotDoubleLeft[2] = {2, 3};
        const double dotDoubleRight[2] = {5, 7};
        std::memcpy(packedDoubleDot.wideRegs[0].data(), dotDoubleLeft, 16);
        std::memcpy(packedDoubleDot.wideRegs[8].data(), dotDoubleRight, 16);
        packedDoubleDot.run();
        double dotDoubleResult[2] = {};
        std::memcpy(dotDoubleResult, packedDoubleDot.wideRegs[0].data(), 16);
        CHECK(dotDoubleResult[0] == 31 && dotDoubleResult[1] == 31,
              "DPPD broadcasts the selected two-lane dot product according to imm8");

        PcodeEvaluator packedAbsolute(disassemble(0x9C0));
        packedAbsolute.wideRegs[8].resize(16);
        const int8_t signedBytes[16] = {
            -1, -2, 3, -128, 5, -6, 7, -8,
            9, -10, 11, -12, 13, -14, 15, -16};
        std::memcpy(packedAbsolute.wideRegs[8].data(), signedBytes, 16);
        packedAbsolute.run();
        CHECK(packedAbsolute.wideRegs[0][0] == 1 &&
                  packedAbsolute.wideRegs[0][1] == 2 &&
                  packedAbsolute.wideRegs[0][2] == 3 &&
                  packedAbsolute.wideRegs[0][3] == 0x80,
              "PABSB computes two's-complement absolute values including INT8_MIN");

        PcodeEvaluator blendWords(disassemble(0x9D0));
        blendWords.wideRegs[0].resize(16);
        blendWords.wideRegs[8].resize(16);
        const uint16_t oldWords[8] = {0, 1, 2, 3, 4, 5, 6, 7};
        const uint16_t newWords[8] = {10, 11, 12, 13, 14, 15, 16, 17};
        std::memcpy(blendWords.wideRegs[0].data(), oldWords, 16);
        std::memcpy(blendWords.wideRegs[8].data(), newWords, 16);
        blendWords.run();
        uint16_t blendedWords[8] = {};
        std::memcpy(blendedWords, blendWords.wideRegs[0].data(), 16);
        CHECK(blendedWords[0] == 0 && blendedWords[1] == 11 &&
                  blendedWords[6] == 6 && blendedWords[7] == 17,
              "PBLENDW selects all eight word lanes from imm8");

        PcodeEvaluator alignBytes(disassemble(0x9E0));
        alignBytes.wideRegs[0].resize(16);
        alignBytes.wideRegs[8].resize(16);
        for (uint8_t index = 0; index < 16; ++index) {
            alignBytes.wideRegs[0][index] = static_cast<uint8_t>(0x80 + index);
            alignBytes.wideRegs[8][index] = index;
        }
        alignBytes.run();
        CHECK(alignBytes.wideRegs[0][0] == 8 &&
                  alignBytes.wideRegs[0][7] == 15 &&
                  alignBytes.wideRegs[0][8] == 0x80 &&
                  alignBytes.wideRegs[0][15] == 0x87,
              "PALIGNR extracts a byte window from the concatenated source/destination pair");

        PcodeEvaluator duplicateLowSingles(disassemble(0x9F0));
        duplicateLowSingles.wideRegs[8].resize(16);
        const uint32_t duplicateInput[4] = {1, 2, 3, 4};
        std::memcpy(duplicateLowSingles.wideRegs[8].data(), duplicateInput, 16);
        duplicateLowSingles.run();
        uint32_t duplicateOutput[4] = {};
        std::memcpy(duplicateOutput, duplicateLowSingles.wideRegs[0].data(), 16);
        CHECK(duplicateOutput[0] == 1 && duplicateOutput[1] == 1 &&
                  duplicateOutput[2] == 3 && duplicateOutput[3] == 3,
              "MOVSLDUP duplicates even single-precision lanes within each block");

        PcodeEvaluator duplicateDouble(disassemble(0xA10));
        duplicateDouble.wideRegs[8].resize(16);
        const uint64_t duplicateQwords[2] = {0x1122334455667788ULL,
                                             0x99aabbccddeeff00ULL};
        std::memcpy(duplicateDouble.wideRegs[8].data(), duplicateQwords, 16);
        duplicateDouble.run();
        uint64_t duplicatedQwords[2] = {};
        std::memcpy(duplicatedQwords, duplicateDouble.wideRegs[0].data(), 16);
        CHECK(duplicatedQwords[0] == duplicateQwords[0] &&
                  duplicatedQwords[1] == duplicateQwords[0],
              "MOVDDUP duplicates the low double-precision lane");

        PcodeEvaluator mmxMove(disassemble(0xA20));
        mmxMove.regs[16384 + 8] = 0x0123456789abcdefULL;
        mmxMove.wideRegs[8].assign(16, 0xaa);
        mmxMove.run();
        CHECK(mmxMove.regValue(16384).value_or(0) == 0x0123456789abcdefULL &&
                  mmxMove.wideRegs[8][0] == 0xaa,
              "unprefixed MOVQ uses independent MMX registers without aliasing XMM state");

        PcodeEvaluator mmxStore(disassemble(0xA50));
        mmxStore.regs[16384] = 0x8877665544332211ULL;
        mmxStore.regs[RAX] = 0x6000;
        mmxStore.run();
        uint64_t storedMmx = 0;
        for (unsigned byte = 0; byte < 8; ++byte)
            storedMmx |= static_cast<uint64_t>(mmxStore.ram[0x6000 + byte])
                         << (byte * 8);
        CHECK(storedMmx == 0x8877665544332211ULL,
              "MOVQ stores exactly one MMX qword to memory");

        PcodeEvaluator mmxLoad(disassemble(0xA40));
        mmxLoad.regs[RAX] = 0x6100;
        for (unsigned byte = 0; byte < 8; ++byte)
            mmxLoad.ram[0x6100 + byte] = static_cast<uint8_t>(0x10 + byte);
        mmxLoad.run();
        CHECK(mmxLoad.regValue(16384).value_or(0) == 0x1716151413121110ULL,
              "MOVQ loads a memory qword into the independent MMX bank");

        PcodeEvaluator extractByte(disassemble(0xA60));
        extractByte.wideRegs[8].resize(16);
        for (uint8_t lane = 0; lane < 16; ++lane)
            extractByte.wideRegs[8][lane] = lane;
        extractByte.run();
        CHECK(extractByte.regValue(RBX).value_or(0) == 15,
              "PEXTRB masks imm8 to the available sixteen byte lanes");

        PcodeEvaluator extractDword(disassemble(0xA70));
        extractDword.wideRegs[8].resize(16);
        const uint32_t extractionDwords[4] = {1, 2, 0xdeadbeefU, 4};
        std::memcpy(extractDword.wideRegs[8].data(), extractionDwords, 16);
        extractDword.run();
        CHECK(extractDword.regValue(RBX).value_or(0) == 0xdeadbeefU,
              "PEXTRD follows reg-source/rm-destination ModRM direction");

        PcodeEvaluator extractQword(disassemble(0xA80));
        extractQword.wideRegs[8].resize(16);
        const uint64_t extractionQwords[2] = {1, 0xfedcba9876543210ULL};
        std::memcpy(extractQword.wideRegs[8].data(), extractionQwords, 16);
        extractQword.run();
        CHECK(extractQword.regValue(RBX).value_or(0) == extractionQwords[1],
              "PEXTRQ uses REX.W and masks the immediate to one bit");

        PcodeEvaluator insertByte(disassemble(0xA90));
        insertByte.wideRegs[0].assign(16, 0);
        insertByte.regs[RBX] = 0xab;
        insertByte.run();
        CHECK(insertByte.wideRegs[0][2] == 0xab,
              "PINSRB inserts the low source byte at the masked lane index");

        PcodeEvaluator insertQword(disassemble(0xAC0));
        insertQword.wideRegs[0].assign(16, 0);
        insertQword.regs[RBX] = 0x1122334455667788ULL;
        insertQword.run();
        uint64_t insertedQword = 0;
        std::memcpy(&insertedQword, insertQword.wideRegs[0].data() + 8, 8);
        CHECK(insertedQword == 0x1122334455667788ULL,
              "PINSRQ uses the full 64-bit GPR source and masked lane index");

        PcodeEvaluator insertWord(disassemble(0xAA0));
        insertWord.wideRegs[0].assign(16, 0);
        insertWord.regs[RBX] = 0xbeef;
        insertWord.run();
        uint16_t insertedWord = 0;
        std::memcpy(&insertedWord, insertWord.wideRegs[0].data() + 2, 2);
        CHECK(insertedWord == 0xbeef,
              "PINSRW masks its immediate to the eight available word lanes");

        PcodeEvaluator insertDwordLegacy(disassemble(0xAB0));
        insertDwordLegacy.wideRegs[0].assign(16, 0);
        insertDwordLegacy.regs[RBX] = 0xcafebabeU;
        insertDwordLegacy.run();
        uint32_t insertedDword = 0;
        std::memcpy(&insertedDword,
                    insertDwordLegacy.wideRegs[0].data() + 12, 4);
        CHECK(insertedDword == 0xcafebabeU,
              "PINSRD inserts into one of four dword lanes");

        PcodeEvaluator vexExtract(disassemble(0xAD0));
        vexExtract.wideRegs[8].resize(16);
        std::memcpy(vexExtract.wideRegs[8].data(), extractionQwords, 16);
        vexExtract.run();
        CHECK(vexExtract.regValue(RBX).value_or(0) == extractionQwords[1],
              "VPEXTRQ decodes VEX.W and writes the r/m GPR destination");

        PcodeEvaluator vexInsert(disassemble(0xAE0));
        vexInsert.wideRegs[8].assign(16, 0x11);
        vexInsert.regs[RBX] = 0xaabbccddU;
        vexInsert.run();
        insertedDword = 0;
        std::memcpy(&insertedDword, vexInsert.wideRegs[0].data() + 8, 4);
        CHECK(insertedDword == 0xaabbccddU && vexInsert.wideRegs[0][0] == 0x11,
              "VPINSRD takes its preserved lanes from the VEX.vvvv source");

        PcodeEvaluator horizontalWords(disassemble(0xAF0));
        horizontalWords.wideRegs[0].resize(16);
        horizontalWords.wideRegs[8].resize(16);
        const int16_t horizontalWordLeft[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        const int16_t horizontalWordRight[8] = {10, 20, 30, 40, 50, 60, 70, 80};
        std::memcpy(horizontalWords.wideRegs[0].data(), horizontalWordLeft, 16);
        std::memcpy(horizontalWords.wideRegs[8].data(), horizontalWordRight, 16);
        horizontalWords.run();
        int16_t horizontalWordResult[8] = {};
        std::memcpy(horizontalWordResult, horizontalWords.wideRegs[0].data(), 16);
        CHECK(horizontalWordResult[0] == 3 && horizontalWordResult[3] == 15 &&
                  horizontalWordResult[4] == 30 && horizontalWordResult[7] == 150,
              "PHADDW performs pairwise wrapping sums from both operands");

        PcodeEvaluator horizontalDwordSubtract(disassemble(0xB00));
        horizontalDwordSubtract.wideRegs[0].resize(16);
        horizontalDwordSubtract.wideRegs[8].resize(16);
        const int32_t subtractLeft[4] = {10, 3, -5, 7};
        const int32_t subtractRight[4] = {100, 40, -20, -30};
        std::memcpy(horizontalDwordSubtract.wideRegs[0].data(), subtractLeft, 16);
        std::memcpy(horizontalDwordSubtract.wideRegs[8].data(), subtractRight, 16);
        horizontalDwordSubtract.run();
        int32_t subtractResult[4] = {};
        std::memcpy(subtractResult,
                    horizontalDwordSubtract.wideRegs[0].data(), 16);
        CHECK(subtractResult[0] == 7 && subtractResult[1] == -12 &&
                  subtractResult[2] == 60 && subtractResult[3] == 10,
              "PHSUBD preserves signed two's-complement wrapping subtraction");

        PcodeEvaluator saturatedHorizontal(disassemble(0xB10));
        saturatedHorizontal.wideRegs[0].resize(16);
        saturatedHorizontal.wideRegs[8].resize(16);
        const int16_t saturatingLeft[8] = {30000, 30000, -30000, -30000,
                                           1, 2, 3, 4};
        const int16_t saturatingRight[8] = {32767, 1, -32768, -1,
                                            5, 6, 7, 8};
        std::memcpy(saturatedHorizontal.wideRegs[0].data(), saturatingLeft, 16);
        std::memcpy(saturatedHorizontal.wideRegs[8].data(), saturatingRight, 16);
        saturatedHorizontal.run();
        int16_t saturatedResult[8] = {};
        std::memcpy(saturatedResult, saturatedHorizontal.wideRegs[0].data(), 16);
        CHECK(saturatedResult[0] == 32767 && saturatedResult[1] == -32768 &&
                  saturatedResult[4] == 32767 && saturatedResult[5] == -32768,
              "PHADDSW saturates signed word results at both boundaries");

        PcodeEvaluator implicitStringIndex(disassemble(0xB20));
        implicitStringIndex.wideRegs[0].assign(16, 0);
        implicitStringIndex.wideRegs[8].assign(16, 0);
        const char equalLeft[] = "abc";
        const char equalRight[] = "axc";
        std::memcpy(implicitStringIndex.wideRegs[0].data(), equalLeft, 4);
        std::memcpy(implicitStringIndex.wideRegs[8].data(), equalRight, 4);
        implicitStringIndex.run();
        CHECK(implicitStringIndex.regValue(RCX).value_or(99) == 1 &&
                  implicitStringIndex.regValue(CF).value_or(0) == 1 &&
                  implicitStringIndex.regValue(ZF).value_or(0) == 1 &&
                  implicitStringIndex.regValue(SF).value_or(0) == 1 &&
                  implicitStringIndex.regValue(OF).value_or(1) == 0,
              "PCMPISTRI returns the first unequal byte and exact architectural flags");

        PcodeEvaluator implicitStringMask(disassemble(0xB30));
        implicitStringMask.wideRegs[16].assign(16, 0);
        implicitStringMask.wideRegs[8].assign(16, 0);
        std::memcpy(implicitStringMask.wideRegs[16].data(), "aeiou", 6);
        std::memcpy(implicitStringMask.wideRegs[8].data(), "codex", 6);
        implicitStringMask.run();
        uint16_t compactStringMask = 0;
        std::memcpy(&compactStringMask,
                    implicitStringMask.wideRegs[0].data(), 2);
        CHECK(compactStringMask == 0x0a,
              "PCMPISTRM equal-any emits the compact IntRes2 bit mask in XMM0");

        PcodeEvaluator expandedStringMask(disassemble(0xB40));
        expandedStringMask.wideRegs[16] = implicitStringMask.wideRegs[16];
        expandedStringMask.wideRegs[8] = implicitStringMask.wideRegs[8];
        expandedStringMask.run();
        CHECK(expandedStringMask.wideRegs[0][0] == 0 &&
                  expandedStringMask.wideRegs[0][1] == 0xff &&
                  expandedStringMask.wideRegs[0][2] == 0 &&
                  expandedStringMask.wideRegs[0][3] == 0xff,
              "PCMPISTRM bit 6 expands result bits into byte masks");

        PcodeEvaluator explicitStringIndex(disassemble(0xB50));
        explicitStringIndex.wideRegs[0].assign(16, 0);
        explicitStringIndex.wideRegs[8].assign(16, 0);
        explicitStringIndex.wideRegs[0][0] = 'a';
        explicitStringIndex.wideRegs[0][1] = 'z';
        std::memcpy(explicitStringIndex.wideRegs[8].data(), "Aq9", 3);
        explicitStringIndex.regs[RAX] = 2;
        explicitStringIndex.regs[16] = 3;
        explicitStringIndex.run();
        CHECK(explicitStringIndex.regValue(RCX).value_or(99) == 1 &&
                  explicitStringIndex.regValue(SF).value_or(0) == 1 &&
                  explicitStringIndex.regValue(ZF).value_or(0) == 1,
              "PCMPESTRI uses absolute clamped EAX/EDX lengths and range aggregation");

        PcodeEvaluator explicitOrderedMask(disassemble(0xB60));
        explicitOrderedMask.wideRegs[16].assign(16, 0);
        explicitOrderedMask.wideRegs[8].assign(16, 0);
        std::memcpy(explicitOrderedMask.wideRegs[16].data(), "cat", 3);
        std::memcpy(explicitOrderedMask.wideRegs[8].data(), "xxcat", 5);
        explicitOrderedMask.regs[RAX] = 3;
        explicitOrderedMask.regs[16] = 5;
        explicitOrderedMask.run();
        compactStringMask = 0;
        std::memcpy(&compactStringMask,
                    explicitOrderedMask.wideRegs[0].data(), 2);
        CHECK(compactStringMask == 0x04,
              "PCMPESTRM equal-ordered identifies the substring start position");

        const PcodeInsn multiplyAddWordsInsn = disassemble(0xB70);
        PcodeEvaluator multiplyAddWords(multiplyAddWordsInsn);
        multiplyAddWords.wideRegs[0].resize(16);
        multiplyAddWords.wideRegs[8].resize(16);
        const int16_t maddLeft[8] = {-32768, -32768, 2, 3, -4, 5, 6, -7};
        const int16_t maddRight[8] = {-32768, -32768, 10, 20, 7, 8, -9, -10};
        std::memcpy(multiplyAddWords.wideRegs[0].data(), maddLeft, 16);
        std::memcpy(multiplyAddWords.wideRegs[8].data(), maddRight, 16);
        multiplyAddWords.run();
        int32_t maddResult[4] = {};
        std::memcpy(maddResult, multiplyAddWords.wideRegs[0].data(), 16);
        CHECK(static_cast<uint32_t>(maddResult[0]) == 0x80000000U &&
                  maddResult[1] == 80 && maddResult[2] == 12 && maddResult[3] == 16,
              "PMADDWD performs signed products and exact wrapping pair sums");

        PcodeEvaluator mixedMultiplyAdd(disassemble(0xB80));
        mixedMultiplyAdd.wideRegs[0].assign(16, 255);
        mixedMultiplyAdd.wideRegs[8].resize(16);
        for (size_t lane = 0; lane < 16; lane += 2) {
            mixedMultiplyAdd.wideRegs[8][lane] = 127;
            mixedMultiplyAdd.wideRegs[8][lane + 1] = 127;
        }
        mixedMultiplyAdd.wideRegs[8][2] = static_cast<uint8_t>(-128);
        mixedMultiplyAdd.wideRegs[8][3] = static_cast<uint8_t>(-128);
        mixedMultiplyAdd.run();
        int16_t mixedResult[8] = {};
        std::memcpy(mixedResult, mixedMultiplyAdd.wideRegs[0].data(), 16);
        CHECK(mixedResult[0] == 32767 && mixedResult[1] == -32768,
              "PMADDUBSW multiplies unsigned by signed bytes and saturates pair sums");

        PcodeEvaluator multiplyEvenDwords(disassemble(0xB90));
        multiplyEvenDwords.wideRegs[0].resize(16);
        multiplyEvenDwords.wideRegs[8].resize(16);
        const int32_t mulDqLeft[4] = {-3, 999, 100000, 888};
        const int32_t mulDqRight[4] = {7, 777, -200000, 666};
        std::memcpy(multiplyEvenDwords.wideRegs[0].data(), mulDqLeft, 16);
        std::memcpy(multiplyEvenDwords.wideRegs[8].data(), mulDqRight, 16);
        multiplyEvenDwords.run();
        int64_t mulDqResult[2] = {};
        std::memcpy(mulDqResult, multiplyEvenDwords.wideRegs[0].data(), 16);
        CHECK(mulDqResult[0] == -21 && mulDqResult[1] == -20000000000LL,
              "PMULDQ multiplies only even-numbered signed dword lanes to qwords");

        PcodeEvaluator roundedHighWords(disassemble(0xBA0));
        roundedHighWords.wideRegs[0].resize(16);
        roundedHighWords.wideRegs[8].resize(16);
        const int16_t highLeft[8] = {16384, -32768, 1000, -1000, 1, 2, 3, 4};
        const int16_t highRight[8] = {16384, -32768, 1000, 1000, 1, 2, 3, 4};
        std::memcpy(roundedHighWords.wideRegs[0].data(), highLeft, 16);
        std::memcpy(roundedHighWords.wideRegs[8].data(), highRight, 16);
        roundedHighWords.run();
        int16_t highResult[8] = {};
        std::memcpy(highResult, roundedHighWords.wideRegs[0].data(), 16);
        CHECK(highResult[0] == 8192 && highResult[1] == -32768,
              "PMULHRSW rounds the signed high product and preserves the 0x8000 boundary");

        PcodeEvaluator lowDwordMultiply(disassemble(0xBB0));
        lowDwordMultiply.wideRegs[0].resize(16);
        lowDwordMultiply.wideRegs[8].resize(16);
        const uint32_t lowMulLeft[4] = {0xffffffffU, 0x80000000U, 3, 4};
        const uint32_t lowMulRight[4] = {2, 2, 5, 6};
        std::memcpy(lowDwordMultiply.wideRegs[0].data(), lowMulLeft, 16);
        std::memcpy(lowDwordMultiply.wideRegs[8].data(), lowMulRight, 16);
        lowDwordMultiply.run();
        uint32_t lowMulResult[4] = {};
        std::memcpy(lowMulResult, lowDwordMultiply.wideRegs[0].data(), 16);
        CHECK(lowMulResult[0] == 0xfffffffeU && lowMulResult[1] == 0 &&
                  lowMulResult[2] == 15 && lowMulResult[3] == 24,
              "PMULLD returns the low 32 bits of every full-width product");

        PcodeEvaluator signBytes(disassemble(0xBC0));
        signBytes.wideRegs[0].resize(16);
        signBytes.wideRegs[8].resize(16);
        for (size_t lane = 0; lane < 16; ++lane) {
            signBytes.wideRegs[0][lane] = static_cast<uint8_t>(lane + 1);
            signBytes.wideRegs[8][lane] = lane % 3 == 0 ? 0xff
                                              : lane % 3 == 1 ? 0 : 1;
        }
        signBytes.run();
        CHECK(signBytes.wideRegs[0][0] == 0xff &&
                  signBytes.wideRegs[0][1] == 0 &&
                  signBytes.wideRegs[0][2] == 3,
              "PSIGNB negates, clears or preserves each lane from signed controls");

        PcodeEvaluator shiftBytesLeft(disassemble(0xBF0));
        shiftBytesLeft.wideRegs[0].resize(16);
        for (uint8_t lane = 0; lane < 16; ++lane)
            shiftBytesLeft.wideRegs[0][lane] = lane;
        shiftBytesLeft.run();
        CHECK(shiftBytesLeft.wideRegs[0][0] == 0 &&
                  shiftBytesLeft.wideRegs[0][3] == 0 &&
                  shiftBytesLeft.wideRegs[0][4] == 0 &&
                  shiftBytesLeft.wideRegs[0][15] == 11,
              "PSLLDQ shifts bytes left within the 128-bit lane");

        PcodeEvaluator shiftBytesRight(disassemble(0xC00));
        shiftBytesRight.wideRegs[0].resize(16);
        for (uint8_t lane = 0; lane < 16; ++lane)
            shiftBytesRight.wideRegs[0][lane] = lane;
        shiftBytesRight.run();
        CHECK(shiftBytesRight.wideRegs[0][0] == 4 &&
                  shiftBytesRight.wideRegs[0][11] == 15 &&
                  shiftBytesRight.wideRegs[0][12] == 0,
              "PSRLDQ shifts bytes right and zero-fills the high end");

        PcodeEvaluator oversizedByteShift(disassemble(0xC90));
        oversizedByteShift.wideRegs[0].assign(16, 0xff);
        oversizedByteShift.run();
        CHECK(std::all_of(oversizedByteShift.wideRegs[0].begin(),
                          oversizedByteShift.wideRegs[0].end(),
                          [](uint8_t byte) { return byte == 0; }),
              "PSLLDQ counts greater than fifteen clear the complete lane");

        PcodeEvaluator packedTest(disassemble(0xC10));
        packedTest.wideRegs[0].assign(16, 0xf0);
        packedTest.wideRegs[8].assign(16, 0x0f);
        packedTest.run();
        CHECK(packedTest.regValue(ZF).value_or(0) == 1 &&
                  packedTest.regValue(CF).value_or(0) == 0 &&
                  packedTest.regValue(OF).value_or(1) == 0 &&
                  packedTest.regValue(SF).value_or(1) == 0 &&
                  packedTest.regValue(AF).value_or(1) == 0 &&
                  packedTest.regValue(PF).value_or(1) == 0,
              "PTEST computes ZF/CF reductions and clears OF/SF/AF/PF");

        PcodeEvaluator vexByteShift(disassemble(0xC20));
        vexByteShift.wideRegs[8].resize(16);
        for (uint8_t lane = 0; lane < 16; ++lane)
            vexByteShift.wideRegs[8][lane] = static_cast<uint8_t>(0x20 + lane);
        vexByteShift.run();
        CHECK(vexByteShift.wideRegs[0][4] == 0x20 &&
                  vexByteShift.wideRegs[0][15] == 0x2b,
              "VPSLLDQ obtains its source from ModRM and destination from VEX.vvvv");

        PcodeEvaluator vexMultiplyAdd(disassemble(0xC30));
        vexMultiplyAdd.wideRegs[8].resize(16);
        vexMultiplyAdd.wideRegs[16].resize(16);
        const int16_t vexMaddLeft[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        const int16_t vexMaddRight[8] = {10, 20, 30, 40, 50, 60, 70, 80};
        std::memcpy(vexMultiplyAdd.wideRegs[8].data(), vexMaddLeft, 16);
        std::memcpy(vexMultiplyAdd.wideRegs[16].data(), vexMaddRight, 16);
        vexMultiplyAdd.run();
        std::memcpy(maddResult, vexMultiplyAdd.wideRegs[0].data(), 16);
        CHECK(maddResult[0] == 50 && maddResult[3] == 1130,
              "VPMADDWD uses independent VEX sources and destination");

        PcodeEvaluator reciprocalPacked(disassemble(0xCA0));
        reciprocalPacked.wideRegs[8].resize(16);
        const float reciprocalInput[4] = {2.0f, -4.0f, 0.0f,
                                           std::numeric_limits<float>::infinity()};
        std::memcpy(reciprocalPacked.wideRegs[8].data(), reciprocalInput, 16);
        reciprocalPacked.run();
        float reciprocalResult[4] = {};
        std::memcpy(reciprocalResult, reciprocalPacked.wideRegs[0].data(), 16);
        CHECK(reciprocalResult[0] == 0.5f && reciprocalResult[1] == -0.25f &&
                  std::isinf(reciprocalResult[2]) && reciprocalResult[3] == 0,
              "RCPPS handles finite, signed-zero and infinity lanes without exceptions");

        PcodeEvaluator reciprocalScalar(disassemble(0xCB0));
        reciprocalScalar.wideRegs[0].assign(16, 0x55);
        reciprocalScalar.wideRegs[8].resize(16);
        const float scalarFour = 4.0f;
        std::memcpy(reciprocalScalar.wideRegs[8].data(), &scalarFour, 4);
        reciprocalScalar.run();
        float reciprocalScalarResult = 0;
        std::memcpy(&reciprocalScalarResult,
                    reciprocalScalar.wideRegs[0].data(), 4);
        CHECK(reciprocalScalarResult == 0.25f &&
                  reciprocalScalar.wideRegs[0][4] == 0x55,
              "RCPSS replaces only the low lane and preserves upper destination bits");

        PcodeEvaluator reciprocalSquareRoot(disassemble(0xCC0));
        reciprocalSquareRoot.wideRegs[8].resize(16);
        const float rsqrtInput[4] = {4.0f, 16.0f, 0.0f, -1.0f};
        std::memcpy(reciprocalSquareRoot.wideRegs[8].data(), rsqrtInput, 16);
        reciprocalSquareRoot.run();
        float rsqrtResult[4] = {};
        std::memcpy(rsqrtResult, reciprocalSquareRoot.wideRegs[0].data(), 16);
        CHECK(rsqrtResult[0] == 0.5f && rsqrtResult[1] == 0.25f &&
                  std::isinf(rsqrtResult[2]) && std::isnan(rsqrtResult[3]) &&
                  (reciprocalSquareRoot.mxcsr & 0x3fU) == 0,
              "RSQRTPS implements special values without setting MXCSR exception flags");

        PcodeEvaluator reciprocalSquareRootScalar(disassemble(0xCD0));
        reciprocalSquareRootScalar.wideRegs[0].assign(16, 0x66);
        reciprocalSquareRootScalar.wideRegs[8].resize(16);
        const float scalarSixteen = 16.0f;
        std::memcpy(reciprocalSquareRootScalar.wideRegs[8].data(),
                    &scalarSixteen, 4);
        reciprocalSquareRootScalar.run();
        std::memcpy(&reciprocalScalarResult,
                    reciprocalSquareRootScalar.wideRegs[0].data(), 4);
        CHECK(reciprocalScalarResult == 0.25f &&
                  reciprocalSquareRootScalar.wideRegs[0][4] == 0x66,
              "RSQRTSS updates only the scalar lane");

        PcodeEvaluator vexReciprocalScalar(disassemble(0xEF0));
        vexReciprocalScalar.wideRegs[8].assign(16, 0x5a);
        vexReciprocalScalar.wideRegs[16].resize(16);
        std::memcpy(vexReciprocalScalar.wideRegs[16].data(), &scalarFour, 4);
        vexReciprocalScalar.run();
        std::memcpy(&reciprocalScalarResult,
                    vexReciprocalScalar.wideRegs[0].data(), 4);
        CHECK(reciprocalScalarResult == 0.25f &&
                  vexReciprocalScalar.wideRegs[0][4] == 0x5a,
              "VRCPSS reads src2 and preserves scalar upper lanes from src1");

        PcodeEvaluator vexReciprocalSquareRootPacked(disassemble(0xF00));
        vexReciprocalSquareRootPacked.wideRegs[8].resize(16);
        std::memcpy(vexReciprocalSquareRootPacked.wideRegs[8].data(),
                    rsqrtInput, 16);
        vexReciprocalSquareRootPacked.run();
        std::memcpy(rsqrtResult,
                    vexReciprocalSquareRootPacked.wideRegs[0].data(), 16);
        CHECK(rsqrtResult[0] == 0.5f && rsqrtResult[1] == 0.25f &&
                  std::isinf(rsqrtResult[2]) && std::isnan(rsqrtResult[3]),
              "VRSQRTPS applies reciprocal square root to every packed lane");

        PcodeEvaluator roundPackedSingle(disassemble(0xCE0));
        roundPackedSingle.wideRegs[8].resize(16);
        const float roundSingleInput[4] = {1.9f, -1.1f, 2.0f, -0.25f};
        std::memcpy(roundPackedSingle.wideRegs[8].data(), roundSingleInput, 16);
        roundPackedSingle.run();
        float roundSingleResult[4] = {};
        std::memcpy(roundSingleResult, roundPackedSingle.wideRegs[0].data(), 16);
        CHECK(roundSingleResult[0] == 1 && roundSingleResult[1] == -2 &&
                  roundSingleResult[2] == 2 && roundSingleResult[3] == -1 &&
                  (roundPackedSingle.mxcsr & (1U << 5)) != 0,
              "ROUNDPS obeys imm8 floor mode and records precision status");

        PcodeEvaluator roundPackedDouble(disassemble(0xCF0));
        roundPackedDouble.wideRegs[8].resize(16);
        const double roundDoubleInput[2] = {1.1, -1.9};
        std::memcpy(roundPackedDouble.wideRegs[8].data(), roundDoubleInput, 16);
        roundPackedDouble.run();
        double roundDoubleResult[2] = {};
        std::memcpy(roundDoubleResult,
                    roundPackedDouble.wideRegs[0].data(), 16);
        CHECK(roundDoubleResult[0] == 2 && roundDoubleResult[1] == -1,
              "ROUNDPD applies the selected rounding mode to both double lanes");

        PcodeEvaluator roundScalarSingle(disassemble(0xD00));
        roundScalarSingle.wideRegs[0].assign(16, 0x77);
        roundScalarSingle.wideRegs[8].resize(16);
        const float negativeFraction = -1.75f;
        std::memcpy(roundScalarSingle.wideRegs[8].data(), &negativeFraction, 4);
        roundScalarSingle.run();
        float roundedScalar = 0;
        std::memcpy(&roundedScalar, roundScalarSingle.wideRegs[0].data(), 4);
        CHECK(roundedScalar == -1 && roundScalarSingle.wideRegs[0][4] == 0x77,
              "ROUNDSS truncates the low source and preserves destination upper lanes");

        PcodeEvaluator suppressRoundPrecision(disassemble(0xD10));
        suppressRoundPrecision.mxcsr = 0;
        suppressRoundPrecision.wideRegs[0].assign(16, 0);
        suppressRoundPrecision.wideRegs[8].resize(16);
        const double oneAndHalf = 1.5;
        std::memcpy(suppressRoundPrecision.wideRegs[8].data(), &oneAndHalf, 8);
        suppressRoundPrecision.run();
        double roundedDouble = 0;
        std::memcpy(&roundedDouble, suppressRoundPrecision.wideRegs[0].data(), 8);
        CHECK(!suppressRoundPrecision.fault && roundedDouble == 2 &&
                  (suppressRoundPrecision.mxcsr & (1U << 5)) == 0,
              "ROUNDSD imm8 suppress-exception bit prevents PE and #XM");

        PcodeEvaluator vexRoundPackedDouble(disassemble(0xF10));
        vexRoundPackedDouble.wideRegs[8].resize(32);
        const double vexRoundDoubleInput[4] = {1.1, -1.9, 2.0, -0.1};
        std::memcpy(vexRoundPackedDouble.wideRegs[8].data(),
                    vexRoundDoubleInput, 32);
        vexRoundPackedDouble.run();
        double vexRoundDoubleResult[4] = {};
        std::memcpy(vexRoundDoubleResult,
                    vexRoundPackedDouble.wideRegs[0].data(), 32);
        CHECK(vexRoundDoubleResult[0] == 2 &&
                  vexRoundDoubleResult[1] == -1 &&
                  vexRoundDoubleResult[2] == 2 &&
                  vexRoundDoubleResult[3] == 0,
              "VROUNDPD rounds every YMM lane with the imm8 mode");

        PcodeEvaluator vexRoundScalarDouble(disassemble(0xF20));
        vexRoundScalarDouble.wideRegs[8].assign(16, 0x39);
        vexRoundScalarDouble.wideRegs[16].resize(16);
        const double negativeOnePointOne = -1.1;
        std::memcpy(vexRoundScalarDouble.wideRegs[16].data(),
                    &negativeOnePointOne, 8);
        vexRoundScalarDouble.run();
        std::memcpy(&roundedDouble,
                    vexRoundScalarDouble.wideRegs[0].data(), 8);
        CHECK(roundedDouble == -2 &&
                  vexRoundScalarDouble.wideRegs[0][8] == 0x39,
              "VROUNDSD rounds src2 and preserves the remaining lanes from src1");

        PcodeEvaluator vexScalarAdd(disassemble(0xD20));
        vexScalarAdd.wideRegs[8].assign(16, 0x44);
        vexScalarAdd.wideRegs[16].resize(16);
        const float vexAddRight = 2.5f, vexAddLeft = 1.5f;
        std::memcpy(vexScalarAdd.wideRegs[8].data(), &vexAddLeft, 4);
        std::memcpy(vexScalarAdd.wideRegs[16].data(), &vexAddRight, 4);
        vexScalarAdd.run();
        float vexScalarResult = 0;
        std::memcpy(&vexScalarResult, vexScalarAdd.wideRegs[0].data(), 4);
        CHECK(vexScalarResult == 4.0f && vexScalarAdd.wideRegs[0][4] == 0x44,
              "VADDSS computes src1+src2 and copies upper lanes from src1");

        auto checkVexScalar32 = [&](uint64_t address, float lhs, float rhs,
                                    float expected, const char* message) {
            PcodeEvaluator evaluator(disassemble(address));
            evaluator.wideRegs[8].assign(16, 0x4c);
            evaluator.wideRegs[16].resize(16);
            std::memcpy(evaluator.wideRegs[8].data(), &lhs, 4);
            std::memcpy(evaluator.wideRegs[16].data(), &rhs, 4);
            evaluator.run();
            float actual = 0;
            std::memcpy(&actual, evaluator.wideRegs[0].data(), 4);
            CHECK(actual == expected && evaluator.wideRegs[0][4] == 0x4c,
                  message);
        };
        checkVexScalar32(0xF40, 7.0f, 2.0f, 5.0f,
                         "VSUBSS implements three-operand scalar subtraction");
        checkVexScalar32(0xD40, 3.0f, 2.0f, 6.0f,
                         "VMULSS implements three-operand scalar multiplication");
        checkVexScalar32(0xF60, 8.0f, 2.0f, 4.0f,
                         "VDIVSS implements three-operand scalar division");
        checkVexScalar32(0xD60, 7.0f, 2.0f, 2.0f,
                         "VMINSS implements scalar minimum selection");
        checkVexScalar32(0xF80, 7.0f, 2.0f, 7.0f,
                         "VMAXSS implements scalar maximum selection");
        checkVexScalar32(0xF90, 99.0f, 9.0f, 3.0f,
                         "VSQRTSS computes src2 and uses src1 for upper lanes");

        auto checkVexScalar64 = [&](uint64_t address, double lhs, double rhs,
                                    double expected, const char* message) {
            PcodeEvaluator evaluator(disassemble(address));
            evaluator.wideRegs[8].assign(16, 0x6d);
            evaluator.wideRegs[16].resize(16);
            std::memcpy(evaluator.wideRegs[8].data(), &lhs, 8);
            std::memcpy(evaluator.wideRegs[16].data(), &rhs, 8);
            evaluator.run();
            double actual = 0;
            std::memcpy(&actual, evaluator.wideRegs[0].data(), 8);
            CHECK(actual == expected && evaluator.wideRegs[0][8] == 0x6d,
                  message);
        };
        checkVexScalar64(0xF30, 1.5, 2.5, 4.0,
                         "VADDSD implements three-operand scalar addition");
        checkVexScalar64(0xD30, 7.0, 2.0, 5.0,
                         "VSUBSD implements three-operand scalar subtraction");
        checkVexScalar64(0xF50, 3.0, 2.0, 6.0,
                         "VMULSD implements three-operand scalar multiplication");
        checkVexScalar64(0xD50, 8.0, 2.0, 4.0,
                         "VDIVSD implements three-operand scalar division");
        checkVexScalar64(0xF70, 7.0, 2.0, 2.0,
                         "VMINSD implements scalar minimum selection");
        checkVexScalar64(0xD70, 7.0, 2.0, 7.0,
                         "VMAXSD implements scalar maximum selection");
        checkVexScalar64(0xFA0, 99.0, 9.0, 3.0,
                         "VSQRTSD computes src2 and uses src1 for upper lanes");

        PcodeEvaluator vexScalarMemory(disassemble(0xFB0));
        vexScalarMemory.regs[RAX] = 0x6f00;
        vexScalarMemory.wideRegs[8].assign(16, 0x7e);
        std::memcpy(vexScalarMemory.wideRegs[8].data(), &vexAddLeft, 4);
        for (unsigned byte = 0; byte < 4; ++byte)
            vexScalarMemory.ram[0x6f00 + byte] =
                reinterpret_cast<const uint8_t*>(&vexAddRight)[byte];
        vexScalarMemory.run();
        std::memcpy(&vexScalarResult,
                    vexScalarMemory.wideRegs[0].data(), 4);
        CHECK(vexScalarResult == 4.0f &&
                  vexScalarMemory.wideRegs[0][4] == 0x7e,
              "VEX scalar memory forms load only the scalar src2 operand");

        PcodeEvaluator moveLowLoad(disassemble(0xD80));
        moveLowLoad.regs[RAX] = 0x7000;
        moveLowLoad.wideRegs[0].assign(16, 0xaa);
        const uint64_t lowLaneValue = 0x0123456789abcdefULL;
        for (unsigned byte = 0; byte < 8; ++byte)
            moveLowLoad.ram[0x7000 + byte] =
                static_cast<uint8_t>(lowLaneValue >> (byte * 8));
        moveLowLoad.run();
        uint64_t movedLow = 0, preservedHigh = 0;
        std::memcpy(&movedLow, moveLowLoad.wideRegs[0].data(), 8);
        std::memcpy(&preservedHigh, moveLowLoad.wideRegs[0].data() + 8, 8);
        CHECK(movedLow == lowLaneValue && preservedHigh == 0xaaaaaaaaaaaaaaaaULL,
              "MOVLPS loads the low qword while preserving the high qword");

        PcodeEvaluator moveHighLoad(disassemble(0xDA0));
        moveHighLoad.regs[RAX] = 0x7000;
        moveHighLoad.ram = moveLowLoad.ram;
        moveHighLoad.wideRegs[0].assign(16, 0xbb);
        moveHighLoad.run();
        uint64_t preservedLow = 0, movedHigh = 0;
        std::memcpy(&preservedLow, moveHighLoad.wideRegs[0].data(), 8);
        std::memcpy(&movedHigh, moveHighLoad.wideRegs[0].data() + 8, 8);
        CHECK(preservedLow == 0xbbbbbbbbbbbbbbbbULL && movedHigh == lowLaneValue,
              "MOVHPS loads the high qword while preserving the low qword");

        PcodeEvaluator moveHighStore(disassemble(0xDB0));
        moveHighStore.regs[RAX] = 0x7100;
        moveHighStore.wideRegs[0].resize(16);
        std::memcpy(moveHighStore.wideRegs[0].data() + 8, &lowLaneValue, 8);
        moveHighStore.run();
        uint64_t storedHigh = 0;
        for (unsigned byte = 0; byte < 8; ++byte)
            storedHigh |= static_cast<uint64_t>(moveHighStore.ram[0x7100 + byte])
                          << (byte * 8);
        CHECK(storedHigh == lowLaneValue,
              "MOVHPS stores exactly the source high qword");

        PcodeEvaluator moveLowDoubleStore(disassemble(0xFC0));
        moveLowDoubleStore.regs[RAX] = 0x7120;
        moveLowDoubleStore.wideRegs[0].resize(16);
        std::memcpy(moveLowDoubleStore.wideRegs[0].data(), &lowLaneValue, 8);
        moveLowDoubleStore.run();
        uint64_t storedLowDouble = 0;
        for (unsigned byte = 0; byte < 8; ++byte)
            storedLowDouble |=
                static_cast<uint64_t>(moveLowDoubleStore.ram[0x7120 + byte])
                << (byte * 8);
        CHECK(storedLowDouble == lowLaneValue,
              "MOVLPD stores exactly the source low qword");

        PcodeEvaluator moveHighDoubleLoad(disassemble(0xFD0));
        moveHighDoubleLoad.regs[RAX] = 0x7140;
        moveHighDoubleLoad.wideRegs[0].assign(16, 0xcc);
        for (unsigned byte = 0; byte < 8; ++byte)
            moveHighDoubleLoad.ram[0x7140 + byte] =
                static_cast<uint8_t>(lowLaneValue >> (byte * 8));
        moveHighDoubleLoad.run();
        std::memcpy(&preservedLow,
                    moveHighDoubleLoad.wideRegs[0].data(), 8);
        std::memcpy(&movedHigh,
                    moveHighDoubleLoad.wideRegs[0].data() + 8, 8);
        CHECK(preservedLow == 0xccccccccccccccccULL &&
                  movedHigh == lowLaneValue,
              "MOVHPD loads the destination high qword and preserves its low qword");

        PcodeEvaluator vexReciprocalMemory(disassemble(0xFE0));
        vexReciprocalMemory.regs[RAX] = 0x7160;
        vexReciprocalMemory.wideRegs[8].assign(16, 0x2d);
        for (unsigned byte = 0; byte < 4; ++byte)
            vexReciprocalMemory.ram[0x7160 + byte] =
                reinterpret_cast<const uint8_t*>(&scalarFour)[byte];
        vexReciprocalMemory.run();
        std::memcpy(&reciprocalScalarResult,
                    vexReciprocalMemory.wideRegs[0].data(), 4);
        CHECK(reciprocalScalarResult == 0.25f &&
                  vexReciprocalMemory.wideRegs[0][4] == 0x2d,
              "VRCPSS memory form combines loaded src2 with src1 upper lanes");

        PcodeEvaluator vexRoundMemory(disassemble(0xFF0));
        vexRoundMemory.regs[RAX] = 0x7180;
        vexRoundMemory.wideRegs[8].assign(16, 0x3e);
        const double memoryRoundInput = -1.9;
        for (unsigned byte = 0; byte < 8; ++byte)
            vexRoundMemory.ram[0x7180 + byte] =
                reinterpret_cast<const uint8_t*>(&memoryRoundInput)[byte];
        vexRoundMemory.run();
        std::memcpy(&roundedDouble, vexRoundMemory.wideRegs[0].data(), 8);
        CHECK(roundedDouble == -1 && vexRoundMemory.wideRegs[0][8] == 0x3e,
              "VROUNDSD memory form rounds loaded src2 and preserves src1");

        PcodeEvaluator reciprocalSquareRootMemory(disassemble(0x1000));
        reciprocalSquareRootMemory.regs[RAX] = 0x71a0;
        reciprocalSquareRootMemory.wideRegs[0].assign(16, 0x4f);
        for (unsigned byte = 0; byte < 4; ++byte)
            reciprocalSquareRootMemory.ram[0x71a0 + byte] =
                reinterpret_cast<const uint8_t*>(&scalarSixteen)[byte];
        reciprocalSquareRootMemory.run();
        std::memcpy(&reciprocalScalarResult,
                    reciprocalSquareRootMemory.wideRegs[0].data(), 4);
        CHECK(reciprocalScalarResult == 0.25f &&
                  reciprocalSquareRootMemory.wideRegs[0][4] == 0x4f,
              "RSQRTSS memory form reads one dword and preserves upper lanes");

        PcodeEvaluator vexRoundScalar(disassemble(0xE10));
        vexRoundScalar.wideRegs[8].assign(16, 0x33);
        vexRoundScalar.wideRegs[16].resize(16);
        const float vexRoundInput = 1.1f;
        std::memcpy(vexRoundScalar.wideRegs[16].data(), &vexRoundInput, 4);
        vexRoundScalar.run();
        std::memcpy(&roundedScalar, vexRoundScalar.wideRegs[0].data(), 4);
        CHECK(roundedScalar == 2 && vexRoundScalar.wideRegs[0][4] == 0x33,
              "VROUNDSS uses src2 for the rounded lane and src1 for upper lanes");

        PcodeEvaluator vexUnpack(disassemble(0xE20));
        vexUnpack.wideRegs[8].resize(32);
        vexUnpack.wideRegs[16].resize(32);
        const uint32_t unpackLeft[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        const uint32_t unpackRight[8] = {11, 12, 13, 14, 15, 16, 17, 18};
        std::memcpy(vexUnpack.wideRegs[8].data(), unpackLeft, 32);
        std::memcpy(vexUnpack.wideRegs[16].data(), unpackRight, 32);
        vexUnpack.run();
        uint32_t unpackResult[8] = {};
        std::memcpy(unpackResult, vexUnpack.wideRegs[0].data(), 32);
        CHECK(unpackResult[0] == 1 && unpackResult[1] == 11 &&
                  unpackResult[2] == 2 && unpackResult[3] == 12 &&
                  unpackResult[4] == 5 && unpackResult[5] == 15,
              "VUNPCKLPS interleaves independently inside both 128-bit lanes");

        PcodeEvaluator insertHalf(disassemble(0xE60));
        insertHalf.wideRegs[8].assign(32, 0x11);
        insertHalf.wideRegs[16].assign(16, 0x22);
        insertHalf.run();
        CHECK(insertHalf.wideRegs[0][0] == 0x11 &&
                  insertHalf.wideRegs[0][15] == 0x11 &&
                  insertHalf.wideRegs[0][16] == 0x22 &&
                  insertHalf.wideRegs[0][31] == 0x22,
              "VINSERTF128 replaces the selected half without changing the other half");

        PcodeEvaluator permuteHalves(disassemble(0xE70));
        permuteHalves.wideRegs[8].resize(32);
        permuteHalves.wideRegs[16].resize(32);
        std::fill(permuteHalves.wideRegs[8].begin(),
                  permuteHalves.wideRegs[8].begin() + 16, 0x10);
        std::fill(permuteHalves.wideRegs[8].begin() + 16,
                  permuteHalves.wideRegs[8].end(), 0x11);
        std::fill(permuteHalves.wideRegs[16].begin(),
                  permuteHalves.wideRegs[16].begin() + 16, 0x20);
        std::fill(permuteHalves.wideRegs[16].begin() + 16,
                  permuteHalves.wideRegs[16].end(), 0x21);
        permuteHalves.run();
        CHECK(permuteHalves.wideRegs[0][0] == 0x11 &&
                  permuteHalves.wideRegs[0][16] == 0x20,
              "VPERM2F128 independently selects both destination halves");

        PcodeEvaluator signExtendBytes(disassemble(0xE90));
        signExtendBytes.regs[RAX] = 0x7200;
        const int8_t narrowSigned[8] = {-128, -2, -1, 0, 1, 2, 100, 127};
        for (size_t byte = 0; byte < 8; ++byte)
            signExtendBytes.ram[0x7200 + byte] =
                static_cast<uint8_t>(narrowSigned[byte]);
        signExtendBytes.run();
        int16_t widenedSigned[8] = {};
        std::memcpy(widenedSigned, signExtendBytes.wideRegs[0].data(), 16);
        CHECK(widenedSigned[0] == -128 && widenedSigned[1] == -2 &&
                  widenedSigned[6] == 100 && widenedSigned[7] == 127,
              "PMOVSXBW sign-extends every low source byte into a word");

        PcodeEvaluator moveHighToLow(disassemble(0xEC0));
        moveHighToLow.wideRegs[0].assign(16, 0xaa);
        moveHighToLow.wideRegs[8].assign(16, 0xbb);
        moveHighToLow.run();
        CHECK(moveHighToLow.wideRegs[0][0] == 0xbb &&
                  moveHighToLow.wideRegs[0][7] == 0xbb &&
                  moveHighToLow.wideRegs[0][8] == 0xaa,
              "MOVHLPS copies the source high qword into destination low qword");

        PcodeEvaluator nonTemporalStore(disassemble(0xEE0));
        nonTemporalStore.regs[RAX] = 0x7300;
        nonTemporalStore.wideRegs[0].resize(16);
        for (uint8_t byte = 0; byte < 16; ++byte)
            nonTemporalStore.wideRegs[0][byte] = byte;
        nonTemporalStore.run();
        CHECK(nonTemporalStore.ram[0x7300] == 0 &&
                  nonTemporalStore.ram[0x730f] == 15,
              "MOVNTDQ stores the full vector while retaining non-temporal intent semantically");

        PcodeEvaluator zeroUpper(disassemble(0xEA0));
        zeroUpper.wideRegs[0].resize(32);
        for (uint8_t byte = 0; byte < 32; ++byte)
            zeroUpper.wideRegs[0][byte] = static_cast<uint8_t>(byte + 1);
        zeroUpper.run();
        CHECK(zeroUpper.wideRegs[0][0] == 1 &&
                  zeroUpper.wideRegs[0][15] == 16 &&
                  zeroUpper.wideRegs[0][16] == 0 &&
                  zeroUpper.wideRegs[0][31] == 0,
              "VZEROUPPER preserves XMM state and clears only the YMM upper half");

        PcodeEvaluator zeroAll(disassemble(0xEB0));
        zeroAll.wideRegs[0].assign(32, 0xff);
        zeroAll.run();
        CHECK(zeroAll.wideRegs[0][0] == 0 && zeroAll.wideRegs[0][31] == 0,
              "VZEROALL clears the complete YMM register file");

        PcodeEvaluator signHigh(disassemble(0x1030));
        signHigh.regs[RAX] = 1ULL << 63;
        signHigh.run();
        CHECK(signHigh.regValue(16).value_or(0) == ~0ULL,
              "CQO sign-extends RAX into RDX");

        PcodeEvaluator unsignedMultiply(disassemble(0x1040));
        unsignedMultiply.regs[RAX] = 5;
        unsignedMultiply.regs[RBX] = 0x7400;
        for (unsigned byte = 0; byte < 8; ++byte)
            unsignedMultiply.ram[0x7400 + byte] =
                static_cast<uint8_t>(3ULL >> (byte * 8));
        unsignedMultiply.run();
        CHECK(unsignedMultiply.regValue(RAX).value_or(0) == 15 &&
                  unsignedMultiply.regValue(16).value_or(1) == 0 &&
                  unsignedMultiply.regValue(CF).value_or(1) == 0,
              "MUL produces the exact RDX:RAX product and overflow flags");

        PcodeEvaluator signedMultiply(disassemble(0x1050));
        signedMultiply.regs[RAX] = static_cast<uint64_t>(-2LL);
        signedMultiply.regs[RBX] = 0x7420;
        for (unsigned byte = 0; byte < 8; ++byte)
            signedMultiply.ram[0x7420 + byte] =
                static_cast<uint8_t>(3ULL >> (byte * 8));
        signedMultiply.run();
        CHECK(signedMultiply.regValue(RAX).value_or(0) ==
                  static_cast<uint64_t>(-6LL) &&
                  signedMultiply.regValue(16).value_or(0) == ~0ULL &&
                  signedMultiply.regValue(OF).value_or(1) == 0,
              "one-operand IMUL produces the signed double-width product");

        PcodeEvaluator compareExchange8(disassemble(0x1060));
        compareExchange8.regs[RSI] = 0x7440;
        compareExchange8.regs[RAX] = 0x11223344;
        compareExchange8.regs[16] = 0x55667788;
        compareExchange8.regs[RBX] = 0xaabbccdd;
        compareExchange8.regs[RCX] = 0xeeff0011;
        const uint64_t compare8 = 0x5566778811223344ULL;
        for (unsigned byte = 0; byte < 8; ++byte)
            compareExchange8.ram[0x7440 + byte] =
                static_cast<uint8_t>(compare8 >> (byte * 8));
        compareExchange8.run();
        uint64_t exchanged8 = 0;
        for (unsigned byte = 0; byte < 8; ++byte)
            exchanged8 |= static_cast<uint64_t>(compareExchange8.ram[0x7440 + byte])
                          << (byte * 8);
        CHECK(exchanged8 == 0xeeff0011aabbccddULL &&
                  compareExchange8.regValue(ZF).value_or(0) == 1,
              "CMPXCHG8B atomically compares EDX:EAX and stores ECX:EBX");

        PcodeEvaluator compareExchange16(disassemble(0x1070));
        compareExchange16.regs[RSI] = 0x7460;
        compareExchange16.regs[RAX] = 0x1111;
        compareExchange16.regs[16] = 0x2222;
        compareExchange16.regs[RBX] = 0x3333;
        compareExchange16.regs[RCX] = 0x4444;
        for (unsigned byte = 0; byte < 8; ++byte) {
            compareExchange16.ram[0x7460 + byte] =
                static_cast<uint8_t>(0x1111ULL >> (byte * 8));
            compareExchange16.ram[0x7468 + byte] =
                static_cast<uint8_t>(0x2222ULL >> (byte * 8));
        }
        compareExchange16.run();
        CHECK(compareExchange16.ram[0x7460] == 0x33 &&
                  compareExchange16.ram[0x7468] == 0x44 &&
                  compareExchange16.regValue(ZF).value_or(0) == 1,
              "CMPXCHG16B atomically updates the complete 128-bit memory value");

        PcodeEvaluator frame(disassemble(0x1080));
        frame.regs[32] = 0x7500; frame.regs[40] = 0x7600;
        for (unsigned byte = 0; byte < 8; ++byte)
            frame.ram[0x75f8 + byte] = static_cast<uint8_t>(0x7700ULL >> (byte * 8));
        frame.run();
        CHECK(frame.regValue(40).value_or(0) == 0x74f8 &&
                  frame.regValue(32).value_or(0) == 0x74d8,
              "ENTER creates the requested nested frame and local allocation");

        PcodeEvaluator flagsRoundTrip(disassemble(0x10A0));
        flagsRoundTrip.regs[32] = 0x7800;
        flagsRoundTrip.regs[CF] = 1; flagsRoundTrip.regs[ZF] = 1;
        flagsRoundTrip.run();
        CHECK(flagsRoundTrip.regValue(32).value_or(0) == 0x77f8 &&
                  (flagsRoundTrip.ram[0x77f8] & 1U) != 0,
              "PUSHF materializes architectural flags on the stack");
        PcodeEvaluator popFlags(disassemble(0x10B0));
        popFlags.regs[32] = 0x77f8; popFlags.ram = flagsRoundTrip.ram;
        popFlags.run();
        CHECK(popFlags.regValue(CF).value_or(0) == 1 &&
                  popFlags.regValue(ZF).value_or(0) == 1 &&
                  popFlags.regValue(32).value_or(0) == 0x7800,
              "POPF restores status flags and advances RSP");

        PcodeEvaluator loadMxcsr(disassemble(0x10F0));
        loadMxcsr.regs[RAX] = 0x7820;
        const uint32_t requestedMxcsr = 0x3f80;
        for (unsigned byte = 0; byte < 4; ++byte)
            loadMxcsr.ram[0x7820 + byte] =
                static_cast<uint8_t>(requestedMxcsr >> (byte * 8));
        loadMxcsr.run();
        CHECK(loadMxcsr.mxcsr == requestedMxcsr,
              "LDMXCSR restores the complete valid MXCSR state");

        PcodeEvaluator portInput(disassemble(0x1110));
        portInput.regs[16] = 0x80; portInput.regs[RDI] = 0x7840;
        portInput.ioPorts[0x80] = 0x5a; portInput.run();
        CHECK(portInput.ram[0x7840] == 0x5a &&
                  portInput.regValue(RDI).value_or(0) == 0x7841,
              "INSB transfers from DX port to ES:RDI and advances RDI");

        PcodeEvaluator timestamp(disassemble(0x1180));
        timestamp.timestampCounter = 0x1122334455667788ULL;
        timestamp.processorId = 0xa5a5;
        timestamp.run();
        CHECK(timestamp.regValue(RAX).value_or(0) == 0x55667788 &&
                  timestamp.regValue(16).value_or(0) == 0x11223344 &&
                  timestamp.regValue(RCX).value_or(0) == 0xa5a5,
              "RDTSCP returns TSC and processor auxiliary identifier");

        PcodeEvaluator random(disassemble(0x11A0));
        random.run();
        CHECK(random.regValue(RAX).has_value() &&
                  random.regValue(CF).value_or(0) == 1,
              "RDRAND returns deterministic executable entropy and success CF");

        PcodeEvaluator accessControl(disassemble(0x1240));
        accessControl.privilegeLevel = 0; accessControl.run();
        CHECK(accessControl.alignmentAccessEnabled,
              "STAC sets architectural access-control state at CPL0");
        PcodeEvaluator deniedAccessControl(disassemble(0x1230));
        deniedAccessControl.privilegeLevel = 3; deniedAccessControl.run();
        CHECK(deniedAccessControl.fault &&
                  deniedAccessControl.fault->vector ==
                      PcodeEvaluator::X86Fault::InvalidOpcode,
              "CLAC raises #UD outside CPL0");

        PcodeEvaluator translate(disassemble(0x12B0));
        translate.regs[RBX] = 0x7900; translate.regs[RAX] = 3;
        translate.ram[0x7903] = 0xc7; translate.run();
        CHECK((translate.regValue(RAX).value_or(0) & 0xffU) == 0xc7,
              "XLAT loads AL from DS:[RBX+unsigned AL]");

        PcodeEvaluator invalidOpcode(disassemble(0x1300));
        invalidOpcode.run();
        CHECK(invalidOpcode.fault &&
                  invalidOpcode.fault->vector ==
                      PcodeEvaluator::X86Fault::InvalidOpcode,
              "UD2 deterministically raises #UD");

        PcodeEvaluator ahFlags(disassemble(0x10D0));
        ahFlags.regs[RAX] = 0xd500;
        ahFlags.run();
        CHECK(ahFlags.regValue(CF).value_or(0) == 1 &&
                  ahFlags.regValue(PF).value_or(0) == 1 &&
                  ahFlags.regValue(AF).value_or(0) == 1 &&
                  ahFlags.regValue(ZF).value_or(0) == 1 &&
                  ahFlags.regValue(SF).value_or(0) == 1,
              "SAHF restores all five status flags from AH");

        PcodeEvaluator storeMxcsr(disassemble(0x1100));
        storeMxcsr.regs[RAX] = 0x7920; storeMxcsr.mxcsr = 0x5f80;
        storeMxcsr.run();
        CHECK(storeMxcsr.ram[0x7920] == 0x80 &&
                  storeMxcsr.ram[0x7921] == 0x5f,
              "STMXCSR stores the architectural 32-bit control/status value");

        PcodeEvaluator monitor(disassemble(0x11F0));
        monitor.regs[RAX] = 0x7a00; monitor.run();
        CHECK(monitor.monitorArmed && monitor.monitoredAddress == 0x7a00,
              "MONITOR arms the watched linear address");
        PcodeEvaluator monitorWait(disassemble(0x1210));
        monitorWait.monitorArmed = true; monitorWait.run();
        CHECK(monitorWait.halted && !monitorWait.monitorArmed,
              "MWAIT consumes the monitor state and enters wait state");

        PcodeEvaluator fastCall(disassemble(0x1450));
        fastCall.modelSpecificRegs[0xc0000081U] = 0x10ULL << 32;
        fastCall.modelSpecificRegs[0xc0000082U] = 0xffff800000001000ULL;
        fastCall.modelSpecificRegs[0xc0000084U] = 1ULL << 9;
        fastCall.run();
        CHECK(fastCall.privilegeLevel == 0 &&
                  fastCall.lastBranchTarget().value_or(0) ==
                      0xffff800000001000ULL,
              "SYSCALL saves return state and enters the configured kernel target");

        PcodeEvaluator fastReturn(disassemble(0x1250));
        fastReturn.privilegeLevel = 0;
        fastReturn.regs[RCX] = 0x400123;
        fastReturn.regs[88] = 2 | (1U << 9);
        fastReturn.run();
        CHECK(fastReturn.privilegeLevel == 3 &&
                  fastReturn.lastBranchTarget().value_or(0) == 0x400123,
              "SYSRET restores user RIP/RFLAGS and returns to CPL3");

        PcodeEvaluator interruptReturn(disassemble(0x1260));
        interruptReturn.regs[32] = 0x7b00;
        const uint64_t interruptFrame[3] = {0x401000, 0x33, 0x203};
        for (unsigned slot = 0; slot < 3; ++slot)
            for (unsigned byte = 0; byte < 8; ++byte)
                interruptReturn.ram[0x7b00 + slot * 8 + byte] =
                    static_cast<uint8_t>(interruptFrame[slot] >> (byte * 8));
        interruptReturn.run();
        CHECK(interruptReturn.lastBranchTarget().value_or(0) == 0x401000 &&
                  interruptReturn.regValue(32).value_or(0) == 0x7b18,
              "IRET restores RIP, CS and RFLAGS from the interrupt frame");

        PcodeEvaluator accessRights(disassemble(0x1290));
        accessRights.regs[RCX] = 0x08;
        accessRights.gdtr.base = 0x7c00;
        const uint64_t codeDescriptor = 0x00cf9a000000ffffULL;
        for (unsigned byte = 0; byte < 8; ++byte)
            accessRights.ram[0x7c08 + byte] =
                static_cast<uint8_t>(codeDescriptor >> (byte * 8));
        accessRights.run();
        CHECK(accessRights.regValue(ZF).value_or(0) == 1 &&
                  accessRights.regValue(RAX).has_value(),
              "LAR validates a GDT selector and returns its access-rights image");

        PcodeEvaluator popRegister(disassemble(0x1400));
        popRegister.regs[32] = 0x7d00;
        const uint64_t poppedValue = 0x1122334455667788ULL;
        for (unsigned byte = 0; byte < 8; ++byte)
            popRegister.ram[0x7d00 + byte] =
                static_cast<uint8_t>(poppedValue >> (byte * 8));
        popRegister.run();
        CHECK(popRegister.regValue(RAX).value_or(0) == poppedValue &&
                  popRegister.regValue(32).value_or(0) == 0x7d08,
              "POP lowers to analyzable load plus stack update semantics");

        PcodeEvaluator pushRegister(disassemble(0x1460));
        pushRegister.regs[32] = 0x7e00;
        pushRegister.regs[RBX] = poppedValue;
        pushRegister.run();
        uint64_t pushedValue = 0;
        for (unsigned byte = 0; byte < 8; ++byte)
            pushedValue |= static_cast<uint64_t>(
                               pushRegister.ram[0x7df8 + byte]) << (byte * 8);
        CHECK(pushRegister.regValue(32).value_or(0) == 0x7df8 &&
                  pushedValue == poppedValue,
              "PUSH lowers to analyzable stack update plus store semantics");

        PcodeEvaluator gsLoad(disassemble(0x1470));
        gsLoad.regs[X86_GS_BASE_OFFSET] = 0x8000;
        const uint64_t tibSelf = 0x8877665544332211ULL;
        for (unsigned byte = 0; byte < 8; ++byte)
            gsLoad.ram[0x8030 + byte] =
                static_cast<uint8_t>(tibSelf >> (byte * 8));
        gsLoad.run();
        CHECK(gsLoad.regValue(RAX).value_or(0) == tibSelf,
              "GS segment override adds the architectural GS base to memory addresses");

    }
    {
        Program program;
        program.arch = "x86-64";
        program.format = "PE32+";
        CHECK(program.memory.addBlock("coverage", 0, image,
                                      static_cast<int>(Perm::R) |
                                          static_cast<int>(Perm::X)),
              "map semantic coverage corpus");
        const SemanticCoverageReport coverage =
            auditSemanticCoverage(program, engine, 8192);
        if (coverage.decodeFailures || coverage.emptySemantics ||
            coverage.unimplementedOperations || coverage.decodedBytes != image.size()) {
            std::printf("coverage diag failures=%zu bytes=%zu/%zu empty=%zu unimpl=%zu\n",
                        coverage.decodeFailures, coverage.decodedBytes, image.size(),
                        coverage.emptySemantics, coverage.unimplementedOperations);
            for (const auto& missing : coverage.missingByMnemonic)
                std::printf("coverage missing %s: %zu\n",
                            missing.first.c_str(), missing.second);
        }
        CHECK(coverage.instructions > 100 && coverage.decodeFailures == 0 &&
                  coverage.decodedBytes == image.size() &&
                  coverage.emptySemantics == 0 &&
                  coverage.unimplementedOperations == 0,
              "semantic coverage gate rejects empty or unimplemented x86 semantics");
        const ConstructorProofReport proofs = auditConstructorProof(engine);
        CHECK(proofs.constructors > 1000 && proofs.sharedSpecifications > 20 &&
                  proofs.unproven == 0 && proofs.unprovenByMnemonic.empty(),
              "constructor proof inventory reaches zero unproven x86 encodings");
        bool requestedFamiliesProven = true;
        for (const char* mnemonic : {
                 "rcpps", "rcpss", "rsqrtps", "rsqrtss",
                 "vrcpps", "vrcpss", "vrsqrtps", "vrsqrtss",
                 "roundps", "roundpd", "roundss", "roundsd",
                 "vroundps", "vroundpd", "vroundss", "vroundsd",
                 "vaddss", "vaddsd", "vsubss", "vsubsd",
                 "vmulss", "vmulsd", "vdivss", "vdivsd",
                 "vminss", "vminsd", "vmaxss", "vmaxsd",
                 "vsqrtss", "vsqrtsd",
                 "movlps", "movlpd", "movhps", "movhpd"})
            requestedFamiliesProven &=
                proofs.unprovenByMnemonic.count(mnemonic) == 0;
        CHECK(requestedFamiliesProven,
              "all requested RCP/RSQRT, ROUND, VEX scalar and MOVL/H constructors are proven");
    }

    if (failures) {
        std::printf("%d x86 flag test(s) failed\n", failures);
        return 1;
    }
    std::puts("all x86 flag tests passed");
    return 0;
}
