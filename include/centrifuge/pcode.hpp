// centrifuge - a Ghidra reimplementation in C++17
// pcode.hpp - p-code intermediate representation (Ghidra's decompiler IR)
//
// Every instruction decodes to a straight-line list of p-code ops over
// varnodes. This is the substrate for the Sleigh-style spec engine (v0.3),
// the future decompiler (v0.4+), and a small interpreter used for validation.
#pragma once

#include <cstdint>
#include <array>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "centrifuge/disasm.hpp" // Insn

namespace centrifuge {

// Synthetic register-space offsets used for the architectural bases behind
// x86 FS/GS segment overrides.  They intentionally do not overlap integer,
// vector, mask, MMX, flag, or x87 register banks.
constexpr uint64_t X86_FS_BASE_OFFSET = 12288;
constexpr uint64_t X86_GS_BASE_OFFSET = 12296;

enum class POp : uint8_t {
    COPY,
    LOAD,
    STORE,
    BRANCH,
    CBRANCH,
    BRANCHIND,
    CALL,
    CALLIND,
    RETURN,
    TRAP,
    SYSCALL,
    MEMORY_BARRIER,
    CACHE_HINT,
    X86_XSTATE_SAVE,
    X86_XSTATE_RESTORE,
    X86_SYSTEM,
    X86_STRING,
    X86_DIVIDE,
    INT_EQUAL,
    INT_NOTEQUAL,
    INT_LESS,
    INT_SLESS,
    INT_LESSEQUAL,
    INT_SLESSEQUAL,
    INT_ZEXT,
    INT_SEXT,
    INT_ADD,
    INT_SUB,
    INT_NEGATE,
    INT_NOT,
    INT_XOR,
    INT_AND,
    INT_OR,
    INT_LEFT,
    INT_RIGHT,
    INT_SRIGHT,
    INT_MULT,
    INT_DIV,
    INT_SDIV,
    INT_REM,
    INT_SREM,
    INT_CARRY,
    INT_SCARRY,
    INT_SBORROW,
    INT_PARITY,
    INT_POPCOUNT,
    INT_COUNT_LEADING_ZERO,
    INT_COUNT_TRAILING_ZERO,
    INT_PDEP,
    INT_PEXT,
    INT_BSWAP,
    INT_CRC32C,
    INT_MULT_OVERFLOW,
    INT_SMULT_OVERFLOW,
    FLOAT_EQUAL,
    FLOAT_NOTEQUAL,
    FLOAT_LESS,
    FLOAT_LESSEQUAL,
    FLOAT_NAN,
    FLOAT_ADD,
    FLOAT_SUB,
    FLOAT_MULT,
    FLOAT_DIV,
    FLOAT_NEG,
    FLOAT_ABS,
    FLOAT_SQRT,
    FLOAT_MIN,
    FLOAT_MAX,
    FLOAT_ROUND,
    FLOAT_SIN,
    FLOAT_COS,
    FLOAT_TAN,
    FLOAT_ATAN2,
    FLOAT_LOG2,
    FLOAT_EXP2,
    FLOAT_REMAINDER,
    FLOAT_SCALE,
    // Conversion metadata is carried in PcodeOp::aux.  INT2FLOAT stores the
    // destination IEEE lane width, FLOAT2INT stores the source lane width and
    // bit 15 selects truncation, and FLOAT2FLOAT stores source/destination
    // widths in the low/high byte respectively.
    FLOAT_INT2FLOAT,
    FLOAT_FLOAT2INT,
    FLOAT_FLOAT2FLOAT,
    SIMD_MASK,
    // Lane-oriented operations used by SSE, AVX and AVX-512.  The low byte
    // of aux is the lane width.  Operation-specific mode bits are documented
    // at their emitters/evaluator; keeping these as first-class p-code avoids
    // opaque helper calls and makes the semantics executable in tests.
    SIMD_COMPARE,
    SIMD_COMPARE_MASK,
    SIMD_MOVEMASK,
    SIMD_ADDSUB,
    SIMD_BLEND,
    SIMD_FP_COMPARE,
    SIMD_COMPARE_CHECK,
    SIMD_HORIZONTAL,
    // Packed conversion and dot-product operations.  Conversion aux stores
    // source lane width in the low byte and destination lane width in the
    // high seven bits; bit 15 selects truncation for FLOAT2INT.
    SIMD_INT2FLOAT,
    SIMD_FLOAT2INT,
    SIMD_FLOAT2FLOAT,
    SIMD_DOT_PRODUCT,
    SIMD_ABS,
    SIMD_INT_HORIZONTAL,
    SIMD_STRING_COMPARE,
    SIMD_STRING_MASK,
    SIMD_MULTIPLY,
    SIMD_SIGN,
    SIMD_BYTE_SHIFT,
    SIMD_TEST,
    SIMD_APPROX,
    SIMD_ROUND,
    SIMD_PERMUTE128,
    SIMD_EXTEND,
    SIMD_ZERO_UPPER,
    SIMD_SATURATE,
    SIMD_UNPACK,
    SIMD_PACK,
    SIMD_SHUFFLE,
    SIMD_SHIFT,
    SIMD_EXTRACT,
    SIMD_INSERT,
    SIMD_BROADCAST,
    SIMD_GATHER,
    SIMD_SCATTER,
    SIMD_AVERAGE,
    SIMD_MINMAX,
    SIMD_SAD,
    AES_ENC,
    AES_DEC,
    AES_IMC,
    AES_KEYGEN,
    GF2P8_MUL,
    GF2P8_AFFINE,
    GF2P8_AFFINE_INV,
    CARRYLESS_MULT,
    SHA1_MSG1,
    SHA1_MSG2,
    SHA1_NEXTE,
    SHA1_RNDS4,
    SHA256_MSG1,
    SHA256_MSG2,
    SHA256_RNDS2,
    X86_GUARD,
    X87_REQUIRE,
    X87_PUSH,
    X87_POP,
    X87_FREE,
    X87_TAG,
    X87_EXAMINE,
    X87_ROTATE,
    X87_CONSTANT,
    X87_COMPARE_CHECK,
    BOOL_NEGATE,
    BOOL_XOR,
    BOOL_AND,
    BOOL_OR,
    PIECE,
    SUBPIECE,
    SELECT,
    UNIMPLEMENTED,
};

enum class X86SystemAction : uint8_t {
    None = 0, Cpuid, ReadMsr, WriteMsr, GetXbv, SetXbv, ClearTaskSwitched,
    SwapGs, DisableInterrupts, EnableInterrupts, Halt, InvalidatePage,
    InvalidateCaches, WriteBackInvalidateCaches, ReadControl, WriteControl,
    StoreGdtr, StoreIdtr, LoadGdtr, LoadIdtr, StoreLdt, LoadLdt,
    StoreTask, LoadTask, PortIn, PortOut,
    SignExtendHigh, MultiplyAccumulator, CompareExchangeWide, EnterFrame,
    PopValue, PushFlags, PopFlags, LoadAhFlags, StoreAhFlags, SetAlCarry,
    LoadMxcsr, StoreMxcsr, StringPortIn, StringPortOut,
    ReadTimestamp, ReadTimestampAux, ReadPerformanceCounter,
    RandomValue, ReadProcessorId, ReadShadowStack,
    ArmMonitor, MonitorWait, SetAccessControl,
    FastSystemCall, FastSystemReturn, SoftwareInterrupt,
    InterruptReturn, FarReturn, AccessRights, SegmentLimit, TranslateByte,
};

const char* pOpName(POp p);

struct Varnode {
    uint64_t id = 0;
    enum Kind { REGISTER, CONST, UNIQUE, RAM } kind = CONST;
    uint64_t offset = 0; // reg offset / const value / unique id / ram address
    int size = 0;        // bytes
    std::string name;    // register name / temp name

    bool isConst() const { return kind == CONST; }
};

struct PcodeOp {
    POp op = POp::UNIMPLEMENTED;
    uint64_t out = 0; // varnode id, 0 = no output
    uint64_t in0 = 0, in1 = 0, in2 = 0;
    uint16_t aux = 0; // operation-specific metadata (e.g. SIMD lane width)
};

// p-code translation of a single machine instruction
struct PcodeInsn {
    uint64_t addr = 0;
    uint64_t nextAddr = 0;
    std::string text; // disassembly text
    int size = 0;
    Insn::Kind kind = Insn::OTHER;
    uint64_t target = 0;
    bool targetKnown = false;

    std::vector<PcodeOp> ops;
    std::map<uint64_t, Varnode> varnodes; // id -> varnode
    std::map<std::string, uint64_t> named; // operand name -> varnode id

    const Varnode* find(uint64_t id) const {
        auto it = varnodes.find(id);
        return it == varnodes.end() ? nullptr : &it->second;
    }
    std::string varnodeName(uint64_t id) const;
};

// Straightforward p-code interpreter. Registers/ram not provided are
// "unknown"; arithmetic on unknown yields unknown. Used both for semantic
// validation (concrete register values) and branch-target folding.
class PcodeEvaluator {
public:
    // Own the instruction so constructing an evaluator from a temporary
    // disassembly result cannot leave a dangling reference.
    explicit PcodeEvaluator(const PcodeInsn& insn) : insn_(insn) {}

    std::map<uint64_t, uint64_t> regs; // register offset -> value
    std::map<uint64_t, std::vector<uint8_t>> wideRegs; // SIMD registers
    std::map<uint64_t, uint8_t> ram;   // ram address -> byte
    uint64_t xcr0 = 0x7;               // x87 | SSE | AVX enabled by default
    uint64_t xss = 0;                  // supervisor-state component mask
    uint32_t mxcsr = 0x1f80;           // architectural SSE control/status
    uint8_t privilegeLevel = 3;
    uint8_t iopl = 0;
    // Feature bits default to present so existing concrete execution remains
    // backwards compatible.  Tests/clients can clear individual bits to
    // model CPUID-disabled instruction families.
    uint64_t x86Features = ~0ULL;
    std::map<uint64_t, std::array<uint32_t, 4>> cpuidLeaves;
    std::map<uint32_t, uint64_t> controlRegs;
    std::map<uint32_t, uint64_t> modelSpecificRegs;
    std::map<uint16_t, uint32_t> ioPorts;
    std::map<uint32_t, uint64_t> performanceCounters;
    struct DescriptorTable {
        uint16_t limit = 0;
        uint64_t base = 0;
    };
    DescriptorTable gdtr, idtr;
    uint16_t ldtr = 0;
    uint16_t taskRegister = 0;
    bool interruptsEnabled = true;
    bool interruptShadow = false;
    bool halted = false;
    bool alignmentAccessEnabled = false;
    bool monitorArmed = false;
    uint64_t monitoredAddress = 0;
    uint64_t timestampCounter = 0;
    uint32_t processorId = 0;
    uint64_t shadowStackPointer = 0;
    uint64_t randomState = 0x9e3779b97f4a7c15ULL;
    uint64_t instructionPointer = 0;
    uint16_t codeSegment = 0x33;
    uint16_t stackSegment = 0x2b;
    uint64_t cacheGeneration = 0;
    std::vector<uint64_t> invalidatedPages;

    enum class X86Fault : uint8_t {
        DivideError = 0, InvalidOpcode = 6, DeviceNotAvailable = 7,
        GeneralProtection = 13,
        X87FloatingPoint = 16, SimdFloatingPoint = 19,
    };
    struct FaultInfo {
        X86Fault vector = X86Fault::InvalidOpcode;
        uint32_t errorCode = 0;
        uint64_t address = 0;
    };
    std::optional<FaultInfo> fault;

    void run();
    std::optional<uint64_t> regValue(uint64_t offset) const;
    std::optional<uint64_t> varnodeValue(uint64_t id) const;
    std::optional<std::vector<uint8_t>> wideValue(uint64_t id) const;
    std::optional<uint64_t> lastBranchTarget() const { return lastBranch_; }
    bool branchTaken() const { return branchTaken_; }

private:
    PcodeInsn insn_;
    std::map<uint64_t, std::optional<uint64_t>> vals_;
    std::map<uint64_t, std::optional<std::vector<uint8_t>>> wideVals_;
    std::optional<uint64_t> lastBranch_;
    bool branchTaken_ = false;
    bool suppressRemaining_ = false;
    std::optional<uint64_t> evalOp(const PcodeOp& op);
    std::optional<std::vector<uint8_t>> evalWideOp(const PcodeOp& op);
};

} // namespace centrifuge
