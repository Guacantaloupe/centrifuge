// centrifuge - a Ghidra reimplementation in C++17
// memory.hpp - address-space / memory-image model
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace centrifuge {

// Permission bits. Values deliberately match ELF PF_* flags (R=4, W=2, X=1).
enum class Perm : int {
    X = 1,
    W = 2,
    R = 4,
};

struct MemoryBlock {
    std::string name;
    uint64_t base = 0;
    std::vector<uint8_t> data;
    int perm = 0; // OR of Perm values

    bool contains(uint64_t addr) const {
        return addr >= base && (addr - base) < data.size();
    }
    uint64_t end() const { return base + data.size(); }
};

// A flat, non-overlapping set of mapped blocks. This is the "program image"
// that loaders (ELF/PE/...) populate and analysis passes read from.
class MemoryImage {
public:
    // Returns false if `data` is empty or the block would overlap an existing one.
    bool addBlock(std::string name, uint64_t base, std::vector<uint8_t> data, int perm);

    const MemoryBlock* blockAt(uint64_t addr) const;
    bool isExecutable(uint64_t addr) const;
    bool isReadable(uint64_t addr) const;

    // Write n bytes at addr into the containing block (in-place loader
    // fixups such as PE IAT binding). False if unmapped or out of bounds.
    bool write(uint64_t addr, const void* src, size_t n);

    // Read exactly n bytes at addr. False if out of bounds.
    bool read(uint64_t addr, void* dst, size_t n) const;

    // Read a NUL-terminated string (maxLen cap). True on success/truncation,
    // false only if nothing could be read.
    bool readString(uint64_t addr, std::string& out, size_t maxLen) const;

    const std::vector<MemoryBlock>& blocks() const { return blocks_; }
    bool empty() const { return blocks_.empty(); }

private:
    std::vector<MemoryBlock> blocks_;
};

} // namespace centrifuge
