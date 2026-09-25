// centrifuge - a Ghidra reimplementation in C++17
// memory.cpp - address-space / memory-image model
#include "centrifuge/memory.hpp"

#include <cstring>
#include <limits>

namespace centrifuge {

bool MemoryImage::addBlock(std::string name, uint64_t base,
                           std::vector<uint8_t> data, int perm) {
    if (data.empty()) return false;
    if (data.size() > std::numeric_limits<uint64_t>::max() - base)
        return false;
    const uint64_t end = base + data.size();
    for (const auto& b : blocks_) {
        if (base < b.end() && end > b.base) return false; // overlap
    }
    blocks_.push_back(MemoryBlock{std::move(name), base, std::move(data), perm});
    return true;
}

const MemoryBlock* MemoryImage::blockAt(uint64_t addr) const {
    for (const auto& b : blocks_) {
        if (b.contains(addr)) return &b;
    }
    return nullptr;
}

bool MemoryImage::isExecutable(uint64_t addr) const {
    const auto* b = blockAt(addr);
    return b && (b->perm & static_cast<int>(Perm::X));
}

bool MemoryImage::isReadable(uint64_t addr) const {
    const auto* b = blockAt(addr);
    return b && (b->perm & static_cast<int>(Perm::R));
}

bool MemoryImage::read(uint64_t addr, void* dst, size_t n) const {
    if (n == 0) return true;
    const auto* b = blockAt(addr);
    if (!b) return false;
    const size_t off = static_cast<size_t>(addr - b->base);
    if (off > b->data.size() || n > b->data.size() - off) return false;
    std::memcpy(dst, b->data.data() + off, n);
    return true;
}

bool MemoryImage::readString(uint64_t addr, std::string& out, size_t maxLen) const {
    out.clear();
    for (size_t i = 0; i < maxLen; ++i) {
        if (i > std::numeric_limits<uint64_t>::max() - addr)
            return !out.empty();
        uint8_t c = 0;
        if (!read(addr + i, &c, 1)) return !out.empty();
        if (c == 0) return true;
        out.push_back(static_cast<char>(c));
    }
    return true;
}

bool MemoryImage::write(uint64_t addr, const void* src, size_t n) {
    if (n == 0) return true;
    for (auto& b : blocks_) {
        if (!b.contains(addr)) continue;
        const size_t off = static_cast<size_t>(addr - b.base);
        if (n > b.data.size() - off) return false;
        std::memcpy(b.data.data() + off, src, n);
        return true;
    }
    return false;
}

} // namespace centrifuge
