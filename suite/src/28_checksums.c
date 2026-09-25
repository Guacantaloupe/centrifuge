/* 28. Checksums / Hash Primitives family — compiler idiom recognition. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(ck_xor_checksum);
uint8_t ck_xor_checksum(const uint8_t *d, size_t n) {
    MARK(ck_xor_checksum);
    uint8_t x = 0;
    for (size_t i = 0; i < n; i++) x ^= d[i];
    return x;
}
TAG(ck_adler32);
uint32_t ck_adler32(const uint8_t *d, size_t n) {
    MARK(ck_adler32);
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n; i++) {
        a = (a + d[i]) % 65521;
        b = (b + a) % 65521;
    }
    return b << 16 | a;
}
TAG(ck_fletcher16);
uint16_t ck_fletcher16(const uint8_t *d, size_t n) {
    MARK(ck_fletcher16);
    uint16_t s0 = 0, s1 = 0;
    for (size_t i = 0; i < n; i++) {
        s0 = (uint16_t)((s0 + d[i]) % 255);
        s1 = (uint16_t)((s1 + s0) % 255);
    }
    return (uint16_t)(s1 << 8 | s0);
}
TAG(ck_crc16);
uint16_t ck_crc16(const uint8_t *d, size_t n) {
    MARK(ck_crc16);
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < n; i++) {
        crc ^= d[i];
        for (int b = 0; b < 8; b++)
            crc = crc & 1 ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
    }
    return crc;
}
TAG(ck_crc32_bitwise);
uint32_t ck_crc32_bitwise(const uint8_t *d, size_t n) {
    MARK(ck_crc32_bitwise);
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= d[i];
        for (int b = 0; b < 8; b++)
            crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
    }
    return ~crc;
}
TAG(ck_crc32_table);
uint32_t ck_crc32_table(const uint8_t *d, size_t n) {
    MARK(ck_crc32_table);
    static uint32_t tab[256];
    if (!tab[1]) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int b = 0; b < 8; b++)
                c = c & 1 ? (c >> 1) ^ 0xEDB88320u : c >> 1;
            tab[i] = c;
        }
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) crc = tab[(crc ^ d[i]) & 255] ^ (crc >> 8);
    return ~crc;
}
TAG(ck_crc32_slicing8);
uint32_t ck_crc32_slicing8(const uint8_t *d, size_t n) {
    MARK(ck_crc32_slicing8);
    /* process 4 bytes per step with the same table (slicing-by-4 shape) */
    static uint32_t tab[256];
    if (!tab[1]) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int b = 0; b < 8; b++)
                c = c & 1 ? (c >> 1) ^ 0xEDB88320u : c >> 1;
            tab[i] = c;
        }
    }
    uint32_t crc = 0xFFFFFFFFu;
    while (n >= 4) {
        crc ^= (uint32_t)d[0] | (uint32_t)d[1] << 8 |
               (uint32_t)d[2] << 16 | (uint32_t)d[3] << 24;
        crc = tab[crc & 255] ^ (crc >> 8);
        crc = tab[crc & 255] ^ (crc >> 8);
        crc = tab[crc & 255] ^ (crc >> 8);
        crc = tab[crc & 255] ^ (crc >> 8);
        d += 4;
        n -= 4;
    }
    while (n--) crc = tab[(crc ^ *d++) & 255] ^ (crc >> 8);
    return ~crc;
}
TAG(ck_fnv1a);
uint64_t ck_fnv1a(const uint8_t *d, size_t n) {
    MARK(ck_fnv1a);
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) {
        h ^= d[i];
        h *= 1099511628211ull;
    }
    return h;
}
TAG(ck_murmur_style);
uint64_t ck_murmur_style(uint64_t k) {
    MARK(ck_murmur_style);
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdull;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ull;
    k ^= k >> 33;
    return k;
}
TAG(ck_xxhash_mix);
uint64_t ck_xxhash_mix(uint64_t acc, uint64_t lane) {
    MARK(ck_xxhash_mix);
    const uint64_t P1 = 11400714785074694797ull;
    const uint64_t P2 = 14029467366897019727ull;
    acc += lane * P2;
    acc = (acc << 31) | (acc >> 33);
    return acc * P1;
}
TAG(ck_rolling_hash);
uint32_t ck_rolling_hash(const uint8_t *d, size_t n, size_t w) {
    MARK(ck_rolling_hash);
    const uint32_t base = 257;
    uint32_t h = 0, pow = 1;
    for (size_t i = 0; i < w; i++) {
        h = h * base + d[i];
        pow *= base;
    }
    uint32_t best = h;
    for (size_t i = w; i < n; i++) {
        h = h * base - d[i - w] * pow + d[i];
        best ^= h;
    }
    return best;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ck_xor_checksum,   (variant_fn)ck_adler32,
    (variant_fn)ck_fletcher16,     (variant_fn)ck_crc16,
    (variant_fn)ck_crc32_bitwise,  (variant_fn)ck_crc32_table,
    (variant_fn)ck_crc32_slicing8, (variant_fn)ck_fnv1a,
    (variant_fn)ck_murmur_style,   (variant_fn)ck_xxhash_mix,
    (variant_fn)ck_rolling_hash,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}
