/* 27. Compression family. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(cp_rle_byte);
int cp_rle_byte(const uint8_t *in, int n, uint8_t *out) {
    MARK(cp_rle_byte);
    int k = 0;
    for (int i = 0; i < n;) {
        int run = 1;
        while (i + run < n && in[i + run] == in[i] && run < 255) run++;
        out[k++] = (uint8_t)run;
        out[k++] = in[i];
        i += run;
    }
    return k;
}
TAG(cp_rle_word);
int cp_rle_word(const uint16_t *in, int n, uint16_t *out) {
    MARK(cp_rle_word);
    int k = 0;
    for (int i = 0; i < n;) {
        int run = 1;
        while (i + run < n && in[i + run] == in[i] && run < 65535) run++;
        out[k++] = (uint16_t)run;
        out[k++] = in[i];
        i += run;
    }
    return k;
}
TAG(cp_huffman_lengths);
void cp_huffman_lengths(const uint64_t *freq, int n, int *depth) {
    MARK(cp_huffman_lengths);
    /* simple O(n^2) two-queue merge, computing code lengths only */
    uint64_t q1[64], q2[64];
    int h1 = 0, t1 = n, h2 = 0, t2 = 0;
    for (int i = 0; i < n; i++) q1[i] = freq[i];
    for (int i = 0; i < n - 1; i++) {
        uint64_t a = h1 < t1 && (h2 >= t2 || q1[h1] <= q2[h2]) ? q1[h1++]
                                                               : q2[h2++];
        uint64_t b = h1 < t1 && (h2 >= t2 || q1[h1] <= q2[h2]) ? q1[h1++]
                                                               : q2[h2++];
        q2[t2++] = a + b;
        depth[i] = 1;
    }
    for (int i = 0; i < n; i++) depth[i] = i < n - 1 ? depth[i] : 0;
}
TAG(cp_lz77);
int cp_lz77(const uint8_t *in, int n, uint8_t *out) {
    MARK(cp_lz77);
    int k = 0;
    for (int i = 0; i < n;) {
        int best_len = 0, best_off = 0;
        for (int off = 1; off <= i && off < 256; off++) {
            int len = 0;
            while (i + len < n && len < 255 && in[i + len] == in[i - off + len])
                len++;
            if (len > best_len) { best_len = len; best_off = off; }
        }
        if (best_len >= 3) {
            out[k++] = (uint8_t)best_off;
            out[k++] = (uint8_t)best_len;
            i += best_len;
        } else {
            out[k++] = 0;
            out[k++] = in[i++];
        }
    }
    return k;
}
TAG(cp_lzss);
int cp_lzss(const uint8_t *in, int n, uint8_t *out) {
    MARK(cp_lzss);
    /* flag-byte group of 8 tokens */
    int k = 0, i = 0;
    while (i < n) {
        int flag_pos = k++;
        uint8_t flags = 0;
        for (int b = 0; b < 8 && i < n; b++) {
            int best_len = 0, best_off = 0;
            for (int off = 1; off <= i && off < 4096; off++) {
                int len = 0;
                while (i + len < n && len < 18 && in[i + len] == in[i - off + len])
                    len++;
                if (len > best_len) { best_len = len; best_off = off; }
            }
            if (best_len >= 3) {
                flags |= 1 << b;
                out[k++] = (uint8_t)(best_off >> 4);
                out[k++] = (uint8_t)((best_off & 15) << 4 | (best_len - 3));
                i += best_len;
            } else {
                out[k++] = in[i++];
            }
        }
        out[flag_pos] = flags;
    }
    return k;
}
TAG(cp_lzw);
int cp_lzw(const uint8_t *in, int n, uint16_t *out) {
    MARK(cp_lzw);
    static int dict[4096][2];
    int ncodes = 256, k = 0;
    int cur = in[0];
    for (int i = 1; i < n; i++) {
        int c = in[i], found = -1;
        for (int d = 256; d < ncodes; d++)
            if (dict[d][0] == cur && dict[d][1] == c) { found = d; break; }
        if (found >= 0) cur = found;
        else {
            out[k++] = (uint16_t)cur;
            if (ncodes < 4096) { dict[ncodes][0] = cur; dict[ncodes][1] = c; ncodes++; }
            cur = c;
        }
    }
    out[k++] = (uint16_t)cur;
    return k;
}
TAG(cp_delta_encode);
void cp_delta_encode(int32_t *a, int n) {
    MARK(cp_delta_encode);
    for (int i = n - 1; i > 0; i--) a[i] -= a[i - 1];
}
TAG(cp_bit_pack);
int cp_bit_pack(const uint32_t *vals, int n, int bits, uint8_t *out) {
    MARK(cp_bit_pack);
    uint32_t acc = 0;
    int nbits = 0, k = 0;
    for (int i = 0; i < n; i++) {
        acc |= (vals[i] & ((1u << bits) - 1)) << nbits;
        nbits += bits;
        while (nbits >= 8) {
            out[k++] = (uint8_t)acc;
            acc >>= 8;
            nbits -= 8;
        }
    }
    if (nbits) out[k++] = (uint8_t)acc;
    return k;
}
TAG(cp_varint);
int cp_varint(uint64_t v, uint8_t *out) {
    MARK(cp_varint);
    int k = 0;
    do {
        uint8_t b = (uint8_t)(v & 0x7f);
        v >>= 7;
        out[k++] = v ? b | 0x80 : b;
    } while (v);
    return k;
}
TAG(cp_varint_decode);
uint64_t cp_varint_decode(const uint8_t *in, int *used) {
    MARK(cp_varint_decode);
    uint64_t v = 0;
    int shift = 0, k = 0;
    for (;;) {
        uint8_t b = in[k++];
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    *used = k;
    return v;
}
TAG(cp_dict_compress);
int cp_dict_compress(const char *in, const char *const *dict, int ndict,
                     int *ids) {
    MARK(cp_dict_compress);
    int k = 0;
    for (const char *p = in; *p;) {
        int best = -1, best_len = 0;
        for (int d = 0; d < ndict; d++) {
            int len = 0;
            while (p[len] && dict[d][len] && p[len] == dict[d][len]) len++;
            if (len > best_len) { best_len = len; best = d; }
        }
        if (best_len >= 2) { ids[k++] = best; p += best_len; }
        else { ids[k++] = -p[0]; p++; }
    }
    return k;
}
TAG(cp_entropy_decoder_state);
int cp_entropy_decoder_state(uint8_t state, int bit) {
    MARK(cp_entropy_decoder_state);
    /* table-driven arithmetic-decoder state transition (toy) */
    static const uint8_t trans[4][2] = { {1, 2}, {0, 3}, {3, 0}, {2, 1} };
    return trans[state & 3][bit & 1];
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)cp_rle_byte,      (variant_fn)cp_rle_word,
    (variant_fn)cp_huffman_lengths,(variant_fn)cp_lz77,
    (variant_fn)cp_lzss,          (variant_fn)cp_lzw,
    (variant_fn)cp_delta_encode,  (variant_fn)cp_bit_pack,
    (variant_fn)cp_varint,        (variant_fn)cp_varint_decode,
    (variant_fn)cp_dict_compress, (variant_fn)cp_entropy_decoder_state,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}
