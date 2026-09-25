/* 38. Switch & Jump Table family — multi-target switch/jump-table recovery. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(sw_small_dense);
int sw_small_dense(int x) {
    MARK(sw_small_dense);
    switch (x) {
    case 0: return 10;
    case 1: return 11;
    case 2: return 12;
    case 3: return 13;
    default: return -1;
    }
}
TAG(sw_sparse);
int sw_sparse(int x) {
    MARK(sw_sparse);
    /* sparse cases: compiler may use binary search or bitmask */
    switch (x) {
    case 1: return 1;
    case 10: return 10;
    case 100: return 100;
    case 1000: return 1000;
    case 10000: return 10000;
    default: return 0;
    }
}
TAG(sw_fallthrough);
int sw_fallthrough(int x) {
    MARK(sw_fallthrough);
    int r = 0;
    switch (x) {
    case 0: r += 1; /* fallthrough */
    case 1: r += 2; /* fallthrough */
    case 2: r += 4; break;
    case 3: r += 8; /* fallthrough */
    default: r += 16;
    }
    return r;
}
TAG(sw_big_dense);
int sw_big_dense(unsigned x) {
    MARK(sw_big_dense);
    /* 32 dense cases: forces a real jump table */
    switch (x & 31u) {
    case 0: return 0;   case 1: return 1;   case 2: return 4;
    case 3: return 9;   case 4: return 16;  case 5: return 25;
    case 6: return 36;  case 7: return 49;  case 8: return 64;
    case 9: return 81;  case 10: return 100; case 11: return 121;
    case 12: return 144; case 13: return 169; case 14: return 196;
    case 15: return 225; case 16: return 256; case 17: return 289;
    case 18: return 324; case 19: return 361; case 20: return 400;
    case 21: return 441; case 22: return 484; case 23: return 529;
    case 24: return 576; case 25: return 625; case 26: return 676;
    case 27: return 729; case 28: return 784; case 29: return 841;
    case 30: return 900; case 31: return 961;
    }
    return -1;
}
TAG(sw_negative_cases);
int sw_negative_cases(int x) {
    MARK(sw_negative_cases);
    switch (x) {
    case -100: return 1;
    case -10: return 2;
    case -1: return 3;
    case 0: return 4;
    case 1: return 5;
    case 100: return 6;
    default: return 0;
    }
}
TAG(sw_char_switch);
int sw_char_switch(char c) {
    MARK(sw_char_switch);
    switch (c) {
    case 'a': return 1;
    case 'b': return 2;
    case 'c': return 3;
    case 'z': return 26;
    default: return -1;
    }
}
TAG(sw_string_lookup_style);
int sw_string_lookup_style(int op) {
    MARK(sw_string_lookup_style);
    /* enum-like dispatch: add/sub/mul/div/mod/and/or/xor/shl/shr */
    switch (op) {
    case 0: return 0xA0D0;
    case 1: return 0x5E81;
    case 2: return 0xE012;
    case 3: return 0xD1E3;
    case 4: return 0xD10C;
    case 5: return 0xA0D5;
    case 6: return 0x0FD6;
    case 7: return 0xDF17;
    case 8: return 0x5FD8;
    case 9: return 0x5FD9;
    default: return -1;
    }
}
TAG(sw_nested_switch);
int sw_nested_switch(int a, int b) {
    MARK(sw_nested_switch);
    switch (a) {
    case 0:
        switch (b) {
        case 0: return 0;
        case 1: return 1;
        default: return -1;
        }
    case 1:
        switch (b) {
        case 0: return 10;
        case 1: return 11;
        case 2: return 12;
        default: return -10;
        }
    default:
        return 99;
    }
}
TAG(sw_switch_in_loop);
int sw_switch_in_loop(const int *ops, int n) {
    MARK(sw_switch_in_loop);
    int acc = 0;
    for (int i = 0; i < n; i++) {
        switch (ops[i] & 7) {
        case 0: acc += 1; break;
        case 1: acc -= 1; break;
        case 2: acc <<= 1; break;
        case 3: acc >>= 1; break;
        case 4: acc ^= 0x5A; break;
        case 5: acc |= 0x0F; break;
        case 6: acc &= 0xF0; break;
        default: acc = 0; break;
        }
    }
    return acc;
}
TAG(sw_shared_arms);
int sw_shared_arms(int x) {
    MARK(sw_shared_arms);
    switch (x) {
    case 0:
    case 1:
    case 2:
        return 100;
    case 3:
    case 4:
        return 200;
    case 5:
        return 300;
    default:
        return -1;
    }
}
TAG(sw_two_way_branchy);
int sw_two_way_branchy(int x, int y) {
    MARK(sw_two_way_branchy);
    /* mix of if/else and switch */
    if (x < 0) return -1;
    if (y > 100) return 100;
    switch (x & 3) {
    case 0: return y;
    case 1: return y + x;
    case 2: return y - x;
    default: return y * x;
    }
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)sw_small_dense,      (variant_fn)sw_sparse,
    (variant_fn)sw_fallthrough,      (variant_fn)sw_big_dense,
    (variant_fn)sw_negative_cases,   (variant_fn)sw_char_switch,
    (variant_fn)sw_string_lookup_style, (variant_fn)sw_nested_switch,
    (variant_fn)sw_switch_in_loop,   (variant_fn)sw_shared_arms,
    (variant_fn)sw_two_way_branchy,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
