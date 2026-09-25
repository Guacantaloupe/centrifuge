/* 40. Pathological CFG family — goto, computed dispatch, irreducible shapes.
 * Per contract: irreducible CFGs must keep goto rather than force structure. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(pt_goto_forward);
int pt_goto_forward(int x) {
    MARK(pt_goto_forward);
    if (x < 0) goto neg;
    x += 10;
    goto done;
neg:
    x = -x;
done:
    return x;
}
TAG(pt_goto_loop);
int pt_goto_loop(int n) {
    MARK(pt_goto_loop);
    int i = 0, s = 0;
loop:
    if (i >= n) goto out;
    s += i * 2;
    i++;
    goto loop;
out:
    return s;
}
TAG(pt_goto_state_machine);
int pt_goto_state_machine(int input) {
    MARK(pt_goto_state_machine);
    int state = 0, acc = 0;
    int tok = input & 3;
s0:
    if (tok == 0) { acc += 1; goto s1; }
    if (tok == 1) { acc -= 1; goto s2; }
    goto done;
s1:
    acc *= 2;
    tok = (tok + 1) & 3;
    goto s0;
s2:
    acc ^= 0x55;
    tok = (tok + 2) & 3;
    if (acc & 0x100) goto done;
    goto s0;
done:
    return acc + state;
}
TAG(pt_computed_goto_style);
int pt_computed_goto_style(int sel, int v) {
    MARK(pt_computed_goto_style);
    /* dispatch table over helper labels via switch (portable computed goto) */
    int r = v;
    switch (sel & 3) {
    case 0: goto add;
    case 1: goto sub;
    case 2: goto mul;
    default: goto fin;
    }
add:
    r += 7;
    goto fin;
sub:
    r -= 3;
    goto fin;
mul:
    r *= 5;
fin:
    return r;
}
TAG(pt_several_gotos_one_label);
int pt_several_gotos_one_label(int x) {
    MARK(pt_several_gotos_one_label);
    int r = 0;
    if (x & 1) goto merge;
    r += 1;
    if (x & 2) goto merge;
    r += 2;
    if (x & 4) goto merge;
    r += 4;
merge:
    return r + x;
}
TAG(pt_deeply_nested_breakout);
int pt_deeply_nested_breakout(int n) {
    MARK(pt_deeply_nested_breakout);
    int s = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < n; j++) {
            for (int k = 0; k < n; k++) {
                if (i * j * k > 50) goto bail;
                s += i + j + k;
            }
        }
    }
    return s;
bail:
    return -s;
}
TAG(pt_error_chain_goto);
int pt_error_chain_goto(int step) {
    MARK(pt_error_chain_goto);
    int rc = 0;
    if (step == 0) goto fail1;
    rc = 1;
    if (step == 1) goto fail2;
    rc = 2;
    if (step == 2) goto cleanup;
    rc = 3;
    goto cleanup;
fail1:
    rc = -1;
    goto cleanup;
fail2:
    rc = -2;
cleanup:
    return rc * 10;
}
TAG(pt_cross_jump_shape);
int pt_cross_jump_shape(int a, int b) {
    MARK(pt_cross_jump_shape);
    /* structured code whose optimized CFG may become irreducible */
    int x = a, y = b;
    if (a > b) {
        x -= b;
        if (x > 10) y += x;
    } else {
        y -= a;
        if (y > 10) x += y;
    }
    if ((x + y) & 1) goto odd;
    return x * y;
odd:
    return x + y;
}
TAG(pt_duff_device);
int pt_duff_device(int *to, int count) {
    MARK(pt_duff_device);
    /* classic duff's device: loop/switch interleave */
    int sum = 0;
    int n = (count + 7) / 8;
    switch (count % 8) {
    case 0: do { *to++ = sum++; /* fallthrough */
    case 7:      *to++ = sum++; /* fallthrough */
    case 6:      *to++ = sum++; /* fallthrough */
    case 5:      *to++ = sum++; /* fallthrough */
    case 4:      *to++ = sum++; /* fallthrough */
    case 3:      *to++ = sum++; /* fallthrough */
    case 2:      *to++ = sum++; /* fallthrough */
    case 1:      *to++ = sum++;
            } while (--n > 0);
    }
    return sum;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)pt_goto_forward,       (variant_fn)pt_goto_loop,
    (variant_fn)pt_goto_state_machine, (variant_fn)pt_computed_goto_style,
    (variant_fn)pt_several_gotos_one_label, (variant_fn)pt_deeply_nested_breakout,
    (variant_fn)pt_error_chain_goto,   (variant_fn)pt_cross_jump_shape,
    (variant_fn)pt_duff_device,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
