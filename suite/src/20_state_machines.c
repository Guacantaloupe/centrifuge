/* 20. State Machine family — the switch/jump-table recovery stressor. */
#include <stddef.h>
#include <stdint.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

TAG(fsm_switch_2);
int fsm_switch_2(int state, int input) {
    MARK(fsm_switch_2);
    switch (state) {
        case 0: return input ? 1 : 0;
        case 1: return input ? 1 : 0;
        default: return -1;
    }
}
TAG(fsm_switch_4);
int fsm_switch_4(int state, int input) {
    MARK(fsm_switch_4);
    switch (state) {
        case 0: return input ? 1 : 0;
        case 1: return input ? 3 : 2;
        case 2: return input ? 0 : 3;
        case 3: return input ? 2 : 1;
        default: return -1;
    }
}
TAG(fsm_switch_8);
int fsm_switch_8(int state, int input) {
    MARK(fsm_switch_8);
    switch (state) {
        case 0: return 1;
        case 1: return input ? 2 : 3;
        case 2: return input ? 4 : 5;
        case 3: return input ? 6 : 7;
        case 4: return 0;
        case 5: return 1;
        case 6: return 2;
        case 7: return input ? 7 : 0;
        default: return -1;
    }
}
TAG(fsm_switch_16);
int fsm_switch_16(int state, int input) {
    MARK(fsm_switch_16);
    switch (state) {
        case 0: return 1;
        case 1: return 2;
        case 2: return 3;
        case 3: return 4;
        case 4: return 5;
        case 5: return 6;
        case 6: return 7;
        case 7: return 8;
        case 8: return 9;
        case 9: return input ? 10 : 12;
        case 10: return 11;
        case 11: return 0;
        case 12: return 13;
        case 13: return 14;
        case 14: return 15;
        case 15: return input ? 15 : 0;
        default: return -1;
    }
}
TAG(fsm_switch_32);
int fsm_switch_32(int state, int input) {
    MARK(fsm_switch_32);
    switch (state) {
        case 0: return 1;
        case 1: return 2;
        case 2: return 3;
        case 3: return 4;
        case 4: return 5;
        case 5: return 6;
        case 6: return 7;
        case 7: return 8;
        case 8: return 9;
        case 9: return 10;
        case 10: return 11;
        case 11: return 12;
        case 12: return 13;
        case 13: return 14;
        case 14: return 15;
        case 15: return 16;
        case 16: return 17;
        case 17: return 18;
        case 18: return 19;
        case 19: return 20;
        case 20: return 21;
        case 21: return 22;
        case 22: return 23;
        case 23: return 24;
        case 24: return input ? 25 : 28;
        case 25: return 26;
        case 26: return 27;
        case 27: return 0;
        case 28: return 29;
        case 29: return 30;
        case 30: return 31;
        case 31: return input ? 31 : 0;
        default: return -1;
    }
}
TAG(fsm_switch_64);
int fsm_switch_64(int state, int input) {
    MARK(fsm_switch_64);
    switch (state) {
        case 0: return 1;
        case 1: return 2;
        case 2: return 3;
        case 3: return 4;
        case 4: return 5;
        case 5: return 6;
        case 6: return 7;
        case 7: return 8;
        case 8: return 9;
        case 9: return 10;
        case 10: return 11;
        case 11: return 12;
        case 12: return 13;
        case 13: return 14;
        case 14: return 15;
        case 15: return 16;
        case 16: return 17;
        case 17: return 18;
        case 18: return 19;
        case 19: return 20;
        case 20: return 21;
        case 21: return 22;
        case 22: return 23;
        case 23: return 24;
        case 24: return 25;
        case 25: return 26;
        case 26: return 27;
        case 27: return 28;
        case 28: return 29;
        case 29: return 30;
        case 30: return 31;
        case 31: return 32;
        case 32: return 33;
        case 33: return 34;
        case 34: return 35;
        case 35: return 36;
        case 36: return 37;
        case 37: return 38;
        case 38: return 39;
        case 39: return 40;
        case 40: return 41;
        case 41: return 42;
        case 42: return 43;
        case 43: return 44;
        case 44: return 45;
        case 45: return 46;
        case 46: return 47;
        case 47: return 48;
        case 48: return 49;
        case 49: return 50;
        case 50: return 51;
        case 51: return 52;
        case 52: return 53;
        case 53: return 54;
        case 54: return 55;
        case 55: return 56;
        case 56: return 57;
        case 57: return 58;
        case 58: return 59;
        case 59: return input ? 60 : 63;
        case 60: return 61;
        case 61: return 62;
        case 62: return 0;
        case 63: return input ? 63 : 0;
        default: return -1;
    }
}
TAG(fsm_sparse);
int fsm_sparse(int state, int input) {
    MARK(fsm_sparse);
    switch (state) {
        case 0: return input ? 1000000 : 7;
        case 7: return input ? 1000000 : 123456;
        case 123456: return 0;
        case 1000000: return input ? 7 : 0;
        default: return -1;
    }
}
TAG(fsm_negative_cases);
int fsm_negative_cases(int state, int input) {
    MARK(fsm_negative_cases);
    switch (state) {
        case -5: return input ? -3 : -1;
        case -3: return input ? -1 : 0;
        case -1: return input ? 0 : -5;
        case 0: return input ? 2 : 4;
        case 2: return 3;
        case 4: return 3;
        case 3: return 5;
        default: return -5;
    }
}
TAG(fsm_fallthrough);
int fsm_fallthrough(int state, int input) {
    MARK(fsm_fallthrough);
    int code = 0;
    switch (state) {
        case 0:
        case 1:
        case 2:
            code = 10; break;
        case 3:
            code = 20;
            /* fallthrough */
        case 4:
            code += input ? 1 : 2;
            break;
        default:
            code = -1;
    }
    return code;
}
TAG(fsm_nested_switch);
int fsm_nested_switch(int state, int sub, int input) {
    MARK(fsm_nested_switch);
    switch (state) {
        case 0:
            switch (sub) {
                case 0: return input ? 1 : 2;
                case 1: return input ? 3 : 4;
                default: return -1;
            }
        case 1:
            switch (sub) {
                case 0: return 10;
                case 1: return input ? 11 : 12;
                default: return -2;
            }
        default: return -3;
    }
}
TAG(fsm_switch_in_loop);
int fsm_switch_in_loop(const int *inputs, int n) {
    MARK(fsm_switch_in_loop);
    int state = 0;
    for (int i = 0; i < n; i++)
        switch (state) {
            case 0: state = inputs[i] ? 1 : 0; break;
            case 1: state = inputs[i] ? 2 : 0; break;
            case 2: state = 2; break;
            default: state = 0;
        }
    return state;
}
TAG(fsm_loop_in_switch);
int fsm_loop_in_switch(int state, int fuel) {
    MARK(fsm_loop_in_switch);
    int acc = 0;
    switch (state) {
        case 0:
            while (fuel-- > 0) acc += 3;
            break;
        case 1:
            while (fuel-- > 0) acc += 5;
            break;
        case 2:
            for (int i = 0; i < fuel; i++) acc += i;
            break;
        default:
            acc = -1;
    }
    return acc;
}
typedef int (*fsm_fn)(int, int);
static fsm_fn g_trans[] = {
    fsm_switch_2, fsm_switch_4, fsm_switch_8, fsm_switch_16,
};
TAG(fsm_fnptr_table);
int fsm_fnptr_table(int state, int input) {
    MARK(fsm_fnptr_table);
    return g_trans[state & 3](state >> 2, input);
}
TAG(fsm_computed_table);
int fsm_computed_table(int state, int input) {
    MARK(fsm_computed_table);
    static const int next[4][2] = { {0, 1}, {2, 3}, {1, 0}, {3, 2} };
    if (state < 0 || state > 3) return -1;
    return next[state][input & 1];
}
TAG(fsm_error_state);
int fsm_error_state(int state, int input) {
    MARK(fsm_error_state);
    switch (state) {
        case 0: if (input < 0) return 99; return 1;
        case 1: if (input > 100) return 99; return 2;
        case 2: return 3;
        case 99: return 99;
        default: return 99;
    }
}
TAG(fsm_state_substate);
int fsm_state_substate(int state, int substate, int input) {
    MARK(fsm_state_substate);
    int s = state * 4 + substate;
    switch (s) {
        case 0: return input ? 1 : 4;
        case 1: return input ? 2 : 5;
        case 2: return input ? 3 : 6;
        case 3: return 0;
        case 4: return input ? 5 : 8;
        case 5: return input ? 6 : 9;
        case 6: return input ? 7 : 10;
        case 7: return 4;
        case 8: return input ? 0 : 8;
        case 9: return 10;
        case 10: return 11;
        default: return 0;
    }
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)fsm_switch_2,   (variant_fn)fsm_switch_4,
    (variant_fn)fsm_switch_8,   (variant_fn)fsm_switch_16,
    (variant_fn)fsm_switch_32,  (variant_fn)fsm_switch_64,
    (variant_fn)fsm_sparse,     (variant_fn)fsm_negative_cases,
    (variant_fn)fsm_fallthrough,(variant_fn)fsm_nested_switch,
    (variant_fn)fsm_switch_in_loop, (variant_fn)fsm_loop_in_switch,
    (variant_fn)fsm_fnptr_table,(variant_fn)fsm_computed_table,
    (variant_fn)fsm_error_state,(variant_fn)fsm_state_substate,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}
