#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct widget {
    uint32_t kind;
    uint32_t flags;
    uint64_t serial;
    uint32_t score;
};

static struct widget *make_widget(uint32_t kind) {
    struct widget *w = (struct widget *)malloc(sizeof(struct widget));
    w->kind = kind;
    w->flags = 0;
    w->serial = 0;
    w->score = 0;
    return w;
}

uint64_t use_widget(uint32_t kind) {
    struct widget *p = make_widget(kind);
    p->flags = 1;
    return (uint64_t)p->kind + p->serial + p->score;
}

int main(void) {
    printf("%llu\n", (unsigned long long)use_widget(3));
    return 0;
}
