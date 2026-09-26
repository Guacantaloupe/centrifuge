/* 10. Linked List family. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

struct snode { int val; struct snode *next; };
struct dnode { int val; struct dnode *prev, *next; };
static struct snode g_sn[32];
static struct dnode g_dn[32];

TAG(ll_insert_head);
struct snode *ll_insert_head(struct snode *head, struct snode *n) {
    MARK(ll_insert_head);
    n->next = head;
    return n;
}
TAG(ll_insert_tail);
struct snode *ll_insert_tail(struct snode *head, struct snode *n) {
    MARK(ll_insert_tail);
    n->next = 0;
    if (!head) return n;
    struct snode *p = head;
    while (p->next) p = p->next;
    p->next = n;
    return head;
}
TAG(ll_delete);
struct snode *ll_delete(struct snode *head, int val) {
    MARK(ll_delete);
    struct snode **pp = &head;
    while (*pp) {
        if ((*pp)->val == val) { *pp = (*pp)->next; break; }
        pp = &(*pp)->next;
    }
    return head;
}
TAG(ll_reverse_iter);
struct snode *ll_reverse_iter(struct snode *head) {
    MARK(ll_reverse_iter);
    struct snode *prev = 0, *cur = head;
    while (cur) {
        struct snode *next = cur->next;
        cur->next = prev;
        prev = cur;
        cur = next;
    }
    return prev;
}
TAG(ll_reverse_rec);
struct snode *ll_reverse_rec(struct snode *head, struct snode *acc) {
    MARK(ll_reverse_rec);
    if (!head) return acc;
    struct snode *next = head->next;
    head->next = acc;
    return ll_reverse_rec(next, head);
}
TAG(ll_dinsert);
void ll_dinsert(struct dnode *head, struct dnode *n) {
    MARK(ll_dinsert);
    n->next = head->next;
    n->prev = head;
    head->next->prev = n;
    head->next = n;
}
TAG(ll_ddelete);
void ll_ddelete(struct dnode *n) {
    MARK(ll_ddelete);
    n->prev->next = n->next;
    n->next->prev = n->prev;
}
struct cnode { int val; struct cnode *next; };
TAG(ll_circular_insert);
struct cnode *ll_circular_insert(struct cnode *tail, struct cnode *n) {
    MARK(ll_circular_insert);
    if (!tail) { n->next = n; return n; }
    n->next = tail->next;
    tail->next = n;
    return n;
}
/* intrusive list: node embedded in host struct */
struct ihost { int payload; struct ihost *ilink; };
TAG(ll_intrusive_push);
void ll_intrusive_push(struct ihost **head, struct ihost *h) {
    MARK(ll_intrusive_push);
    h->ilink = *head;
    *head = h;
}
TAG(ll_intrusive_walk);
long long ll_intrusive_walk(struct ihost *head) {
    MARK(ll_intrusive_walk);
    long long sum = 0;
    for (struct ihost *h = head; h; h = h->ilink) sum += h->payload;
    return sum;
}
/* sentinel-based singly list */
struct slist { struct snode head; struct snode *tail; };
TAG(ll_sentinel_init);
void ll_sentinel_init(struct slist *l) {
    MARK(ll_sentinel_init);
    l->head.next = 0;
    l->tail = &l->head;
}
TAG(ll_sentinel_push);
void ll_sentinel_push(struct slist *l, struct snode *n) {
    MARK(ll_sentinel_push);
    n->next = 0;
    l->tail->next = n;
    l->tail = n;
}
TAG(ll_traverse_sum);
long long ll_traverse_sum(struct snode *head) {
    MARK(ll_traverse_sum);
    long long sum = 0;
    for (struct snode *p = head; p; p = p->next) sum += p->val;
    return sum;
}
TAG(ll_pool_alloc);
struct snode *ll_pool_alloc(void) {
    MARK(ll_pool_alloc);
    static int next = 0;
    return &g_sn[next++ & 31];
}
TAG(ll_raii_style);
void ll_raii_style(struct snode **head) {
    /* destroy-whole-list pattern (C stand-in for RAII dtor chains) */
    MARK(ll_raii_style);
    while (*head) {
        struct snode *d = *head;
        *head = d->next;
        d->next = 0;
        d->val = 0;
    }
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ll_insert_head,   (variant_fn)ll_insert_tail,
    (variant_fn)ll_delete,        (variant_fn)ll_reverse_iter,
    (variant_fn)ll_reverse_rec,   (variant_fn)ll_dinsert,
    (variant_fn)ll_ddelete,       (variant_fn)ll_circular_insert,
    (variant_fn)ll_intrusive_push,(variant_fn)ll_intrusive_walk,
    (variant_fn)ll_sentinel_init, (variant_fn)ll_sentinel_push,
    (variant_fn)ll_traverse_sum,  (variant_fn)ll_pool_alloc,
    (variant_fn)ll_raii_style,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return ll_traverse_sum(0) & 0;
}
