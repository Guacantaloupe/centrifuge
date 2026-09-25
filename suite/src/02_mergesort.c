/* 02. MergeSort family. */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

static int g_arr[64];

TAG(ms_temp_per_recursion);
void ms_temp_per_recursion(int *a, int n) {
    MARK(ms_temp_per_recursion);
    if (n <= 1) return;
    int m = n / 2;
    int *tmp = (int *)malloc((size_t)n * sizeof(int));
    ms_temp_per_recursion(a, m);
    ms_temp_per_recursion(a + m, n - m);
    int i = 0, j = m, k = 0;
    while (i < m && j < n) tmp[k++] = a[i] <= a[j] ? a[i++] : a[j++];
    while (i < m) tmp[k++] = a[i++];
    while (j < n) tmp[k++] = a[j++];
    for (i = 0; i < n; i++) a[i] = tmp[i];
    free(tmp);
}

static int g_scratch[128];
TAG(ms_shared_scratch);
void ms_shared_scratch(int *a, int *tmp, int lo, int hi) {
    MARK(ms_shared_scratch);
    if (lo >= hi) return;
    int m = (lo + hi) / 2;
    ms_shared_scratch(a, tmp, lo, m);
    ms_shared_scratch(a, tmp, m + 1, hi);
    int i = lo, j = m + 1, k = lo;
    while (i <= m && j <= hi) tmp[k++] = a[i] <= a[j] ? a[i++] : a[j++];
    while (i <= m) tmp[k++] = a[i++];
    while (j <= hi) tmp[k++] = a[j++];
    for (i = lo; i <= hi; i++) a[i] = tmp[i];
}
TAG(ms_shared_entry);
void ms_shared_entry(int *a, int n) {
    MARK(ms_shared_entry);
    ms_shared_scratch(a, g_scratch, 0, n - 1);
}

TAG(ms_bottomup_pow2);
void ms_bottomup_pow2(int *a, int n) {
    MARK(ms_bottomup_pow2);
    for (int w = 1; w < n; w *= 2)
        for (int i = 0; i + w < n; i += 2 * w) {
            int m = i + w - 1, hi = i + 2 * w - 1;
            if (hi >= n) hi = n - 1;
            int i0 = i, j = m + 1, k = 0;
            int tmp[64];
            while (i0 <= m && j <= hi) tmp[k++] = a[i0] <= a[j] ? a[i0++] : a[j++];
            while (i0 <= m) tmp[k++] = a[i0++];
            while (j <= hi) tmp[k++] = a[j++];
            for (i0 = 0; i0 < k; i0++) a[i + i0] = tmp[i0];
        }
}
TAG(ms_bottomup_arbitrary);
void ms_bottomup_arbitrary(int *a, int n) {
    MARK(ms_bottomup_arbitrary);
    for (int w = 1; w < n; w = w * 2 + (w & -w ? 1 : 1))
        for (int i = 0; i < n; i += 2 * w) {
            int m = i + w; if (m > n) m = n;
            int hi = i + 2 * w; if (hi > n) hi = n;
            int i0 = i, j = m, k = 0;
            int tmp[64];
            while (i0 < m && j < hi) tmp[k++] = a[i0] <= a[j] ? a[i0++] : a[j++];
            while (i0 < m) tmp[k++] = a[i0++];
            while (j < hi) tmp[k++] = a[j++];
            for (i0 = 0; i0 < k; i0++) a[i + i0] = tmp[i0];
        }
}

TAG(ms_pointer);
void ms_pointer(int *begin, int *end) {
    MARK(ms_pointer);
    if (end - begin <= 1) return;
    int *mid = begin + (end - begin) / 2;
    ms_pointer(begin, mid);
    ms_pointer(mid, end);
    int tmp[64], *k = tmp;
    int *i = begin, *j = mid;
    while (i < mid && j < end) *k++ = *i <= *j ? *i++ : *j++;
    while (i < mid) *k++ = *i++;
    while (j < end) *k++ = *j++;
    for (i = begin, k = tmp; i < end; i++, k++) *i = *k;
}
TAG(ms_index);
void ms_index(int *a, int lo, int hi) {
    MARK(ms_index);
    if (lo >= hi) return;
    int m = (lo + hi) / 2;
    ms_index(a, lo, m);
    ms_index(a, m + 1, hi);
    int tmp[64], k = 0;
    int i = lo, j = m + 1;
    while (i <= m && j <= hi) tmp[k++] = a[i] <= a[j] ? a[i++] : a[j++];
    while (i <= m) tmp[k++] = a[i++];
    while (j <= hi) tmp[k++] = a[j++];
    for (i = 0; i < k; i++) a[lo + i] = tmp[i];
}

TAG(ms_sentinel);
void ms_sentinel(int *a, int n) {
    MARK(ms_sentinel);
    if (n <= 1) return;
    int m = n / 2;
    int L[40], R[40];
    for (int i = 0; i < m; i++) L[i] = a[i];
    for (int i = 0; i < n - m; i++) R[i] = a[m + i];
    L[m] = R[n - m] = 0x7fffffff;
    ms_sentinel(L, m);
    ms_sentinel(R, n - m);
    int i = 0, j = 0;
    for (int k = 0; k < n; k++) a[k] = L[i] <= R[j] ? L[i++] : R[j++];
}
TAG(ms_no_sentinel);
void ms_no_sentinel(int *a, int n) {
    MARK(ms_no_sentinel);
    if (n <= 1) return;
    int m = n / 2, L[40], R[40];
    for (int i = 0; i < m; i++) L[i] = a[i];
    for (int i = 0; i < n - m; i++) R[i] = a[m + i];
    ms_no_sentinel(L, m);
    ms_no_sentinel(R, n - m);
    int i = 0, j = 0, k = 0;
    while (i < m && j < n - m) a[k++] = L[i] <= R[j] ? L[i++] : R[j++];
    while (i < m) a[k++] = L[i++];
    while (j < n - m) a[k++] = R[j++];
}

struct srec { int key, order; };
TAG(ms_stable_struct);
void ms_stable_struct(struct srec *a, struct srec *tmp, int lo, int hi) {
    MARK(ms_stable_struct);
    if (lo >= hi) return;
    int m = (lo + hi) / 2;
    ms_stable_struct(a, tmp, lo, m);
    ms_stable_struct(a, tmp, m + 1, hi);
    int i = lo, j = m + 1, k = lo;
    while (i <= m && j <= hi) {
        if (a[i].key < a[j].key) tmp[k++] = a[i++];
        else if (a[j].key < a[i].key) tmp[k++] = a[j++];
        else tmp[k++] = a[i].order < a[j].order ? a[i++] : a[j++];
    }
    while (i <= m) tmp[k++] = a[i++];
    while (j <= hi) tmp[k++] = a[j++];
    for (i = lo; i <= hi; i++) a[i] = tmp[i];
}

struct node2 { int val; struct node2 *next; };
static struct node2 *ms_list_merge(struct node2 *a, struct node2 *b) {
    struct node2 head, *tail = &head;
    while (a && b) {
        if (a->val <= b->val) { tail->next = a; a = a->next; }
        else { tail->next = b; b = b->next; }
        tail = tail->next;
    }
    tail->next = a ? a : b;
    return head.next;
}
TAG(ms_linked_list);
struct node2 *ms_linked_list(struct node2 *head) {
    MARK(ms_linked_list);
    if (!head || !head->next) return head;
    struct node2 *slow = head, *fast = head->next;
    while (fast && fast->next) { slow = slow->next; fast = fast->next->next; }
    struct node2 *mid = slow->next;
    slow->next = 0;
    return ms_list_merge(ms_linked_list(head), ms_linked_list(mid));
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)ms_temp_per_recursion, (variant_fn)ms_shared_entry,
    (variant_fn)ms_bottomup_pow2,      (variant_fn)ms_bottomup_arbitrary,
    (variant_fn)ms_pointer,            (variant_fn)ms_index,
    (variant_fn)ms_sentinel,           (variant_fn)ms_no_sentinel,
    (variant_fn)ms_stable_struct,      (variant_fn)ms_linked_list,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return g_arr[0] & 1;
}
