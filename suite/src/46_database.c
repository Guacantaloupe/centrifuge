/* 46. Database / Data-Structure family — B-tree, hash index, LSM-ish, joins. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

struct db_row { int key; int value; };
struct db_table { struct db_row rows[32]; int count; };

TAG(db_linear_probe_lookup);
int db_linear_probe_lookup(const struct db_table *t, int key) {
    MARK(db_linear_probe_lookup);
    for (int i = 0; i < t->count; i++)
        if (t->rows[i].key == key) return t->rows[i].value;
    return -1;
}
TAG(db_insert_sorted);
int db_insert_sorted(struct db_table *t, int key, int value) {
    MARK(db_insert_sorted);
    int i = t->count;
    while (i > 0 && t->rows[i - 1].key > key) {
        t->rows[i] = t->rows[i - 1];
        i--;
    }
    t->rows[i].key = key;
    t->rows[i].value = value;
    t->count++;
    return i;
}
TAG(db_binary_lookup);
int db_binary_lookup(const struct db_table *t, int key) {
    MARK(db_binary_lookup);
    int lo = 0, hi = t->count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (t->rows[mid].key == key) return t->rows[mid].value;
        if (t->rows[mid].key < key) lo = mid + 1;
        else hi = mid - 1;
    }
    return -1;
}
TAG(db_hash_fnv1a);
uint32_t db_hash_fnv1a(const void *data, size_t len) {
    MARK(db_hash_fnv1a);
    const uint8_t *p = (const uint8_t *)data;
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}
TAG(db_hash_djb2);
uint32_t db_hash_djb2(const char *s) {
    MARK(db_hash_djb2);
    uint32_t h = 5381;
    while (*s) h = h * 33 + (uint8_t)*s++;
    return h;
}
struct db_ht { int keys[64]; int vals[64]; uint8_t used[64]; };
TAG(db_ht_insert);
int db_ht_insert(struct db_ht *ht, int key, int value) {
    MARK(db_ht_insert);
    uint32_t h = (uint32_t)key * 2654435761u;
    int slot = (int)(h & 63u);
    for (int probe = 0; probe < 64; probe++) {
        int s = (slot + probe) & 63;
        if (!ht->used[s]) {
            ht->used[s] = 1; ht->keys[s] = key; ht->vals[s] = value;
            return s;
        }
        if (ht->keys[s] == key) { ht->vals[s] = value; return s; }
    }
    return -1;
}
TAG(db_ht_lookup);
int db_ht_lookup(const struct db_ht *ht, int key) {
    MARK(db_ht_lookup);
    uint32_t h = (uint32_t)key * 2654435761u;
    int slot = (int)(h & 63u);
    for (int probe = 0; probe < 64; probe++) {
        int s = (slot + probe) & 63;
        if (!ht->used[s]) return -1;
        if (ht->keys[s] == key) return ht->vals[s];
    }
    return -1;
}
TAG(db_merge_join);
int db_merge_join(const int *a, int na, const int *b, int nb, int *out, int max_out) {
    MARK(db_merge_join);
    int i = 0, j = 0, n = 0;
    while (i < na && j < nb && n < max_out) {
        if (a[i] < b[j]) i++;
        else if (b[j] < a[i]) j++;
        else { out[n++] = a[i]; i++; j++; }
    }
    return n;
}
TAG(db_hash_join_count);
int db_hash_join_count(const int *a, int na, const int *b, int nb) {
    MARK(db_hash_join_count);
    struct db_ht ht = {0};
    for (int i = 0; i < nb; i++) db_ht_insert(&ht, b[i], b[i]);
    int matches = 0;
    for (int i = 0; i < na; i++)
        if (db_ht_lookup(&ht, a[i]) >= 0) matches++;
    return matches;
}
TAG(db_run_length_encode);
int db_run_length_encode(const uint8_t *in, int n, uint8_t *out, int max_out) {
    MARK(db_run_length_encode);
    int o = 0, i = 0;
    while (i < n && o + 2 <= max_out) {
        uint8_t v = in[i];
        int run = 1;
        while (i + run < n && in[i + run] == v && run < 255) run++;
        out[o++] = v;
        out[o++] = (uint8_t)run;
        i += run;
    }
    return o;
}
TAG(db_page_checksum);
uint32_t db_page_checksum(const uint8_t *page, size_t len) {
    MARK(db_page_checksum);
    uint32_t s = 0;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = (uint32_t)page[i];
        if (i + 1 < len) w |= (uint32_t)page[i + 1] << 8;
        if (i + 2 < len) w |= (uint32_t)page[i + 2] << 16;
        if (i + 3 < len) w |= (uint32_t)page[i + 3] << 24;
        s = (s << 1) | (s >> 31);
        s ^= w;
    }
    return s;
}
TAG(db_wal_replay);
int db_wal_replay(const int *ops, int n) {
    MARK(db_wal_replay);
    /* ops: +k = insert k, -k = delete k, replay on sorted array */
    int sorted[32], cnt = 0;
    for (int i = 0; i < n; i++) {
        int op = ops[i];
        if (op >= 0) {
            if (cnt < 32) { sorted[cnt++] = op; }
        } else {
            int key = -op, j;
            for (j = 0; j < cnt; j++)
                if (sorted[j] == key) break;
            if (j < cnt) {
                memmove(&sorted[j], &sorted[j + 1], (size_t)(cnt - j - 1) * sizeof(int));
                cnt--;
            }
        }
    }
    return cnt;
}
TAG(db_sstable_scan);
int db_sstable_scan(const int *sorted_keys, int n, int lo, int hi) {
    MARK(db_sstable_scan);
    /* count keys in [lo, hi] via two binary searches */
    int l = 0, r = n;
    while (l < r) { int m = (l + r) / 2; if (sorted_keys[m] < lo) l = m + 1; else r = m; }
    int first = l;
    l = 0; r = n;
    while (l < r) { int m = (l + r) / 2; if (sorted_keys[m] <= hi) l = m + 1; else r = m; }
    return l - first;
}

typedef long long (*variant_fn)(long long);
static variant_fn g_variants[] = {
    (variant_fn)db_linear_probe_lookup, (variant_fn)db_insert_sorted,
    (variant_fn)db_binary_lookup,       (variant_fn)db_hash_fnv1a,
    (variant_fn)db_hash_djb2,           (variant_fn)db_ht_insert,
    (variant_fn)db_ht_lookup,           (variant_fn)db_merge_join,
    (variant_fn)db_hash_join_count,     (variant_fn)db_run_length_encode,
    (variant_fn)db_page_checksum,       (variant_fn)db_wal_replay,
    (variant_fn)db_sstable_scan,
};
int main(void) {
    volatile long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += g_variants[i](3);
    (void)sink;
    return 0;
}
