/* 11. Binary Tree family. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#define TAG(id) static volatile int tag_##id = __LINE__
#define MARK(id) do { (void)tag_##id; } while (0)

struct tnode { int key; struct tnode *left, *right; };
static struct tnode g_pool[64];

TAG(bt_preorder);
void bt_preorder(struct tnode *t) {
    MARK(bt_preorder);
    if (!t) return;
    volatile int sink = t->key;
    (void)sink;
    bt_preorder(t->left);
    bt_preorder(t->right);
}
TAG(bt_inorder);
void bt_inorder(struct tnode *t) {
    MARK(bt_inorder);
    if (!t) return;
    bt_inorder(t->left);
    volatile int sink = t->key;
    (void)sink;
    bt_inorder(t->right);
}
TAG(bt_postorder);
void bt_postorder(struct tnode *t) {
    MARK(bt_postorder);
    if (!t) return;
    bt_postorder(t->left);
    bt_postorder(t->right);
    volatile int sink = t->key;
    (void)sink;
}
TAG(bt_preorder_iter);
void bt_preorder_iter(struct tnode *root) {
    MARK(bt_preorder_iter);
    struct tnode *st[64];
    int sp = 0;
    st[sp++] = root;
    while (sp > 0) {
        struct tnode *t = st[--sp];
        if (!t) continue;
        volatile int sink = t->key;
        (void)sink;
        st[sp++] = t->right;
        st[sp++] = t->left;
    }
}
TAG(bt_bfs);
void bt_bfs(struct tnode *root) {
    MARK(bt_bfs);
    struct tnode *q[64];
    int head = 0, tail = 0;
    q[tail++] = root;
    while (head < tail) {
        struct tnode *t = q[head++];
        if (!t) continue;
        volatile int sink = t->key;
        (void)sink;
        q[tail++] = t->left;
        q[tail++] = t->right;
    }
}
TAG(bst_insert);
struct tnode *bst_insert(struct tnode *root, struct tnode *n) {
    MARK(bst_insert);
    n->left = n->right = 0;
    if (!root) return n;
    struct tnode *p = root;
    for (;;) {
        if (n->key < p->key) {
            if (!p->left) { p->left = n; break; }
            p = p->left;
        } else {
            if (!p->right) { p->right = n; break; }
            p = p->right;
        }
    }
    return root;
}
TAG(bst_search);
struct tnode *bst_search(struct tnode *root, int key) {
    MARK(bst_search);
    while (root) {
        if (key == root->key) return root;
        root = key < root->key ? root->left : root->right;
    }
    return 0;
}
TAG(bst_delete);
struct tnode *bst_delete(struct tnode *root, int key) {
    MARK(bst_delete);
    if (!root) return 0;
    if (key < root->key) root->left = bst_delete(root->left, key);
    else if (key > root->key) root->right = bst_delete(root->right, key);
    else if (!root->left) return root->right;
    else if (!root->right) return root->left;
    else {
        struct tnode *s = root->right;
        while (s->left) s = s->left;
        root->key = s->key;
        root->right = bst_delete(root->right, s->key);
    }
    return root;
}
struct avl { int key, h; struct avl *l, *r; };
static int avl_h(struct avl *n) { return n ? n->h : 0; }
static struct avl *avl_rot_r(struct avl *y) {
    struct avl *x = y->l;
    y->l = x->r;
    x->r = y;
    y->h = avl_h(y->l) > avl_h(y->r) ? avl_h(y->l) + 1 : avl_h(y->r) + 1;
    x->h = avl_h(x->l) > avl_h(x->r) ? avl_h(x->l) + 1 : avl_h(x->r) + 1;
    return x;
}
static struct avl *avl_rot_l(struct avl *x) {
    struct avl *y = x->r;
    x->r = y->l;
    y->l = x;
    x->h = avl_h(x->l) > avl_h(x->r) ? avl_h(x->l) + 1 : avl_h(x->r) + 1;
    y->h = avl_h(y->l) > avl_h(y->r) ? avl_h(y->l) + 1 : avl_h(y->r) + 1;
    return y;
}
static struct avl *avl_insert(struct avl *n, int key) {
    if (!n) {
        static int pi = 0;
        n = (struct avl *)&g_pool[pi++ & 63];
        n->key = key; n->h = 1; n->l = n->r = 0;
        return n;
    }
    if (key < n->key) n->l = avl_insert(n->l, key);
    else n->r = avl_insert(n->r, key);
    n->h = avl_h(n->l) > avl_h(n->r) ? avl_h(n->l) + 1 : avl_h(n->r) + 1;
    int bal = avl_h(n->l) - avl_h(n->r);
    if (bal > 1)
        return key < n->l->key ? avl_rot_r(n) :
               (n->l = avl_rot_l(n->l), avl_rot_r(n));
    if (bal < -1)
        return key > n->r->key ? avl_rot_l(n) :
               (n->r = avl_rot_r(n->r), avl_rot_l(n));
    return n;
}
TAG(avl_insert_entry);
struct avl *avl_insert_entry(struct avl *root, int key) {
    MARK(avl_insert_entry);
    return avl_insert(root, key);
}
struct rb { int key, red; struct rb *l, *r, *p; };
TAG(rb_insert_fixup_step);
void rb_insert_fixup_step(struct rb *n) {
    MARK(rb_insert_fixup_step);
    /* one fixup iteration: parent is red, uncle decides case */
    struct rb *p = n->p;
    if (!p || !p->red) return;
    struct rb *g = p->p;
    if (!g) { p->red = 0; return; }
    struct rb *u = p == g->l ? g->r : g->l;
    if (u && u->red) {
        p->red = u->red = 0;
        g->red = 1;
        rb_insert_fixup_step(g);
    } else {
        if (p == g->l) {
            if (n == p->r) { p->red = 0; g->red = 1; }
            else { n->red = 0; g->red = 1; }
        } else {
            if (n == p->l) { p->red = 0; g->red = 1; }
            else { n->red = 0; g->red = 1; }
        }
    }
}
struct splay { int key; struct splay *l, *r; };
static struct splay *splay_right(struct splay *x) {
    struct splay *y = x->l;
    x->l = y->r;
    y->r = x;
    return y;
}
static struct splay *splay_left(struct splay *x) {
    struct splay *y = x->r;
    x->r = y->l;
    y->l = x;
    return y;
}
TAG(splay_topdown);
struct splay *splay_topdown(struct splay *root, int key) {
    MARK(splay_topdown);
    if (!root) return 0;
    struct splay head;
    head.l = head.r = 0;
    struct splay *l = &head, *r = &head;
    for (;;) {
        if (key < root->key) {
            if (!root->l) break;
            if (key < root->l->key) {
                root = splay_right(root);
                if (!root->l) break;
            }
            r->l = root;
            r = root;
            root = root->l;
        } else if (key > root->key) {
            if (!root->r) break;
            if (key > root->r->key) {
                root = splay_left(root);
                if (!root->r) break;
            }
            l->r = root;
            l = root;
            root = root->r;
        } else break;
    }
    r->l = root->r;
    l->r = root->l;
    root->l = head.r;
    root->r = head.l;
    return root;
}
struct treap { int key, pri; struct treap *l, *r; };
TAG(treap_merge);
struct treap *treap_merge(struct treap *a, struct treap *b) {
    MARK(treap_merge);
    if (!a) return b;
    if (!b) return a;
    if (a->pri > b->pri) {
        a->r = treap_merge(a->r, b);
        return a;
    }
    b->l = treap_merge(a, b->l);
    return b;
}
struct pnode { int key; struct pnode *l, *r, *parent; };
TAG(bt_parent_walk);
struct pnode *bt_parent_walk(struct pnode *n) {
    MARK(bt_parent_walk);
    while (n->parent) n = n->parent;
    return n;
}
TAG(bt_destroy_rec);
void bt_destroy_rec(struct tnode *t) {
    MARK(bt_destroy_rec);
    if (!t) return;
    bt_destroy_rec(t->left);
    bt_destroy_rec(t->right);
    t->left = t->right = 0;
    t->key = 0;
}

typedef void (*variant_fn)(void);
static variant_fn g_variants[] = {
    (variant_fn)bt_preorder,    (variant_fn)bt_inorder,
    (variant_fn)bt_postorder,   (variant_fn)bt_preorder_iter,
    (variant_fn)bt_bfs,         (variant_fn)bst_insert,
    (variant_fn)bst_search,     (variant_fn)bst_delete,
    (variant_fn)avl_insert_entry,(variant_fn)rb_insert_fixup_step,
    (variant_fn)splay_topdown,  (variant_fn)treap_merge,
    (variant_fn)bt_parent_walk, (variant_fn)bt_destroy_rec,
};
int main(void) {
    volatile unsigned long long sink = 0;
    for (size_t i = 0; i < sizeof(g_variants) / sizeof(g_variants[0]); i++)
        sink += (unsigned long long)(uintptr_t)g_variants[i];
    (void)sink;
    return 0;
}
