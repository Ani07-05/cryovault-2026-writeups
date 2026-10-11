// BSGS for theta^k = x + y*theta in F_p[theta]/(theta^2 + a theta + b), p ~ 2^126
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
typedef unsigned __int128 u128;
typedef uint64_t u64;
static u128 P, PINV; // PINV = -p^-1 mod 2^128

static void mul256(u128 a, u128 b, u128 *hi, u128 *lo) {
    u64 a0 = (u64)a, a1 = a >> 64, b0 = (u64)b, b1 = b >> 64;
    u128 p00 = (u128)a0 * b0, p01 = (u128)a0 * b1, p10 = (u128)a1 * b0, p11 = (u128)a1 * b1;
    u128 mid = (p00 >> 64) + (u64)p01 + (u64)p10;
    *lo = (u64)p00 | (mid << 64);
    *hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
}
static u128 redc(u128 hi, u128 lo) {
    u128 m = lo * PINV, mh, ml;
    mul256(m, P, &mh, &ml);
    u128 s = lo + ml; u128 carry = s < lo;
    u128 r = hi + mh + carry; // < 2p < 2^128
    if (r >= P) r -= P;
    return r;
}
static u128 mm(u128 a, u128 b) { u128 h, l; mul256(a, b, &h, &l); return redc(h, l); }
static u128 add(u128 a, u128 b) { u128 r = a + b; if (r >= P) r -= P; return r; }
static u128 sub(u128 a, u128 b) { return a >= b ? a - b : a + P - b; }
static u128 R2, ONE, A_, B_;
static u128 tomont(u128 x) { return mm(x, R2); }
static u128 frommont(u128 x) { return redc(0, x); }
typedef struct { u128 c0, c1; } E;
static E emul(E x, E y) {
    u128 t00 = mm(x.c0, y.c0), t11 = mm(x.c1, y.c1);
    u128 t01 = add(mm(x.c0, y.c1), mm(x.c1, y.c0));
    // theta^2 = -a theta - b
    E r;
    r.c0 = sub(t00, mm(t11, B_));
    r.c1 = sub(t01, mm(t11, A_));
    return r;
}
static E epow(E x, u64 e) {
    E r = {ONE, 0};
    while (e) { if (e & 1) r = emul(r, x); x = emul(x, x); e >>= 1; }
    return r;
}
static u128 parse(const char *s) { u128 r = 0; for (; *s >= '0' && *s <= '9'; s++) r = r * 10 + (*s - '0'); return r; }
typedef struct { u64 key; u64 j; } Ent;
static int cmp(const void *a, const void *b) {
    u64 x = ((Ent *)a)->key, y = ((Ent *)b)->key; return x < y ? -1 : x > y;
}
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "r"); char buf[200]; u128 v[6];
    for (int i = 0; i < 6; i++) { fgets(buf, 200, f); v[i] = parse(buf); }
    P = v[0]; u64 q = (u64)v[5];
    // PINV via Newton: inv = p^-1 mod 2^128
    u128 inv = P; for (int i = 0; i < 7; i++) inv *= 2 - P * inv;
    PINV = -inv;
    // R mod p, R2 mod p
    u128 R = (-P) % P; // 2^128 mod p
    ONE = R;
    u128 r2 = R; for (int i = 0; i < 128; i++) { r2 <<= 0; r2 = add(r2, r2); } // R*2^128 = R^2/R... compute R^2 mod p = R * 2^128
    R2 = r2;
    A_ = tomont(v[1]); B_ = tomont(v[2]);
    E T = {tomont(v[3]), tomont(v[4])};
    E th = {0, ONE};
    u64 m = (u64)ceil(sqrt((double)q)) + 1;
    Ent *tab = malloc(sizeof(Ent) * m);
    E c = {ONE, 0};
    for (u64 j = 0; j < m; j++) { tab[j].key = (u64)c.c0 ^ ((u64)c.c1 * 0x9e3779b97f4a7c15ULL); tab[j].j = j; c = emul(c, th); }
    qsort(tab, m, sizeof(Ent), cmp);
    fprintf(stderr, "baby done m=%llu\n", (unsigned long long)m);
    // theta^-1 = -(theta + a)
    E thi = {sub(0, A_), sub(0, ONE)};
    E chk = emul(thi, th); // should be 1
    if (chk.c0 != ONE || chk.c1 != 0) { fprintf(stderr, "inverse wrong\n"); return 1; }
    E g = epow(thi, m);
    E cur = T;
    for (u64 i = 0; i <= m; i++) {
        u64 key = (u64)cur.c0 ^ ((u64)cur.c1 * 0x9e3779b97f4a7c15ULL);
        u64 lo = 0, hi = m;
        while (lo < hi) { u64 mid = (lo + hi) / 2; if (tab[mid].key < key) lo = mid + 1; else hi = mid; }
        for (u64 t = lo; t < m && tab[t].key == key; t++) {
            u64 k = i * m + tab[t].j;
            E chk2 = epow(th, k);
            if (chk2.c0 == T.c0 && chk2.c1 == T.c1) { printf("%llu\n", (unsigned long long)k); return 0; }
        }
        cur = emul(cur, g);
    }
    fprintf(stderr, "not found\n");
    return 1;
}
