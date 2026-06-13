/*
 * gen_fixtures — generate the committed test fixtures for rcode.
 *
 * Reads RCode.txt (the original RC1/RC2/RC3 scheme), extends each cipher to
 * the 94-symbol alphabet (preserving the original 44 mappings; repairing the
 * RC3 x/0 -> ? collision), and writes cipher/pattern/input fixtures into
 * tests/fixtures/. Run from the repo root: `make fixtures`.
 *
 * C11, no external dependencies. Tooling is C by project convention.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define N  94
#define LO 0x21
#define FIX(name) "tests/fixtures/" name

/* The original 44-symbol plaintext alphabet, in RCode.txt header order. */
static const char *PLAIN44 =
    "abcdefghijklmnopqrstuvwxyz0123456789,.?!'_;\"";

static _Noreturn void fail(const char *msg) {
    fprintf(stderr, "gen_fixtures: %s\n", msg);
    exit(1);
}

/* ---- parse the three cipher rows out of RCode.txt ------------------- */

/* A cipher row is the only kind of line with exactly 44 single-char tokens
 * (the header line has 45 tokens incl the "(RCn)" marker; example lines have
 * multi-char tokens). */
static void parse_rc_rows(const char *path, char rows[3][44]) {
    FILE *f = fopen(path, "rb");
    if (!f) fail("cannot open RCode.txt (run from repo root)");
    size_t cap = 8192, flen = 0;
    char *buf = malloc(cap);
    if (!buf) fail("oom");
    for (;;) {
        if (flen == cap) { cap *= 2; buf = realloc(buf, cap); if (!buf) fail("oom"); }
        size_t r = fread(buf + flen, 1, cap - flen, f);
        flen += r;
        if (r == 0) break;
    }
    fclose(f);

    int nrows = 0;
    size_t i = 0;
    while (i < flen) {
        size_t s = i;
        while (i < flen && buf[i] != '\n') i++;
        size_t e = i;
        if (i < flen) i++;
        if (e > s && buf[e - 1] == '\r') e--;

        char toks[64];
        int nt = 0, all_single = 1;
        size_t p = s;
        while (p < e) {
            while (p < e && (buf[p] == ' ' || buf[p] == '\t')) p++;
            if (p >= e) break;
            size_t ts = p;
            while (p < e && buf[p] != ' ' && buf[p] != '\t') p++;
            size_t tl = p - ts;
            if (tl != 1) all_single = 0;
            if (nt < 64 && tl == 1) toks[nt] = buf[ts];
            nt++;
        }
        if (nt == 44 && all_single) {
            if (nrows < 3) memcpy(rows[nrows], toks, 44);
            nrows++;
        }
    }
    free(buf);
    if (nrows != 3) fail("expected exactly 3 cipher rows in RCode.txt");
}

/* ---- build a 94-symbol permutation from a 44-symbol mapping --------- */

/* Preserve the first occurrence of each original mapping; treat a colliding
 * plaintext (RC3's x/0 -> ?) and the 50 new symbols as fillers assigned to
 * the unused images in ascending order. Result is a verified bijection. */
static void build94(const char row[44], uint8_t out[N]) {
    int fixed[N], used[N];
    for (int i = 0; i < N; i++) { fixed[i] = -1; used[i] = 0; }

    for (int j = 0; j < 44; j++) {
        int pi = (unsigned char)PLAIN44[j] - LO;
        int ci = (unsigned char)row[j] - LO;
        if (pi < 0 || pi >= N || ci < 0 || ci >= N) fail("symbol out of range");
        if (!used[ci]) { fixed[pi] = ci; used[ci] = 1; }
        /* else: collision (e.g. RC3 0->? after x->?), leave for filler pass */
    }

    int freeimg[N], nfree = 0;
    for (int i = 0; i < N; i++) if (!used[i]) freeimg[nfree++] = i;
    int fi = 0;
    for (int pi = 0; pi < N; pi++) if (fixed[pi] == -1) fixed[pi] = freeimg[fi++];
    if (fi != nfree) fail("internal fill mismatch");

    int seen[N];
    for (int i = 0; i < N; i++) seen[i] = 0;
    for (int i = 0; i < N; i++) {
        if (fixed[i] < 0 || fixed[i] >= N || seen[fixed[i]]) fail("not a bijection");
        seen[fixed[i]] = 1;
        out[i] = (uint8_t)(LO + fixed[i]);
    }
}

static void build_rot(int r, uint8_t out[N]) {
    for (int i = 0; i < N; i++) out[i] = (uint8_t)(LO + (i + r) % N);
}

/* ---- writers -------------------------------------------------------- */

static void write_lines(const char *path, uint8_t (*rows)[N], int nrows) {
    FILE *f = fopen(path, "wb");
    if (!f) fail("cannot write fixture (does tests/fixtures/ exist?)");
    for (int k = 0; k < nrows; k++) {
        for (int i = 0; i < N; i++) {
            if (i) fputc(' ', f);
            fputc(rows[k][i], f);
        }
        fputc('\n', f);
    }
    fclose(f);
}

static void write_bytes(const char *path, const void *p, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f) fail("cannot write fixture");
    if (n) fwrite(p, 1, n, f);
    fclose(f);
}
static void write_str(const char *path, const char *s) {
    write_bytes(path, s, strlen(s));
}

int main(void) {
    if (strlen(PLAIN44) != 44) fail("PLAIN44 length != 44");

    char rows44[3][44];
    parse_rc_rows("RCode.txt", rows44);

    uint8_t e1[N], e2[N], e3[N];
    build94(rows44[0], e1);
    build94(rows44[1], e2);
    build94(rows44[2], e3);

    /* Pin row identity & order: plaintext 'a' maps to g/;/q under RC1/RC2/RC3.
     * Guards against a corrupted RCode.txt yielding wrong-but-44-token rows. */
    {
        int ai = 'a' - LO;
        if (e1[ai] != 'g' || e2[ai] != ';' || e3[ai] != 'q')
            fail("parsed RC rows are out of order or do not match RCode.txt");
    }

    write_lines(FIX("rc1.ciphers"), &e1, 1);
    write_lines(FIX("rc2.ciphers"), &e2, 1);
    write_lines(FIX("rc3.ciphers"), &e3, 1);

    uint8_t rc123[3][N];
    memcpy(rc123[0], e1, N);
    memcpy(rc123[1], e2, N);
    memcpy(rc123[2], e3, N);
    write_lines(FIX("rc123.ciphers"), rc123, 3);

    /* N-boundary fixtures: distinct rotations r=1..K */
    static uint8_t rot[50][N];
    int counts[] = {1, 3, 9, 10, 50};
    const char *names[] = {
        FIX("n1.ciphers"), FIX("n3.ciphers"), FIX("n9.ciphers"),
        FIX("n10.ciphers"), FIX("n50.ciphers")
    };
    for (int c = 0; c < 5; c++) {
        for (int t = 0; t < counts[c]; t++) build_rot(t + 1, rot[t]);
        write_lines(names[c], rot, counts[c]);
    }

    uint8_t id[N];
    build_rot(0, id);
    write_lines(FIX("identity.ciphers"), &id, 1);

    /* rejection fixtures (written byte-exactly) */
    {
        FILE *f = fopen(FIX("bad_tokencount.ciphers"), "wb"); /* 93 tokens */
        if (!f) fail("write");
        for (int i = 0; i < 93; i++) { if (i) fputc(' ', f); fputc(LO + i, f); }
        fputc('\n', f); fclose(f);
    }
    {
        FILE *f = fopen(FIX("bad_twobyte_token.ciphers"), "wb"); /* token0 = "!!" */
        if (!f) fail("write");
        for (int i = 0; i < N; i++) {
            if (i) fputc(' ', f);
            if (i == 0) { fputc('!', f); fputc('!', f); }
            else fputc(LO + i, f);
        }
        fputc('\n', f); fclose(f);
    }
    {
        FILE *f = fopen(FIX("bad_nonbijection.ciphers"), "wb"); /* '!' twice, '"' missing */
        if (!f) fail("write");
        for (int i = 0; i < N; i++) {
            if (i) fputc(' ', f);
            fputc(i == 1 ? LO + 0 : LO + i, f);
        }
        fputc('\n', f); fclose(f);
    }
    {
        FILE *f = fopen(FIX("bad_nonascii.ciphers"), "wb"); /* token0 = byte 0x80 */
        if (!f) fail("write");
        for (int i = 0; i < N; i++) {
            if (i) fputc(' ', f);
            fputc(i == 0 ? 0x80 : LO + i, f);
        }
        fputc('\n', f); fclose(f);
    }
    {
        FILE *f = fopen(FIX("bad_toomany.ciphers"), "wb"); /* 95 tokens */
        if (!f) fail("write");
        for (int i = 0; i < N; i++) { fputc(LO + i, f); fputc(' ', f); }
        fputc(LO, f); /* one extra token */
        fputc('\n', f); fclose(f);
    }
    {
        /* valid first line, non-bijection second line (exercises cipher index 2) */
        FILE *f = fopen(FIX("bad_second_line.ciphers"), "wb");
        if (!f) fail("write");
        for (int i = 0; i < N; i++) { if (i) fputc(' ', f); fputc(LO + i, f); }
        fputc('\n', f);
        for (int i = 0; i < N; i++) { if (i) fputc(' ', f); fputc(i == 1 ? LO : LO + i, f); }
        fputc('\n', f); fclose(f);
    }

    /* input fixtures */
    write_str(FIX("tqbf.txt"), "the quick brown fox jumps over the lazy dog\n");
    {
        uint8_t all94[N + 1];
        for (int i = 0; i < N; i++) all94[i] = (uint8_t)(LO + i);
        all94[N] = '\n';
        write_bytes(FIX("all94.txt"), all94, N + 1);
    }
    write_str(FIX("ws.txt"), "hi there\tworld\r\nsecond line\n");
    write_bytes(FIX("empty.txt"), "", 0);
    write_str(FIX("pat132312.txt"), "132312\n");

    { unsigned char b = 0x80; write_bytes(FIX("in_0x80.bin"), &b, 1); }
    { unsigned char b = 0x00; write_bytes(FIX("in_0x00.bin"), &b, 1); }
    { unsigned char b = 0x07; write_bytes(FIX("in_0x07.bin"), &b, 1); }

    fputs("fixtures written to tests/fixtures/\n", stdout);
    return 0;
}
