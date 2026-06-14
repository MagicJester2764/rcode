/*
 * cpscommon.h — shared helpers for the rcode generator tools (cps-gen, ptn-gen).
 *
 * Header-only (all functions `static inline`); each tool includes it directly,
 * matching the project's single-translation-unit, no-dependency style.
 *
 * cps_load mirrors rcode.c::load_ciphers (SPEC.md §2.2 is the single source of
 * truth for the .cps format); the generator round-trip test guards against drift.
 *
 * POSIX bits used: <unistd.h> (getpid), <sys/stat.h> (stat), localtime_r.
 */
#ifndef CPSCOMMON_H
#define CPSCOMMON_H

/* Enable POSIX declarations (localtime_r, getpid, stat) under -std=c11. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define CPS_LO 0x21 /* '!' */
#define CPS_HI 0x7E /* '~' */
#define CPS_N  94   /* CPS_HI - CPS_LO + 1 */

/* Exit codes, mirroring rcode (SPEC §4). */
enum { CPS_OK = 0, CPS_USAGE = 1, CPS_VALID = 2, CPS_RUNTIME = 3 };

/* Set by each tool's main() so diagnostics carry the right program name. */
static const char *g_prog = "cps";

/* ---- diagnostics ---------------------------------------------------- */

static _Noreturn void cps_vdie(int code, const char *fmt, va_list ap) {
    fprintf(stderr, "%s: ", g_prog);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    exit(code);
}
static inline _Noreturn void die_usage(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); cps_vdie(CPS_USAGE, fmt, ap);
}
static inline _Noreturn void die_validation(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); cps_vdie(CPS_VALID, fmt, ap);
}
static inline _Noreturn void die_runtime(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); cps_vdie(CPS_RUNTIME, fmt, ap);
}

/* ---- argument parsing ----------------------------------------------- */

/* Parse a non-negative decimal integer CLI value (usage error on failure). */
static inline uint64_t cps_parse_u64(const char *s, const char *what) {
    if (!s || !*s) die_usage("%s requires a value", what);
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            die_usage("%s must be a non-negative integer, got '%s'", what, s);
        uint64_t nv = v * 10 + (uint64_t)(*p - '0');
        if (nv < v) die_usage("%s value too large", what);
        v = nv;
    }
    return v;
}

/* ---- file slurp (lifted from rcode.c::read_whole_file) -------------- */

static inline char *cps_read_whole_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); errno = ENOMEM; return NULL; }
    for (;;) {
        if (len == cap) {
            if (cap > SIZE_MAX / 2) { free(buf); fclose(f); errno = EOVERFLOW; return NULL; }
            size_t ncap = cap * 2;
            char *nb = realloc(buf, ncap);
            if (!nb) { free(buf); fclose(f); errno = ENOMEM; return NULL; }
            buf = nb; cap = ncap;
        }
        size_t r = fread(buf + len, 1, cap - len, f);
        len += r;
        if (r == 0) break;
    }
    if (ferror(f)) { int e = errno; free(buf); fclose(f); errno = e; return NULL; }
    fclose(f);
    *out_len = len;
    return buf;
}

/* ---- .cps load / write (mirrors rcode.c::load_ciphers) -------------- */

/* Parse and validate a .cps file. Appends its ciphers to *rows (grown with
 * realloc; *n / *cap track length/capacity). Each non-blank line must be 94
 * single-byte tokens forming a bijection of CPS_LO..CPS_HI. Fatal on failure. */
static inline void cps_load_into(const char *path, uint8_t (**rows)[CPS_N],
                                 size_t *n, size_t *cap) {
    size_t flen;
    char *buf = cps_read_whole_file(path, &flen);
    if (!buf) die_runtime("cannot read '%s': %s", path, strerror(errno));

    size_t before = *n;
    size_t i = 0;
    while (i < flen) {
        size_t start = i;
        while (i < flen && buf[i] != '\n') i++;
        size_t end = i;
        if (i < flen) i++;
        if (end > start && buf[end - 1] == '\r') end--;

        int blank = 1;
        for (size_t p = start; p < end; p++) {
            unsigned char c = (unsigned char)buf[p];
            if (!(c == ' ' || c == '\t' || c == '\r' || c == '\n')) { blank = 0; break; }
        }
        if (blank) continue;

        size_t cidx = *n - before + 1; /* 1-based index within this file */
        uint8_t row[CPS_N];
        size_t ntok = 0, p = start;
        while (p < end) {
            while (p < end && (buf[p] == ' ' || buf[p] == '\t')) p++;
            if (p >= end) break;
            size_t ts = p;
            while (p < end && buf[p] != ' ' && buf[p] != '\t') p++;
            size_t tlen = p - ts;
            if (tlen != 1)
                die_validation("'%s' cipher %zu: token %zu ('%.*s') is not a single byte",
                               path, cidx, ntok + 1, (int)tlen, buf + ts);
            unsigned char tb = (unsigned char)buf[ts];
            if (tb < CPS_LO || tb > CPS_HI)
                die_validation("'%s' cipher %zu: token %zu byte 0x%02X outside printable "
                               "range [0x21,0x7E]", path, cidx, ntok + 1, tb);
            if (ntok < CPS_N) row[ntok] = tb;
            ntok++;
        }
        if (ntok != CPS_N)
            die_validation("'%s' cipher %zu: expected %d tokens, got %zu",
                           path, cidx, CPS_N, ntok);

        int seen[CPS_N] = {0};
        for (int t = 0; t < CPS_N; t++) {
            int idx = row[t] - CPS_LO;
            if (seen[idx])
                die_validation("'%s' cipher %zu: symbol '%c' appears more than once "
                               "(not a bijection)", path, cidx, row[t]);
            seen[idx] = 1;
        }

        if (*n == *cap) {
            size_t ncap = *cap ? *cap * 2 : 8;
            if (*cap > SIZE_MAX / 2 || ncap > SIZE_MAX / sizeof(**rows))
                die_runtime("too many cipher alphabets");
            uint8_t (*nr)[CPS_N] = realloc(*rows, ncap * sizeof(**rows));
            if (!nr) die_runtime("out of memory loading ciphers");
            *rows = nr; *cap = ncap;
        }
        memcpy((*rows)[*n], row, CPS_N);
        (*n)++;
    }
    free(buf);

    if (*n == before)
        die_validation("'%s': no cipher alphabets found", path);
}

static inline void cps_write(FILE *f, uint8_t (*rows)[CPS_N], size_t n) {
    for (size_t k = 0; k < n; k++) {
        for (int i = 0; i < CPS_N; i++) {
            if (i) fputc(' ', f);
            fputc(rows[k][i], f);
        }
        fputc('\n', f);
    }
}

/* ---- PRNG (splitmix64; non-crypto, this is a toy cipher) ------------ */

typedef struct { uint64_t s; } cps_rng;

static inline uint64_t cps_rng_next(cps_rng *r) {
    uint64_t z = (r->s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
static inline void cps_rng_seed_fixed(cps_rng *r, uint64_t seed) { r->s = seed; }
static inline void cps_rng_seed_os(cps_rng *r) {
    uint64_t s = 0;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { if (fread(&s, 1, sizeof s, f) != sizeof s) s = 0; fclose(f); }
    if (s == 0) s = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 16);
    r->s = s;
}
/* Unbiased uniform in [0, bound) via rejection sampling. bound must be > 0. */
static inline uint64_t cps_rnd_below(cps_rng *r, uint64_t bound) {
    uint64_t threshold = (0ULL - bound) % bound; /* 2^64 mod bound */
    uint64_t x;
    do { x = cps_rng_next(r); } while (x < threshold);
    return x % bound;
}
/* Fill perm[] with a uniformly random permutation of CPS_LO..CPS_HI. */
static inline void cps_fisher_yates(uint8_t perm[CPS_N], cps_rng *r) {
    for (int i = 0; i < CPS_N; i++) perm[i] = (uint8_t)(CPS_LO + i);
    for (int i = CPS_N - 1; i > 0; i--) {
        size_t j = (size_t)cps_rnd_below(r, (uint64_t)i + 1);
        uint8_t t = perm[i]; perm[i] = perm[j]; perm[j] = t;
    }
}

/* ---- output naming / paths ----------------------------------------- */

/* Fill ts with the current local time as YYYYMMDD-HHMMSS (computed once per run). */
static inline void cps_timestamp(char *ts, size_t cap) {
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    if (strftime(ts, cap, "%Y%m%d-%H%M%S", &tmv) == 0)
        die_runtime("failed to format timestamp");
}
/* Build "<ts>.<ext>" or, with_index, "<ts>-<index>.<ext>" (ext includes the dot). */
static inline void cps_build_name(char *buf, size_t cap, const char *ts,
                                  const char *ext, int with_index, int index) {
    if (with_index) snprintf(buf, cap, "%s-%d%s", ts, index, ext);
    else snprintf(buf, cap, "%s%s", ts, ext);
}
static inline void cps_join(char *buf, size_t cap, const char *dir, const char *name) {
    if (dir && dir[0]) snprintf(buf, cap, "%s/%s", dir, name);
    else snprintf(buf, cap, "%s", name);
}
static inline void cps_check_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode))
        die_runtime("output directory '%s' does not exist", dir);
}
/* Open path for writing; refuse to clobber an existing file unless force. */
static inline FILE *cps_open_out(const char *path, int force) {
    if (!force) {
        struct stat st;
        if (stat(path, &st) == 0)
            die_runtime("refusing to overwrite '%s' (use --force)", path);
    }
    FILE *f = fopen(path, "wb");
    if (!f) die_runtime("cannot open output '%s': %s", path, strerror(errno));
    return f;
}
static inline void cps_close_out(FILE *f, const char *path) {
    if (fflush(f) != 0 || ferror(f) || fclose(f) != 0)
        die_runtime("write error on '%s': %s", path, strerror(errno));
}

#endif /* CPSCOMMON_H */
