/*
 * rcode — polyalphabetic substitution cipher over the 94 printable
 * non-space ASCII characters. See SPEC.md for the authoritative spec.
 *
 * Single translation unit, C11, no external dependencies.
 */
/* Enable POSIX declarations (mkstemp, fdopen, fchmod, unlink) under -std=c11. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#define ALPHA_LO 0x21 /* '!' */
#define ALPHA_HI 0x7E /* '~' */
#define ALPHA_N  94   /* ALPHA_HI - ALPHA_LO + 1 */

#define RCODE_VERSION "1.0"

/* Exit codes (SPEC §4). */
enum {
    EX_OK      = 0,
    EX_USAGE   = 1, /* bad command line */
    EX_VALID   = 2, /* cipher/pattern file content invalid */
    EX_RUNTIME = 3  /* IO failure, or out-of-alphabet byte in the data stream */
};

/* byte -> plaintext index (0..93), or -1. Built by init_pidx(). */
static int16_t g_pidx[256];

static void init_pidx(void) {
    for (int i = 0; i < 256; i++) g_pidx[i] = -1;
    for (int b = ALPHA_LO; b <= ALPHA_HI; b++)
        g_pidx[b] = (int16_t)(b - ALPHA_LO);
}

/* Whitespace passes through and never advances the pattern (SPEC §1). */
static int is_ws(int c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* Pattern token separators (SPEC §3.1); '\r' tolerated for CRLF files. */
static int is_sep(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',';
}

/* ---- diagnostics ---------------------------------------------------- */

static _Noreturn void vdie(int code, const char *fmt, va_list ap) {
    fputs("rcode: ", stderr);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    exit(code);
}
static _Noreturn void die_usage(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vdie(EX_USAGE, fmt, ap);
}
static _Noreturn void die_validation(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vdie(EX_VALID, fmt, ap);
}
static _Noreturn void die_runtime(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vdie(EX_RUNTIME, fmt, ap);
}

/* ---- file slurp ----------------------------------------------------- */

/* Read an entire (small, config) file into a malloc'd buffer.
 * Returns NULL on error with errno set. *out_len receives the length. */
static char *read_whole_file(const char *path, size_t *out_len) {
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

/* ---- ciphers -------------------------------------------------------- */

struct ciphers {
    size_t n;
    uint8_t (*enc)[ALPHA_N]; /* enc[k][i] = ciphertext byte for plaintext index i */
    uint8_t (*inv)[ALPHA_N]; /* inv[k][g_pidx[c]] = plaintext index whose cipher byte is c */
};

static void load_ciphers(const char *path, struct ciphers *cs) {
    size_t flen;
    char *buf = read_whole_file(path, &flen);
    if (!buf) die_runtime("cannot read ciphers file '%s': %s", path, strerror(errno));

    cs->n = 0; cs->enc = NULL; cs->inv = NULL;
    size_t cap = 0;

    size_t i = 0;
    while (i < flen) {
        size_t start = i;
        while (i < flen && buf[i] != '\n') i++;
        size_t end = i;            /* exclusive: at '\n' or flen */
        if (i < flen) i++;         /* consume the '\n' */
        if (end > start && buf[end - 1] == '\r') end--; /* CRLF tolerance */

        /* skip blank (whitespace-only) lines */
        int blank = 1;
        for (size_t p = start; p < end; p++)
            if (!is_ws((unsigned char)buf[p])) { blank = 0; break; }
        if (blank) continue;

        size_t cidx = cs->n + 1; /* 1-based for messages */
        uint8_t row[ALPHA_N];
        size_t ntok = 0;
        size_t p = start;
        while (p < end) {
            while (p < end && (buf[p] == ' ' || buf[p] == '\t')) p++;
            if (p >= end) break;
            size_t ts = p;
            while (p < end && buf[p] != ' ' && buf[p] != '\t') p++;
            size_t tlen = p - ts;
            if (tlen != 1)
                die_validation("ciphers file '%s' cipher %zu: token %zu ('%.*s') "
                               "is not a single byte", path, cidx, ntok + 1,
                               (int)tlen, buf + ts);
            unsigned char tb = (unsigned char)buf[ts];
            if (tb < ALPHA_LO || tb > ALPHA_HI)
                die_validation("ciphers file '%s' cipher %zu: token %zu byte 0x%02X "
                               "outside printable range [0x21,0x7E]",
                               path, cidx, ntok + 1, tb);
            if (ntok < ALPHA_N) row[ntok] = tb;
            ntok++;
        }
        if (ntok != ALPHA_N)
            die_validation("ciphers file '%s' cipher %zu: expected %d tokens, got %zu",
                           path, cidx, ALPHA_N, ntok);

        /* bijection: 94 in-range tokens with no duplicate => permutation */
        int seen[ALPHA_N] = {0};
        for (int t = 0; t < ALPHA_N; t++) {
            int idx = row[t] - ALPHA_LO;
            if (seen[idx])
                die_validation("ciphers file '%s' cipher %zu: symbol '%c' appears "
                               "more than once (not a bijection)", path, cidx, row[t]);
            seen[idx] = 1;
        }

        if (cs->n == cap) {
            size_t ncap = cap ? cap * 2 : 8;
            if (cap > SIZE_MAX / 2 || ncap > SIZE_MAX / sizeof(*cs->enc))
                die_runtime("too many cipher alphabets");
            uint8_t (*ne)[ALPHA_N] = realloc(cs->enc, ncap * sizeof(*cs->enc));
            if (!ne) die_runtime("out of memory loading ciphers");
            cs->enc = ne; cap = ncap;
        }
        memcpy(cs->enc[cs->n], row, ALPHA_N);
        cs->n++;
    }
    free(buf);

    if (cs->n == 0)
        die_validation("ciphers file '%s': no cipher alphabets found", path);

    if (cs->n > SIZE_MAX / sizeof(*cs->inv))
        die_runtime("too many cipher alphabets");
    cs->inv = malloc(cs->n * sizeof(*cs->inv));
    if (!cs->inv) die_runtime("out of memory building inverse tables");
    for (size_t k = 0; k < cs->n; k++)
        for (int idx = 0; idx < ALPHA_N; idx++) {
            int j = cs->enc[k][idx] - ALPHA_LO;
            cs->inv[k][j] = (uint8_t)idx;
        }
}

/* ---- pattern -------------------------------------------------------- */

static void push_index(uint32_t **pat, size_t *len, size_t *cap, uint32_t v) {
    if (*len == *cap) {
        size_t ncap = *cap ? *cap * 2 : 16;
        if (*cap > SIZE_MAX / 2 || ncap > SIZE_MAX / sizeof(**pat))
            die_runtime("pattern too large");
        uint32_t *np = realloc(*pat, ncap * sizeof(**pat));
        if (!np) die_runtime("out of memory parsing pattern");
        *pat = np; *cap = ncap;
    }
    (*pat)[(*len)++] = v;
}

/* value is either "inline:<text>" or a file path. n = cipher count. */
static uint32_t *load_pattern(const char *value, size_t n, size_t *out_len) {
    const char *text;
    char *owned = NULL;
    size_t tlen;

    if (strncmp(value, "inline:", 7) == 0) {
        text = value + 7;
        tlen = strlen(text);
    } else {
        owned = read_whole_file(value, &tlen);
        if (!owned) die_runtime("cannot read pattern file '%s': %s",
                                value, strerror(errno));
        text = owned;
    }

    uint32_t *pat = NULL;
    size_t len = 0, cap = 0;

    if (n <= 9) {
        /* each digit is one index; separators ignored (SPEC §3.1) */
        for (size_t p = 0; p < tlen; p++) {
            unsigned char c = (unsigned char)text[p];
            if (is_sep(c)) continue;
            if (c < '0' || c > '9')
                die_validation("pattern: unexpected character '%c' (N=%zu uses one "
                               "digit per index)", c, n);
            uint32_t v = (uint32_t)(c - '0');
            if (v < 1 || v > n)
                die_validation("pattern: index %u out of range [1,%zu]", v, n);
            push_index(&pat, &len, &cap, v);
        }
    } else {
        /* whitespace/comma-separated decimal integers (SPEC §3.1).
         * A single unseparated run of >=2 digits is a "bare digit string":
         * ambiguous for N>9 (e.g. "12" could be index 12 or indices 1,2),
         * so it is rejected. Multi-digit indices are allowed only when the
         * pattern is explicitly separated into multiple tokens. */
        size_t ntok = 0, fts = 0, fte = 0;
        {
            size_t q = 0;
            while (q < tlen) {
                while (q < tlen && is_sep((unsigned char)text[q])) q++;
                if (q >= tlen) break;
                size_t s = q;
                while (q < tlen && !is_sep((unsigned char)text[q])) q++;
                if (ntok == 0) { fts = s; fte = q; }
                ntok++;
            }
        }
        if (ntok == 1 && fte - fts >= 2)
            die_validation("pattern: bare digit string '%.*s' is ambiguous for "
                           "N>9; separate indices with spaces, tabs, newlines, "
                           "or commas", (int)(fte - fts), text + fts);

        size_t p = 0;
        while (p < tlen) {
            while (p < tlen && is_sep((unsigned char)text[p])) p++;
            if (p >= tlen) break;
            size_t ts = p;
            while (p < tlen && !is_sep((unsigned char)text[p])) p++;
            size_t te = p;
            uint64_t v = 0;
            for (size_t q = ts; q < te; q++) {
                unsigned char c = (unsigned char)text[q];
                if (c < '0' || c > '9')
                    die_validation("pattern: invalid token '%.*s'",
                                   (int)(te - ts), text + ts);
                v = v * 10 + (uint64_t)(c - '0');
                if (v > n)
                    die_validation("pattern: index '%.*s' out of range [1,%zu]",
                                   (int)(te - ts), text + ts, n);
            }
            if (v < 1)
                die_validation("pattern: index 0 out of range [1,%zu]", n);
            push_index(&pat, &len, &cap, (uint32_t)v);
        }
    }

    free(owned);
    if (len == 0) die_validation("pattern is empty");
    *out_len = len;
    return pat;
}

/* ---- stream encrypt/decrypt ---------------------------------------- */

static void run_stream(int decrypt, const struct ciphers *cs,
                       const uint32_t *pat, size_t plen,
                       FILE *in, FILE *out) {
    unsigned char ibuf[65536];
    unsigned char obuf[65536];
    size_t olen = 0;
    unsigned long long offset = 0;
    size_t pos = 0; /* advances only on alphabet chars */
    size_t r;

    while ((r = fread(ibuf, 1, sizeof ibuf, in)) > 0) {
        for (size_t t = 0; t < r; t++) {
            unsigned char b = ibuf[t];
            unsigned char outb;
            if (is_ws(b)) {
                outb = b;
            } else {
                int idx = g_pidx[b];
                if (idx < 0)
                    die_runtime("input byte 0x%02X at offset %llu is not in the "
                                "alphabet", b, offset);
                uint32_t k = pat[pos % plen] - 1;
                outb = decrypt
                     ? (unsigned char)(ALPHA_LO + cs->inv[k][idx])
                     : cs->enc[k][idx];
                pos++;
            }
            if (olen == sizeof obuf) {
                if (fwrite(obuf, 1, olen, out) != olen)
                    die_runtime("write error: %s", strerror(errno));
                olen = 0;
            }
            obuf[olen++] = outb;
            offset++;
        }
    }
    if (ferror(in)) die_runtime("read error: %s", strerror(errno));
    if (olen && fwrite(obuf, 1, olen, out) != olen)
        die_runtime("write error: %s", strerror(errno));
    if (fflush(out) != 0 || ferror(out))
        die_runtime("write error: %s", strerror(errno));
}

/* ---- in-place transform -------------------------------------------- */

/* Temp file to remove if we exit before the atomic rename completes. */
static char *g_tmp_cleanup = NULL;
static void cleanup_tmp(void) {
    if (g_tmp_cleanup) unlink(g_tmp_cleanup);
}

/* Transform `path` in place: stream it through a sibling temp file, then
 * atomically rename over the original (so a failure never corrupts it). */
static void run_in_place(int decrypt, const struct ciphers *cs,
                         const uint32_t *pat, size_t plen, const char *path) {
    FILE *in = fopen(path, "rb");
    if (!in) die_runtime("cannot open input '%s': %s", path, strerror(errno));

    size_t plen_path = strlen(path);
    char *tmp = malloc(plen_path + sizeof "-rcodeXXXXXX");
    if (!tmp) die_runtime("out of memory");
    memcpy(tmp, path, plen_path);
    memcpy(tmp + plen_path, "-rcodeXXXXXX", sizeof "-rcodeXXXXXX");

    int fd = mkstemp(tmp);
    if (fd < 0) die_runtime("cannot create temp file for '%s': %s", path, strerror(errno));
    atexit(cleanup_tmp);
    g_tmp_cleanup = tmp; /* remove the temp if run_stream/IO fatally exits */

    FILE *out = fdopen(fd, "wb");
    if (!out) { close(fd); die_runtime("cannot open temp file: %s", strerror(errno)); }

    /* Best-effort: give the new file the original's permission bits.
     * fstat on the already-open input fd avoids a TOCTOU on the path. */
    struct stat st;
    if (fstat(fileno(in), &st) == 0) (void)fchmod(fd, st.st_mode & 07777);

    run_stream(decrypt, cs, pat, plen, in, out);

    fclose(in);
    if (fclose(out) != 0) die_runtime("write error on temp file: %s", strerror(errno));
    if (rename(tmp, path) != 0)
        die_runtime("cannot replace '%s': %s", path, strerror(errno));

    g_tmp_cleanup = NULL; /* renamed away; nothing to clean up */
    free(tmp);
}

/* ---- CLI ------------------------------------------------------------ */

static void print_help(void) {
    fputs(
"Usage:\n"
"  rcode encrypt --ciphers <file> --pattern <file|inline:...> [--in <f>] [--out <f>]\n"
"  rcode decrypt --ciphers <file> --pattern <file|inline:...> [--in <f>] [--out <f>]\n"
"  rcode <encrypt|decrypt> --ciphers <file> --pattern <...> --in-place <file>\n"
"\n"
"Options:\n"
"  --ciphers <file>   cipher-alphabet file: each non-blank line is 94 single-byte\n"
"                     tokens (a permutation of 0x21..0x7E). Required.\n"
"  --pattern <value>  pattern file path, or inline:<text>. Indices in [1,N] where\n"
"                     N is the cipher count. For N<=9 a bare digit string like\n"
"                     132312 works; for N>9 indices must be separated. Required.\n"
"  --in <file>        input path (default: stdin).\n"
"  --out <file>       output path (default: stdout).\n"
"  --in-place <file>  transform <file> in place (atomic temp + rename); cannot be\n"
"                     combined with --in or --out.\n"
"  --help, --version\n"
"\n"
"Exit codes: 0 ok, 1 usage error, 2 validation error, 3 runtime/IO error.\n",
        stdout);
}

static void print_version(void) {
    puts("rcode " RCODE_VERSION);
}

int main(int argc, char **argv) {
    init_pidx();

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help")) {
            print_help(); return EX_OK;
        }
        if (!strcmp(argv[i], "--version")) {
            print_version(); return EX_OK;
        }
    }

    if (argc < 2)
        die_usage("missing subcommand (encrypt|decrypt). Try --help");

    int decrypt;
    if (!strcmp(argv[1], "encrypt")) decrypt = 0;
    else if (!strcmp(argv[1], "decrypt")) decrypt = 1;
    else die_usage("unknown subcommand '%s' (expected encrypt|decrypt)", argv[1]);

    const char *ciphers = NULL, *pattern = NULL, *infile = NULL, *outfile = NULL;
    const char *inplace = NULL;
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--ciphers")) {
            if (ciphers) die_usage("--ciphers given more than once");
            if (++i >= argc) die_usage("--ciphers requires a value");
            ciphers = argv[i];
        } else if (!strcmp(a, "--pattern")) {
            if (pattern) die_usage("--pattern given more than once");
            if (++i >= argc) die_usage("--pattern requires a value");
            pattern = argv[i];
        } else if (!strcmp(a, "--in")) {
            if (infile) die_usage("--in given more than once");
            if (++i >= argc) die_usage("--in requires a value");
            infile = argv[i];
        } else if (!strcmp(a, "--out")) {
            if (outfile) die_usage("--out given more than once");
            if (++i >= argc) die_usage("--out requires a value");
            outfile = argv[i];
        } else if (!strcmp(a, "--in-place")) {
            if (inplace) die_usage("--in-place given more than once");
            if (++i >= argc) die_usage("--in-place requires a value");
            inplace = argv[i];
        } else {
            die_usage("unknown argument '%s'", a);
        }
    }
    if (!ciphers) die_usage("--ciphers is required");
    if (!pattern) die_usage("--pattern is required");
    if (inplace && (infile || outfile))
        die_usage("--in-place cannot be combined with --in or --out");

    struct ciphers cs;
    load_ciphers(ciphers, &cs);

    size_t plen;
    uint32_t *pat = load_pattern(pattern, cs.n, &plen);

    if (inplace) {
        run_in_place(decrypt, &cs, pat, plen, inplace);
    } else {
        FILE *in = infile ? fopen(infile, "rb") : stdin;
        if (!in) die_runtime("cannot open input '%s': %s", infile, strerror(errno));
        FILE *out = outfile ? fopen(outfile, "wb") : stdout;
        if (!out) die_runtime("cannot open output '%s': %s", outfile, strerror(errno));

        run_stream(decrypt, &cs, pat, plen, in, out);

        if (infile) fclose(in);
        if (outfile && fclose(out) != 0)
            die_runtime("write error closing '%s': %s", outfile, strerror(errno));
    }

    free(pat);
    free(cs.enc);
    free(cs.inv);
    return EX_OK;
}
