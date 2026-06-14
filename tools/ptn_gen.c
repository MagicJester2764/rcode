/*
 * ptn-gen — generate .ptn pattern files for rcode from one or more .cps files.
 *
 *   ptn-gen CPS_FILE... [--length L] [--files M] [-o FILE | --out-dir DIR]
 *                       [--seed S] [--force]
 *
 * N is the total number of ciphers across all input .cps files. The pattern is
 * L uniformly random indices in [1,N], space-separated. L defaults to 3*N and
 * must be at least N. Multiple independent patterns can be produced (--files);
 * patterns are never combined.
 *
 * C11, no external dependencies. See cpscommon.h for shared helpers.
 */
#include "cpscommon.h"

#define PTN_GEN_VERSION "1.0"
#define NAMEBUF 64
#define PATHBUF 4096

static void print_help(void) {
    fputs(
"Usage:\n"
"  ptn-gen CPS_FILE... [--length L] [--files M] [-o FILE | --out-dir DIR] [--seed S] [--force]\n"
"\n"
"Generates a random rcode pattern over N ciphers, where N is the TOTAL cipher\n"
"count across all input .cps files. Indices are uniform in [1,N].\n"
"\n"
"  --length L     pattern length (default 3*N, minimum N).\n"
"  --files M      number of independent pattern files (default 1).\n"
"  -o, --out FILE exact output path (only when M=1).\n"
"  --out-dir DIR  existing directory for default-named output (excludes -o).\n"
"  --seed S       seed the RNG for reproducible output.\n"
"  --force        overwrite existing files instead of refusing.\n"
"  --help, --version\n"
"\n"
"Default names are <YYYYMMDD-HHMMSS>.ptn, or <YYYYMMDD-HHMMSS>-<i>.ptn (i from 1)\n"
"when M>1.\n"
"\n"
"Note: rcode reads a single --ciphers file. If you pass multiple .cps files\n"
"here, combine them first (cps-gen combine) so the encrypt-time cipher count\n"
"matches this pattern's index range.\n"
"\n"
"Exit codes: 0 ok, 1 usage error, 2 validation error, 3 runtime/IO error.\n",
        stdout);
}

static void print_version(void) { puts("ptn-gen " PTN_GEN_VERSION); }

static void write_pattern(const char *path, int force, uint64_t len,
                          size_t n, cps_rng *rng) {
    FILE *f = cps_open_out(path, force);
    for (uint64_t j = 0; j < len; j++) {
        uint64_t v = 1 + cps_rnd_below(rng, (uint64_t)n);
        if (j) fputc(' ', f);
        fprintf(f, "%llu", (unsigned long long)v);
    }
    fputc('\n', f);
    cps_close_out(f, path);
    printf("wrote %s (length %llu, N=%zu)\n", path, (unsigned long long)len, n);
}

int main(int argc, char **argv) {
    g_prog = "ptn-gen";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help")) { print_help(); return CPS_OK; }
        if (!strcmp(argv[i], "--version")) { print_version(); return CPS_OK; }
    }

    uint64_t length = 0, files = 1, seed = 0;
    int have_length = 0, have_seed = 0, force = 0;
    const char *outfile = NULL, *outdir = NULL;
    const char **inputs = malloc(sizeof(*inputs) * (size_t)(argc > 1 ? argc : 1));
    if (!inputs) die_runtime("out of memory");
    size_t nin = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--length")) {
            length = cps_parse_u64(i + 1 < argc ? argv[++i] : NULL, "--length");
            have_length = 1;
        } else if (!strcmp(a, "--files")) {
            files = cps_parse_u64(i + 1 < argc ? argv[++i] : NULL, "--files");
        } else if (!strcmp(a, "--out") || !strcmp(a, "-o")) {
            if (++i >= argc) die_usage("--out requires a value");
            outfile = argv[i];
        } else if (!strcmp(a, "--out-dir")) {
            if (++i >= argc) die_usage("--out-dir requires a value");
            outdir = argv[i];
        } else if (!strcmp(a, "--seed")) {
            seed = cps_parse_u64(i + 1 < argc ? argv[++i] : NULL, "--seed");
            have_seed = 1;
        } else if (!strcmp(a, "--force")) {
            force = 1;
        } else if (a[0] == '-' && a[1]) {
            die_usage("unknown argument '%s'", a);
        } else {
            inputs[nin++] = a;
        }
    }
    if (nin < 1) die_usage("ptn-gen needs at least one input .cps file");
    if (files < 1) die_usage("--files must be >= 1");
    if (outfile && outdir) die_usage("--out and --out-dir are mutually exclusive");
    if (outfile && files > 1)
        die_usage("--out names a single file but --files is %llu", (unsigned long long)files);
    if (outdir) cps_check_dir(outdir);

    /* N = total ciphers across all inputs (each file fully validated). */
    uint8_t (*rows)[CPS_N] = NULL;
    size_t n = 0, cap = 0;
    for (size_t k = 0; k < nin; k++) cps_load_into(inputs[k], &rows, &n, &cap);
    free(rows); /* only the count matters */

    uint64_t L;
    if (have_length) {
        L = length;
        if (L < (uint64_t)n)
            die_validation("--length %llu is less than the cipher count N=%zu",
                           (unsigned long long)L, n);
    } else {
        if ((uint64_t)n > UINT64_MAX / 3)
            die_runtime("cipher count too large for default length");
        L = (uint64_t)n * 3;
    }

    cps_rng rng;
    if (have_seed) cps_rng_seed_fixed(&rng, seed); else cps_rng_seed_os(&rng);

    char ts[16];
    cps_timestamp(ts, sizeof ts);
    int multi = files > 1;

    for (uint64_t fi = 0; fi < files; fi++) {
        char namebuf[NAMEBUF], pathbuf[PATHBUF];
        const char *path;
        if (outfile) {
            path = outfile;
        } else {
            cps_build_name(namebuf, sizeof namebuf, ts, ".ptn", multi, (size_t)(fi + 1));
            cps_join(pathbuf, sizeof pathbuf, outdir, namebuf);
            path = pathbuf;
        }
        write_pattern(path, force, L, n, &rng);
    }

    free(inputs);
    return CPS_OK;
}
