/*
 * cps-gen — generate, combine, and split .cps cipher-alphabet files for rcode.
 *
 *   cps-gen gen     [--per-file C] [--files M] [-o FILE | --out-dir DIR]
 *                   [--seed S] [--force]
 *   cps-gen combine FILE... [-o FILE | --out-dir DIR] [--force]
 *   cps-gen split   FILE [--per-file K] [--out-dir DIR] [--force]
 *
 * C11, no external dependencies. See cpscommon.h for shared helpers.
 */
#include "cpscommon.h"

#define CPS_GEN_VERSION "1.0"
#define NAMEBUF 64
#define PATHBUF 4096

static void print_help(void) {
    fputs(
"Usage:\n"
"  cps-gen gen     [--per-file C] [--files M] [-o FILE | --out-dir DIR] [--seed S] [--force]\n"
"  cps-gen combine FILE... [-o FILE | --out-dir DIR] [--force]\n"
"  cps-gen split   FILE [--per-file K] [--out-dir DIR] [--force]\n"
"\n"
"gen      Generate random valid cipher alphabets (94-symbol permutations).\n"
"         --per-file C  ciphers per file (default 1).\n"
"         --files M     number of files (default 1). M>1 names them <ts>-<i>.cps.\n"
"combine  Concatenate the ciphers of all input .cps files into one .cps.\n"
"split    Split one .cps file's ciphers into parts of K ciphers each\n"
"         (default K=1), named <ts>-<i>.cps.\n"
"\n"
"  -o, --out FILE   exact output path (only when a single file is produced).\n"
"  --out-dir DIR    existing directory for default-named output (excludes -o).\n"
"  --seed S         seed the RNG for reproducible output.\n"
"  --force          overwrite existing files instead of refusing.\n"
"  --help, --version\n"
"\n"
"Default names are <YYYYMMDD-HHMMSS>.cps, or <YYYYMMDD-HHMMSS>-<i>.cps (i from 1)\n"
"when more than one file is produced.\n"
"Exit codes: 0 ok, 1 usage error, 2 validation error, 3 runtime/IO error.\n",
        stdout);
}

static void print_version(void) { puts("cps-gen " CPS_GEN_VERSION); }

/* Write one cipher row to an open file. */
static void write_row(FILE *f, uint8_t row[CPS_N]) {
    uint8_t (*one)[CPS_N] = (uint8_t (*)[CPS_N])row;
    cps_write(f, one, 1);
}

static void cmd_gen(int argc, char **argv) {
    uint64_t per_file = 1, files = 1, seed = 0;
    const char *outfile = NULL, *outdir = NULL;
    int force = 0, have_seed = 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--per-file"))
            per_file = cps_parse_u64(i + 1 < argc ? argv[++i] : NULL, "--per-file");
        else if (!strcmp(a, "--files"))
            files = cps_parse_u64(i + 1 < argc ? argv[++i] : NULL, "--files");
        else if (!strcmp(a, "--out") || !strcmp(a, "-o")) {
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
        } else {
            die_usage("unknown argument '%s'", a);
        }
    }
    if (per_file < 1) die_usage("--per-file must be >= 1");
    if (files < 1) die_usage("--files must be >= 1");
    if (outfile && outdir) die_usage("--out and --out-dir are mutually exclusive");
    if (outfile && files > 1)
        die_usage("--out names a single file but --files is %llu", (unsigned long long)files);
    if (outdir) cps_check_dir(outdir);

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
            cps_build_name(namebuf, sizeof namebuf, ts, ".cps", multi, (size_t)(fi + 1));
            cps_join(pathbuf, sizeof pathbuf, outdir, namebuf);
            path = pathbuf;
        }
        FILE *f = cps_open_out(path, force);
        for (uint64_t c = 0; c < per_file; c++) {
            uint8_t row[CPS_N];
            cps_fisher_yates(row, &rng);
            write_row(f, row);
        }
        cps_close_out(f, path);
        printf("wrote %s (%llu cipher%s)\n", path,
               (unsigned long long)per_file, per_file == 1 ? "" : "s");
    }
}

static void cmd_combine(int argc, char **argv) {
    const char *outfile = NULL, *outdir = NULL;
    int force = 0;
    const char **inputs = malloc(sizeof(*inputs) * (size_t)argc);
    if (!inputs) die_runtime("out of memory");
    size_t nin = 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--out") || !strcmp(a, "-o")) {
            if (++i >= argc) die_usage("--out requires a value");
            outfile = argv[i];
        } else if (!strcmp(a, "--out-dir")) {
            if (++i >= argc) die_usage("--out-dir requires a value");
            outdir = argv[i];
        } else if (!strcmp(a, "--force")) {
            force = 1;
        } else if (a[0] == '-' && a[1]) {
            die_usage("unknown argument '%s'", a);
        } else {
            inputs[nin++] = a;
        }
    }
    if (nin < 1) die_usage("combine needs at least one input .cps file");
    if (outfile && outdir) die_usage("--out and --out-dir are mutually exclusive");
    if (outdir) cps_check_dir(outdir);

    uint8_t (*rows)[CPS_N] = NULL;
    size_t n = 0, cap = 0;
    for (size_t k = 0; k < nin; k++) cps_load_into(inputs[k], &rows, &n, &cap);

    char ts[16], namebuf[NAMEBUF], pathbuf[PATHBUF];
    const char *path;
    if (outfile) {
        path = outfile;
    } else {
        cps_timestamp(ts, sizeof ts);
        cps_build_name(namebuf, sizeof namebuf, ts, ".cps", 0, 0);
        cps_join(pathbuf, sizeof pathbuf, outdir, namebuf);
        path = pathbuf;
    }
    FILE *f = cps_open_out(path, force);
    cps_write(f, rows, n);
    cps_close_out(f, path);
    printf("wrote %s (%zu ciphers)\n", path, n);

    free(rows);
    free(inputs);
}

static void cmd_split(int argc, char **argv) {
    uint64_t per_file = 1;
    const char *outdir = NULL, *infile = NULL;
    int force = 0;

    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--per-file"))
            per_file = cps_parse_u64(i + 1 < argc ? argv[++i] : NULL, "--per-file");
        else if (!strcmp(a, "--out-dir")) {
            if (++i >= argc) die_usage("--out-dir requires a value");
            outdir = argv[i];
        } else if (!strcmp(a, "--force")) {
            force = 1;
        } else if (a[0] == '-' && a[1]) {
            die_usage("unknown argument '%s'", a);
        } else if (!infile) {
            infile = a;
        } else {
            die_usage("split takes a single input file (got extra '%s')", a);
        }
    }
    if (!infile) die_usage("split needs an input .cps file");
    if (per_file < 1) die_usage("--per-file must be >= 1");
    if (outdir) cps_check_dir(outdir);

    uint8_t (*rows)[CPS_N] = NULL;
    size_t n = 0, cap = 0;
    cps_load_into(infile, &rows, &n, &cap);

    size_t parts = (n + per_file - 1) / per_file;
    char ts[16];
    cps_timestamp(ts, sizeof ts);

    for (size_t p = 0; p < parts; p++) {
        char namebuf[NAMEBUF], pathbuf[PATHBUF];
        cps_build_name(namebuf, sizeof namebuf, ts, ".cps", 1, (size_t)(p + 1));
        cps_join(pathbuf, sizeof pathbuf, outdir, namebuf);
        size_t start = p * per_file;
        size_t cnt = n - start < per_file ? n - start : per_file;
        FILE *f = cps_open_out(pathbuf, force);
        cps_write(f, rows + start, cnt);
        cps_close_out(f, pathbuf);
        printf("wrote %s (%zu cipher%s)\n", pathbuf, cnt, cnt == 1 ? "" : "s");
    }
    free(rows);
}

int main(int argc, char **argv) {
    g_prog = "cps-gen";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help")) { print_help(); return CPS_OK; }
        if (!strcmp(argv[i], "--version")) { print_version(); return CPS_OK; }
    }
    if (argc < 2) die_usage("missing subcommand (gen|combine|split). Try --help");

    const char *sub = argv[1];
    if (!strcmp(sub, "gen")) cmd_gen(argc, argv);
    else if (!strcmp(sub, "combine")) cmd_combine(argc, argv);
    else if (!strcmp(sub, "split")) cmd_split(argc, argv);
    else die_usage("unknown subcommand '%s' (expected gen|combine|split)", sub);

    return CPS_OK;
}
