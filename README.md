# RCode

A polyalphabetic substitution cipher utility in C11. It generalizes the
original RC1/RC2/RC3 scheme to an arbitrary number `N` of substitution
alphabets over the **94 printable non-space ASCII characters**, selected
per character by a repeating index pattern.

See [`SPEC.md`](SPEC.md) for the authoritative specification. This is a toy
cipher with **no cryptographic security claim**.

## Build

```
make            # builds ./rcode
make test       # builds and runs the test suite
make fixtures   # regenerates the committed test fixtures from RCode.txt
make clean
```

No external dependencies; a C11 compiler is all that's required.

## Usage

```
rcode encrypt --ciphers <file> --pattern <file|inline:...> [--in <file>] [--out <file>]
rcode decrypt --ciphers <file> --pattern <file|inline:...> [--in <file>] [--out <file>]
rcode <encrypt|decrypt> --ciphers <file> --pattern <...> --in-place <file>
```

- `--ciphers <file>` — cipher-alphabet file (required). Each non-blank line is
  one cipher: exactly 94 single-byte tokens (a permutation of `0x21..0x7E`)
  separated by spaces/tabs, in plaintext-alphabet order. Ciphers are numbered
  from 1 in file order; `N` is the number of cipher lines.
- `--pattern <value>` — a pattern file path, or an inline value prefixed
  `inline:`. Indices lie in `[1,N]`, separated by space/tab/newline/comma. For
  `N ≤ 9` a bare digit string such as `132312` is accepted (one digit per
  index); for `N > 9` indices must be separated.
- `--in` / `--out` — default to stdin / stdout.
- `--in-place <file>` — transform `<file>` and write the result back to it
  (written to a sibling temp file and atomically renamed, so a failure never
  corrupts the original). Mutually exclusive with `--in` / `--out`.
- `--help`, `--version`.

Whitespace (space, tab, CR, LF) passes through untouched and does not advance
the pattern. Letter case is significant. Any other byte is a fatal error.

### Example

```
$ printf 'the quick brown fox jumps over the lazy dog\n' \
    | rcode encrypt --ciphers tests/fixtures/rc123.cps --pattern inline:132312
q2" ye23z cu9sd g0? 'a4lm 6y". _.o h;jf b65
```

Round-trip guarantee: `decrypt(encrypt(P)) == P` for any input `P` of
plaintext-alphabet bytes and whitespace under the same `(ciphers, pattern)`.

## Generating keys: `cps-gen` and `ptn-gen`

`make` also builds two helpers for producing the input files. Both name their
output `<YYYYMMDD-HHMMSS>.<ext>`, or `<...>-<i>.<ext>` (`i` from 1) when more
than one file is produced; both refuse to overwrite an existing file unless
`--force`, and accept `--seed S` for reproducible output.

`cps-gen` — create / combine / split cipher files:

```
cps-gen gen     [--per-file C] [--files M] [-o FILE | --out-dir DIR] [--seed S] [--force]
cps-gen combine FILE... [-o FILE | --out-dir DIR] [--force]
cps-gen split   FILE [--per-file K] [--out-dir DIR] [--force]
```

- `gen` writes random valid cipher alphabets — `--per-file C` ciphers per file,
  across `--files M` files.
- `combine` concatenates the ciphers of several `.cps` files into one.
- `split` breaks one `.cps` file into parts of `K` ciphers each.

`ptn-gen` — create pattern files from existing cipher files:

```
ptn-gen CPS_FILE... [--length L] [--files M] [-o FILE | --out-dir DIR] [--seed S] [--force]
```

`N` is the total cipher count across all input `.cps` files. The pattern is `L`
uniformly random indices in `[1,N]`; `L` defaults to `3*N` and must be at least
`N`. Because `rcode` reads a single `--ciphers` file, combine multiple `.cps`
inputs (`cps-gen combine`) before encrypting so the index range matches.

```
$ cps-gen gen --per-file 3 -o key.cps
$ ptn-gen key.cps -o key.ptn
$ rcode encrypt --ciphers key.cps --pattern key.ptn --in msg.txt --out msg.enc
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | success |
| `1`  | usage error (bad command line) |
| `2`  | validation error (malformed cipher or pattern file) |
| `3`  | runtime/IO error (file open/read/write, refusing to overwrite, or an out-of-alphabet byte in the data stream) |

All three tools (`rcode`, `cps-gen`, `ptn-gen`) share these codes.

## Layout

```
src/rcode.c          the tool (single translation unit)
tools/cpscommon.h    shared helpers for the generators (.cps load/validate, RNG, naming)
tools/cps_gen.c      cps-gen: generate / combine / split .cps files
tools/ptn_gen.c      ptn-gen: generate .ptn files from .cps files
tools/gen_fixtures.c generates the committed test fixtures from RCode.txt
tests/run_tests.sh   rcode test runner (round-trips + exit-code assertions)
tests/gen_tests.sh   cps-gen / ptn-gen tests (round-trip, split/combine, exit codes)
tests/fixtures/      committed static cipher/pattern/input fixtures
```
