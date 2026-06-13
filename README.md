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
- `--help`, `--version`.

Whitespace (space, tab, CR, LF) passes through untouched and does not advance
the pattern. Letter case is significant. Any other byte is a fatal error.

### Example

```
$ printf 'the quick brown fox jumps over the lazy dog\n' \
    | rcode encrypt --ciphers tests/fixtures/rc123.ciphers --pattern inline:132312
q2" ye23z cu9sd g0? 'a4lm 6y". _.o h;jf b65
```

Round-trip guarantee: `decrypt(encrypt(P)) == P` for any input `P` of
plaintext-alphabet bytes and whitespace under the same `(ciphers, pattern)`.

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | success |
| `1`  | usage error (bad command line) |
| `2`  | validation error (malformed cipher or pattern file) |
| `3`  | runtime/IO error (file open/read/write, or an out-of-alphabet byte in the data stream) |

## Layout

```
src/rcode.c          the tool (single translation unit)
tools/gen_fixtures.c generates the committed test fixtures from RCode.txt
tests/run_tests.sh   test runner (round-trips + exit-code assertions)
tests/fixtures/      committed static cipher/pattern/input fixtures
```
