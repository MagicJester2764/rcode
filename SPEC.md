# RCode — Specification

A polyalphabetic substitution cipher utility in C. Generalizes the original
RC1/RC2/RC3 scheme to an arbitrary number `N` of substitution alphabets,
selected per character by a repeating index pattern.

## 1. Plaintext alphabet

A fixed ordered set of the **94 printable non-space ASCII characters**, in
ASCII code-point order (`0x21` `!` through `0x7E` `~`):

```
! " # $ % & ' ( ) * + , - . /
0 1 2 3 4 5 6 7 8 9
: ; < = > ? @
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
[ \ ] ^ _ `
a b c d e f g h i j k l m n o p q r s t u v w x y z
{ | } ~
```

- Positions are 1-indexed in this document; 0-indexed in code.
- Letter case is significant: `A` and `a` are distinct plaintext symbols and
  encrypt independently. No case folding.
- Whitespace (space `0x20`, tab `0x09`, CR `0x0D`, LF `0x0A`) is passed
  through untouched and does **not** advance the pattern counter.
- Any other byte (non-ASCII, NUL, other control chars) is a hard error
  (exit non-zero, message to stderr including the byte offset).

## 2. Substitution alphabets

A *cipher alphabet* is a permutation of the 94 plaintext symbols. The symbol
at position `i` of cipher `k` is the ciphertext for the `i`-th plaintext
symbol under cipher `k`.

### 2.1 File format

A plain-text file. Each non-blank line is one cipher alphabet: exactly 94
single-byte tokens separated by ASCII spaces and/or tabs, in
plaintext-alphabet order. Blank lines (only whitespace) are skipped.

The format has **no comment syntax** because every printable ASCII character
is now in the alphabet and would collide with any marker. Keep notes in a
sidecar file.

Example layout (one cipher on one line, broken here only for readability —
real files keep each cipher on a single line):

```
! " # $ % & ' ( ) * + , - . / 0 1 2 3 4 5 6 7 8 9 : ; < = > ? @
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z [ \ ] ^ _ `
a b c d e f g h i j k l m n o p q r s t u v w x y z { | } ~
```

(That example is the identity permutation. Real ciphers should be non-trivial
rearrangements.)

Ciphers are numbered starting at **1** in file order.

### 2.2 Validation (load time, fatal on failure)

For each cipher alphabet:

1. Exactly 94 tokens, each exactly one byte, each in `[0x21, 0x7E]`.
2. **Bijection check**: every plaintext symbol appears exactly once.
   (This rejects the original RC3-style collision where `x` and `0` both
   mapped to `?`.)

If any cipher fails, exit non-zero, name the file, the cipher index, and the
offending symbol(s) or token count.

## 3. Pattern

A sequence of cipher indices in `[1, N]`. Applied in order to consecutive
*alphabet* characters of the input, wrapping around when exhausted.
Whitespace input does not consume a pattern slot.

### 3.1 File format

A plain-text file containing integers separated by ASCII space, tab, newline,
or comma. No comments.

- For `N ≤ 9`, a bare digit string like `132312` is accepted (each digit is
  one index).
- For `N > 9`, indices **must** be whitespace- or comma-separated; bare digit
  strings are rejected to avoid ambiguity.

The pattern must be non-empty and every value must lie in `[1, N]`. Validation
errors are fatal.

The `--pattern` CLI flag also accepts an inline value as `inline:<text>`
where `<text>` follows the same rules.

## 4. CLI

```
rcode encrypt --ciphers <file> --pattern <file|inline> [--in <file>] [--out <file>]
rcode decrypt --ciphers <file> --pattern <file|inline> [--in <file>] [--out <file>]
```

- `--ciphers <file>` — path to the cipher-alphabet file (§2.1). Required.
- `--pattern <value>` — path to a pattern file (§3.1), or an inline value
  prefixed `inline:` (e.g. `--pattern inline:132312` or
  `--pattern inline:1,3,2,3,1,2`). Required.
- `--in <file>` — input path; defaults to stdin.
- `--out <file>` — output path; defaults to stdout.
- `--help`, `--version`.

Exit codes: `0` success, `1` usage error, `2` validation error,
`3` runtime/IO error.

## 5. Encryption

For each input byte in order:

1. If it is whitespace (space, tab, CR, LF), emit it verbatim. Do not advance
   the pattern.
2. Else, look up its plaintext index `i ∈ [0, 93]`. If not found, fatal error.
3. Take the next pattern value `k` (wrapping). Emit cipher `k`'s symbol at
   position `i`.

## 6. Decryption

Identical to §5 but using the inverse permutation of cipher `k`. Inverses are
precomputed at load time from the validated bijections.

Decryption assumes the input was produced under the same `(ciphers, pattern)`
pair. A non-whitespace ciphertext byte not present in cipher `k`'s alphabet
is a fatal error.

## 7. Round-trip guarantee

For any input `P` consisting only of plaintext-alphabet bytes and whitespace,
and any valid `(ciphers, pattern)`:

```
decrypt(encrypt(P)) == P
```

The test suite must cover at minimum:

- The three single-cipher and one mixed-pattern examples from `RCode.txt`,
  with input lowercased (the original `T` becomes `t` since case folding is
  no longer automatic) and the cipher alphabets extended to 94 symbols (the
  original 44 mappings preserved; the additional 50 symbols filled by any
  valid permutation).
- A pattern longer than the input.
- An input longer than the pattern (forces wrap).
- All 94 alphabet symbols in one input, including both `A` and `a` to confirm
  case is significant.
- `N = 1`, `N = 3`, `N = 9`, `N = 10` (digit-string boundary), `N = 50`.
- Rejection cases: non-bijection cipher, out-of-range pattern index,
  out-of-alphabet input byte (non-ASCII or control char), wrong token count
  on a cipher line.

## 8. Implementation notes

- Target C11, no external dependencies. Single translation unit acceptable.
- Byte → plaintext-index lookup: a 256-entry `int16_t` table indexed by the
  raw byte. Entries for `0x21..0x7E` hold the symbol's index `0..93`;
  everything else holds `-1`. Whitespace bytes are tested before the lookup
  and never reach it.
- Cipher and inverse tables: two `uint8_t[N][94]` arrays. Lookup is O(1).
- Pattern stored as a `uint32_t` array; index with `pos % pattern_len`.
- Stream input/output; do not require the whole file in memory.
- All diagnostics to stderr; only ciphertext/plaintext to stdout.

## 9. Out of scope (v1)

- Configurable plaintext alphabet.
- Binary input, non-ASCII (UTF-8) input, or extended ASCII.
- Pattern generation / key derivation.
- Any cryptographic security claim — this is a toy substitution cipher.
