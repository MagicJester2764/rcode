#!/bin/sh
# rcode test suite. POSIX sh. Usage: sh tests/run_tests.sh [path-to-rcode]
# Drives the compiled binary against the committed fixtures and asserts the
# round-trip guarantee (SPEC §7) plus exit codes for every rejection case.
set -u

RCODE="${1:-./rcode}"
DIR=$(dirname "$0")
FIX="$DIR/fixtures"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'PASS  %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }

# roundtrip <name> <ciphers> <pattern> <infile>
roundtrip() {
    name=$1; ciph=$2; pat=$3; inf=$4
    "$RCODE" encrypt --ciphers "$ciph" --pattern "$pat" --in "$inf" --out "$TMP/ct" 2>"$TMP/e"
    if [ $? -ne 0 ]; then bad "$name (encrypt: $(cat "$TMP/e"))"; return; fi
    "$RCODE" decrypt --ciphers "$ciph" --pattern "$pat" --in "$TMP/ct" --out "$TMP/pt" 2>"$TMP/e"
    if [ $? -ne 0 ]; then bad "$name (decrypt: $(cat "$TMP/e"))"; return; fi
    if cmp -s "$inf" "$TMP/pt"; then ok "$name"; else bad "$name (round-trip mismatch)"; fi
}

# expect_exit <name> <expected-code> <cmd...>
expect_exit() {
    name=$1; exp=$2; shift 2
    "$@" >/dev/null 2>"$TMP/e"
    got=$?
    if [ "$got" -eq "$exp" ]; then ok "$name (exit $got)"
    else bad "$name (expected $exp, got $got: $(cat "$TMP/e"))"; fi
}

# expect_stderr <name> <substring>  (checks the stderr left by the previous expect_exit)
expect_stderr() {
    if grep -q -- "$2" "$TMP/e"; then ok "$1 (stderr names the path)"
    else bad "$1 (stderr missing '$2': $(cat "$TMP/e"))"; fi
}

# exact_output <name> <ciphers> <pattern> <infile> <expected-file>  (asserts exit 0 AND bytes)
exact_output() {
    name=$1; ciph=$2; pat=$3; inf=$4; exp=$5
    "$RCODE" encrypt --ciphers "$ciph" --pattern "$pat" --in "$inf" --out "$TMP/ct" 2>"$TMP/e"
    if [ $? -ne 0 ]; then bad "$name (encrypt exit nonzero: $(cat "$TMP/e"))"; return; fi
    if cmp -s "$TMP/ct" "$exp"; then ok "$name"; else bad "$name (got: $(cat "$TMP/ct"))"; fi
}

# ---- round-trips: RCode.txt examples (lowercased), single + mixed -----
roundtrip "rc1 single-cipher (tqbf)"  "$FIX/rc1.ciphers"   inline:1       "$FIX/tqbf.txt"
roundtrip "rc2 single-cipher (tqbf)"  "$FIX/rc2.ciphers"   inline:1       "$FIX/tqbf.txt"
roundtrip "rc3 single-cipher (tqbf)"  "$FIX/rc3.ciphers"   inline:1       "$FIX/tqbf.txt"
roundtrip "rc123 mixed pattern 132312" "$FIX/rc123.ciphers" inline:132312 "$FIX/tqbf.txt"
roundtrip "mixed pattern from file"   "$FIX/rc123.ciphers" "$FIX/pat132312.txt" "$FIX/tqbf.txt"

# ---- known-answer tests: exact ciphertext must match RCode.txt --------
# These pin actual substitution; round-trip alone cannot detect a no-op/identity cipher.
printf 'q2" ye23z cu9sd g0? %sa4lm 6y". _.o h;jf b65\n' "'" >"$TMP/expect"
exact_output "mixed KAT == RCode.txt line 23" "$FIX/rc123.ciphers" inline:132312 "$FIX/tqbf.txt" "$TMP/expect"
printf 'qb? 6e13v !.9ud 098 %se4f2 9y?. qb? hgjc 795\n' "'" >"$TMP/expect"
exact_output "rc1 KAT == RCode.txt line 11" "$FIX/rc1.ciphers" inline:1 "$FIX/tqbf.txt" "$TMP/expect"
printf '_2o yr,%sz 3u64j g6? hrkl7 6"ou _2o tq5f p6x\n' "'" >"$TMP/expect"
exact_output "rc3 KAT == RCode.txt line 17" "$FIX/rc3.ciphers" inline:1 "$FIX/tqbf.txt" "$TMP/expect"

# no-op guard: a real cipher must change the bytes (catches identity/no-op regressions)
"$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt" --out "$TMP/ct" 2>"$TMP/e"
if cmp -s "$FIX/tqbf.txt" "$TMP/ct"; then bad "rc1 encrypt was a no-op"
else ok "rc1 encrypt changes bytes (not a no-op)"; fi

# ---- pattern length vs input length ----------------------------------
printf 'hi' >"$TMP/short"
roundtrip "pattern longer than input" "$FIX/n3.ciphers" inline:123123123 "$TMP/short"
roundtrip "input longer than pattern (wrap)" "$FIX/n3.ciphers" inline:12 "$FIX/tqbf.txt"

# ---- all 94 symbols incl both A and a (case significance) ------------
roundtrip "all 94 symbols (A != a)" "$FIX/rc123.ciphers" inline:132312 "$FIX/all94.txt"

# identity cipher: ciphertext must equal plaintext exactly (exact-output)
exact_output "identity cipher is a no-op (exact output)" "$FIX/identity.ciphers" inline:1 "$FIX/all94.txt" "$FIX/all94.txt"

# ---- N boundaries: 1, 3, 9, 10, 50 -----------------------------------
roundtrip "N=1"  "$FIX/n1.ciphers"  inline:1            "$FIX/tqbf.txt"
roundtrip "N=3"  "$FIX/n3.ciphers"  inline:132          "$FIX/tqbf.txt"
roundtrip "N=9"  "$FIX/n9.ciphers"  inline:132312       "$FIX/tqbf.txt"
roundtrip "N=10 (separated indices)" "$FIX/n10.ciphers" "inline:1 5 10 3" "$FIX/tqbf.txt"
roundtrip "N=50 (separated indices)" "$FIX/n50.ciphers" "inline:50 1 25 7" "$FIX/tqbf.txt"

# digit-string boundary (SPEC §3.1): N<=9 reads each digit as an index;
# N>9 rejects bare (unseparated) multi-digit strings even when in range.
roundtrip "N=9 accepts bare digit string 132312" "$FIX/n9.ciphers" inline:132312 "$FIX/tqbf.txt"
expect_exit "N=10 rejects bare digit string 132312 (out of range run)" 2 \
    "$RCODE" encrypt --ciphers "$FIX/n10.ciphers" --pattern inline:132312 --in "$FIX/tqbf.txt"
expect_exit "N=10 rejects bare digit string 11 (in range)" 2 \
    "$RCODE" encrypt --ciphers "$FIX/n10.ciphers" --pattern inline:11 --in "$FIX/tqbf.txt"
expect_stderr "  ^ rejected as bare digit string" "bare digit string"
expect_exit "N=50 rejects bare digit string 25 (in range)" 2 \
    "$RCODE" encrypt --ciphers "$FIX/n50.ciphers" --pattern inline:25 --in "$FIX/tqbf.txt"
roundtrip "N=10 accepts separated multi-digit (1 10)" "$FIX/n10.ciphers" "inline:1 10" "$FIX/tqbf.txt"
roundtrip "N=10 accepts lone single-digit index (5)" "$FIX/n10.ciphers" inline:5 "$FIX/tqbf.txt"

# duplicate index values are legal
roundtrip "duplicate index pattern (111)" "$FIX/n3.ciphers" inline:111 "$FIX/tqbf.txt"

# ---- whitespace passthrough / CRLF / trailing newline / empty --------
roundtrip "whitespace + CRLF passthrough"  "$FIX/rc123.ciphers" inline:132312 "$FIX/ws.txt"
roundtrip "empty input"                    "$FIX/rc1.ciphers"   inline:1      "$FIX/empty.txt"

# ---- rejection cases (SPEC §7) ---------------------------------------
# Each cipher rejection also asserts the stderr names the intended validation
# path, so a future check-reorder that still exits 2 cannot pass silently.
expect_exit "reject non-bijection cipher"  2 \
    "$RCODE" encrypt --ciphers "$FIX/bad_nonbijection.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt"
expect_stderr "  ^ bijection path" "not a bijection"
expect_exit "reject wrong token count"     2 \
    "$RCODE" encrypt --ciphers "$FIX/bad_tokencount.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt"
expect_stderr "  ^ token-count path" "expected 94 tokens"
expect_exit "reject two-byte token"        2 \
    "$RCODE" encrypt --ciphers "$FIX/bad_twobyte_token.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt"
expect_stderr "  ^ token-length path" "is not a single byte"
expect_exit "reject non-ASCII cipher byte" 2 \
    "$RCODE" encrypt --ciphers "$FIX/bad_nonascii.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt"
expect_stderr "  ^ byte-range path" "outside printable range"
expect_exit "reject too-many tokens (95)"  2 \
    "$RCODE" encrypt --ciphers "$FIX/bad_toomany.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt"
expect_stderr "  ^ token-count path (95)" "got 95"
# invalid SECOND cipher line: exit 2 and the 1-based index must be reported
expect_exit "reject invalid 2nd cipher line" 2 \
    "$RCODE" encrypt --ciphers "$FIX/bad_second_line.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt"
expect_stderr "  ^ reports cipher index 2" "cipher 2"
expect_exit "reject out-of-range pattern index" 2 \
    "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:2 --in "$FIX/tqbf.txt"
expect_exit "reject empty pattern"         2 \
    "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline: --in "$FIX/tqbf.txt"

expect_exit "reject out-of-alphabet input 0x80" 3 \
    "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$FIX/in_0x80.bin"
expect_exit "reject NUL input 0x00"        3 \
    "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$FIX/in_0x00.bin"
expect_exit "reject control input 0x07"    3 \
    "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$FIX/in_0x07.bin"
expect_exit "reject unwritable --out"      3 \
    "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt" --out "$TMP/nodir/out"
expect_exit "reject missing input file"    3 \
    "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$TMP/does_not_exist"

# ---- decrypt-side rejections (isolate the inverse-table/decrypt branch) --
expect_exit "decrypt: reject out-of-alphabet input 0x80" 3 \
    "$RCODE" decrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$FIX/in_0x80.bin"
expect_exit "decrypt: reject control input 0x07" 3 \
    "$RCODE" decrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --in "$FIX/in_0x07.bin"
expect_exit "decrypt: reject non-bijection cipher" 2 \
    "$RCODE" decrypt --ciphers "$FIX/bad_nonbijection.ciphers" --pattern inline:1 --in "$FIX/tqbf.txt"
expect_exit "decrypt: reject out-of-range pattern index" 2 \
    "$RCODE" decrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:2 --in "$FIX/tqbf.txt"

# ---- default stdin/stdout paths (no --in/--out) ----------------------
"$RCODE" encrypt --ciphers "$FIX/rc123.ciphers" --pattern inline:132312 <"$FIX/tqbf.txt" >"$TMP/ct" 2>"$TMP/e"
"$RCODE" decrypt --ciphers "$FIX/rc123.ciphers" --pattern inline:132312 <"$TMP/ct" >"$TMP/pt" 2>"$TMP/e"
if cmp -s "$FIX/tqbf.txt" "$TMP/pt"; then ok "stdin/stdout defaults round-trip"
else bad "stdin/stdout defaults (got: $(cat "$TMP/pt"))"; fi

# ---- usage errors (exit 1) -------------------------------------------
expect_exit "usage: no subcommand"      1 "$RCODE"
expect_exit "usage: unknown subcommand" 1 "$RCODE" frobnicate --ciphers "$FIX/rc1.ciphers" --pattern inline:1
expect_exit "usage: missing --ciphers"  1 "$RCODE" encrypt --pattern inline:1
expect_exit "usage: missing --pattern"  1 "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers"
expect_exit "usage: unknown flag"       1 "$RCODE" encrypt --ciphers "$FIX/rc1.ciphers" --pattern inline:1 --bogus
expect_exit "usage: --ciphers without value" 1 "$RCODE" encrypt --ciphers

# ---- --help / --version (exit 0) -------------------------------------
expect_exit "--help exits 0"    0 "$RCODE" --help
expect_exit "--version exits 0" 0 "$RCODE" --version

# ---- summary ----------------------------------------------------------
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
