#!/bin/sh
# Tests for cps-gen and ptn-gen.
# Usage: sh tests/gen_tests.sh [cps-gen] [ptn-gen] [rcode]
set -u

CPS="${1:-./cps-gen}"
PTN="${2:-./ptn-gen}"
RCODE="${3:-./rcode}"
DIR=$(dirname "$0")
FIX="$DIR/fixtures"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT INT TERM

pass=0
fail=0
ok()  { pass=$((pass + 1)); printf 'PASS  %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf 'FAIL  %s\n' "$1"; }

# expect_exit <name> <expected-code> <cmd...>
expect_exit() {
    name=$1; exp=$2; shift 2
    "$@" >/dev/null 2>"$W/e"
    got=$?
    if [ "$got" -eq "$exp" ]; then ok "$name (exit $got)"
    else bad "$name (expected $exp, got $got: $(cat "$W/e"))"; fi
}
# expect_stderr <name> <substring>  (stderr of the previous expect_exit)
expect_stderr() {
    if grep -q -- "$2" "$W/e"; then ok "$1 (stderr ok)"
    else bad "$1 (stderr missing '$2': $(cat "$W/e"))"; fi
}

printf 'the quick brown fox 123 ABC xyz {|}~\n' >"$W/in.txt"

# roundtrip via a generated cipher + generated pattern (drift detector)
gen_roundtrip() {
    name=$1; perfile=$2; lenflag=$3   # lenflag e.g. "" or "--length 30"
    "$CPS" gen --per-file "$perfile" --seed 7 --out "$W/rt.cps" --force >/dev/null 2>"$W/e" \
        || { bad "$name (cps-gen: $(cat "$W/e"))"; return; }
    # shellcheck disable=SC2086
    "$PTN" "$W/rt.cps" --seed 8 $lenflag --out "$W/rt.ptn" --force >/dev/null 2>"$W/e" \
        || { bad "$name (ptn-gen: $(cat "$W/e"))"; return; }
    "$RCODE" encrypt --ciphers "$W/rt.cps" --pattern "$W/rt.ptn" --in "$W/in.txt" --out "$W/rt.ct" 2>"$W/e" \
        || { bad "$name (encrypt: $(cat "$W/e"))"; return; }
    "$RCODE" decrypt --ciphers "$W/rt.cps" --pattern "$W/rt.ptn" --in "$W/rt.ct" --out "$W/rt.pt" 2>"$W/e" \
        || { bad "$name (decrypt: $(cat "$W/e"))"; return; }
    if cmp -s "$W/in.txt" "$W/rt.pt"; then ok "$name"; else bad "$name (round-trip mismatch)"; fi
}

# ---- end-to-end round-trips across N boundaries ----------------------
gen_roundtrip "round-trip N=1"  1  ""
gen_roundtrip "round-trip N=3"  3  ""
gen_roundtrip "round-trip N=9"  9  ""
gen_roundtrip "round-trip N=10 (default 3N)" 10 ""
gen_roundtrip "round-trip N=10 explicit --length 50" 10 "--length 50"
gen_roundtrip "round-trip N=50" 50 ""

# N>9 patterns must be space-separated (not a bare digit string), and rcode
# must accept the result (self-contained: explicit N=11 cipher file).
"$CPS" gen --per-file 11 --seed 9 --out "$W/n11.cps" --force >/dev/null 2>&1
"$PTN" "$W/n11.cps" --seed 9 --out "$W/sp.ptn" --force >/dev/null 2>"$W/e" \
    || bad "N>9 ptn-gen failed: $(cat "$W/e")"
if grep -q ' ' "$W/sp.ptn"; then ok "N>9 pattern is space-separated"
else bad "N>9 pattern not space-separated: $(head -c 80 "$W/sp.ptn")"; fi
if "$RCODE" encrypt --ciphers "$W/n11.cps" --pattern "$W/sp.ptn" --in "$W/in.txt" --out /dev/null 2>"$W/e"
then ok "N>9 pattern accepted by rcode"; else bad "N>9 pattern rejected: $(cat "$W/e")"; fi

# default length is 3*N
"$CPS" gen --per-file 4 --seed 1 --out "$W/n4.cps" --force >/dev/null 2>&1
"$PTN" "$W/n4.cps" --seed 1 --out "$W/n4.ptn" --force >/dev/null 2>&1
cnt=$(tr ' ' '\n' < "$W/n4.ptn" | grep -c .)
if [ "$cnt" -eq 12 ]; then ok "default length == 3*N (12 for N=4)"
else bad "default length: expected 12, got $cnt"; fi

# ---- split then combine reconstructs the original --------------------
"$CPS" gen --per-file 4 --seed 3 --out "$W/orig.cps" --force >/dev/null 2>&1
mkdir "$W/split"
"$CPS" split "$W/orig.cps" --per-file 1 --out-dir "$W/split" --force >/dev/null 2>"$W/e"
nparts=$(ls "$W/split"/*.cps 2>/dev/null | wc -l)
if [ "$nparts" -eq 4 ]; then ok "split N=4 per-file 1 -> 4 parts"
else bad "split parts: expected 4, got $nparts"; fi
# shellcheck disable=SC2046
"$CPS" combine $(ls "$W/split"/*.cps | sort -V) -o "$W/recombined.cps" --force >/dev/null 2>"$W/e"
if cmp -s "$W/orig.cps" "$W/recombined.cps"; then ok "split then combine == original"
else bad "split/combine mismatch"; fi

# combine cipher count == sum of inputs
"$CPS" gen --per-file 1 --seed 4 --out "$W/c1.cps" --force >/dev/null 2>&1
"$CPS" gen --per-file 3 --seed 5 --out "$W/c3.cps" --force >/dev/null 2>&1
"$CPS" combine "$W/c1.cps" "$W/c3.cps" -o "$W/c4.cps" --force >/dev/null 2>"$W/e"
lines=$(grep -c . "$W/c4.cps")
if [ "$lines" -eq 4 ]; then ok "combine count == 1+3"
else bad "combine count: expected 4, got $lines"; fi

# ---- determinism (seed reproducibility) ------------------------------
"$CPS" gen --per-file 2 --seed 42 --out "$W/d1.cps" --force >/dev/null 2>&1
"$CPS" gen --per-file 2 --seed 42 --out "$W/d2.cps" --force >/dev/null 2>&1
if cmp -s "$W/d1.cps" "$W/d2.cps"; then ok "cps-gen --seed reproducible"
else bad "cps-gen --seed not reproducible"; fi
"$CPS" gen --per-file 2 --seed 43 --out "$W/d3.cps" --force >/dev/null 2>&1
if cmp -s "$W/d1.cps" "$W/d3.cps"; then bad "cps-gen different seeds gave identical output"
else ok "cps-gen different seeds differ"; fi
"$PTN" "$W/d1.cps" --seed 99 --out "$W/p1.ptn" --force >/dev/null 2>&1
"$PTN" "$W/d1.cps" --seed 99 --out "$W/p2.ptn" --force >/dev/null 2>&1
if cmp -s "$W/p1.ptn" "$W/p2.ptn"; then ok "ptn-gen --seed reproducible"
else bad "ptn-gen --seed not reproducible"; fi

# ---- default naming convention ---------------------------------------
mkdir "$W/single"
"$CPS" gen --seed 1 --out-dir "$W/single" >/dev/null 2>&1
nm=$(ls "$W/single")
case "$nm" in
    [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].cps)
        ok "single-file name is <date>-<time>.cps" ;;
    *) bad "single-file name unexpected: $nm" ;;
esac
mkdir "$W/multi"
"$CPS" gen --files 3 --seed 1 --out-dir "$W/multi" >/dev/null 2>&1
nmulti=$(ls "$W/multi"/*-1.cps "$W/multi"/*-2.cps "$W/multi"/*-3.cps 2>/dev/null | wc -l)
if [ "$nmulti" -eq 3 ]; then ok "multi-file names use -<i> suffix (1..3)"
else bad "multi-file naming: expected 3 indexed files, got $nmulti"; fi

# ---- exit codes ------------------------------------------------------
expect_exit "ptn-gen --length < N rejected" 2 \
    "$PTN" "$W/n4.cps" --length 3 --out "$W/x.ptn" --force
expect_exit "cps-gen --per-file 0 rejected" 1 "$CPS" gen --per-file 0
expect_exit "cps-gen --files 0 rejected"    1 "$CPS" gen --files 0
expect_exit "ptn-gen --files 0 rejected"    1 "$PTN" "$W/n4.cps" --files 0
expect_exit "cps-gen -o with --files 2"     1 "$CPS" gen --files 2 -o "$W/x.cps"
expect_exit "cps-gen -o with --out-dir"     1 "$CPS" gen -o "$W/x.cps" --out-dir "$W"
expect_exit "combine with no inputs"        1 "$CPS" combine -o "$W/x.cps"
expect_exit "ptn-gen with no inputs"        1 "$PTN" --out "$W/x.ptn"
expect_exit "unknown subcommand"            1 "$CPS" frobnicate

expect_exit "combine non-bijection -> validation" 2 \
    "$CPS" combine "$FIX/bad_nonbijection.cps" -o "$W/x.cps" --force
expect_stderr "  ^ names bijection fault" "not a bijection"
expect_exit "split non-bijection -> validation" 2 \
    "$CPS" split "$FIX/bad_nonbijection.cps" --out-dir "$W" --force
expect_exit "combine empty file -> validation" 2 \
    "$CPS" combine "$FIX/empty.txt" -o "$W/x.cps" --force
expect_stderr "  ^ names empty file" "no cipher alphabets found"
expect_exit "ptn-gen on bad cps -> validation" 2 \
    "$PTN" "$FIX/bad_nonbijection.cps" --out "$W/x.ptn" --force

expect_exit "missing --out-dir -> runtime" 3 \
    "$CPS" gen --out-dir "$W/no_such_dir"

# refuse-overwrite, then --force
"$CPS" gen --seed 1 --out "$W/ow.cps" --force >/dev/null 2>&1
expect_exit "refuse to overwrite without --force" 3 "$CPS" gen --seed 2 --out "$W/ow.cps"
expect_stderr "  ^ says refusing" "refusing to overwrite"
expect_exit "overwrite with --force ok" 0 "$CPS" gen --seed 2 --out "$W/ow.cps" --force

# help / version
expect_exit "cps-gen --help"    0 "$CPS" --help
expect_exit "cps-gen --version" 0 "$CPS" --version
expect_exit "ptn-gen --help"    0 "$PTN" --help
expect_exit "ptn-gen --version" 0 "$PTN" --version

# ---- summary ---------------------------------------------------------
printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
