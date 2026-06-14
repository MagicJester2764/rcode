CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2

.PHONY: all test fixtures clean

all: rcode cps-gen ptn-gen

rcode: src/rcode.c
	$(CC) $(CFLAGS) -o $@ $<

gen_fixtures: tools/gen_fixtures.c
	$(CC) $(CFLAGS) -o $@ $<

cps-gen: tools/cps_gen.c tools/cpscommon.h
	$(CC) $(CFLAGS) -o $@ $<

ptn-gen: tools/ptn_gen.c tools/cpscommon.h
	$(CC) $(CFLAGS) -o $@ $<

# Regenerate the committed static fixtures from RCode.txt.
fixtures: gen_fixtures
	mkdir -p tests/fixtures
	./gen_fixtures

test: rcode cps-gen ptn-gen
	sh tests/run_tests.sh ./rcode
	sh tests/gen_tests.sh ./cps-gen ./ptn-gen ./rcode

clean:
	rm -f rcode gen_fixtures cps-gen ptn-gen
