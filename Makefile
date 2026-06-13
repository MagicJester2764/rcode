CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -O2

.PHONY: all test fixtures clean

all: rcode

rcode: src/rcode.c
	$(CC) $(CFLAGS) -o $@ $<

gen_fixtures: tools/gen_fixtures.c
	$(CC) $(CFLAGS) -o $@ $<

# Regenerate the committed static fixtures from RCode.txt.
fixtures: gen_fixtures
	mkdir -p tests/fixtures
	./gen_fixtures

test: rcode
	sh tests/run_tests.sh ./rcode

clean:
	rm -f rcode gen_fixtures
