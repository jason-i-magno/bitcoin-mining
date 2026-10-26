# C port of the regtest miner. No dependencies beyond libc and pthreads.
#
#   make          build ./miner (tuned for this CPU with -march=native)
#   make test     build and run the unit tests with UBSan
#   make clean

CFLAGS ?= -O3 -march=native
CFLAGS += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -MMD -MP
LDLIBS += -pthread

# UBSan in trap mode needs no runtime library; FORTIFY adds buffer-overflow checks.
TEST_CFLAGS := -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -g -O2 -D_FORTIFY_SOURCE=3 \
               -fsanitize=undefined -fsanitize-trap=all -Isrc

LIB_SRC := src/sha256.c src/encoding.c src/json.c src/rpc.c src/tx.c src/block.c src/mining.c
LIB_OBJ := $(LIB_SRC:src/%.c=build/%.o)

miner: build/main.o $(LIB_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build/test: tests/test.c $(LIB_SRC) $(wildcard src/*.h) | build
	$(CC) $(TEST_CFLAGS) -o $@ tests/test.c $(LIB_SRC) $(LDLIBS)

build:
	mkdir -p build

test: build/test
	./build/test

clean:
	rm -rf build miner

.PHONY: test clean

-include $(LIB_OBJ:.o=.d) build/main.d
