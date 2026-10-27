# C port of the regtest miner. No dependencies beyond libc and pthreads.
#
#   make          build ./miner (tuned for this CPU with -march=native)
#   make GPU=1    add OpenCL GPU mining (miner --gpu); needs an OpenCL driver and headers
#   make test     build and run the unit tests with UBSan (GPU=1 tests the GPU too)
#   make clean

CFLAGS ?= -O3 -march=native
CFLAGS += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -MMD -MP
LDLIBS += -pthread

ifeq ($(GPU),1)
CPPFLAGS += -DHAVE_OPENCL -Ibuild
LDLIBS += -lOpenCL
endif

# UBSan in trap mode needs no runtime library; FORTIFY adds buffer-overflow checks.
TEST_CFLAGS := -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -g -O2 -D_FORTIFY_SOURCE=3 \
               -fsanitize=undefined -fsanitize-trap=all -Isrc

LIB_SRC := src/sha256.c src/sha256_shani.c src/encoding.c src/json.c src/rpc.c src/tx.c src/block.c \
           src/mining.c src/gpu.c
LIB_OBJ := $(LIB_SRC:src/%.c=build/%.o)

miner: build/main.o $(LIB_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c build/gpu-setting | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

# The kernel's source as an array of lines, which gpu.c hands to the OpenCL compiler at
# run time. (One string would exceed the 4095 characters C promises to support.)
build/search_cl.h: src/search.cl Makefile | build
	{ echo 'static const char *const search_cl[] = {'; \
	  sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/    "/' -e 's/$$/\\n",/' $<; \
	  echo '};'; } > $@

build/gpu.o: build/search_cl.h

build/test: tests/test.c $(LIB_SRC) $(wildcard src/*.h) build/search_cl.h build/gpu-setting | build
	$(CC) $(TEST_CFLAGS) $(CPPFLAGS) -o $@ tests/test.c $(LIB_SRC) $(LDLIBS)

# Holds the last GPU setting and changes only when it does, so switching GPU on or
# off rebuilds everything compiled with the old flags.
build/gpu-setting: FORCE | build
	@echo '$(GPU)' | cmp -s - $@ || echo '$(GPU)' > $@

build:
	mkdir -p build

test: build/test
	./build/test

clean:
	rm -rf build miner

.PHONY: test clean FORCE

-include $(LIB_OBJ:.o=.d) build/main.d
