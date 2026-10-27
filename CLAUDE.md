# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

An educational Bitcoin miner that mines real, consensus-valid blocks on a regtest chain, implemented twice: in Python (`miner/`, **standard library only**) and in C11 (`c/`, **libc and pthreads only**, so it has its own SHA-256, JSON parser and HTTP client). The one exception is the C miner's optional OpenCL GPU search, which is compiled in only with `make -C c GPU=1`. Neither implementation has a linter or formatter config. Keep both dependency-free unless asked.

## Commands

```sh
python3 -m unittest                                   # all Python tests; no node needed
python3 -m unittest tests.test_mining.MineBlockTest   # one class (or append .test_name for one test)

make -C c                                             # builds c/miner (-O3 -march=native)
make -C c test                                        # C tests: one binary, build/test, runs every check (UBSan in trap mode)
c/miner --benchmark 5                                 # C hashrate and SHA-256 implementation; needs no node
make -C c GPU=1                                       # adds c/miner --gpu; needs OpenCL headers and a driver
RUSTICL_ENABLE=radeonsi make -C c test GPU=1          # also tests the GPU (Mesa's rusticl hides AMD GPUs without the variable)
RUSTICL_ENABLE=radeonsi c/miner --gpu --benchmark 5   # GPU hashrate

scripts/regtest.sh start | stop | reset | cli ARGS... # local node; needs bitcoind and bitcoin-cli on PATH
python3 -m miner --blocks 101                         # mine against that node (c/miner takes the same flags, plus --threads)
```

`scripts/regtest.sh` keeps all node state in `./data` (gitignored), and `reset` deletes `data/regtest`. Both miners authenticate with the cookie at `<datadir>/regtest/.cookie` by default. Other networks need `--rpc-url` plus `--rpc-user`/`--rpc-password`. `c/miner`'s default `--datadir data` is relative to the current directory, so run it from the repo root.

## Verifying changes

The unit tests check encodings against real mainnet vectors (the genesis block, the genesis coinbase, block 100000's merkle root), but only `bitcoind` can judge consensus validity. After touching anything that affects block contents (the coinbase, merkle roots, the witness commitment, header fields, serialization), run an end-to-end check against a real node with whichever miner changed:

```sh
scripts/regtest.sh start
python3 -m miner --blocks 101   # matures one coinbase so the wallet can spend
scripts/regtest.sh cli sendtoaddress "$(scripts/regtest.sh cli getnewaddress)" 1.5
python3 -m miner                # block must include the tx; any rejection reports bitcoind's reason
```

The user may have their own node from `scripts/regtest.sh` running on the default regtest ports (18443/18444) with a chain in `./data`. Don't mine on it or spend from its wallet. Test against a separate node instead: `bitcoind -regtest -datadir=<tmpdir> -rpcport=28443 -listen=0 -daemonwait -fallbackfee=0.0001`, then `createwallet miner`, then pass `--rpc-url http://127.0.0.1:28443 --datadir <tmpdir>` to either miner.

## Architecture

The modules form a strict layering: `encoding` ← `tx` ← `block` ← `mining` ← `__main__`/`main.c`. `rpc` stands apart. The C files mirror the Python modules one for one (`c/src/sha256.c`, `sha256_shani.c` and `json.c` stand in for `hashlib` and `json`). When changing consensus logic in one implementation, make the same change in the other.

- **Byte order convention:** every hash is held in internal byte order. Conversion to and from the byte-reversed hex used by RPC and explorers happens only at the boundary (`from_display_hex` / `to_display_hex`). Proof of work compares the digest as a little-endian integer; in C, targets are 32-byte little-endian arrays compared by `hash_meets_target`.
- **The Python RPC object is duck-typed:** `mining.py` only needs something with `.call(method, *params)`. Tests pass a `FakeRPC` to drive `mine_block` without a node, so keep it that way rather than importing `BitcoinRPC` there. C's `mine_block` takes a concrete `rpc_client`, so it is covered only end to end; the C tests cover `build_candidate`, `search` and serialization directly.
- **`build_candidate` cross-checks the node:** it recomputes the witness commitment and decodes `nBits`, then fails (a `ValueError` in Python, `false` plus a message in C) if either disagrees with `getblocktemplate`'s `default_witness_commitment` / `target`. Keep these checks; they catch mistakes before a block is submitted.
- **Search loop (`mine_block`):** it searches nonces in chunks of `CHUNK_SIZE` (2^20 in Python, 2^26 in C), rebuilding the candidate each chunk (cheap next to the hashing). It refetches the template after `TEMPLATE_MAX_AGE` seconds, and after 2³² failed nonces it increments the extranonce in the coinbase scriptSig to get a new merkle root. Every search hashes the first 64 header bytes once (the midstate; `header_midstate` in C).
- **C SHA-256 dispatch:** `sha256_compress` forwards to `sha256_compress_shani` when CPUID reports SHA-NI, otherwise to `sha256_compress_generic`. The SHA-NI functions get the instructions from `__attribute__((target("sha,sse4.1")))`, not from `-msha`, so the binary still runs on CPUs without them; keep such instructions out of every other function. `sha256_use` forces an implementation. The tests run everything on the fastest one, then rerun the hashing tests on the generic one and compare both on random input. On a CPU without SHA-NI, its tests are skipped with a note.
- **C hashing fast path (`search_worker`):** it pre-fills the SHA-256 padding words so each attempt is two `sha256_compress` calls, the first writing its digest straight into the second's block (copying it instead cost 14% with `-march=native`, through a store-forwarding stall). It rejects most hashes on the top 32 bits alone (`state[7]` byte-swapped). `test_search_matches_reference` checks it against plain `sha256d`, including the equal-top-bits case, so run it after any optimization. Measure speed with `c/miner --benchmark` in both the default build and `make -C c CFLAGS=-O3`, since their code generation differs. Slices are split evenly across threads; slice 0 runs on the calling thread, and a shared stop flag is checked every 65,536 nonces. With more than one thread, the returned nonce is valid but not necessarily the lowest in the range.

- **C GPU search (`gpu.c`, `search.cl`):** with `--gpu`, `mine_block` calls `gpu_search` instead of `search`. The CPU still builds the candidate; the kernel gets the midstate, the header's 3 words before the nonce and the target limbs, and one work item tries one nonce, in launches of `GPU_BATCH` (2^24). `atomic_min` makes each launch report its lowest valid nonce, so like a one-thread CPU search the result is the first valid nonce in the range, and `gpu_search` rechecks it with `header_hash` before returning it. Without `GPU=1`, `HAVE_OPENCL` is undefined and `gpu.c` compiles to stubs whose `gpu_open` explains how to rebuild. The Makefile records the setting in `build/gpu-setting` so switching it rebuilds everything, and turns `search.cl` into `build/search_cl.h`, an array of lines, since one string literal would exceed C's 4095-character limit. `test_gpu_search` compares the GPU with the CPU, including in later launches and near nonce 2^32, and skips with a note when no GPU is available.
- **Keep the GPU kernel free of loops and arrays:** Mesa's rusticl ignored `#pragma unroll`, and arrays inside the loop went to scratch memory, a 5x slowdown. Rounds are written out with macros, and blocks are passed as `uint8`/`uint16` values. After changing the kernel, check `MESA_SHADER_CACHE_DISABLE=true AMD_DEBUG=cs,asm,stats c/miner --gpu --benchmark 1`: the search kernel (the one with a code size of about 26 KB) should show `Scratch: 0`. On this driver `rotate()` costs two instructions, and writing it as a 64-bit shift was slower.

## Consensus details that are easy to break

- The coinbase scriptSig must start with the height encoded exactly like Bitcoin Core's `CScript() << height` (BIP34): `push_int` in Python, `buf_push_int` in C. Heights 1–16 are `OP_1`–`OP_16`, not data pushes. The whole scriptSig must be 2–100 bytes.
- The txid (`Transaction.txid()` / `coinbase_txid`) hashes the non-witness serialization; that is what the merkle root uses. When a witness commitment output exists, the coinbase input must carry exactly one 32-byte witness item (`WITNESS_RESERVED_VALUE`). In the witness merkle tree, the coinbase's wtxid is defined as 32 zero bytes.
