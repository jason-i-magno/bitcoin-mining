# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

An educational Bitcoin miner that mines real, consensus-valid blocks on a regtest chain, implemented twice: in Python (`miner/`, **standard library only**) and in C11 (`c/`, **libc and pthreads only**, so it has its own SHA-256, JSON parser and HTTP client). Neither has a linter or formatter config. Keep both dependency-free unless asked.

## Commands

```sh
python3 -m unittest                                   # all Python tests; no node needed
python3 -m unittest tests.test_mining.MineBlockTest   # one class (or append .test_name for one test)

make -C c                                             # builds c/miner (-O3 -march=native)
make -C c test                                        # C tests: one binary, build/test, runs every check (UBSan in trap mode)
c/miner --benchmark 5                                 # C hashrate; needs no node

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

The modules form a strict layering: `encoding` ← `tx` ← `block` ← `mining` ← `__main__`/`main.c`. `rpc` stands apart. The C files mirror the Python modules one for one (`c/src/sha256.c` and `json.c` stand in for `hashlib` and `json`). When changing consensus logic in one implementation, make the same change in the other.

- **Byte order convention:** every hash is held in internal byte order. Conversion to and from the byte-reversed hex used by RPC and explorers happens only at the boundary (`from_display_hex` / `to_display_hex`). Proof of work compares the digest as a little-endian integer; in C, targets are 32-byte little-endian arrays compared by `hash_meets_target`.
- **The Python RPC object is duck-typed:** `mining.py` only needs something with `.call(method, *params)`. Tests pass a `FakeRPC` to drive `mine_block` without a node, so keep it that way rather than importing `BitcoinRPC` there. C's `mine_block` takes a concrete `rpc_client`, so it is covered only end to end; the C tests cover `build_candidate`, `search` and serialization directly.
- **`build_candidate` cross-checks the node:** it recomputes the witness commitment and decodes `nBits`, then fails (a `ValueError` in Python, `false` plus a message in C) if either disagrees with `getblocktemplate`'s `default_witness_commitment` / `target`. Keep these checks; they catch mistakes before a block is submitted.
- **Search loop (`mine_block`):** it searches nonces in chunks of `CHUNK_SIZE` (2^20 in Python, 2^26 in C), rebuilding the candidate each chunk (cheap next to the hashing). It refetches the template after `TEMPLATE_MAX_AGE` seconds, and after 2³² failed nonces it increments the extranonce in the coinbase scriptSig to get a new merkle root. Both `search` functions hash the first 64 header bytes once (the midstate).
- **C hashing fast path (`search_worker`):** it pre-fills the SHA-256 padding words so each attempt is two `sha256_compress` calls, and rejects most hashes on the top 32 bits alone (`state[7]` byte-swapped). `test_search_matches_reference` checks it against plain `sha256d`, including the equal-top-bits case, so run it after any optimization. Slices are split evenly across threads; slice 0 runs on the calling thread, and a shared stop flag is checked every 65,536 nonces. With more than one thread, the returned nonce is valid but not necessarily the lowest in the range.

## Consensus details that are easy to break

- The coinbase scriptSig must start with the height encoded exactly like Bitcoin Core's `CScript() << height` (BIP34): `push_int` in Python, `buf_push_int` in C. Heights 1–16 are `OP_1`–`OP_16`, not data pushes. The whole scriptSig must be 2–100 bytes.
- The txid (`Transaction.txid()` / `coinbase_txid`) hashes the non-witness serialization; that is what the merkle root uses. When a witness commitment output exists, the coinbase input must carry exactly one 32-byte witness item (`WITNESS_RESERVED_VALUE`). In the witness merkle tree, the coinbase's wtxid is defined as 32 zero bytes.
