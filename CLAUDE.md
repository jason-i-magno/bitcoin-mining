# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

An educational Bitcoin miner in pure Python that mines real, consensus-valid blocks on a regtest chain. **Standard library only**: there are no dependencies, no build step, and no linter or formatter config. Keep it that way unless asked.

## Commands

```sh
python3 -m unittest                                   # all tests; no node needed
python3 -m unittest tests.test_mining.MineBlockTest   # one class (or append .test_name for one test)

scripts/regtest.sh start | stop | reset | cli ARGS... # local node; needs bitcoind and bitcoin-cli on PATH
python3 -m miner --blocks 101                         # mine against that node
```

`scripts/regtest.sh` keeps all node state in `./data` (gitignored), and `reset` deletes `data/regtest`. By default the miner authenticates with the cookie at `<datadir>/regtest/.cookie`, so other networks need `--rpc-url` plus `--rpc-user`/`--rpc-password`.

## Verifying changes

The unit tests check encodings against real mainnet vectors (the genesis block, the genesis coinbase, block 100000's merkle root), but only `bitcoind` can judge consensus validity. After touching anything that affects block contents (the coinbase, merkle roots, the witness commitment, header fields, serialization), run an end-to-end check against a real node:

```sh
scripts/regtest.sh start
python3 -m miner --blocks 101   # matures one coinbase so the wallet can spend
scripts/regtest.sh cli sendtoaddress "$(scripts/regtest.sh cli getnewaddress)" 1.5
python3 -m miner                # block must include the tx; any rejection raises RuntimeError with bitcoind's reason
```

## Architecture

The modules form a strict layering: `encoding` ← `tx` ← `block` ← `mining` ← `__main__`. `rpc` stands apart.

- **Byte order convention:** every hash is held as `bytes` in internal byte order. Conversion to and from the byte-reversed hex used by RPC and explorers happens only at the boundary (`from_display_hex` / `to_display_hex`, used in `mining.py` and `__main__.py`). Proof of work compares the digest as a little-endian integer.
- **The RPC object is duck-typed:** `mining.py` only needs something with `.call(method, *params)`. Tests pass a `FakeRPC` to drive `mine_block` without a node, so keep it that way rather than importing `BitcoinRPC` there.
- **`build_candidate` cross-checks the node:** it recomputes the witness commitment and decodes `nBits`, then raises `ValueError` if either disagrees with `getblocktemplate`'s `default_witness_commitment` / `target`. Keep these checks; they catch mistakes before a block is submitted.
- **Search loop (`mine_block`):** it searches nonces in chunks of `CHUNK_SIZE`, rebuilding the candidate each chunk (cheap next to the hashing). It refetches the template after `TEMPLATE_MAX_AGE` seconds, and after 2³² failed nonces it increments the extranonce in the coinbase scriptSig to get a new merkle root. `search` hashes the first 64 header bytes once (the midstate) and only re-hashes the nonce-bearing tail.

## Consensus details that are easy to break

- The coinbase scriptSig must start with `push_int(height)`, which must match Bitcoin Core's `CScript() << height` byte for byte (BIP34). Heights 1–16 are `OP_1`–`OP_16`, not data pushes. The whole scriptSig must be 2–100 bytes.
- `Transaction.txid()` hashes the non-witness serialization; that is what the merkle root uses. When a witness commitment output exists, the coinbase input must carry exactly one 32-byte witness item (`WITNESS_RESERVED_VALUE`). In the witness merkle tree, the coinbase's wtxid is defined as 32 zero bytes.
