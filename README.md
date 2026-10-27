# bitcoin-mining

A minimal Bitcoin miner in pure Python (standard library only). It mines real blocks on a private
**regtest** chain, which Bitcoin Core validates and accepts exactly as it would on mainnet. The only
difference is the difficulty: regtest's target is met by about half of all hashes, so a CPU finds a
block in one or two attempts. A multithreaded [C version](#c-version) lives in `c/`, with optional
[GPU mining](#gpu-version) through OpenCL.

## Setup

- Python 3.10+
- Bitcoin Core (`bitcoind` and `bitcoin-cli` on your `PATH`). Download a release from
  <https://bitcoincore.org/en/download/>, check it against `SHA256SUMS`, extract it, and add its
  `bin/` directory to `PATH`.

## Run

```sh
scripts/regtest.sh start               # node + "miner" wallet, data in ./data
python3 -m miner --blocks 101          # coinbase rewards need 100 confirmations to be spendable
scripts/regtest.sh cli getbalance      # 50.00000000: block 1's reward has matured
scripts/regtest.sh cli sendtoaddress "$(scripts/regtest.sh cli getnewaddress)" 1.5
python3 -m miner                       # mines a block that includes that transaction
scripts/regtest.sh stop                # or `reset` to wipe the chain and start over
```

Run the tests with `python3 -m unittest`. They check the code against real mainnet data (the
genesis block, block 100000's merkle root) and don't need a node.

## How it works

| File | Role |
|---|---|
| `miner/mining.py` | The loop: fetch a template, build a candidate block, search nonces, submit |
| `miner/tx.py` | Transaction serialization and the coinbase that pays the reward |
| `miner/block.py` | 80-byte header, merkle root, segwit witness commitment |
| `miner/encoding.py` | `sha256d`, varints, Script pushes, decoding `nBits` into a target |
| `miner/rpc.py` | JSON-RPC client for `bitcoind` |
| `scripts/regtest.sh` | Start, stop, or reset the local node |

1. **`getblocktemplate`**: the node returns the previous block hash, the mempool transactions to
   include, the reward (`coinbasevalue` = subsidy + fees), the time, and the target.
2. **Coinbase**: a transaction with no inputs that pays `coinbasevalue` to your address. Its
   scriptSig holds the block height and an 8-byte extranonce.
3. **Merkle root**: computed from the coinbase txid plus every template transaction's txid.
4. **Header**: version, previous hash, merkle root, time, bits, nonce.
5. **Search**: try nonces until `sha256d(header) <= target`. If all 2³² nonces fail, increment
   the extranonce. That changes the coinbase txid and the merkle root, giving a fresh nonce space.
6. **`submitblock`**: send the serialized block. `null` means the node accepted it.

## Details that trip people up

- **Byte order.** RPC and block explorers show hashes byte-reversed. Hashing and serialization use
  the internal order (`from_display_hex` / `to_display_hex`). The proof-of-work comparison reads the
  hash as a *little-endian* number, which is why displayed block hashes start with zeros.
- **BIP34.** The coinbase scriptSig must *start with* the height, encoded exactly as Bitcoin Core's
  `CScript() << height`. For heights 1–16 that is `OP_1`–`OP_16`, not a data push.
- **SegWit.** Transaction ids in the merkle root exclude witness data. The witness data is committed
  separately, in an `OP_RETURN` coinbase output (BIP141). The miner computes that commitment itself
  and checks it against the node's `default_witness_commitment`.
- **Midstate.** SHA-256 works in 64-byte chunks, and the nonce lives in the header's second chunk.
  So the first chunk is hashed once per candidate, not once per attempt. Real miners do the same.

## C version

`c/` is a port of the same miner to C11. It needs nothing beyond libc and pthreads, so it includes
its own SHA-256, JSON parser and HTTP client. Its files mirror the Python modules one for one
(`mining.c` and `mining.py`, `tx.c` and `tx.py`, and so on), and it adds multithreaded hashing.

```sh
make -C c                    # builds c/miner, tuned for this CPU (-march=native)
make -C c test               # unit tests, using the same mainnet vectors as the Python suite
c/miner --blocks 101         # same flags as python3 -m miner, plus --threads
c/miner --benchmark 5        # measure hashrate on every core; needs no node
```

Run it from the repo root so that the default `--datadir data` finds the node's cookie.

Its hashing loop goes further than the Python one. Besides the midstate, it fills in the SHA-256
padding for both hashes ahead of time, so each attempt is exactly two calls to the compression
function. It also rejects most hashes by comparing only their top 32 bits with the target.

That compression function uses the CPU's SHA extensions (SHA-NI) on x86 processors that have them:
Intel since Ice Lake (2019) and Atom since Goldmont, AMD since Zen. Other CPUs get portable C. The
choice is made at run time, so a build without the default `-march=native` (`make -C c CFLAGS=-O3`)
runs on any x86-64 CPU, uses SHA-NI where it can, and is just as fast. `c/miner --benchmark` reports
which one it used. On a 6-core, 12-thread AMD Ryzen 5 3600X:

| Miner | Hashrate |
|---|---|
| Python, 1 thread | 0.86 MH/s |
| C, portable SHA-256, 1 thread | 2.5 MH/s |
| C, portable SHA-256, 12 threads | 16.9 MH/s |
| C, SHA-NI, 1 thread | 14.4 MH/s |
| C, SHA-NI, 12 threads | 137 MH/s |
| C, OpenCL on an AMD Radeon RX 5600 XT GPU | 1,050 MH/s |
| Industrial ASIC | ~200,000,000 MH/s |

Python's `hashlib` calls OpenSSL, which also uses SHA-NI, so most of Python's time per attempt goes
to the interpreter rather than to hashing.

## GPU version

`make -C c GPU=1` adds an OpenCL nonce search, used with `c/miner --gpu`. The CPU still builds every
candidate block. The GPU only searches nonces, 16.7 million (2^24) per launch, with one work item per
nonce (`c/src/search.cl`). Each launch reports the lowest nonce that meets the target, and the CPU
rechecks it before submitting. This is the project's one dependency: you need an OpenCL driver for
your GPU and the headers to build against. On Fedora, Mesa's rusticl driver covers AMD and Intel
GPUs:

```sh
sudo dnf install mesa-libOpenCL clinfo opencl-headers OpenCL-ICD-Loader-devel
export RUSTICL_ENABLE=radeonsi    # rusticl hides AMD GPUs without this (use iris for Intel)
clinfo -l                         # should list your GPU
make -C c GPU=1
make -C c test GPU=1              # checks that the GPU finds the same nonces as the CPU
c/miner --gpu --benchmark 5
c/miner --gpu --blocks 101
```

Mesa may print a warning about libclc on every run. That is one reason the CPU rechecks the GPU's
answers.

On regtest the GPU gains nothing. A launch hashes all 16.7 million nonces even though one or two would
do, so `attempts` reads 16777216 for each block. On mainnet, at a difficulty of 140 trillion, a solo
GPU at 1 GH/s would take around 18 million years per block on average.

## Ideas for next steps

- Write a Stratum v1 client (`mining.subscribe` / `mining.notify` / `mining.submit`) and mine a
  pool's work instead of your node's. The pool sends coinbase halves and a merkle branch instead of
  full transactions.
- Give the C miner an ARMv8 `sha256_compress` that uses the SHA-256 crypto extensions (`sha256h`,
  `sha256h2`, `sha256su0`, `sha256su1`), next to the x86 SHA-NI one in `c/src/sha256_shani.c`.
- Add BIP320 version rolling as a second source of search space alongside the extranonce.
- Speed up the GPU kernel: compute the nonce-independent first rounds once per launch, and skip the
  second hash's last rounds when its top word already fails the target.

## License

MIT. See [LICENSE](LICENSE).
