# bitcoin-mining

A minimal Bitcoin miner in pure Python (standard library only). It mines real blocks on a private
**regtest** chain, which Bitcoin Core validates and accepts exactly as it would on mainnet. The only
difference is the difficulty: regtest's target is met by about half of all hashes, so a CPU finds a
block in one or two attempts.

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

## Ideas for next steps

- Write a Stratum v1 client (`mining.subscribe` / `mining.notify` / `mining.submit`) and mine a
  pool's work instead of your node's. The pool sends coinbase halves and a merkle branch instead of
  full transactions.
- Measure hashrate on a harder target, then move `search` to C or Rust and use every core.
  Compare the result with an ASIC's hundreds of TH/s.
- Add BIP320 version rolling as a second source of search space alongside the extranonce.

## License

MIT. See [LICENSE](LICENSE).
