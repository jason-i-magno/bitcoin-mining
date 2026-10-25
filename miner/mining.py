"""Turn a block template into a candidate block, then search for a nonce that solves it."""

import hashlib
import time
from dataclasses import dataclass

from .block import BlockHeader, merkle_root, witness_commitment
from .encoding import bits_to_target, compact_size, from_display_hex, to_display_hex
from .tx import Transaction, build_coinbase, witness_commitment_script

NONCE_SPACE = 1 << 32
EXTRANONCE_SIZE = 8
CHUNK_SIZE = 1 << 20  # nonces to try between checks for a fresher template
TEMPLATE_MAX_AGE = 30  # seconds before asking the node for a new template


@dataclass
class Candidate:
    """A complete block, except that its header nonce may not satisfy the target yet."""

    header: BlockHeader
    coinbase: Transaction
    transactions: list[bytes]  # the template's other transactions, already serialized
    target: int
    height: int

    def serialize(self) -> bytes:
        return b"".join(
            [
                self.header.serialize(),
                compact_size(1 + len(self.transactions)),
                self.coinbase.serialize(),
                *self.transactions,
            ]
        )


@dataclass
class MinedBlock:
    height: int
    hash: str
    nonce: int
    extranonce: int
    tx_count: int
    attempts: int
    seconds: float


def fetch_template(rpc) -> dict:
    return rpc.call("getblocktemplate", {"rules": ["segwit"]})


def build_candidate(template: dict, script_pubkey: bytes, extranonce: int) -> Candidate:
    txs = template["transactions"]

    commitment = None
    if "default_witness_commitment" in template:
        commitment = witness_commitment([from_display_hex(tx["hash"]) for tx in txs])
        # The node computed the same value; a mismatch means our witness merkle tree is wrong.
        if witness_commitment_script(commitment).hex() != template["default_witness_commitment"]:
            raise ValueError("computed witness commitment does not match the node's")

    coinbase = build_coinbase(
        height=template["height"],
        extranonce=extranonce.to_bytes(EXTRANONCE_SIZE, "little"),
        value=template["coinbasevalue"],
        script_pubkey=script_pubkey,
        witness_commitment=commitment,
    )
    txids = [coinbase.txid()] + [from_display_hex(tx["txid"]) for tx in txs]
    header = BlockHeader(
        version=template["version"],
        prev_block=from_display_hex(template["previousblockhash"]),
        merkle_root=merkle_root(txids),
        timestamp=template["curtime"],
        bits=int(template["bits"], 16),
    )

    target = bits_to_target(header.bits)
    if target != int(template["target"], 16):
        raise ValueError("decoded nBits does not match the node's target")

    return Candidate(
        header=header,
        coinbase=coinbase,
        transactions=[bytes.fromhex(tx["data"]) for tx in txs],
        target=target,
        height=template["height"],
    )


def search(header: BlockHeader, target: int, start: int, stop: int) -> int | None:
    """Return the first nonce in [start, stop) whose header hash is <= target, if any."""
    raw = header.serialize()
    # SHA-256 consumes 64-byte blocks, and the first 64 header bytes don't depend on
    # the nonce. Hash them once and resume from that "midstate" for every attempt.
    midstate = hashlib.sha256(raw[:64])
    tail = raw[64:76]  # end of merkle root, timestamp, bits
    for nonce in range(start, stop):
        h = midstate.copy()
        h.update(tail + nonce.to_bytes(4, "little"))
        digest = hashlib.sha256(h.digest()).digest()
        # The hash is compared as a little-endian number, which is why
        # displayed (byte-reversed) block hashes start with zeros.
        if int.from_bytes(digest, "little") <= target:
            return nonce
    return None


def mine_block(rpc, script_pubkey: bytes, log=print) -> MinedBlock:
    """Mine and submit one block on top of the node's current tip."""
    started = fetched_at = time.monotonic()
    template = fetch_template(rpc)
    extranonce = nonce_start = attempts = 0

    while True:
        if time.monotonic() - fetched_at > TEMPLATE_MAX_AGE:
            # Pick up a new tip, new mempool transactions, and a current timestamp.
            log(f"  {attempts / (time.monotonic() - started):,.0f} H/s, refreshing template")
            template = fetch_template(rpc)
            fetched_at = time.monotonic()
            nonce_start = 0

        candidate = build_candidate(template, script_pubkey, extranonce)
        stop = min(nonce_start + CHUNK_SIZE, NONCE_SPACE)
        nonce = search(candidate.header, candidate.target, nonce_start, stop)

        if nonce is None:
            attempts += stop - nonce_start
            nonce_start = stop
            if nonce_start == NONCE_SPACE:
                # Every nonce failed. A new extranonce changes the coinbase txid, and
                # with it the merkle root, giving another 2^32 headers to try.
                extranonce += 1
                nonce_start = 0
            continue

        attempts += nonce - nonce_start + 1
        candidate.header.nonce = nonce
        result = rpc.call("submitblock", candidate.serialize().hex())
        if result is not None:
            raise RuntimeError(f"node rejected block at height {candidate.height}: {result}")
        return MinedBlock(
            height=candidate.height,
            hash=to_display_hex(candidate.header.hash()),
            nonce=nonce,
            extranonce=extranonce,
            tx_count=1 + len(candidate.transactions),
            attempts=attempts,
            seconds=time.monotonic() - started,
        )
