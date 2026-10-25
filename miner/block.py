"""Block header, merkle tree, and the segwit witness commitment."""

import struct
from dataclasses import dataclass

from .encoding import sha256d
from .tx import WITNESS_RESERVED_VALUE


def merkle_root(hashes: list[bytes]) -> bytes:
    """Hash pairs level by level until one hash remains. Odd levels duplicate their last hash."""
    if not hashes:
        raise ValueError("merkle root of an empty list")
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def witness_commitment(wtxids: list[bytes]) -> bytes:
    """BIP141 commitment to every transaction's witness data, given the non-coinbase wtxids.

    The coinbase's wtxid is defined as all zeros, since it can't commit to itself.
    """
    witness_root = merkle_root([bytes(32), *wtxids])
    return sha256d(witness_root + WITNESS_RESERVED_VALUE)


@dataclass
class BlockHeader:
    version: int
    prev_block: bytes  # internal byte order
    merkle_root: bytes  # internal byte order
    timestamp: int
    bits: int
    nonce: int = 0

    def serialize(self) -> bytes:
        """The 80 bytes that get hashed."""
        return struct.pack(
            "<i32s32sIII",
            self.version,
            self.prev_block,
            self.merkle_root,
            self.timestamp,
            self.bits,
            self.nonce,
        )

    def hash(self) -> bytes:
        return sha256d(self.serialize())
