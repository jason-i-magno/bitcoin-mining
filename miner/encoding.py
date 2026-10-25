"""Byte-level primitives: hashing, integer encodings, and the compact target format."""

import hashlib


def sha256d(data: bytes) -> bytes:
    """Bitcoin's hash function: SHA-256 applied twice."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def from_display_hex(s: str) -> bytes:
    """Parse a txid/block hash as shown by RPC and explorers into internal byte order.

    Hashes are displayed byte-reversed, so the hex you see is backwards relative
    to the bytes that get hashed and serialized.
    """
    return bytes.fromhex(s)[::-1]


def to_display_hex(h: bytes) -> str:
    return h[::-1].hex()


def compact_size(n: int) -> bytes:
    """Variable-length integer used for counts and lengths in transactions and blocks."""
    if n < 0xFD:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def push_data(data: bytes) -> bytes:
    """Script that pushes `data` onto the stack, using the smallest push opcode."""
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data  # OP_PUSHDATA1
    if n <= 0xFFFF:
        return b"\x4d" + n.to_bytes(2, "little") + data  # OP_PUSHDATA2
    return b"\x4e" + n.to_bytes(4, "little") + data  # OP_PUSHDATA4


def push_int(n: int) -> bytes:
    """Script that pushes a non-negative integer, byte-for-byte like Bitcoin Core's `CScript() << n`.

    BIP34 requires the coinbase scriptSig to start with exactly this encoding of
    the block height, so heights 1-16 must use OP_1..OP_16 rather than a data push.
    """
    if n == 0:
        return b"\x00"  # OP_0
    if n <= 16:
        return bytes([0x50 + n])  # OP_1 (0x51) .. OP_16 (0x60)
    # Minimal little-endian; Script numbers are signed, so add a 0x00 byte
    # if the top bit is set to keep the value positive.
    length = (n.bit_length() + 8) // 8
    return push_data(n.to_bytes(length, "little"))


def bits_to_target(bits: int) -> int:
    """Decode the header's compact 'nBits' field into the full 256-bit target.

    The top byte is a base-256 exponent and the low 3 bytes a mantissa:
    target = mantissa * 256^(exponent - 3).
    """
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))
