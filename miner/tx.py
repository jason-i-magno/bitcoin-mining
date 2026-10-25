"""Transaction serialization and coinbase construction."""

from dataclasses import dataclass, field

from .encoding import compact_size, push_data, push_int, sha256d

# BIP141: the coinbase's single witness item, and the tag that marks the commitment output.
WITNESS_RESERVED_VALUE = bytes(32)
WITNESS_COMMITMENT_HEADER = bytes.fromhex("aa21a9ed")
OP_RETURN = b"\x6a"

DEFAULT_COINBASE_TAG = b"/py-regtest-miner/"


@dataclass
class TxIn:
    prev_txid: bytes  # internal byte order
    prev_index: int
    script_sig: bytes
    sequence: int = 0xFFFFFFFF
    witness: list[bytes] = field(default_factory=list)


@dataclass
class TxOut:
    value: int  # satoshis
    script_pubkey: bytes


@dataclass
class Transaction:
    version: int
    inputs: list[TxIn]
    outputs: list[TxOut]
    locktime: int = 0

    def serialize(self, include_witness: bool = True) -> bytes:
        witness = include_witness and any(txin.witness for txin in self.inputs)
        parts = [self.version.to_bytes(4, "little")]
        if witness:
            parts.append(b"\x00\x01")  # segwit marker and flag
        parts.append(compact_size(len(self.inputs)))
        for txin in self.inputs:
            parts += [
                txin.prev_txid,
                txin.prev_index.to_bytes(4, "little"),
                compact_size(len(txin.script_sig)),
                txin.script_sig,
                txin.sequence.to_bytes(4, "little"),
            ]
        parts.append(compact_size(len(self.outputs)))
        for txout in self.outputs:
            parts += [
                txout.value.to_bytes(8, "little"),
                compact_size(len(txout.script_pubkey)),
                txout.script_pubkey,
            ]
        if witness:
            for txin in self.inputs:
                parts.append(compact_size(len(txin.witness)))
                for item in txin.witness:
                    parts += [compact_size(len(item)), item]
        parts.append(self.locktime.to_bytes(4, "little"))
        return b"".join(parts)

    def txid(self) -> bytes:
        """Hash of the serialization *without* witness data, in internal byte order.

        This is what goes into the block's merkle root.
        """
        return sha256d(self.serialize(include_witness=False))


def witness_commitment_script(commitment: bytes) -> bytes:
    return OP_RETURN + push_data(WITNESS_COMMITMENT_HEADER + commitment)


def build_coinbase(
    height: int,
    extranonce: bytes,
    value: int,
    script_pubkey: bytes,
    witness_commitment: bytes | None = None,
    tag: bytes = DEFAULT_COINBASE_TAG,
) -> Transaction:
    """Build the transaction that pays the block reward (subsidy + fees) to `script_pubkey`.

    The scriptSig carries the height (required by BIP34), then the extranonce,
    which the miner changes to get a new merkle root once the header nonce is exhausted.
    """
    script_sig = push_int(height) + push_data(extranonce) + push_data(tag)
    if not 2 <= len(script_sig) <= 100:
        raise ValueError(f"coinbase scriptSig must be 2-100 bytes, got {len(script_sig)}")

    outputs = [TxOut(value, script_pubkey)]
    witness = []
    if witness_commitment is not None:
        outputs.append(TxOut(0, witness_commitment_script(witness_commitment)))
        witness = [WITNESS_RESERVED_VALUE]

    coinbase_input = TxIn(
        prev_txid=bytes(32),  # a coinbase spends nothing: null prevout
        prev_index=0xFFFFFFFF,
        script_sig=script_sig,
        witness=witness,
    )
    return Transaction(version=2, inputs=[coinbase_input], outputs=outputs)
