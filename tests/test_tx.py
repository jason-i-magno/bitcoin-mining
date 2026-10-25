import unittest

from miner.encoding import from_display_hex
from miner.tx import Transaction, TxIn, TxOut, build_coinbase

GENESIS_COINBASE_HEX = (
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff"
    "4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72"
    "206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff"
    "0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f"
    "61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
)
GENESIS_TXID = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"


class TransactionTest(unittest.TestCase):
    def test_genesis_coinbase(self):
        raw = bytes.fromhex(GENESIS_COINBASE_HEX)
        script_sig = raw[42:42 + 0x4D]
        script_pubkey = raw[-4 - 0x43:-4]
        tx = Transaction(
            version=1,
            inputs=[TxIn(bytes(32), 0xFFFFFFFF, script_sig)],
            outputs=[TxOut(50 * 100_000_000, script_pubkey)],
        )
        self.assertEqual(tx.serialize().hex(), GENESIS_COINBASE_HEX)
        self.assertEqual(tx.txid(), from_display_hex(GENESIS_TXID))


class CoinbaseTest(unittest.TestCase):
    SCRIPT = bytes.fromhex("0014" + "11" * 20)  # a P2WPKH output

    def test_starts_with_bip34_height(self):
        cb = build_coinbase(height=1, extranonce=bytes(8), value=50, script_pubkey=self.SCRIPT)
        self.assertEqual(cb.inputs[0].script_sig[:1], b"\x51")
        cb = build_coinbase(height=500000, extranonce=bytes(8), value=50, script_pubkey=self.SCRIPT)
        self.assertEqual(cb.inputs[0].script_sig[:4].hex(), "0320a107")

    def test_witness_commitment(self):
        commitment = bytes(range(32))
        cb = build_coinbase(1, bytes(8), 50, self.SCRIPT, witness_commitment=commitment)
        self.assertEqual(cb.outputs[1].value, 0)
        self.assertEqual(cb.outputs[1].script_pubkey.hex(), "6a24aa21a9ed" + commitment.hex())
        self.assertEqual(cb.inputs[0].witness, [bytes(32)])
        # The segwit marker appears in the full serialization but not in what the txid hashes.
        self.assertEqual(cb.serialize()[4:6], b"\x00\x01")
        self.assertNotEqual(cb.serialize(include_witness=False)[4:6], b"\x00\x01")

    def test_without_commitment_has_no_witness(self):
        cb = build_coinbase(1, bytes(8), 50, self.SCRIPT)
        self.assertEqual(len(cb.outputs), 1)
        self.assertEqual(cb.serialize(), cb.serialize(include_witness=False))

    def test_extranonce_changes_txid(self):
        a = build_coinbase(1, (0).to_bytes(8, "little"), 50, self.SCRIPT)
        b = build_coinbase(1, (1).to_bytes(8, "little"), 50, self.SCRIPT)
        self.assertNotEqual(a.txid(), b.txid())

    def test_rejects_oversized_script_sig(self):
        with self.assertRaises(ValueError):
            build_coinbase(1, bytes(8), 50, self.SCRIPT, tag=b"x" * 100)
