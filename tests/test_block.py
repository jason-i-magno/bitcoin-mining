import unittest

from miner.block import BlockHeader, merkle_root, witness_commitment
from miner.encoding import from_display_hex, sha256d, to_display_hex


class HeaderTest(unittest.TestCase):
    def test_genesis_block_hash(self):
        header = BlockHeader(
            version=1,
            prev_block=bytes(32),
            merkle_root=from_display_hex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"),
            timestamp=1231006505,
            bits=0x1D00FFFF,
            nonce=2083236893,
        )
        self.assertEqual(len(header.serialize()), 80)
        self.assertEqual(
            to_display_hex(header.hash()),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
        )


class MerkleTest(unittest.TestCase):
    def test_single_hash_is_its_own_root(self):
        h = bytes(range(32))
        self.assertEqual(merkle_root([h]), h)

    def test_block_100000(self):
        txids = [
            "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
            "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
            "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
            "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
        ]
        self.assertEqual(
            to_display_hex(merkle_root([from_display_hex(t) for t in txids])),
            "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766",
        )

    def test_odd_level_duplicates_last_hash(self):
        a, b, c = (bytes([i]) * 32 for i in range(3))
        self.assertEqual(merkle_root([a, b, c]), sha256d(sha256d(a + b) + sha256d(c + c)))


class WitnessCommitmentTest(unittest.TestCase):
    def test_coinbase_only_block(self):
        # The value Bitcoin Core puts in default_witness_commitment for an empty block.
        self.assertEqual(
            witness_commitment([]).hex(),
            "e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
        )
