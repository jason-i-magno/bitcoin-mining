import unittest

from miner.encoding import bits_to_target
from miner.mining import build_candidate, mine_block, search

SCRIPT_PUBKEY = bytes.fromhex("0014" + "11" * 20)

# Shaped like bitcoind's getblocktemplate reply for block 1 on a fresh regtest chain.
REGTEST_TEMPLATE = {
    "version": 0x20000000,
    "previousblockhash": "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
    "transactions": [],
    "coinbasevalue": 50 * 100_000_000,
    "target": f"{bits_to_target(0x207FFFFF):064x}",
    "curtime": 1_700_000_000,
    "bits": "207fffff",
    "height": 1,
    "default_witness_commitment": "6a24aa21a9ed"
    "e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
}


class FakeRPC:
    def __init__(self, template):
        self.template = template
        self.submitted = []

    def call(self, method, *params):
        if method == "getblocktemplate":
            return self.template
        if method == "submitblock":
            self.submitted.append(bytes.fromhex(params[0]))
            return None
        raise AssertionError(f"unexpected RPC {method}")


class BuildCandidateTest(unittest.TestCase):
    def test_header_fields_come_from_template(self):
        candidate = build_candidate(REGTEST_TEMPLATE, SCRIPT_PUBKEY, extranonce=0)
        self.assertEqual(candidate.header.version, 0x20000000)
        self.assertEqual(candidate.header.bits, 0x207FFFFF)
        self.assertEqual(candidate.header.prev_block[::-1].hex(), REGTEST_TEMPLATE["previousblockhash"])
        # With only a coinbase, the merkle root is the coinbase txid.
        self.assertEqual(candidate.header.merkle_root, candidate.coinbase.txid())

    def test_rejects_mismatched_witness_commitment(self):
        template = dict(REGTEST_TEMPLATE, default_witness_commitment="6a24aa21a9ed" + "00" * 32)
        with self.assertRaises(ValueError):
            build_candidate(template, SCRIPT_PUBKEY, extranonce=0)


class SearchTest(unittest.TestCase):
    def test_found_nonce_meets_target(self):
        candidate = build_candidate(REGTEST_TEMPLATE, SCRIPT_PUBKEY, extranonce=0)
        nonce = search(candidate.header, candidate.target, 0, 1000)
        self.assertIsNotNone(nonce)
        candidate.header.nonce = nonce
        self.assertLessEqual(int.from_bytes(candidate.header.hash(), "little"), candidate.target)

    def test_impossible_target_finds_nothing(self):
        candidate = build_candidate(REGTEST_TEMPLATE, SCRIPT_PUBKEY, extranonce=0)
        self.assertIsNone(search(candidate.header, 0, 0, 1000))


class MineBlockTest(unittest.TestCase):
    def test_submits_a_block_that_meets_the_target(self):
        rpc = FakeRPC(REGTEST_TEMPLATE)
        mined = mine_block(rpc, SCRIPT_PUBKEY, log=lambda _: None)

        (raw,) = rpc.submitted
        self.assertEqual(raw[80], 1)  # transaction count: just the coinbase
        header_hash = bytes.fromhex(mined.hash)[::-1]
        self.assertLessEqual(int.from_bytes(header_hash, "little"), bits_to_target(0x207FFFFF))
        self.assertEqual(mined.height, 1)
        self.assertEqual(mined.attempts, mined.nonce + 1)
