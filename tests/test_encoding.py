import unittest

from miner.encoding import bits_to_target, compact_size, push_data, push_int


class CompactSizeTest(unittest.TestCase):
    def test_boundaries(self):
        cases = {
            0: "00",
            0xFC: "fc",
            0xFD: "fdfd00",
            0xFFFF: "fdffff",
            0x10000: "fe00000100",
            0xFFFFFFFF: "feffffffff",
            0x100000000: "ff0000000001000000",
        }
        for n, expected in cases.items():
            self.assertEqual(compact_size(n).hex(), expected, n)


class ScriptTest(unittest.TestCase):
    def test_push_data(self):
        self.assertEqual(push_data(b""), b"\x00")
        self.assertEqual(push_data(b"\xab" * 75), b"\x4b" + b"\xab" * 75)
        self.assertEqual(push_data(b"\xab" * 76), b"\x4c\x4c" + b"\xab" * 76)

    def test_push_int_matches_bitcoin_core(self):
        cases = {
            1: "51",  # OP_1
            16: "60",  # OP_16
            17: "0111",
            127: "017f",
            128: "028000",  # 0x80 alone would read as negative zero
            255: "02ff00",
            256: "020001",
            32767: "02ff7f",
            32768: "03008000",
            500000: "0320a107",
        }
        for n, expected in cases.items():
            self.assertEqual(push_int(n).hex(), expected, n)


class TargetTest(unittest.TestCase):
    def test_genesis_difficulty(self):
        self.assertEqual(bits_to_target(0x1D00FFFF), 0xFFFF << 208)

    def test_regtest_difficulty(self):
        # Regtest's target is about half of all hashes, so ~2 attempts per block.
        self.assertEqual(bits_to_target(0x207FFFFF), 0x7FFFFF << 232)

    def test_wiki_example(self):
        self.assertEqual(
            f"{bits_to_target(0x1B0404CB):064x}",
            "00000000000404cb000000000000000000000000000000000000000000000000",
        )
