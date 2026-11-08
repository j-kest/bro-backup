# SPDX-License-Identifier: AGPL-3.0-or-later
import unittest

import _env  # noqa: F401

from bro import pairing


class Codes(unittest.TestCase):
    def test_roundtrip_with_whitespace(self):
        code = pairing.encode_code("BRO1.", {"n": "Alice", "dt": "x", "pt": "y"})
        spaced = code[:10] + "\n  " + code[10:]
        self.assertEqual(pairing.decode_code(spaced, "BRO1.", ("n", "dt"))["n"], "Alice")

    def test_wrong_prefix_and_missing_field(self):
        code = pairing.encode_code("BROH1.", {"n": "Alice"})
        with self.assertRaises(ValueError):
            pairing.decode_code(code, "BRO1.", ("n",))
        with self.assertRaises(ValueError):
            pairing.decode_code(code, "BROH1.", ("n", "tok"))


if __name__ == "__main__":
    unittest.main()
