# SPDX-License-Identifier: AGPL-3.0-or-later
import base64
import unittest
from unittest import mock

import _env  # noqa: F401

from bro import auth

# RFC 6238 appendix B, SHA1: secret "12345678901234567890". The RFC lists 8 digits, we use the last 6.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()
RFC = {59: "94287082", 1111111109: "07081804", 1234567890: "89005924", 2000000000: "69279037"}


class Totp(unittest.TestCase):
    def test_rfc6238_vectors(self):
        for t, code in RFC.items():
            self.assertEqual(auth._totp(RFC_SECRET, t // 30), code[-6:], t)

    def test_drift_and_replay(self):
        t = 1234567890
        code = auth._totp(RFC_SECRET, t // 30)
        step = auth.totp_counter_for(RFC_SECRET, code, at=t + 30)  # one step late: still fine
        self.assertEqual(step, t // 30)
        self.assertIsNone(auth.totp_counter_for(RFC_SECRET, code, last_used=step, at=t))  # used twice
        self.assertIsNone(auth.totp_counter_for(RFC_SECRET, code, at=t + 90))  # too late

    def test_bad_input(self):
        self.assertIsNone(auth.totp_counter_for(RFC_SECRET, "12345"))
        self.assertIsNone(auth.totp_counter_for("", "123456"))
        self.assertEqual(len(auth.new_totp_secret()), 32)


class Lockout(unittest.TestCase):
    def test_lock_after_five(self):
        addr = "192.0.2.10"
        auth.clear_fails(addr)
        with mock.patch.object(auth, "notify") as n:
            for _ in range(auth.MAX_FAILS - 1):
                auth.register_fail(addr)
            self.assertEqual(auth.locked_for(addr), 0)
            auth.register_fail(addr)
            self.assertGreater(auth.locked_for(addr), 0)
            n.assert_called_once()
        auth.clear_fails(addr)
        self.assertEqual(auth.locked_for(addr), 0)


if __name__ == "__main__":
    unittest.main()
