# SPDX-License-Identifier: AGPL-3.0-or-later
"""What comes in from bros right now: restic locks and rest-server counters, measured on this NAS."""
import io
import os
import re
import time
import unittest
from unittest import mock

import _env

from bro import core, incoming, receiving, web

PW = "a-long-test-password"
METRICS = '''# HELP rest_server_blob_write_bytes_total Total number of bytes written to blobs
rest_server_blob_write_bytes_total{repo="bob",type="data",user="bob"} 3.000925e+06
rest_server_blob_write_bytes_total{repo="bob",type="index",user="bob"} 419
rest_server_blob_write_bytes_total{repo="carol",type="data",user="carol"} 1000
rest_server_blob_write_total{repo="bob",type="data",user="bob"} 2
'''


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def opener_for(text, seen=None):
    def op(req, timeout=None):
        if seen is not None:
            seen.append(req)
        return Resp(text.encode())
    return op


class Incoming(unittest.TestCase):
    def setUp(self):
        _env.reset()
        incoming._samples.clear()
        incoming._session.clear()
        incoming._last["at"] = 0.0

    def lock(self, user, age_s):
        d = os.path.join(core.RECEIVE_DIR, user, "locks")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, "a" * 64)
        open(p, "w").close()
        t = time.time() - age_s
        os.utime(p, (t, t))

    def test_counters_per_user_with_the_metrics_login(self):
        seen = []
        self.assertEqual(incoming.read_counters(opener_for(METRICS, seen)), {"bob": 3001344, "carol": 1000})
        self.assertTrue(seen[0].full_url.endswith("/metrics"))
        self.assertTrue(seen[0].get_header("Authorization").startswith("Basic "))
        self.assertIn("metrics_pw", core.SECRET_KEYS)

    def test_speed_and_session(self):
        self.lock("bob", 30)
        t0 = time.time()
        for i, total in enumerate((1_000_000, 6_000_000, 11_000_000)):
            with mock.patch.object(incoming.time, "time", return_value=t0 + 5 * i):
                incoming.sample(force=True, opener=opener_for(f'rest_server_blob_write_bytes_total{{user="bob"}} {total}'))
        with mock.patch.object(incoming, "sample"), mock.patch.object(incoming.time, "time", return_value=t0 + 10):
            st = incoming.status(["bob", "carol"])
        self.assertTrue(st["bob"]["active"])
        self.assertAlmostEqual(st["bob"]["speed"], 1_000_000, delta=1)
        self.assertFalse(st["carol"]["active"])
        self.assertEqual(web.incoming_text(st["carol"]), "")
        self.assertIn("Receiving now: ", web.incoming_text(dict(st["bob"], received=10_000_000)))

    def test_old_lock_is_not_a_backup(self):
        self.lock("bob", incoming.LOCK_FRESH + 60)
        with mock.patch.object(incoming, "sample"):
            self.assertFalse(incoming.status(["bob"])["bob"]["active"])
        self.assertIsNone(incoming.lock_age("nobody"))

    def test_restart_of_rest_server_resets(self):
        incoming.sample(force=True, opener=opener_for('rest_server_blob_write_bytes_total{user="bob"} 5000'))
        incoming.sample(force=True, opener=opener_for('rest_server_blob_write_bytes_total{user="bob"} 10'))
        self.assertEqual(list(incoming._samples["bob"])[-1][1], 10)
        self.assertEqual(len(incoming._samples["bob"]), 1)

    def test_metrics_login_kept_and_name_reserved(self):
        receiving.write_htpasswd({})
        receiving.ensure_metrics_user()
        h = receiving.read_htpasswd()["metrics"]
        receiving.ensure_metrics_user()
        self.assertEqual(receiving.read_htpasswd()["metrics"], h)  # not rewritten every time
        user, _pw, _tok = receiving.new_receiver("Metrics", 10)
        self.assertNotEqual(user, "metrics")


class Page(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW), sources=[])
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        mock.patch.object(web.time, "sleep").start()
        self.addCleanup(mock.patch.stopall)
        tok = lambda p: re.search(r'name="csrf" value="([^"]+)"', self.c.get(p).get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "csrf": tok("/login")})

    def test_live_json_needs_login_and_reports(self):
        receiving.new_receiver("Bob", 10)
        with mock.patch.object(incoming, "status", return_value={"bob": {"active": True, "speed": 2_000_000,
                                                                         "received": 50_000_000, "since": None}}):
            r = self.c.get("/live.json")
            self.assertEqual(r.status_code, 200, r.get_data(as_text=True)[:300])
            j = r.get_json()
            self.assertIn("Receiving now", j["incoming"]["bob"]["text"])
            self.assertIn('data-incoming="bob"', self.c.get("/").get_data(as_text=True))
        self.assertNotEqual(web.app.test_client().get("/live.json").status_code, 200)


if __name__ == "__main__":
    unittest.main()
