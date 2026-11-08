# SPDX-License-Identifier: AGPL-3.0-or-later
"""The safety score on the overview."""
import datetime
import unittest

import _env

from bro import core, safety
from test_peers import mk_dest


def ago(days):
    return core.iso(core.now() - datetime.timedelta(days=days))


class Safety(unittest.TestCase):
    def setUp(self):
        _env.reset()

    def good_dest(self, name="Bob"):
        d = mk_dest(name)
        core.update_dest(d["id"], last_ok=ago(0.5), escrow_at=ago(1), restore_test={"ok": True, "at": ago(3)})
        return d

    def everything_set(self):
        with core.mutate() as st:
            st["recovery"]["key"] = "k"
            st["settings"].update(ntfy_url="https://ntfy.example/x")

    def test_nothing_yet(self):
        r = safety.compute()
        self.assertLessEqual(r["score"], 20)
        self.assertEqual(r["label"], "Not safe")
        self.assertEqual(r["todo"][0]["fix"], "Pair with a bro")

    def test_one_good_bro(self):
        self.everything_set()
        self.good_dest()
        r = safety.compute()
        self.assertEqual(r["score"], 85)
        self.assertEqual(r["label"], "Safe")
        self.assertEqual([i["fix"] for i in r["todo"]], ["Add a second bro: if one is gone, the other still has everything"])

    def test_two_good_bros_is_very_safe(self):
        self.everything_set()
        self.good_dest("Bob")
        self.good_dest("Carol")
        r = safety.compute()
        self.assertEqual((r["score"], r["label"], r["todo"]), (100, "Very safe", []))

    def test_old_backup_caps_the_score(self):
        self.everything_set()
        d = self.good_dest()
        core.update_dest(d["id"], last_ok=ago(5))
        self.assertLessEqual(safety.compute()["score"], 20)
        core.update_dest(d["id"], last_ok=ago(0.5), last_error="boom")
        self.assertLessEqual(safety.compute()["score"], 20)

    def test_ransomware_alarm_caps_the_score(self):
        self.everything_set()
        self.good_dest("Bob")
        self.good_dest("Carol")
        with core.mutate() as st:
            st["alarm"] = {"at": ago(0), "reasons": ["x"]}
        r = safety.compute()
        self.assertEqual((r["score"], r["label"]), (40, "At risk"))
        self.assertIn("red banner", r["todo"][0]["fix"])

    def test_old_restore_test_and_damage_cost_points(self):
        self.everything_set()
        d = self.good_dest()
        core.update_dest(d["id"], restore_test={"ok": True, "at": ago(60)}, full_check={"ok": False})
        r = safety.compute()
        self.assertEqual(r["score"], 85 - 15 - 10)
        self.assertIn("Safety: 60/100 (At risk)", safety.report_line())


if __name__ == "__main__":
    unittest.main()
