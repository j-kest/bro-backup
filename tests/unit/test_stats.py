# SPDX-License-Identifier: AGPL-3.0-or-later
"""Statistics: growth, when space runs out, reliability, folders, savings, and the page itself."""
import datetime
import subprocess
import unittest
from unittest import mock

import _env

from bro import alarm, backup, core, stats
from test_alarm import item
from test_peers import mk_dest, mk_receiver
from test_security import WebBase

GIB = core.GIB


def ago(days):
    return core.iso(core.now() - datetime.timedelta(days=days))


class Forecast(unittest.TestCase):
    def test_growth_and_full_in(self):
        t0 = core.now()
        pts = [(t0 - datetime.timedelta(days=20 - i), 50 * GIB + i * GIB) for i in range(21)]  # 1 GiB a day
        self.assertAlmostEqual(stats.growth_per_day(pts), GIB, delta=1)
        days, g = stats.full_in(pts, 100 * GIB)
        self.assertAlmostEqual(days, 30, delta=0.1)
        self.assertEqual(stats.full_in(pts[:2], 100 * GIB), (None, None))  # too little history
        flat = [(t, 10) for t, _ in pts]
        self.assertEqual(stats.full_in(flat, 100), (None, 0.0))

    def test_running_out_is_told_once(self):
        _env.reset()
        d = mk_dest()
        core.update_dest(d["id"], remote_quota_gib=100, remote_usage=85 * GIB,
                         history=[{"at": ago(10 - i), "usage": (75 + i) * GIB} for i in range(11)])
        sent = []
        with mock.patch.object(stats, "notify", lambda t, m, priority="high": sent.append(t)):
            stats.check_running_out()
            stats.check_running_out()
        self.assertEqual(sent, ["Your space at Bob is full in about 15 days"])


class PerBro(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.d = mk_dest()

    def test_reliability_paths_savings_folders(self):
        core.update_dest(self.d["id"], runs=[{"at": ago(40), "outcome": "failed"}] +
                         [{"at": ago(i), "outcome": "ok"} for i in range(9)] + [{"at": ago(3), "outcome": "failed"},
                                                                               {"at": ago(2), "outcome": "interrupted"}],
                         history=[{"at": ago(i), "seconds": 60, "added": 100 * 1024 ** 2, "path": "direct" if i else "relay",
                                   "src_added": {"photos": 10, "docs": 2}} for i in range(4)],
                         repo_stats={"at": ago(1), "stored": 60, "uncompressed": 90, "files": 100})
        d = core.get_dest(self.d["id"])
        r = stats.reliability(d)
        self.assertEqual((r["runs"], r["ok"], r["failed"], r["interrupted"]), (10, 9, 1, 1))
        self.assertEqual(r["avg_seconds"], 60)
        self.assertEqual(stats.paths(d), ({"direct": 3, "relay": 1}, 4))
        self.assertEqual(stats.savings(d)["share"], 0.4)
        self.assertEqual(stats.folder_growth(), [{"key": "photos", "bytes": 40}, {"key": "docs", "bytes": 8}])
        self.assertAlmostEqual(stats.speeds(d)[0]["bps"], 100 * 1024 ** 2 * 8 / 60)


class Recording(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.d = mk_dest()
        ok = subprocess.CompletedProcess([], 0, "{}", "")
        for p in (mock.patch.object(backup.procs, "ensure_tunnel"), mock.patch.object(backup, "check_quota"),
                  mock.patch.object(backup, "ensure_repo"), mock.patch.object(backup, "restic_env", return_value={}),
                  mock.patch.object(backup, "notify"), mock.patch.object(alarm, "notify"),
                  mock.patch.object(alarm, "inspect", return_value=([], [])),
                  mock.patch.object(backup, "restic", return_value=ok)):
            p.start()
        self.addCleanup(mock.patch.stopall)

    def test_runs_and_folder_bytes_are_recorded(self):
        info = dict(item("photos", 1, 0, 1, "s2"), data_added=12345)
        with mock.patch.object(backup, "restic_backup", return_value=(
                {"data_added": 12345, "total_bytes_processed": 1, "files_new": 1, "files_changed": 0,
                 "files_unmodified": 1}, None, [info])):
            backup.run_backup(self.d["id"])
        with mock.patch.object(backup, "restic_backup", side_effect=backup.JobError("boom")):
            backup.run_backup(self.d["id"])
        d = core.get_dest(self.d["id"])
        self.assertEqual([r["outcome"] for r in d["runs"]], ["ok", "failed"])
        self.assertEqual(d["history"][-1]["src_added"], {"photos": 12345})

    def test_daily_samples(self):
        user, _ = mk_receiver("Carol")
        core.receive_stats[user] = {"usage": 5 * GIB}
        stats.sample_daily()
        stats.sample_daily()  # the same day: one sample
        st = core.load_state()
        self.assertEqual(len(st["recv_history"][user]), 1)
        self.assertEqual(len(st["space_history"]), 1)


class Page(WebBase):
    def test_page_renders(self):
        self.login()
        d = mk_dest()
        core.update_dest(d["id"], remote_quota_gib=100, remote_usage=85 * GIB,
                         runs=[{"at": ago(1), "outcome": "ok"}],
                         history=[{"at": ago(10 - i), "usage": (75 + i) * GIB, "added": GIB, "seconds": 100,
                                   "path": "lan", "src_added": {"photos": GIB}} for i in range(11)])
        page = self.c.get("/stats").get_data(as_text=True)
        for text in ("When space runs out", "Your space at Bob", "100%", "local network 100%", "photos", "around"):
            self.assertIn(text, page)
        self.assertIn("Upload speed per backup", self.c.get(f"/dest/{d['id']}/history").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
