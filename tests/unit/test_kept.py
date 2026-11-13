# SPDX-License-Identifier: AGPL-3.0-or-later
"""What a bro deletes is kept for a few days and can be put back; and the limit we ask bros to keep to."""
import datetime
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import _env

from bro import backup, core, kept, pair_api, peers, receiving
from test_peers import mk_dest, mk_receiver
from test_security import PW, WebBase

DAY = datetime.date(2026, 11, 12)


def put(user, rel, data=b"x" * 100):
    p = os.path.join(core.RECEIVE_DIR, user, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
    return p


def gone_files(user):
    base = os.path.join(kept.KEPT_DIR, user, "gone")
    return sorted(os.path.relpath(os.path.join(r, f), base) for r, _d, fs in os.walk(base) for f in fs)


class Keeping(unittest.TestCase):
    def setUp(self):
        _env.reset()
        kept.stats.clear()
        self.user, _ = mk_receiver("Bob")
        shutil.rmtree(os.path.join(core.RECEIVE_DIR, self.user))
        self.a = put(self.user, "data/ab/abcd")
        self.snap = put(self.user, "snapshots/s1")
        put(self.user, "config")
        put(self.user, "locks/l1")
        put(self.user, "data/ab/upload.rest-server-temp")
        p = mock.patch.object(kept, "notify")
        self.notify = p.start()
        self.addCleanup(p.stop)

    def test_deleted_files_are_kept_then_dropped(self):
        self.assertEqual(kept.sweep(self.user, DAY), 0)
        self.assertEqual(os.stat(self.a).st_nlink, 2)  # a second name, no second copy
        live = os.path.join(kept.KEPT_DIR, self.user, "live")
        self.assertFalse(os.path.exists(os.path.join(live, "locks")))
        self.assertFalse(os.path.exists(os.path.join(live, "data/ab/upload.rest-server-temp")))
        os.remove(self.a)
        os.remove(self.snap)
        self.assertEqual(kept.sweep(self.user, DAY), 2)
        self.assertEqual(gone_files(self.user), ["2026-11-12/data/ab/abcd", "2026-11-12/snapshots/s1"])
        self.assertEqual(kept.stats[self.user], {"files": 2, "bytes": 200, "oldest": "2026-11-12", "until": "2026-11-19"})
        kept.sweep(self.user, DAY + datetime.timedelta(days=6))
        self.assertEqual(len(gone_files(self.user)), 2)
        kept.sweep(self.user, DAY + datetime.timedelta(days=7))
        self.assertEqual(gone_files(self.user), [])
        self.assertNotIn(self.user, kept.stats)

    def test_put_back(self):
        kept.sweep(self.user, DAY)
        os.remove(self.a)
        os.remove(self.snap)
        put(self.user, "snapshots/s1", b"new one with the same name")  # sent again in the meantime
        kept.sweep(self.user, DAY)
        files, size = kept.restore(self.user)
        self.assertEqual((files, size), (1, 100))
        self.assertEqual(open(self.a, "rb").read(), b"x" * 100)
        self.assertEqual(open(self.snap, "rb").read(), b"new one with the same name")  # what exists is left alone
        self.assertEqual(gone_files(self.user), [])
        os.remove(self.a)
        kept.sweep(self.user, DAY)  # and it is protected again
        self.assertEqual(gone_files(self.user), ["2026-11-12/data/ab/abcd"])

    def test_deleted_and_sent_again_between_two_sweeps(self):
        kept.sweep(self.user, DAY)
        os.remove(self.a)
        put(self.user, "data/ab/abcd", b"other")
        self.assertEqual(kept.sweep(self.user, DAY), 1)
        self.assertEqual(open(os.path.join(kept.KEPT_DIR, self.user, "gone/2026-11-12/data/ab/abcd"), "rb").read(), b"x" * 100)

    def test_owner_is_told_about_a_mass_deletion(self):
        for i in range(30):
            put(self.user, f"data/00/{i:04d}")
        kept.sweep(self.user, DAY)
        os.remove(self.a)
        kept.sweep(self.user, DAY)
        self.notify.assert_not_called()
        shutil.rmtree(os.path.join(core.RECEIVE_DIR, self.user, "data"))
        kept.sweep(self.user, DAY)
        self.assertIn("deleted most of his backup", self.notify.call_args[0][0])

    def test_off_and_owner_deletes(self):
        kept.sweep(self.user, DAY)
        with core.mutate() as st:
            st["settings"]["keep_deleted_days"] = 0
        kept.sweep(self.user, DAY)
        self.assertFalse(os.path.exists(os.path.join(kept.KEPT_DIR, self.user)))
        with core.mutate() as st:
            st["settings"]["keep_deleted_days"] = 7
        kept.sweep(self.user, DAY)
        peers.stop_receiving(self.user, delete_data=True)
        self.assertFalse(os.path.exists(os.path.join(kept.KEPT_DIR, self.user)))
        kept.sweep_all()
        self.assertFalse(os.path.exists(os.path.join(kept.KEPT_DIR, self.user)))

    def test_no_hard_links_here(self):
        with mock.patch.object(kept.os, "link", side_effect=OSError(18, "Invalid cross-device link")):
            kept.sweep(self.user, DAY)
        self.assertEqual(kept.unsupported, ["Invalid cross-device link"])
        kept.sweep(self.user, DAY)
        self.assertEqual(kept.unsupported, [])


class Page(WebBase):
    def test_put_back_button_and_setting(self):
        self.login()
        user, _ = mk_receiver("Carol")
        p = put(user, "data/ab/abcd")
        kept.sweep(user, DAY)
        os.remove(p)
        with mock.patch.object(kept, "notify"):
            kept.sweep(user, DAY)
        page = self.c.get("/").get_data(as_text=True)
        self.assertIn("deleted by him, kept until 2026-11-19", page)
        r = self.c.post(f"/receiver/{user}/put-back", data={"csrf": self.csrf("/")}, follow_redirects=True)
        self.assertIn("Put back 1 file(s)", r.get_data(as_text=True))
        self.assertTrue(os.path.exists(p))
        base = {"csrf": self.csrf("/settings"), "backup_hour": "2", "alert_hours": "72", "default_quota_gib": "500",
                "retention": "standard", "ransomware_watch": "1", "alert_receivers": "1", "restore_test": "1",
                "report_day": "0", "keep_deleted_days": "0"}
        self.assertIn("needs your current password", self.c.post("/settings", data=base, follow_redirects=True).get_data(as_text=True))
        self.c.post("/settings", data=dict(base, current_pw=PW, keep_deleted_days="14", recv_limit_mbit="8",
                                           recv_limit_night_mbit="0"))
        s = core.settings()
        self.assertEqual((s["keep_deleted_days"], s["recv_limit_kib"], s["recv_limit_night_kib"]), (14, 977, 0))


@unittest.skipUnless(shutil.which(core.RESTIC), "needs the restic binary")
class RealRestic(unittest.TestCase):
    """Everything a bro deleted with forget and prune comes back, and restic accepts the repository."""

    def test_forget_everything_then_put_back(self):
        _env.reset()
        kept.stats.clear()
        user, _ = mk_receiver("Bob")
        repo = os.path.join(core.RECEIVE_DIR, user)
        shutil.rmtree(repo)
        src = tempfile.mkdtemp()
        with open(os.path.join(src, "file.txt"), "w") as f:
            f.write("important " * 1000)
        env = dict(os.environ, RESTIC_REPOSITORY=repo, RESTIC_PASSWORD="test-password-1", RESTIC_CACHE_DIR=tempfile.mkdtemp())

        def r(*args):
            return subprocess.run([core.RESTIC, *args], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(r("init").returncode, 0)
        self.assertEqual(r("backup", src).returncode, 0)
        kept.sweep(user, DAY)
        self.assertEqual(r("forget", "--keep-last", "1", "--host", "nobody", "--prune").returncode, 0)
        ids = [x.split()[0] for x in r("snapshots", "--compact").stdout.splitlines() if x[:8].strip().isalnum() and len(x.split()[0]) == 8]
        self.assertEqual(r("forget", ids[0], "--prune").returncode, 0)  # what an attacker with the login would do
        self.assertNotIn(ids[0], r("snapshots").stdout)
        with mock.patch.object(kept, "notify"):
            self.assertGreater(kept.sweep(user, DAY), 0)
        files, _size = kept.restore(user)
        self.assertGreater(files, 0)
        self.assertIn(ids[0], r("snapshots").stdout)
        out = tempfile.mkdtemp()
        self.assertEqual(r("restore", ids[0], "--target", out).returncode, 0)
        self.assertEqual(r("check", "--read-data").returncode, 0)


class BroLimit(unittest.TestCase):
    def setUp(self):
        _env.reset()

    def at(self, hour):
        return datetime.datetime(2026, 11, 12, hour, 30)

    def test_what_we_ask(self):
        s = dict(core.DEFAULT_SETTINGS, recv_limit_kib=1000)
        self.assertEqual(receiving.limit_for_bros(s, self.at(12)), (1000, None))
        s.update(recv_limit_night_kib=0)  # no limit at night (22 to 7)
        self.assertEqual(receiving.limit_for_bros(s, self.at(12)), (1000, 9 * 3600 + 1800))
        self.assertEqual(receiving.limit_for_bros(s, self.at(23)), (0, 7 * 3600 + 1800))

    def test_status_tells_the_bro(self):
        user, pw = mk_receiver("Bob")
        with core.mutate() as st:
            st["settings"]["recv_limit_kib"] = 500
        import base64
        hdr = {"Authorization": "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()}
        with mock.patch.object(pair_api.space, "measure", return_value={"level": "ok"}):
            j = pair_api.pair_app.test_client().get("/bro/status", headers=hdr).get_json()
        self.assertEqual((j["limit_kib"], j["limit_for"]), (500, None))

    def test_sender_takes_the_lowest(self):
        d = mk_dest()
        self.assertEqual(backup.limit_args(None, d), [])
        with mock.patch.object(backup.procs, "pair_call", return_value={"usage": 1, "quota_gib": 5, "limit_kib": 800,
                                                                       "limit_for": 3600}):
            backup.check_quota(d)
        d = core.get_dest(d["id"])
        self.assertEqual(backup.limit_args(None, d), ["--limit-upload", "800", "--limit-download", "800"])
        self.assertTrue(backup.bro_limit_change(d))
        with core.mutate() as st:
            st["settings"]["limit_upload_kib"] = 300
        self.assertEqual(backup.limit_args(None, d), ["--limit-upload", "300", "--limit-download", "800"])
        self.assertEqual(backup.limit_args("/seed/x", d), [])  # a seed to a disk is not limited
        with mock.patch.object(backup.procs, "pair_call", return_value={"usage": 1, "quota_gib": 5, "limit_kib": "fast", "limit_for": -5}):
            backup.check_quota(d)
        d = core.get_dest(d["id"])
        self.assertEqual((d["remote_limit_kib"], d["remote_limit_until"]), (0, None))  # nonsense from a bro: no limit

    def test_unreachable_bro_keeps_the_limit(self):
        d = mk_dest()
        core.update_dest(d["id"], remote_limit_kib=800, remote_limit_until=core.iso(core.now()))
        with mock.patch.object(backup.procs, "pair_call", side_effect=RuntimeError("Bro not reachable")):
            d = backup.refresh_bro_limit(core.get_dest(d["id"]))
        self.assertEqual(d["remote_limit_kib"], 800)
        self.assertGreater(backup.bro_limit_change(d), datetime.datetime.now().astimezone() + datetime.timedelta(minutes=50))


if __name__ == "__main__":
    unittest.main()
