# SPDX-License-Identifier: AGPL-3.0-or-later
"""The ransomware alarm: judging a backup, keeping old versions, clearing with the password."""
import datetime
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import _env

from bro import alarm, backup, core, web
from test_peers import mk_dest

PW = "a-long-test-password"


def counts(new, changed, unmod):
    return {"files_new": new, "files_changed": changed, "files_unmodified": unmod}


def item(key, new, changed, unmod, snap):
    return {"key": key, **counts(new, changed, unmod), "snapshot_id": snap}


class Judge(unittest.TestCase):
    def test_mass_change_is_suspicious(self):
        r = alarm.judge_counts("photos", counts(0, 4000, 1000), counts(10, 20, 4970), 0.01)
        self.assertEqual(len(r), 1)
        self.assertIn("4000 of 5000 files new or changed", r[0])

    def test_normal_day_and_small_folders_are_fine(self):
        self.assertEqual(alarm.judge_counts("photos", counts(30, 20, 4950), counts(10, 20, 4970), 0.01), [])
        self.assertEqual(alarm.judge_counts("docs", counts(0, 80, 10), counts(0, 5, 85), 0.01), [])  # under 100 files

    def test_a_folder_that_always_changes_a_lot_is_judged_against_itself(self):
        self.assertEqual(alarm.judge_counts("logs", counts(500, 200, 300), counts(400, 200, 400), 0.6), [])

    def test_mass_delete_is_suspicious(self):
        r = alarm.judge_counts("photos", counts(0, 0, 1000), counts(0, 0, 5000), 0.01)
        self.assertIn("4000 of 5000 files gone", r[0])

    def test_baseline_leaves_out_the_first_backup(self):
        hist = [{"src": {"photos": [5000, 0, 0, False]}}] + [{"src": {"photos": [10, 40, 4950, True]}}] * 3
        self.assertAlmostEqual(alarm.baseline(hist, "photos"), 0.01)
        self.assertEqual(alarm.baseline([], "photos"), alarm.BASELINE_FLOOR)
        hist = [{"src": {"logs": [300, 300, 400, True]}}] * 5
        self.assertAlmostEqual(alarm.baseline(hist, "logs"), 0.6)

    def test_renamed_files(self):
        removed = [f"/p/img{i}.jpg" for i in range(80)]
        added = [f"/p/img{i}.jpg.lockbit" for i in range(80)]
        reasons, ex = alarm.judge_diff("photos", added, removed)
        self.assertIn("80 files came back with an extra extension, mostly .lockbit", reasons[0])
        self.assertEqual(ex[0], "/p/img0.jpg -> /p/img0.jpg.lockbit")
        # a handful of renamed files is normal
        self.assertEqual(alarm.judge_diff("photos", added[:10], removed[:10])[0], [])

    def test_ransom_notes_in_several_places(self):
        added = ["/a/HOW_TO_DECRYPT.txt", "/b/HOW_TO_DECRYPT.txt", "/c/d/HOW_TO_DECRYPT.txt", "/a/x.jpg"]
        reasons, ex = alarm.judge_diff("docs", added, [])
        self.assertIn("ransom notes in 3 folders", reasons[0])
        for name in ("Restore-My-Files.txt", "README_FOR_DECRYPT.html", "!!!RECOVER_YOUR_FILES!!!.hta"):
            self.assertTrue(alarm.NOTE_RE.search(name), name)
        for name in ("README.txt", "decrypted-photos.jpg", "restore-notes.md", "recovery.txt"):
            self.assertFalse(alarm.NOTE_RE.search(name), name)
        self.assertEqual(alarm.judge_diff("docs", added[:2], [])[0], [])  # one or two places: not enough


class Inspect(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.sent = []
        p = mock.patch.object(alarm, "notify", lambda t, m, priority="high": self.sent.append(t))
        p.start()
        self.addCleanup(mock.patch.stopall)

    def test_first_backup_never_judged(self):
        d = mk_dest()
        self.assertEqual(alarm.inspect(d, [item("photos", 5000, 0, 0, "s1")]), ([], []))

    def test_judged_against_the_previous_backup(self):
        d = mk_dest()
        core.update_dest(d["id"], last_sources=[item("photos", 10, 20, 4970, "s1")])
        reasons, _ = alarm.inspect(core.get_dest(d["id"]), [item("photos", 0, 4000, 1000, "s2")])
        self.assertTrue(reasons)
        with core.mutate() as st:
            st["settings"]["ransomware_watch"] = False
        self.assertEqual(alarm.inspect(core.get_dest(d["id"]), [item("photos", 0, 4000, 1000, "s2")]), ([], []))

    def test_alarm_notifies_once_then_daily(self):
        d = mk_dest()
        core.update_dest(d["id"], last_sources=[item("photos", 10, 20, 4970, "aaaaaaaa11")])
        d = core.get_dest(d["id"])
        alarm.raise_alarm(d, ["photos: lots"], [], [item("photos", 0, 4000, 1000, "bbbbbbbb22")])
        alarm.raise_alarm(d, ["photos: lots"], [], [item("photos", 0, 4000, 1000, "cccccccc33")])
        self.assertEqual(len(self.sent), 1)
        a = alarm.active()
        self.assertEqual(a["snaps"][d["id"]], ["bbbbbbbb", "cccccccc"])
        self.assertEqual(a["before"][d["id"]], ["aaaaaaaa"])  # the last good one, not overwritten later
        alarm.remind()
        self.assertEqual(len(self.sent), 1)
        with core.mutate() as st:
            st["alarm"]["notified_at"] = core.iso(core.now() - datetime.timedelta(hours=25))
        alarm.remind()
        self.assertEqual(len(self.sent), 2)
        alarm.clear()
        self.assertIsNone(alarm.active())


class Backup(unittest.TestCase):
    """A backup with the alarm on never runs restic forget."""

    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", restore_test=False)
        self.d = mk_dest()
        core.update_dest(self.d["id"], last_check=core.iso(core.now()))
        self.calls = []
        ok = subprocess.CompletedProcess([], 0, "", "")
        for p in (mock.patch.object(backup.procs, "ensure_tunnel"), mock.patch.object(backup, "check_quota"),
                  mock.patch.object(backup, "ensure_repo"), mock.patch.object(backup, "restic_env", return_value={}),
                  mock.patch.object(backup, "notify"), mock.patch.object(alarm, "notify"),
                  mock.patch.object(backup, "restic", side_effect=lambda d, *a, **k: self.calls.append(next(x for x in a if not x.startswith("-") and x != "2m")) or ok),
                  mock.patch.object(backup, "restic_backup", return_value=(
                      {"data_added": 1, "total_bytes_processed": 1, "files_new": 0, "files_changed": 4000,
                       "files_unmodified": 1000}, None, [item("photos", 0, 4000, 1000, "s2")]))):
            p.start()
        self.addCleanup(mock.patch.stopall)

    def test_forget_skipped_while_alarm_on(self):
        with mock.patch.object(alarm, "inspect", return_value=(["photos: lots"], [])):
            backup.run_backup(self.d["id"])
        self.assertNotIn("forget", self.calls)
        d = core.get_dest(self.d["id"])
        self.assertIn("ransomware alarm is on", d["last_warning"])
        self.assertTrue(d["history"][-1]["alarm"])
        alarm.clear()
        self.calls.clear()
        with mock.patch.object(alarm, "inspect", return_value=([], [])):
            backup.run_backup(self.d["id"])
        self.assertIn("forget", self.calls)

    def test_history_remembers_counts_per_folder(self):
        with mock.patch.object(alarm, "inspect", return_value=([], [])):
            backup.run_backup(self.d["id"])
        self.assertEqual(core.get_dest(self.d["id"])["history"][-1]["src"], {"photos": [0, 4000, 1000, False]})


@unittest.skipUnless(shutil.which(core.RESTIC), "restic not installed")
class RealDiff(unittest.TestCase):
    def test_snapshot_diff_with_restic(self):
        tmp = tempfile.mkdtemp()
        env = dict(os.environ, RESTIC_REPOSITORY=os.path.join(tmp, "repo"), RESTIC_PASSWORD="x",
                   RESTIC_CACHE_DIR=os.path.join(tmp, "cache"))
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        for i in range(3):
            with open(os.path.join(src, f"f{i}.jpg"), "w") as f:
                f.write(str(i))
        run = lambda *a: subprocess.run([core.RESTIC, *a], env=env, cwd=src, capture_output=True, text=True, check=True)
        run("init")
        run("backup", ".")
        os.rename(os.path.join(src, "f1.jpg"), os.path.join(src, "f1.jpg.locked"))
        run("backup", ".")
        ids = [x.split()[0] for x in run("snapshots", "--compact").stdout.splitlines() if x[:8].isalnum() and len(x.split()[0]) == 8]
        added, removed = alarm.snapshot_diff(env, ids[0], ids[1])
        self.assertEqual((added, removed), (["/f1.jpg.locked"], ["/f1.jpg"]))
        shutil.rmtree(tmp)


class Clear(unittest.TestCase):
    def setUp(self):
        _env.reset()
        with core.mutate() as st:
            st["settings"].update(name="Alice", pw_hash=core.hash_ui_password(PW))
            st["alarm"] = {"at": core.iso(core.now()), "reasons": ["photos: 4000 of 5000 files new or changed"],
                           "examples": ["/p/a.jpg -> /p/a.jpg.locked"], "snaps": {}, "before": {}}
        web.auth.clear_fails("127.0.0.1")
        web.app.secret_key = "unit-test"
        self.c = web.app.test_client()
        mock.patch.object(web.time, "sleep").start()
        self.addCleanup(mock.patch.stopall)
        import re
        self.tok = lambda path: re.search(r'name="csrf" value="([^"]+)"', self.c.get(path).get_data(as_text=True)).group(1)
        self.c.post("/login", data={"pw": PW, "csrf": self.tok("/login")})

    def test_banner_and_clear_needs_password(self):
        page = self.c.get("/").get_data(as_text=True)
        self.assertIn("Possible ransomware", page)
        self.assertIn("/p/a.jpg -&gt; /p/a.jpg.locked", page)
        self.c.post("/alarm/clear", data={"csrf": self.tok("/"), "current_pw": "wrong"})
        self.assertTrue(alarm.active())
        self.c.post("/alarm/clear", data={"csrf": self.tok("/"), "current_pw": PW})
        self.assertIsNone(alarm.active())
        self.assertNotIn("Possible ransomware", self.c.get("/").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
