# SPDX-License-Identifier: AGPL-3.0-or-later
"""A first backup that cannot fit in the space the bro gave is not started."""
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import _env

from bro import alarm, backup, core
from test_alarm import item
from test_peers import mk_dest

GIB = core.GIB


class Fits(unittest.TestCase):
    def setUp(self):
        _env.reset()
        core.sources_size.clear()
        self.d = mk_dest()
        self.calls = []
        ok = subprocess.CompletedProcess([], 0, "", "")
        for p in (mock.patch.object(backup.procs, "ensure_tunnel"), mock.patch.object(backup, "ensure_repo"),
                  mock.patch.object(backup, "restic_env", return_value={}), mock.patch.object(backup, "notify"),
                  mock.patch.object(alarm, "notify"), mock.patch.object(alarm, "inspect", return_value=([], [])),
                  mock.patch.object(backup, "restic", return_value=ok),
                  mock.patch.object(backup, "restic_backup", side_effect=lambda *a, **k: self.calls.append(1) or (
                      {"data_added": 1, "total_bytes_processed": 1, "files_new": 0, "files_changed": 0,
                       "files_unmodified": 1}, None, [item("photos", 0, 0, 1, "s2")]))):
            p.start()
        self.addCleanup(mock.patch.stopall)

    def run_with(self, quota_gib, usage, size):
        with mock.patch.object(backup.procs, "pair_call", return_value={"usage": usage, "quota_gib": quota_gib}), \
                mock.patch.object(backup, "sources_bytes", return_value=size):
            backup.run_backup(self.d["id"])
        return core.get_dest(self.d["id"])

    def test_too_big_is_not_started(self):
        d = self.run_with(100, 869 * 1024 ** 2, int(763.5 * GIB))
        self.assertEqual(self.calls, [])
        self.assertIn("Not started: your folders hold 763.5 GiB, and Bob gave you 100 GiB", d["last_error"])

    def test_fits_and_later_backups_are_not_measured(self):
        d = self.run_with(100, 0, 90 * GIB)
        self.assertEqual(self.calls, [1])
        self.assertTrue(d["last_ok"])
        with mock.patch.object(backup, "sources_bytes", side_effect=AssertionError("measured again")), \
                mock.patch.object(backup.procs, "pair_call", return_value={"usage": 95 * GIB, "quota_gib": 100}):
            backup.run_backup(self.d["id"])  # same folders as last time: only the quota check counts
        self.assertEqual(len(self.calls), 2)

    def test_folders_added_are_checked_again(self):
        self.run_with(100, 0, 90 * GIB)
        with core.mutate() as st:
            st["settings"]["sources"] = ["/nas/photos", "/nas/videos"]
        d = self.run_with(100, 80 * GIB, 500 * GIB)
        self.assertIn("Not started", d["last_error"])

    def test_no_quota_no_check(self):
        self.run_with(0, 0, 10 ** 15)
        self.assertEqual(self.calls, [1])

    def later(self, usage, history_added, added):
        self.run_with(100, 0, 1 * GIB)  # a first backup that fits
        core.update_dest(self.d["id"], history=[{"added": history_added}])
        with mock.patch.object(backup, "estimate_added", return_value=added) as est:
            d = self.run_with(100, usage, 1 * GIB)
        return d, est

    def test_later_backup_with_room_is_not_dry_run(self):
        d, est = self.later(10 * GIB, 1 * GIB, 0)
        est.assert_not_called()
        self.assertEqual(len(self.calls), 2)

    def test_later_backup_that_does_not_fit_sends_nothing(self):
        d, est = self.later(95 * GIB, 2 * GIB, 8 * GIB)
        est.assert_called_once()
        self.assertEqual(len(self.calls), 1)
        self.assertIn("this backup would add 8.0 GiB at Bob, and only 5.0 GiB", d["last_error"])
        self.assertIn("Nothing was sent", d["last_error"])

    def test_later_backup_that_fits_runs(self):
        d, est = self.later(95 * GIB, 2 * GIB, 3 * GIB)
        est.assert_called_once()
        self.assertEqual(len(self.calls), 2)
        self.assertIsNone(d["last_error"])

    def test_unknown_estimate_does_not_block(self):
        d, est = self.later(95 * GIB, 2 * GIB, None)
        self.assertEqual(len(self.calls), 2)


@unittest.skipUnless(shutil.which(core.RESTIC), "needs the restic binary")
class DryRun(unittest.TestCase):
    def test_estimate_matches_what_restic_adds(self):
        _env.reset()
        d = mk_dest()
        repo, src = tempfile.mkdtemp(), tempfile.mkdtemp()
        env = dict(os.environ, RESTIC_REPOSITORY=repo, RESTIC_PASSWORD="pw-test-1", RESTIC_CACHE_DIR=tempfile.mkdtemp())
        subprocess.run([core.RESTIC, "init"], env=env, capture_output=True, check=True)
        with open(os.path.join(src, "a"), "wb") as f:
            f.write(os.urandom(3_000_000))
        item = {"key": "x", "root": src, "target": ".", "cwd": src}
        with mock.patch.object(backup, "restic_env", return_value=env):
            first = backup.estimate_added(d, [item], dict(core.settings(), name="Alice"))
            subprocess.run(backup.backup_args(d, item, core.settings(), "alice"), cwd=src, env=env, capture_output=True, check=True)
            again = backup.estimate_added(d, [item], dict(core.settings(), name="Alice"))
        self.assertGreater(first, 2_900_000)
        self.assertLess(again, 100_000)  # nothing new: only a little metadata
        self.assertEqual(os.listdir(os.path.join(repo, "snapshots")).__len__(), 1)  # the dry runs wrote nothing


if __name__ == "__main__":
    unittest.main()
