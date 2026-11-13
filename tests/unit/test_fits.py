# SPDX-License-Identifier: AGPL-3.0-or-later
"""A first backup that cannot fit in the space the bro gave is not started."""
import subprocess
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


if __name__ == "__main__":
    unittest.main()
