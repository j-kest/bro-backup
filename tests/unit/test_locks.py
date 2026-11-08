# SPDX-License-Identifier: AGPL-3.0-or-later
"""Locks that a stopped restic leaves behind at a bro: removed before cleanup, and a lock that is in use
postpones the cleanup instead of failing the backup."""
import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import _env

from bro import alarm, backup, core
from test_alarm import item
from test_peers import mk_dest

LOCKED = ("unable to create lock in backend: repository is already locked by PID 153 on a1b2c3d4e5f6 by root "
          "(UID 0, GID 0)\nlock was created at 2026-11-08 09:41:18 (9h4m2s ago)\nstorage ID 0c0ffee0\n"
          "the `unlock` command can be used to remove stale locks\n")


class Cleanup(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.d = mk_dest()
        core.update_dest(self.d["id"], last_check=core.iso(core.now()))
        self.calls, self.forget = [], subprocess.CompletedProcess([], 0, "", "")
        ok = subprocess.CompletedProcess([], 0, "", "")

        def fake(d, *a, **k):
            cmd = next(x for x in a if not x.startswith("-") and x != "2m")
            self.calls.append(cmd)
            return self.forget if cmd == "forget" else ok
        for p in (mock.patch.object(backup.procs, "ensure_tunnel"), mock.patch.object(backup, "check_quota"),
                  mock.patch.object(backup, "ensure_repo"), mock.patch.object(backup, "restic_env", return_value={}),
                  mock.patch.object(backup, "notify"), mock.patch.object(alarm, "notify"),
                  mock.patch.object(alarm, "inspect", return_value=([], [])),
                  mock.patch.object(backup, "restic", side_effect=fake),
                  mock.patch.object(backup, "restic_backup", return_value=(
                      {"data_added": 1, "total_bytes_processed": 1, "files_new": 0, "files_changed": 1,
                       "files_unmodified": 1}, None, [item("photos", 0, 1, 1, "s2")]))):
            p.start()
        self.addCleanup(mock.patch.stopall)

    def test_stale_locks_removed_before_cleanup(self):
        backup.run_backup(self.d["id"])
        self.assertEqual(self.calls[:2], ["unlock", "forget"])
        self.assertTrue(core.get_dest(self.d["id"])["last_ok"])

    def test_a_lock_in_use_postpones_cleanup(self):
        self.forget = subprocess.CompletedProcess([], 1, "", LOCKED)
        backup.run_backup(self.d["id"])
        d = core.get_dest(self.d["id"])
        self.assertIsNone(d["last_error"])
        self.assertTrue(d["last_ok"])
        self.assertIn("Cleanup postponed to the next backup", d["last_warning"])
        self.assertIn("locked by PID 153 on a1b2c3d4e5f6", d["last_warning"])
        self.assertIsNone(d.get("last_prune"))  # the weekly clean-up is not marked as done

    def test_other_errors_still_fail(self):
        self.forget = subprocess.CompletedProcess([], 1, "", "Fatal: wrong password\n")
        backup.run_backup(self.d["id"])
        self.assertIn("Cleanup failed", core.get_dest(self.d["id"])["last_error"])


@unittest.skipUnless(shutil.which(core.RESTIC) or os.path.exists(core.RESTIC), "needs the restic binary")
class RealRestic(unittest.TestCase):
    """What restic itself does with locks, so the comment in clear_stale_locks stays true."""

    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.env = dict(os.environ, RESTIC_REPOSITORY=self.repo, RESTIC_PASSWORD="test-password-1")
        self.r("init")

    def r(self, *args):
        return subprocess.run([core.RESTIC, *args], env=self.env, capture_output=True, text=True, timeout=120)

    def holder(self):
        """A restic that holds a lock: a backup waiting for data on stdin."""
        p = subprocess.Popen([core.RESTIC, "backup", "--stdin"], env=self.env, stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.listdir(os.path.join(self.repo, "locks")):
                return p
            time.sleep(0.1)
        p.kill()
        p.stdin.close()
        self.fail("restic did not take a lock")

    def test_lock_of_a_killed_restic(self):
        p = self.holder()
        p.send_signal(signal.SIGKILL)
        p.wait()
        p.stdin.close()
        self.assertIn("already locked", self.r("forget", "--keep-last", "1").stderr)  # restic does not skip it
        self.assertEqual(self.r("unlock").returncode, 0)
        self.assertEqual(os.listdir(os.path.join(self.repo, "locks")), [])
        self.assertEqual(self.r("forget", "--keep-last", "1").returncode, 0)

    def test_lock_of_a_running_restic_stays(self):
        p = self.holder()
        try:
            self.r("unlock")
            self.assertEqual(len(os.listdir(os.path.join(self.repo, "locks"))), 1)
        finally:
            p.kill()
            p.wait()
            p.stdin.close()


if __name__ == "__main__":
    unittest.main()
