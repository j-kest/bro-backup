# SPDX-License-Identifier: AGPL-3.0-or-later
"""Picking up a backup at the bro's on a disk, and getting everything back with only the recovery code."""
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import _env

from bro import backup, core, nas, pickup, recovery
from test_peers import mk_dest, mk_receiver

RC = "ABCD-EFGH-JKLM-NPQR-STUV-WXYZ-2345-6789"


def fake_repo(user, files=None):
    repo = os.path.join(core.RECEIVE_DIR, user)
    for sub in ("keys", "snapshots", "index", "data/ab"):
        os.makedirs(os.path.join(repo, sub), exist_ok=True)
    with open(os.path.join(repo, "config"), "w") as f:
        f.write("cfg")
    for rel, body in (files or {"snapshots/" + "1" * 64: "snap", "data/ab/" + "a" * 64: "pack"}).items():
        with open(os.path.join(repo, rel), "w") as f:
            f.write(body)
    return repo


def sealed_bundle(user, repo_password="repo-pw"):
    salt = os.urandom(16)
    key = recovery.derive_key(RC, salt)
    bundle = {"v": 1, "settings": {"name": "Alice"}, "identity": {"x": 1}, "receivers": {}, "htpasswd": "",
              "destinations": [{"id": "d1", "name": "Bob", "user": user, "password": "p", "repo_password": repo_password,
                                "data_ticket": _env.ticket("bb" * 32), "pair_ticket": _env.ticket("bb" * 32)}]}
    return recovery.seal(bundle, key.hex(), salt.hex())


def _salt(path):
    with open(os.path.join(path, pickup.ESCROW_FILE)) as f:
        return json.load(f)["blob"]["salt"]


class Base(unittest.TestCase):
    def setUp(self):
        _env.reset()
        self.seed = tempfile.mkdtemp()
        for p in (mock.patch.object(pickup.threading, "Thread", _env.SyncThread),
                  mock.patch.object(pickup, "notify"), mock.patch.object(pickup, "SEED_MOUNT", self.seed),
                  mock.patch.object(nas, "SEED_MOUNT", self.seed)):
            p.start()
        self.addCleanup(mock.patch.stopall)
        self.addCleanup(shutil.rmtree, self.seed, True)


class BroSide(Base):
    def test_copy_to_disk(self):
        user, _ = mk_receiver("Alice")
        repo = fake_repo(user)
        os.symlink("/etc/passwd", os.path.join(repo, "data", "ab", "link"))  # never copied
        with open(os.path.join(core.ESCROW_DIR, f"{user}.json"), "w") as f:
            json.dump({"sealed": True}, f)
        target, external, total = pickup.make_pickup(user)
        self.assertTrue(external)
        self.assertTrue(target.startswith(self.seed))
        self.assertTrue(os.path.isfile(os.path.join(target, "data", "ab", "a" * 64)))
        self.assertFalse(os.path.lexists(os.path.join(target, "data", "ab", "link")))
        self.assertTrue(os.path.isfile(os.path.join(target, pickup.ESCROW_FILE)))
        m = pickup.read_marker(target)
        self.assertEqual((m["user"], m["for"], m["escrow"]), (user, "Alice", True))
        self.assertTrue(core.load_state()["receivers"][user]["pickup"]["ok"])
        self.assertEqual([x["path"] for x in pickup.scan()], [os.path.realpath(target)])

    def test_copy_order_snapshots_before_data(self):
        user, _ = mk_receiver("Alice")
        fake_repo(user)
        order = []
        real = shutil.copyfile
        with mock.patch.object(pickup.shutil, "copyfile", lambda s, d, **k: order.append(s) or real(s, d, **k)):
            pickup.make_pickup(user)
        kinds = [p.split(os.sep + user + os.sep, 1)[1].split(os.sep)[0] for p in order if os.sep + user + os.sep in p]
        self.assertLess(kinds.index("snapshots"), kinds.index("data"))

    def test_refusals(self):
        with self.assertRaises(ValueError):
            pickup.make_pickup("../etc")
        user, _ = mk_receiver("Alice")
        with self.assertRaises(ValueError):  # nothing backed up yet
            pickup.make_pickup(user)
        fake_repo(user)
        with mock.patch.object(nas, "free_space", return_value=10), self.assertRaises(ValueError):
            pickup.make_pickup(user)


class YourSide(Base):
    def make_disk(self, user="alice-x1", escrow=True):
        path = os.path.join(self.seed, "backup-of-alice")
        os.makedirs(os.path.join(path, "snapshots"))
        with open(os.path.join(path, "config"), "w") as f:
            f.write("cfg")
        if escrow:  # exactly as the bro stores it (pair_api /bro/escrow)
            with open(os.path.join(path, pickup.ESCROW_FILE), "w") as f:
                json.dump({"blob": sealed_bundle(user), "stored": core.iso(core.now())}, f)
        with open(os.path.join(path, pickup.PICKUP_MARKER), "w") as f:
            json.dump({"from": "Bob", "for": "Alice", "user": user, "created": core.iso(core.now()), "size": 3}, f)
        return os.path.realpath(path)

    def test_recover_with_only_the_recovery_code(self):
        path = self.make_disk()
        with self.assertRaises(ValueError):
            pickup.recover_from_disk(path, "WRONG-CODE")
        bundle, m, d = pickup.recover_from_disk(path, RC)
        self.assertEqual(m["from"], "Bob")
        d = core.get_dest("d1")
        self.assertEqual((d["mode"], d["restore_from"]), ("hold", path))  # never backs up by itself after a recovery
        self.assertEqual(core.load_state()["recovery"]["key"], recovery.derive_key(RC, bytes.fromhex(
            _salt(path))).hex())

    def test_disk_without_key_copy(self):
        path = self.make_disk(escrow=False)
        with self.assertRaises(ValueError) as e:
            pickup.recover_from_disk(path, RC)
        self.assertIn("help code", str(e.exception))

    def test_odd_markers_are_ignored(self):
        path = self.make_disk()
        with open(os.path.join(path, pickup.PICKUP_MARKER), "w") as f:
            json.dump({"user": "../../etc", "from": "<script>"}, f)
        self.assertEqual(pickup.scan(), [])
        with open(os.path.join(path, pickup.PICKUP_MARKER), "w") as f:
            json.dump(["not", "a", "dict"], f)
        self.assertEqual(pickup.scan(), [])

    def test_restore_source_only_for_the_right_bro(self):
        d = mk_dest()  # user "alice"
        other = self.make_disk(user="someone-else")
        with self.assertRaises(ValueError):
            pickup.use_for_restore(d["id"], other)
        shutil.rmtree(other)
        mine = self.make_disk(user="alice")
        pickup.use_for_restore(d["id"], mine)
        self.assertEqual(backup.restore_source(core.get_dest(d["id"])), mine)
        with self.assertRaises(ValueError):  # a folder that is not where BRO Backup looks
            elsewhere = tempfile.mkdtemp()
            shutil.copytree(mine, os.path.join(elsewhere, "x"))
            pickup.use_for_restore(d["id"], os.path.join(elsewhere, "x"))

    def test_restore_reads_go_to_the_disk(self):
        d = mk_dest()
        mine = self.make_disk(user="alice")
        pickup.use_for_restore(d["id"], mine)
        with mock.patch.object(backup.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            backup.restic(core.get_dest(d["id"]), "snapshots", "--json", read=True)
        args, kw = run.call_args
        self.assertIn("--no-lock", args[0])
        self.assertEqual(kw["env"]["RESTIC_REPOSITORY"], mine)


@unittest.skipUnless(shutil.which(core.RESTIC), "restic not installed")
class CommandLine(Base):
    def test_restore_on_any_pc(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        disk = os.path.join(self.seed, "backup-of-alice")
        src = os.path.join(tmp, "src")
        os.makedirs(os.path.join(src, "sub"))
        with open(os.path.join(src, "sub", "offer.docx"), "w") as f:
            f.write("the original")
        env = dict(os.environ, RESTIC_REPOSITORY=disk, RESTIC_PASSWORD="repo-pw", RESTIC_CACHE_DIR=os.path.join(tmp, "c"))
        for a in (["init"], ["backup", "--tag", "bro", "--tag", "src:tank", "."]):
            subprocess.run([core.RESTIC, *a], env=env, cwd=src, check=True, capture_output=True)
        with open(os.path.join(disk, pickup.ESCROW_FILE), "w") as f:
            json.dump(sealed_bundle("alice-x1"), f)
        with open(os.path.join(disk, pickup.PICKUP_MARKER), "w") as f:
            json.dump({"from": "Bob", "user": "alice-x1", "created": core.iso(core.now()), "size": 1}, f)
        out = os.path.join(tmp, "out")
        with mock.patch("sys.stdin", io.StringIO("wrong\n")), mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(pickup.restore_from_disk_cli(["--to", out, "--code", "-"]), 1)
        buf = io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(RC + "\n")), mock.patch("sys.stdout", buf):
            self.assertEqual(pickup.restore_from_disk_cli(["--to", out, "--code", "-"]), 0, buf.getvalue())
        with open(os.path.join(out, "tank", "sub", "offer.docx")) as f:
            self.assertEqual(f.read(), "the original")
        self.assertFalse(os.path.exists(os.path.join(out, ".restic-cache")))


if __name__ == "__main__":
    unittest.main()
