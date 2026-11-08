# SPDX-License-Identifier: AGPL-3.0-or-later
"""Where each folder is read from: a ZFS snapshot, or live when a snapshot would miss child datasets."""
import datetime
import os
import shutil
import tempfile
import unittest
from unittest import mock

import _env

from bro import backup, core, nas


def snap_name(hours_ago):
    return (datetime.datetime.now() - datetime.timedelta(hours=hours_ago)).strftime("auto-%Y-%m-%d_%H-%M")


class ZfsPlan(unittest.TestCase):
    def setUp(self):
        _env.reset()
        shutil.rmtree(core.NAS_DIR, ignore_errors=True)
        self.nas = os.path.realpath(core.NAS_DIR)
        self.mounts = tempfile.NamedTemporaryFile("w", delete=False, suffix=".mountinfo")
        self.mounts.close()
        self.addCleanup(os.remove, self.mounts.name)
        p = mock.patch.object(nas, "MOUNTINFO", self.mounts.name)
        p.start()
        self.addCleanup(mock.patch.stopall)

    def dataset(self, rel, snapshot_hours=None, child_of_snapshot=None):
        """A folder that looks like a ZFS dataset root, optionally with one snapshot."""
        path = os.path.join(self.nas, rel)
        os.makedirs(os.path.join(path, ".zfs", "snapshot"), exist_ok=True)
        if snapshot_hours is not None:
            os.makedirs(os.path.join(path, ".zfs", "snapshot", snap_name(snapshot_hours)))
        return path

    def mount(self, *paths):
        with open(self.mounts.name, "a") as f:
            for i, p in enumerate(paths):
                f.write(f"{100 + i} 1 0:{50 + i} / {p.replace(' ', chr(92) + '040')} rw,relatime - zfs pool/x rw\n")

    def plan(self, *sources):
        with core.mutate() as st:
            st["settings"]["sources"] = list(sources)
        return {i["key"]: i for i in backup.backup_plan()}

    def test_plain_dataset_reads_its_snapshot(self):
        vw = self.dataset("fast/Vaultwarden", snapshot_hours=2)
        self.mount(vw)
        item = self.plan(vw)["fast/Vaultwarden"]
        self.assertTrue(item["origin"].startswith("zfs:"), item)

    def test_child_datasets_make_the_parent_read_live(self):
        immich = self.dataset("tank/immich", snapshot_hours=2)
        library = self.dataset("tank/immich/library", snapshot_hours=2)
        upload = self.dataset("tank/immich/my upload", snapshot_hours=2)
        self.mount(immich, library, upload,
                   os.path.join(immich, ".zfs", "snapshot", snap_name(2)))  # an automounted snapshot is no child
        self.assertEqual(backup.sub_datasets(immich), [upload, library] if upload < library else [library, upload])
        item = self.plan(immich)["tank/immich"]
        self.assertEqual((item["origin"], item["cwd"], item["target"]), ("live", immich, "."))
        self.assertIn("2 child dataset(s)", item["note"])

    def test_child_datasets_ticked_one_by_one_use_their_own_snapshots(self):
        immich = self.dataset("tank/immich")
        library = self.dataset("tank/immich/library", snapshot_hours=2)
        self.mount(immich, library)
        items = self.plan(library)
        self.assertTrue(items["tank/immich/library"]["origin"].startswith("zfs:"))

    def test_empty_snapshot_falls_back_to_live(self):
        data = self.dataset("tank/immich/data", snapshot_hours=2)  # the snapshot folder is empty
        os.makedirs(os.path.join(data, "library"))
        self.mount(data)
        with mock.patch.object(backup.time, "sleep") as slept:
            item = self.plan(data)["tank/immich/data"]
        self.assertEqual(item["origin"], "live")
        self.assertIn("looks empty in the app", item["note"])
        self.assertEqual(slept.call_count, 2)  # looked three times first
        snap = os.path.join(data, ".zfs", "snapshot", snap_name(2))
        os.makedirs(os.path.join(snap, "library"))
        self.assertTrue(self.plan(data)["tank/immich/data"]["origin"].startswith("zfs:"))

    def test_picker_shows_child_datasets(self):
        vw = self.dataset("fast/Vaultwarden")
        data, pg = self.dataset("fast/Vaultwarden/data"), self.dataset("fast/Vaultwarden/pgData")
        os.makedirs(os.path.join(vw, "plain-folder"))  # an ordinary folder is not listed at level 3
        self.mount(vw, data, pg)
        rows = [(f["label"], f["depth"]) for f in nas.list_folders()]
        self.assertEqual(rows, [("fast", 1), ("Vaultwarden", 2), ("data", 3), ("pgData", 3)])
        items = self.plan(data, pg)
        self.assertEqual(set(items), {"fast/Vaultwarden/data", "fast/Vaultwarden/pgData"})

    def test_picker_hides_synology_system_folders(self):
        for d in ("GoogleDrive/#recycle", "GoogleDrive/@eaDir", "GoogleDrive/projects", "@appstore", "#snapshot"):
            os.makedirs(os.path.join(self.nas, d))
        self.assertEqual([f["label"] for f in nas.list_folders()], ["GoogleDrive", "projects"])

    def test_no_mountinfo_keeps_the_old_behaviour(self):
        vw = self.dataset("fast/Vaultwarden", snapshot_hours=2)
        os.remove(self.mounts.name)
        open(self.mounts.name, "w").close()  # recreated so cleanup works
        with mock.patch.object(nas, "MOUNTINFO", "/nonexistent/mountinfo"):
            self.assertTrue(self.plan(vw)["fast/Vaultwarden"]["origin"].startswith("zfs:"))


if __name__ == "__main__":
    unittest.main()
