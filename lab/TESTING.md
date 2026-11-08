# Testing BRO Backup without a NAS

This lab runs two bros, **alice** and **bob**, plus a mail catcher on one computer. Each bro gets
its own test data, and alice's `tank` folder behaves like a ZFS dataset with snapshots. You can
test almost everything here: pairing, backups, ZFS snapshot reading, restores, the restore test,
email, the backup window, seeding via an external disk, recovering a crashed NAS, an address change
and stopping with a bro.

## What you need

- Docker Desktop (Windows or macOS) or Docker Engine (Linux)
- PowerShell 7, or Windows PowerShell 5.1
- About 2 GB of free disk space
- An internet connection the first time, to build the image

## Start

```powershell
cd lab
.\lab.ps1
```

The first start builds the image, which takes a few minutes. After that:

| What | Where |
|---|---|
| alice | http://localhost:8481 |
| bob | http://localhost:8482 |
| caught emails | http://localhost:8025 |

Windows may block the script because it was downloaded. Run `Unblock-File .\lab.ps1` once, or start it
with `powershell -ExecutionPolicy Bypass -File .\lab.ps1`.

Other commands: `-Action Status`, `-Action Logs -Bro bob`, `-Action Stop`, `-Action Reset -Force`.
Run `Get-Help .\lab.ps1 -Full` or read the top of the script for all of them.

## Checklist

Tick them off as you go. "Expected" is what should happen. Anything else is a bug: download the
diagnostics bundle (Logs page) of both bros and send it along.

### Basics

- [ ] **1. Setup wizard.** On alice and bob: pick a name and password, and select the folders `tank` and `media`.
  Write down the recovery code. Expected: the app only continues after you confirm the last 4 characters.
- [ ] **2. Pairing.** On alice: *Invite a bro*, name bob, 5 GiB, *Create code*. On bob: paste it under
  *Got a code from a bro?*, keep "give space back" on, *Pair*.
  Expected: both sides show each other, and the first backup starts by itself within a minute.
- [ ] **3. Connection.** Click *Speed* next to the bro.
  Expected: "Direct on the local network". Both containers sit on the same Docker network.
- [ ] **4. Self-check.** Open *Self-check* on both.
  Expected: relay servers reachable, `media` shown as "Live" (that is right: it has no snapshots),
  "Notifications: none" until you do step 6.
- [ ] **5. Where each folder is read from** (Settings).
  Expected: `tank` from a ZFS snapshot (`auto-...`), `media` live.

### Notifications

- [ ] **6. Email.** Settings, Email: server `mail`, port `1025`, security *None*, send to any address.
  Save, then *Send a test notification*. Expected: it shows up at http://localhost:8025.
- [ ] **7. Wrong address.** Enter `not-an-address` as recipient and save. Expected: refused with a clear message.

### Backups and restores

- [ ] **8. Changes.** Run `.\lab.ps1 -Action ChangeData`, then `.\lab.ps1 -Action NewSnapshot`, then
  *Now* on alice. Expected: 1 new and 1 changed file, the rest unchanged, a small amount sent.
- [ ] **9. Snapshot age.** Do step 8 without `NewSnapshot`. Expected: the backup still reads the old
  snapshot, so the new file is not in it yet. That is correct: a snapshot is a frozen moment.
- [ ] **10. Restore an old version.** Restore on alice, choose a version from before step 8.
  Expected: the deleted `IMG_0001.jpg` is back, in `alice/data/restore`. Your live data is untouched.
- [ ] **11. Speed test.** *Speed*, *Run speed test*. Expected: upload and download speeds, and time estimates.
- [ ] **12. Upload limit.** Settings, limit 5 Mbit/s, run the speed test again.
  Expected: the estimate says it uses your limit.

### Restore test

- [ ] **13. Passing test.** Restore, *Run a restore test*. Expected: passed, with the number of files checked.
- [ ] **14. Broken backup.** `.\lab.ps1 -Action CorruptBackup`, then run the restore test again (a few times if needed: it checks a sample).
  Expected: failed, overview turns red, an email arrives.
- [ ] **15. Continue after it.** There is no repair button yet. Reset the lab (`.\lab.ps1 -Action Reset -Force`) to continue with clean data.

### Space

- [ ] **16. Quota.** On bob, change alice's space with the field next to her name.
  Expected: alice's overview shows the new limit after her next backup. To really hit the limit,
  start the lab with more data than the smallest quota (`.\lab.ps1 -SizeMB 1500`, quota 1 GiB):
  alice's backup then fails, at bob's limit. From the next try on, alice says
  "Quota at bob reached" before sending anything. Raise it again and the next backup works.
- [ ] **17. Revoke.** On bob, *Revoke* alice. Expected: alice's next backup fails with "Login refused".
  Pair again afterwards to continue.

### Backup window

- [ ] **18. Window.** Settings: back up at the current hour, stop at the next hour. Expected: the
  self-check shows the window as open. Change it so the current hour is outside the window: no
  backup starts by itself, but *Now* still works.

### First backup via an external disk

- [ ] **19. Seed.** Reset the lab. Pair again, but tick *Send my first backup to him on an external disk*.
  Expected: alice writes her first backup to the `usb` folder (the "disk"). bob sees it under
  Import and imports it. After that, alice's backups go over the network and send only the changes.

### Crashed NAS

- [ ] **20. Crash.** `.\lab.ps1 -Action Crash -Bro alice`. alice starts empty, like a new NAS.
- [ ] **21. Help code.** On bob, *Help code* next to alice.
- [ ] **22. Recover.** On alice's setup page, open *My NAS crashed or was replaced*, enter the help code
  and the recovery code from step 1. Expected: alice gets her settings and pairings back, and backups are
  paused so an empty NAS does not overwrite anything.
- [ ] **23. Restore everything.** Restore the newest version. Then *Resume backups*.

### Picking files, leaving things out, repair

- [ ] **25. Browse and pick.** Restore, *Browse* next to a version of `tank`. Open `photos/2026`, tick two photos,
  go back and tick `documents`, click *Restore selected*. Expected: only those, in `alice/data/restore`.
- [ ] **26. Search.** In the same version, search `note-07`, then `*.txt`. Expected: matching files with their folder.
- [ ] **27. Junk.** Put a `Thumbs.db` and a file `~$test.docx` in `alice/nas/tank/documents`, run `NewSnapshot`, then *Now*.
  Expected: browsing the new version does not show them.
- [ ] **28. Own patterns and size.** Settings, *Also skip*: `*.iso`, *Skip files larger than*: 0.1. Put a `movie.iso`
  and a file over 100 MB in `tank`, `NewSnapshot`, *Now*. Expected: neither is in the new version.
- [ ] **29. Full check.** Restore, *Run a full check*. Expected: "no errors".
- [ ] **30. Repair.** `.\lab.ps1 -Action CorruptBackup`, then *Run a full check* again. Expected: red overview, damaged files
  listed, a *Repair* button. Click it and follow the overview. Expected: after the repair the full check finds no errors,
  and a restore test passes.
- [ ] **31. Weekly report.** Settings, *Send the weekly report now*. Expected: a mail at http://localhost:8025 with each bro's status.
- [ ] **32. Silent bro.** Stop bob (`docker compose stop bob`) and wait longer than *Notify when there was no backup for*
  (minimum 24 hours, so this one takes a day). Expected: alice gets "bob has not backed up to you for a while".

### Security, databases, speed, history

- [ ] **33. Two-step login.** Security, *Set up* with your password. Scan the QR code with an authenticator app and type
  the code. Log out and in again. Expected: the login asks for a code, and the same code does not work twice.
- [ ] **34. Lockout.** Log out and enter a wrong password 5 times. Expected: "Too many wrong attempts", a mail at
  http://localhost:8025, and even the right password is refused for 15 minutes.
- [ ] **35. Locked out.** `docker compose exec alice python main.py reset-two-step`, then `reset-password`.
  Expected: two-step login is off, and you can log in with the printed temporary password.
- [ ] **36. Session expiry.** Leave the page alone for over an hour. Expected: the next click asks you to log in.
- [ ] **37. SQLite dump.** Put a SQLite database in `alice/nas/tank/apps` (any `.db` or `.sqlite3` file, for example a copy
  of a Vaultwarden `db.sqlite3`). Settings, *Look for databases*, tick it, save, *Now*. Expected: Settings shows the
  dump, a version of `@databases` appears under Restore, and the restored copy opens fine.
- [ ] **38. Immich dumps.** Create `alice/nas/tank/apps/immich/backups/immich-db-backup-20261101T020000-v1.130.0-pg14.sql.gz`
  (any content). *Look for databases*. Expected: Settings mentions Immich, the self-check shows the dump and its age.
- [ ] **39. Day and night.** Settings: limit upload 2 Mbit/s, at night 0, night from the next full hour to the hour after.
  Put a file of 2 GB in `alice/nas/tank`, run `NewSnapshot`, then *Now* a few minutes before the full hour.
  Expected: at the full hour the Logs page shows "Upload limit changes now (no limit)" and the backup speeds up.
- [ ] **40. History.** After a few backups, *History* next to bob. Expected: three charts, a value when you hover a bar,
  and a table of every backup.

### Addresses and stopping with a bro

- [ ] **41. New address.** `.\lab.ps1 -Action ChangeAddress -Bro alice`. Expected: within about a minute bob's
  overview shows "new address received" under alice, and *Now* at bob still works. Run it again to move alice back.
  The lab has internet relays, so a real NAS would usually find alice through those anyway; here the
  address that alice sends herself is what keeps it working when the relays are blocked.
- [ ] **42. Check-in.** Self-check at alice. Expected: "Own address" with the number of relays and direct
  addresses, and per bro "Address: last exchanged ...".
- [ ] **43. Stop backing up.** At bob: **×** next to alice. Expected: a page that explains what happens and offers
  to stop storing alice's backups too. Type a wrong name: nothing happens. Type `Alice`, keep both boxes ticked.
  Expected at bob: alice is gone from both lists, and her data is under "Backups of bros that stopped".
  Expected at alice within a minute: "Stopped by Bob" in red, a mail, and bob's data under
  "Backups of bros that stopped" with "deleted on" a week from now.
- [ ] **44. Keep or delete.** At alice: *Keep* next to bob's data. Expected: the date disappears. Then *Delete now*.
  Expected: the row disappears and `alice/data/receive` no longer has bob's folder.
- [ ] **45. Clean up.** At alice: **×** next to bob. Expected: no name check problems, and "You no longer back up to Bob."
- [ ] **46. Stop storing only.** Pair again (steps 2 to 4), then at alice: *Stop* next to bob under "Bros backing up
  to me". Expected at bob within a minute: "Stopped by Alice". Bob's backups to alice stop, alice's backups to bob go on.
- [ ] **47. Automatic test.** On a fresh lab (`.\lab.ps1 -Action Reset -Force`, then `.\lab.ps1 -SizeMB 40`):
  `python3 ../tests/lab/e2e.py` (or `python` on Windows). Expected: green lines and "All checks passed".
  It takes about 5 minutes.

### Updates, disk space, ransomware

- [ ] **48. Update notice.** Settings, Updates: the box is ticked. Open Self-check: the row "Version" shows
  the version, "the latest" or "not checked yet" (the lab has internet, so normally the latest).
  Untick the box and save: Self-check says checking is off.
- [ ] **49. Upgrade from an older version.** Build the new image with a normal `.\lab.ps1`, then
  `.\lab.ps1 -Action Reset -Force` and start with an older image, for example
  `.\lab.ps1 -Image ghcr.io/j-kest/bro-backup:0.9.0 -SizeMB 40`. Then
  `python3 ../tests/lab/upgrade.py --old ghcr.io/j-kest/bro-backup:0.9.0 --new bro-backup:lab`.
  Expected: "All checks passed". About 10 minutes.
- [ ] **50. Disk filling up.** At alice, under "Bros backing up to me", set bob's space to more than
  the free space of your PC disk (for example 5000 GiB). Expected within an hour (or at once in Self-check):
  "You gave bros more space than is free" on the overview, a warning row in Self-check, one notification.
- [ ] **51. Ransomware alarm.** On a fresh lab: `python3 ../tests/lab/ransomware.py`. It adds 300 documents
  to alice, then "encrypts" them in a new snapshot (renamed to `.locked`, ransom notes in three folders).
  Expected: "All checks passed": the alarm went on, old versions were kept, the version before the attack
  restored the originals, and clearing the alarm needed the password. About 10 minutes.
- [ ] **52. Picking up a backup on a disk.** On a fresh lab: `python3 ../tests/lab/pickup.py`. bob copies
  alice's backup to the "usb" folder, a PC without network restores it with only the recovery code, then
  alice's NAS is wiped, bob goes offline, and the new alice recovers and restores from the disk. Expected:
  "All checks passed", restored files identical to the originals. About 10 minutes.
- [ ] **53. Restore on your own PC.** With the disk from step 52 (the folder in `lab\usb`):
  `..\install\restore-from-disk.ps1 -Disk .\usb -Image bro-backup:lab`. Expected: it asks for alice's
  recovery code, green "Done", her files in `BRO-restore` in your user folder.
- [ ] **54. Safety score and space requests.** On a fresh lab: `python3 ../tests/lab/probro.py`. Expected:
  "All checks passed": alice's overview shows 75/100 with "Add a second bro" as first to do, alice asks bob
  for 10 GiB more, bob grants it, alice sees 15 GiB, and bob's CSV export has alice with his reference.
- [ ] **55. PCs and servers (UrBackup).** On a fresh lab: `python3 ../tests/lab/urbackup.py`. It builds a
  storage laid out like UrBackup's on alice's NAS. Expected: "All checks passed": both computers listed, the
  silent one notified, the storage included, sent to bob and restored with its hard links. With a real
  UrBackup server: install the TrueNAS app, back up one PC, and check that the overview lists it.
- [ ] **56. Pausing backups.** On a fresh lab started with `-SizeMB 120`: `python3 ../tests/lab/pause.py`.
  Expected: "All checks passed": bob shows "Receiving now" with a speed near the upload limit,
  restic stops within seconds of Pause, nothing starts during the pause, Now is refused, and after
  Resume the backup finishes.
- [ ] **57. Bros on the same network.** On two real NAS devices in the same network: fill in each NAS's
  address under Settings, Local network, publish UDP 7841 and 7842, and click Speed next to the bro.
  Expected: "local network" instead of "via relay". The lab cannot show this: its two bros already reach
  each other directly inside one Docker network.
- [ ] **58. Speed test through the real pair server.** Start the lab without `-Image`, so it builds the real
  image with waitress, with `-SizeMB 20`: `python3 ../tests/lab/speed.py`. Expected: "All checks passed",
  upload and download both measured. An image without waitress falls back to a development server and
  does not show what the real pair server refuses.
- [ ] **59. Asked again before what cannot be undone.** Settings, Recovery code: without your password nothing
  changes; with it you get a new code and a notification. The same for Stop backing up to a bro, deleting
  a bro's backups, Delete now under leftover data, and an import with "replace existing". With two-step
  login on, each also needs a fresh code from your app.
- [ ] **60. A lock left behind.** On a fresh lab with `-SizeMB 80`: `python3 ../tests/lab/stale_lock.py`.
  Expected: "All checks passed": bob's restic is killed during a backup, its lock stays at alice, and the
  next backup removes it and runs the weekly cleanup.

### Help

- [ ] **24. Diagnostics.** Logs, *Download diagnostics*. Open the zip and search for your passwords and
  the recovery code. Expected: not found.

## Over the internet (optional)

Both bros on one computer always connect directly. To test a real internet connection, run alice
on one PC and bob on another one on a different network (a laptop on a phone hotspot works):

```powershell
.\lab.ps1 -Only alice     # PC 1
.\lab.ps1 -Only bob       # PC 2, from its own copy of this folder
```

The speed test then shows whether you connect directly or through a relay.

## What the lab cannot test

- Real ZFS snapshots. The lab mimics the `.zfs/snapshot` folder that BRO Backup reads. Whether the
  real one is readable inside the container only shows on TrueNAS (Settings and Self-check show it).
- The TrueNAS installer and Synology Container Manager.
- Very large first backups (several TB) and days-long seeds.
