# BRO Backup (Best Remote Online Backup)

![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue)
![Status: beta](https://img.shields.io/badge/status-beta-orange)

Encrypted off-site backups to a friend's NAS, and his to yours. No subscription, no account, no open ports. One app, one code to exchange.

> **v1.2.** Tested in a lab with the real restic, rest-server and dumbpipe, and on a TrueNAS and a Synology. Keep another backup next to BRO Backup until it has proven itself on your NAS.

## How it works

- Your data is encrypted on your own NAS before it leaves. Your bro stores it but cannot read it, and the other way around.
- The two NAS devices find each other by key, through NAT, without port forwarding.
- Pairing takes one code. It works once, and is worthless after pairing.
- A recovery code (shown once at setup) plus a help code from your bro brings everything back after a crash.

## Try it first, without a NAS

The [`lab`](lab/) folder runs two bros and a mail catcher on one computer with Docker Desktop, with test data and a fake ZFS snapshot. `.\lab\lab.ps1` starts it, and [lab/TESTING.md](lab/TESTING.md) is a checklist from pairing to repairing a damaged backup.

## Install

**The easy way:** open the [setup page](https://j-kest.github.io/bro-backup/). It builds the exact steps for TrueNAS SCALE, Synology or any Docker host.

### TrueNAS SCALE 24.10 or newer: the installer

Open **System → Shell** and run:

```sh
curl -fsSL https://raw.githubusercontent.com/j-kest/bro-backup/main/install/truenas-install.py -o /tmp/bro-install.py && sudo python3 /tmp/bro-install.py
```

It asks a few questions, shows a summary and changes nothing until you confirm. Then, through TrueNAS's own API, it:

1. creates a dataset `bro-backup` on the pool you choose, with a quota;
2. adds a daily snapshot task for it (kept 30 days);
3. installs the app, with read-only access to the pools you pick.

Add `--dry-run` to see what it would do without changing anything. The installer can be run again safely: what already exists is kept, and the app is updated.

### Without GitHub: build the image yourself

You can run BRO Backup before the image is published. On TrueNAS, copy the release zip to a share, then in **System → Shell**:

```sh
cd /mnt/YOUR-POOL/YOUR-SHARE
python3 -m zipfile -e bro-backup-v1.2.0.zip .
cd bro-backup
sudo docker build -f app/Dockerfile -t bro-backup:1.1 .
sudo python3 install/truenas-install.py --image bro-backup:1.1
```

With `--image` pointing to a local image, the installer adds `pull_policy: never`, so TrueNAS uses your build instead of downloading. To move the image to another NAS: `sudo docker save bro-backup:1.1 | gzip > bro-backup-1.1.tar.gz`, then import it there (Synology: Container Manager → Image → Import) and use `image: bro-backup:1.1` with `pull_policy: never` in the compose file.

### Synology DSM 7.2 or newer

1. Install **Container Manager** from the Package Center.
2. In File Station, inside the shared folder `docker`, create two folders: `bro-backup` and `bro-backup-app`.
3. In Container Manager, create a **Project** named `bro-backup` with path `/docker/bro-backup-app`, and paste `install-synology.yaml`. Change `/volume1` if your files are on another volume, and `TZ` to your time zone.

### Any Docker host

```yaml
services:
  bro-backup:
    image: ghcr.io/j-kest/bro-backup:1
    restart: unless-stopped
    init: true
    cap_drop: [ALL]                # only what the app needs: read every file, restore owners and times
    cap_add: [DAC_READ_SEARCH, DAC_OVERRIDE, CHOWN, FOWNER, FSETID]
    security_opt: ["no-new-privileges:true"]
    environment:
      TZ: Europe/Brussels          # your time zone: the nightly backup runs at local time
      BRO_LAN_ADDRS: "192.168.1.10" # this NAS's address on your network (optional, see below)
    ports:
      - "8484:8484"
      - "7841:7841/udp"            # direct connections (data)
      - "7842:7842/udp"            # direct connections (pairing)
    volumes:
      - /srv/bro-backup:/data      # BRO Backup's own data, incl. your bros' backups
      - /srv/data:/nas:ro          # the files you want to protect, read-only
```

### First start

Open `http://<ip-of-your-nas>:8484`. The wizard asks for a name, a password and the folders to protect. Then you get your **recovery code**: store it in a password manager or on paper, never on the NAS itself.

## Pairing with a bro

- **You**: "Invite a bro", give a name and how much space you give him. You get a code. Leave "If he gives me space back, I back up to him too" ticked if your backups should also go to him.
- Send the code via Signal or WhatsApp, not by email. It works once, for 7 days.
- **Your bro**: pastes it under "Got a code from a bro?" and leaves "He may back up to me too" ticked.
- Done. Both NAS devices back up to each other every night. Each of you decides with his own box whether his NAS sends backups to the other.

### When an address changes

A new internet connection or a router restart gives a NAS another address. Normally the relays and the address lookup of iroh find the bro again by themselves. For when those are not reachable (a firewall, a LAN without internet), the bros also keep each other up to date:

- Every few hours each bro checks in with the bros it backs up to, and they exchange their current addresses.
- When the address of the NAS itself changes, BRO Backup restarts its listeners for a fresh address and sends it to every bro that backs up to it. It also does this once a day when nothing is being transferred.
- A new address is only accepted from the same bro: the identity in it must match the one from pairing.

The overview shows "new address received" under the bro, and the self-check shows your own address and when it was last exchanged with each bro.

## Stopping with a bro

Click **×** next to a bro under "My backups at bros", or **Stop** next to a bro under "Bros backing up to me". A page explains what happens and asks you to type the bro's name.

- **Stop backing up to a bro.** You can no longer restore from him. You can ask him to delete your backups, and, if he also backs up to you, stop storing his. He gets a message right away, or within 30 days when his NAS is offline.
- **Stop storing a bro's backups.** His login stops working right away and the copy of his keys is deleted. If you also back up to him, he is told right away; otherwise his NAS notices at its next check. His backups stay on your NAS unless you choose to delete them.
- **Data that stays behind** appears under "Backups of bros that stopped", with its size and a **Delete now** button.
- **When a bro asks you to delete his backups**, they are deleted after 7 days, so a mistake can still be undone with **Keep**. If your NAS keeps backups append-only, nothing is deleted by itself: you decide.
- **When a bro stops storing yours**, the overview says "Stopped by ..." and you get a notification. Pair with someone else so your data stays safe.

## Bros on the same network

BRO Backup runs in a Docker network of its own and only sees its internal address, not the address of the NAS. Two bros on the same network, or on VLANs that reach each other, would then connect through a relay: slow, and not meant for much data. Fill in the address of the NAS under **Settings → Local network** (the TrueNAS installer does this for you), and publish UDP `7841` and `7842` on the same port numbers. Your bros get the address right after you save and connect directly; the overview then says **local network** next to the bro. Bros at other locations are not affected.

## Consistent backups from ZFS snapshots

Files that change during a backup, such as a database, can end up in a backup in a state that does not work. On TrueNAS, BRO Backup therefore reads each folder from the **newest ZFS snapshot** of its dataset, one frozen moment, when that snapshot is at most 26 hours old. Without a recent snapshot it reads the live folder and tells you why.

- **Settings → Where each folder is read from** shows, per folder, whether it comes from a snapshot or live, and the reason.
- You only need a periodic snapshot task for the datasets that hold your folders (Data Protection in TrueNAS). Daily is enough.
- Unchanged files are recognised whether a folder is read from a snapshot or live, so a nightly backup only reads what changed.
- **Child datasets**: a ZFS snapshot holds only its own dataset, so in it the folders of child datasets are empty. A folder that holds child datasets is therefore always read live, and the reason says so. To read them from snapshots, tick the child datasets themselves: the folder picker lists them one level deeper, and each is then read from its own snapshot. A recursive snapshot task takes all of them at the same moment.

## Email through Microsoft 365

Exchange Online turns Basic authentication for SMTP off by default at the end of 2026, so a Microsoft 365 mailbox with a user name and password stops working as a mail server ([Microsoft](https://techcommunity.microsoft.com/blog/exchange/updated-exchange-online-smtp-auth-basic-authentication-deprecation-timeline/4489835)). BRO Backup can send through the Microsoft Graph API instead, with an app registration and a client secret:

1. Run `install/m365-mail-setup.ps1 -Mailbox nas@yourdomain.com` (Application Administrator and Exchange Administrator). It makes the app registration and allows it to send as that one mailbox only, with [RBAC for Applications](https://learn.microsoft.com/Exchange/permissions-exo/application-rbac). It gives the app no Mail.Send consent in Entra ID: that consent would count for every mailbox in your tenant. A shared mailbox works and needs no license.
2. Under **Settings → Email**, choose **Microsoft 365 (Graph API)** and paste the values the script printed, including the expiry date of the secret: you are warned 30 and 7 days before it stops working.
3. Click **Send a test notification**. A new permission can take 30 minutes to 2 hours in Exchange.

## Seeing what comes in

Next to each bro that backs up to you, the overview shows when a backup comes in: **Receiving now: 4.2 MiB/s, 1.3 GiB so far**. It refreshes every 5 seconds without reloading the page. Both signs are measured on your own NAS, so it works whatever version the bro runs: a restic lock in his repository refreshed in the last 10 minutes, and the bytes rest-server wrote for him (its Prometheus counters, readable only by an internal login of this app, never by a bro). The speed is the average over 30 seconds; restic sends in packs of a few MiB, so it moves in steps.

## What a bro deletes is kept for a week

A bro cleans up his own old versions, so he must be able to delete on your NAS. But whoever gets hold of his NAS (ransomware, a thief) could delete his whole backup the same way. So what a bro deletes stays on your NAS for 7 days (**Settings → Space for bros**, 0 to 90 days) in a folder his login cannot reach. The overview shows "deleted by him, kept until ..." next to his name, and **Put back** undoes it. When most of a backup disappears at once, you get a notification: ask your bro whether he meant it.

It costs no extra space while the files exist (a kept file is a second name for the same data, a hard link), and the deleted data does not count toward his quota. It needs the whole bro-backup folder to be one file system; the self-check tells you when that is not so. After **Put back**, ask your bro to run a full check. This is the middle road between normal and **append-only**: with append-only nothing can ever be deleted and usage only grows.

## A speed limit for your bros

Under **Settings → Schedule**, "Bros may send to me at most" sets how fast each bro may send to you, with another value at night if you like (same night hours as your own limit). Your bro's NAS asks for it before every backup and keeps to the lowest of his own limit and yours; it also holds for what he fetches from you (a restore or a check), because that is your upload. His NAS applies it: a bro on a version before 1.1 does not follow it yet, and Settings tells you who.

## Pausing backups

**Pause backups** above your list of bros stops sending for 1 hour, 4 hours, 24 hours or until you resume. A backup that is running stops within seconds; after the pause it continues where it was, without sending again what was already uploaded. Backups from your bros to your NAS go on as usual. A banner on the overview and a row in the self-check show the pause; **Resume now** ends it.

## Restoring files

**Restore** next to a bro lists every version. **Restore all** brings back a whole folder as it was then. **Browse** opens a version like a file manager: open folders, search by name (`invoice`, or a pattern like `*.pdf`), tick the files and folders you need and click **Restore selected**. Everything goes to the `restore` folder inside your bro-backup folder, so nothing on your NAS is ever overwritten.

## Never sending what cannot fit

Before a first backup, and after you add folders, BRO Backup measures the selected folders and does not start when they cannot fit in the space your bro gave you. Later backups are checked too once space gets short (less than 10 GiB free, or less than three times your biggest recent backup): restic then first works out, without sending anything, exactly how much the backup would add. When that does not fit, nothing is sent and the overview says why. With plenty of room this check is skipped, because it reads the changed files twice.

## Choosing folders

Settings shows the first two levels of your NAS. Click ▸ next to a folder to open it and tick folders deeper down; a ticked folder includes everything below it. Folders you chose deeper down open by themselves when you come back to Settings.

## Leaving things out

BRO Backup skips junk by default: Windows and macOS thumbnails (`Thumbs.db`, `.DS_Store`), Synology system folders (`@eaDir`, `#recycle`, `#snapshot`), Office lock files (`~$...`), trash folders and temporary or half-downloaded files. Under **Settings → Leave out** you can switch that off, add your own patterns (one per line, e.g. `*.iso`) and skip files above a size. Changes apply from the next backup on.

## Databases

A database that is written to during a backup can come back broken. Two kinds are covered:

- **SQLite** (Vaultwarden, Home Assistant and many small apps). Under **Settings → Databases**, click **Look for databases** and tick the ones you want. Before every backup, BRO Backup makes a consistent copy with SQLite's online backup API, the same thing as `sqlite3 db ".backup file"`, which is [what Vaultwarden recommends](https://github.com/dani-garcia/vaultwarden/wiki/Backing-up-your-vault). Each copy is checked with `PRAGMA integrity_check` and sent along as the folder `@databases`. A failed dump is reported but never stops the backup.
- **Immich (PostgreSQL)**. Immich makes its own dumps every day in `UPLOAD_LOCATION/backups` ([Immich docs](https://docs.immich.app/administration/backup-and-restore)). Back up the Immich upload folder and those dumps go along. The self-check warns when the newest one is older than 48 hours.

Other PostgreSQL or MySQL databases: let the app or a scheduled task write a dump into a folder you back up. BRO Backup does not connect to other containers' databases itself.

## PCs and servers (UrBackup)

BRO Backup backs up what is on the NAS. For the computers in the house or the office, use [UrBackup](https://www.urbackup.org) (open source, AGPLv3, an app on TrueNAS): image and file backups of Windows, macOS and Linux machines to the NAS, with a USB stick for bare-metal restores, much like Synology's Active Backup for Business. BRO Backup then takes the UrBackup storage to your bros with everything else.

- **Found by itself**: every hour BRO Backup looks for UrBackup storage under `/nas` (three levels deep, folder names only). The overview and **Settings → Folders** show it, with **Include it** when it is not selected yet. You also get one notification about that.
- **Every computer watched**: the overview lists each computer with its last backup, the number of file and image backups and the backed-up volumes, read from UrBackup's folder and file names. When a computer has no backup for longer than the notification limit (72 hours by default), you get a notification, again every 72 hours while it lasts. Each computer has its own row in the self-check.
- **Safety score**: with UrBackup there, two parts count too: is its storage sent offsite, and does every computer have a recent backup. The score stays out of 100.
- **Efficient**: UrBackup stores unchanged files as hard links; restic stores their content once, and a restore brings the hard links and the `current` link back. `urbackup_tmp_files` (data still coming in) is always left out.

Tips:

- Put the UrBackup storage on its own dataset with daily snapshots, and let BRO Backup run after UrBackup's backup window: it then reads a consistent snapshot.
- Leave UrBackup's automatic database backup on (it is on by default and lands in the `urbackup` folder of the storage), so a new UrBackup server can take over the storage after a crash.
- UrBackup's own settings, its clients and its restores stay in the UrBackup web interface; BRO Backup never changes anything there.

**Putting the client on a Windows PC**: `install/urbackup-client.ps1` asks your UrBackup server for an installer made for that PC (its name and its own key inside) and runs it silently, as administrator:

```powershell
.\urbackup-client.ps1 -Server http://truenas.local:55414 -AllowHttp
```

The installer runs as administrator, and UrBackup cannot sign an installer its server makes per computer. Over plain http, anyone on your network who pretends to be the server could hand out his own program, so the script refuses http unless you add `-AllowHttp` (fine on a network you trust). Put the UrBackup web interface behind https to drop that switch.

Make a separate UrBackup web user for it with only the rights `status: some` and `add_client: all`, and turn on **Download client from update server** in UrBackup's general settings. From an RMM tool, pass the login in the `URBACKUP_USER` and `URBACKUP_PASSWORD` environment variables; `-DownloadOnly` only fetches the installer. This follows UrBackup's own example ([Download custom client installer via Python](https://urbackup.atlassian.net/wiki/spaces/US/pages/9568258/Download+custom+client+installer+via+Python)).

## Restore test

Once a month, after a successful backup, BRO Backup restores a few random files from each bro to a temporary folder. restic verifies them, and files that did not change since are compared with your originals byte for byte. A failed test turns the overview red, sends a notification and is repeated after the next backup. You can also run one any time: **Restore → Run a restore test**.

## Ransomware alarm

Ransomware often encrypts files days or weeks after it got in. The nightly backup then sends the encrypted files to your bros, and cleaning up old versions would slowly throw away the last good ones. So after every backup, BRO Backup compares each folder with its own past:

- **far more files new or changed than usual**: at least 100 files and a quarter of the folder, and at least five times what is normal for that folder;
- **far fewer files than in the previous backup**: at least 100 files and a quarter of the folder gone;
- **files that came back with an extra extension**, such as `photo.jpg` becoming `photo.jpg.locked` (at least 50);
- **ransom notes**, such as `HOW_TO_DECRYPT.txt` or `Restore-My-Files.txt`, in at least three folders.

The last two come from the list of changes between the previous and the new version (`restic diff`). The first backup of a folder is never judged.

When something is found:

- you get a notification with high priority, and a reminder every day while it lasts;
- the overview turns red with what was found and examples;
- **nothing is cleaned up at any bro**: every old version stays;
- under **Restore**, the suspicious versions are marked, and so is the last version before the alarm.

Backups keep running: they cost a bit of space, but they never remove anything while the alarm is on. Did you do it yourself, a big reorganisation for example? Click **This was me** on the overview. That needs your password, so whoever took over your NAS cannot simply switch it off. Cleaning up then starts again with the next backup.

It is a warning, not a virus scanner: ransomware that changes only a few files at a time, or a folder with fewer than 100 files, is not noticed. Keep the bro-backup folder on its own dataset with snapshots, and consider append-only.

## Integrity check and repair

Every week BRO Backup reads 2% of your backup at each bro to check it. **Restore → Run a full check** reads all of it. When either finds damaged data, the overview turns red and the Restore page offers **Repair**. That follows [restic's own procedure](https://restic.readthedocs.io/en/stable/077_troubleshooting.html): remove the damaged files at your bro, send the missing data again from your NAS, remove from old versions what can no longer be recovered, and check everything again. Damage like this usually comes from a disk or memory problem at your bro, so he should check his disks first. Repair needs your bro to have append-only switched off.

## Safety score

The overview opens with one number: how safe your data is, out of 100, with the two or three things that would raise it most. It follows the 3-2-1 rule (three copies, one of them far away): your NAS is one copy, every bro with a backup of the last two days another one.

| Points | For |
|---|---|
| 30 | A bro with a backup of the last two days |
| 15 | A second bro with one |
| 15 | A passed restore test this month at every such bro |
| 10 | No damage found in your backups |
| 10 | A recovery code |
| 5 | A key copy at a bro |
| 10 | Notifications (ntfy or email) |
| 5 | The ransomware alarm on, and not going off |

Without a recent copy at a bro the score stays at 20 or lower; with the ransomware alarm on, at 40 or lower. 90 or more is "Very safe", 70 "Safe", 40 "At risk". The score is also in the weekly report and in the self-check.

## Self-check

**Self-check** in the menu checks this NAS, the internet connection and every bro in one go, and says what to fix: is the data folder writable, how full is its disk, is `/nas` mounted read-only, are the selected folders there, can each folder be read from a ZFS snapshot, is the time zone set, are all parts running, is the recovery code set, are notifications set up, can the relay servers be reached, does every bro answer and how fast, did the last backup and restore test pass, and is data still coming in from the bros that back up to you. Nothing is changed. The result is also part of the diagnostics bundle.

## Notifications

BRO Backup notifies you when a backup or restore test fails, or when there was no successful backup for too long (72 hours by default). Use [ntfy](https://ntfy.sh) for push messages on your phone, email over SMTP, or both. **Settings → Send a test notification** checks that it arrives.

A failed backup is tried again every hour, but you hear about it once: again only when the error changes or a day has passed, and you get a "works again" when it succeeds. A restore first checks that it fits in the bro-backup folder, so it never fills the space your bros' backups need.

Once a week (Monday 09:00 by default) you also get a short report: per bro the last successful backup, the space used and the last restore test, and for every bro that backs up to you when his last data came in. When a bro that backs up to you sends nothing for longer than the notification limit, you hear that too: his NAS may be off.

### When the disk fills up

Every hour BRO Backup measures the disk under its data folder, where the backups of your bros are stored. On TrueNAS with a dataset quota, that is the quota, not the whole pool. From 90% used the overview warns and you get a notification. From 97% it is red: backups of your bros, and maybe your own, will soon fail. ZFS also gets slow when it is very full. You get one message each time it gets worse, and a reminder after 3 days if it stays that way.

You are also warned when you gave your bros more space than is free. Their quotas minus what they already use is more than the free space, so they can fill the disk before they reach their quota.

Your bros only see whether your disk is fine, filling up or almost full, never how big it is. When your bro's disk is almost full, your overview says so next to him and you get one notification, so you can let him know.

## Backup window

By default a backup runs until it is done. With **Settings → Stop at** you set a window, for example 01:00 to 07:00: scheduled backups only start inside it, and a backup still running when the window closes is stopped cleanly. The next night continues from where restic last saved its progress. restic saves it at least every 10 minutes, so each stop sends at most about 10 minutes of upload again. In the lab, a backup stopped after 13 minutes had to send only 532 of 1200 MB again the next time. **Now** on the overview ignores the window.

## Upload speed by time of day

**Settings → Limit upload** applies all day. Fill in **At night** too, for example 0 (no limit) between 22:00 and 07:00, and BRO Backup switches between the two. A backup that runs past the switch is stopped and resumed with the new limit right away. That costs at most about 10 minutes of upload, because restic saves its progress at least every 10 minutes.

## History

**History** next to a bro shows charts of the data sent per backup, the space used at your bro and how long each backup took, plus a table of every backup. It keeps about a year.

## Connection and speed test

Every bro on the overview shows how your NAS devices are connected:

- **direct**: straight over the internet, the fastest route;
- **local network**: both NAS devices on the same LAN, ideal for a first backup before your bro takes his NAS home;
- **via relay**: a direct connection did not work, traffic goes through a shared, rate-limited relay (still encrypted).

Click **Speed** next to a bro to measure upload and download through the same connection your backups use. Nothing is stored at your bro. The upload goes in parts of 8 MiB and is timed by your NAS, so it measures until your bro has really received it. The download stops after the agreed time, even when the bro keeps sending. When two bros test the same NAS at once, the second one is asked to try again in a minute; when you and your bro test each other at the same moment, both tests run but each measures about half. A bro on 0.10.11 cannot take the upload test; ask him to update. You also get an estimate of how long the first backup, a nightly backup and a full restore take. When the first backup would take more than two days, it suggests sending it on a disk.

## First backup on an external disk

A first backup of a few terabytes over a home upload can take days or weeks. Faster:

1. When pairing, tick **"Send my first backup to him on an external disk"**. Already paired but no backup yet? Click **Via disk**.
2. BRO Backup writes the first backup to a folder, encrypted as always. Backups over the internet wait meanwhile.
3. Take the disk to your bro. He copies the folder into `import` inside his bro-backup folder, and clicks **Import**.
4. Within 10 minutes your NAS notices and continues over the internet. From then on only changes are sent.

To write straight to a USB disk, add a line under `volumes`:

- Synology: `- /volumeUSB1/usbshare:/seed`
- TrueNAS: create the USB disk as its own pool first (**this erases the disk**), then `- /mnt/YOUR-USB-POOL:/seed`

Whoever finds the disk only sees encrypted blocks.

## When your NAS crashes

1. Install BRO Backup again on your repaired or new NAS.
2. Ask your bro to click **Help code** next to your name in his BRO Backup.
3. In the wizard, open "My NAS crashed or was replaced" and enter the help code and your recovery code.
4. Your bros, settings and folders come back. **Backups are paused**, so an empty new NAS cannot push out your good versions.
5. Restore your files, then click **Resume backups** for each bro.

Lost your recovery code? Create a new one in Settings while your NAS still works. Settings also offers a downloadable emergency key file.

### Picking up your backup on a disk

Getting terabytes back over the internet takes days: your bro's upload speed is the limit. Your bro lives nearby, so the fastest way is a disk.

1. **Your bro** connects a USB disk (mounted at `/seed`, see "First backup on an external disk") and clicks **Copy to disk** next to your name. Your backup and your key copy go to a folder `backup-of-<you>-<date>` on the disk, still encrypted: he never needs or sees a key. Without an external disk the folder lands in his bro-backup folder.
2. **You** take the disk home. Only your **recovery code** is needed, no help code and no internet:
   - **On a new NAS**: connect the disk (mounted at `/seed`, or copy the folder into the `import` folder of bro-backup). In the wizard, open "My bro copied my backup to a disk for me", pick the disk and enter your recovery code. Your bros come back, paused, and **Restore** reads from the disk.
   - **On a NAS that still runs** (only the data was lost): connect the disk, open **Restore** next to your bro and click **Restore from the disk**.
   - **On any PC with Docker Desktop**, without a NAS: `.\install\restore-from-disk.ps1 -Disk E:\`. It asks for your recovery code and puts the newest version of every folder in `BRO-restore` in your user folder. The disk is mounted read-only and the container gets no network. On Linux or macOS: `docker run --rm -it --network none -v /media/disk:/seed:ro -v ~/restored:/out ghcr.io/j-kest/bro-backup:1 python main.py restore-from-disk`.
3. Afterwards, backups continue over the internet: only what changed since travels.

The copy is made in a safe order (versions before data), so every version on the disk is complete, even if your NAS was still backing up while it was copied.

## What's inside the container

| Component | Role |
|---|---|
| App (Python/Flask) | Wizard, dashboard, schedule, pairing, seed, import, recovery, notifications. Manages the parts below. |
| restic 0.18.1 | Encrypts and deduplicates your data before it leaves |
| rest-server 0.14.0 | Receives your bros' backups, each in its own private repository |
| dumbpipe 0.40.1 (iroh) | Connection by key, with NAT hole punching and a relay as fallback |

Binaries are pinned by version and SHA256 in the Dockerfile.

## Security

- **Data**: encrypted client-side by restic. Your bro only sees encrypted blocks.
- **Transport**: QUIC with endpoint keys (iroh). When the connection falls back to a relay, it only forwards encrypted packets.
- **Pairing codes**: single use. The password inside the code is rotated after pairing, and it opens nothing until the bro has used the code: no rest-server login and no pairing API calls.
- **Key copies at your bros**: AES-256-GCM with a key derived from your recovery code (scrypt, 160 bits of entropy). Fetching one requires a help code your bro creates.
- **Web UI**: password (scrypt), optional two-step login with an authenticator app (TOTP), CSRF token, LAN only (port 8484). The session cookie only carries a random id: logins live inside the app, so logging out ends a login for real, changing the password or turning on two-step login logs out your other devices, and a restart of the app logs everybody out. After 5 wrong logins from one address it is blocked for 15 minutes and you get a notification. You are logged out after 60 minutes without activity and always after 12 hours. Security headers stop the page from being framed by other sites. The pairing API and rest-server only listen on 127.0.0.1 inside the container.
- **The first setup**: until it is done, anyone who can reach port 8484 could choose the password. The TrueNAS installer therefore puts a code in the link it shows at the end, and only that link opens the setup. On Synology or another Docker host, finish the setup right after installing, or set `BRO_SETUP_CODE` yourself and open `/setup?code=...`.
- **No https on the web page**: the password goes over your LAN as plain text, like on most NAS apps. Keep port 8484 on a network you trust and never forward it to the internet; for https, put it behind a reverse proxy.
- **The container**: runs with only the capabilities it needs (reading every file, restoring owners and times) and `no-new-privileges`. The base image is pinned by digest, Python packages by exact version, the binaries by SHA256, and GitHub Actions by commit.
- **Keys on the NAS**: the bro-backup folder holds the passwords of your backups and the login secrets (`config/state.json`, readable only by the app). Do not share that dataset over SMB or NFS; whoever can read it can read your backups.
- **Never backed up**: `/nas` is read-only. The self-check and an hourly check warn when a mount below `/nas` is writable after all (on TrueNAS a dataset that is mounted after the app started can arrive without the read-only flag); restart the app to fix it. Any folder containing a `.bro-backup-data` file (any BRO Backup data folder, also from another or older install) and any seed folder is excluded.
- **Deleted by a bro**: kept for 7 days outside the reach of his login, so a stolen login cannot wipe a backup at once (see above). rest-server never changes a file in place, so a kept file cannot be damaged either.
- **Quota**: checked on your side too, not only by the bro who sends. A bro more than 5% over the space you gave him loses his login until you give him more; rest-server also refuses to write beyond the sum of all quotas + 10%.
- **What comes from a bro is checked**: names are plain text of at most 40 characters, addresses and logins must look exactly like what BRO Backup itself sends, and a new address must carry the same identity as at pairing. A seed disk may only hold a plain restic repository: links or unknown files refuse the import.
- **Linking pairs made before v0.10**: which of your logins belongs to which bro is only accepted with proof. Your NAS asks the bro behind the address he gave to show, with an HMAC, that he holds the link key of that login. The proof is tied to his endpoint id, so another bro cannot pass it on.
- **Space requests**: only a bro's own login can ask for more space for himself; the amount and the note are checked, and the note is plain text.
- **Copy to disk**: the disk holds only what your bro already stores for you: your encrypted backup and your key copy, sealed with your recovery code (AES-256-GCM, so a changed file is refused). Without that code the disk is useless. Restoring on a PC runs without network, with the disk read-only.
- **Ransomware alarm**: when a backup looks like an attack, old versions are no longer cleaned up anywhere until you clear the alarm, and clearing it needs your password.
- **Disk status for bros**: the status call of a bro only carries ok, filling up or almost full about your disk, never sizes.
- **Update check**: one GET request a day to `api.github.com`, without any data about you. Only release numbers like `0.10.2` are accepted and the link always points to the releases of this repository. Can be turned off.
- **Calls to a bro**: redirects are never followed, an answer may be at most 1 MiB and must be JSON, and only known fields of the right type are kept. A relay server in a bro's address is only used when it is one of n0's relays (any server under `relay.n0.iroh.link`, written as a plain address: a URL with a backslash, a login or a path is refused because parsers read those differently), and direct addresses on this NAS itself, link-local, multicast or below port 1024 are dropped, so a bro cannot point your NAS at a server of his choice or at a service on your network. Addresses on your LAN stay: bros on the same network need them. Folder names are passed to restic after `--`, so a folder called `--something` is never an option.
- **Settings that matter for an attacker**: changing notifications, email, the no-backup alert, the weekly report, the restore test, retention, append-only or the ransomware alarm needs your current password, and so does leaving something out of the backups (a folder unticked, a pattern added, a lower size limit). Wrong passwords count toward the login lockout. The no-backup alert waits at most 14 days. A stored password or secret is removed when its server changes and no new one is given, so it never goes to another server.
- **What cannot be undone needs your password**, plus a fresh code from your app when two-step login is on, and sends a notification: a new recovery code (it replaces the key copies at your bros), sending the first backup via a disk (it stops backups over the internet to that bro), stopping with a bro, deleting a bro's backups on your NAS, replacing them with a seed, and the emergency keys file. A walk-up at an unlocked browser or a stolen session cannot do these.
- **Reviewed**: v0.10 had an independent security review. Its findings (among them a script injection through a bro's name and links on a seed disk) are fixed in v0.10.1, each with a test in `tests/unit/test_security.py`. A second independent audit of v0.10.10 is handled in v0.10.11, and its re-check (R1 to R8) in v0.10.12, with a test per finding in `tests/unit/test_audit.py`.
- **Recommended on TrueNAS**: the bro-backup folder as its own dataset with a quota and daily snapshots (the installer does this). That protects your bros against ransomware.

### Locked out

Lost the phone with your authenticator app, or forgot the password? Open a shell in the BRO Backup container (TrueNAS: Apps, BRO Backup, Shell; Synology: Container Manager, the container, Terminal) and run:

```sh
python main.py reset-two-step     # switches two-step login off
python main.py reset-password     # prints a temporary password
```

Only someone with admin access to the NAS itself can do this.

## Settings

| Setting | Default | What it does |
|---|---|---|
| Folders | chosen in the wizard | Which folders go to your bros |
| Back up every night at | 02:00 | Hour of the daily backup |
| Keep old versions | Standard: 7 days, 4 weeks, 12 months | Short or Long also available |
| Limit upload | 0 (no limit) | In Mbit/s |
| At night | same as the day | Another limit between the night hours (22:00 to 07:00 by default) |
| Databases | none | SQLite databases to dump before every backup |
| Stop at (backup window) | no window | Scheduled backups only run between the backup hour and this hour |
| ntfy URL and token | empty | Push notifications when a backup fails or falls behind |
| Email (SMTP) | empty | The same notifications by email. STARTTLS, SSL/TLS or none |
| Email via Microsoft 365 | off | The same notifications through the Microsoft Graph API, see "Email through Microsoft 365" |
| Notify after | 72 hours | Hours without a successful backup before you get a notification |
| Default space per bro | 500 GiB | Suggested when creating a code |
| Keep what a bro deletes | 7 days | Deleted data of a bro stays this long and can be put back |
| Bros may send to me at most | no limit | Speed limit each bro keeps to, by day and at night |
| Append-only | off | Bros cannot delete anything here, not even old versions |
| Read from ZFS snapshots | on, max 26 h old | Consistent backups, see above |
| Monthly restore test | on | See above |
| Skip junk | on | Thumbnails, trash, lock and temporary files |
| Also skip | empty | Your own patterns, one per line |
| Skip files larger than | 0 (no limit) | In GB |
| Weekly report | Monday 09:00 | Or another day, or off |
| Notify about silent bros | on | When a bro backing up to you sends nothing for the notification limit |
| Check for new versions | on | Once a day, see Updating |
| Ransomware alarm | on | Warn and keep all old versions when a backup looks like files were encrypted or deleted |

## Troubleshooting

| What you see | Likely cause | What to do |
|---|---|---|
| The page on port 8484 does not open | The app is not running, or the port is taken | Check the app is Running. Change `"8484:8484"` to e.g. `"8490:8484"` |
| "Setting up the connection" stays | No internet, or a firewall blocks outgoing UDP | Check the logs. Allow outgoing UDP |
| Backups are very slow | Traffic goes through a relay instead of directly | Click **Speed** next to the bro. If it says "via relay", add `"7841:7841/udp"` and `"7842:7842/udp"` under `ports` on both NAS devices |
| "via relay" between two NAS devices on the same network | The app only knows its Docker address | Fill in the NAS address under Settings → Local network on both, with UDP 7841 and 7842 published |
| "No folders of your NAS are visible" | The `/nas` volume line is wrong | Check the path |
| "Login refused by your bro" | His NAS was recovered, or he removed your login by hand | Ask him for a new code |
| "Stopped by ..." | Your bro no longer stores your backups | Remove him with × and pair with someone else |
| A bro is "not reachable" after a new internet connection | His address changed while the relays were not reachable either | Wait for the next check-in (a few hours), or ask him to open BRO Backup: his NAS sends the new address within a minute of starting |
| "Not started: your folders hold ..." | Before a first backup (or after you added folders) BRO Backup measures your folders, and they do not fit in the space your bro gave you | Ask him for more space with **ask for more**, choose fewer folders, or send the first backup on a disk |
| "Not started: this backup would add ..." | Space at your bro is getting short, and restic's dry run shows that tonight's new data does not fit. Nothing was sent | Ask him for more space, leave large new files out, or keep fewer old versions |
| "Quota at ... reached" | The space your bro gave you is used up | Ask your bro for more: he changes it next to your name under "Bros backing up to me". Or select fewer folders |
| A folder is read "live" | No recent ZFS snapshot of its dataset, or the folder holds child datasets | Add a daily periodic snapshot task for that dataset in TrueNAS; for child datasets, tick those instead of the parent |
| Restore test: "Data at your bro is damaged" | Disk or memory problems at your bro | Ask him to check his pool (scrub) and disks. Then **Restore → Run a full check**, and **Repair** if it finds damage |
| Repair: "append-only" | Your bro does not allow deleting | Ask him to switch append-only off for the repair |
| "Cleanup failed: ... repository is already locked" (up to 0.10.12) | A restic that was stopped hard (the app restarted during a backup, or the bro was unreachable when it finished) left its lock at your bro | From 0.10.13 such locks are removed by themselves before cleaning up. The backup itself was fine |
| "Cleanup postponed: your bro's copy is in use" | Another restic is still using your backup at the bro right now | Nothing: it is tried again at the next backup. If it keeps coming back for days, check that the same backup is not running from a second NAS (a restored copy that is still online) |
| Locked out of the web page | Lost phone or password | See "Locked out" under Security |
| "Database dump ... failed" | The file moved, or it is not SQLite | Look for databases again in Settings. The rest of the backup ran normally |
| "There is no key copy on this disk" | Your key copy had not reached your bro yet (no recovery code set, or the bro was offline) | Recover with a help code from your bro and your recovery code, then click **Restore from the disk** under Restore |
| "<computer> has not been backed up for N days" | The computer was off, or its UrBackup client stopped or lost the server | Check the computer and the UrBackup web interface |
| "UrBackup storage is not sent offsite" | The UrBackup folder is not selected | **Include it** on the overview or in **Settings → Folders** |
| "Possible ransomware" | A backup looked like many files were encrypted, renamed or deleted | Check your files. Yours were attacked: restore the version marked "last before the alarm". You did it yourself: **This was me** on the overview |
| "The disk is filling up" or "almost full" | The dataset with the bro-backup folder is running out of space | Free up space, enlarge the dataset or its quota, or lower the space of a bro under **Bros backing up to me** |
| Not sure what is wrong | | Open **Self-check**: it lists every problem with what to do |
| Anything else | | Open **Logs** and click **Download diagnostics**. The bundle holds settings, status and logs, without passwords, keys or files. Send it to whoever helps you |
| "The recovery code is not correct" | A typo | Recovery codes never contain I, O, 0 or 1 |

## Storing for many bros (Pro bro)

Not everybody has a friend with a NAS. An IT company, a club or one handy person can be the bro for many people: one BRO Backup that stores backups for customers without a friend, or as a second copy next to their friend. Everything above works the same; for many bros there is also:

- **Search** in the list of bros that back up to you, from six bros on, with the total stored.
- **A reference** per bro (your customer name or number), under **References** below the list.
- **Usage per month**: the highest usage of every bro in each month, kept two years, as a CSV export (**Usage per month (CSV)** below the list). Separated by `;`, so it opens directly in Excel with Belgian settings. Names that look like a formula are neutralised.
- **Space requests**: a bro clicks **ask for more** under the space at his bro, with an optional note. You get a notification and **Grant** or **Decline** it on the overview. He sees the new space at his next backup.

Suggestions for running it as a service:

- Run it on its own server or NAS, with the bro-backup folder on its own dataset with a quota and snapshots, and consider **append-only** so no customer (or attacker with his NAS) can delete his old versions.
- Watch the disk warning and **Space promised to bros** in the self-check: the sum of all quotas should fit on the disk.
- Customers keep their own keys: you only ever store encrypted blocks and a key copy sealed with their recovery code. The European data protection board names exactly this, strong encryption with the key only at the customer, as a sufficient measure for backups in its recommendations on transfers ("use case 3").
- **Storing backups for a business is still processing personal data on its behalf.** Under article 28 of the GDPR that needs a written processor agreement (verwerkersovereenkomst): what is stored, for how long, security, subprocessors, deletion at the end. This is not legal advice: have your agreement checked.

## Updating

Once a day BRO Backup asks GitHub for the latest release. When there is a newer version, the overview shows it, with a link to what changed, and you get one notification. Only a plain request to the GitHub API goes out: nothing about your NAS, your bros or your backups. Turn it off under **Settings → Updates**. Updating itself is always up to you.

The image tag in the compose file is the major version (`1`), so every 1.x release (1.1.1, 1.2, ...) arrives under the same tag and you never edit the compose file for it. A 2.0 would need a new tag on purpose, because it may change how things work. Fetching the new image is still a step:

- **TrueNAS**: in **System → Shell**:
  ```sh
  curl -fsSL https://raw.githubusercontent.com/j-kest/bro-backup/main/install/truenas-install.py -o /tmp/bro-install.py && sudo python3 /tmp/bro-install.py --update
  ```
  It fetches the newest image and restarts the app, without questions, and says which version you went from and to. TrueNAS's own "Update available" for custom apps is not reliable, and a plain `docker pull` does not restart the app on the new image.
- **Any Docker host**: `docker compose pull && docker compose up -d` in the folder of the compose file.
- **Synology**: in Container Manager, download the image again under **Image**, then restart the project. Or let the NAS do it: **Control Panel → Task Scheduler → Create → Scheduled Task → User-defined script**, user `root`, weekly, with `cd /volume1/docker/bro-backup-app && docker compose pull && docker compose up -d` (change the folder if your project is elsewhere). Compose only restarts the app when the image really changed. (Not tried on a real Synology.)

Coming from an older tag (`0.10`, `1.0` or `1.1`), change it to `1` once. Bros on different versions keep working together: 0.10.2 backs up to and from bros on 0.9.0, and pairs made on 0.9.0 get the new features once both sides have updated (see Tested). Update to 0.10.2 rather than 0.10.0 or 0.10.1: only 0.10.2 links pairs made on 0.9.

The overview shows which version each bro runs, next to his name: in orange when it is older than yours. It is refreshed within minutes after either of you updates, and before every backup. The self-check lists the bros that should update.

After an update everyone has to log in again.

## Dependency: n0's relays

dumbpipe uses the public relays of n0, the company behind iroh. n0 calls them "suitable for development and testing", rate-limited and without uptime guarantees ([iroh docs](https://docs.iroh.computer/concepts/relays)). Most connections do not need them: according to the same page, about 9 in 10 network situations allow a direct connection, and the relay is only a fallback. Your data stays encrypted end to end, so the risk is availability and speed, not privacy.

**Your own relay** is possible with iroh (the open source `iroh-relay` server with a domain name and Let's Encrypt, see [self-hosting](https://docs.iroh.computer/iroh-services/relays/self-hosted.md)), but dumbpipe 0.40.1 cannot use it yet: it has no option to choose a relay. Two pull requests that add one are open upstream ([#105](https://github.com/n0-computer/dumbpipe/pull/105), [#121](https://github.com/n0-computer/dumbpipe/pull/121)). When dumbpipe gets that option, BRO Backup will get a relay setting.

Until then, the surest way around the relays is a direct connection: forward UDP ports 7841 and 7842 on the router to the NAS and add `"7841:7841/udp"` and `"7842:7842/udp"` under `ports`. **Speed** next to a bro shows whether the connection is direct or via relay.

## Tested

Every push runs the unit tests (`tests/unit`) and the lab test (`tests/lab/e2e.py`: pairing, an address change without relays, unpairing, pairing again) in GitHub Actions, on the image built from the real Dockerfile. An image is only published when they pass.

**Upgrade test** (`tests/lab/upgrade.py`): two bros pair and back up on v0.9.0, then update one at a time. Checked: logging in again, the state keeps the bro and his login, a new bro and an old one back up to each other both ways, snapshots from v0.9 stay listed next to the new ones, both sides say hello within a minute once the second one has updated, the two directions of the old pairing get linked (proven with the link key, not by name), an address change, and stopping a bro (the other side is told). Run it with `python3 tests/lab/upgrade.py --old <old image> --new <new image>` on a lab started with the old image.

v0.10 was tested in Docker: the lab in [`lab`](lab/) ran two containers side by side with the real restic, rest-server and dumbpipe binaries, driven by the lab script under PowerShell 7. Tested there: pairing in both directions, an address change without relays (the other bro received the new address and backups continued), unpairing in both directions (messages, tombstone, scheduled deletion, leftover data), backups read from (simulated) ZFS snapshots, leaving out junk, browsing, searching and restoring selected files, the restore test, a full integrity check and repairing deliberately damaged data, email notifications, the weekly report, the silent-bro alert, two-step login (including replayed codes being refused), the login lockout and session expiry, the emergency reset, SQLite dumps of a database being written to (consistent, integrity check passed), Immich dump detection, day/night upload limits (restic restarted with the new limit at the switch), the history charts, the speed test, the self-check, the backup window, seeding via a shared "disk" folder, crash recovery with recovery code and help code, and a diagnostics bundle checked for leaked secrets. The TrueNAS installer was tested against a simulated TrueNAS API.

**On real NAS devices** (1.0 and 1.1): the TrueNAS installer and updates on TrueNAS SCALE 25.10, installing and updating on a Synology with Container Manager, two NAS devices backing up to each other over the internet and on the same LAN (direct connection), reading from real ZFS snapshots, restoring files.

**Not tested yet:** connections through n0's relays for a long time, seeds of several terabytes, more than two bros at once on real hardware, keeping deleted files (hard links) on a real Synology volume.

## License

BRO Backup is free software under the **GNU Affero General Public License v3.0 or later** (`AGPL-3.0-or-later`), see `LICENSE`. Copyright (C) 2026 the BRO Backup authors.

- You may use, change and share it, also commercially.
- If you distribute a modified version, or let others use it over a network, you must offer them its source code under the same license. Set `SOURCE_URL` to your own repository; the link is shown at the bottom of every page.
- Bundled third-party software keeps its own license, see `app/THIRD_PARTY_NOTICES.md`.
- Contributing: see `CONTRIBUTING.md` (DCO sign-off). Security issues: see `SECURITY.md`.

## For maintainers

1. Push to GitHub. If the repository is not `j-kest/bro-backup`, update it in `install-*.yaml`, `install/truenas-install.py`, `install/restore-from-disk.ps1`, `docs/index.html`, `UPDATE_REPO` in `app/bro/updates.py` and `SOURCE_URL` in `app/bro/core.py`.
2. Publish a GitHub release with a new tag such as `v1.2.0` (the update check reads the latest release; `1.2.0` without the v works too). The workflow runs the tests, then builds `ghcr.io/<org>/bro-backup:1.1` for amd64 and arm64.
3. Make the package public (Packages → bro-backup → Package settings).
   The workflows pin every action by commit SHA (Dependabot proposes updates), and the Dockerfile pins restic, rest-server and dumbpipe by SHA256.
4. Enable GitHub Pages from the `docs` folder for the setup page.

True one-click install in the TrueNAS UI is only possible through the official community catalog in `truenas/apps`: first a feature request on the TrueNAS forum, then a pull request once approved.
