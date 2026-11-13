# version : 1.1.0
# created by : JK and CF
# last edited : 12/11/2026
# Name : bro-backup (bro/selfcheck.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Self-check, logs, diagnostics bundle and emergency key export."""

import datetime
import io
import json
import logging
import os
import socket
import ssl
import threading
import time
import zipfile

from flask import Response, flash, jsonify, redirect, render_template, request, url_for

from . import alarm, backup, dumps, kept, lan, nas, peers, procs, recovery, safety, scheduler, space, updates, urbackup, web
from .core import (
    CONFIG_DIR,
    backups_paused,
    DATA_DIR,
    ESCROW_DIR,
    GIB,
    IROH_DNS,
    IROH_RELAYS,
    NAS_DIR,
    PAUSED_MODES,
    RECEIVE_DIR,
    UI_PORT,
    VERSION,
    activity,
    conn_paths,
    human_bytes,
    iso,
    load_state,
    local_time,
    log,
    log_ring,
    my_tickets,
    notification_channels,
    notify,
    now,
    parse,
    receive_stats,
    recv_activity,
    redact,
    redact_text,
    settings,
    slug,
)

# ---------------------------------------------------------------- self-check
selfcheck_state = {"running": False, "result": None}


def _mount_options(path):
    """Mount options of the mount that holds this path inside the container, or None."""
    best, opts = "", None
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                parts = line.split()
                mnt = parts[4]
                if (path == mnt or path.startswith(mnt.rstrip("/") + "/")) and len(mnt) > len(best):
                    best, opts = mnt, parts[5].split(",")
    except OSError:
        return None
    return opts


def _reach(host, port=443, timeout=6):
    """TLS handshake with host:port. Returns (ok, detail)."""
    t0 = time.time()
    try:
        ip = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][4][0]
    except OSError as e:
        return False, f"name not found ({e.strerror or e})"
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host):
                return True, f"{int((time.time() - t0) * 1000)} ms"
    except (OSError, ssl.SSLError) as e:
        return False, str(e) or e.__class__.__name__


def versions_row(st):
    """(area, name, status, text, fix) about the versions our bros run, or None without bros."""
    bros = {}
    for d in st["destinations"]:
        if d.get("mode") != "revoked":
            bros[d["name"]] = d.get("peer_version")
    for r in st["receivers"].values():
        if r.get("accepted"):
            bros.setdefault(r.get("bro_name") or r["name"], r.get("peer_version"))
    if not bros:
        return None
    mine = updates.parse_version(VERSION)
    older = sorted(f"{n} ({v})" for n, v in bros.items() if updates.parse_version(v or "") and mine
                   and updates.parse_version(v) < mine)
    unknown = sorted(n for n, v in bros.items() if not updates.parse_version(v or ""))
    if older:
        return ("Your bros", "Versions", "warn", f"Older than yours ({VERSION}): " + ", ".join(older),
                "Ask them to update. The speed test and the speed limit for bros need the same version on both sides.")
    return ("Your bros", "Versions", "ok", f"All on {VERSION} or newer" + (
        f"; not known yet for {', '.join(unknown)}" if unknown else ""), None)


def selfcheck_checks():
    """Every check is {"area", "name", "status": ok|warn|err|info, "text", "fix"}."""
    out = []

    def add(area, name, status, text, fix=None):
        out.append({"area": area, "name": name, "status": status, "text": text, "fix": fix})

    scheduler.refresh_receive_stats()
    st = load_state()
    s = st["settings"]
    # --- this NAS
    try:
        test = os.path.join(CONFIG_DIR, ".write-test")
        with open(test, "w") as f:
            f.write("ok")
        os.remove(test)
        free = nas.free_space(DATA_DIR)
        add("This NAS", "Data folder", "ok", f"Writable, {human_bytes(free)} free")
    except OSError as e:
        add("This NAS", "Data folder", "err", f"Not writable: {e.strerror}",
            "Check that the bro-backup folder is mounted at /data and is writable.")
    total_quota = sum(int(r.get("quota_gib") or 0) for r in st["receivers"].values())
    if total_quota:
        free = nas.free_space(RECEIVE_DIR) or 0
        used = sum((receive_stats.get(u) or {}).get("usage") or 0 for u in st["receivers"])
        need = total_quota * GIB - used
        if need > free:
            add("This NAS", "Space for your bros", "warn",
                f"You promised {total_quota} GiB, {human_bytes(used)} is used and only {human_bytes(free)} is free",
                "Lower a quota on the Overview page or free up space.")
        else:
            add("This NAS", "Space for your bros", "ok", f"{total_quota} GiB promised, enough free space")
    row = versions_row(st)
    if row:
        add(*row)
    if st["receivers"]:
        keep = kept.days(s)
        if not keep:
            add("This NAS", "Deleted backups of bros", "warn", "Not kept: what a bro deletes is gone right away",
                "Set a number of days under Settings, Space for bros. It protects your bros when someone else gets hold of their NAS.")
        elif kept.unsupported:
            add("This NAS", "Deleted backups of bros", "err", f"Cannot be kept: {kept.unsupported[0]}",
                "The whole bro-backup folder (/data) must be one file system, so a deleted file can keep a second name.")
        else:
            add("This NAS", "Deleted backups of bros", "ok", f"Kept for {keep} days" + (
                f", {human_bytes(kept.total_bytes())} waiting now" if kept.total_bytes() else ""))
    opts = _mount_options(os.path.realpath(NAS_DIR))
    if not os.path.isdir(NAS_DIR):
        add("This NAS", "Your data (/nas)", "err", "Not mounted", "Mount your pool or volume at /nas, read-only.")
    else:
        try:
            n = len([e for e in os.scandir(NAS_DIR) if e.is_dir()])
            rw = nas.writable_mounts()
            if rw:
                add("This NAS", "Your data (/nas)", "err",
                    f"{n} folders visible, but writable for the app: " + ", ".join(os.path.relpath(m, NAS_DIR) for m in rw[:4]),
                    "BRO Backup never writes there. Restart the app: a dataset made after it started is not "
                    "read-only for it until then. Still writable after a restart: add :ro to the volume.")
            elif opts is not None and "ro" not in opts:
                add("This NAS", "Your data (/nas)", "warn", f"{n} folders visible, but mounted read-write",
                    "Add :ro to the /nas volume. BRO Backup never needs to write there.")
            else:
                add("This NAS", "Your data (/nas)", "ok", f"{n} folders visible, every mount read-only")
        except OSError as e:
            add("This NAS", "Your data (/nas)", "err", f"Not readable: {e.strerror}")
    plan = backup.backup_plan()
    if not s["sources"]:
        add("This NAS", "Folders to back up", "warn", "None selected yet", "Choose folders in Settings.")
    else:
        missing = [p for p in s["sources"] if not os.path.isdir(p)]
        if missing:
            add("This NAS", "Folders to back up", "err",
                "Gone or not mounted: " + ", ".join(os.path.relpath(m, NAS_DIR) for m in missing),
                "Check the mounts, or remove these folders in Settings.")
        else:
            add("This NAS", "Folders to back up", "ok", f"{len(plan)} folder(s), all present")
    for i in plan:
        if i["origin"] == "dump":
            add("This NAS", f"Read {i['key']}", "ok", "Database dumps, made just before each backup")
        elif i["origin"].startswith("zfs:"):
            add("This NAS", f"Read {i['key']}", "ok", f"From ZFS snapshot {i['origin'][4:]}")
        elif not s["use_zfs_snapshots"]:
            add("This NAS", f"Read {i['key']}", "info", "Live (reading from snapshots is off)")
        else:
            add("This NAS", f"Read {i['key']}", "warn", f"Live: {i['note'] or 'not on a ZFS dataset'}",
                "Create a daily periodic snapshot task in TrueNAS for this dataset. "
                "On Synology or plain Docker this is normal.")
    for path, r in (st.get("dump_results") or {}).items():
        if path not in s.get("sqlite_dbs", []):
            continue
        name = os.path.relpath(path, NAS_DIR)
        if r.get("ok"):
            add("This NAS", f"Database {name}", "ok", f"Dumped {local_time(r.get('at'))} ({human_bytes(r.get('size'))}, {r.get('method')})")
        else:
            add("This NAS", f"Database {name}", "err", f"Last dump failed: {r.get('error')}",
                "Check that the file still exists and is a SQLite database. The rest of the backup still runs.")
    for x in dumps.immich_status((st.get("db_scan") or {}).get("immich") or []):
        where = os.path.relpath(x["folder"], NAS_DIR)
        if x["ok"]:
            add("This NAS", "Immich database dumps", "ok", f"{x['count']} in {where}, newest {x['age_h']:.0f} h old")
        else:
            add("This NAS", "Immich database dumps", "warn",
                f"Newest dump in {where} is {x['age_h']:.0f} h old" if x["age_h"] is not None else f"No dumps in {where}",
                "In Immich: Administration, Settings, Backup settings: check that database dumps are switched on.")
    tz = os.environ.get("TZ") or "UTC"
    if tz in ("UTC", "Etc/UTC"):
        add("This NAS", "Time zone", "warn", "UTC: the nightly backup runs at UTC time",
            "Set TZ in the compose file, for example TZ: Europe/Brussels.")
    else:
        add("This NAS", "Time zone", "ok", f"{tz}, now {datetime.datetime.now().strftime('%H:%M')}")
    for name, v in web.tool_versions().items():
        add("This NAS", name, "err" if v.startswith("unavailable") else "ok", v)
    for key, label in (("rest-server", "Receiving backups"), ("listen-data", "Data listener"),
                       ("listen-pair", "Pairing listener")):
        pr = procs.procs.get(key)
        if pr and pr.alive():
            add("This NAS", label, "ok", f"Running ({pr.fails} restarts)" if pr.fails else "Running")
        else:
            add("This NAS", label, "err", "Not running", "See the Logs page for its last output.")
    if my_tickets.get("data"):
        a = peers.ticket_addrs(my_tickets["data"])
        lp = procs.procs.get("listen-data")
        since = f", address from {local_time(iso(datetime.datetime.fromtimestamp(lp.started, datetime.timezone.utc)))}" \
            if lp and lp.started else ""
        add("This NAS", "Own address", "ok" if a["relays"] else ("warn" if a["direct"] else "err"),
            f"{len(a['relays'])} relay(s), {len(a['direct'])} direct address(es){since}",
            None if a["relays"] else "No relay in your address: bros can only reach you via the addresses listed. "
            "See Internet below.")
        lan_ips = lan.configured(s)
        add("This NAS", "Addresses on your network", "ok" if lan_ips else "info",
            ", ".join(lan_ips) + " (UDP 7841 and 7842)" if lan_ips else "None set",
            None if lan_ips else "Bros on the same network or on VLANs that reach each other connect via a relay. "
            "Fill in this NAS's address under Settings, Local network, and publish UDP 7841 and 7842 in the app.")
    if s.get("mail_method") == "m365":
        exp = s.get("m365_secret_expires")
        try:
            days = (datetime.date.fromisoformat(exp) - datetime.date.today()).days if exp else None
        except ValueError:
            days = None
        add("This NAS", "Email via Microsoft 365", "warn" if days is not None and days <= 30 else "ok",
            f"From {s.get('m365_sender') or '?'}" + (f", client secret valid until {exp}" if exp else ""),
            "Make a new client secret in Entra ID and paste it under Settings, Email." if days is not None and days <= 30
            else None)
    pz = backups_paused(st)
    if pz:
        add("This NAS", "Backups", "warn", "Paused " + (f"until {local_time(pz['until'])}" if pz.get("until")
                                                         else "until you resume them"),
            "Resume them at the top of the overview.")
    rc = st["recovery"]
    if rc.get("key"):
        add("This NAS", "Recovery code", "ok", f"Set on {local_time(rc.get('created'))}")
    else:
        add("This NAS", "Recovery code", "err", "Not set", "Create one under Overview, recovery code.")
    ch = notification_channels(s)
    add("This NAS", "Notifications", "ok" if ch else "warn",
        ", ".join(ch) if ch else "None: you will not hear about failed backups",
        None if ch else "Set up ntfy or email in Settings.")
    for x in urbackup.status(st):
        add("This NAS", f"UrBackup {x['rel']}", "ok" if x["included"] else "warn",
            f"{len(x['clients'])} computer(s), " + ("sent offsite" if x["included"] else "NOT sent offsite"),
            None if x["included"] else "Include the folder in Settings, Folders.")
        for c in x["clients"]:
            add("This NAS", f"Computer {c['name']}", "ok" if c["ok"] else "warn",
                f"last backup {local_time(c['last'])}" + (f", images of {', '.join(c['volumes'])}" if c["volumes"] else ""),
                None if c["ok"] else "Is the computer on, and the UrBackup client running? See the UrBackup web interface.")
    sf = safety.compute()
    add("This NAS", "Safety score", sf["level"], f"{sf['score']}/100 ({sf['label']})",
        "; ".join(i["fix"] for i in sf["todo"][:3]) or None)
    a = alarm.active()
    if a:
        add("This NAS", "Ransomware alarm", "err", f"On since {local_time(a['at'])}: {a['reasons'][0]}",
            "Check your files. Nothing is cleaned up at your bros until you clear the alarm on the overview.")
    elif not s.get("ransomware_watch", True):
        add("This NAS", "Ransomware alarm", "warn", "Off", "Turn it on in Settings: it costs nothing.")
    else:
        add("This NAS", "Ransomware alarm", "ok", "Watching every backup")
    m = space.measure()
    if m:
        hint = {"err": "Free up space, enlarge the dataset or its quota, or give bros less space.",
                "warn": "Keep an eye on it: ZFS slows down when it gets very full."}.get(m["level"])
        add("This NAS", "Free space", m["level"], space.describe(m), hint)
        if m["overcommitted"]:
            add("This NAS", "Space promised to bros", "warn",
                f"{human_bytes(m['promised'])} still allowed, {human_bytes(m['free'])} free",
                "Enlarge the dataset or its quota, or lower a bro's space.")
    else:
        add("This NAS", "Free space", "err", "Could not be measured", "Check that the data folder is mounted.")
    if not s.get("update_check", True):
        add("This NAS", "Version", "info", f"{VERSION} (checking for new versions is off)")
    else:
        u = updates.info()
        if updates.newer(u.get("latest")):
            add("This NAS", "Version", "warn", f"{VERSION}, {u['latest']} is available",
                f"See {u.get('url') or updates.RELEASES_URL} for what changed, then update the image tag.")
        elif u.get("latest"):
            add("This NAS", "Version", "ok", f"{VERSION}, the latest (checked {local_time(u.get('checked_at'))})")
        else:
            add("This NAS", "Version", "info", f"{VERSION}" + (f" (could not check: {u['error'][:80]})"
                                                              if u.get("error") else " (not checked yet)"))
    if s.get("backup_end_hour", -1) >= 0:
        add("This NAS", "Backup window", "info",
            f"{int(s['backup_hour']):02d}:00 to {int(s['backup_end_hour']):02d}:00, "
            + ("open now" if backup.in_window(s) else "closed now"))
    # --- internet
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(len(IROH_RELAYS) + 1) as pool:  # all at once: a blocked network costs 6 s, not 30
        relay_res = list(pool.map(_reach, IROH_RELAYS))
        dns_res = pool.submit(_reach, IROH_DNS).result()
    ok_relays = [f"{h.split('.')[0]} {detail}" for h, (ok, detail) in zip(IROH_RELAYS, relay_res) if ok]
    if ok_relays:
        add("Internet", "Relay servers", "ok", "Reachable: " + ", ".join(ok_relays))
    else:
        add("Internet", "Relay servers", "err", "None reachable over HTTPS",
            "Check the internet connection and firewall of the NAS. Without relays, "
            "bros only find each other on the same network.")
    ok, detail = dns_res
    add("Internet", "Address lookup (iroh DNS)", "ok" if ok else "warn",
        f"Reachable, {detail}" if ok else f"Not reachable: {detail}")
    add("Internet", "Direct connections (UDP)", "info",
        "Not testable from here. Run a speed test: it shows whether you are connected directly or via a relay.")
    # --- each bro you back up to
    for d in st["destinations"]:
        area = f"Bro: {d['name']}"
        pr = procs.procs.get(f"tunnel-{d['id']}")
        add(area, "Tunnel", "ok" if pr and pr.alive() else "err", "Running" if pr and pr.alive() else "Not running")
        t0 = time.time()
        try:
            info = backup.bro_status(d, timeout=40)
            ms = int((time.time() - t0) * 1000)
            q = info.get("quota_gib") or 0
            add(area, "Reachable", "ok", f"Answered in {ms} ms (version {info.get('v') or 'unknown'}), "
                f"{human_bytes(info.get('usage'))} of {q} GiB used")
        except Exception as e:
            add(area, "Reachable", "err", web.friendly_error(str(e)),
                "Is your bro's NAS on and online? Ask him to open BRO Backup and check his Self-check page.")
        if d.get("mode") == "revoked":
            add(area, "Pairing", "err", f"{d['name']} stopped storing your backups on {local_time(d.get('revoked_at'))}",
                "Remove this bro on the overview and pair with someone else.")
        elif d.get("last_contact"):
            add(area, "Address", "ok", f"Last exchanged {local_time(d.get('last_contact'))}"
                + (f", new address received {local_time(d['address_changed'])}" if d.get("address_changed") else ""))
        path = conn_paths.get(d["id"])
        if path:
            add(area, "Connection", "ok" if path["type"] in ("direct", "lan") else "info",
                {"direct": "Direct over the internet", "lan": "Direct on the local network",
                 "relay": "Through a relay server (works, but slower)"}.get(path["type"], path["type"]))
        last_ok = parse(d.get("last_ok"))
        if d.get("mode") in PAUSED_MODES:
            add(area, "Backups", "warn", f"Paused ({d.get('mode')})")
        elif d.get("last_error"):
            add(area, "Backups", "err", "Last backup failed: " + web.friendly_error(d["last_error"]))
        elif last_ok:
            age = (now() - last_ok).total_seconds() / 3600
            add(area, "Backups", "ok" if age < int(s["alert_hours"]) else "warn",
                f"Last successful backup {local_time(d.get('last_ok'))}")
        else:
            add(area, "Backups", "info", "No backup yet")
        rt = d.get("restore_test")
        if rt:
            add(area, "Restore test", "ok" if rt.get("ok") else "err",
                f"{local_time(rt.get('at'))}: " + ("passed" if rt.get("ok") else web.friendly_error(rt.get("error") or "failed")))
        else:
            add(area, "Restore test", "info", "Not run yet")
        fc = d.get("full_check")
        if fc and not fc.get("ok"):
            add(area, "Integrity", "err", f"Damaged data found on {local_time(fc.get('at'))}",
                "Open Restore for this bro: it explains what to do and offers a repair.")
        elif fc:
            add(area, "Integrity", "ok", f"{'Full check' if fc.get('full') else 'Check'} on {local_time(fc.get('at'))}: no errors")
    # --- bros backing up here
    for user, r in st["receivers"].items():
        stats = receive_stats.get(user) or {}
        name = r.get("bro_name") or r["name"]
        if not r.get("accepted"):
            add(f"Receiving: {name}", "Pairing", "info", "Code not used yet")
            continue
        seen = parse(stats.get("last_seen"))
        if seen and now() - seen < datetime.timedelta(hours=int(s["alert_hours"])):
            add(f"Receiving: {name}", "Last data", "ok", f"{local_time(stats.get('last_seen'))}, "
                f"{human_bytes(stats.get('usage'))} of {r['quota_gib']} GiB")
        else:
            add(f"Receiving: {name}", "Last data", "warn",
                f"Nothing received since {local_time(stats.get('last_seen')) if seen else 'pairing'}",
                "Ask your bro whether his backups still run.")
        add(f"Receiving: {name}", "Key copy", "ok" if os.path.exists(os.path.join(ESCROW_DIR, f"{user}.json")) else "warn",
            "Stored here" if os.path.exists(os.path.join(ESCROW_DIR, f"{user}.json")) else "Not received yet")
    return out


def run_selfcheck():
    if selfcheck_state["running"]:
        return
    selfcheck_state["running"] = True
    try:
        checks = selfcheck_checks()
        counts = {k: sum(1 for c in checks if c["status"] == k) for k in ("ok", "warn", "err", "info")}
        selfcheck_state["result"] = {"at": iso(now()), "checks": checks, "counts": counts}
        log.info("Self-check: %s ok, %s warnings, %s errors", counts["ok"], counts["warn"], counts["err"])
    except Exception as e:
        log.exception("Self-check failed: %s", e)
        selfcheck_state["result"] = {"at": iso(now()), "checks": [], "counts": {}, "error": str(e)}
    finally:
        selfcheck_state["running"] = False


@web.app.get("/selfcheck")
def selfcheck_page():
    if not selfcheck_state["result"] and not selfcheck_state["running"]:
        threading.Thread(target=run_selfcheck, daemon=True).start()
        time.sleep(0.2)
    res = selfcheck_state["result"]
    groups = {}
    for c in (res or {}).get("checks", []):
        groups.setdefault(c["area"], []).append(c)
    return render_template("selfcheck.html", res=res, groups=groups, running=selfcheck_state["running"])


@web.app.post("/selfcheck")
def selfcheck_run():
    threading.Thread(target=run_selfcheck, daemon=True).start()
    time.sleep(0.3)
    return redirect(url_for("selfcheck_page"))


@web.app.get("/selfcheck.json")
def selfcheck_json():
    if request.args.get("run") == "1":
        run_selfcheck()
    return jsonify(selfcheck_state["result"] or {})


@web.app.post("/notify-test")
def notify_test():
    s = settings()
    if not notification_channels(s):
        flash("Set up ntfy or email first, and save.", "err")
        return redirect(url_for("settings_page"))
    res = notify("BRO Backup test", f"This is a test notification from {s['name'] or 'BRO Backup'}. "
                 "If you read this, notifications work.", priority="default")
    for ch, err in res.items():
        flash(f"{ch}: sent." if not err else f"{ch}: failed ({err})", "err" if err else "ok")
    return redirect(url_for("settings_page"))


@web.app.get("/logs")
def logs_page():
    level = logging.WARNING if request.args.get("level") == "warning" else logging.INFO
    lines = [t for lv, t in log_ring.lines if lv >= level][-500:]
    return render_template("logs.html", lines=lines, level=request.args.get("level", "all"),
                           processes=web.process_overview(), paths=conn_paths)


@web.app.get("/diagnostics.zip")
def diagnostics():
    st = load_state()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        def put(name, data):
            z.writestr(name, data if isinstance(data, str) else json.dumps(data, indent=2, default=str))
        put("README.txt", "BRO Backup diagnostics. Passwords, keys and full connection tickets are removed.\n")
        put("info.json", {"version": VERSION, "time": iso(now()), "tz": os.environ.get("TZ"),
                          "tools": web.tool_versions(), "ui_port": UI_PORT,
                          "disk_free_data": nas.free_space(DATA_DIR), "my_tickets_ready": sorted(my_tickets)})
        rec = st["recovery"]
        put("state.json", redact({**st, "recovery": {"set": bool(rec.get("key")), "created": rec.get("created")}}))
        put("plan.json", backup.backup_plan())
        if selfcheck_state["result"]:
            put("selfcheck.json", selfcheck_state["result"])
        put("processes.json", web.process_overview())
        put("connections.json", conn_paths)
        put("receive_stats.json", receive_stats)
        put("activity.json", {"sending": activity, "receiving": recv_activity})
        put("log-recent.txt", "\n".join(t for _, t in log_ring.lines))
        logfile = os.path.join(CONFIG_DIR, "bro-backup.log")
        if os.path.exists(logfile):
            with open(logfile, errors="replace") as f:
                put("log-file.txt", redact_text(f.read()[-2_000_000:]))
        try:
            with open("/proc/self/mountinfo") as f:
                put("mounts.txt", "\n".join(l.strip() for l in f if any(m in l for m in (" /nas", " /data", " /seed"))))
        except OSError:
            pass
    buf.seek(0)
    name = f"bro-backup-diagnostics-{slug(st['settings']['name'])}-{datetime.datetime.now().strftime('%Y%m%d-%H%M')}.zip"
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename={name}"})


@web.app.post("/keys")
def keys():
    """Every key in one file: only with the current password, and the code when two-step login is on."""
    if not web._reauth_ok():  # password first, then one fresh code (same rule as the login)
        return web._reauth_failed(web.url_for("settings_page") + "#keys")
    st = load_state()
    log.warning("Emergency keys downloaded from %s", web.request.remote_addr)
    notify("Emergency keys downloaded", f"Someone downloaded the file with all keys from {web.request.remote_addr}. "
           "If that was not you, change your password and check the Logs page.", priority="high")
    export = {"exported": iso(now()), "app": "bro-backup", "version": VERSION,
              "name": st["settings"]["name"],
              "note": "Emergency keys. Without this file or your recovery code you cannot restore your backups.",
              **recovery.recovery_bundle(st)}
    return Response(json.dumps(export, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": f"attachment; filename=bro-backup-keys-{slug(st['settings']['name'])}.json"})


