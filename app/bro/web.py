# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/web.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""The web UI."""

import datetime
import json
import os
import re
import secrets
import subprocess
import threading
import time

from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for

from . import (
    alarm,
    auth,
    backup,
    charts,
    checks,
    dumps,
    incoming,
    lan,
    m365,
    nas,
    pair_api,
    pairing,
    peers,
    pickup,
    probro,
    procs,
    recovery,
    reports,
    safety,
    scheduler,
    space,
    speed,
    updates,
    urbackup,
)
from .core import (
    tag_dec,
    clean_name,
    CODE_DAYS,
    DEFAULT_EXCLUDES,
    DUMBPIPE,
    ESCROW_DIR,
    GIB,
    NAS_DIR,
    REST_SERVER,
    RESTIC,
    RETENTION_PRESETS,
    SMTP_SECURITY,
    SOURCE_URL,
    SPEED_SECONDS,
    VERSION,
    WEEKDAYS,
    activity,
    check_ui_password,
    conn_paths,
    ensure_identity,
    get_dest,
    hash_ui_password,
    human_bytes,
    human_secs,
    backups_paused,
    iso,
    job_locks,
    last_lines,
    load_state,
    local_time,
    log,
    mutate,
    my_tickets,
    notification_channels,
    notify,
    now,
    receive_stats,
    recv_activity,
    redact_text,
    settings,
    setup_done,
    update_dest,
)

# ---------------------------------------------------------------- web UI
app = Flask("bro-ui", root_path=pair_api.APP_ROOT)
app.config.update(SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_NAME="bro_backup_session",  # other apps on the same NAS address use "session"
                  MAX_CONTENT_LENGTH=1024 * 1024)
app.jinja_env.filters["bytes"] = human_bytes
app.jinja_env.filters["ltime"] = local_time
app.jinja_env.filters["duration"] = human_secs


def friendly_error(text):
    """One plain sentence for a technical error; the details stay available."""
    t = (text or "").lower()
    if "ciphertext verification failed" in t or "decrypting blob" in t or "hash mismatch" in t:
        return "Data at your bro is damaged: restic could not decrypt or verify it. Ask your bro to check his disks."
    if "differs from the original" in t:
        return "A restored file differs from your original."
    if "not reachable" in t or "connection refused" in t or "timed out" in t:
        return "Your bro could not be reached."
    if "no versions to test" in t:
        return "There are no versions to test yet."
    first = next((line for line in (text or "").splitlines() if line.strip()), "")
    return first[:160]


app.jinja_env.filters["friendly"] = friendly_error
app.jinja_env.filters["mbit"] = lambda bps: f"{bps / 1e6:.1f} Mbit/s" if bps else "-"


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(16)
    return session["csrf"]


app.jinja_env.globals.update(csrf_token=csrf_token, version=VERSION, source_url=SOURCE_URL,
                             two_step=lambda: auth.two_step_on())


@app.before_request
def guard():
    if request.path == "/healthz" or (request.method == "GET" and request.path.startswith("/static/")):
        return None  # the font and the health check need no login
    if request.method == "POST":
        token = session.get("csrf")
        if not token or not secrets.compare_digest(token, request.form.get("csrf", "")):
            abort(400)
    if not setup_done():
        return None if request.path == "/setup" else redirect(url_for("setup"))
    if request.path == "/setup":
        return redirect(url_for("index"))
    if session.get("ok") and session.get("sid") not in _live:  # logged out elsewhere, or the app restarted
        session.clear()
        if request.path != "/login":
            return redirect(url_for("login"))
    if session.get("ok"):
        t = time.time()
        if t - session.get("seen", 0) > auth.IDLE_TIMEOUT or t - session.get("since", 0) > auth.MAX_SESSION:
            _live.pop(session.get("sid"), None)
            session.clear()
            flash("You were logged out after a while without activity. Log in again.", "err")
            return redirect(url_for("login"))
        if t - session.get("seen", 0) > 30 and request.path not in BACKGROUND_PATHS:  # not on every request
            session["seen"] = t  # the page polling by itself is no activity: an open tab still logs out
    if request.path != "/login" and not session.get("ok"):
        return redirect(url_for("login"))
    return None


@app.after_request
def security_headers(resp):
    # The pages use a little inline script and style, and nothing from other sites.
    resp.headers.setdefault("Content-Security-Policy",
                            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                            "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    if session.get("ok"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


# Logins live on the server. The cookie only carries a random id: it is signed but readable, so no
# secret (recovery code, invite code, TOTP secret) goes into it, and logging out ends the login for real.
# A restart of the app logs everybody out.
_live = {}  # session id -> {"t": login time, "data": values that must not go into the cookie}


def start_session():
    csrf, flashes = session.get("csrf"), session.get("_flashes")
    session.clear()  # a fresh session after login: nothing from before carries over...
    if csrf:
        session["csrf"] = csrf
    if flashes:  # ...except messages for the next page (the result of a recovery in the setup, for example)
        session["_flashes"] = flashes
    t = time.time()
    for sid in [k for k, v in _live.items() if t - v["t"] > auth.MAX_SESSION]:
        _live.pop(sid, None)
    sid = secrets.token_urlsafe(24)
    _live[sid] = {"t": t, "data": {}}
    session.update(ok=True, since=t, seen=t, sid=sid)


def vault():
    """Per-login values kept on the server instead of in the cookie."""
    return _live[session["sid"]]["data"]


def end_other_sessions():
    keep = session.get("sid")
    for sid in [k for k in _live if k != keep]:
        _live.pop(sid, None)


BACKGROUND_PATHS = ("/live.json", "/selfcheck.json")


@app.get("/healthz")
def healthz():
    return "ok"


@app.get("/live.json")
def live_json():
    """What the overview refreshes every few seconds: incoming backups and our own running jobs."""
    st = load_state()
    inc = incoming.status(list(st["receivers"]))
    return jsonify(incoming={u: dict(v, text=incoming_text(v)) for u, v in inc.items()},
                   activity={d["id"]: activity.get(d["id"]) or "" for d in st["destinations"]})


def incoming_text(v):
    if not v["active"]:
        return ""
    if v["speed"] >= 1024:
        return f"Receiving now: {human_bytes(v['speed'])}/s, {human_bytes(v['received'])} so far"
    return "Busy: a backup, check or cleanup is running" + (
        f", {human_bytes(v['received'])} received" if v["received"] else "")


def recover_from_bro(help_code, recovery_code):
    data = pairing.decode_code(help_code, "BROH1.", ("pt", "tok"))
    resp = procs.pair_call(data["pt"], "POST", "/bro/recover", {"tok": data["tok"]}, timeout=60)
    blob = resp["blob"]
    try:
        bundle, key = recovery.unseal(blob, recovery_code)
    except Exception:
        raise ValueError("The recovery code is not correct. Check that you typed it correctly.")
    recovery.apply_bundle(bundle, key.hex(), blob["salt"])
    return bundle, clean_name(resp.get("n")) or clean_name(data.get("n"))


@app.route("/setup", methods=["GET", "POST"])
def setup():
    folders = nas.list_folders()
    if request.method != "POST":
        return render_template("setup.html", folders=folders, form={}, disks=pickup.scan())
    f = request.form
    name = f.get("name", "").strip()
    pw, pw2 = f.get("pw", ""), f.get("pw2", "")
    help_code, rcode = f.get("help_code", "").strip(), f.get("recovery_code", "").strip()
    disk, disk_rc = f.get("disk", "").strip(), f.get("disk_code", "").strip()
    keyfile = request.files.get("keys")
    restoring = bool(help_code or rcode or disk or (keyfile and keyfile.filename))

    def fail(msg):
        flash(msg, "err")
        return render_template("setup.html", folders=folders, form=f, disks=pickup.scan())
    if len(pw) < 10 or pw != pw2:
        return fail("Choose the same password twice, at least 10 characters.")
    if not name and not restoring:
        return fail("Give your NAS a name.")
    with mutate() as st:
        st["settings"]["pw_hash"] = hash_ui_password(pw)
        st["settings"]["name"] = name
    try:
        if disk:
            if disk not in {x["path"] for x in pickup.scan()}:
                raise ValueError("That disk is no longer there.")
            if not disk_rc:
                raise ValueError("Enter your recovery code to open the backup on the disk.")
            bundle, m, d = pickup.recover_from_disk(disk, disk_rc)
            flash(f"Recovered from the disk copied by {m['from']}: {len(bundle.get('destinations') or [])} bro(s) back. "
                  "Go to Restore next to " + (d["name"] if d else "your bro") + ": it restores from the disk, "
                  "no internet needed.", "ok")
        elif help_code or rcode:
            if not (help_code and rcode):
                raise ValueError("To recover you need both the help code from your bro and your recovery code.")
            bundle, bro = recover_from_bro(help_code, rcode)
            flash(f"Recovered via {bro}: {len(bundle.get('destinations') or [])} bro(s) back. "
                  "Go to Restore to get your files back.", "ok")
        elif keyfile and keyfile.filename:
            imp = json.load(keyfile.stream)
            recovery.apply_bundle({"identity": imp.get("identity") or {}, "destinations": imp.get("destinations") or [],
                          "receivers": imp.get("receivers") or {}, "htpasswd": imp.get("htpasswd"),
                          "settings": {"name": name or imp.get("name")}}, None, None)
            flash(f"Keys restored: {len(imp.get('destinations') or [])} bro(s).", "ok")
    except Exception as e:
        with mutate() as st:
            st["settings"]["pw_hash"] = ""
        return fail(f"Recovery failed: {e}")
    with mutate() as st:
        if name:
            st["settings"]["name"] = name
        chosen = nas.clean_sources(f.getlist("src"))
        if chosen or not restoring:
            st["settings"]["sources"] = chosen
        has_rc = bool(st["recovery"].get("key"))
    ensure_identity()
    start_session()
    procs.supervise_once()
    if not has_rc:
        code = recovery.new_recovery_code()
        recovery.set_recovery_code(code)
        vault()["show_rc"] = code
        return redirect(url_for("recovery_page"))
    return redirect(url_for("index"))


@app.route("/recovery-code", methods=["GET", "POST"])
def recovery_page():
    code = vault().get("show_rc")
    if request.method == "POST":
        if code and recovery.norm_recovery_code(request.form.get("last", "")) == recovery.norm_recovery_code(code)[-4:]:
            vault().pop("show_rc", None)
            flash("Recovery code confirmed. Keep it safe, it will never be shown again.", "ok")
            return redirect(url_for("index"))
        flash("The last 4 characters do not match. Look again at what you wrote down.", "err")
    if not code:
        return redirect(url_for("index"))
    return render_template("recovery.html", code=code)


@app.post("/recovery-code/new")
def recovery_new():
    """A new code replaces the key copies at every bro: the old code then opens nothing. So: password (and code)."""
    if not _reauth_ok():
        return _reauth_failed(url_for("settings_page") + "#recovery")
    had = bool((load_state().get("recovery") or {}).get("key"))
    code = recovery.new_recovery_code()
    recovery.set_recovery_code(code)
    vault()["show_rc"] = code
    log.warning("New recovery code made from %s", request.remote_addr)
    if had:
        notify("Recovery code replaced", f"A new recovery code was made from {request.remote_addr}. The old code no "
               "longer opens the key copies at your bros. If that was not you, change your password and make a new "
               "code yourself.", priority="high")
    return redirect(url_for("recovery_page"))


@app.route("/login", methods=["GET", "POST"])
def login():
    addr = request.remote_addr or "?"
    two_step = auth.two_step_on()
    if request.method == "POST":
        wait = auth.locked_for(addr)
        if wait:
            flash(f"Too many wrong attempts. Try again in {wait // 60 + 1} minute(s).", "err")
            return render_template("login.html", two_step=two_step), 429
        time.sleep(0.5)
        s = settings()
        ok = check_ui_password(request.form.get("pw", ""), s["pw_hash"])
        if ok and two_step:  # check and use the code under the state lock: one code, one login
            with mutate() as st:
                ss = st["settings"]
                step = auth.totp_counter_for(ss["totp_secret"], request.form.get("code", ""), int(ss.get("totp_last", -1)))
                if step is not None:
                    ss["totp_last"] = step
            ok = step is not None
        if ok:
            auth.clear_fails(addr)
            start_session()
            return redirect(url_for("index"))
        auth.register_fail(addr)
        flash("Wrong password or code." if two_step else "Wrong password.", "err")
    return render_template("login.html", two_step=two_step)


@app.post("/logout")
def logout():
    _live.pop(session.get("sid"), None)
    session.clear()
    return redirect(url_for("login"))


@app.get("/")
def index():
    if vault().get("show_rc"):
        return redirect(url_for("recovery_page"))
    st = load_state()
    receivers = []
    for user, r in st["receivers"].items():
        stats = receive_stats.get(user, {})
        receivers.append({"user": user, "name": r.get("bro_name") or r["name"], "quota_gib": r["quota_gib"],
                          "accepted": r.get("accepted"), "created": r["created"],
                          "usage": stats.get("usage"), "last_seen": stats.get("last_seen"),
                          "escrow": os.path.exists(os.path.join(ESCROW_DIR, f"{user}.json")),
                          "busy": recv_activity.get(user), "import_error": r.get("import_error"),
                          "blocked": r.get("quota_blocked"), "pickup": r.get("pickup"), "ref": r.get("ref"),
                          "request": r.get("space_request")})
    inc = incoming.status([r["user"] for r in receivers])
    for r in receivers:
        r["incoming"] = incoming_text(inc.get(r["user"]) or {"active": False})
    pending = {p["dest_id"]: p.get("error") for p in st["pending_accepts"]}
    dests = st["destinations"]
    root, external = nas.seed_root()
    return render_template("index.html", dests=dests, receivers=receivers, activity=activity, paths=conn_paths,
                           s=st["settings"], pending=pending,
                           problems=[d for d in dests if d.get("last_error") or d.get("mode") == "seed_error"
                                     or (d.get("restore_test") and not d["restore_test"].get("ok"))
                                     or (d.get("full_check") and not d["full_check"].get("ok"))
                                     or d.get("mode") == "revoked"],
                           ready=bool(my_tickets.get("data") and my_tickets.get("pair")),
                           invite_code=vault().pop("invite_code", None),
                           help_code=vault().pop("help_code", None),
                           seeds=nas.scan_seeds(), seed_root=root, seed_external=external,
                           seed_free=nas.free_space(root), has_rc=bool(st["recovery"].get("key")),
                           leftovers=peers.leftover_data(), update=updates.available(),
                           space=space.measure(), alarm=alarm.active(), safety=safety.compute(st),
                           receivers_total=sum(r["usage"] or 0 for r in receivers), ub=urbackup.status(st),
                           pause=backups_paused(st))


@app.post("/alarm/clear")
def alarm_clear():
    """'This was me': the ransomware alarm goes off and cleaning up old versions starts again. Needs the password."""
    if not _current_pw_ok():
        flash("Wrong password: the alarm stays on.", "err")
        return redirect(url_for("index"))
    alarm.clear()
    flash("Alarm cleared. Old versions are cleaned up again as usual from the next backup.", "ok")
    return redirect(url_for("index"))


@app.post("/urbackup/include")
def urbackup_include():
    """Add a UrBackup storage folder to the folders that go to the bros."""
    path = request.form.get("path", "")
    if path not in {x["path"] for x in urbackup.status()}:
        abort(400)
    with mutate() as st:
        st["settings"]["sources"] = nas.clean_sources((st["settings"].get("sources") or []) + [path])
    flash(f"{os.path.relpath(path, NAS_DIR)} now goes to your bros, from the next backup on.", "ok")
    return redirect(request.referrer if (request.referrer or "").startswith(request.host_url) else url_for("index"))


@app.post("/urbackup/scan")
def urbackup_scan():
    found = urbackup.scan()
    flash(f"UrBackup: {len(found)} storage folder(s) found." if found else
          "No UrBackup storage found under /nas (looked 3 levels deep).", "ok" if found else "err")
    return redirect(url_for("settings_page"))


@app.post("/update/dismiss")
def update_dismiss():
    updates.dismiss()
    flash("Hidden until the next version.", "ok")
    return redirect(url_for("index"))


@app.post("/invite")
def invite():
    name = request.form.get("name", "").strip()
    try:
        quota = max(1, int(request.form.get("quota", settings()["default_quota_gib"])))
        if not name:
            raise ValueError("Give your bro a name.")
        vault()["invite_code"] = pairing.make_invite(name, quota, request.form.get("seed") == "1",
                                                     mutual_ok=request.form.get("mutual_ok") == "1")
        flash(f"Code for {name} is ready. Send it via Signal or WhatsApp, not by email. "
              f"It works once, for {CODE_DAYS} days.", "ok")
    except Exception as e:
        flash(str(e), "err")
    return redirect(url_for("index"))


@app.post("/add")
def add():
    try:
        mutual = request.form.get("mutual") == "1"
        seed = request.form.get("seed") == "1"
        quota = max(1, int(request.form.get("quota", settings()["default_quota_gib"])))
        d, result = pairing.accept_code(request.form.get("code", ""), mutual, quota, seed)
        how = "The first backup is now being written to disk." if seed else "The first backup has started."
        if result == "ok":
            both = " in both directions" if d.get("mutual") else ""
            one_way = f" {d['name']} chose not to back up to you, so you give him no space." \
                if mutual and d.get("mutual_refused") else ""
            flash(f"Paired with {d['name']}{both}. {how}{one_way}", "ok")
        else:
            flash(f"{d['name']} added, but your bro has not confirmed yet ({result}). "
                  "This will be retried automatically.", "err")
    except Exception as e:
        flash(f"Code not usable: {e}", "err")
    return redirect(url_for("index"))


def _confirmed(name):
    want = (name if isinstance(name, str) else str(name or "")).strip().casefold()
    return bool(want) and (request.form.get("confirm") or "").strip().casefold() == want


@app.route("/receiver/<user>/remove", methods=["GET", "POST"])
def receiver_remove(user):
    st = load_state()
    r = st["receivers"].get(user)
    if not r:
        abort(404)
    name = r.get("bro_name") or r["name"]
    if request.method == "POST":
        if r.get("accepted") and not _confirmed(name):  # an unused code can go without typing
            flash(f"Type {name} to confirm.", "err")
            return redirect(url_for("receiver_remove", user=user))
        if recv_activity.get(user):
            flash(f"Busy right now: {recv_activity[user]}. Try again when it is done.", "err")
            return redirect(url_for("index"))
        delete = request.form.get("delete_data") == "1"
        if delete and not _reauth_ok():
            return _reauth_failed(url_for("receiver_remove", user=user))
        peers.stop_receiving(user, delete_data=delete)
        if delete:
            log.warning("Backups of %s deleted from %s", name, request.remote_addr)
            notify(f"Backups of {name} deleted", f"Deleted from {request.remote_addr}, together with his login.",
                   priority="high")
        flash(f"You no longer store {name}'s backups. " + (
            "His data is deleted." if delete else "His encrypted data stays until you delete it below."), "ok")
        return redirect(url_for("index"))
    path = os.path.join(peers.RECEIVE_DIR, user)
    return render_template("remove.html", kind="receiver", name=name, r=r,
                           usage=peers.dir_size(path) if os.path.isdir(path) else 0,
                           linked=peers.linked_dest(user, st))


@app.post("/leftover/<user>/delete")
def leftover_delete(user):
    if not _reauth_ok():
        return _reauth_failed(url_for("index"))
    try:
        size = peers.delete_data_now(user)
        flash(f"Deleted ({human_bytes(size)}).", "ok")
        log.warning("Leftover backups of %s deleted from %s", user, request.remote_addr)
        notify(f"Backups of {user} deleted", f"{human_bytes(size)} deleted from {request.remote_addr}.", priority="high")
    except ValueError as e:
        flash(str(e), "err")
    return redirect(url_for("index"))


@app.post("/leftover/<user>/keep")
def leftover_keep(user):
    peers.cancel_delete(user)
    flash("Kept. Nothing is deleted until you choose so.", "ok")
    return redirect(url_for("index"))


@app.post("/receiver/<user>/quota")
def receiver_quota(user):
    try:
        quota = int(request.form.get("quota", 0))
        if quota < 1:
            raise ValueError
    except ValueError:
        flash("Enter the space in whole GiB, at least 1.", "err")
        return redirect(url_for("index"))
    stats = receive_stats.get(user) or {}
    with mutate() as st:
        r = st["receivers"].get(user)
        if not r:
            abort(404)
        old, r["quota_gib"] = r["quota_gib"], quota
        name = r.get("bro_name") or r["name"]
    scheduler.refresh_receive_stats(only=user)  # unblocks him right away if he now fits
    msg = f"Space for {name} changed from {old} to {quota} GiB."
    if stats.get("usage") and stats["usage"] > quota * GIB:
        msg += f" He already uses {human_bytes(stats['usage'])}: his next backup will stop until he cleans up or you give more space."
    flash(msg, "ok")
    return redirect(url_for("index"))


@app.post("/receiver/<user>/ref")
def receiver_ref(user):
    try:
        probro.set_ref(user, request.form.get("ref", ""))
    except LookupError:
        abort(404)
    return redirect(url_for("index") + "#receivers")


@app.post("/receiver/<user>/space/<answer>")
def receiver_space_answer(user, answer):
    if answer not in ("grant", "decline"):
        abort(404)
    try:
        name, old, new = probro.answer_request(user, answer == "grant")
    except LookupError as e:
        flash(str(e), "err")
        return redirect(url_for("index"))
    if answer == "grant":
        scheduler.refresh_receive_stats(only=user)  # unblocks him right away if he now fits
        flash(f"Space for {name} raised from {old} to {new} GiB. He sees it at his next backup.", "ok")
    else:
        flash(f"Request of {name} declined. He keeps {old} GiB.", "ok")
    return redirect(url_for("index"))


@app.get("/receivers.csv")
def receivers_csv():
    """Peak usage per bro per month, for billing or just to see who grows."""
    return Response(probro.usage_csv(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=bro-usage-{now().strftime('%Y%m%d')}.csv"})


@app.post("/dest/<dest_id>/ask-space")
def dest_ask_space(dest_id):
    d = get_dest(dest_id)
    if not d:
        abort(404)
    try:
        gib = int(request.form.get("gib", 0))
        probro.ask_space(d, gib, request.form.get("note", ""))
        update_dest(dest_id, space_asked={"gib": gib, "at": iso(now())})
        flash(f"Asked {d['name']} for {gib} GiB more. He gets a notification.", "ok")
    except ValueError as e:
        flash(str(e) if str(e) else "Enter the space in whole GiB.", "err")
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        flash(f"{d['name']} could not be reached: {msg[:120]}" if "(404)" not in msg else
              f"{d['name']} runs an older BRO Backup that cannot receive requests yet. Ask him directly.", "err")
    return redirect(url_for("index"))


@app.post("/receiver/<user>/help")
def receiver_help(user):
    try:
        vault()["help_code"] = {"code": pairing.make_help_code(user), "for": user}
        flash(f"Help code created. Only give it to your bro himself, preferably in person or via Signal. "
              f"It works for {CODE_DAYS} days.", "ok")
    except Exception as e:
        flash(str(e), "err")
    return redirect(url_for("index"))


@app.post("/import")
def import_seed():
    path = request.form.get("path", "")
    seed = next((x for x in nas.scan_seeds() if x["path"] == path), None)
    if not seed or not seed["known"]:
        flash("This seed does not belong to one of your bros.", "err")
    elif not seed["complete"]:
        flash("This seed is not finished yet. Let your bro finish writing it first.", "err")
    elif request.form.get("replace") == "1" and not _reauth_ok():  # replacing deletes what he has here now
        return _reauth_failed(url_for("index"))
    else:
        threading.Thread(target=nas.run_import, args=(path, seed["user"], request.form.get("replace") == "1"),
                         daemon=True).start()
        flash(f"Import from {seed['from']} started.", "ok")
    return redirect(url_for("index"))


PAUSE_HOURS = {"1": 1, "4": 4, "24": 24, "0": None}  # 0 = until you resume


@app.post("/pause")
def pause_backups():
    """Stop sending backups for a while. A running backup stops within seconds and later continues where it was."""
    hours = PAUSE_HOURS.get(request.form.get("hours", "0"), None)
    until = iso(now() + datetime.timedelta(hours=hours)) if hours else None
    with mutate() as st:
        st["pause"] = {"at": iso(now()), "until": until}
    log.info("Backups paused %s", f"until {until}" if until else "until resumed")
    busy = [d["name"] for d in load_state()["destinations"] if activity.get(d["id"])]
    flash("Backups paused" + (f" until {local_time(until)}" if until else " until you resume them") + "."
          + (f" The running backup to {', '.join(busy)} stops in a few seconds." if busy else ""), "ok")
    return redirect(url_for("index"))


@app.post("/resume")
def resume_backups():
    with mutate() as st:
        st.pop("pause", None)
    log.info("Backups resumed")
    stopped = [d for d in load_state()["destinations"] if d.get("pause_stop")]
    for d in stopped:  # continue what the pause interrupted, now instead of at the next schedule
        threading.Thread(target=backup.run_backup, args=(d["id"],), daemon=True).start()
    flash("Backups resumed." + (" The interrupted backup continues now." if stopped else ""), "ok")
    return redirect(url_for("index"))


@app.post("/dest/<dest_id>/run")
def dest_run(dest_id):
    if backups_paused():
        flash("Backups are paused. Resume them first (at the top of the overview).", "err")
        return redirect(url_for("index"))
    lock = job_locks.get(dest_id)
    if lock and lock.locked():  # run_backup would quietly do nothing: say so instead of "started"
        flash(f"Busy right now: {activity.get(dest_id) or 'another job for this bro'}. "
              "Click Now again when it is done.", "err")
        return redirect(url_for("index"))
    threading.Thread(target=backup.run_backup, args=(dest_id,), daemon=True).start()
    flash("Backup started.", "ok")
    return redirect(url_for("index"))


@app.post("/dest/<dest_id>/seed")
def dest_seed(dest_id):
    threading.Thread(target=backup.run_seed, args=(dest_id,), daemon=True).start()
    flash("The seed is being written. Backups over the internet are paused meanwhile.", "ok")
    return redirect(url_for("index"))


@app.post("/dest/<dest_id>/online")
def dest_online(dest_id):
    was = (get_dest(dest_id) or {}).get("mode")
    update_dest(dest_id, mode=None, last_run=None, restore_from=None)  # later restores go over the internet again
    flash("Backups resumed." if was == "hold" else "Seed cancelled. The backup now goes over the internet.", "ok")
    return redirect(url_for("index"))


@app.route("/dest/<dest_id>/remove", methods=["GET", "POST"])
def dest_remove(dest_id):
    st = load_state()
    d = get_dest(dest_id)
    if not d:
        abort(404)
    linked = peers.linked_receiver(d, st)
    if request.method == "POST":
        if not _confirmed(d["name"]):
            flash(f"Type {d['name']} to confirm.", "err")
            return redirect(url_for("dest_remove", dest_id=dest_id))
        if not _reauth_ok():
            return _reauth_failed(url_for("dest_remove", dest_id=dest_id))
        lock = job_locks.get(dest_id)
        if activity.get(dest_id) or (lock and lock.locked()):
            flash(f"Busy right now: {activity.get(dest_id) or 'another job for this bro'}. Try again when it is done.",
                  "err")
            return redirect(url_for("index"))
        _, gone = peers.remove_destination(dest_id, ask_delete=request.form.get("ask_delete") == "1",
                                           also_receiver=request.form.get("also_receiver") == "1")
        log.warning("Stopped backing up to %s from %s (asked to delete: %s)", d["name"], request.remote_addr,
                    request.form.get("ask_delete") == "1")
        notify(f"No longer backing up to {d['name']}", f"Done from {request.remote_addr}" +
               (f", and {d['name']} was asked to delete your backups." if request.form.get("ask_delete") == "1" else "."),
               priority="high")
        told = "" if d.get("mode") == "revoked" else " He is being told."
        flash(f"You no longer back up to {d['name']}.{told}" +
              (" You also no longer store his backups." if gone else ""), "ok")
        return redirect(url_for("index"))
    lpath = os.path.join(peers.RECEIVE_DIR, linked) if linked else None
    return render_template("remove.html", kind="dest", d=d, name=d["name"], linked=linked,
                           linked_usage=peers.dir_size(lpath) if lpath and os.path.isdir(lpath) else 0,
                           other_dests=[x["name"] for x in st["destinations"]
                                        if x["id"] != dest_id and x.get("mode") != "revoked"])


@app.get("/dest/<dest_id>/snapshots")
def dest_snapshots(dest_id):
    d = get_dest(dest_id)
    if not d:
        abort(404)
    snaps, err = [], None
    try:
        p = backup.restic(d, "--no-lock", "snapshots", "--json", timeout=180, read=True)  # read-only: never wait for or block a job
        if p.returncode == 0:
            snaps = sorted(json.loads(p.stdout or "[]"), key=lambda x: x["time"], reverse=True)
            for x in snaps:
                x["src"] = tag_dec(next((t[4:] for t in x.get("tags") or [] if t.startswith("src:")), None))
        else:
            err = last_lines(p.stderr)
    except Exception as e:
        err = str(e)
    a = alarm.active() or {}
    disk = backup.restore_source(d)
    return render_template("snapshots.html", d=d, snaps=snaps, err=err, busy=activity.get(dest_id),
                           suspicious=set((a.get("snaps") or {}).get(dest_id) or []),
                           before=set((a.get("before") or {}).get(dest_id) or []),
                           disk=disk, disk_info=pickup.read_marker(disk) if disk else None,
                           disks=[] if disk else pickup.for_dest(d))


@app.post("/dest/<dest_id>/restore-source")
def dest_restore_source(dest_id):
    """Restore from a disk the bro made, or over the internet again."""
    if not get_dest(dest_id):
        abort(404)
    path = request.form.get("path", "")
    try:
        if path:
            m = pickup.use_for_restore(dest_id, path)
            flash(f"Restoring from the disk copied by {m['from']} on {m['created'][:10]}: no internet needed.", "ok")
        else:
            update_dest(dest_id, restore_from=None)
            flash("Restoring over the internet again.", "ok")
    except ValueError as e:
        flash(str(e), "err")
    return redirect(url_for("dest_snapshots", dest_id=dest_id))


@app.post("/receiver/<user>/pickup")
def receiver_pickup(user):
    """Copy a bro's backup to a disk, so he can pick it up after a crash."""
    try:
        target, external, total = pickup.make_pickup(user)
        where = "the external disk" if external else "the bro-backup folder (no external disk mounted)"
        flash(f"Copying {human_bytes(total)} to {where}: {target}. You get a notification when it is done.", "ok")
    except ValueError as e:
        flash(str(e), "err")
    return redirect(url_for("index"))


@app.post("/dest/<dest_id>/restore")
def dest_restore(dest_id):
    snap = request.form.get("snapshot", "")
    if not re.fullmatch(r"[0-9a-f]{8,64}", snap):
        abort(400)
    if job_locks.get(dest_id) and job_locks[dest_id].locked():
        flash(f"Busy right now: {activity.get(dest_id) or 'another job for this bro'}. Try again when it is done.", "err")
        return redirect(url_for("dest_snapshots", dest_id=dest_id))
    paths = [x for x in request.form.getlist("path") if x.startswith("/") and "\x00" not in x][:500]
    threading.Thread(target=backup.run_restore, args=(dest_id, snap, paths or None), daemon=True).start()
    what = f"{len(paths)} selected item(s) from version" if paths else "Restore of version"
    flash(f"{what} {snap[:8]} started. You will find it in the restore folder of bro-backup.", "ok")
    return redirect(url_for("index"))


@app.get("/dest/<dest_id>/browse/<snap>")
def dest_browse(dest_id, snap):
    d = get_dest(dest_id)
    if not d or not re.fullmatch(r"[0-9a-f]{8,64}", snap):
        abort(404)
    path = "/" + request.args.get("path", "/").strip("/")
    q = request.args.get("q", "").strip()
    entries, err, info = [], None, {}
    try:
        if q:  # search inside this version
            pat = q if any(c in q for c in "*?[") else f"*{q}*"
            if pat.startswith("-"):  # never let a search term become a restic option
                pat = "*" + pat
            p = backup.restic(d, "--no-lock", "find", "--json", "--snapshot", snap, "--", pat, timeout=600, read=True)
            if p.returncode == 0:
                for block in json.loads(p.stdout or "[]"):
                    for m in block.get("matches") or []:
                        entries.append({"name": m["path"], "path": m["path"], "type": m.get("type"),
                                        "size": m.get("size"), "mtime": m.get("mtime")})
                entries = entries[:1000]
        else:
            p = backup.restic(d, "--no-lock", "ls", "--json", snap, "--", path, timeout=600, read=True)
            if p.returncode == 0:
                for line in p.stdout.splitlines():
                    try:
                        x = json.loads(line)
                    except ValueError:
                        continue
                    if x.get("struct_type") == "snapshot" or x.get("message_type") == "snapshot":
                        info = x
                    elif x.get("path") and x["path"] != path:
                        entries.append({"name": x["name"], "path": x["path"], "type": x.get("type"),
                                        "size": x.get("size"), "mtime": x.get("mtime")})
                entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))
        if p.returncode != 0:
            err = last_lines(p.stderr)
    except Exception as e:
        err = str(e)
    crumbs, acc = [], ""
    for part in [x for x in path.split("/") if x]:
        acc += "/" + part
        crumbs.append((part, acc))
    src = tag_dec(next((t[4:] for t in info.get("tags") or [] if t.startswith("src:")), None))
    return render_template("browse.html", d=d, snap=snap, path=path, entries=entries, err=err, q=q,
                           crumbs=crumbs, src=src, when=info.get("time"), busy=activity.get(dest_id))


@app.post("/dest/<dest_id>/full-check")
def dest_full_check(dest_id):
    if job_locks.get(dest_id) and job_locks[dest_id].locked():
        flash("Something else is running for this bro. Try again when it is done.", "err")
    else:
        threading.Thread(target=checks.run_full_check, args=(dest_id,), daemon=True).start()
        flash("Full check started. It reads all your data at your bro, so it can take a long time.", "ok")
    return redirect(url_for("dest_snapshots", dest_id=dest_id))


@app.post("/dest/<dest_id>/repair")
def dest_repair(dest_id):
    d = get_dest(dest_id)
    if not d or not (d.get("full_check") or {}).get("packs"):
        flash("Nothing to repair. Run a full check first.", "err")
    elif job_locks.get(dest_id) and job_locks[dest_id].locked():
        flash("Something else is running for this bro. Try again when it is done.", "err")
    else:
        threading.Thread(target=checks.run_repair, args=(dest_id,), daemon=True).start()
        flash("Repair started. Follow it on the overview.", "ok")
    return redirect(url_for("index"))


@app.post("/report-now")
def report_now():
    if not notification_channels(settings()):
        flash("Set up ntfy or email first, and save.", "err")
    else:
        for ch, err in reports.send_report().items():
            flash(f"Report via {ch}: sent." if not err else f"Report via {ch}: failed ({err})", "err" if err else "ok")
    return redirect(url_for("settings_page"))


@app.post("/dest/<dest_id>/restore-test")
def dest_restore_test(dest_id):
    if job_locks.get(dest_id) and job_locks[dest_id].locked():
        flash("A backup or test to this bro is running. Try again when it is done.", "err")
    else:
        threading.Thread(target=checks.run_restore_test, args=(dest_id,), daemon=True).start()
        flash("Restore test started. The result shows on the overview.", "ok")
    return redirect(url_for("index"))


@app.get("/dest/<dest_id>/speed")
def dest_speed(dest_id):
    d = get_dest(dest_id)
    if not d:
        abort(404)
    busy = activity.get(dest_id)
    testing = bool(busy and busy.startswith(("Speed test", "Measuring")))
    return render_template("speed.html", d=d, busy=busy, testing=testing, path=conn_paths.get(dest_id),
                           seconds=SPEED_SECONDS, s=settings())


@app.post("/dest/<dest_id>/speed")
def dest_speed_run(dest_id):
    if job_locks.get(dest_id) and job_locks[dest_id].locked():
        flash("A backup or seed to this bro is running. Try again when it is done.", "err")
        return redirect(url_for("dest_speed", dest_id=dest_id))
    threading.Thread(target=speed.run_speedtest, args=(dest_id,), daemon=True).start()
    time.sleep(0.3)
    return redirect(url_for("dest_speed", dest_id=dest_id))


# Changing these needs the current password: they decide where alerts (and their secrets) go, and how long
# old versions survive. A walk-up or a stolen session must not be able to redirect or silence them.
SENSITIVE_SETTINGS = ("ntfy_url", "ntfy_token", "smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password",
                      "mail_method", "mail_to", "mail_from", "m365_tenant", "m365_client_id", "m365_sender",
                      "m365_secret", "append_only", "retention", "ransomware_watch",
                      # silencing: no alerts, no report, no restore test means nobody notices that backups stopped
                      "alert_hours", "report_day", "alert_receivers", "restore_test")
ALERT_HOURS_MAX = 24 * 14


def _narrowed(before, s):
    """What a change leaves out of the backups from now on: folders removed (that still exist), patterns added,
    a lower size limit. Each of those needs the password too: no alarm notices a folder that is not sent."""
    out = []
    gone = [p for p in before.get("sources") or [] if os.path.isdir(p) and p not in s["sources"]]
    if gone:
        out.append("folders removed")
    if set(s["excludes"]) - set(before.get("excludes") or []):
        out.append("patterns added")
    old, new = float(before.get("exclude_larger_gb") or 0), s["exclude_larger_gb"]
    if new and (not old or new < old):
        out.append("lower size limit")
    return out


def _drop_moved_secrets(before, s, f):
    """A stored secret never follows its endpoint to a new server: without a new one it is removed."""
    dropped = []
    rules = (("ntfy_token", ("ntfy_url",), "ntfy token"), ("smtp_password", ("smtp_host", "smtp_user"), "mail password"),
             ("m365_secret", ("m365_tenant", "m365_client_id"), "Microsoft 365 client secret"))
    for secret, endpoint, label in rules:
        moved = any(s.get(k) != before.get(k) for k in endpoint)
        if moved and before.get(secret) and not f.get(secret, "").strip():
            s[secret] = ""
            dropped.append(label)
    return dropped


@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    if request.method == "POST":
        f = request.form
        lan_before = lan.configured()
        pw_ok = bool(f.get("current_pw")) and _current_pw_ok()  # before taking the state lock
        try:
            with mutate() as st:
                s = st["settings"]
                before = dict(s)
                s["sources"] = nas.clean_sources(f.getlist("src"))
                s["backup_hour"] = min(23, max(0, int(f.get("backup_hour", 2))))
                s["retention"] = f.get("retention") if f.get("retention") in RETENTION_PRESETS else "standard"
                s["limit_upload_kib"] = round(max(0, float(f.get("limit_mbit", 0) or 0)) * 1e6 / 8 / 1024)  # restic wants KiB/s
                night = f.get("limit_night_mbit", "").strip()
                s["limit_night_kib"] = round(max(0, float(night)) * 1e6 / 8 / 1024) if night else -1
                s["night_start"] = min(23, max(0, int(f.get("night_start", 22))))
                s["night_end"] = min(23, max(0, int(f.get("night_end", 7))))
                s["ntfy_url"] = f.get("ntfy_url", "").strip()
                s["ntfy_token"] = f.get("ntfy_token", "").strip() or s["ntfy_token"]
                s["append_only"] = f.get("append_only") == "1"
                s["alert_hours"] = min(ALERT_HOURS_MAX, max(24, int(f.get("alert_hours", 72))))
                s["default_quota_gib"] = max(1, int(f.get("default_quota_gib", 500)))
                s["use_zfs_snapshots"] = f.get("use_zfs_snapshots") == "1"
                s["snapshot_max_age_h"] = min(24 * 14, max(1, int(f.get("snapshot_max_age_h", 26))))
                s["restore_test"] = f.get("restore_test") == "1"
                s["ransomware_watch"] = f.get("ransomware_watch") == "1"
                end = int(f.get("backup_end_hour", -1))
                s["backup_end_hour"] = end if 0 <= end <= 23 and end != s["backup_hour"] else -1
                s["smtp_host"] = f.get("smtp_host", "").strip()
                s["smtp_port"] = min(65535, max(1, int(f.get("smtp_port") or 587)))
                s["smtp_security"] = f.get("smtp_security") if f.get("smtp_security") in SMTP_SECURITY else "starttls"
                s["smtp_user"] = f.get("smtp_user", "").strip()
                if f.get("smtp_password_clear") == "1":
                    s["smtp_password"] = ""
                else:
                    s["smtp_password"] = f.get("smtp_password", "") or s["smtp_password"]
                s["mail_method"] = "m365" if f.get("mail_method") == "m365" else "smtp"
                for k in ("m365_tenant", "m365_client_id", "m365_sender"):
                    s[k] = f.get(k, s.get(k, "")).strip()
                if f.get("m365_secret_clear") == "1":
                    s["m365_secret"] = ""
                else:
                    s["m365_secret"] = f.get("m365_secret", "").strip() or s["m365_secret"]
                exp = f.get("m365_secret_expires", s.get("m365_secret_expires", "")).strip()
                if exp and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp):
                    raise ValueError("the expiry date of the client secret must be a date")
                s["m365_secret_expires"] = exp
                if s["mail_method"] == "m365":
                    problem = m365.check_fields(s["m365_tenant"], s["m365_client_id"], s["m365_sender"])
                    if problem:
                        raise ValueError(problem)
                s["mail_from"] = f.get("mail_from", "").strip()
                s["mail_to"] = f.get("mail_to", "").strip()
                s["exclude_defaults"] = f.get("exclude_defaults") == "1"
                pats = [x.strip() for x in f.get("excludes", "").splitlines() if x.strip()]
                if len(pats) > 200 or any(len(x) > 300 for x in pats):
                    raise ValueError("Too many or too long exclusion patterns")
                s["excludes"] = pats
                s["exclude_larger_gb"] = max(0.0, float(f.get("exclude_larger_gb") or 0))
                rd = int(f.get("report_day", 0))
                s["report_day"] = rd if -1 <= rd <= 6 else 0
                s["alert_receivers"] = f.get("alert_receivers") == "1"
                s["update_check"] = f.get("update_check") == "1"
                if "lan_addrs" in f:
                    good, bad = lan.parse_addrs(f.get("lan_addrs"))
                    if bad:
                        raise ValueError("not a usable address on your network: " + ", ".join(bad[:3]))
                    if good != lan.configured(s):
                        s["lan_addrs"] = good  # until then the address the installer passed in stays in use
                nas_root = os.path.realpath(NAS_DIR) + os.sep
                s["sqlite_dbs"] = sorted({p for p in f.getlist("sqlite_db")
                                          if os.path.realpath(p).startswith(nas_root) and os.path.isfile(p)})
                if s["mail_to"] and not re.fullmatch(r"[^@\s,]+@[^@\s,]+(\s*,\s*[^@\s,]+@[^@\s,]+)*", s["mail_to"]):
                    raise ValueError("The email address to send to does not look right")
                dropped = _drop_moved_secrets(before, s, f)
                changed = [k for k in SENSITIVE_SETTINGS if s.get(k) != before.get(k)] + _narrowed(before, s)
                if changed and not pw_ok:
                    raise ValueError("changing notifications and alerts, leaving folders out, or how backups are kept "
                                     "needs your current password (field next to Save), or there were too many wrong "
                                     "attempts")
                if changed:
                    log.info("Sensitive settings changed: %s", ", ".join(changed))
            flash("Settings saved." + (f" The saved {' and '.join(dropped)} was removed because the server changed: "
                                       "enter it again." if dropped else ""), "ok")
            if lan.configured() != lan_before:  # tell the bros the new way in now, not at the next slow loop
                threading.Thread(target=peers.keep_in_touch, daemon=True).start()
        except ValueError as e:
            flash(f"Not saved: {e}", "err")
        return redirect(url_for("settings_page"))
    st = load_state()
    return render_template("settings.html", s=st["settings"], folders=nas.list_folders(), ub=urbackup.status(st),
                           lan_addrs=lan.configured(st["settings"]),
                           excluded=nas.find_self_in_nas(), presets=RETENTION_PRESETS, plan=backup.backup_plan(),
                           rc=st["recovery"], dests=st["destinations"], default_excludes=DEFAULT_EXCLUDES,
                           weekdays=WEEKDAYS, db_scan=st.get("db_scan") or {}, dump_results=st.get("dump_results") or {},
                           db_choices=sorted(set(st["settings"].get("sqlite_dbs") or []) |
                                             {x["path"] for x in (st.get("db_scan") or {}).get("sqlite", [])}))


def process_overview():
    out = []
    for key, pr in sorted(procs.procs.items()):
        out.append({"key": key, "alive": pr.alive(), "restarts": pr.fails,
                    "started": iso(datetime.datetime.fromtimestamp(pr.started, datetime.timezone.utc)) if pr.started else None,
                    "last": [redact_text(x) for x in pr.lines[-4:]]})
    return out


def tool_versions():
    out = {}
    for name, cmd in (("restic", [RESTIC, "version"]), ("dumbpipe", [DUMBPIPE, "--version"]),
                      ("rest-server", [REST_SERVER, "--version"])):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            out[name] = (r.stdout or r.stderr).strip().splitlines()[0][:120]
        except Exception as e:
            out[name] = f"unavailable: {e}"
    return out







@app.get("/dest/<dest_id>/history")
def dest_history(dest_id):
    d = get_dest(dest_id)
    if not d:
        abort(404)
    hist = d.get("history") or []
    recent = hist[-60:]
    graphs = [("Data sent per backup", charts.bars(recent, "added", human_bytes, "Data sent per backup")),
              (f"Space used at {d['name']}", charts.line(hist, "usage", human_bytes, f"Space used at {d['name']}")),
              ("Duration per backup", charts.bars(recent, "seconds", charts.duration_fmt, "Duration per backup"))]
    total_sent = sum(e.get("added") or 0 for e in hist)
    return render_template("history.html", d=d, hist=hist, graphs=graphs, total_sent=total_sent)

@app.post("/databases/scan")
def databases_scan():
    dumps.scan_in_background()
    flash("Looking for databases in your folders. Refresh this page in a moment.", "ok")
    return redirect(url_for("settings_page") + "#databases")

# ---------------------------------------------------------------- security page
def _current_pw_ok():
    """The current password, asked again for sensitive changes. Counts against the same lockout as the login."""
    addr = request.remote_addr or "?"
    if auth.locked_for(addr):
        return False
    if check_ui_password(request.form.get("current_pw", ""), settings()["pw_hash"]):
        return True
    auth.register_fail(addr)
    return False


def _code_ok():
    """The code from the authenticator app: one code, one use, checked and used up under the state lock."""
    with mutate() as st:
        ss = st["settings"]
        step = auth.totp_counter_for(ss.get("totp_secret"), request.form.get("code", ""), int(ss.get("totp_last", -1)))
        if step is not None:
            ss["totp_last"] = step
    if step is None:
        auth.register_fail(request.remote_addr or "?")
    return step is not None


def _reauth_ok():
    """For what cannot be undone: the current password, plus a fresh code when two-step login is on.
    The password comes first, so a wrong password never uses up a code."""
    return _current_pw_ok() and (not auth.two_step_on() or _code_ok())


def _reauth_failed(where):
    flash("Not done: password" + (" or code" if auth.two_step_on() else "") + " not correct, "
          "or too many wrong attempts.", "err")
    return redirect(where)


@app.get("/security")
def security_page():
    s = settings()
    pending = vault().get("totp_pending")
    uri = auth.totp_uri(pending, s["name"]) if pending else None
    return render_template("security.html", two_step=bool(s.get("totp_secret")), pending=pending, uri=uri,
                           qr=auth.qr_svg(uri) if uri else None, idle_min=auth.IDLE_TIMEOUT // 60,
                           max_h=auth.MAX_SESSION // 3600, max_fails=auth.MAX_FAILS, window_min=auth.FAIL_WINDOW // 60)


@app.post("/security/password")
def security_password():
    f = request.form
    if not _current_pw_ok():
        flash("Your current password is not correct (or too many attempts: wait 15 minutes).", "err")
    elif len(f.get("new_pw", "")) < 10:
        flash("The new password needs at least 10 characters.", "err")
    elif f.get("new_pw") != f.get("new_pw2"):
        flash("The two new passwords are not the same.", "err")
    else:
        with mutate() as st:
            st["settings"]["pw_hash"] = hash_ui_password(f["new_pw"])
        end_other_sessions()
        log.info("Password of the web page changed")
        flash("Password changed. Other devices are logged out.", "ok")
    return redirect(url_for("security_page"))


@app.post("/security/two-step/start")
def two_step_start():
    if not _current_pw_ok():
        flash("Your current password is not correct (or too many attempts: wait 15 minutes).", "err")
    else:
        vault()["totp_pending"] = auth.new_totp_secret()
    return redirect(url_for("security_page"))


@app.post("/security/two-step/confirm")
def two_step_confirm():
    pending = vault().get("totp_pending")
    step = auth.totp_counter_for(pending, request.form.get("code", "")) if pending else None
    if step is None:
        flash("That code does not match. Check the time on your phone and try the next code.", "err")
        return redirect(url_for("security_page"))
    with mutate() as st:
        st["settings"].update(totp_secret=pending, totp_last=step)
    vault().pop("totp_pending", None)
    end_other_sessions()
    log.info("Two-step login turned on")
    flash("Two-step login is on. From now on you also need a code from your app to log in.", "ok")
    return redirect(url_for("security_page"))


@app.post("/security/two-step/cancel")
def two_step_cancel():
    vault().pop("totp_pending", None)
    return redirect(url_for("security_page"))


@app.post("/security/two-step/off")
def two_step_off():
    if not (_current_pw_ok() and _code_ok()):  # the code is used up, like at the login
        flash("Password or code not correct.", "err")
    else:
        with mutate() as st:
            st["settings"].update(totp_secret="", totp_last=-1)
        log.warning("Two-step login turned off")
        flash("Two-step login is off.", "ok")
    return redirect(url_for("security_page"))

# The pages in selfcheck.py register themselves on `app` when imported.
from . import selfcheck  # noqa: E402,F401
