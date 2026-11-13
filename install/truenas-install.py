#!/usr/bin/env python3
# version : 1.2.0
# created by : JK and CF
# last edited : 13/11/2026
# Name : bro-backup (install/truenas-install.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
#
# Interactive installer for BRO Backup on TrueNAS SCALE 24.10 or newer.
# It uses TrueNAS's own API (midclt) to:
#   1. create a dataset for BRO Backup, with a quota
#   2. add a daily snapshot task for it
#   3. install the BRO Backup app
# Run it in the TrueNAS shell:  sudo python3 truenas-install.py
# Add --dry-run to only show what it would do.

import argparse
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import time

IMAGE = os.environ.get("BRO_IMAGE", "ghcr.io/j-kest/bro-backup:1")
APP_NAME = "bro-backup"
DATASET_NAME = "bro-backup"
MIDCLT = os.environ.get("BRO_MIDCLT", "midclt")
GIB = 1024 ** 3
SKIP_CHILDREN = {"ix-apps", ".ix-apps", "ix-applications", ".system", DATASET_NAME}

TTY = sys.stdout.isatty()
RED, GREEN, YELLOW, BOLD, END = ("\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[0m") if TTY else ("",) * 5


def ok(msg):
    if DRY and SETTING_UP:  # in a dry run nothing below step 4 really happens
        print(f"{YELLOW}• not done (dry run): {msg}{END}")
        return
    print(f"{GREEN}✔ {msg}{END}")


LIFECYCLE_LOG = "/var/log/app_lifecycle.log"


def lifecycle_hint():
    """What TrueNAS's own log says about the last failure of this app, in plain words."""
    try:
        with open(LIFECYCLE_LOG, errors="replace") as f:
            line = next((x for x in reversed(f.readlines()[-200:]) if f"'{APP_NAME}' app" in x), "")
    except OSError:
        return None
    if "unauthorized" in line or "denied" in line:
        return (f"TrueNAS may not download {IMAGE}: the image is not public (or does not exist). "
                "On GitHub: Packages, bro-backup, Package settings, Change visibility, Public.")
    if "port is already allocated" in line or "address already in use" in line:
        return "A port is already in use by another app. Run the installer again and choose another web port."
    if "bind source path does not exist" in line:
        return "A folder to mount does not exist. Check the pools you chose."
    if "toomanyrequests" in line:
        return "The image registry asked to slow down. Wait a few minutes and run the installer again."
    return f"TrueNAS says: {line.split(' app: ', 1)[-1].strip()[-300:]}" if line else None


def err(msg):
    print(f"{RED}✘ {msg}{END}")


def warn(msg):
    print(f"{YELLOW}! {msg}{END}")


def step(msg):
    print(f"\n{BOLD}{msg}{END}")


class ApiError(Exception):
    pass


DRY = False
SETTING_UP = False


def call(method, *args, write=False):
    """Call the TrueNAS API through midclt. Writes are skipped in --dry-run mode."""
    cmd = [MIDCLT, "call", method, *[json.dumps(a) if not isinstance(a, str) else a for a in args]]
    if DRY and write:
        print(f"  [dry-run] {method} {' '.join(cmd[3:])[:300]}")
        return None
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise ApiError((p.stderr or p.stdout).strip()[-800:])
    out = p.stdout.strip()
    try:
        return json.loads(out) if out else None
    except json.JSONDecodeError:
        return out


def wait_job(job_id, label):
    """Wait for a TrueNAS job to finish and show its progress."""
    if job_id is None:
        return None
    last = None
    while True:
        jobs = call("core.get_jobs", json.dumps([["id", "=", int(job_id)]]))
        if not jobs:
            raise ApiError(f"job {job_id} not found")
        job = jobs[0]
        pct = int((job.get("progress") or {}).get("percent") or 0)
        if TTY and pct != last:
            print(f"\r  {label}: {pct}%", end="", flush=True)
            last = pct
        if job["state"] == "SUCCESS":
            if TTY:
                print()
            return job.get("result")
        if job["state"] in ("FAILED", "ABORTED"):
            if TTY:
                print()
            raise ApiError(job.get("error") or job.get("exception") or job["state"])
        time.sleep(2)


def ask(question, default=None, choices=None):
    hint = f" [{default}]" if default not in (None, "") else ""
    while True:
        try:
            answer = input(f"{question}{hint}: ").strip()
        except EOFError:
            answer = ""
        answer = answer or ("" if default is None else str(default))
        if not choices or answer in choices:
            return answer
        err(f"Choose one of: {', '.join(choices)}")


def ask_yes(question, default=True):
    answer = ask(f"{question} (y/n)", "y" if default else "n", ["y", "n", "Y", "N", "yes", "no"])
    return answer.lower().startswith("y")


def ask_int(question, default, minimum=0):
    while True:
        answer = ask(question, default)
        if answer.isdigit() and int(answer) >= minimum:
            return int(answer)
        err(f"Enter a whole number of at least {minimum}")


def human(n):
    return f"{n / 1024 ** 4:.1f} TiB" if n >= 1024 ** 4 else f"{n / GIB:.0f} GiB"


def port_in_use(port):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def own_port(port):
    """True when that port belongs to BRO Backup itself (an update): then it is not taken."""
    try:
        out = subprocess.run(["docker", "ps", "--filter", f"name=ix-{APP_NAME}-", "--format", "{{.Ports}}"],
                             capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return f":{port}->" in out


def nas_ips():
    """IPv4 addresses of this NAS on your network (not loopback or link-local)."""
    ips = []
    try:
        for ip in call("interface.ip_in_use", json.dumps({"ipv4": True, "ipv6": False})) or []:
            a = str(ip.get("address", ""))
            if a and not a.startswith(("127.", "169.254.")) and a not in ips:
                ips.append(a)
    except ApiError:
        pass
    return ips


SETUP_CODE = secrets.token_urlsafe(12)  # only the link with this code opens the first-run setup


def compose(pool, nas_mounts, port, tz="UTC", lan_ips=()):
    vols = [f"      - /mnt/{pool}/{DATASET_NAME}:/data"]
    # rslave: ZFS mounts a snapshot on the host when it is first opened; without it that mount never
    # reaches the container and every snapshot looks empty there (seen on TrueNAS 25.10)
    vols += [f"      - {host}:/nas/{name}:ro,rslave" for host, name in nas_mounts]
    return "\n".join([
        "services:",
        f"  {APP_NAME}:",
        f"    image: {IMAGE}",
        "    restart: unless-stopped",
        "    init: true",
        "    cap_drop: [ALL]",  # only what the app needs: read every file, restore owners and times
        "    cap_add: [DAC_READ_SEARCH, DAC_OVERRIDE, CHOWN, FOWNER, FSETID]",
        '    security_opt: ["no-new-privileges:true"]',
        *(["    pull_policy: never"] if "/" not in IMAGE.split(":")[0] else []),  # locally built image
        "    environment:",
        f"      TZ: {tz}",
        f"      BRO_SETUP_CODE: \"{SETUP_CODE}\"",  # until the setup is done, only the link with this code opens it
        *([f"      BRO_LAN_ADDRS: \"{','.join(lan_ips[:4])}\""] if lan_ips else []),  # bros on your network: direct
        "    ports:",
        f"      - \"{port}:8484\"",
        "      - \"7841:7841/udp\"",
        "      - \"7842:7842/udp\"",
        "    volumes:",
        *vols,
        "",
    ])


def main():
    global DRY
    ap = argparse.ArgumentParser(description="Install BRO Backup on TrueNAS SCALE")
    ap.add_argument("--dry-run", action="store_true", help="only show what would happen")
    ap.add_argument("--image", help="use this image instead, e.g. a locally built bro-backup:1.1")
    ap.add_argument("--update", action="store_true",
                    help="only fetch the newest image and restart the app, without questions")
    opts = ap.parse_args()
    DRY = opts.dry_run
    global IMAGE
    if opts.image:
        IMAGE = opts.image
    if opts.update:
        return update_only()

    print(f"{BOLD}BRO Backup installer for TrueNAS SCALE{END}")
    print("Encrypted off-site backups to a friend's NAS. Nothing is changed until you confirm.\n")

    # ---------------------------------------------------------------- checks
    step("1/5  Checking this TrueNAS")
    if not shutil.which(MIDCLT):
        err("midclt not found. Run this in the shell of TrueNAS SCALE.")
        return 1
    try:
        version = call("system.version")
    except ApiError as e:
        err(f"Cannot talk to the TrueNAS API: {e}")
        err("Run it with sudo:  sudo python3 truenas-install.py")
        return 1
    digits = "".join(c if c.isdigit() or c == "." else " " for c in str(version)).split()
    major_minor = tuple(int(x) for x in (digits[0].split(".") + ["0"])[:2]) if digits else (0, 0)
    if major_minor < (24, 10):
        err(f"{version} is too old. BRO Backup needs TrueNAS SCALE 24.10 or newer (Docker apps).")
        return 1
    ok(f"{version}")

    pools = call("pool.query", json.dumps([]), json.dumps({"select": ["name", "status"]})) or []
    pools = [p["name"] for p in pools if p.get("status") in (None, "ONLINE")]
    if not pools:
        err("No healthy pool found. Create a pool first under Storage.")
        return 1
    free = {}
    for p in pools:
        ds = call("pool.dataset.query", json.dumps([["id", "=", p]]),
                  json.dumps({"select": ["available"], "extra": {"retrieve_children": False}})) or [{}]
        free[p] = int(((ds[0].get("available") or {}).get("parsed")) or 0)

    try:
        tz = (call("system.general.config") or {}).get("timezone") or "UTC"
    except ApiError:
        tz = "UTC"

    docker = call("docker.config") or {}
    apps_pool = docker.get("pool")
    if apps_pool:
        ok(f"Apps are enabled (apps pool: {apps_pool})")
    else:
        warn("Apps are not enabled yet on this TrueNAS.")

    # ---------------------------------------------------------------- questions
    step("2/5  A few questions")
    default_pool = max(pools, key=lambda p: free[p])
    print("Pools on this NAS:")
    for p in pools:
        print(f"  - {p}  ({human(free[p])} free)")
    pool = ask("Pool for BRO Backup (your bros' backups are stored here too)", default_pool, pools)
    dataset = f"{pool}/{DATASET_NAME}"

    quota = ask_int("Maximum space for your bros' backups, in GiB (0 = no limit)", 1000)
    snapshots = ask_yes("Take a daily snapshot of it, kept for 30 days? Recommended: protects your bros against ransomware")

    print("Which pools may BRO Backup read (read-only) to find the folders you want to protect?")
    visible = ask("Pools, separated by a space", " ".join(pools)).split()
    bad = [v for v in visible if v not in pools]
    if bad:
        err(f"Unknown pool(s): {', '.join(bad)}")
        return 1

    port = ask_int("Port for the web page", 8484, 1024)
    while port_in_use(port) and not own_port(port):
        warn(f"Port {port} is already in use on this NAS.")
        port = ask_int("Choose another port", port + 6, 1024)

    use_for_apps = False
    if not apps_pool:
        use_for_apps = ask_yes(f"Enable Apps on pool '{pool}'? (needed for BRO Backup)")
        if not use_for_apps:
            err("Enable Apps first under Apps > Configuration > Choose Pool, then run this again.")
            return 1

    existing_ds = call("pool.dataset.query", json.dumps([["id", "=", dataset]])) or []
    existing_app = call("app.query", json.dumps([["name", "=", APP_NAME]])) or []

    # ---------------------------------------------------------------- summary
    step("3/5  This is what will happen")
    if use_for_apps:
        print(f"  - Enable Apps on pool {pool}")
    print(f"  - {'Keep the existing' if existing_ds else 'Create'} dataset {dataset}"
          + (f" with a quota of {quota} GiB" if quota and not existing_ds else ""))
    if snapshots:
        print(f"  - Daily snapshot of {dataset} at 01:30, kept for 30 days")
    print(f"  - {'Update' if existing_app else 'Install'} the app '{APP_NAME}' ({IMAGE})")
    for v in visible:
        print(f"      reads /mnt/{v} (read-only)")
    print(f"      web page on port {port}, time zone {tz}")
    lan_ips = nas_ips()
    if lan_ips:
        print(f"      bros on your network connect directly to {', '.join(lan_ips[:4])} (UDP 7841 and 7842)")
    if not ask_yes("Continue?"):
        print("Nothing was changed.")
        return 0

    # ---------------------------------------------------------------- do it
    step("4/5  Setting up")
    global SETTING_UP
    SETTING_UP = True
    if DRY:
        warn("Dry run: the steps below are only shown, nothing is really changed.")
    try:
        if use_for_apps:
            job = call("docker.update", json.dumps({"pool": pool}), write=True)
            wait_job(job, "Enabling Apps")
            ok(f"Apps enabled on {pool}")

        if existing_ds:
            ok(f"Dataset {dataset} already exists, kept as it is")
        else:
            spec = {"name": dataset, "type": "FILESYSTEM", "share_type": "GENERIC"}
            if quota:
                spec["quota"] = max(quota * GIB + quota * GIB // 10, GIB)
            call("pool.dataset.create", json.dumps(spec), write=True)
            ok(f"Dataset {dataset} created" + (f" (quota {quota} GiB + 10%)" if quota else ""))

        if snapshots:
            tasks = call("pool.snapshottask.query", json.dumps([["dataset", "=", dataset]])) or []
            if tasks:
                ok("A snapshot task for this dataset already exists, kept as it is")
            else:
                call("pool.snapshottask.create", json.dumps({
                    "dataset": dataset, "recursive": False, "lifetime_value": 30, "lifetime_unit": "DAY",
                    "naming_schema": "bro-%Y-%m-%d_%H-%M", "enabled": True,
                    "schedule": {"minute": "30", "hour": "1", "dom": "*", "month": "*", "dow": "*"}}),
                    write=True)
                ok("Daily snapshot task added")

        mounts = [(f"/mnt/{v}", v) for v in visible]
        install_app(existing_app, pool, mounts, port, visible, tz)
    except ApiError as e:
        err(f"Stopped: {e}")
        hint = lifecycle_hint()
        if hint:
            err(hint)
        err("Whatever was already created stays. You can safely run this installer again.")
        return 1

    # ---------------------------------------------------------------- done
    step("5/5  Done")
    if DRY:
        print("Dry run finished: nothing was changed. Run the same command without --dry-run to install.")
        return 0
    ips = nas_ips()
    urls = [f"http://{ip}:{port}/setup?code={SETUP_CODE}" for ip in ips] or \
        [f"http://<ip-of-your-nas>:{port}/setup?code={SETUP_CODE}"]
    ok("BRO Backup is installed.")
    print(f"\nOpen {BOLD}{urls[0]}{END} in your browser" + (f" (or {', '.join(urls[1:])})" if len(urls) > 1 else "") + ".")
    print("Only this link opens the first setup, so nobody else on your network can set the password first.")
    print("The web page walks you through the rest: a name, a password, the folders to protect,")
    print("and your recovery code. Keep that code safe, outside this NAS.")
    print("(Already set up? Then the code does nothing: just log in as usual.)")
    return 0


def image_version(image):
    """The BRO Backup version inside a local image (the label the build puts on it), or None."""
    try:
        p = subprocess.run(["docker", "image", "inspect", image, "--format",
                            '{{index .Config.Labels "org.opencontainers.image.version"}}'],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    v = p.stdout.strip()
    return v if p.returncode == 0 and v and v != "<no value>" else None


def running_image():
    """The image the app uses now, from TrueNAS's view of it."""
    apps = call("app.query", json.dumps([["name", "=", APP_NAME]]),
                json.dumps({"extra": {"retrieve_config": False}})) or []
    images = ((apps[0].get("active_workloads") or {}).get("images") or []) if apps else []
    return apps, (images[0] if images else None)


def pull_and_redeploy():
    """Fetch the newest image for the tag and start the app on it. TrueNAS's own update keeps an image
    it already has under the same tag, so an update without this stays on the old version."""
    job = call("app.pull_images", APP_NAME, json.dumps({"redeploy": True}), write=True)
    wait_job(job, "Fetching the newest image and restarting")


def update_only():
    print(f"{BOLD}BRO Backup: update{END}")
    if not shutil.which(MIDCLT):
        err("midclt not found. Run this in the shell of TrueNAS SCALE.")
        return 1
    try:
        apps, image = running_image()
        if not apps:
            err(f"The app '{APP_NAME}' is not installed. Run this installer without --update first.")
            return 1
        before = image_version(image) if image else None
        if image and "/" not in image.split(":")[0]:
            warn(f"The app uses a locally built image ({image}): build the new one first, then run "
                 f"this installer with --image again.")
            return 1
        pull_and_redeploy()
    except ApiError as e:
        err(f"Stopped: {e}")
        hint = lifecycle_hint()
        if hint:
            err(hint)
        return 1
    after = image_version(image) if image else None
    if DRY:
        return 0
    if before and after and before == after:
        ok(f"Already the newest version: {after}")
    else:
        ok(f"Updated{f' from {before}' if before else ''} to {after or 'the newest version'}")
    return 0


def install_app(existing_app, pool, mounts, port, visible, tz):
    """Install or update the app. If TrueNAS refuses a pool root as a host path, fall back to its datasets."""
    for attempt in ("pools", "datasets"):
        cfg = compose(pool, mounts, port, tz, nas_ips())
        try:
            if existing_app:
                job = call("app.update", APP_NAME, json.dumps({"custom_compose_config_string": cfg}), write=True)
                wait_job(job, "Updating the app")
                if "/" in IMAGE.split(":")[0]:  # from a registry: make sure the newest image for the tag runs
                    pull_and_redeploy()
                ok(f"App '{APP_NAME}' updated" + (f" to {image_version(IMAGE)}" if image_version(IMAGE) else ""))
            else:
                job = call("app.create", json.dumps({"app_name": APP_NAME, "custom_app": True,
                                                     "custom_compose_config_string": cfg}), write=True)
                wait_job(job, "Installing the app (downloading the image can take a minute)")
                ok(f"App '{APP_NAME}' installed")
            if DRY:
                print("  [dry-run] compose that would be used:\n" + "\n".join("    " + x for x in cfg.splitlines()))
            return
        except ApiError as e:
            if attempt == "datasets" or "path" not in str(e).lower():
                raise
            warn("TrueNAS does not accept a whole pool as a folder for the app. Using its datasets instead.")
            mounts = []
            for v in visible:
                kids = call("pool.dataset.query", json.dumps([["pool", "=", v]]),
                            json.dumps({"select": ["id", "mountpoint"], "extra": {"retrieve_children": False}})) or []
                for k in kids:
                    parts = k["id"].split("/")
                    if len(parts) == 2 and parts[1] not in SKIP_CHILDREN and k.get("mountpoint"):
                        mounts.append((k["mountpoint"], f"{v}/{parts[1]}"))
            if not mounts:
                raise ApiError("No datasets found to make readable. Create a dataset for your data first.")
            for host, _ in mounts:
                print(f"      reads {host} (read-only)")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nStopped. Nothing more was changed.")
        sys.exit(130)
