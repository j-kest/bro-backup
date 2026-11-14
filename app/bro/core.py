# version : 1.3.1
# created by : JK and CF
# last edited : 14/11/2026
# Name : bro-backup (bro/core.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Settings, state, paths, logging and small helpers shared by every part."""

import base64
import datetime
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import smtplib
import urllib.parse
import ssl
import threading
import urllib.error
import urllib.request
from collections import deque
from contextlib import contextmanager
from email.message import EmailMessage

VERSION = "1.3.1"
# AGPL-3.0 section 13: users interacting over a network must be able to get the source.
# Change this when you run a modified version.
SOURCE_URL = os.environ.get("SOURCE_URL", "https://github.com/j-kest/bro-backup")

# ---------------------------------------------------------------- paths and ports
DATA_DIR = os.environ.get("DATA_DIR", "/data")
NAS_DIR = os.environ.get("NAS_DIR", "/nas")
SEED_MOUNT = os.environ.get("SEED_MOUNT", "/seed")   # optional: external disk
CONFIG_DIR = os.path.join(DATA_DIR, "config")
RECEIVE_DIR = os.path.join(DATA_DIR, "receive")
RESTORE_DIR = os.path.join(DATA_DIR, "restore")
IMPORT_DIR = os.path.join(DATA_DIR, "import")
ESCROW_DIR = os.path.join(CONFIG_DIR, "escrow")
STATE_FILE = os.path.join(CONFIG_DIR, "state.json")
HTPASSWD = os.path.join(RECEIVE_DIR, ".htpasswd")

UI_PORT = int(os.environ.get("UI_PORT", "8484"))
PAIR_PORT = int(os.environ.get("PAIR_PORT", "8485"))
REST_PORT = int(os.environ.get("REST_PORT", "8000"))
IROH_DATA_PORT = int(os.environ.get("IROH_DATA_PORT", "7841"))
IROH_PAIR_PORT = int(os.environ.get("IROH_PAIR_PORT", "7842"))
SLOW_LOOP_SECONDS = int(os.environ.get("SLOW_LOOP_SECONDS", "600"))  # seed status, key copies, pending

RESTIC = os.environ.get("RESTIC_BIN", "restic")
REST_SERVER = os.environ.get("REST_SERVER_BIN", "rest-server")
DUMBPIPE = os.environ.get("DUMBPIPE_BIN", "dumbpipe")

GIB = 1024 ** 3
CODE_DAYS = 7
SEED_MARKER = "bro-seed.json"
DATA_MARKER = ".bro-backup-data"  # any folder containing this file is never backed up
SKIP_DIRS = {"ix-apps", ".ix-apps", "ix-applications", ".system", "lost+found", ".zfs"}
RETENTION_PRESETS = {
    "short": ["--keep-daily", "7", "--keep-weekly", "4"],
    "standard": ["--keep-daily", "7", "--keep-weekly", "4", "--keep-monthly", "12"],
    "long": ["--keep-daily", "14", "--keep-weekly", "8", "--keep-monthly", "24", "--keep-yearly", "5"],
}
LEGACY_RETENTION = {"kort": "short", "standaard": "standard", "lang": "long"}  # v0.3 values
DEFAULT_SETTINGS = {"name": "", "pw_hash": "", "sources": [], "backup_hour": 2,
                    "retention": "standard", "limit_upload_kib": 0, "ntfy_url": "",
                    "ntfy_token": "", "append_only": False, "alert_hours": 72,
                    "default_quota_gib": 500, "use_zfs_snapshots": True, "snapshot_max_age_h": 26,
                    "restore_test": True, "backup_end_hour": -1, "totp_secret": "", "totp_last": -1, "sqlite_dbs": [], "limit_night_kib": -1, "night_start": 22, "night_end": 7,
                    "recv_limit_kib": 0, "recv_limit_night_kib": -1, "keep_deleted_days": 7,
                    "smtp_host": "", "smtp_port": 587, "smtp_security": "starttls", "smtp_user": "",
                    "smtp_password": "", "mail_from": "", "mail_to": "",
                    "exclude_defaults": True, "excludes": [], "exclude_larger_gb": 0,
                    "report_day": 0, "alert_receivers": True, "update_check": True, "ransomware_watch": True,
                    "lan_addrs": None, "mail_method": "smtp", "m365_tenant": "", "m365_client_id": "",
                    "m365_secret": "", "m365_sender": "", "m365_secret_expires": ""}
# Junk most people never want in a backup: OS thumbnails and trash, Synology system folders,
# Office lock files and temporary files
DEFAULT_EXCLUDES = ["Thumbs.db", "desktop.ini", ".DS_Store", "._*", "@eaDir", "#recycle", "#snapshot",
                    ".Trash-*", ".recycle", "~$*", "*.tmp", "*.part", "*.crdownload",
                    "urbackup_tmp_files"]
REPORT_HOUR = 9  # weekly report goes out at 09:00 local time
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
PACK_REPAIR_RE = re.compile(r"restic repair packs ((?:[0-9a-f]{64}\s*)+)")
SMTP_SECURITY = ("starttls", "ssl", "none")
# default iroh relays used by dumbpipe (only used by the self-check to test reachability)
IROH_RELAYS = ("euc1-1.relay.n0.iroh.link", "use1-1.relay.n0.iroh.link", "usw1-1.relay.n0.iroh.link",
               "aps1-1.relay.n0.iroh.link")
IROH_DNS = "dns.iroh.link"
SEED_MODES = ("seeding", "seed_ready", "seed_error")
PAUSED_MODES = SEED_MODES + ("hold", "revoked")  # hold = paused after a recovery, revoked = the bro stopped
RC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no I, O, 0, 1: nothing to confuse
SNAP_TIME_RE = re.compile(r"(\d{4})-?(\d{2})-?(\d{2})[_T. -]?(\d{2})[-:.]?(\d{2})")
RESTORE_TEST_DAYS = 30
RESTORE_TEST_FILES = 20
RESTORE_TEST_MAX_BYTES = 200 * 1024 ** 2
SPEED_SECONDS = int(os.environ.get("SPEED_SECONDS", "10"))   # length of each speed test direction
SPEED_MAX_BYTES = 2 * 1024 ** 3                               # never transfer more than this per direction
SPEED_PART = 8 * 1024 ** 2   # the upload test sends parts of this size: the pair server accepts no larger request
# iroh logs which network path a connection uses; we only ask dumbpipe for those events
PATH_LOG = "warn,iroh::_events::path=debug"
PATH_RE = re.compile(r"_events::path::selected.*?network_path=(Ip|Relay)\(([^)]*)\)")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
log = logging.getLogger("bro-backup")
logging.getLogger("werkzeug").setLevel(logging.WARNING)


class LogRing(logging.Handler):
    """Keeps the most recent log lines in memory for the Logs page."""
    def __init__(self, size=3000):
        super().__init__()
        self.lines = deque(maxlen=size)
        self.setFormatter(logging.Formatter(LOG_FORMAT))

    def emit(self, record):
        try:
            self.lines.append((record.levelno, redact_text(self.format(record))))
        except Exception:
            pass


SECRET_KEYS = {"metrics_pw", "password", "repo_password", "pw_hash", "pw_sha", "token", "help_token", "ntfy_token", "smtp_password", "m365_secret", "totp_secret",
               "data_secret", "pair_secret", "salt", "ct", "nonce", "htpasswd", "pw", "tok", "lk", "link_key"}
TICKET_KEYS = {"data_ticket", "pair_ticket", "dt", "pt", "peer_pt", "pushed", "helloed"}


def redact_text(text):
    """Remove anything secret-like from text that may end up in logs or a diagnostics bundle."""
    text = re.sub(r"\b(endpoint[a-z0-9]{10})[a-z0-9]{10,}", r"\1…", text or "")
    text = re.sub(r"(\b[a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s]+@", r"\1***@", text)  # user:password@ in any URL
    text = re.sub(r"\b(BRO1|BROH1)\.[A-Za-z0-9_-]{8,}", r"\1.***", text)
    return text


# Not secret like a password, but not for a diagnostics zip either: on ntfy.sh the topic name is the only
# secret, and addresses and tenant names say who you are. A support person never needs them.
PERSONAL_KEYS = {"mail_to", "mail_from", "smtp_user", "m365_sender", "m365_tenant", "m365_client_id"}


def _ntfy_host(v):
    """Only the scheme and server of the ntfy URL: no user:password@, no topic."""
    try:
        u = urllib.parse.urlsplit(str(v))
        host = u.hostname or ""
        if u.port:
            host += f":{u.port}"
    except ValueError:
        return "***"
    return f"{u.scheme}://{host}/***" if u.scheme and host else "***"


def redact(obj):
    if isinstance(obj, dict):
        return {k: ("***" if (k in SECRET_KEYS or k in PERSONAL_KEYS) and v else
                    _ntfy_host(v) if k == "ntfy_url" and v else
                    (str(v)[:18] + "…" if k in TICKET_KEYS and v else redact(v))) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    return redact_text(obj) if isinstance(obj, str) else obj


log_ring = LogRing()
logging.getLogger().addHandler(log_ring)

state_lock = threading.RLock()
job_locks = {}
activity = {}          # dest_id -> current action (sending)
recv_activity = {}     # user -> current action (receiving, e.g. import)
receive_stats = {}     # user -> {"usage", "last_seen", "snapshots"}
my_tickets = {}        # "data"/"pair" -> this NAS's ticket
dest_ports = {}        # dest_id -> local tunnel port
conn_paths = {}        # dest_id -> {"type": direct|lan|relay, "detail", "at"}
sources_size = {}      # cache: {"bytes", "at"}
direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never through a proxy


# ---------------------------------------------------------------- helpers
def now():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt):
    return dt.isoformat(timespec="seconds") if dt else None


def parse(s):
    return datetime.datetime.fromisoformat(s) if s else None


def human_bytes(n):
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def human_secs(s):
    s = int(s or 0)
    if s < 1:
        return "under a second"
    if s < 90:
        return f"{s} s"
    if s < 5400:
        return f"{s // 60} min"
    if s < 172800:
        return f"{s / 3600:.1f} h"
    return f"{s / 86400:.1f} days"


def local_time(s):
    if isinstance(s, str):
        s = re.sub(r"(\.\d{6})\d+", r"\1", s).replace("Z", "+00:00")  # restic returns nanoseconds
        try:
            s = datetime.datetime.fromisoformat(s)
        except ValueError:
            return s[:16]
    return s.astimezone().strftime("%Y-%m-%d %H:%M") if s else "-"


def sha256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def clean_name(value, maxlen=40):
    """A name that came from another bro: plain text only. No control characters or line breaks (fake
    log lines), bounded length, always a string (a list or number would break the pages that use it)."""
    if not isinstance(value, str):
        return ""
    value = re.sub(r"[\x00-\x1f\x7f\u2028\u2029\u202a-\u202e\u2066-\u2069]", " ", value)
    return re.sub(r"\s+", " ", value).strip()[:maxlen]


VERSION_RE = re.compile(r"^[0-9A-Za-z.+-]{1,32}$")


def int_or_none(v, lo=0, hi=10 ** 18):
    """A number from a bro, only when it really is a sane integer (a bro is not trusted for types)."""
    return v if isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi else None


def version_or_none(v):
    return v if isinstance(v, str) and VERSION_RE.match(v) else None


def tag_enc(v):
    """A folder name as a restic tag value: restic splits --tag on commas, so encode them (and %)."""
    return str(v).replace("%", "%25").replace(",", "%2C")


def tag_dec(v):
    return None if v is None else v.replace("%2C", ",").replace("%25", "%")


def slug(s, maxlen=32):
    return re.sub(r"[^a-z0-9-]+", "-", (s or "").lower()).strip("-")[:maxlen] or "bro"


def last_lines(text, n=6):
    return "\n".join([x for x in (text or "").strip().splitlines() if x][-n:])


def dir_size(path):
    total = 0
    for root, _dirs, files in os.walk(path):
        for fn in files:
            try:
                total += os.lstat(os.path.join(root, fn)).st_size
            except OSError:
                pass
    return total


def b64e(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ---------------------------------------------------------------- state
STATE_BAK = STATE_FILE + ".bak"


def _read_state():
    """state.json, or its previous version when it is missing or damaged (a crash or a full disk while
    writing). Only when neither exists is this a new install. When both are damaged we stop: starting the
    setup wizard over an existing install would lose every key."""
    errors = []
    for path in (STATE_FILE, STATE_BAK):
        try:
            with open(path) as f:
                st = json.load(f)
            if not isinstance(st, dict):
                raise ValueError("not an object")
            if path == STATE_BAK:
                log.error("state.json was missing or damaged (%s): using state.json.bak",
                                               "; ".join(errors) or "missing")
            return st
        except FileNotFoundError:
            errors.append(f"{os.path.basename(path)} missing")
        except (ValueError, UnicodeDecodeError) as e:
            errors.append(f"{os.path.basename(path)}: {e}")
    if all(x.endswith("missing") for x in errors):
        return {}
    raise RuntimeError("state.json and its copy are damaged (" + "; ".join(errors) + "). Restore it from a "
                       "ZFS snapshot of the bro-backup folder (config/state.json).")


def load_state():
    st = _read_state()
    st.setdefault("settings", {})
    for k, v in DEFAULT_SETTINGS.items():
        st["settings"].setdefault(k, v)
    st["settings"]["retention"] = LEGACY_RETENTION.get(st["settings"]["retention"], st["settings"]["retention"])
    for k, v in (("identity", {}), ("destinations", []), ("receivers", {}),
                 ("pending_accepts", []), ("recovery", {}), ("revoked", {}), ("pending_goodbyes", []),
                 ("pending_deletes", {})):
        st.setdefault(k, v)
    return st


def save_state(st):
    """Written to a new file, synced to disk, then swapped in. The version before stays as state.json.bak."""
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    if os.path.exists(STATE_FILE):  # the copy is a second name for the current file: state.json never disappears
        new_bak = STATE_BAK + ".new"
        try:
            if os.path.lexists(new_bak):
                os.remove(new_bak)
            os.link(STATE_FILE, new_bak)
            os.replace(new_bak, STATE_BAK)
        except OSError:
            shutil.copy2(STATE_FILE, STATE_BAK)
    os.replace(tmp, STATE_FILE)
    try:
        fd = os.open(os.path.dirname(STATE_FILE), os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


@contextmanager
def mutate():
    with state_lock:
        st = load_state()
        yield st
        save_state(st)


def settings():
    return load_state()["settings"]


def backups_paused(st=None):
    """The pause the user set ({"at", "until"}; until None = until he resumes), or None. An expired pause is none."""
    p = (st or load_state()).get("pause")
    if not p:
        return None
    until = parse(p.get("until"))
    if until and now() >= until:
        return None
    return p


def setup_done():
    s = settings()
    return bool(s["pw_hash"] and s["name"])


def get_dest(dest_id):
    return next((d for d in load_state()["destinations"] if d["id"] == dest_id), None)


def update_dest(dest_id, **fields):
    with mutate() as st:
        for d in st["destinations"]:
            if d["id"] == dest_id:
                d.update(fields)


def ensure_identity():
    with mutate() as st:
        st["identity"].setdefault("data_secret", secrets.token_hex(32))
        st["identity"].setdefault("pair_secret", secrets.token_hex(32))


def hash_ui_password(pw):
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1)
    return f"scrypt${salt.hex()}${h.hex()}"


def check_ui_password(pw, stored):
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1)
        return secrets.compare_digest(calc.hex(), h)
    except Exception:
        return False


def header_text(text):
    """A header value: as it is when it is plain ASCII, else RFC 2047 encoded (ntfy reads that), so a bro called
    Łukasz does not make the notification fail."""
    try:
        text.encode("ascii")
        return text
    except UnicodeEncodeError:
        return "=?UTF-8?B?" + base64.b64encode(text.encode()).decode() + "?="


def send_ntfy(s, title, message, priority="high"):
    headers = {"Title": header_text(title), "Priority": priority, "Tags": "floppy_disk"}
    if s["ntfy_token"]:
        headers["Authorization"] = f"Bearer {s['ntfy_token']}"
    urllib.request.urlopen(urllib.request.Request(s["ntfy_url"], data=message.encode(),
                                                  headers=headers), timeout=10)


def send_mail(s, title, message):
    if s.get("mail_method") == "m365":
        from . import m365  # Microsoft 365 via the Graph API: no SMTP, no Basic authentication
        return m365.send(s, title, message, f"BRO Backup on {s['name'] or 'your NAS'}")
    msg = EmailMessage()
    msg["Subject"] = title
    msg["From"] = s["mail_from"] or s["smtp_user"] or f"bro-backup@{slug(s['name']) or 'nas'}.local"
    msg["To"] = s["mail_to"]
    msg.set_content(f"{message}\n\n-- \nBRO Backup on {s['name'] or 'your NAS'}")
    port = int(s["smtp_port"] or (465 if s["smtp_security"] == "ssl" else 587))
    ctx = ssl.create_default_context()
    if s["smtp_security"] == "ssl":
        server = smtplib.SMTP_SSL(s["smtp_host"], port, timeout=20, context=ctx)
    else:
        server = smtplib.SMTP(s["smtp_host"], port, timeout=20)
    with server:
        if s["smtp_security"] == "starttls":
            server.starttls(context=ctx)
        if s["smtp_user"]:
            server.login(s["smtp_user"], s["smtp_password"])
        server.send_message(msg)


def notification_channels(s):
    out = []
    if s["ntfy_url"]:
        out.append("ntfy")
    if s.get("mail_method") == "m365":
        from . import m365
        if m365.configured(s):
            out.append("email")
    elif s["smtp_host"] and s["mail_to"]:
        out.append("email")
    return out


def notify(title, message, priority="high"):
    """Sends to every channel that is set up. Returns {channel: None (sent) or error text}."""
    log.warning("%s: %s", title, message)
    s = settings()
    result = {}
    for ch in notification_channels(s):
        try:
            send_ntfy(s, title, message, priority) if ch == "ntfy" else send_mail(s, title, message)
            result[ch] = None
        except Exception as e:
            result[ch] = str(e) or e.__class__.__name__
            log.error("%s notification failed: %s", ch, result[ch])
    return result


