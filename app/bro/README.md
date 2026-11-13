# The code, module by module

`app/main.py` only starts the app: `serve()` from `server.py`, or an emergency command
(`python main.py reset-two-step` or `reset-password`). Everything else lives in this package.

| Module | What it does |
|---|---|
| `core.py` | Paths, ports and constants, default settings, the state file (`load_state`, `mutate`), logging with redaction, small helpers, notifications (ntfy and email) |
| `server.py` | Startup (`init`, `serve`) and the emergency commands |
| `web.py` | The Flask app for the web page: login, setup wizard, overview, pairing pages, restore, browse, settings, security, history |
| `selfcheck.py` | Self-check, Logs page, diagnostics bundle, emergency key export (registers its pages on `web.app`) |
| `auth.py` | Login lockout, two-step login (TOTP, RFC 6238), session limits, QR code |
| `pair_api.py` | The small API that bros call through dumbpipe: accept a pairing, status, key copies, recovery, speed test |
| `pairing.py` | Invite and help codes, accepting a code, mutual pairing |
| `peers.py` | Staying in touch: check-ins (hello), sending a new address, reading tickets, linking the two directions of pairs made before v0.10, stopping with a bro (goodbye, tombstones), data that bros left behind |
| `receiving.py` | Logins on our own rest-server for the bros that back up here |
| `procs.py` | Background processes (rest-server, dumbpipe listeners and tunnels) and which network path a tunnel uses |
| `backup.py` | restic: what to back up and from where (ZFS snapshots), exclusions, upload limits by time of day, the backup window, backups, seeds, restores |
| `kept.py` | What a bro deletes is kept for a few days (hard links) and can be put back |
| `dumps.py` | SQLite dumps before a backup, finding databases, checking Immich's own dumps |
| `checks.py` | Restore test, full integrity check and repair |
| `speed.py` | Speed test and time estimates |
| `updates.py` | Once a day: is there a newer release on GitHub |
| `urbackup.py` | PCs and servers through UrBackup: finding its storage, reading every computer's last backup, notifications |
| `safety.py` | The safety score on the overview: points per part of the 3-2-1 rule, and what to do next |
| `probro.py` | Storing for many bros: references, usage per month and the CSV export, space requests |
| `pickup.py` | Picking up a backup at the bro's on a disk: Copy to disk, recovering and restoring from it, and the restore command for any PC |
| `alarm.py` | Ransomware alarm: judging every backup against the past of each folder, keeping old versions while the alarm is on |
| `space.py` | Hourly: is the disk under the data folder filling up, and did we promise bros more than is free |
| `reports.py` | Weekly report and alerts about bros that went silent |
| `charts.py` | The SVG charts on the history page |
| `nas.py` | Folders on the NAS, the external disk for seeds, importing a seed |
| `recovery.py` | Recovery code, encrypted key copies at bros, recovering after a crash |
| `scheduler.py` | The loop that starts everything on time |

## Conventions

- Settings and state live in one JSON file. Change them only inside `with mutate() as st:`.
- Modules import names from `core` directly, and other modules as a whole (`from . import backup`,
  then `backup.run_backup(...)`), so circular imports stay harmless.
- One job at a time per bro: every job takes `job_locks[dest_id]`.
- Anything that can hold a secret goes through `redact()` or `redact_text()` before it reaches a log
  or the diagnostics bundle. New secret settings go into `SECRET_KEYS` in `core.py`.
- The UI is in English. Error texts for people go through `friendly_error()`.

- The pair API answers 401 for an unknown login and 410 for a login we removed on purpose (a
  tombstone in `state["revoked"]`), so a bro can tell "you were stopped" from "something is wrong".
- A ticket from a bro is only accepted with the endpoint id of the one from pairing (`peers.same_identity`).

## Testing

- `tests/unit`: `python -m unittest discover -s tests/unit -t tests/unit`. Every test gets a fresh
  data folder (`_env.reset()`); the network is mocked (`procs.pair_call`).
- `tests/lab/e2e.py`: two real bros in the lab, see `lab/TESTING.md`.
- Both run in GitHub Actions on every push. Before a pull request, also try by hand in the lab at least:
  pairing, a backup, browsing and restoring a file, and the self-check.
