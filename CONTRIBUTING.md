# Contributing to BRO Backup

Thanks for helping. BRO Backup is free software under the GNU Affero General Public License v3.0 or later (see `LICENSE`).

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by` line. With it you certify that you have the right to submit your contribution under this project's license, as described at https://developercertificate.org.

```
git commit -s -m "Short description"
```

This adds:

```
Signed-off-by: Your Name <you@example.com>
```

Pull requests without a sign-off are not merged.

## How we work

- Small, focused pull requests. One topic per PR.
- Start with `app/bro/README.md`: it explains which module does what, and the conventions.
- Run the unit tests: `pip install -r app/requirements.txt`, then
  `python -m unittest discover -s tests/unit -t tests/unit`. They need no Docker and take a few seconds.
- Test in the lab (`lab/lab.ps1`, checklist in `lab/TESTING.md`): two bros on one computer, no NAS needed.
  `python3 tests/lab/e2e.py` runs the automatic part on a fresh lab.
- GitHub Actions runs both on every push and pull request (`.github/workflows/test.yml`). A pull request
  is only merged when they pass. New behaviour comes with a unit test.
- Describe what you tested, and on which NAS (TrueNAS version, Synology DSM version).
- New files start with:
  ```
  # SPDX-License-Identifier: AGPL-3.0-or-later
  ```
- Do not report security problems as public issues. See `SECURITY.md`.
