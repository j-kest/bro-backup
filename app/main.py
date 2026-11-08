# version : 0.10
# created by : JK and CF
# last edited : 01/11/2026
# Name : bro-backup (main.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
#
# BRO Backup (Best Remote Online Backup): encrypted off-site backups to a friend's NAS.
# One container: the app manages restic (backups), rest-server (receiving) and dumbpipe/iroh
# (connectivity without accounts or port forwarding). Pairing takes a single code.
#
# The code lives in the package bro/. Start here: bro/README.md explains what is where.

import sys

from bro.server import cli, serve

if __name__ == "__main__":
    sys.exit(cli(sys.argv[1:])) if len(sys.argv) > 1 else serve()
