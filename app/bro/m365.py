# version : 1.0.0
# created by : JK and CF
# last edited : 08/11/2026
# Name : bro-backup (bro/m365.py)
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 the BRO Backup authors
"""Notification mail through Microsoft 365, with the Microsoft Graph API instead of SMTP.

Exchange Online turns Basic authentication for SMTP off by default at the end of 2026. Graph needs no
SMTP at all: an app registration with a client secret gets a token (client credentials) and sends with
POST /users/{mailbox}/sendMail. Limit the app to that one mailbox with RBAC for Applications in
Exchange Online (install/m365-mail-setup.ps1 does all of it); never give it the tenant-wide Mail.Send
consent in Entra ID, which would let it send as anyone.

Standalone on purpose: no imports from the rest of the app, so core can use it without a cycle."""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

LOGIN = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SEND = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"
SCOPE = "https://graph.microsoft.com/.default"
GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
MAIL_RE = re.compile(r"^[^@\s,;<>\"]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_token = {"key": None, "value": None, "exp": 0.0}


def check_fields(tenant, client_id, sender):
    """Returns the first problem with what was filled in, or None."""
    if not (GUID_RE.match(tenant or "") or DOMAIN_RE.match(tenant or "")):
        return "the tenant must be its ID or a domain such as contoso.onmicrosoft.com"
    if not GUID_RE.match(client_id or ""):
        return "the application (client) ID must look like 00000000-0000-0000-0000-000000000000"
    if not MAIL_RE.match(sender or ""):
        return "the mailbox to send from must be an email address"
    return None


def configured(s):
    return bool(s.get("m365_tenant") and s.get("m365_client_id") and s.get("m365_secret")
                and s.get("m365_sender") and s.get("mail_to"))


def _error_text(e):
    """What Microsoft said, in one line, without the request's details."""
    try:
        body = json.loads(e.read().decode("utf-8", "replace"))
    except (ValueError, OSError):
        return f"HTTP {e.code}"
    if isinstance(body.get("error"), dict):  # Graph
        return f"{body['error'].get('code', '')}: {body['error'].get('message', '')}".strip(": ")
    desc = str(body.get("error_description") or body.get("error") or f"HTTP {e.code}")
    return desc.splitlines()[0][:300]  # Entra: "AADSTS7000215: Invalid client secret provided. ..."


def token(s, opener=urllib.request.urlopen):
    key = (s["m365_tenant"], s["m365_client_id"], s["m365_secret"])
    if _token["key"] == key and time.time() < _token["exp"]:
        return _token["value"]
    data = urllib.parse.urlencode({"client_id": s["m365_client_id"], "client_secret": s["m365_secret"],
                                   "scope": SCOPE, "grant_type": "client_credentials"}).encode()
    url = LOGIN.format(tenant=urllib.parse.quote(s["m365_tenant"], safe=""))
    try:
        with opener(urllib.request.Request(url, data=data), timeout=20) as r:
            body = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Microsoft 365 refused the app login: {_error_text(e)}") from None
    _token.update(key=key, value=body["access_token"], exp=time.time() + int(body.get("expires_in", 3600)) - 120)
    return _token["value"]


def send(s, title, message, footer, opener=urllib.request.urlopen):
    to = [a.strip() for a in s["mail_to"].split(",") if a.strip()]
    payload = {"message": {"subject": title,
                           "body": {"contentType": "Text", "content": f"{message}\n\n-- \n{footer}"},
                           "toRecipients": [{"emailAddress": {"address": a}} for a in to]},
               "saveToSentItems": False}
    url = SEND.format(sender=urllib.parse.quote(s["m365_sender"], safe="@"))
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {token(s, opener)}",
                                          "Content-Type": "application/json"})
    try:
        with opener(req, timeout=20) as r:
            if r.status != 202:
                raise RuntimeError(f"Microsoft 365 answered HTTP {r.status} instead of 202")
    except urllib.error.HTTPError as e:
        hint = ""
        if e.code in (401, 403):
            _token.update(key=None)  # a new token next time
            hint = (". Check that the app may send as this mailbox (New-ManagementRoleAssignment). "
                    "A new permission can take up to 2 hours.")
        raise RuntimeError(f"Microsoft 365 did not send the mail: {_error_text(e)}{hint}") from None
