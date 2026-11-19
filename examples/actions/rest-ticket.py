"""A Pathwarden finding action: open a ticket for a finding in any JSON REST
API, check its status, and close it once the finding is fixed. It returns a
record, which Pathwarden saves on the finding. See rest-ticket.md beside it.

    [[action]]
    name = "desk"
    command = ["C:\\Program Files\\Python313\\python.exe", "C:\\Pathwarden\\actions\\rest-ticket.py"]
    base_url = "https://desk.example.com/api"   # the API, https://
    token_env = "PATHWARDEN_DESK_TOKEN"          # the variable that holds its token
    queue = "Identity"                           # optional

The API it expects (stub-desk.py beside it is one):

    GET   {base_url}/tickets?external_id=FINDING-ID   -> a list of tickets
    POST  {base_url}/tickets                          -> the new ticket
    GET   {base_url}/tickets/{id}                     -> the ticket
    PATCH {base_url}/tickets/{id}                     -> the ticket, changed

A ticket is a JSON object with at least `id`, and `number`, `status` and
`url` when it has them. The paths, the fields and the closed statuses are
settings, so most ticket systems fit; see rest-ticket.md.
"""

from __future__ import annotations

import urllib.parse

import pathwarden_action as pw

ACTIONS = [
    {
        "id": "open",
        "label": "Open a ticket",
        "description": "Opens a ticket for the team that fixes this finding.",
        "sends": "The finding's ID, title, severity, summary, affected objects and remediation, and your note, to the ticket system.",
        "inputs": [
            {"id": "note", "label": "Note for the team", "type": "textarea", "max": 2000},
            {"id": "urgency", "label": "Urgency", "type": "choice", "choices": ["Low", "Medium", "High"], "default": "Medium"},
        ],
        "once": True,
        "follow_ups": ["status", "close"],
    },
    {
        "id": "status",
        "label": "Check status",
        "for": "record",
        "sends": "The ticket's ID, to read it.",
    },
    {
        "id": "close",
        "label": "Close ticket",
        "description": "Closes the ticket, now that Pathwarden no longer finds this.",
        "for": "record",
        "when": ["fixed"],
        "sends": "The ticket's ID and a closing note.",
        "inputs": [
            {"id": "comment", "label": "Closing note", "type": "text", "default": "Fixed: Pathwarden no longer finds this."},
        ],
    },
]

CLOSED = "closed,resolved,done,cancelled"


class Desk:
    """The ticket system, as the settings describe it."""

    def __init__(self, req: pw.Request):
        self.req = req
        self.base = str(req.setting("base_url", required=True)).rstrip("/")
        pw.check_target(self.base)  # https://, or http:// to this computer
        self.token = req.secret("token", required=False)
        if req.setting("token_env") and not self.token:
            req.secret("token")  # names the variable that isn't set
        self.tickets = req.setting("tickets_path", "/tickets")
        self.ticket = req.setting("ticket_path", "/tickets/{id}")
        self.queue = req.setting("queue")
        self.closed = {s.strip().lower() for s in str(req.setting("closed_statuses", CLOSED)).split(",") if s.strip()}

    def url(self, path: str, **values: str) -> str:
        for k, v in values.items():
            path = path.replace("{" + k + "}", urllib.parse.quote(str(v), safe=""))
        return self.base + path

    def call(self, method: str, url: str, body=None):
        return self.req.http(method, url, body=body, bearer=self.token).json()

    def record(self, ticket, *, kept=None, open_without_status: bool = True) -> dict:
        """The ticket as a record on the finding. A follow-up's record
        replaces the one saved, so `kept` (the record it ran on) gives
        whatever this answer doesn't. Without a status in the answer, the
        ticket is open as `open_without_status` says."""
        if not isinstance(ticket, dict) or not ticket.get(self.req.setting("id_field", "id")):
            raise pw.Failed("The ticket system's answer has no ticket ID.")

        def get(name):
            v = ticket.get(self.req.setting(f"{name}_field", name))
            return None if v is None or str(v).strip() == "" else str(v)

        kept = dict(kept or {})
        tid = get("id")
        number = get("number") or kept.get("number") or tid
        status = get("status") or kept.get("status")
        url = get("url")
        web = self.req.setting("web_url")  # e.g. https://desk.example.com/tickets/{number}
        if web:
            url = web.replace("{id}", urllib.parse.quote(tid, safe="")).replace("{number}", urllib.parse.quote(number, safe=""))
        if not url or pw.https_problem(url) is not None:
            url = kept.get("url")
        fields = dict(kept.get("fields") or {})
        if self.queue:
            fields["Queue"] = self.queue
        if get("status"):
            is_open = status.lower() not in self.closed
        else:
            is_open = open_without_status
        return pw.record(
            tid,
            kind=kept.get("kind") or "ticket",
            label=kept.get("label"),
            number=number,
            status=status,
            open=is_open,
            url=url,
            fields=fields,
        )


def description(req: pw.Request) -> str:
    f = req.finding
    parts = [f.get("summary") or f.get("title") or ""]
    affected = [a.get("name") or a.get("id") for a in f.get("affected") or [] if isinstance(a, dict)]
    if affected:
        shown = affected[:20]
        more = f" and {len(affected) - 20} more" if len(affected) > 20 else ""
        parts.append("Affected: " + ", ".join(shown) + more)
    if f.get("remediation"):
        parts.append("Remediation: " + f["remediation"])
    if req.inputs.get("note"):
        parts.append(f"Note from {req.requested_by.get('by') or 'the requester'}: {req.inputs['note']}")
    parts.append(f"Pathwarden finding {req.fingerprint}, run {req.run.get('run_id')}.")
    return "\n\n".join(p for p in parts if p)


def open_ticket(req: pw.Request):
    desk = Desk(req)
    f = req.finding
    title = f"Pathwarden {f.get('rule')}: {f.get('title')}"[:120]
    body = {
        "title": title,
        "description": description(req),
        "severity": f.get("severity"),
        "urgency": req.inputs.get("urgency"),
        "queue": desk.queue,
        "external_id": req.fingerprint,
    }
    if req.dry_run:
        # Everything but the calls: the settings are read and the ticket is built.
        return pw.ok(f"Dry run: would open \"{title}\" at {desk.base}.")
    # Reconcile by the finding's ID: never two open tickets for one finding.
    pw.progress("Looking for an open ticket for this finding")
    found = desk.call("GET", desk.url(desk.tickets) + "?external_id=" + urllib.parse.quote(req.fingerprint))
    for ticket in found if isinstance(found, list) else []:
        r = desk.record(ticket)
        if r["open"]:
            return pw.ok(f"{r['number']} is already open for this finding.", records=[r])
    pw.progress("Opening a ticket")
    r = desk.record(desk.call("POST", desk.url(desk.tickets), body))
    pw.progress(f"Opened {r['number']}")
    links = [pw.link("Open the ticket", r["url"])] if r.get("url") else []
    return pw.ok(f"Opened {r['number']}.", records=[r], links=links)


def record_id(req: pw.Request) -> str:
    if not req.record or not req.record.get("id"):
        raise pw.Failed("This runs on a ticket of the finding, and none was given.")
    return str(req.record["id"])


def status(req: pw.Request):
    desk = Desk(req)
    tid = record_id(req)
    if req.dry_run:
        return pw.ok(f"Dry run: would read ticket {tid}.")
    pw.progress(f"Reading ticket {tid}")
    # The record returned replaces the saved one: it carries every field.
    r = desk.record(
        desk.call("GET", desk.url(desk.ticket, id=tid)),
        kept=req.record,
        open_without_status=req.record.get("open") is True,
    )
    shown = f" is {r['status']}" if r.get("status") else (" is open" if r["open"] else " is closed")
    return pw.ok(f"{r['number']}{shown}.", records=[r])


def close(req: pw.Request):
    desk = Desk(req)
    tid = record_id(req)
    body = {"status": req.setting("close_status", "Closed"), "comment": req.inputs.get("comment") or ""}
    if req.dry_run:
        return pw.ok(f"Dry run: would close ticket {tid}.")
    if req.finding.get("status") != "fixed":
        raise pw.Failed("The finding isn't fixed, so its ticket stays open.")
    pw.progress(f"Closing ticket {tid}")
    # The record returned replaces the saved one: it carries every field.
    r = desk.record(desk.call("PATCH", desk.url(desk.ticket, id=tid), body), kept=req.record, open_without_status=False)
    return pw.ok(f"Closed {r['number']}.", records=[r])


if __name__ == "__main__":
    pw.main(ACTIONS, {"open": open_ticket, "status": status, "close": close})
