"""A helper for writing Pathwarden finding actions in Python.

A finding action is a program Pathwarden runs for one finding when someone
asks (docs/actions.md). This module speaks the protocol for you: it reads
the request, answers `describe`, calls your function for `run`, prints
progress lines, and writes a checked result to the file Pathwarden names.
An exception becomes a failed run with a plain message.

Python 3.9 or later, standard library only. Copy this file next to your
action, then:

    import pathwarden_action as pw

    ACTIONS = [{
        "id": "hello",
        "label": "Say hello",
        "sends": "Nothing: it only answers.",
    }]

    def hello(req):
        pw.progress("Saying hello")
        return pw.ok(f"Hello from {req.finding['fingerprint']}.")

    if __name__ == "__main__":
        pw.main(ACTIONS, {"hello": hello})

Everything here follows pathwarden.action-*.v1. The caps are the ones
Pathwarden applies (crates/pathwarden-core/src/actions.rs), so what this
module writes is never cut or refused on the other side.
"""

from __future__ import annotations

import ipaddress
import json
import os
import ssl
import sys
import traceback
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union

__all__ = [
    "Failed",
    "Request",
    "Response",
    "check_describe",
    "check_target",
    "https_problem",
    "clean_result",
    "failed",
    "link",
    "main",
    "ok",
    "progress",
    "record",
]

__version__ = "1.0.0"

REQUEST_SCHEMA = "pathwarden.action-request.v1"
DESCRIBE_SCHEMA = "pathwarden.action-describe.v1"
RESULT_SCHEMA = "pathwarden.action-result.v1"
REQUEST_ENV = "PATHWARDEN_ACTION_REQUEST"
RESULT_ENV = "PATHWARDEN_ACTION_RESULT"

# The caps Pathwarden applies (actions.rs MAX_* constants).
MAX_ACTIONS = 20
MAX_INPUTS = 20
MAX_ID = 40
MAX_LABEL = 80
MAX_DESCRIPTION = 300
MAX_SENDS = 500
MAX_CHOICES = 50
MAX_CHOICE = 100
TEXT_MAX = 200
TEXT_MAX_LIMIT = 1000
TEXTAREA_MAX = 2000
TEXTAREA_MAX_LIMIT = 4000
MAX_MESSAGE = 2000
MAX_FIELDS = 20
MAX_FIELD = 200
MAX_NAME = 60
MAX_RECORD_TEXT = 200
MAX_RECORDS = 5
MAX_LINKS = 5
MAX_URL = 2048
MAX_LINE_CHARS = 500

INPUT_TYPES = ("text", "textarea", "choice", "bool")
SEVERITIES = ("critical", "high", "medium", "low", "info")
CATEGORIES = ("attack_path", "hygiene")
STATES = ("open", "held", "accepted", "fixed")

Handler = Callable[["Request"], Any]


# --------------------------------------------------------------- results


class Failed(Exception):
    """Raise to end the run as failed with a plain message for the person
    who clicked: `raise pw.Failed("The desk said no: 403 Forbidden.")`.
    Any other exception fails the run too, with its type in the message and
    the traceback on stderr (Show details)."""


def ok(message: str = "", links: Iterable[dict] = (), records: Iterable[dict] = ()) -> dict:
    """A result that says the action worked."""
    return {"ok": True, "message": message, "links": list(links), "records": list(records)}


def failed(message: str, links: Iterable[dict] = (), records: Iterable[dict] = ()) -> dict:
    """A result that says the action didn't work."""
    return {"ok": False, "message": message, "links": list(links), "records": list(records)}


def link(label: str, url: str) -> dict:
    """A link the result card offers. It must be https://."""
    return {"label": label, "url": url}


def record(
    id: str,
    *,
    kind: Optional[str] = None,
    label: Optional[str] = None,
    number: Optional[str] = None,
    url: Optional[str] = None,
    status: Optional[str] = None,
    open: bool = False,
    fields: Optional[Mapping[str, Any]] = None,
) -> dict:
    """Something the action created or looks after, such as a ticket. It is
    saved on the finding. A follow-up returns the same `id` to update it;
    `open` says whether it is still open in the other system."""
    r: Dict[str, Any] = {"id": str(id), "open": bool(open)}
    for key, value in (("kind", kind), ("label", label), ("number", number), ("url", url), ("status", status)):
        if value is not None:
            r[key] = str(value)
    if fields:
        r["fields"] = dict(fields)
    return r


# ------------------------------------------------------------- progress


def _utf8_streams() -> None:
    # Pathwarden reads stdout and stderr as UTF-8; Windows pipes default to
    # the ANSI code page. Done once, before the handler runs, so whatever
    # it prints goes out as UTF-8 too.
    for out in (sys.stdout, sys.stderr):
        if hasattr(out, "reconfigure"):
            try:
                out.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
            except (ValueError, OSError):
                pass


# The values of the secrets read through `Request.secret`. They are taken
# out of every message, progress line and note, because what an action
# prints is saved on the finding and shared with the history.
_secrets: set = set()
HIDDEN = "[hidden]"
# Shorter values aren't taken out: they would replace ordinary text.
MIN_SECRET = 4


def _scrub(text: str) -> str:
    for value in sorted(_secrets, key=len, reverse=True):
        text = text.replace(value, HIDDEN)
    return text


def progress(line: str) -> None:
    """Prints one progress line. Pathwarden shows it while the action runs
    and keeps the latest 200, each cut to 500 characters."""
    for part in _scrub(str(line)).splitlines() or [""]:
        text = _clean(part, MAX_LINE_CHARS, lines=False)[0]
        if text:
            print(text, file=sys.stdout, flush=True)


def note(line: str) -> None:
    """Writes a line to stderr: kept for Show details, never shown as
    progress. Use it for what helps someone fix a failure."""
    print(_scrub(str(line)), file=sys.stderr, flush=True)


# --------------------------------------------------------------- request


class Response:
    """What `Request.http` got back."""

    def __init__(self, status: int, headers: Mapping[str, str], body: bytes):
        self.status = status
        self.headers = dict(headers)
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        if not self.body.strip():
            return None
        try:
            return json.loads(self.text)
        except ValueError as e:
            raise Failed(f"The answer wasn't JSON ({e}).") from None


class Request:
    """One request from Pathwarden, with its fields as attributes:

    - `kind`: "describe" or "run".
    - `action`: the ID of the action to run.
    - `inputs`: what the person typed or chose, by input ID, already
      checked against the inputs you described.
    - `dry_run`: True when the action must change nothing.
    - `settings`: the `[[action]]` block's other keys.
    - `run`: `run_id`, `domains`, `pathwarden`.
    - `finding`: the finding, as the event document has it, plus `guide`
      and `status` (open, held, accepted or fixed).
    - `record`: for a follow-up, the record it runs on; else None.
    - `requested_by`: `by` and `on`, the user and computer who asked.
    - `raw`: the whole request as it came.
    """

    def __init__(self, raw: Mapping[str, Any], env: Optional[Mapping[str, str]] = None):
        self.raw = dict(raw)
        self.env = dict(os.environ if env is None else env)
        self.kind: str = str(raw.get("kind") or "")
        self.action: str = str(raw.get("action") or "")
        self.inputs: Dict[str, Any] = dict(raw.get("inputs") or {})
        self.dry_run: bool = bool(raw.get("dry_run"))
        self.settings: Dict[str, Any] = dict(raw.get("settings") or {})
        self.run: Dict[str, Any] = dict(raw.get("run") or {})
        self.finding: Dict[str, Any] = dict(raw.get("finding") or {})
        self.record: Optional[Dict[str, Any]] = raw.get("record") or None
        self.requested_by: Dict[str, Any] = dict(raw.get("requested_by") or {})

    @property
    def fingerprint(self) -> str:
        """The finding's ID, e.g. PW-006-1bbba15126c6fc31. It stays the same
        on every run, so use it as the key in the other system."""
        return str(self.finding.get("fingerprint") or "")

    def setting(self, name: str, default: Any = None, *, required: bool = False) -> Any:
        """A setting of the `[[action]]` block. With `required`, a missing
        one fails the run with a message that names it."""
        value = self.settings.get(name)
        if value is None or value == "":
            if required:
                raise Failed(f"Set {name} in this action's settings.")
            return default
        return value

    def secret(self, name: str, *, required: bool = True) -> Optional[str]:
        """The value of the environment variable that setting `<name>_env`
        names. Secrets never go in the settings themselves: Pathwarden
        passes only the variables `*_env` settings name."""
        var = self.settings.get(f"{name}_env")
        if not var:
            if required:
                raise Failed(
                    f"Set {name}_env in this action's settings to the name of the environment variable that holds the {name}."
                )
            return None
        # A stray newline or space (common when a token is pasted) would
        # end up in a header, and an error quoting it would get past _scrub.
        value = (self.env.get(str(var)) or "").strip()
        if not value:
            if required:
                raise Failed(f"The environment variable {var} (named by {name}_env) isn't set for this account.")
            return None
        if len(value) >= MIN_SECRET:
            _secrets.add(value)
        return value

    def http(
        self,
        method: str,
        url: str,
        *,
        body: Any = None,
        bearer: Optional[str] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: float = 30,
    ) -> Response:
        """Sends one HTTPS request and returns the answer; an answer of 400
        or above fails the run, with the status in the message.

        - `body` is sent as JSON; `bearer` as `Authorization: Bearer ...`.
        - Certificates are checked against the system's trusted roots (on
          Windows, its certificate store), never turned off. The proxy
          variables are honoured.
        - http:// is refused, except to this computer (localhost,
          127.0.0.1, ::1), for a test server.
        - On a dry run, only GET and HEAD are sent; anything else fails the
          run, so a dry run can't change anything by mistake.
        - A redirect is followed only to the same scheme, host and port;
          one anywhere else fails the run, so the token isn't sent on.
        - Messages name only the scheme, host and port: a webhook's path
          or query may hold its key.
        """
        method = method.upper()
        check_target(url)
        if self.dry_run and method not in ("GET", "HEAD"):
            raise Failed(
                f"Dry run: {method} {_shown(url)} wasn't sent, because a dry run changes nothing. Return before sending it when req.dry_run is true."
            )
        data = None
        h = {"Accept": "application/json", "User-Agent": f"pathwarden-action/{__version__}"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            h["Content-Type"] = "application/json"
        if bearer:
            h["Authorization"] = f"Bearer {bearer}"
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        context = ssl.create_default_context()
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context), _SameOriginRedirect()
        )
        try:
            with opener.open(req, timeout=timeout) as r:
                return Response(r.status, r.headers, r.read())
        except urllib.error.HTTPError as e:
            text = e.read()[:2000].decode("utf-8", errors="replace")
            note(f"{method} {_shown(url)}: {e.code} {e.reason}\n{text}")
            raise Failed(f"{method} {_shown(url)} answered {e.code} {e.reason}.") from None
        except urllib.error.URLError as e:
            raise Failed(f"Couldn't reach {_shown(url)}: {e.reason}.") from None
        except OSError as e:
            raise Failed(f"Couldn't reach {_shown(url)}: {e}.") from None


def _shown(url: str) -> str:
    """`url` as messages show it: scheme://host[:port] only. A webhook's
    path (hooks.example.com/services/T0/B0/KEY) or query may hold its key,
    and a message is saved on the finding and shared."""
    try:
        p = urllib.parse.urlsplit(str(url))
        host = p.hostname or ""
        port = p.port
    except ValueError:
        return "that address"
    if not p.scheme or not host:
        return "that address"
    if ":" in host:
        host = f"[{host}]"
    return f"{p.scheme}://{host}" + (f":{port}" if port is not None else "")


def _origin(url: str) -> Tuple[str, str, Optional[int]]:
    p = urllib.parse.urlsplit(url)
    scheme = p.scheme.lower()
    port = p.port if p.port is not None else {"https": 443, "http": 80}.get(scheme)
    return scheme, (p.hostname or "").lower(), port


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    """Follows a redirect only to the same scheme, host and port. urllib
    would otherwise send Authorization and Cookie on to any address,
    https:// to http:// included."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = req.full_url
        newurl = urllib.parse.urljoin(old, newurl)
        try:
            same = _origin(newurl) == _origin(old)
        except ValueError:
            same = False
        if not same:
            raise Failed(
                f"{req.get_method()} {_shown(old)} answered {code}, a redirect to {_shown(newurl)}, which wasn't followed: "
                "a redirect is followed only to the same address. Set the address it redirects to."
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_target(url: str) -> None:
    p = urllib.parse.urlsplit(url)
    if p.scheme == "https" and p.hostname:
        return
    if p.scheme == "http" and p.hostname and _loopback(p.hostname):
        return
    raise Failed(f"{_shown(url)} must start with https:// (http:// only to this computer, for testing).")


# --------------------------------------------------------------- checks


def _clean(text: Any, cap: int, lines: bool) -> Tuple[str, bool]:
    """Text as Pathwarden keeps it: tabs as spaces, control and bidi
    characters dropped (line breaks kept when `lines`), trimmed, cut to
    `cap` characters with an ellipsis. And whether it was cut."""
    s = str(text).replace("\r\n", "\n").replace("\t", " ")
    s = "".join(
        c
        for c in s
        if (lines and c == "\n")
        or not (unicodedata.category(c) == "Cc" or c in _BIDI)
    ).strip()
    if len(s) <= cap:
        return s, False
    return s[: cap - 1] + "…", True


_BIDI = set("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")


def https_problem(url: Any) -> Optional[str]:
    """Why Pathwarden would leave `url` out of a result, or None."""
    if not isinstance(url, str):
        return "must be text"
    s = url.strip()
    if len(s.encode("utf-8")) > MAX_URL:  # in bytes, as Pathwarden counts
        return "is longer than 2,048 characters"
    if any(c.isspace() or unicodedata.category(c) == "Cc" or c in _BIDI for c in s):
        return "holds a space or a control character"
    if s[:8].lower() != "https://":
        return "must start with https://"
    authority = s[8:].split("/")[0].split("?")[0].split("#")[0]
    if "@" in authority:
        return "must not hold a user name or password"
    host, _, port = authority.rpartition(":")
    if not (port.isdigit() and host):
        host = authority
    if not host or any(c in host for c in '\\<>"'):
        return "has no host"
    return None


def clean_result(result: Any) -> Tuple[dict, List[str]]:
    """`result` as Pathwarden would keep it, and what was changed, in the
    words `pathwarden action check` uses. A plain string is a message that
    worked; None is "Done."."""
    notes: List[str] = []
    if result is None:
        result = ok()
    elif isinstance(result, str):
        result = ok(result)
    if not isinstance(result, Mapping):
        raise TypeError(f"an action must return pw.ok(...), pw.failed(...), a message or None, not {type(result).__name__}")
    out: Dict[str, Any] = {"schema": RESULT_SCHEMA, "ok": bool(result.get("ok", False))}
    message, cut = _clean(_scrub(result.get("message") or ""), MAX_MESSAGE, lines=True)
    if cut:
        notes.append(f"message is longer than {MAX_MESSAGE} characters; it was cut")
    out["message"] = message
    links = []
    for i, l in enumerate(list(result.get("links") or [])):
        if i >= MAX_LINKS:
            notes.append(f"links has more than {MAX_LINKS} links; the rest were left out")
            break
        label, cut = _clean((l or {}).get("label") or "", MAX_LABEL, lines=False)
        why = https_problem((l or {}).get("url"))
        if why:
            notes.append(f"links[{i}].url {why}; the link was left out")
            continue
        if not label:
            notes.append(f"links[{i}].label is missing")
            continue
        links.append({"label": label, "url": l["url"].strip()})
    out["links"] = links
    records = []
    seen = set()
    for i, r in enumerate(list(result.get("records") or [])):
        if i >= MAX_RECORDS:
            notes.append(f"records has more than {MAX_RECORDS} records; the rest were left out")
            break
        at = f"records[{i}]"
        rid, cut = _clean((r or {}).get("id") or "", MAX_RECORD_TEXT, lines=False)
        if not rid or cut:
            notes.append(f"{at}.id is missing or longer than {MAX_RECORD_TEXT} characters; the record was left out")
            continue
        if rid in seen:
            notes.append(f"{at}.id '{rid}' is there twice; the second was left out")
            continue
        seen.add(rid)
        # Only a real true is open, as Pathwarden reads it.
        is_open = r.get("open")
        if is_open is not None and not isinstance(is_open, bool):
            notes.append(f"{at}.open must be true or false, not {type(is_open).__name__}; it is read as false")
        kept: Dict[str, Any] = {"id": rid, "open": is_open is True}
        for key in ("kind", "label", "number", "status"):
            if r.get(key) is not None:
                text, cut = _clean(r[key], MAX_RECORD_TEXT, lines=False)
                if cut:
                    notes.append(f"{at}.{key} is longer than {MAX_RECORD_TEXT} characters; it was cut")
                kept[key] = text
        if r.get("url") is not None:
            why = https_problem(r["url"])
            if why:
                notes.append(f"{at}.url {why}; it was left out")
            else:
                kept["url"] = r["url"].strip()
        fields: Dict[str, str] = {}
        for j, (k, v) in enumerate(dict(r.get("fields") or {}).items()):
            if j >= MAX_FIELDS:
                notes.append(f"{at}.fields has more than {MAX_FIELDS} fields; the rest were left out")
                break
            name, cut = _clean(k, MAX_NAME, lines=False)
            if cut or not name or name in fields:
                notes.append(f"{at}.fields name '{name}' is empty, too long or there twice; it was left out")
                continue
            if isinstance(v, bool):
                v = "true" if v else "false"
            if not isinstance(v, (str, int, float)):
                notes.append(f"{at}.fields.{name} must be text; it was left out")
                continue
            text, cut = _clean(v, MAX_FIELD, lines=False)
            if cut:
                notes.append(f"{at}.fields.{name} is longer than {MAX_FIELD} characters; it was cut")
            fields[name] = text
        if fields:
            kept["fields"] = fields
        records.append(kept)
    out["records"] = records
    return out, notes


def _id_ok(s: Any) -> bool:
    return (
        isinstance(s, str)
        and 0 < len(s) <= MAX_ID
        and all(c in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in s)
    )


def check_describe(actions: Any) -> List[str]:
    """Problems with a list of actions, in the words `pathwarden action
    check` uses; empty when there are none. The helper runs this for every
    describe and writes what it finds to stderr."""
    p: List[str] = []
    if isinstance(actions, Mapping):
        actions = actions.get("actions")
    if not isinstance(actions, list) or not actions:
        return ["actions must be a list of at least one action"]
    if len(actions) > MAX_ACTIONS:
        p.append(f"actions has more than {MAX_ACTIONS} actions; the rest are left out")
    ids = [a.get("id") for a in actions if isinstance(a, Mapping)]
    record_ids = {a.get("id") for a in actions if isinstance(a, Mapping) and a.get("for") == "record"}
    for i, a in enumerate(actions[:MAX_ACTIONS]):
        at = f"actions[{i}]"
        if not isinstance(a, Mapping):
            p.append(f"{at} must be an object")
            continue
        if not _id_ok(a.get("id")):
            p.append(f"{at}.id must be lowercase letters, digits, - and _, at most {MAX_ID}")
        elif ids.count(a["id"]) > 1:
            p.append(f"{at}.id '{a['id']}' is there twice")
        for key, cap, required in (("label", MAX_LABEL, True), ("description", MAX_DESCRIPTION, False), ("sends", MAX_SENDS, True)):
            v = a.get(key)
            if v is None:
                if required:
                    p.append(
                        f"{at}.{key} is missing"
                        + (": say in plain words what leaves the computer" if key == "sends" else "")
                    )
            elif not isinstance(v, str):
                p.append(f"{at}.{key} must be text")
            elif len(v.strip()) > cap:
                p.append(f"{at}.{key} is longer than {cap} characters")
            elif required and not v.strip():
                p.append(f"{at}.{key} is empty")
        f = a.get("applies_to") or {}
        if not isinstance(f, Mapping):
            p.append(f"{at}.applies_to must be an object")
            f = {}
        if f.get("min_severity") is not None and str(f["min_severity"]).lower() not in SEVERITIES:
            p.append(f"{at}.applies_to.min_severity '{f['min_severity']}' isn't one of {', '.join(SEVERITIES)}")
        for c in f.get("categories") or []:
            if str(c).lower().replace("-", "_") not in CATEGORIES:
                p.append(f"{at}.applies_to.categories: '{c}' isn't one of attack_path, hygiene")
        for r in f.get("rules") or []:
            if not (isinstance(r, str) and r and all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in r)):
                p.append(f"{at}.applies_to.rules: '{r}' is not a rule ID such as PW-001")
        inputs = a.get("inputs") or []
        if len(inputs) > MAX_INPUTS:
            p.append(f"{at}.inputs has more than {MAX_INPUTS} inputs")
        input_ids = []
        for j, inp in enumerate(inputs):
            ia = f"{at}.inputs[{j}]"
            if not isinstance(inp, Mapping):
                p.append(f"{ia} must be an object")
                continue
            if not _id_ok(inp.get("id")):
                p.append(f"{ia}.id must be lowercase letters, digits, - and _")
            elif inp["id"] in input_ids:
                p.append(f"{ia}.id '{inp['id']}' is there twice")
            input_ids.append(inp.get("id"))
            if not isinstance(inp.get("label"), str) or not inp["label"].strip():
                p.append(f"{ia}.label is missing")
            t = inp.get("type")
            if t not in INPUT_TYPES:
                p.append(f"{ia}.type '{t}' isn't one of {', '.join(INPUT_TYPES)}")
                continue
            if "max" in inp and inp["max"] is not None:
                limit = {"text": TEXT_MAX_LIMIT, "textarea": TEXTAREA_MAX_LIMIT}.get(t)
                if limit is None:
                    p.append(f"{ia}.max is only for text and textarea inputs")
                elif not (isinstance(inp["max"], int) and not isinstance(inp["max"], bool) and 1 <= inp["max"] <= limit):
                    p.append(f"{ia}.max must be a whole number from 1 to {limit}")
            choices = inp.get("choices") or []
            if t == "choice":
                if not choices:
                    p.append(f"{ia}.choices must be a list of at least one choice")
                if len(choices) > MAX_CHOICES:
                    p.append(f"{ia}.choices has more than {MAX_CHOICES} choices")
                if len(set(map(str, choices))) != len(choices):
                    p.append(f"{ia}.choices has a choice twice")
                for c in choices:
                    if not isinstance(c, str) or not c.strip() or len(c.strip()) > MAX_CHOICE:
                        p.append(f"{ia}.choices: each must be text of 1 to {MAX_CHOICE} characters")
            d = inp.get("default")
            if d is not None:
                if t == "bool" and not isinstance(d, bool):
                    p.append(f"{ia}.default must be true or false")
                elif t == "choice" and d not in choices:
                    p.append(f"{ia}.default must be one of the choices")
                elif t in ("text", "textarea"):
                    cap = inp.get("max") or (TEXTAREA_MAX if t == "textarea" else TEXT_MAX)
                    if not isinstance(d, str) or len(d) > cap:
                        p.append(f"{ia}.default must be text no longer than max, without control characters")
        if a.get("once") is not None and not isinstance(a["once"], bool):
            p.append(f"{at}.once must be true or false")
        if a.get("for") not in (None, "record"):
            p.append(f"{at}.for {json.dumps(a['for'])} isn't \"record\", the only value v1 knows")
        when = a.get("when")
        if when is not None:
            # One status, or a list of them; one listed twice counts once.
            states = when if isinstance(when, list) else [when]
            if not states:
                p.append(f"{at}.when must list at least one of {', '.join(STATES)}")
            for s in states:
                if s not in STATES:
                    p.append(f"{at}.when: {json.dumps(s)} isn't one of {', '.join(STATES)}")
        for fu in a.get("follow_ups") or []:
            if fu not in record_ids:
                p.append(f"Action '{a.get('id')}': follow-up '{fu}' isn't an action of this program with for: \"record\"")
    return p


# ------------------------------------------------------------------ main


Describe = Union[List[dict], Callable[[Dict[str, Any]], List[dict]]]


def _write(path: Optional[str], doc: dict) -> None:
    text = json.dumps(doc, ensure_ascii=False, indent=2)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        note(f"{RESULT_ENV} isn't set, so the answer goes to stdout:")
        print(text, file=sys.stdout, flush=True)


def _read_request(stdin) -> Dict[str, Any]:
    data = stdin.buffer.read() if hasattr(stdin, "buffer") else stdin.read()
    if isinstance(data, bytes):
        data = data.decode("utf-8-sig")
    data = data.lstrip("﻿")
    if not data.strip():
        return {}
    req = json.loads(data)
    if not isinstance(req, dict):
        raise ValueError("the request must be a JSON object")
    return req


def main(
    describe: Describe,
    handlers: Mapping[str, Handler],
    *,
    stdin=None,
    env: Optional[Mapping[str, str]] = None,
    exit: bool = True,
) -> int:
    """Runs the action program: reads the request from stdin, and writes
    the answer to the file named in PATHWARDEN_ACTION_RESULT.

    - `describe`: the list of actions (as docs/action-reference.md describes them),
      or a function of the settings that returns it. `schema` is added.
    - `handlers`: a function per action ID. It gets a `Request` and
      returns `pw.ok(...)`, `pw.failed(...)`, a message (it worked) or
      None ("Done.", or "Dry run: nothing was changed.").
    - `pw.Failed` fails the run with its message; any other exception
      fails it with the exception's type and message, and the traceback
      goes to stderr.

    Exits 0 when the answer says it worked, else 1 (`exit=False` returns
    the code instead, for tests)."""
    _utf8_streams()
    env = dict(os.environ if env is None else env)
    stdin = sys.stdin if stdin is None else stdin
    path = env.get(RESULT_ENV) or None
    code = 1
    try:
        raw = _read_request(stdin)
    except (ValueError, UnicodeDecodeError) as e:
        _write(path, {"schema": RESULT_SCHEMA, "ok": False, "message": f"The request couldn't be read: {e}."})
        return _done(1, exit)
    if raw.get("schema") not in (None, REQUEST_SCHEMA):
        # Within v1 fields are only added; another schema is a change this
        # program doesn't know.
        _write(path, {"schema": RESULT_SCHEMA, "ok": False, "message": f"This program reads {REQUEST_SCHEMA}, not {raw.get('schema')}: update it."})
        return _done(1, exit)
    req = Request(raw, env)
    kind = req.kind or env.get(REQUEST_ENV, "")
    if kind == "describe":
        actions = describe(req.settings) if callable(describe) else describe
        actions = list(actions.get("actions", [])) if isinstance(actions, Mapping) else list(actions)
        for problem in check_describe(actions):
            note(f"describe: {problem}")
        for a in actions:
            if isinstance(a, Mapping) and a.get("id") not in handlers:
                note(f"describe: action '{a.get('id')}' has no handler")
        _write(path, {"schema": DESCRIBE_SCHEMA, "actions": actions})
        return _done(0, exit)
    if kind != "run":
        _write(path, {"schema": RESULT_SCHEMA, "ok": False, "message": f"Unknown request kind '{kind}'."})
        return _done(1, exit)
    handler = handlers.get(req.action)
    try:
        if handler is None:
            raise Failed(f"This program has no action '{req.action}'.")
        answer = handler(req)
        if answer is None and req.dry_run:
            answer = ok("Dry run: nothing was changed.")
        result, notes = clean_result(answer)
        for n in notes:
            note(f"result: {n}")
        code = 0 if result["ok"] else 1
    except Failed as e:
        result, _ = clean_result(failed(str(e) or "It didn't work."))
    except Exception as e:  # any other bug: a failed run, with details
        note(traceback.format_exc().rstrip())
        result, _ = clean_result(failed(f"It failed: {type(e).__name__}: {e}"))
    # A message may quote a secret (an exception's text can hold a header
    # value), and it is saved on the finding and shared: take them out.
    result["message"] = _scrub(result["message"])
    _write(path, result)
    return _done(code, exit)


def _done(code: int, exit: bool) -> int:
    if exit:
        sys.stdout.flush()
        sys.exit(code)
    return code
