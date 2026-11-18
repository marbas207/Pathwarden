"""Tests for pathwarden_action.py. Standard library only:

    python -m unittest discover -s examples/actions -p "test_*.py"
"""

from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pathwarden_action as pw  # noqa: E402

ACTIONS = [
    {
        "id": "open",
        "label": "Open a ticket",
        "sends": "The finding's title.",
        "inputs": [{"id": "note", "label": "Note", "type": "textarea"}],
        "once": True,
        "follow_ups": ["status"],
    },
    {"id": "status", "label": "Check status", "for": "record", "sends": "The ticket's number."},
]

FINDING = {"fingerprint": "PW-001-0000000000000000", "rule": "PW-001", "title": "A sample", "status": "open"}


class Stdin:
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


def request(**kw):
    r = {
        "schema": pw.REQUEST_SCHEMA,
        "kind": "run",
        "action": "open",
        "inputs": {"note": "hi"},
        "dry_run": False,
        "settings": {},
        "run": {"run_id": "r", "domains": ["SCALE.LOCAL"], "pathwarden": "1.0.0"},
        "finding": FINDING,
        "record": None,
        "requested_by": {"by": "SCALE\\analyst", "on": "PW-DEMO-01"},
    }
    r.update(kw)
    return r


class Run:
    """Runs pw.main on a request and keeps what it wrote."""

    def __init__(self, req, handlers, describe=ACTIONS, env=None, raw=None):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "result.json")
        e = {pw.RESULT_ENV: self.path}
        e.update(env or {})
        data = raw if raw is not None else json.dumps(req).encode("utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.code = pw.main(describe, handlers, stdin=Stdin(data), env=e, exit=False)
        self.stdout, self.stderr = out.getvalue(), err.getvalue()
        with open(self.path, encoding="utf-8") as f:
            self.answer = json.load(f)
        self.dir.cleanup()


class DescribeTests(unittest.TestCase):
    def test_describe_writes_the_actions_with_the_schema(self):
        r = Run({"schema": pw.REQUEST_SCHEMA, "kind": "describe", "settings": {}}, {"open": None, "status": None})
        self.assertEqual(r.code, 0)
        self.assertEqual(r.answer["schema"], pw.DESCRIBE_SCHEMA)
        self.assertEqual([a["id"] for a in r.answer["actions"]], ["open", "status"])
        self.assertEqual(r.stderr, "")

    def test_describe_can_depend_on_the_settings(self):
        def actions(settings):
            return ACTIONS if settings.get("full") else ACTIONS[:1]

        r = Run({"kind": "describe", "settings": {"full": False}}, {"open": None}, describe=actions)
        self.assertEqual(len(r.answer["actions"]), 1)
        self.assertIn("follow-up 'status' isn't an action of this program", r.stderr)

    def test_problems_are_named_in_pathwardens_words(self):
        bad = [{"id": "a", "label": "A", "sends": "x", "inputs": [{"id": "n", "label": "N", "type": "number"}]}, {"id": "B", "label": "B"}]
        problems = pw.check_describe(bad)
        self.assertIn("actions[0].inputs[0].type 'number' isn't one of text, textarea, choice, bool", problems)
        self.assertIn("actions[1].sends is missing: say in plain words what leaves the computer", problems)
        self.assertTrue(any(p.startswith("actions[1].id must be lowercase") for p in problems), problems)

    def test_when_takes_a_list_of_states_or_fixed(self):
        ok = [{"id": "a", "label": "A", "sends": "x", "when": ["open", "fixed"]}, {"id": "b", "label": "B", "sends": "x", "when": "fixed"}]
        self.assertEqual(pw.check_describe(ok), [])
        bad = [{"id": "a", "label": "A", "sends": "x", "when": ["closed"]}]
        self.assertEqual(len(pw.check_describe(bad)), 1)

    def test_a_missing_handler_is_noted(self):
        r = Run({"kind": "describe", "settings": {}}, {"open": None})
        self.assertIn("action 'status' has no handler", r.stderr)

    def test_the_kind_can_come_from_the_environment(self):
        r = Run(None, {"open": None, "status": None}, env={pw.REQUEST_ENV: "describe"}, raw=b"")
        self.assertEqual(r.answer["schema"], pw.DESCRIBE_SCHEMA)


class RunTests(unittest.TestCase):
    def test_a_handler_gets_the_request_and_its_result_is_written(self):
        seen = {}

        def open_(req):
            seen["req"] = req
            pw.progress("Opening a ticket")
            return pw.ok("Opened T-1.", records=[pw.record("t-1", number="T-1", status="Open", open=True, url="https://desk.example.com/T-1")])

        r = Run(request(), {"open": open_})
        self.assertEqual(r.code, 0)
        self.assertEqual(r.stdout, "Opening a ticket\n")
        self.assertEqual(r.answer["schema"], pw.RESULT_SCHEMA)
        self.assertTrue(r.answer["ok"])
        self.assertEqual(r.answer["records"][0]["number"], "T-1")
        req = seen["req"]
        self.assertEqual(req.inputs, {"note": "hi"})
        self.assertEqual(req.fingerprint, FINDING["fingerprint"])
        self.assertEqual(req.requested_by["on"], "PW-DEMO-01")

    def test_a_message_or_none_is_enough(self):
        self.assertEqual(Run(request(), {"open": lambda r: "Sent."}).answer["message"], "Sent.")
        self.assertTrue(Run(request(), {"open": lambda r: None}).answer["ok"])
        dry = Run(request(dry_run=True), {"open": lambda r: None}).answer
        self.assertEqual(dry["message"], "Dry run: nothing was changed.")

    def test_failed_is_a_plain_message(self):
        def open_(req):
            raise pw.Failed("The desk said no: 403 Forbidden.")

        r = Run(request(), {"open": open_})
        self.assertEqual(r.code, 1)
        self.assertEqual(r.answer, {"schema": pw.RESULT_SCHEMA, "ok": False, "message": "The desk said no: 403 Forbidden.", "links": [], "records": []})

    def test_a_bug_is_a_failed_run_with_the_traceback_on_stderr(self):
        def open_(req):
            return {}["missing"]

        r = Run(request(), {"open": open_})
        self.assertFalse(r.answer["ok"])
        self.assertEqual(r.answer["message"], "It failed: KeyError: 'missing'")
        self.assertIn("Traceback", r.stderr)

    def test_an_unknown_action_fails(self):
        r = Run(request(action="nope"), {"open": lambda r: None})
        self.assertEqual(r.answer["message"], "This program has no action 'nope'.")

    def test_a_broken_request_fails(self):
        r = Run(None, {}, raw=b"{not json")
        self.assertFalse(r.answer["ok"])
        self.assertTrue(r.answer["message"].startswith("The request couldn't be read"))

    def test_another_request_schema_fails(self):
        r = Run(request(schema="pathwarden.action-request.v2"), {"open": lambda r: None})
        self.assertFalse(r.answer["ok"])
        self.assertIn("not pathwarden.action-request.v2", r.answer["message"])

    def test_a_request_with_a_bom_reads(self):
        r = Run(None, {"open": lambda r: r.inputs["note"]}, raw=b"\xef\xbb\xbf" + json.dumps(request()).encode())
        self.assertEqual(r.answer["message"], "hi")

    def test_without_the_result_variable_the_answer_goes_to_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            pw.main(ACTIONS, {"open": lambda r: "Sent."}, stdin=Stdin(json.dumps(request()).encode()), env={}, exit=False)
        self.assertEqual(json.loads(out.getvalue())["message"], "Sent.")
        self.assertIn("isn't set", err.getvalue())


class SettingsTests(unittest.TestCase):
    def test_secrets_come_from_the_variable_an_env_setting_names(self):
        req = pw.Request(request(settings={"token_env": "DESK_TOKEN"}), env={"DESK_TOKEN": "s3cret"})
        self.assertEqual(req.secret("token"), "s3cret")
        with self.assertRaisesRegex(pw.Failed, "DESK_TOKEN .* isn't set"):
            pw.Request(request(settings={"token_env": "DESK_TOKEN"}), env={}).secret("token")
        with self.assertRaisesRegex(pw.Failed, "Set token_env"):
            pw.Request(request(), env={}).secret("token")
        self.assertIsNone(pw.Request(request(), env={}).secret("token", required=False))

    def test_a_required_setting_names_itself(self):
        req = pw.Request(request(settings={"base_url": "https://x.example"}))
        self.assertEqual(req.setting("base_url", required=True), "https://x.example")
        self.assertEqual(req.setting("queue", "Identity"), "Identity")
        with self.assertRaisesRegex(pw.Failed, "Set queue in this action's settings."):
            req.setting("queue", required=True)


class ResultTests(unittest.TestCase):
    def test_text_is_cleaned_and_capped_as_pathwarden_does(self):
        r, notes = pw.clean_result(pw.ok("a‮\x07b\r\nc\t" + "x" * 3000))
        self.assertTrue(r["message"].startswith("ab\nc x"))
        self.assertEqual(len(r["message"]), pw.MAX_MESSAGE)
        self.assertTrue(r["message"].endswith("…"))
        self.assertIn("message is longer than 2000 characters; it was cut", notes)

    def test_only_https_links_are_kept(self):
        r, notes = pw.clean_result(
            pw.ok(links=[pw.link("A", "http://x.example"), pw.link("B", "https://user:pw@x.example"), pw.link("C", "https://x.example/c")])
        )
        self.assertEqual(r["links"], [{"label": "C", "url": "https://x.example/c"}])
        self.assertIn("links[0].url must start with https://; the link was left out", notes)
        self.assertIn("links[1].url must not hold a user name or password; the link was left out", notes)

    def test_records_and_fields_are_capped(self):
        many = [pw.record(f"r{i}", fields={f"f{j}": "v" * 300 for j in range(25)}) for i in range(7)]
        r, notes = pw.clean_result(pw.ok(records=many))
        self.assertEqual(len(r["records"]), pw.MAX_RECORDS)
        self.assertEqual(len(r["records"][0]["fields"]), pw.MAX_FIELDS)
        self.assertEqual(len(r["records"][0]["fields"]["f0"]), pw.MAX_FIELD)
        self.assertIn("records has more than 5 records; the rest were left out", notes)

    def test_a_record_needs_an_id_and_keeps_open(self):
        r, notes = pw.clean_result(pw.ok(records=[{"number": "X"}, pw.record("a", open=True, fields={"Done": False, "Count": 3})]))
        self.assertEqual(r["records"], [{"id": "a", "open": True, "fields": {"Done": "false", "Count": "3"}}])
        self.assertEqual(len(notes), 1)


class HttpTests(unittest.TestCase):
    def test_http_is_refused_but_to_this_computer(self):
        req = pw.Request(request())
        with self.assertRaisesRegex(pw.Failed, "must start with https://"):
            req.http("GET", "http://desk.example.com/api")
        pw.check_target("http://127.0.0.1:8080/api")
        pw.check_target("http://localhost/api")
        pw.check_target("http://[::1]/api")

    def test_a_dry_run_sends_only_reads(self):
        req = pw.Request(request(dry_run=True))
        with self.assertRaisesRegex(pw.Failed, "Dry run: POST https://desk.example.com/api wasn't sent"):
            req.http("POST", "https://desk.example.com/api?key=hidden", body={})

    def test_it_talks_json_and_names_a_refusal(self):
        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                ok = self.headers.get("Authorization") == "Bearer t"
                self.send_response(201 if ok else 401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"echo": body}).encode())

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/tickets"
            req = pw.Request(request())
            r = req.http("POST", url, body={"a": 1}, bearer="t")
            self.assertEqual((r.status, r.json()), (201, {"echo": {"a": 1}}))
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaisesRegex(pw.Failed, "answered 401"):
                    req.http("POST", url, body={}, bearer="wrong")
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
