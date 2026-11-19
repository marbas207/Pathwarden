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

    def test_when_takes_one_state_or_a_list(self):
        ok = [
            {"id": "a", "label": "A", "sends": "x", "when": ["open", "fixed"]},
            {"id": "b", "label": "B", "sends": "x", "when": "fixed"},
            {"id": "c", "label": "C", "sends": "x", "when": "open"},
            {"id": "d", "label": "D", "sends": "x", "when": "held"},
            {"id": "e", "label": "E", "sends": "x", "when": ["fixed", "fixed"]},
        ]
        self.assertEqual(pw.check_describe(ok), [])
        for when in (["closed"], "closed", [], 3):
            bad = [{"id": "a", "label": "A", "sends": "x", "when": when}]
            self.assertEqual(len(pw.check_describe(bad)), 1, when)

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

    def test_stdout_and_stderr_are_utf8_before_the_handler_runs(self):
        class Stream(io.StringIO):
            def reconfigure(self, **kw):
                self.encoding_set = kw.get("encoding")

        out, err = Stream(), Stream()
        seen = {}

        def open_(req):
            seen["out"] = getattr(out, "encoding_set", None)
            seen["err"] = getattr(err, "encoding_set", None)

        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            env = {pw.RESULT_ENV: os.path.join(d, "result.json")}
            pw.main(ACTIONS, {"open": open_}, stdin=Stdin(json.dumps(request()).encode()), env=env, exit=False)
        self.assertEqual(seen, {"out": "utf-8", "err": "utf-8"})

    def test_without_the_result_variable_the_answer_goes_to_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            pw.main(ACTIONS, {"open": lambda r: "Sent."}, stdin=Stdin(json.dumps(request()).encode()), env={}, exit=False)
        self.assertEqual(json.loads(out.getvalue())["message"], "Sent.")
        self.assertIn("isn't set", err.getvalue())


class SecretTests(unittest.TestCase):
    def test_a_secret_is_taken_out_of_messages_progress_and_notes(self):
        settings = {"token_env": "DESK_TOKEN"}
        env = {"DESK_TOKEN": "tok-9f8e7d6c5b4a"}

        def open_(req):
            token = req.secret("token")
            pw.progress(f"Using {token}")
            raise ValueError(f"Invalid header value b'Bearer {token}'")

        r = Run(request(settings=settings), {"open": open_}, env=env)
        self.assertFalse(r.answer["ok"])
        self.assertEqual(r.answer["message"], "It failed: ValueError: Invalid header value b'Bearer [hidden]'")
        self.assertNotIn("tok-9f8e7d6c5b4a", r.stdout + r.stderr)
        self.assertIn("[hidden]", r.stdout)

        def failed_(req):
            raise pw.Failed(f"No: {req.secret('token')}")

        self.assertEqual(Run(request(settings=settings), {"open": failed_}, env=env).answer["message"], "No: [hidden]")

    def test_a_pasted_secret_is_trimmed_and_a_long_message_is_scrubbed_before_its_cut(self):
        req = pw.Request(request(settings={"token_env": "DESK_TOKEN"}), env={"DESK_TOKEN": " tok-1a2b3c4d\n"})
        self.assertEqual(req.secret("token"), "tok-1a2b3c4d")
        settings = {"token_env": "DESK_TOKEN"}
        env = {"DESK_TOKEN": "tok-1a2b3c4d"}

        def long_(req):
            token = req.secret("token")
            return pw.failed("x" * (pw.MAX_MESSAGE - 4) + token)

        r = Run(request(settings=settings), {"open": long_}, env=env)
        self.assertNotIn("tok-", r.answer["message"])

    def test_messages_show_only_the_scheme_host_and_port(self):
        self.assertEqual(pw._shown("https://hooks.example.com/services/T0/B0/SECRET?k=v#f"), "https://hooks.example.com")
        self.assertEqual(pw._shown("https://user:pw@desk.example.com:8443/a"), "https://desk.example.com:8443")
        self.assertEqual(pw._shown("http://[::1]:8080/x"), "http://[::1]:8080")
        req = pw.Request(request(dry_run=True))
        with self.assertRaises(pw.Failed) as e:
            req.http("POST", "https://hooks.example.com/services/T0/B0/SECRET", body={})
        self.assertNotIn("SECRET", str(e.exception))
        self.assertNotIn("/services", str(e.exception))
        with self.assertRaises(pw.Failed) as e:
            pw.check_target("ftp://hooks.example.com/services/SECRET")
        self.assertNotIn("SECRET", str(e.exception))


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

    def test_only_a_real_true_is_open(self):
        for value in ("yes", "false", 1, [1]):
            r, notes = pw.clean_result(pw.ok(records=[{"id": "a", "open": value}]))
            self.assertIs(r["records"][0]["open"], False, value)
            self.assertTrue(any("records[0].open must be true or false" in n for n in notes), notes)
        r, notes = pw.clean_result(pw.ok(records=[{"id": "a", "open": True}, {"id": "b"}]))
        self.assertEqual([x["open"] for x in r["records"]], [True, False])
        self.assertEqual(notes, [])

    def test_a_link_is_capped_in_utf8_bytes(self):
        url = "https://x.example/" + "é" * 1100
        self.assertLess(len(url), pw.MAX_URL)
        self.assertEqual(pw.https_problem(url), "is longer than 2,048 characters")
        self.assertEqual(pw.https_problem("https://x.example/a‮b"), "holds a space or a control character")


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
        with self.assertRaisesRegex(pw.Failed, "Dry run: POST https://desk.example.com wasn't sent"):
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

    def test_a_redirect_is_followed_only_to_the_same_address(self):
        seen = []

        def server_for(handler):
            server = http.server.HTTPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return server

        class Other(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        other = server_for(Other)

        class Here(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/away":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{other.server_port}/secret/path")
                elif self.path == "/near":
                    self.send_response(302)
                    self.send_header("Location", "/there")
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps({"path": self.path, "auth": self.headers.get("Authorization")}).encode())
                    return
                self.end_headers()

            def log_message(self, *a):
                pass

        here = server_for(Here)
        try:
            req = pw.Request(request())
            base = f"http://127.0.0.1:{here.server_port}"
            self.assertEqual(req.http("GET", base + "/near", bearer="t").json(), {"path": "/there", "auth": "Bearer t"})
            with self.assertRaises(pw.Failed) as e:
                req.http("GET", base + "/away", bearer="t")
            self.assertIn("wasn't followed", str(e.exception))
            self.assertNotIn("/secret", str(e.exception))
            self.assertEqual(seen, [])
            self.assertEqual(pw._origin("https://a.example/x"), pw._origin("https://A.example:443/y"))
            self.assertNotEqual(pw._origin("https://a.example/x"), pw._origin("http://a.example/x"))
        finally:
            for s in (here, other):
                s.shutdown()
                s.server_close()


if __name__ == "__main__":
    unittest.main()
