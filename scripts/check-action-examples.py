"""Checks the finding action developer kit: the JSON Schemas in docs/schemas,
the examples and helpers in examples/actions, and, given a pathwarden
binary, `pathwarden action check` on every example.

    python scripts/check-action-examples.py [--pathwarden PATH] [--no-powershell]

Standard library only (Python 3.9+), so CI runs it without installing
anything. What it does:

1. Reads the three schemas and checks they use only what the validator
   below knows, that every $ref resolves and every pattern compiles.
2. Runs the helper tests: Python's unittest and, when PowerShell is
   there (powershell or pwsh), PathwardenAction.Tests.ps1.
3. Runs each example as Pathwarden would, by hand: describe, then a dry
   run of each action on a sample finding. Every request, describe and
   result is validated against its schema.
4. Starts stub-desk.py and runs rest-ticket.py for real (open, open
   again, status, close) and post-to-webhook.ps1 against it.
5. Checks that documents Pathwarden refuses fail the schemas too.
6. With --pathwarden, runs `pathwarden action check` on every example in
   a scratch folder, and expects no problems.

Exits 1 when anything fails, after running everything.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "docs" / "schemas"
EXAMPLES = ROOT / "examples" / "actions"

FAILURES: list = []


def step(name: str) -> None:
    print(f"\n== {name}", flush=True)


def check(ok: bool, what: str) -> bool:
    print(("ok   " if ok else "FAIL ") + what, flush=True)
    if not ok:
        FAILURES.append(what)
    return ok


# ------------------------------------------------------------ validator

KNOWN = {
    "$schema", "$id", "$ref", "$defs", "$comment", "title", "description",
    "type", "const", "enum", "required", "properties", "additionalProperties",
    "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength",
    "pattern", "minimum", "maximum", "maxProperties", "propertyNames",
    "allOf", "oneOf", "if", "then",
}
TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer()),
}


def lint_schema(schema: dict, name: str) -> list:
    """Problems with a schema: unknown keywords, refs that don't resolve,
    patterns that don't compile."""
    problems = []

    def walk(node, at):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("properties", "$defs"):
                    for pk, pv in v.items():
                        walk(pv, f"{at}/{k}/{pk}")
                    continue
                if k not in KNOWN:
                    problems.append(f"{name}{at}: unknown keyword {k}")
                if k == "$ref":
                    try:
                        resolve(schema, v)
                    except KeyError:
                        problems.append(f"{name}{at}: $ref {v} doesn't resolve")
                if k == "pattern":
                    try:
                        re.compile(v)
                    except re.error as e:
                        problems.append(f"{name}{at}: pattern doesn't compile: {e}")
                if k == "type":
                    for t in v if isinstance(v, list) else [v]:
                        if t not in TYPES:
                            problems.append(f"{name}{at}: unknown type {t}")
                if isinstance(v, (dict, list)) and k not in ("enum", "const", "required"):
                    walk(v, f"{at}/{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{at}/{i}")

    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        problems.append(f"{name}: $schema isn't draft 2020-12")
    walk(schema, "")
    return problems


def resolve(root: dict, ref: str):
    if not ref.startswith("#/"):
        raise KeyError(ref)
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def validate(value, schema, root=None, at="$") -> list:
    """Errors of `value` against `schema` (the subset in KNOWN)."""
    root = root if root is not None else schema
    errors = []
    if "$ref" in schema:
        errors += validate(value, resolve(root, schema["$ref"]), root, at)
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(TYPES[t](value) for t in types):
            return errors + [f"{at}: should be {' or '.join(types)}, not {json.dumps(value)[:60]}"]
    if "const" in schema and value != schema["const"]:
        errors.append(f"{at}: should be {json.dumps(schema['const'])}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{at}: {json.dumps(value)[:60]} isn't one of {schema['enum']}")
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{at}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{at}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{at}: {value[:60]!r} doesn't match {schema['pattern'][:60]}")
    if TYPES["number"](value):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{at}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{at}: above {schema['maximum']}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{at}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{at}: more than {schema['maxItems']} items")
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errors.append(f"{at}: items aren't unique")
        if "items" in schema:
            for i, v in enumerate(value):
                errors += validate(v, schema["items"], root, f"{at}[{i}]")
    if isinstance(value, dict):
        for r in schema.get("required", []):
            if r not in value:
                errors.append(f"{at}: {r} is missing")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            errors.append(f"{at}: more than {schema['maxProperties']} properties")
        props = schema.get("properties", {})
        for k, v in value.items():
            if "propertyNames" in schema:
                errors += validate(k, schema["propertyNames"], root, f"{at} name {k!r}")
            if k in props:
                errors += validate(v, props[k], root, f"{at}.{k}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors += validate(v, schema["additionalProperties"], root, f"{at}.{k}")
            elif schema.get("additionalProperties") is False:
                errors.append(f"{at}: {k} isn't allowed")
    for sub in schema.get("allOf", []):
        errors += validate(value, sub, root, at)
    if "oneOf" in schema:
        passing = [s for s in schema["oneOf"] if not validate(value, s, root, at)]
        if len(passing) != 1:
            errors.append(f"{at}: matches {len(passing)} of oneOf, not exactly 1")
    if "if" in schema and not validate(value, schema["if"], root, at):
        errors += validate(value, schema.get("then", {}), root, at)
    return errors


# ------------------------------------------------------------ programs


def powershell() -> str | None:
    for name in ("pwsh", "powershell"):
        found = shutil.which(name)
        if found:
            return found
    return None


def program(example: str, ps: str | None) -> list | None:
    path = str(EXAMPLES / example)
    if example.endswith(".py"):
        return [sys.executable, path]
    if ps is None:
        return None
    return [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path]


def exchange(argv: list, request: dict, env: dict | None = None, timeout: int = 60):
    """Runs a program as Pathwarden does: the request on stdin, the kind in
    PATHWARDEN_ACTION_REQUEST, the answer in the file PATHWARDEN_ACTION_RESULT
    names. Returns (exit code, progress lines, stderr, the answer or None)."""
    with tempfile.TemporaryDirectory() as d:
        result = os.path.join(d, "result.json")
        e = dict(os.environ)
        e.update(env or {})
        e["PATHWARDEN_ACTION_REQUEST"] = request["kind"]
        e["PATHWARDEN_ACTION_RESULT"] = result
        p = subprocess.run(argv, input=json.dumps(request).encode("utf-8"), capture_output=True, env=e, timeout=timeout, cwd=d)
        answer = None
        if os.path.exists(result):
            with open(result, encoding="utf-8-sig") as f:
                answer = json.load(f)
        lines = [l for l in p.stdout.decode("utf-8", "replace").splitlines() if l.strip()]
        return p.returncode, lines, p.stderr.decode("utf-8", "replace"), answer


SAMPLE_FINDING = {
    "change": "new", "first_seen": 1795010520, "times_seen": 1,
    "rule_title": "Account or group outside Tier Zero controls a Tier Zero object",
    "rule": "PW-001", "category": "attack_path", "severity": "critical", "rule_severity": "critical",
    "exposure": None, "fingerprint": "PW-001-0000000000000000",
    "title": "HELPDESK@SCALE.LOCAL can take over DOMAIN ADMINS@SCALE.LOCAL (sample)",
    "domain": "SCALE.LOCAL", "summary": "A sample finding, made up to test an action.",
    "remediation": "Nothing to do: this finding is a sample.",
    "affected": [{"id": "S-1-5-21-1-2-3-512", "name": "DOMAIN ADMINS@SCALE.LOCAL", "kind": "Group"}],
    "path": {"source": "HELPDESK@SCALE.LOCAL", "target": "DOMAIN ADMINS@SCALE.LOCAL",
             "steps": [{"from": "HELPDESK@SCALE.LOCAL", "from_kind": "Group", "edge": "GenericAll", "to": "DOMAIN ADMINS@SCALE.LOCAL", "to_kind": "Group"}]},
    "references": [], "suppressed": None, "rests_on": {"sessions": False, "local_groups": False},
    "guide": "# PW-001\n\nA sample guide.", "status": "open",
}
SAMPLE_RECORD = {"id": "sample-1", "kind": "ticket", "number": "SAMPLE0001", "status": "Open", "open": True}


def run_request(action: dict, settings: dict, dry_run: bool = True, finding=None, record=None, inputs=None) -> dict:
    """A run request for `action` as Pathwarden builds one, with each
    input's default (else sample text, the first choice or false)."""
    if inputs is None:
        inputs = {}
        for i in action.get("inputs") or []:
            if i.get("default") is not None:
                inputs[i["id"]] = i["default"]
            elif i["type"] in ("text", "textarea"):
                inputs[i["id"]] = "Test from Pathwarden"
            elif i["type"] == "choice":
                inputs[i["id"]] = i["choices"][0]
            else:
                inputs[i["id"]] = False
    if record is None and action.get("for") == "record":
        record = SAMPLE_RECORD
    return {
        "schema": "pathwarden.action-request.v1", "kind": "run", "action": action["id"],
        "inputs": inputs, "dry_run": dry_run, "settings": settings,
        "run": {"run_id": "20261118T140200.000Z", "domains": ["SCALE.LOCAL"], "pathwarden": "1.0.0"},
        "finding": finding or SAMPLE_FINDING, "record": record,
        "requested_by": {"by": "SCALE\\analyst", "on": "PW-DEMO-01"},
    }


# The settings each example is checked with; the variables they name.
EXAMPLE_SETTINGS = {
    "post-to-webhook.ps1": {"webhook_env": "PW_EXAMPLE_WEBHOOK", "format": "teams"},
    "rest-ticket.py": {"base_url": "https://desk.example.com/api", "token_env": "PW_EXAMPLE_TOKEN", "queue": "Identity"},
    "owner-lookup.py": {},
}
EXAMPLE_ENV = {"PW_EXAMPLE_WEBHOOK": "https://hooks.example.com/workflows/sample", "PW_EXAMPLE_TOKEN": "sample-token"}


def check_example(name: str, argv: list, schemas: dict) -> None:
    settings = EXAMPLE_SETTINGS[name]
    req = {"schema": "pathwarden.action-request.v1", "kind": "describe", "settings": settings}
    check(not validate(req, schemas["request"]), f"{name}: the describe request fits the request schema")
    code, _, err, answer = exchange(argv, req, EXAMPLE_ENV)
    if not check(code == 0 and answer is not None, f"{name}: describe answers (exit {code}) {err.strip()[:200]}"):
        return
    errors = validate(answer, schemas["describe"])
    check(not errors, f"{name}: describe fits the describe schema {errors[:3]}")
    check(not err.strip(), f"{name}: describe writes nothing to stderr {err.strip()[:200]}")
    for action in answer["actions"]:
        req = run_request(action, settings)
        errors = validate(req, schemas["request"])
        check(not errors, f"{name}/{action['id']}: the dry-run request fits the request schema {errors[:3]}")
        code, lines, err, result = exchange(argv, req, EXAMPLE_ENV)
        if not check(result is not None, f"{name}/{action['id']}: a dry run writes a result {err.strip()[:300]}"):
            continue
        errors = validate(result, schemas["result"])
        check(not errors, f"{name}/{action['id']}: the dry-run result fits the result schema {errors[:3]}")
        check(code == 0 and result.get("ok") is True, f"{name}/{action['id']}: the dry run works: {result.get('message')}")


# ------------------------------------------------------- negative cases

GOOD_DESCRIBE = {
    "schema": "pathwarden.action-describe.v1",
    "actions": [
        {"id": "open", "label": "Open", "sends": "x", "once": True, "follow_ups": ["status"],
         "inputs": [{"id": "note", "label": "Note", "type": "textarea", "max": 4000},
                    {"id": "urgency", "label": "Urgency", "type": "choice", "choices": ["Low", "High"], "default": "Low"},
                    {"id": "now", "label": "Now", "type": "bool", "default": True}],
         "applies_to": {"min_severity": "High", "rules": ["PW-001"], "categories": ["attack-path"]}},
        {"id": "status", "label": "Status", "sends": "x", "for": "record", "when": ["open", "fixed"]},
        {"id": "close", "label": "Close", "sends": "x", "for": "record", "when": "fixed"},
    ],
}
GOOD_RESULT = {
    "schema": "pathwarden.action-result.v1", "ok": True, "message": "Opened T-1.\nIt's in the queue.",
    "links": [{"label": "Open", "url": "https://desk.example.com:8443/T-1?x=1#y"}],
    "records": [{"id": "t-1", "kind": "ticket", "number": "T-1", "status": "Open", "open": True,
                 "url": "https://desk.example.com/T-1", "fields": {"Queue": "Identity", "Count": 3, "Done": False}}],
}


def mutate(doc: dict, path: list, value) -> dict:
    d = copy.deepcopy(doc)
    node = d
    for p in path[:-1]:
        node = node[p]
    if value is KeyError:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return d


REFUSED_DESCRIBE = [
    ("another schema", ["schema"], "pathwarden.action-describe.v2"),
    ("no schema", ["schema"], KeyError),
    ("no actions", ["actions"], []),
    ("an ID with capitals", ["actions", 0, "id"], "Open"),
    ("an ID past 40", ["actions", 0, "id"], "a" * 41),
    ("a label past 80", ["actions", 0, "label"], "x" * 81),
    ("no sends", ["actions", 0, "sends"], KeyError),
    ("a description past 300", ["actions", 0, "description"], "x" * 301),
    ("sends past 500", ["actions", 0, "sends"], "x" * 501),
    ("an input type number", ["actions", 0, "inputs", 0, "type"], "number"),
    ("a textarea max past 4000", ["actions", 0, "inputs", 0, "max"], 4001),
    ("max on a choice", ["actions", 0, "inputs", 1, "max"], 10),
    ("a choice without choices", ["actions", 0, "inputs", 1, "choices"], KeyError),
    ("a choice twice", ["actions", 0, "inputs", 1, "choices"], ["Low", "Low"]),
    ("a bool default that's text", ["actions", 0, "inputs", 2, "default"], "yes"),
    ("a severity Pathwarden doesn't know", ["actions", 0, "applies_to", "min_severity"], "urgent"),
    ("a rule that isn't an ID", ["actions", 0, "applies_to", "rules"], ["PW 001"]),
    ("a category Pathwarden doesn't know", ["actions", 0, "applies_to", "categories"], ["paths"]),
    ("for that isn't record", ["actions", 1, "for"], "finding"),
    ("a state Pathwarden doesn't know", ["actions", 1, "when"], ["closed"]),
    ("when as another single state", ["actions", 1, "when"], "open"),
    ("once as text", ["actions", 0, "once"], "yes"),
]
REFUSED_RESULT = [
    ("another schema", ["schema"], "pathwarden.action-result.v2"),
    ("no ok", ["ok"], KeyError),
    ("ok as text", ["ok"], "true"),
    ("a message past 2000", ["message"], "x" * 2001),
    ("an http link", ["links", 0, "url"], "http://desk.example.com/T-1"),
    ("a link with a password", ["links", 0, "url"], "https://user:pw@desk.example.com/T-1"),
    ("a link with a space", ["links", 0, "url"], "https://desk.example.com/a b"),
    ("a link without a host", ["links", 0, "url"], "https://:443/x"),
    ("six links", ["links"], [{"label": "L", "url": "https://x.example"}] * 6),
    ("a record without an ID", ["records", 0, "id"], KeyError),
    ("six records", ["records"], [{"id": str(i)} for i in range(6)]),
    ("a record number past 200", ["records", 0, "number"], "x" * 201),
    ("a record URL that's http", ["records", 0, "url"], "http://desk.example.com/T-1"),
    ("a field past 200", ["records", 0, "fields", "Queue"], "x" * 201),
    ("21 fields", ["records", 0, "fields"], {f"f{i}": "v" for i in range(21)}),
    ("a field that's a list", ["records", 0, "fields", "Queue"], ["a"]),
]


# ------------------------------------------------------------------ main


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pathwarden", help="a pathwarden binary: also run `pathwarden action check` on every example")
    ap.add_argument("--no-powershell", action="store_true", help="skip what needs PowerShell")
    a = ap.parse_args()
    ps = None if a.no_powershell else powershell()

    step("Schemas")
    schemas = {}
    for kind in ("request", "describe", "result"):
        path = SCHEMAS / f"action-{kind}.v1.json"
        schemas[kind] = json.loads(path.read_text(encoding="utf-8"))
        problems = lint_schema(schemas[kind], path.name)
        check(not problems, f"{path.name} is a draft 2020-12 schema this check can read {problems}")
    check(not validate(GOOD_DESCRIBE, schemas["describe"]), "a describe using every field fits")
    check(not validate(GOOD_RESULT, schemas["result"]), "a result using every field fits")
    for what, path, value in REFUSED_DESCRIBE:
        check(bool(validate(mutate(GOOD_DESCRIBE, path, value), schemas["describe"])), f"describe with {what} doesn't fit")
    for what, path, value in REFUSED_RESULT:
        check(bool(validate(mutate(GOOD_RESULT, path, value), schemas["result"])), f"result with {what} doesn't fit")
    fake = (ROOT / "testdata" / "actions" / "fake-action.sh").read_text(encoding="utf-8")
    for doc, kind in ((re.search(r"answer '(\{\"schema\":\"pathwarden.action-describe.v1\".*?)'\n", fake), "describe"),):
        if doc:
            text = doc.group(1).replace("'\"'\"'", "'")
            check(not validate(json.loads(text), schemas[kind]), "testdata/actions/fake-action.sh's describe fits")

    step("Helper tests")
    p = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", str(EXAMPLES), "-p", "test_*.py"], capture_output=True, text=True)
    check(p.returncode == 0, "pathwarden_action.py: " + (p.stderr.strip().splitlines() or [""])[-1])
    if p.returncode:
        print(p.stderr)
    if ps:
        p = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(EXAMPLES / "PathwardenAction.Tests.ps1")], capture_output=True, text=True)
        check(p.returncode == 0, f"PathwardenAction.psm1 ({Path(ps).name}): " + (p.stdout.strip().splitlines() or [""])[-1])
        if p.returncode:
            print(p.stdout, p.stderr)
    else:
        print("skip PowerShell isn't here: PathwardenAction.Tests.ps1 not run")

    step("Examples, by hand")
    for name in EXAMPLE_SETTINGS:
        argv = program(name, ps)
        if argv is None:
            print(f"skip {name}: PowerShell isn't here")
            continue
        check_example(name, argv, schemas)

    step("Against the stub ticket system")
    stub_check(ps, schemas)

    if a.pathwarden:
        step("pathwarden action check")
        action_checks(a.pathwarden, ps, schemas)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} failed:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("Everything passed.")
    return 0


def stub_check(ps, schemas) -> None:
    stub = subprocess.Popen([sys.executable, "-u", str(EXAMPLES / "stub-desk.py"), "--port", "0", "--token", "sample-token"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        first = stub.stdout.readline()
        m = re.search(r"http://127\.0\.0\.1:(\d+)/api", first)
        if not check(bool(m), f"stub-desk.py starts: {first.strip()}"):
            return
        threading.Thread(target=lambda: [None for _ in stub.stdout], daemon=True).start()
        base = m.group(0)
        settings = {"base_url": base, "token_env": "PW_EXAMPLE_TOKEN", "queue": "Identity"}
        rest = program("rest-ticket.py", ps)
        describe = exchange(rest, {"schema": "pathwarden.action-request.v1", "kind": "describe", "settings": settings}, EXAMPLE_ENV)[3]
        by_id = {x["id"]: x for x in describe["actions"]}

        def go(action, what, **kw):
            req = run_request(by_id[action], settings, dry_run=False, **kw)
            code, lines, err, result = exchange(rest, req, EXAMPLE_ENV)
            errors = validate(result, schemas["result"]) if result else ["no result"]
            check(not errors, f"rest-ticket.py {what}: the result fits the result schema {errors[:3]} {err.strip()[:200]}")
            return code, lines, result or {}

        code, lines, r = go("open", "open")
        check(code == 0 and r.get("ok") and r["records"][0]["number"] == "DESK0001" and r["records"][0]["open"],
              f"rest-ticket.py open opens DESK0001: {r.get('message')} {lines}")
        record = r["records"][0]
        code, lines, r = go("open", "open again")
        check(r.get("message") == "DESK0001 is already open for this finding.", f"rest-ticket.py doesn't open a second ticket: {r.get('message')}")
        code, lines, r = go("status", "status", record=record)
        check(r.get("message") == "DESK0001 is Open.", f"rest-ticket.py status reads it: {r.get('message')}")
        code, lines, r = go("close", "close on an open finding", record=record)
        check(code == 1 and r.get("ok") is False, f"rest-ticket.py won't close the ticket of a finding that isn't fixed: {r.get('message')}")
        fixed = dict(SAMPLE_FINDING, status="fixed")
        code, lines, r = go("close", "close", record=record, finding=fixed)
        check(r.get("ok") and r["records"][0]["open"] is False, f"rest-ticket.py close closes it: {r.get('message')}")
        req = run_request(by_id["open"], settings, dry_run=False, finding=dict(SAMPLE_FINDING, fingerprint="PW-001-1111111111111111"))
        code, lines, err, r = exchange(rest, req, dict(EXAMPLE_ENV, PW_EXAMPLE_TOKEN="wrong"))
        check(code == 1 and r and r["message"].endswith("answered 401 Unauthorized."), f"rest-ticket.py says when the token is refused: {r and r['message']}")
        req = run_request(by_id["open"], settings, dry_run=True)
        code, lines, err, r = exchange(rest, req, EXAMPLE_ENV)
        check(r and r["ok"] and r["message"].startswith("Dry run: would open"), f"rest-ticket.py's dry run sends nothing: {r and r['message']}")

        hook = program("post-to-webhook.ps1", ps)
        if hook is None:
            print("skip post-to-webhook.ps1: PowerShell isn't here")
            return
        for fmt in ("teams", "slack", "json"):
            s = {"webhook_env": "PW_EXAMPLE_WEBHOOK", "format": fmt}
            req = run_request({"id": "alert", "inputs": [{"id": "note", "label": "Note", "type": "textarea"}]}, s, dry_run=False)
            code, lines, err, r = exchange(hook, req, dict(EXAMPLE_ENV, PW_EXAMPLE_WEBHOOK=f"{base}/hooks/team"))
            check(code == 0 and r and r["ok"] and lines == ["Posting to the webhook"],
                  f"post-to-webhook.ps1 posts as {fmt}: {r and r['message']} {err.strip()[:200]}")
    finally:
        stub.terminate()
        stub.wait(10)


def action_checks(binary: str, ps, schemas) -> None:
    with tempfile.TemporaryDirectory() as d:
        env = dict(os.environ, NO_COLOR="1", LOCALAPPDATA=os.path.join(d, "lad"), XDG_STATE_HOME=os.path.join(d, "state"))
        env.update(EXAMPLE_ENV)
        env.pop("PATHWARDEN_SCHEDULED", None)
        # A real request, for a finding of the demo, fits the schema.
        run = lambda *args: subprocess.run([binary, *args], capture_output=True, text=True, env=env, cwd=d, timeout=600)  # noqa: E731
        analyzed = run("run", "--save", "--workspace", "ws", "-i", "demo:")
        findings = run("findings", "-i", "demo:", "--json")
        if check(analyzed.returncode == 0 and findings.returncode == 0, f"the demo is analyzed into a scratch workspace {analyzed.stderr.strip()[-300:] if analyzed.returncode else ''}"):
            listed = json.loads(findings.stdout)
            listed = listed if isinstance(listed, list) else listed.get("findings", [])
            fp = listed[0]["fingerprint"]
            for extra in ([], ["--dry-run"]):
                p = run("action", "--workspace", "ws", "request", fp, *extra)
                errors = validate(json.loads(p.stdout), schemas["request"]) if p.returncode == 0 else [p.stderr.strip()]
                check(not errors, f"pathwarden action request {' '.join([fp, *extra])} fits the request schema {errors[:3]}")
        for name, settings in EXAMPLE_SETTINGS.items():
            argv = program(name, ps)
            if argv is None:
                print(f"skip {name}: PowerShell isn't here")
                continue
            sets = [x for k, v in settings.items() for x in ("--setting", f"{k}={v}")]
            if name.endswith(".ps1"):
                cmd = [binary, "action", "check", str(EXAMPLES / name)] + sets
            else:
                # The full path of this Python: `python` must be in a folder only
                # administrators can change, which a user install isn't.
                cmd = [binary, "action", "check", sys.executable] + sets + ["--", str(EXAMPLES / name)]
            p = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=d, timeout=300)
            out = p.stdout.strip()
            check(p.returncode == 0, f"pathwarden action check {name}: {out.splitlines()[-1] if out else p.stderr.strip()}")
            if p.returncode:
                print(out, p.stderr)


if __name__ == "__main__":
    t = time.time()
    code = main()
    print(f"({time.time() - t:.1f} s)")
    sys.exit(code)
