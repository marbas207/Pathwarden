# Finding action examples and helpers

Everything here is for writing a finding action: your own program that
Pathwarden runs for one finding when someone asks. The guide is
[Writing an action](../../docs/actions.md).

| File | What it is |
|---|---|
| [pathwarden_action.py](pathwarden_action.py) | The Python helper (3.9 or later, standard library only). |
| [PathwardenAction.psm1](PathwardenAction.psm1) | The PowerShell helper (Windows PowerShell 5.1 and PowerShell 7). |
| [post-to-webhook.ps1](post-to-webhook.md) | Posts a finding to a Teams, Slack or other chat webhook. Returns a message. |
| [rest-ticket.py](rest-ticket.md) | Opens a ticket in a JSON REST API, checks its status and closes it once fixed. Returns a record. |
| [owner-lookup.py](owner-lookup.md) | Says who owns a finding's objects, from a CSV file. Returns a message; has an input. |
| [stub-desk.py](stub-desk.py) | A ticket API and chat webhook on this computer, to try the examples against. |
| [owners.example.csv](owners.example.csv) | Sample owners for owner-lookup.py, for the demo's SCALE.LOCAL. |

## Use an example

1. Copy the example and its helper into one folder that only you and
   administrators can change, such as `C:\Pathwarden\actions`. Each
   example imports the helper from its own folder.
2. Put any secret it needs in an environment variable, and give the
   variable's name in the `*_env` setting its page names.
3. Check it, then add it, as its page shows.

## The helpers

Each helper turns a describe block and one function per action into a
working program:

- It reads the request from stdin as UTF-8, and answers `describe` with
  your actions and the schema.
- It calls your function for `run`, and writes its result to the file
  named in `PATHWARDEN_ACTION_RESULT`. Without that variable, it prints the
  answer to stdout, for running by hand.
- An error becomes a failed result with a plain message, and its details
  go to stderr (**Show details**).
- It cleans and caps the result as Pathwarden does, and leaves out a link
  that isn't `https://`, with a note on stderr.
- It reads secrets from the variables `*_env` settings name.
- Its HTTPS function checks certificates against the system's store,
  refuses `http://` except to this computer, and on a dry run refuses
  anything but GET and HEAD.
- It checks your describe block, and notes each problem on stderr.

Python:

```python
import pathwarden_action as pw

ACTIONS = [{"id": "hello", "label": "Say hello", "sends": "Nothing: it only answers."}]

def hello(req):
    pw.progress("Saying hello")
    return pw.ok(f"Hello from {req.fingerprint}.")

if __name__ == "__main__":
    pw.main(ACTIONS, {"hello": hello})
```

| Python | What it does |
|---|---|
| `pw.main(describe, handlers)` | Runs the program. `describe` is the list of actions, or a function of the settings that returns it. |
| `req.kind`, `req.action`, `req.inputs`, `req.dry_run`, `req.settings`, `req.run`, `req.finding`, `req.record`, `req.requested_by`, `req.fingerprint` | The request. |
| `req.setting(name, default, required=False)` | A setting; a missing required one fails with a message naming it. |
| `req.secret(name)` | The variable `<name>_env` names. |
| `req.http(method, url, body=, bearer=, headers=)` | One HTTPS request; `.json()`, `.text`, `.status` on the answer. |
| `pw.progress(line)`, `pw.note(line)` | A progress line; a line on stderr. |
| `pw.ok(message, links=, records=)`, `pw.failed(...)` | A result. A handler may also return a message, or None. |
| `pw.record(id, kind=, number=, status=, open=, url=, fields=)`, `pw.link(label, url)` | A record and a link. |
| `raise pw.Failed("message")` | Fails the run with that message. |

PowerShell:

```powershell
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PathwardenAction.psm1')

Invoke-PathwardenAction -Describe @(@{ id = 'hello'; label = 'Say hello'; sends = 'Nothing: it only answers.' }) -Handlers @{
    hello = {
        param($Request)
        Write-PathwardenProgress 'Saying hello'
        New-PathwardenResult "Hello from $($Request.finding.fingerprint)."
    }
}
```

| PowerShell | What it does |
|---|---|
| `Invoke-PathwardenAction -Describe -Handlers` | Runs the program. `-Describe` is the actions, or a script block that gets the settings. |
| `$Request.kind`, `.action`, `.inputs`, `.dry_run`, `.settings`, `.run`, `.finding`, `.record`, `.requested_by` | The request. |
| `Get-PathwardenSetting -Request -Name [-Default] [-Required]` | A setting. |
| `Get-PathwardenSecret -Request -Name [-Optional]` | The variable `<Name>_env` names. |
| `Invoke-PathwardenHttp -Request -Method -Uri [-Body] [-Bearer] [-Headers]` | One HTTPS request; returns the answer, parsed from JSON. |
| `Write-PathwardenProgress`, `Write-PathwardenNote` | A progress line; a line on stderr. |
| `New-PathwardenResult [-Message] [-Failed] [-Links] [-Records]` | A result. Output it last. |
| `New-PathwardenRecord -Id [-Kind] [-Number] [-Status] [-Open] [-Url] [-Fields]`, `New-PathwardenLink -Label -Url` | A record and a link. |
| `throw "message"` | Fails the run with that message. |

In PowerShell, anything a handler outputs that isn't its result is shown
as a progress line once it ends. Use `Write-PathwardenProgress` for lines
that show while it runs, and `$null = ...` for output you don't want.

## Tests

```powershell
python -m unittest discover -s examples\actions -p "test_*.py"
powershell -NoProfile -ExecutionPolicy Bypass -File examples\actions\PathwardenAction.Tests.ps1
python scripts\check-action-examples.py --pathwarden path\to\pathwarden.exe
```

`scripts/check-action-examples.py` runs both, validates the
[JSON Schemas](../../docs/schemas/) and every example's answers against
them, runs the examples against stub-desk.py, and, given a pathwarden
binary, runs `pathwarden action check` on each. CI runs it on every push.
