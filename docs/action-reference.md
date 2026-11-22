# Action reference

Every field, limit and rule of the finding action protocol, version 1.
Everything here matches what Pathwarden checks, and the
[JSON Schemas](#json-schemas) say the same in a form tools can read. To
build your first action, start with [Writing an action](actions.md).

- [How a program is run](#how-a-program-is-run)
- [The request](#the-request)
- [The describe answer](#the-describe-answer)
- [The result](#the-result)
- [Records and activity](#records-and-activity)
- [Limits](#limits)
- [Without a helper](#without-a-helper)
- [JSON Schemas](#json-schemas)
- [Lifecycle](#lifecycle)
- [Security](#security)
- [Compatibility](#compatibility)
- [An action that signs in through a browser](#an-action-that-signs-in-through-a-browser)

## How a program is run

### The action block

An `[[action]]` block in `pathwarden.toml` names one program and its
settings:

```toml
[[action]]
name = "desk"                            # how its actions are addressed: desk/open
command = ["C:\\Program Files\\Python313\\python.exe", "C:\\Pathwarden\\actions\\rest-ticket.py"]
timeout_seconds = 900                    # one run's time limit: default 300, at most 1800
min_severity = "medium"                  # filters: min_severity, rules, categories
base_url = "https://desk.example.com/api"   # every other key is a setting for the program
token_env = "PATHWARDEN_DESK_TOKEN"         # a secret, by the name of its variable
```

- `name` is lowercase letters, digits and dashes. Without one, the block is
  named after its `plugin`, else `action-N` by its place in the file. Give
  every block a name, because `action-N` changes when blocks move.
- `plugin = "x"` runs `pathwarden-action-x` from beside Pathwarden or from
  its `plugins` folder. Otherwise `command` gives the program and its
  arguments.
- `name`, `plugin`, `command`, `timeout_seconds`, `min_severity`, `rules`
  and `categories` belong to Pathwarden. Every other key goes to the
  program as a setting.
- Several blocks can run the same program with different settings, such
  as one per team.

### Each request

For each request, Pathwarden:

1. starts the program with a cleared environment: `PATH`, `SYSTEMROOT`,
   `SYSTEMDRIVE`, `TEMP`, `TMP`, `HOME`, `USERPROFILE`, `APPDATA`,
   `LOCALAPPDATA`, `COMSPEC`, `PATHEXT`, `WINDIR`, the program folders
   (`PROGRAMFILES`, `PROGRAMFILES(X86)`, `PROGRAMW6432`, `PROGRAMDATA`,
   `COMMONPROGRAMFILES`, `COMMONPROGRAMFILES(X86)`, so browser automation
   such as Playwright finds an installed Edge or Chrome), the proxy variables
   (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, `ALL_PROXY`), and the variables
   the block's `*_env` settings name;
2. sets `PATHWARDEN_ACTION_REQUEST` to the kind, `describe` or `run`, and
   `PATHWARDEN_ACTION_RESULT` to the full path of the file to write the
   answer to;
3. starts it in a private folder, `%LOCALAPPDATA%\Pathwarden\plugin-work`
   on Windows (`~/.local/state/pathwarden/plugin-work` elsewhere), not the
   current folder;
4. writes one JSON request to its stdin and closes it;
5. shows each stdout line as a progress line, and keeps stderr;
6. waits until it exits, its time limit passes or someone cancels. A time
   limit or a cancel stops the program and every process it started;
7. reads the answer file (a plain file, at most 1 MiB, UTF-8 with or
   without a byte order mark) and removes it.

| | describe | run |
|---|---|---|
| Time limit | 60 seconds, or `timeout_seconds` when lower. | `timeout_seconds`: default 300, at most 1,800. |
| Answer | `pathwarden.action-describe.v1` | `pathwarden.action-result.v1` |
| Exit code | Not 0: describe failed. | Not 0: the run failed, whatever the result says. |

Pathwarden keeps a describe answer in memory until the program's file, its
script or its settings change. A describe that failed is asked again after
30 seconds.

### Output

Print progress lines as UTF-8, and flush after each line, or they arrive
all at once at the end. Pathwarden keeps the latest 200, each cut to 500
characters, with control characters dropped. stderr is kept separately, up
to 64 KiB, for **Show details** in the app and the details the command line
prints when a run fails. Put what helps someone fix a failure there, never
secrets.

## The request

`pathwarden.action-request.v1`, one JSON object on stdin. A describe
request carries only the settings:

```json
{ "schema": "pathwarden.action-request.v1", "kind": "describe", "settings": { "base_url": "https://desk.example.com/api", "token_env": "PATHWARDEN_DESK_TOKEN" } }
```

A run request:

```json
{
  "schema": "pathwarden.action-request.v1",
  "kind": "run",
  "action": "open",
  "inputs": { "note": "Please review", "urgency": "High" },
  "dry_run": false,
  "settings": { "base_url": "https://desk.example.com/api", "token_env": "PATHWARDEN_DESK_TOKEN" },
  "run": { "run_id": "20261118T223156.938Z", "domains": ["SCALE.LOCAL"], "pathwarden": "1.0.0-rc.3" },
  "finding": {
    "fingerprint": "PW-006-1bbba15126c6fc31",
    "rule": "PW-006",
    "rule_title": "Kerberoastable account with Tier Zero access",
    "title": "Kerberoastable account SVC-00000@SCALE.LOCAL is Tier Zero",
    "severity": "critical",
    "category": "attack_path",
    "status": "open",
    "summary": "SVC-00000@SCALE.LOCAL has a service principal name, so any domain user can request a ticket encrypted with its password and crack it offline, and it is Tier Zero. ...",
    "remediation": "Move the service to a group managed service account (gMSA), ...",
    "affected": [{ "id": "S-1-5-21-1111-2222-3333-5983", "kind": "User", "name": "SVC-00000@SCALE.LOCAL" }],
    "path": { "source": "SVC-00000@SCALE.LOCAL", "target": "SVC-00000@SCALE.LOCAL", "steps": [] },
    "guide": "# PW-006: Kerberoastable account with Tier Zero access\n...",
    "...": "the rest of the event's fields"
  },
  "record": null,
  "requested_by": { "by": "SCALE\\analyst", "on": "PW-DEMO-01" }
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | text | Always `pathwarden.action-request.v1`. |
| `kind` | text | `describe` or `run`, as `PATHWARDEN_ACTION_REQUEST` says. |
| `settings` | object | The block's settings: every key but Pathwarden's own, as TOML gave them. |
| `action` | text | Run only. The ID of the action to run. |
| `inputs` | object | Run only. Every input the action describes, by ID, checked: text, or `true` or `false` for a `bool`. |
| `dry_run` | true or false | Run only. True: change nothing. |
| `run` | object | Run only. `run_id`, `domains` (collected) and `pathwarden` (the version that analyzed the run). |
| `finding` | object | Run only. The finding; see below. |
| `record` | object or null | Run only. For a follow-up, the record it runs on, as the last result that gave it kept it: `id`, `open`, and `kind`, `label`, `number`, `url`, `status` and `fields` when it has them. Which action made it, who and when aren't sent. Else null. |
| `requested_by` | object | Run only. `by`, the user (`DOMAIN\user`), and `on`, the computer. Each null when unknown. |

### The finding

The finding is the run's [event document](dev/formats.md#the-event-document-pathwardeneventv1)
entry as it is, plus two fields:

- `status`: `open`, `accepted`, `held` or `fixed`.
- `guide`: the rule's step-by-step guide in Markdown, or null.

The statuses mean:

- `open`: found by this run.
- `accepted`: found, and covered by an accepted risk.
- `held`: this run couldn't check it, such as when a collection missed its
  domain. It isn't fixed.
- `fixed`: found by the previous run, gone from this one.

An open or accepted finding has every field of the event's `findings`:
`fingerprint`, `rule`, `rule_title`, `title`, `severity`, `category`,
`change`, `domain`, `summary`, `remediation`, `affected`, `path`,
`references`, `exposure`, `first_seen`, `times_seen`, `suppressed` and
`accepted` (who accepted the risk), and more. A fixed finding has only the
fields of `resolved` (`fingerprint`, `rule`, `severity`, `first_seen`,
`resolved_at`, `title`), and a held one only those of `held`
(`fingerprint`, `rule`). Read every field but `fingerprint`, `rule` and
`status` as optional.

The finding's `fingerprint` is its ID. It stays the same on every run, so
use it as the key in the other system: search for it before you create
something.

### Input values

Pathwarden checks what the person typed against each input's type before
the program starts, so the program gets clean values.

| Type | The dialog shows | The program gets |
|---|---|---|
| `text` | One line, at most `max` characters (default 200, at most 1,000). | Text, trimmed. |
| `textarea` | Several lines, at most `max` (default 2,000, at most 4,000). | Text with `\n` line breaks. |
| `choice` | A list of `choices`, at most 50. | The choice, spelled as described. |
| `bool` | A switch. | `true` or `false`. |

- Every input the action describes is in the request. One left empty is
  `""`, or its `default`. A `choice` without a default gets its first
  choice, and a `bool` gets `false`.
- `required: true` stops the run while the input is empty, with
  "<label> is needed."
- Control characters are refused, except line breaks and tabs in a
  `textarea`.
- On the command line, `--input id=value` gives an input. A `choice`
  matches in any case. A `bool` takes true, false, yes, no, on, off, 1
  or 0.

## The describe answer

`pathwarden.action-describe.v1`, written to the answer file:

```json
{
  "schema": "pathwarden.action-describe.v1",
  "actions": [
    {
      "id": "open",
      "label": "Open a ticket",
      "description": "Opens a ticket for the team that fixes this finding.",
      "sends": "The finding's ID, title, summary and remediation, and your note, to the ticket system.",
      "applies_to": { "min_severity": "medium", "categories": ["attack_path"] },
      "inputs": [
        { "id": "note", "label": "Note for the team", "type": "textarea", "max": 2000 },
        { "id": "urgency", "label": "Urgency", "type": "choice", "choices": ["Low", "Medium", "High"], "default": "Medium" }
      ],
      "once": true,
      "follow_ups": ["status", "close"]
    },
    { "id": "status", "label": "Check status", "for": "record", "sends": "The ticket's ID, to read it." },
    { "id": "close", "label": "Close ticket", "for": "record", "when": ["fixed"], "sends": "The ticket's ID and a closing note." }
  ]
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema` | text | yes | `pathwarden.action-describe.v1`. Missing: a problem is noted. Another: the answer is refused. |
| `actions` | list | yes | 1 to 20 actions, in the order the buttons appear. |

Each action:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | text | yes | Lowercase letters, digits, `-` and `_`, at most 40. Unique in the program. |
| `label` | text | yes | The button, at most 80 characters. |
| `sends` | text | yes | What leaves the computer, in plain words, at most 500 characters. Shown before every run. |
| `description` | text | no | One line in the dialog, at most 300 characters. |
| `applies_to` | object | no | `min_severity`, `rules`, `categories`, on top of the block's filters. |
| `inputs` | list | no | At most 20 inputs; see below. |
| `once` | true or false | no | Hide the action while the finding has an open record from it or an open ticket from an output plugin. |
| `follow_ups` | list | no | IDs of this program's `for: "record"` actions, offered on the records this one returns. |
| `for` | text | no | `"record"`: only offered as a follow-up. |
| `when` | text or list | no | Finding statuses it is offered on: one of `open`, `held`, `accepted`, `fixed`, or a list of them (`"fixed"` means `["fixed"]`). Default: open, held and accepted; for a `for: "record"` action, every status. |

Each input:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | text | yes | Lowercase letters, digits, `-` and `_`, at most 40. Unique in the action. |
| `label` | text | yes | The field's name, at most 80 characters. |
| `type` | text | yes | `text`, `textarea`, `choice` or `bool`. |
| `required` | true or false | no | Can't run while it is empty. |
| `max` | number | no | `text`: 1 to 1,000 (default 200). `textarea`: 1 to 4,000 (default 2,000). Not for the others. |
| `choices` | list | `choice` | 1 to 50 texts, each at most 100 characters, none twice. |
| `default` | | no | `bool`: true or false. `choice`: one of the choices. `text`, `textarea`: text no longer than `max`. |

An action with a problem in its `id`, `label`, filters, inputs, `for` or
`when` isn't offered, and the problem is named. A text that is too long is
cut, and the action is offered. A follow-up that names no `for: "record"`
action of the program is dropped.

### Which findings show an action

| Field | Effect |
|---|---|
| `once: true` | The action is hidden while the finding has an open record from it, or an open ticket from an output plugin (ServiceNow, Jira). One ticket per finding. |
| `for: "record"` | Only offered as a follow-up on a record. |
| `when` | The finding statuses the action is offered on: one of `open`, `held`, `accepted` and `fixed`, or a list of them. Without it: open, held and accepted. A `for: "record"` action without it is offered on its records whatever the finding's status, fixed included. |

A fixed finding shows only the actions whose `when` lists `fixed`, and the
follow-ups of its records. So a "close the ticket" follow-up says
`"when": ["fixed"]`, and an action for every finding says
`"when": ["open", "held", "accepted", "fixed"]`. A single status, such as
`"when": "fixed"`, means the same as a list of that one.

A follow-up is offered only on a record its own program's action made, and
only among that program's actions. Its request carries the record in
`record`.

### Filters

Two sets of filters decide which findings an action is offered on. Both
must match.

- The block's `min_severity`, `rules` and `categories`, set by whoever adds
  the action. They can be changed in the app even with
  `--lock-destinations`.
- The action's own `applies_to`, with the same three keys, set by whoever
  writes the program.

`min_severity` is `critical`, `high`, `medium`, `low` or `info`. `rules`
are rule IDs such as `PW-006`. `categories` are `attack_path` and
`hygiene`. A fixed or held finding is rated by its rule: its category, and
for a held one the highest severity its rule gives.

## The result

`pathwarden.action-result.v1`, written to the answer file:

```json
{
  "schema": "pathwarden.action-result.v1",
  "ok": true,
  "message": "Opened DESK0001.",
  "links": [{ "label": "Open the ticket", "url": "https://desk.example.com/tickets/DESK0001" }],
  "records": [
    {
      "id": "t-1",
      "kind": "ticket",
      "number": "DESK0001",
      "status": "Open",
      "open": true,
      "url": "https://desk.example.com/tickets/DESK0001",
      "fields": { "Queue": "Identity" }
    }
  ]
}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `schema` | text | yes | `pathwarden.action-result.v1`. Missing: a problem is noted. Another: the run failed. |
| `ok` | true or false | yes | Whether it worked. Missing: the run failed. |
| `message` | text | no | What happened, at most 2,000 characters, line breaks kept. Empty: "Done.", or "It didn't work (exit code N)." |
| `links` | list | no | At most 5, each `label` (at most 80 characters) and `url`. |
| `records` | list | no | At most 5; see below. |

Each record:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `id` | text | yes | Its ID in the other system, at most 200 characters, unique in the result. A follow-up returns the same `id` to update it. |
| `kind` | text | no | What it is: `ticket`, `request`. |
| `label` | text | no | A name, when it has no number. |
| `number` | text | no | The number people know it by, such as `RITM0001234`. Shown on the chip. |
| `status` | text | no | Its status there, such as `Open`. Shown on the chip. |
| `open` | true or false | no | Still open there. Default false. |
| `url` | text | no | Where to open it. |
| `fields` | object | no | At most 20 named values to show with it. Names at most 60 characters; values at most 200, as text (numbers and true or false become text). |

`kind`, `label`, `number` and `status` are at most 200 characters each.
Every `url` must be `https://`, with a host, without a user name or
password, spaces or control characters, at most 2,048 characters.

A run counts as worked only when the result says `ok: true` and the
program exits 0. A missing or broken result is a failed run, shown with the
program's output. So is a run that passes its time limit or is cancelled.

## Records and activity

- Pathwarden saves every record a run returns on the finding, in the run
  history's `actions.json`. It is encrypted and shared with the rest of the
  history, so every computer on that history sees it on every later run.
- The finding's ID stays the same across runs, so its records stay with it.
- A record stays until someone removes it, in the app or with
  `pathwarden action records remove`.
- A follow-up that returns a record with the same `id` replaces it: the
  stored record becomes the one returned. Return every field you want
  kept, not only the ones that changed. A field left out is gone.
- `open: true` keeps a `once` action hidden, and makes a fixed finding's
  chip read "Fixed · DESK0001 still Open".
- The saved report's Findings tab lists the fixed findings whose record is
  still open, in a **Fixed, ticket still open** card: rule, title, chip and
  when it was fixed, newest fix first. Without any, there is no card.

Every run that isn't a dry run is saved on the finding's **Activity**,
newest first: who ran which action, from which computer, when, whether it
worked and its message. Failed runs are listed too. Pathwarden keeps the
latest 100 per finding. `pathwarden action activity FINDING_ID` prints
them, and `pathwarden action records FINDING_ID` prints the records.

`pathwarden action records` takes two filters:

| Flag | Lists |
|---|---|
| `--open` | Open records only. |
| `--fixed` | Records of findings the latest run found fixed, newest fix first, each with when it was fixed. |
| `--open --fixed` | The fixed findings whose ticket is still open: the report's card. |

With `--json`, `--fixed` adds `rule`, `title` and `fixed_at` (Unix time)
to each record.

## Limits

| What | Limit | Past it |
|---|---|---|
| Actions per program | 20 | The rest are left out. |
| Inputs per action | 20 | The action isn't offered. |
| An ID | 40 characters | The action isn't offered. |
| A label | 80 characters | Cut. |
| A description | 300 characters | Cut. |
| `sends` | 500 characters | Cut. |
| Choices | 50, each 100 characters | The action isn't offered. |
| A `text` input | `max`, default 200, at most 1,000 | The run is refused. |
| A `textarea` input | `max`, default 2,000, at most 4,000 | The run is refused. |
| The message | 2,000 characters | Cut. |
| Links | 5 | The rest are left out. |
| Records | 5 | The rest are left out. |
| A record's texts | 200 characters | Cut; a long `id` leaves the record out. |
| A record's fields | 20, names 60, values 200 characters | Left out, or cut. |
| A URL | 2,048 characters, `https://` | Left out. |
| The answer file | 1 MiB | The answer is refused. |
| Progress lines | the latest 200, each 500 characters | Older lines dropped; long lines cut. |
| stderr kept | 64 KiB | Cut. |
| describe | 60 seconds | Stopped; describe failed. |
| A run | `timeout_seconds` (300; at most 1,800) | Stopped; the run failed, its output kept. |
| Activity | the latest 100 runs per finding | Older entries dropped. |

Text is never read as HTML. Control characters and bidirectional
formatting characters are dropped, tabs become spaces, and text is trimmed.
Line breaks are kept only in the message.

## Without a helper

The helpers are optional. Any program that follows the protocol works.
A whole action in Windows PowerShell, without the helper:

```powershell
$ErrorActionPreference = 'Stop'
$req = [Console]::In.ReadToEnd() | ConvertFrom-Json
function Answer($doc) { [IO.File]::WriteAllText($env:PATHWARDEN_ACTION_RESULT, (ConvertTo-Json $doc -Depth 10)) }
if ($req.kind -eq 'describe') {
    Answer @{ schema = 'pathwarden.action-describe.v1'; actions = @(@{ id = 'hello'; label = 'Say hello'; sends = 'Nothing.' }) }
    exit 0
}
[Console]::Out.WriteLine('Saying hello'); [Console]::Out.Flush()
Answer @{ schema = 'pathwarden.action-result.v1'; ok = $true; message = "Hello from $($req.finding.fingerprint)." }
```

And in sh. Pathwarden writes the request on one line, and a finding ID
holds only letters, digits and dashes, so `sed` can pick it out. For
anything more, use `jq` or a language with JSON:

```sh
#!/bin/sh
req=$(cat)
if [ "$PATHWARDEN_ACTION_REQUEST" = describe ]; then
    printf '%s' '{"schema":"pathwarden.action-describe.v1","actions":[{"id":"hello","label":"Say hello","sends":"Nothing."}]}' > "$PATHWARDEN_ACTION_RESULT"
    exit 0
fi
echo 'Saying hello'
fp=$(printf '%s' "$req" | sed -n 's/.*"fingerprint":"\([A-Za-z0-9-]*\)".*/\1/p')
printf '{"schema":"pathwarden.action-result.v1","ok":true,"message":"Hello from %s."}' "$fp" > "$PATHWARDEN_ACTION_RESULT"
```

The helpers add UTF-8 in and out on Windows, a failed result with a plain
message for any error, the caps applied before Pathwarden applies them,
secrets from `*_env`, HTTPS requests that refuse to change anything on a
dry run, and checks of your describe block. See
[examples/actions](../examples/actions/README.md).

## JSON Schemas

JSON Schemas (draft 2020-12) for the three documents:

- [action-request.v1.json](schemas/action-request.v1.json): what the
  program reads.
- [action-describe.v1.json](schemas/action-describe.v1.json): what it
  answers to describe.
- [action-result.v1.json](schemas/action-result.v1.json): what it answers
  to run.

A describe or result that passes its schema passes Pathwarden's checks.
The few rules a schema can't say, such as unique IDs and a default that
must be one of the choices, are in each schema's `$comment` and in the
tables above. `scripts/check-action-examples.py` validates the examples
against them.

## Lifecycle

```text
  In the app: click "Open a ticket",          On the command line:
  fill in the inputs, click Run               pathwarden action run FINDING --action desk/open
               |                                          |
               +--------------------+---------------------+
                                    v
  Pathwarden    finds the finding in the run, checks the action applies to it,
                checks the inputs, and builds the request (kind "run")
                                    |
                                    v
  A job         one action at a time; Cancel stops it
                                    |
                                    v
  The program   reads the request on stdin  ---->  prints progress lines (shown live)
                does the work                      writes stderr (kept for the details)
                writes the result to PATHWARDEN_ACTION_RESULT, exits
                                    |
                                    v
  Pathwarden    checks the result: caps, https:// links, at most 5 records;
                a missing or broken result, a non-zero exit, a timeout or a
                cancel is a failed run
                                    |
                                    v
  Saved         unless a dry run: an Activity entry and the records, on the
                finding, in the run history's actions.json, pushed with the
                history
                                    |
                                    v
  Shown         the result card, the record's chip and the Activity list;
                on every later run, on every computer on that history
```

A `describe` request comes before all this, once per program until its
file or settings change.

## Security

An action runs your program, with your rights, on a finding from your
domain. These are the rules Pathwarden keeps, and what is left to you.

### What's sent

The program gets the finding, with names, paths, the guide and who
accepted a risk; the run's domains; the block's settings; and who asked,
from which computer. What leaves the computer is up to the program.

- Say it in `sends`, in plain words. The app shows it before every run, as
  does `pathwarden action run`. Keep it true when you change the program.
- Send only what the other system needs.
- **See exactly what's sent** in the app, and `pathwarden action request`,
  show the request as the program gets it.

### Secrets

- Never put a secret in a setting. Put it in an environment variable, and
  name the variable in a setting ending in `_env`: `token_env =
  "PATHWARDEN_DESK_TOKEN"`.
- `pathwarden action add` refuses a setting named like a secret (`token`,
  `password`, `secret`, `webhook`, `apikey`, `credential`) that doesn't
  end in `_env`.
- The program gets only the variables its `*_env` settings name, and the
  basics in [Each request](#each-request). Pathwarden's own secrets (the
  history passphrase, the evidence signing key, the collection password)
  are never passed, even when named.
- Don't print a secret, in progress lines or stderr, and don't put one in a
  result. Those are shown and saved.

### Who can add and change an action

- The `[[action]]` blocks stay in each computer's settings. They never
  travel through the run history, so a change pushed to the history can't
  add an action or change its program. Each computer that runs an action
  sets it up. Other computers on the same history see its records and
  Activity, but not the action.
- The app started with `--lock-destinations` can change only a block's name,
  time limit and filters. It can't add a block, change its program, or set
  or remove any of the program's settings, `*_env` included. The command
  line can, as can anyone who edits `pathwarden.toml`.
- A program is an absolute path, or an interpreter (`powershell`, `pwsh`,
  `python`, `python3`, `bash`, `sh`, `node`, `cmd`) found in a folder only
  administrators can change. A script it runs needs its full path. A
  network path or mapped network drive is refused, before Windows would
  sign in to that server.
- A program starts in a private folder of its own, never the folder
  Pathwarden was started from.

### Nothing runs unattended

- Actions never run from `pathwarden run` or a scheduled task.
- The app runs one only after someone clicks **Start** in its dialog.
- `pathwarden action run` and `pathwarden action test` ask first, unless
  `--yes`.
- `pathwarden action check` asks whenever a real finding would be sent: a
  block that is set up, or `--fingerprint`. A program given by its path,
  on the built-in sample finding, is checked without asking.
- Ctrl-C, **Cancel** and the time limit stop the program and every process
  it started.

### What Pathwarden refuses, and why

| Refused | Why |
|---|---|
| A link or record URL that isn't `https://`, or holds a user name or password. | People who trust a link on a finding click it. |
| Text read as HTML; control and bidirectional formatting characters. | A result can't change the page, or hide what a text says. |
| More than 5 links or records, text past its cap. | A result can't flood the finding or the history. |
| An answer file that isn't a plain file, or is over 1 MiB. | A pipe or link can't stall or redirect the read. |
| A result from a program that exited with an error. | "It worked" must mean it worked. |
| Running from a scheduled task. | Nobody is there to see what it sends. |

### What is left to you

An action isn't sandboxed. Pathwarden checks what comes back, not what the
program does.

- Keep the program and its scripts where only you and administrators can
  change them.
- Check certificates. Never turn TLS verification off: no
  `verify=False`, no `-SkipCertificateCheck`, no `ignore_https_errors`.
  Trust a company certificate authority through the system's certificate
  store instead. Python's `ssl.create_default_context()`, which the helper
  uses, reads the Windows store. With `requests`, call
  `truststore.inject_into_ssl()`. PowerShell, Edge and Playwright with
  `channel="msedge"` use the Windows store.
- Keep secrets out of what the program prints. Messages and progress
  lines are saved on the finding and shared with the history, and a
  webhook's address holds its key in the path. The helpers take the
  values of `*_env` secrets out of what they print, name only an
  address's scheme, host and port, and follow a redirect only to the
  same address, so a token isn't sent on.
- Reconcile by finding ID, so a retried run doesn't create a second ticket.

## Compatibility

- Version 1 only grows. New fields may appear in the request, the finding
  and the records. Ignore fields you don't know, and don't fail on them.
- Pathwarden ignores fields it doesn't know in your answers, so a program
  can write fields a later version reads.
- A change that would break a program gets a new schema (`v2`), and
  Pathwarden would say so. A program that sees another `schema` in a
  request should fail with a plain message.
- Check `schema` in what you read, and always write it in what you answer.

## An action that signs in through a browser

Some systems only take a person's sign-in, with single sign-on or a
second factor. An action can open a browser window, wait for the person to
sign in, and use that session. This sketch uses Playwright for Python with
the computer's Edge, so no browser is downloaded and certificates are
checked against the Windows store:

```python
import pathwarden_action as pw
from playwright.sync_api import sync_playwright  # pip install playwright

BASE = "https://portal.example.com"

def session_cookie(req):
    """Signs in through a browser window and returns the session cookie, kept in memory only."""
    pw.progress("Opening sign-in window")
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=False)
        page = browser.new_context().new_page()
        page.goto(f"{BASE}/login")
        pw.progress("Waiting for sign-in")
        page.wait_for_url(f"{BASE}/home**", timeout=5 * 60 * 1000)
        cookies = {c["name"]: c["value"] for c in page.context.cookies(BASE)}
        browser.close()
    if "session" not in cookies:
        raise pw.Failed("The sign-in didn't finish.")
    return cookies["session"]

def open_request(req):
    if req.dry_run:
        return pw.ok("Dry run: would sign in and open a request.")
    cookie = session_cookie(req)
    pw.progress("Opening the request")
    r = req.http("POST", f"{BASE}/api/requests", body={"title": req.finding["title"]},
                 headers={"Cookie": f"session={cookie}"}).json()
    pw.progress("Request created")
    return pw.ok(f"Opened {r['number']}.", records=[pw.record(r["id"], number=r["number"], status="Open", open=True)])

pw.main([{"id": "open", "label": "Open a service request", "once": True,
          "sends": "The finding's title, to the portal, after you sign in."}], {"open": open_request})
```

- Set the block's `timeout_seconds` to cover the sign-in, such as 900.
- The window opens on the desktop of the account running Pathwarden. So it
  works from the app and the command line, but not over a remote session
  without a desktop.
- Keep cookies and tokens in memory. Don't write them to a file, a
  progress line or the result.
- Don't pass `ignore_https_errors=True` or turn verification off in the
  HTTP library. If the portal uses a company certificate authority, it is
  in the Windows store already, and Edge and the helper trust it.
- The Python the block runs needs Playwright installed: `python -m pip
  install playwright` with that same python.exe.

More: [Writing an action](actions.md),
[examples/actions](../examples/actions/README.md),
[File formats](dev/formats.md#finding-actions-pathwardenaction-v1).
