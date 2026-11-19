# Writing an action

A finding action is your own program that Pathwarden runs for one finding
when someone asks: open a ticket, alert a team, look up an owner, run a
check. Each action is a button on the finding in the app, and
`pathwarden action run` on the command line. What it did is saved on the
finding, so everyone who shares the run history sees it.

This page takes you from nothing to a working button in about ten minutes,
then covers everything you need for a solid one:

- [What actions are](#what-actions-are)
- [Quick start: alert a team](#quick-start-alert-a-team)
- [Concepts](#concepts)
- [Protocol reference](#protocol-reference)
- [Lifecycle](#lifecycle)
- [Security](#security)
- [Testing and debugging](#testing-and-debugging)
- [Compatibility](#compatibility)
- [Recipes](#recipes)
- [FAQ](#faq)

The kit is in the repository: the Python and PowerShell helpers and three
tested examples in [examples/actions](../examples/actions/README.md), and
the JSON Schemas in [docs/schemas](schemas/).

## What actions are

[Output plugins](plugins.md) and finding actions are both your programs,
started by Pathwarden. They answer different questions.

| | Output plugin (`[[output]]`) | Finding action (`[[action]]`) |
|---|---|---|
| Runs | After every run, by itself. | When someone asks, for one finding. |
| Gets | The whole run: the event document. | One finding, the run it is in, and what the person typed. |
| Gives back | Its exit code and output lines. | A result: a message, links and records. |
| Shows | In the run's log. | Live progress lines, then a result on the finding. |
| Remembers | Nothing. It reconciles by finding ID every run. | Records and activity on the finding, in the run history. |
| From a scheduled task | Yes. | Never. |

Use an output plugin to keep another system in step with every run, such
as one ticket per open finding. Use an action for a person's decision about
one finding: "open a request for this one", "tell the team about this".

The words this page uses:

- A **program** is one `[[action]]` block in `pathwarden.toml`. It may offer
  several actions.
- An **action** is one button. It is addressed as `<block name>/<id>`, such
  as `desk/open`.
- An **input** is a field the action asks for before it runs.
- A **progress line** is a line the program prints while it runs.
- A **result** is what the program says it did.
- A **record** is something the action created or looks after, such as a
  ticket. It is saved on the finding.
- **Activity** is the list of runs on a finding: who ran what, when, and
  how it went.
- A **follow-up** is an action that runs on a record, such as **Check
  status**.

## Quick start: alert a team

You build a PowerShell action that posts a finding to a team's chat
channel. It takes about ten minutes. You need:

- Pathwarden with finding actions (1.0.0-rc.3 or later) and one saved run.
  To get one, click **Try the demo** on the app's **Home**, or run
  `pathwarden run --save -i demo:`.
- Windows PowerShell 5.1, which Windows has, or PowerShell 7.
- An incoming webhook URL for a chat channel. Slack, Google Chat,
  Mattermost and Rocket.Chat take the `{"text": ...}` body this action
  posts. For Microsoft Teams, use
  [post-to-webhook.ps1](../examples/actions/post-to-webhook.md), which
  posts an Adaptive Card. To try it without a chat service, run
  [stub-desk.py](../examples/actions/stub-desk.py) and use
  `http://127.0.0.1:8765/api/hooks/team`.

When the app has more than one environment, add `--env NAME` to each
`pathwarden action` command below.

### 1. Make a folder for actions

Programs in this folder run with your rights, so keep it in a place only
you and administrators can change.

```powershell
New-Item -ItemType Directory -Force C:\Pathwarden\actions
Invoke-WebRequest https://raw.githubusercontent.com/marbas207/Pathwarden/main/examples/actions/PathwardenAction.psm1 -OutFile C:\Pathwarden\actions\PathwardenAction.psm1
```

`PathwardenAction.psm1` is the helper. It reads the request, answers
Pathwarden, prints progress and writes the result, so your script holds
only what the action does.

### 2. Write the action

Save this as `C:\Pathwarden\actions\alert-team.ps1`:

```powershell
# alert-team.ps1: a Pathwarden finding action that posts a finding to a chat webhook.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'PathwardenAction.psm1')

$actions = @(
    @{
        id     = 'alert'
        label  = 'Alert the team'
        sends  = "The finding's ID, title and your note, to the team's chat webhook."
        inputs = @(@{ id = 'note'; label = 'Note for the team'; type = 'textarea' })
    }
)

Invoke-PathwardenAction -Describe $actions -Handlers @{
    alert = {
        param($Request)
        $url = Get-PathwardenSecret -Request $Request -Name webhook
        $f = $Request.finding
        $text = "$($f.fingerprint): $($f.title)`n$($Request.inputs.note)"
        if ($Request.dry_run) { return New-PathwardenResult "Dry run: would post $($f.fingerprint)." }
        Write-PathwardenProgress 'Posting to the webhook'
        $null = Invoke-PathwardenHttp -Request $Request -Method Post -Uri $url -Body @{ text = $text }
        New-PathwardenResult "Posted $($f.fingerprint) to the team's channel."
    }
}
```

- `$actions` describes the button: its label, what it sends, and its one
  input.
- The `alert` handler runs when someone clicks it. `$Request` holds the
  finding, the inputs and the settings.
- `Get-PathwardenSecret` reads the webhook URL from the environment
  variable that the `webhook_env` setting names. The URL is a secret, so it
  is never in `pathwarden.toml`.
- On a dry run, the handler returns before it posts anything.

### 3. Put the webhook URL in an environment variable

```powershell
[Environment]::SetEnvironmentVariable('PATHWARDEN_ALERT_WEBHOOK', 'https://hooks.example.com/your-webhook', 'User')
```

Open a new terminal, and restart the app, so they see it. Pathwarden
passes an action only the variables its `*_env` settings name, and a few
basics such as `PATH`.

### 4. Check it

```powershell
pathwarden action check C:\Pathwarden\actions\alert-team.ps1 --setting webhook_env=PATHWARDEN_ALERT_WEBHOOK
```

`action check` asks the program what it offers, then runs a dry run of
every action it describes, whatever its filters and `when` say, on a
sample finding, and names every problem:

```
Checking alert-team on PW-001-0000000000000000, a sample finding.
No problems: its describe and every dry run passed the checks.
```

### 5. Add it

#### In the app

1. Start the app with `pathwarden ui --allow-destinations`. Without the
   flag, the app can't add an action.
2. In the rail, under **Automate**, click **Plugins and actions**.
3. Under **Finding actions**, add the program: the command below, and the
   setting `webhook_env` = `PATHWARDEN_ALERT_WEBHOOK`.
4. Click **Test**: a dry run on the latest run's first finding it applies
   to.

#### On the command line

```powershell
pathwarden action add --name team-chat --setting webhook_env=PATHWARDEN_ALERT_WEBHOOK -- powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Pathwarden\actions\alert-team.ps1
pathwarden action test team-chat
```

Both write this block to the environment's `pathwarden.toml`:

```toml
[[action]]
name = "team-chat"
command = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "C:\\Pathwarden\\actions\\alert-team.ps1"]
webhook_env = "PATHWARDEN_ALERT_WEBHOOK"
```

### 6. Run it

#### In the app

1. Open a run's report and a finding.
2. Click **Alert the team** in the finding's action bar.
3. Type a note, and click **Run**.

#### On the command line

```powershell
pathwarden action list --fingerprint PW-006-1bbba15126c6fc31
pathwarden action run PW-006-1bbba15126c6fc31 --action team-chat/alert --input note="Can you look at this today?"
```

```
Alert the team (team-chat/alert) on PW-006-1bbba15126c6fc31: Kerberoastable account SVC-00000@SCALE.LOCAL is Tier Zero, in run 20261118-223201-59d471.
It sends: The finding's ID, title and your note, to the team's chat webhook.
Run it? [y/N] y
  [team-chat] Posting to the webhook
Done: Posted PW-006-1bbba15126c6fc31 to the team's channel.
```

That's a working action. The rest of this page makes it a solid one.

## Concepts

### Programs and actions

An `[[action]]` block names one program and its settings. When Pathwarden
needs to know what the program offers, it runs it with a `describe`
request. The program answers with a list of actions, at most 20, each a
button. Pathwarden keeps that answer in memory until the program's file,
its script or its settings change.

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
  every block a name: `action-N` changes when blocks move.
- `plugin = "x"` runs `pathwarden-action-x` from beside Pathwarden or its
  `plugins` folder. Otherwise `command` gives the program and its
  arguments.
- `name`, `plugin`, `command`, `timeout_seconds`, `min_severity`, `rules`
  and `categories` are Pathwarden's. Every other key goes to the program as
  a setting.

### Inputs

An input is a field the action asks for before it runs. Pathwarden checks
what the person gave against the input's type before the program starts,
so the program gets clean values.

| Type | The dialog shows | The program gets |
|---|---|---|
| `text` | One line, at most `max` characters (default 200, at most 1,000). | Text, trimmed. |
| `textarea` | Several lines, at most `max` (default 2,000, at most 4,000). | Text with `\n` line breaks. |
| `choice` | A list of `choices`, at most 50. | The choice, spelled as described. |
| `bool` | A switch. | `true` or `false`. |

- Every input the action describes is in the request. One left empty is
  `""`, or its `default`. A `choice` without a default gets its first
  choice; a `bool` gets `false`.
- `required: true` stops the run while the input is empty, with
  "<label> is needed."
- Control characters are refused, except line breaks and tabs in a
  `textarea`.
- On the command line, `--input id=value` gives an input. A `choice`
  matches in any case. A `bool` takes true, false, yes, no, on, off, 1
  or 0.

### Progress lines

Each line the program prints to stdout is a progress line, shown while it
runs: "Opening sign-in window", "Waiting for sign-in", "Request created".
Pathwarden keeps the latest 200, each cut to 500 characters, with control
characters dropped. Print UTF-8, and flush after each line, or the lines
arrive all at once at the end. The helpers do both.

stderr is kept separately, up to 64 KiB, for **Show details** in the app
and the details the command line prints when a run fails. Put what helps
someone fix a failure there, never secrets.

### Results

A run ends with a result: `ok` (whether it worked), a `message`, up to five
`links`, and up to five `records`. The program writes it as JSON to the file
named in `PATHWARDEN_ACTION_RESULT`.

A run counts as worked only when the result says `ok: true` and the
program exits 0. A missing or broken result is a failed run, shown with the
program's output. So is a run that passes its time limit or is cancelled.

### Records

A record is something the action created or looks after for the finding,
usually a ticket: its `id` in the other system, its `number`, `status` and
`url`, whether it is still `open`, and up to 20 named `fields`.

- Pathwarden saves every record a run returns on the finding, in the run
  history's `actions.json`. It is encrypted and shared with the rest of the
  history, so every computer on that history sees it on every later run.
- The finding's ID stays the same across runs, so its records stay with it.
- A record stays until someone removes it, in the app or with
  `pathwarden action records remove`.
- A follow-up that returns a record with the same `id` replaces it: the
  stored record becomes the one returned. Return every field you want
  kept, not only the ones that changed; a field left out is gone.
- `open: true` keeps a `once` action hidden, and makes a fixed finding's
  chip read "Fixed — DESK0001 still Open".

### Activity

Every run that isn't a dry run is saved on the finding's **Activity**,
newest first: who ran which action, from which computer, when, whether it
worked and its message. Failed runs are listed too. Pathwarden keeps the
latest 100 per finding. `pathwarden action activity FINDING_ID` prints
them, and `pathwarden action records FINDING_ID` the records.

### Follow-ups

A follow-up runs on a record rather than on the finding: **Check status**,
**Close ticket**. It is an action with `for: "record"`, and the action that
makes the record lists it in `follow_ups`:

```json
"actions": [
  { "id": "open", "label": "Open a ticket", "once": true, "follow_ups": ["status", "close"], "sends": "..." },
  { "id": "status", "label": "Check status", "for": "record", "sends": "..." },
  { "id": "close", "label": "Close ticket", "for": "record", "when": ["fixed"], "sends": "..." }
]
```

The request of a follow-up carries the record in `record`. A follow-up is
offered only on a record its program's action made, and only among that
program's actions.

### `once`, `for` and `when`

| Field | Effect |
|---|---|
| `once: true` | The action is hidden while the finding has an open record from it. One ticket per finding. |
| `for: "record"` | Only offered as a follow-up on a record. |
| `when` | The finding statuses the action is offered on: one of `open`, `held`, `accepted` and `fixed`, or a list of them. Without it: open, held and accepted; a `for: "record"` action without it is offered on its records whatever the finding's status, fixed included. |

A fixed finding shows only the actions whose `when` lists `fixed`, and the
follow-ups of its records. So a "close the ticket" follow-up says
`"when": ["fixed"]`, and an action for every finding says
`"when": ["open", "held", "accepted", "fixed"]`. A single status, such as
`"when": "fixed"`, means the same as a list of that one.

A finding's status is in the request's `finding.status`:

- `open`: found by this run.
- `accepted`: found, and covered by an accepted risk.
- `held`: this run couldn't check it, such as when a collection missed its
  domain. It isn't fixed.
- `fixed`: found by the previous run, gone from this one.

### Filters

Two sets of filters decide which findings an action is offered on. Both
must match.

- The block's `min_severity`, `rules` and `categories`, set by whoever adds
  the action. They can be changed in the app without
  `--allow-destinations`.
- The action's own `applies_to`, with the same three keys, set by whoever
  writes the program.

`min_severity` is `critical`, `high`, `medium`, `low` or `info`. `rules`
are rule IDs such as `PW-006`. `categories` are `attack_path` and
`hygiene`. A fixed or held finding is rated by its rule: its category, and
for a held one the highest severity its rule gives.

### Dry runs

A dry run asks the program to change nothing: `dry_run` is `true` in the
request. **Test only** in the app, `--dry-run` on the command line,
`pathwarden action test` and `pathwarden action check` all send one.

A good dry run does everything short of the change: it reads the settings,
finds the secrets, builds what it would send, and may read from the other
system. It then says what it would have done: "Dry run: would open
"Pathwarden PW-006: ..." at https://desk.example.com/api." Dry runs aren't
saved on the finding.

Pathwarden can't enforce a dry run: it trusts the program. The helpers'
HTTP functions refuse anything but GET and HEAD on a dry run, so a
forgotten check fails the dry run instead of changing something.

## Protocol reference

Version 1. Every field, limit and message here matches what Pathwarden
checks; the [JSON Schemas](#json-schemas) say the same in a form tools can
read.

### How a program is run

For each request, Pathwarden:

1. starts the program with a cleared environment: `PATH`, `SYSTEMROOT`,
   `SYSTEMDRIVE`, `TEMP`, `TMP`, `HOME`, `USERPROFILE`, `APPDATA`,
   `LOCALAPPDATA`, `COMSPEC`, `PATHEXT`, `WINDIR`, the proxy variables
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

### The request

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

The finding is the run's [event document](dev/formats.md#the-event-document-pathwardeneventv1)
entry as it is, plus two fields:

- `status`: `open`, `accepted`, `held` or `fixed`.
- `guide`: the rule's step-by-step guide in Markdown, or null.

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

### The describe answer

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
| `once` | true or false | no | Hide the action while the finding has an open record from it. |
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

### The result

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

### Limits

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

Text is never read as HTML. Control characters and bidirectional
formatting characters are dropped, tabs become spaces, and text is trimmed.
Line breaks are kept only in the message.

### Without a helper

The helpers are optional: any program that follows the protocol works. A
whole action in Windows PowerShell, without the helper:

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
holds only letters, digits and dashes, so `sed` can pick it out; for
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

What the helpers add: UTF-8 in and out on Windows, a failed result with a
plain message for any error, the caps applied before Pathwarden applies
them, secrets from `*_env`, HTTPS requests that refuse to change anything
on a dry run, and checks of your describe block. See
[examples/actions](../examples/actions/README.md).

### JSON Schemas

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

- Say it in `sends`, in plain words: the app shows it before every run, as
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
  basics in [How a program is run](#how-a-program-is-run). Pathwarden's own
  secrets (the history passphrase, the evidence signing key, the collection
  password) are never passed, even when named.
- Don't print a secret, in progress lines or stderr, and don't put one in a
  result. Those are shown and saved.

### Who can add and change an action

- The `[[action]]` blocks stay in each computer's settings. They never
  travel through the run history, so a change pushed to the history can't
  add an action or change its program. Each computer that runs an action
  sets it up.
- The app without `--allow-destinations` can change only a block's name,
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
- The app runs one only after someone clicks **Run** in its dialog.
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
| A link or record URL that isn't `https://`, or holds a user name or password. | A link on a finding is clicked by people who trust it. |
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
  store instead. Python's `ssl.create_default_context()`, used by the
  helper, reads the Windows store; with `requests`, call
  `truststore.inject_into_ssl()`. PowerShell, Edge and Playwright with
  `channel="msedge"` use the Windows store.
- Keep secrets out of what the program prints. Messages and progress
  lines are saved on the finding and shared with the history, and a
  webhook's address holds its key in the path. The helpers take the
  values of `*_env` secrets out of what they print, name only an
  address's scheme, host and port, and follow a redirect only to the
  same address, so a token isn't sent on.
- Reconcile by finding ID, so a retried run doesn't create a second ticket.

## Testing and debugging

### Check a program

```powershell
pathwarden action check C:\Pathwarden\actions\rest-ticket.py --setting base_url=https://desk.example.com/api --setting token_env=PATHWARDEN_DESK_TOKEN
```

`action check` runs the program's describe, then a dry run of every action
it describes, whatever its `applies_to`, `when` and the block's filters
say, on a sample finding (a follow-up on a sample record), with each
input's default or sample text. It names every problem, and exits 2 when
there are any:

```
Checking rest-ticket on PW-001-0000000000000000, a sample finding.
2 problems:
  - describe: actions[0].inputs[1].type 'number' isn't one of text, textarea, choice, bool
  - rest-ticket/status: dry run failed: Set base_url in this action's settings.
```

- Give settings with `--setting name=value`, before any `--`.
- A `.ps1`, `.py`, `.sh` or `.js` path runs with its interpreter. `python`
  must be in a folder only administrators can change. If yours is a user
  install, give its full path, with the script after `--`:
  `pathwarden action check C:\Users\you\AppData\Local\Programs\Python\Python313\python.exe --setting name=value -- C:\Pathwarden\actions\rest-ticket.py`.
- `pathwarden action check NAME` checks a block that is set up, with its
  settings.
- `--fingerprint FINDING_ID` dry-runs on a real finding of the environment
  instead of the sample.

### See the request

```powershell
pathwarden action request PW-006-1bbba15126c6fc31 --action desk/open --input note="Please review" > request.json
```

prints the request the program would get. With no action set up, it
prints one with an empty `action`, `inputs` and `settings`: enough to
start writing.

### Feed a request by hand

Run the program the way Pathwarden does, and read what it wrote. In
PowerShell:

```powershell
# Windows PowerShell 5.1: pass text as UTF-8.
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false
pathwarden action request PW-006-1bbba15126c6fc31 --action team-chat/alert --input note="Please review" --dry-run > request.json
$env:PATHWARDEN_ACTION_REQUEST = 'run'
$env:PATHWARDEN_ACTION_RESULT = "$PWD\result.json"
Get-Content request.json -Raw | powershell -NoProfile -ExecutionPolicy Bypass -File C:\Pathwarden\actions\alert-team.ps1
"exit code $LASTEXITCODE"
Get-Content result.json
```

In bash:

```sh
pathwarden action request PW-006-1bbba15126c6fc31 --action desk/open --dry-run > request.json
PATHWARDEN_ACTION_REQUEST=run PATHWARDEN_ACTION_RESULT="$PWD/result.json" \
    python3 /opt/pathwarden/actions/rest-ticket.py < request.json
echo "exit code $?"; cat result.json
```

Edit `request.json` to try a case: `"dry_run": false`, another input, a
`"status": "fixed"` finding, or a `record` for a follow-up. Without
`PATHWARDEN_ACTION_RESULT`, the helpers print the answer to stdout.

### Dry runs and real runs

- `pathwarden action test NAME` dry-runs a block's first action on the
  first finding of the latest run it applies to; `--action ID` picks
  another action.
- `pathwarden action run FINDING_ID --action NAME/ID --dry-run` dry-runs on
  the finding you choose; without `--dry-run` it runs for real.
- `--json` on `action run` prints the outcome as JSON: `ok`, `message`,
  `links`, `records`, `progress`, `details` (stderr), `problems` and how it
  `ended`.
- In the app, **Test only** in the dialog is a dry run.

### Where the output goes

| Output | While it runs | Afterwards |
|---|---|---|
| stdout | Each line shown as progress: in the dialog, or prefixed with the block's name on the command line. | The latest 200 lines are in the outcome (`--json`). |
| stderr | Not shown. | **Show details** in the app; on the command line, printed under "Details" when the run failed. |
| The result | | The result card, and the command line's "Done:" line. Unless a dry run, saved on the finding's Activity and records. |
| What was wrong with the result | | Notes under the result, and `problems` in `--json`. |

Pathwarden doesn't keep the request or the answer file: the file is removed
once read. Log to stderr what you need for a failure.

### Common problems

| You see | Why | Fix |
|---|---|---|
| `python was not found in a system folder on PATH` | A user install of Python isn't trusted. | Give python.exe's full path in `command` and in `action check`. |
| `... is a relative path` | Programs start in their own folder. | Give the script's full path. |
| `It ended without a result (exit code 1).` | The program failed before writing the result file. | Run it by hand and read stderr. |
| `it wrote nothing to the file named in PATHWARDEN_ACTION_RESULT` | describe didn't write its answer. | Write the describe answer to that file, not to stdout. |
| `It said it worked, but ended with exit code 1.` | `ok: true` and a non-zero exit. | Exit 0 when it worked. |
| All progress lines at once at the end | stdout is buffered. | Flush after each line. |
| `?` or garbled letters in names | Not UTF-8. | Read stdin and write stdout as UTF-8. The helpers do. |
| `The environment variable X (named by token_env) isn't set` | Pathwarden passes only named variables, from its own environment. | Set it for the account, then restart the terminal or the app. |

## Compatibility

- Version 1 only grows. New fields may appear in the request, the finding
  and the records. Ignore fields you don't know, and don't fail on them.
- Pathwarden ignores fields it doesn't know in your answers, so a program
  can write fields a later version reads.
- A change that would break a program gets a new schema (`v2`), and
  Pathwarden would say so. A program that sees another `schema` in a
  request should fail with a plain message.
- Check `schema` in what you read, and always write it in what you answer.

## Recipes

### A REST ticket with status and close

[rest-ticket.py](../examples/actions/rest-ticket.md) opens a ticket in any
JSON REST API, saves it as a record, checks its status, and closes it once
the finding is fixed.

```toml
[[action]]
name = "desk"
command = ["C:\\Program Files\\Python313\\python.exe", "C:\\Pathwarden\\actions\\rest-ticket.py"]
base_url = "https://desk.example.com/api"
token_env = "PATHWARDEN_DESK_TOKEN"
queue = "Identity"
```

What makes it solid:

- `open` has `once: true` and searches for an open ticket with the
  finding's ID before it creates one, so a second click or a retry returns
  the same ticket.
- Every ticket comes back as a record with `open` set from its status, so
  the chip and `once` stay right.
- `status` and `close` are follow-ups. `close` says `"when": ["fixed"]`, so
  it shows only once Pathwarden no longer finds the issue, and refuses to
  run on a finding that isn't fixed.
- The paths, the field names and the closed statuses are settings, so most
  ticket systems fit without code changes.
- [stub-desk.py](../examples/actions/stub-desk.py) is a ticket system on
  your computer to try it against.

### A chat alert

[post-to-webhook.ps1](../examples/actions/post-to-webhook.md) posts a
finding to Teams, Slack or any webhook that takes JSON, and returns only a
message.

```toml
[[action]]
name = "alert"
command = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "C:\\Pathwarden\\actions\\post-to-webhook.ps1"]
webhook_env = "PATHWARDEN_ALERT_WEBHOOK"
format = "teams"
min_severity = "high"
```

A webhook URL is a secret: anyone with it can post. Keep it in the
variable `webhook_env` names. Without a record, every click posts again,
and each post is in the finding's Activity.

### An owner lookup that shows a message

[owner-lookup.py](../examples/actions/owner-lookup.md) says who owns the
objects a finding is about, from a CSV file of name patterns. It has one
`choice` input, **Look up**: the affected objects, or those and the
objects on the path. It changes nothing and sends nothing, so it says
`"sends": "Nothing: it reads a file of owners on this computer."`, and a
dry run does the same as a run. The same shape fits a lookup in a CMDB
or an HR API: read, then answer in the message.

### An action that signs in through a browser

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
- The window opens on the desktop of the account running Pathwarden, so it
  works from the app and the command line, not over a remote session
  without a desktop.
- Keep cookies and tokens in memory. Don't write them to a file, a
  progress line or the result.
- Don't pass `ignore_https_errors=True` or turn verification off in the
  HTTP library. If the portal uses a company certificate authority, it is
  in the Windows store already, and Edge and the helper trust it.
- The Python the block runs needs Playwright installed: `python -m pip
  install playwright` with that same python.exe.

## FAQ

**Can an action run on every run?**
No: that's an [output plugin](plugins.md). Actions run only when someone
asks.

**Why is my action missing on a finding?**
Its block's filters or its `applies_to` don't match, its `when` doesn't
list the finding's status, it is a `for: "record"` follow-up, or it has
`once` and the finding has an open record from it. `pathwarden action list`
names a program's problems; `pathwarden action list --fingerprint ID`
shows what applies to one finding.

**Why don't I see my action on a fixed finding?**
A fixed finding shows only actions whose `when` lists `fixed`, and the
follow-ups of its records.

**Can one program offer several actions?**
Yes, up to 20, each a button. Several `[[action]]` blocks can also run the
same program with different settings, such as one per team.

**Does Pathwarden ask the program what it offers every time?**
No. It keeps the describe answer until the program's file, its script or
its settings change. A describe that failed is asked again after 30
seconds.

**Can an action change the finding: accept a risk, retest it?**
No. It returns a result, records and links. People accept risks and
retest.

**Is anything saved from a dry run?**
No. Only runs that aren't dry runs are saved in the finding's Activity.

**Do other computers on the same history get my action?**
They see its records and Activity. They don't get the action: each
computer sets up its own `[[action]]` blocks.

**Which languages work?**
Any. The program reads JSON on stdin and writes a JSON file: Python,
PowerShell, sh, Node.js, or a compiled program given by its full path.

**Does it work on Linux?**
Yes. Use a `.sh` or `.py` script with `sh`, `bash`, `python3` or `pwsh`
from `/usr/bin`, or a program by its full path. The private folder is
`~/.local/state/pathwarden/plugin-work`.

**How do I test without a real ticket system?**
Run [stub-desk.py](../examples/actions/stub-desk.py) and point
`base_url` at `http://127.0.0.1:8765/api`. The helpers allow `http://`
only to this computer.

More: [examples/actions](../examples/actions/README.md),
[output plugins](plugins.md), [File formats](dev/formats.md#finding-actions-pathwardenaction-v1).
