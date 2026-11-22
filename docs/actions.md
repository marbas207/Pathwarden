# Writing an action

A finding action is your own program that Pathwarden runs for one finding
when someone asks: open a ticket, alert a team, look up an owner. It is a
button on the finding in the app, and `pathwarden action run` on the
command line. What it did is saved on the finding.

To set up the examples without writing code, and for how actions differ
from output plugins, see [Using finding actions](finding-actions.md). Every
field and limit is in the [Action reference](action-reference.md). The
helpers and examples are in
[examples/actions](../examples/actions/README.md).

- [Quick start: alert a team](#quick-start-alert-a-team)
- [How an action works](#how-an-action-works)
- [Testing and debugging](#testing-and-debugging)
- [Examples](#examples)
- [FAQ](#faq)

## Quick start: alert a team

You build a PowerShell action that posts a finding to a team's chat
channel. You need:

- Pathwarden 1.0.0-rc.3 or later and one saved run. Click **Try the demo**
  on the app's **Home**, or run `pathwarden run --save -i demo:`.
- Windows PowerShell 5.1, which Windows has, or PowerShell 7.
- An incoming webhook URL for a chat channel that takes a
  `{"text": ...}` body: Slack, Google Chat, Mattermost or Rocket.Chat. For
  Microsoft Teams, use [post-to-webhook.ps1](../examples/actions/post-to-webhook.md),
  which posts an Adaptive Card. With no chat service, run
  [stub-desk.py](../examples/actions/stub-desk.py) and use
  `http://127.0.0.1:8765/api/hooks/team`.

When the app has more than one environment, add `--env NAME` to each
`pathwarden action` command below.

### 1. Make a folder for actions

Programs in this folder run with your rights, so keep it where only you
and administrators can change it. Put the helper in it:

```powershell
New-Item -ItemType Directory -Force C:\Pathwarden\actions
Invoke-WebRequest https://raw.githubusercontent.com/marbas207/Pathwarden/main/examples/actions/PathwardenAction.psm1 -OutFile C:\Pathwarden\actions\PathwardenAction.psm1
```

The helper reads the request, answers Pathwarden, prints progress and
writes the result, so your script holds only what the action does.

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

`$actions` describes the button: its label, what it sends, and its one
input. The `alert` handler runs when someone clicks it, with the finding,
the inputs and the settings in `$Request`. `Get-PathwardenSecret` reads the
webhook URL from the variable the `webhook_env` setting names, so the
secret is never in `pathwarden.toml`. On a dry run, the handler returns
before it posts.

### 3. Put the webhook URL in an environment variable

```powershell
[Environment]::SetEnvironmentVariable('PATHWARDEN_ALERT_WEBHOOK', 'https://hooks.example.com/your-webhook', 'User')
```

Open a new terminal and restart the app so they see it. Pathwarden passes
an action only the variables its `*_env` settings name, and a few basics
such as `PATH`.

### 4. Check it

```powershell
pathwarden action check C:\Pathwarden\actions\alert-team.ps1 --setting webhook_env=PATHWARDEN_ALERT_WEBHOOK
```

```
Checking alert-team on PW-001-0000000000000000, a sample finding.
No problems: its describe and every dry run passed the checks.
```

### 5. Add it

#### In the app

1. In the rail, under **Automate**, click **Plugins and actions**, then
   **Add**.
2. Click **Alert a team**, then **Next**.
3. Fill in **Name** (`team-chat`), **Program** (`powershell`),
   **Arguments, one per line** (the arguments of the command below), and
   the setting `webhook_env` = `PATHWARDEN_ALERT_WEBHOOK`. Click **Save**.
4. Click **Test** for a dry run on the latest run's first finding it
   applies to.

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
3. Type a note, and click **Start**.

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

## How an action works

### Programs and actions

A program is one `[[action]]` block in `pathwarden.toml`: a `name`, a
`command`, and settings. Pathwarden asks it what it offers with a
`describe` request, and it answers with up to 20 actions. Each action is
a button, addressed as `<block name>/<id>`, such as `desk/open`. Every key
Pathwarden doesn't own goes to the program as a setting.
[The action block](action-reference.md#the-action-block) lists the keys.

### Inputs

An input is a field the action asks for before it runs: `text`,
`textarea`, `choice` or `bool`. Pathwarden checks the value against its
type before the program starts, so the program gets clean values. See
[Input values](action-reference.md#input-values).

### Progress lines

Each line the program prints to stdout shows while it runs, such as
"Waiting for sign-in". Print UTF-8 and flush after each line; the helpers
do both. stderr is kept for **Show details**, so put what helps fix a
failure there, never secrets.

### Results

A run ends with a result: `ok`, a `message`, up to five `links` and up to
five `records`, written as JSON to the file named in
`PATHWARDEN_ACTION_RESULT`. A run worked only when the result says
`ok: true` and the program exits 0. See
[The result](action-reference.md#the-result).

### Records

A record is something the action created or looks after, usually a
ticket: its ID in the other system, number, status, link and whether it is
still open. Pathwarden saves it on the finding in the run history, so
every computer on that history sees it on later runs. A follow-up that
returns the same `id` replaces the record, so return every field you want
kept. See [Records and activity](action-reference.md#records-and-activity).

### Activity

Every run that isn't a dry run is listed on the finding's **Activity**:
who ran which action, from which computer, when, and how it went.
`pathwarden action activity FINDING_ID` prints it, and
`pathwarden action records FINDING_ID` prints the records.

### Follow-ups

A follow-up runs on a record rather than on the finding, such as
**Check status** or **Close ticket**. It is an action with
`for: "record"`, and the action that makes the record lists it in
`follow_ups`. Its request carries the record in `record`.

```json
"actions": [
  { "id": "open", "label": "Open a ticket", "once": true, "follow_ups": ["status", "close"], "sends": "..." },
  { "id": "status", "label": "Check status", "for": "record", "sends": "..." },
  { "id": "close", "label": "Close ticket", "for": "record", "when": ["fixed"], "sends": "..." }
]
```

### `once`, `for` and `when`

`once: true` hides an action while the finding has an open ticket from it
or from an output plugin, so each finding gets one ticket. `for: "record"`
offers it only as a follow-up. `when` lists the finding statuses it shows
on: `open`, `held`, `accepted` and `fixed`. A fixed finding shows only
actions whose `when` lists `fixed`, so a close follow-up says
`"when": ["fixed"]`. See
[Which findings show an action](action-reference.md#which-findings-show-an-action).

### Filters

The block's `min_severity`, `rules` and `categories`, set by whoever adds
the action, and the action's own `applies_to`, set by whoever writes it,
must both match a finding. See [Filters](action-reference.md#filters).

### Dry runs

A dry run sets `dry_run` to `true`: change nothing. **Test only** in the
app, `--dry-run`, `pathwarden action test` and `pathwarden action check`
all send one. A good dry run reads the settings, finds the secrets,
builds what it would send, and may read from the other system. Then it
says what it would have done: "Dry run: would open "Pathwarden PW-006:
..." at https://desk.example.com/api." Dry runs aren't saved on the
finding.

Pathwarden can't enforce a dry run; it trusts the program. The helpers'
HTTP functions refuse anything but GET and HEAD on a dry run, so a
forgotten check fails the dry run instead of changing something.

## Testing and debugging

### Check a program

```powershell
pathwarden action check C:\Pathwarden\actions\rest-ticket.py --setting base_url=https://desk.example.com/api --setting token_env=PATHWARDEN_DESK_TOKEN
```

`action check` runs the program's describe, then a dry run of every action
on a sample finding (a follow-up on a sample record), whatever its filters
and `when` say, with each input's default or sample text. It names every
problem and exits 2 when there are any:

```
Checking rest-ticket on PW-001-0000000000000000, a sample finding.
2 problems:
  - describe: actions[0].inputs[1].type 'number' isn't one of text, textarea, choice, bool
  - rest-ticket/status: dry run failed: Set base_url in this action's settings.
```

- Give settings with `--setting name=value`, before any `--`.
- A `.ps1`, `.py`, `.sh` or `.js` path runs with its interpreter. `python`
  must be in a folder only administrators can change. For a user install,
  give its full path, with the script after `--`:
  `pathwarden action check C:\Users\you\AppData\Local\Programs\Python\Python313\python.exe --setting name=value -- C:\Pathwarden\actions\rest-ticket.py`.
- `pathwarden action check NAME` checks a block that is set up, with its
  settings.
- `--fingerprint FINDING_ID` dry-runs on a real finding instead of the
  sample.

### See the request

```powershell
pathwarden action request PW-006-1bbba15126c6fc31 --action desk/open --input note="Please review" > request.json
```

This prints the request the program would get. With no action set up, it
prints one with an empty `action`, `inputs` and `settings`, which is
enough to start writing.

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
  first finding of the latest run it applies to. `--action ID` picks
  another action.
- `pathwarden action run FINDING_ID --action NAME/ID --dry-run` dry-runs on
  the finding you choose. Without `--dry-run`, it runs for real.
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

Pathwarden doesn't keep the request or the answer file, which it removes
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

## Examples

- [rest-ticket.py](../examples/actions/rest-ticket.md) opens a ticket in a
  JSON REST API, saves it as a record, checks its status and closes it
  once the finding is fixed.
- [post-to-webhook.ps1](../examples/actions/post-to-webhook.md) posts a
  finding to Teams, Slack or any JSON webhook, and returns only a message.
- [owner-lookup.py](../examples/actions/owner-lookup.md) says who owns a
  finding's objects, from a CSV file, and changes nothing.
- [An action that signs in through a browser](action-reference.md#an-action-that-signs-in-through-a-browser)
  is a sketch for systems that need a person's single sign-on.

## FAQ

**Why is my action missing on a finding?**
Its block's filters or its `applies_to` don't match, its `when` doesn't
list the finding's status (a fixed finding needs `fixed`), it is a
`for: "record"` follow-up, or it has `once` and the finding has an open
record from it. `pathwarden action list` names a program's problems, and
`pathwarden action list --fingerprint ID` shows what applies to one
finding.

**Can an action change the finding, such as accept a risk or retest it?**
No. It returns a result, records and links. People accept risks and
retest.

**Which languages work?**
Any. The program reads JSON on stdin and writes a JSON file: Python,
PowerShell, sh, Node.js, or a compiled program given by its full path. See
[Without a helper](action-reference.md#without-a-helper).

**Does it work on Linux?**
Yes. Use a `.sh` or `.py` script with `sh`, `bash`, `python3` or `pwsh`
from `/usr/bin`, or a program by its full path.

**How do I test without a real ticket system?**
Run [stub-desk.py](../examples/actions/stub-desk.py) and point
`base_url` at `http://127.0.0.1:8765/api`. The helpers allow `http://`
only to this computer.

More: [Action reference](action-reference.md),
[Using finding actions](finding-actions.md),
[output plugins](plugins.md).
