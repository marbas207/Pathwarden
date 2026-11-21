# Using finding actions

A finding action is a button on a finding. Someone clicks it, Pathwarden
runs a small program of yours for that one finding, and what the program
did is kept on the finding. This page sets up the three examples that come
with Pathwarden's source: a chat alert, a ticket and an owner lookup. To
write your own, see [Writing an action](actions.md).

## Plugins and actions

Plugins run on each scheduled run and handle every finding by themselves,
such as keeping one ServiceNow ticket per finding. Actions run only when
someone clicks a button on one finding, and never on a schedule.

## What a button does

The buttons you add sit after the built-in ones (**Retest**, **Accept
risk** and the others) in a finding's action bar. Past three, the rest are
under **More actions**.

1. Click the button. The dialog shows what the action asks for, such as a
   note, and one line saying what leaves this computer. **See exactly
   what's sent** shows the whole request.
2. Turn on **Test only** to try it without changing anything. Nothing is
   saved.
3. Click **Start**. The program's progress lines show as it writes them.
4. The result says what it did. A ticket comes back as a record, such as
   `RITM10816190 · Open`, with **Open** and **Copy**.

A record stays on the finding. Its chip sits under the finding's title, and
the finding's **Activity** lists who ran what, when, and how it went. When
the finding is fixed and its ticket is still open, the chip turns amber,
and a follow-up such as **Close ticket** comes first.

## Before you start

You need one saved run (click **Try the demo** on **Home** if you have
none), and the examples. They aren't installed with Pathwarden; copy them
from [examples/actions](../examples/actions/README.md) into a folder that
only you and administrators can change. In PowerShell:

```powershell
New-Item -ItemType Directory -Force C:\Pathwarden\actions | Out-Null
$base = 'https://raw.githubusercontent.com/marbas207/Pathwarden/main/examples/actions'
foreach ($f in 'post-to-webhook.ps1', 'PathwardenAction.psm1', 'rest-ticket.py', 'owner-lookup.py', 'pathwarden_action.py', 'owners.example.csv') {
    Invoke-WebRequest "$base/$f" -OutFile "C:\Pathwarden\actions\$f"
}
Get-ChildItem C:\Pathwarden\actions | Unblock-File
```

Each script imports its helper from its own folder, so keep them together.
The Python examples need Python 3.9 or later and nothing else. Give
python.exe by its full path unless Python is installed for all users;
`(Get-Command python).Source` prints it.

## Where secrets go

A webhook URL or an API token never goes on the page or in
`pathwarden.toml`. Put it in an environment variable for the account that
runs Pathwarden, and give the variable's name in the setting that ends in
`_env`:

```powershell
[Environment]::SetEnvironmentVariable('PATHWARDEN_ALERT_WEBHOOK', 'https://example.webhook.office.com/...', 'User')
```

Then stop Pathwarden (**Stop Pathwarden** at the bottom of the rail) and
start it again: it only sees variables that were set when it started. The
action's row on **Plugins and actions** shows whether each variable is set,
never its value. More: [Passwords and tokens](plugins.md#passwords-and-tokens).

## Alert a team

`post-to-webhook.ps1` posts a finding to a chat channel's incoming webhook:
Microsoft Teams, Slack, Google Chat, Mattermost, Rocket.Chat, or anything
that takes JSON. It adds a button, **Alert the team**, that asks for an
optional note. It keeps no record, so each click posts again.

1. Make an incoming webhook for the channel, and put its URL in
   `PATHWARDEN_ALERT_WEBHOOK` as in [Where secrets go](#where-secrets-go).
   For Teams, use a workflow that starts "When a Teams webhook request is
   received".
2. In the rail, under **Automate**, click **Plugins and actions**, then
   **Add**.
3. Click **Alert a team**, then **Next**.
4. Fill in the form:
   - **Name**: `team-chat`.
   - **Program**: `powershell`.
   - **Arguments, one per line**:

     ```text
     -NoProfile
     -NonInteractive
     -ExecutionPolicy
     Bypass
     -File
     C:\Pathwarden\actions\post-to-webhook.ps1
     ```

   - **Settings**: `webhook_env` = `PATHWARDEN_ALERT_WEBHOOK`, then **Add a
     setting** and `format` = `teams`. Use `slack` for Slack, Google Chat,
     Mattermost and Rocket.Chat.
   - **For findings**: **High and above**, if the team only wants those.
5. Click **Save**, then **Test** on the new row. A test builds the post and
   sends nothing.

The same from the command line:

```powershell
pathwarden action add --name team-chat --min-severity high --setting webhook_env=PATHWARDEN_ALERT_WEBHOOK --setting format=teams -- powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\Pathwarden\actions\post-to-webhook.ps1
pathwarden action test team-chat
```

## Open a ticket

`rest-ticket.py` opens a ticket for a finding in a JSON REST API, checks
its status, and closes it once the finding is fixed. It adds **Open a
ticket**, which asks for a note and an urgency, and **Check status** and
**Close ticket** on the ticket it opened. The ticket is a record on the
finding, and the button is hidden while that ticket is open.

To have every finding ticketed in ServiceNow or Jira without anyone
clicking, use the ServiceNow or Jira plugin instead: **Add**, then
**ServiceNow tickets** or **Jira tickets**, then **Every finding, on each
scheduled run**. That needs no script. The action is for teams that ticket
findings one at a time.

The script expects an API that answers like this:

```text
GET   {base_url}/tickets?external_id=FINDING-ID   a list of tickets
POST  {base_url}/tickets                          the new ticket
GET   {base_url}/tickets/{id}                     the ticket
PATCH {base_url}/tickets/{id}                     the ticket, changed
```

Settings change the paths (`tickets_path`, `ticket_path`), the field names
(`id_field`, `number_field`, `status_field`, `url_field`) and the link on
the record (`web_url`). ServiceNow's and Jira's own APIs answer in shapes
of their own, so for those, treat the script as a starting point, or put a
small service in front of the desk that answers as above. Every setting is
in [rest-ticket.md](../examples/actions/rest-ticket.md).

1. Put the API token in `PATHWARDEN_DESK_TOKEN`, as in
   [Where secrets go](#where-secrets-go).
2. Under **Automate**, click **Plugins and actions**, then **Add**.
3. Click **ServiceNow tickets** or **Jira tickets**, then **Next**. Click
   **Only when someone clicks a button on a finding**, then **Next**.
   (**Your own program** works the same way for any other desk.)
4. Fill in the form:
   - **Name**: `service-desk`.
   - **Program**: python.exe's full path, such as
     `C:\Program Files\Python313\python.exe`.
   - **Arguments, one per line**: `C:\Pathwarden\actions\rest-ticket.py`.
   - **Settings**: `base_url` = your API, such as
     `https://desk.example.com/api`; `token_env` =
     `PATHWARDEN_DESK_TOKEN`; `queue` = the queue new tickets go to, such
     as `Identity`.
5. Click **Save**, then **Test** on **Open a ticket**. A test builds the
   ticket and calls nothing.

The same from the command line:

```powershell
pathwarden action add --name service-desk --setting base_url=https://desk.example.com/api --setting token_env=PATHWARDEN_DESK_TOKEN --setting queue=Identity -- "C:\Program Files\Python313\python.exe" C:\Pathwarden\actions\rest-ticket.py
pathwarden action test service-desk --action open
```

To try it with no desk at all, run the stub that comes with the examples,
[stub-desk.py](../examples/actions/stub-desk.py), and point the action at
it:

```powershell
python C:\Pathwarden\actions\stub-desk.py --token test-token
```

Use `base_url` = `http://127.0.0.1:8765/api` and set
`PATHWARDEN_DESK_TOKEN` to `test-token`. Plain `http://` is allowed only to
this computer.

## Look up an owner

`owner-lookup.py` says who owns the objects a finding is about, from a CSV
file. It adds **Find the owners**, which shows the owners in its result. It
sends nothing anywhere and changes nothing.

1. Make the owners file, such as `C:\Pathwarden\actions\owners.csv`. The
   first row whose `match` fits an object's name names its owner; `*`
   stands for anything:

   ```text
   match,owner,contact
   SVC-*@SCALE.LOCAL,Service accounts team,svc-owners@scale.example
   *ADMINS@SCALE.LOCAL,Identity team,identity@scale.example
   *.SCALE.LOCAL,Server team,servers@scale.example
   ```

   `owners.example.csv` is one made for the demo.
2. Under **Automate**, click **Plugins and actions**, then **Add**.
3. Click **Look up an owner**, then **Next**.
4. Fill in the form:
   - **Name**: `owners`.
   - **Program**: python.exe's full path.
   - **Arguments, one per line**: `C:\Pathwarden\actions\owner-lookup.py`.
   - **Settings**: `owners_file` = `C:\Pathwarden\actions\owners.csv`.
5. Click **Save**, then **Test**.

The same from the command line:

```powershell
pathwarden action add --name owners --setting owners_file=C:\Pathwarden\actions\owners.csv -- "C:\Program Files\Python313\python.exe" C:\Pathwarden\actions\owner-lookup.py
pathwarden action test owners
```

## Test before you share

**Test** on **Plugins and actions** runs an action on the first finding of
the latest run it applies to, as a dry run: the program is asked to change
nothing, and nothing is saved. A missing variable or a wrong path is named
in the result. `pathwarden action check` runs the same checks on a script
before you add it ([Check a program](actions.md#check-a-program)).

## Who sees records

Records and activity are saved on the finding in the run history, so
everyone who shares that history sees them, in the app and on the command
line (`pathwarden action records`). A run that couldn't be shared yet is
kept on this computer and goes with the next sync. A downloaded report has
no buttons.

The buttons themselves don't travel with the run history: each computer
that runs an action sets it up. An action runs as the account that runs
Pathwarden, and only after someone clicks **Start**, never from a
scheduled run. An app started with `--lock-destinations` can't add actions
or change their programs ([Safety locks](ui.md#safety-locks)).
