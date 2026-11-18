# rest-ticket.py: a ticket with status and close

A finding action that opens a ticket for a finding in a JSON REST API,
checks its status, and closes it once Pathwarden no longer finds the
issue. Each ticket comes back as a record, saved on the finding.

| Action | ID | Offered | Does |
|---|---|---|---|
| **Open a ticket** | `open` | On a finding without an open ticket from it (`once`). | Looks for an open ticket with the finding's ID, and returns it if there is one; else creates one. Inputs: **Note for the team**, **Urgency** (Low, Medium, High). |
| **Check status** | `status` | On a ticket it opened (`for: "record"`). | Reads the ticket and updates the record. |
| **Close ticket** | `close` | On a ticket it opened, once the finding is fixed (`"when": ["fixed"]`). | Sets the ticket's status to closed, with a note. Refuses on a finding that isn't fixed. |

It needs Python 3.9 or later, and nothing outside the standard library.

## The API it expects

```text
GET   {base_url}/tickets?external_id=FINDING-ID   a list of tickets
POST  {base_url}/tickets                          the new ticket
GET   {base_url}/tickets/{id}                     the ticket
PATCH {base_url}/tickets/{id}                     the ticket, changed
```

A ticket is a JSON object with at least an ID, and its number, status and
web address when it has them. The ticket it creates has `title` ("Pathwarden
PW-006: ..."), `description` (the summary, the affected objects, the
remediation and the note), `severity`, `urgency`, `queue` and
`external_id` (the finding's ID).

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `base_url` | (required) | The API, `https://`. |
| `token_env` | none | The environment variable that holds an API token, sent as `Authorization: Bearer`. |
| `queue` | none | Sent with each new ticket, and shown as the record's Queue. |
| `tickets_path` | `/tickets` | Where to search and create. |
| `ticket_path` | `/tickets/{id}` | One ticket. |
| `id_field`, `number_field`, `status_field`, `url_field` | `id`, `number`, `status`, `url` | The ticket's fields. |
| `web_url` | the ticket's `url` | The record's link, with `{id}` or `{number}`: `https://desk.example.com/tickets/{number}`. |
| `closed_statuses` | `closed,resolved,done,cancelled` | Statuses, any case, that mean the ticket isn't open. |
| `close_status` | `Closed` | The status `close` sets. |

## Set it up

1. Copy `rest-ticket.py` and `pathwarden_action.py` to
   `C:\Pathwarden\actions`.
2. Put the API token in a variable for your account, then open a new
   terminal and restart the app:

   ```powershell
   [Environment]::SetEnvironmentVariable('PATHWARDEN_DESK_TOKEN', '...', 'User')
   ```

3. Check it. Give python.exe's full path unless Python is installed for
   all users:

   ```powershell
   pathwarden action check "C:\Program Files\Python313\python.exe" --setting base_url=https://desk.example.com/api --setting token_env=PATHWARDEN_DESK_TOKEN -- C:\Pathwarden\actions\rest-ticket.py
   ```

4. Add it:

   ```powershell
   pathwarden action add --name desk --setting base_url=https://desk.example.com/api --setting token_env=PATHWARDEN_DESK_TOKEN --setting queue=Identity -- "C:\Program Files\Python313\python.exe" C:\Pathwarden\actions\rest-ticket.py
   ```

   ```toml
   [[action]]
   name = "desk"
   command = ["C:\\Program Files\\Python313\\python.exe", "C:\\Pathwarden\\actions\\rest-ticket.py"]
   base_url = "https://desk.example.com/api"
   token_env = "PATHWARDEN_DESK_TOKEN"
   queue = "Identity"
   ```

5. Open a ticket for a finding:

   ```powershell
   pathwarden action run PW-006-1bbba15126c6fc31 --action desk/open --input note="Please review" --input urgency=High
   ```

A dry run reads the settings and builds the ticket, and calls nothing.

## Try it against the stub

[stub-desk.py](stub-desk.py) is this API on your computer, with tickets in
memory:

```powershell
python stub-desk.py --token test-token
$env:PATHWARDEN_DESK_TOKEN = 'test-token'
pathwarden action check C:\Users\you\AppData\Local\Programs\Python\Python313\python.exe --setting base_url=http://127.0.0.1:8765/api --setting token_env=PATHWARDEN_DESK_TOKEN -- C:\Pathwarden\actions\rest-ticket.py
```

Or feed it requests by hand, as
[Testing and debugging](../../docs/actions.md#feed-a-request-by-hand)
shows: a `run` request with `"action": "open"`, then `"status"` and
`"close"` with the returned record in `record` and, for close,
`"status": "fixed"` in the finding.

More: [Writing an action](../../docs/actions.md#a-rest-ticket-with-status-and-close).
