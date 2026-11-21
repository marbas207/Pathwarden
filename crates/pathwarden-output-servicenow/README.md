# pathwarden-output-servicenow

A Pathwarden output plugin that keeps **one ServiceNow ticket per finding**:
an incident or a requested item (RITM). Each run it creates tickets for new
findings, comments on regressions, reopens tickets that were closed while the
finding is still there, and resolves tickets whose finding is gone.

Tickets are matched by the finding's fingerprint in `correlation_id`, and every
ticket the plugin creates has `correlation_display = "Pathwarden"`. The plugin
only ever reads or changes tickets with that marker. Because ServiceNow itself
is the record of which tickets exist, the plugin keeps no state of its own and
is safe to rerun: the same event produces no further changes.

## Settings

Configured as an `[[output]]` entry in `pathwarden.toml`: in the app with
**Plugins and actions** > **Add ServiceNow**, from the terminal with
`pathwarden plugins add servicenow`, or by hand. Pathwarden passes the table to
the plugin as JSON in `PATHWARDEN_OUTPUT_SETTINGS`.

```toml
[[output]]
plugin = "servicenow"
instance = "https://contoso.service-now.com"
table = "incident"                 # or "sc_req_item" for RITMs
min_severity = "medium"            # only create tickets at or above this
# categories = ["attack_path"]     # optionally only one category
on_closed_but_present = "reopen"   # "reopen" | "comment" | "ignore"
resolve_suppressed = true          # resolve tickets for accepted risks
# token_env = "PATHWARDEN_SN_TOKEN" # bearer token instead of basic auth

[output.fields]                    # extra fields on every new ticket
assignment_group = "Identity Engineering"
category = "Security"

[output.severity_map.critical]     # overrides; defaults below
urgency = "1"
impact = "1"

# [output.resolve_fields]          # override the per-table defaults
# state = "6"
# close_code = "Resolution provided"
# close_notes = "{message}"
```

| Setting | Default | Notes |
|---|---|---|
| `instance` | (required) | Base URL of the instance; must be `https://` (see below) |
| `table` | `incident` | `incident` or `sc_req_item`; other task tables work with explicit `resolve_fields` / `reopen_fields`. Lowercase letters, digits and `_` only |
| `scope` | none | Separates deployments that share one instance (see below). 1-40 characters of `A-Z a-z 0-9 . _ -` |
| `username_env` / `password_env` | `PATHWARDEN_SN_USER` / `PATHWARDEN_SN_PASSWORD` | Names of environment variables, never the secrets themselves |
| `token_env` | none | When set, a bearer token from this variable is used instead of basic auth |
| `min_severity` | `medium` | Findings below it get no new ticket (existing tickets are still kept in sync) |
| `categories` | all | `attack_path`, `hygiene` |
| `fields` | none | Set on every created ticket (`assignment_group`, `category`, `caller_id`, `cmdb_ci`, ...) |
| `severity_map` | critical 1/1, high 2/1, medium 2/2, low 3/3, info 3/3 | Urgency / impact per severity |
| `resolve_fields` | incident: `state=6`, `close_code="Resolution provided"`, `close_notes`; RITM: `state=3`, `close_notes` | `{message}` is replaced with the reason |
| `reopen_fields` | incident: `state=2`; RITM: `state=1` | A `work_notes` entry explaining why is always added |
| `on_closed_but_present` | `reopen` | What to do when a ticket was closed but the finding is still there |
| `resolve_suppressed` | `true` | Resolve tickets of findings that became accepted risks |
| `skip_action_tickets` | `true` | Create no ticket for a finding that has an open ticket from a finding action (see below) |
| `respect_close_codes` | `Won't Fix`, `Not Solved (Not Reproducible)`, `Duplicate`, `Accepted Risk`, `Risk Accepted` | A closed ticket with one of these close codes (any case) is never reopened or commented on |
| `max_resolve_percent` | `50` | Safety limit on resolves per run (see below); `100` disables it |
| `max_create` | `100` | Safety limit on creates per run (see below) |
| `allow_insecure_http` | `false` | Allow `http://` to a non-loopback host |
| `created_by` | the account the plugin signs in as | Only read and change tickets this ServiceNow account created (`sys_created_by`), normally the integration account (see below) |
| `dry_run` | `false` | Same as `--dry-run` |

Choice lists differ between instances. Check that the `state` and `close_code`
values above exist in yours (System Definition > Choice Lists) and override
them if not. A current Personal Developer Instance, for example, refuses
`Resolution provided` and takes `Resolved by caller`; the plugin's error
then names `resolve_fields.close_code`. A dry run doesn't catch this, since
it changes nothing.

A ticket in the `state` of `resolve_fields` (an incident stays active while
Resolved) counts as closed: it isn't resolved again while its finding stays
gone, and is reopened if the finding comes back.

### Scope

Every ticket this plugin creates is marked with `correlation_display =
"Pathwarden"`, and only tickets with exactly that marker are read or changed.
If two deployments (say, two forests, or a lab and production) report into the
same instance with the same marker, each sees the other's tickets as findings
that are gone and resolves them. Give each deployment its own `scope`: tickets
are then marked `Pathwarden:<scope>` and each deployment only touches its own.
The scope ends up inside a Table API query, so it is limited to characters
that cannot change the query. Changing the scope later orphans the existing
tickets (they are no longer read), so pick it once.

### Who can stand in for a ticket

Tickets are recognized by `correlation_display` and `correlation_id` alone, and
any ServiceNow user who can edit some ticket can set those fields. Fingerprints
are visible in existing tickets, so such a user could make an unrelated ticket
pass for a finding's ticket: closed as "Won't Fix", it keeps the real finding
from ever being raised; with a made-up fingerprint, the plugin resolves an
unrelated ticket. Two defenses:

- Only tickets the integration account created are used. Without
  `created_by`, that is the account the plugin signs in as: the basic-auth
  user name, or with a token the session's user (from
  `GET /api/now/ui/user/current_user`). Tickets another account created are
  left alone (never resolved or reopened) and named in a warning, and
  `max_resolve_percent` counts this account's tickets only. When the
  account can't be told, tickets are matched by their correlation fields
  alone, as before, with a warning.
- Set `created_by` to the integration account's user name to choose it
  yourself. Only tickets that account created are then read at all. If the
  integration account changes, set `created_by` to the one that created the
  existing tickets, or they are left alone and new ones are opened.

ACLs that keep other users from writing `correlation_display` and
`correlation_id` close the gap on the ServiceNow side.

### Findings with a ticket from a finding action

A finding action (a button such as "Open a ticket") saves the ticket it
opened as a record on the finding, and the event carries it. A finding
with a record still open is left to that ticket, so the plugin and the
button never open two tickets for one finding:

- No new ticket is created for it, and a closed ticket of the plugin's is
  not reopened or commented on.
- A ticket the plugin already has open is kept as it is: it isn't resolved
  because of the record, it is still commented on when the finding comes
  back, and resolved once the finding is gone.
- Once the record is closed (or removed) and the finding is still there,
  the next run creates or reopens a ticket as usual: the finding isn't
  fixed, and nothing else tracks it any more.

Any open record counts, whatever its kind (`ticket`, `request`, ...): the
kind is free text the action chooses. "Open" is what Pathwarden last
heard from the action, saved when someone ran it or a follow-up. Each
finding skipped gets a line in the run log (`skipped <fingerprint>: a
finding action's ticket (RITM0012345) is open, so no new one`) and the
summary says how many (`3 skipped because a finding action's ticket is
open`); a dry run shows the same. Set `skip_action_tickets = false` to
create tickets regardless. Skipped findings don't count towards
`max_create`.

### Safety limits

A run that would resolve a large share of the open tickets usually means an
incomplete collection, not a sudden clean-up. When more than
`max_resolve_percent` of the active tickets (and at least 5 are active) would
be resolved, no ticket is resolved; creates, comments and reopens still happen,
a warning explains what was held back, and the plugin exits non-zero. When
more than `max_create` tickets would be created, none is created, with the same
warning and exit code. Preview with `--dry-run`, then raise the limit for one
run if the change is real.

Both limits are on the app's ServiceNow form under **Safety limits**, and
`pathwarden plugins add servicenow` takes `--max-create` and
`--max-resolve-percent`.

The plugin also refuses an event without a `findings` list or `run.run_id`, or
with another schema, before any call to ServiceNow: read leniently, such a
document would look like "every finding is gone".

## Credentials and permissions

Set the credentials in the environment of the scheduled task or pipeline, from
its secret store:

- basic auth: `PATHWARDEN_SN_USER` and `PATHWARDEN_SN_PASSWORD`
- or a bearer token: `token_env = "PATHWARDEN_SN_TOKEN"` and that variable

The account needs Table API access with read, create and write on the chosen
table: typically the `itil` role for incidents, or a role that can fulfill
requested items for `sc_req_item`. If your instance uses ACLs on
`correlation_id` / `correlation_display`, allow the account to read and write
both. A dedicated integration account with only these rights is best.

Traffic uses TLS with the operating system's certificate store (so internal CAs
and inspection proxies work) and honors `HTTPS_PROXY` / `HTTP_PROXY` for an
`https://` instance that `NO_PROXY` doesn't name; a loopback or plain
`http://` instance never goes through a proxy. Plain
`http://` is refused, since the credentials would cross the network
unencrypted, except to `localhost`, `127.0.0.0/8` or `::1` (a local test
instance or tunnel) or with `allow_insecure_http = true`. The instance URL may
not hold a user name or password, a backslash, a query or a fragment; errors
never print credentials.

## What it does each run

| Finding in this run | Ticket in ServiceNow | Action |
|---|---|---|
| new / open / regressed, at or above `min_severity` | none | **create** |
| new / open | active | nothing (no noise) |
| regressed | active | **comment**: present again after being resolved |
| new / open / regressed | closed | **reopen** with a note (or comment / ignore) |
| new / open / regressed | closed with a respected close code | nothing; an info line suggests a `[[suppress]]` entry with the fingerprint |
| new / open / regressed, with an open ticket from a finding action | none or closed | nothing; a line says it was skipped ([see above](#findings-with-a-ticket-from-a-finding-action)) |
| suppressed (accepted risk) | active | **resolve**: "Accepted risk: reason" |
| gone | active | **resolve**: "No longer present in Pathwarden run ..." |

New tickets carry the rule's title as their short description
(`Account or group outside Tier Zero controls a Tier Zero object`; severity is
in urgency and impact), and a description that opens with the change to make
(`Remove the Group Policy security permissions EVERYONE holds on DEFAULT DOMAIN
POLICY.`), then the domain, the finding ID, the user exposure, why it matters,
how to fix it, the accepted-risk route, the path as text, the severity,
affected objects, references, and the rule's step-by-step guide.

Tickets whose `sys_id` is not 32 lowercase hex characters are skipped with a
warning and never updated.

## Trying it

Write an event with `pathwarden run ... --event event.json`, then preview the
changes without touching any ticket:

```powershell
$env:PATHWARDEN_SN_USER = "svc-pathwarden"
$env:PATHWARDEN_SN_PASSWORD = "..."
pathwarden-output-servicenow --settings servicenow.json --dry-run < event.json
```

Without credentials, a dry run is an offline preview: existing tickets are not
read, so every finding at or above `min_severity` is listed as a create.

`servicenow.json` holds the same keys as the `[[output]]` table, as JSON:

```json
{ "instance": "https://contoso.service-now.com", "table": "incident" }
```

A dry run still reads existing tickets, so it needs working credentials.
