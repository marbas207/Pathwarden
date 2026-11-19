# pathwarden-output-jira

> **Tested on Jira Cloud, not yet Data Center.** Create, close, reopen,
> reruns without duplicates and leaving other issues alone were checked on a
> live Jira Cloud site (a team-managed project), besides a fake Jira Cloud
> built from Atlassian's REST documentation. On Data Center, try it with
> `--dry-run` and a test project first, and report what differs. In a
> workflow with a status before To Do (such as Idea), a reopened issue goes
> there: set `reopen_transition` to choose.

A Pathwarden output plugin that keeps **one Jira issue per finding**. Each
run it creates issues for new findings, comments on regressions, reopens
issues that were closed while the finding is still there, and closes issues
whose finding is gone (or became an accepted risk).

Issues are matched by labels: every issue the plugin creates carries
`pathwarden` (or `pathwarden-<scope>`) and `pwfp-<fingerprint>`. The plugin
keeps no state of its own; Jira is the record, so it is safe to rerun.

## Settings

In the app: **Plugins and actions** > **Add Jira**. From the terminal:
`pathwarden plugins add jira --instance https://contoso.atlassian.net --project SEC`
(`pathwarden plugins add jira --help` lists the options). Both write an
`[[output]]` block like this one; the form covers every setting below except
`categories`, `priority_map`, `respect_resolutions`, `resolve_suppressed`,
`created_by`, `allow_insecure_http` and `dry_run`, which it keeps as written.

```toml
[[output]]
plugin = "jira"
instance = "https://contoso.atlassian.net"
project = "SEC"
issue_type = "Task"
min_severity = "medium"
# created_by = "5b10a2844c20165700ede21g"   # the integration account's ID

[output.fields]                  # extra fields on every new issue
components = [{ name = "Active Directory" }]
```

| Setting | Default | Notes |
|---|---|---|
| `instance` | (required) | Base URL; `https://` only (see below) |
| `deployment` | `cloud` | `cloud` (REST v3, Atlassian Document Format) or `data_center` (REST v2, plain text; also `server`) |
| `project` | (required) | Project key, e.g. `SEC` |
| `issue_type` | `Task` | Issue type for new issues |
| `username_env` / `token_env` | `PATHWARDEN_JIRA_USER` / `PATHWARDEN_JIRA_TOKEN` | Cloud: account email and [API token](https://id.atlassian.com/manage-profile/security/api-tokens). Data Center: user name and password |
| `pat_env` | none | Data Center: a personal access token, sent as a bearer token instead of basic auth |
| `min_severity` | `medium` | Findings below it get no new issue (existing issues are still kept in sync) |
| `categories` | all | `attack_path`, `hygiene` |
| `fields` | none | Set on every new issue; may not set `project`, `issuetype`, `summary`, `description` or `labels` |
| `set_priority` | `true` | Set the priority from the severity; turn off if Priority is not on the create screen |
| `priority_map` | critical `Highest`, high `High`, medium `Medium`, low `Low`, info `Lowest` | Priority names per severity |
| `close_transition` | first transition to a "done" status | Transition name used to close |
| `reopen_transition` | first transition to a "to do" status, else "in progress" | Transition name used to reopen |
| `close_resolution` | none | Resolution set while closing, for workflows whose close screen asks for one |
| `on_closed_but_present` | `reopen` | `reopen`, `comment` or `ignore` |
| `resolve_suppressed` | `true` | Close issues of findings that became accepted risks |
| `respect_resolutions` | `Won't Do`, `Won't Fix`, `Duplicate`, `Cannot Reproduce`, `Declined`, `Risk Accepted` | A closed issue with one of these resolutions is never reopened or commented on |
| `scope` | none | Separates deployments sharing one project: label `pathwarden-<scope>` |
| `created_by` | the account the plugin signs in as | Only issues this account created are read or changed (see below) |
| `max_resolve_percent` | `50` | Refuse to close more than this share of the open issues in one run |
| `max_create` | `100` | Refuse to create more issues than this in one run |
| `allow_insecure_http` | `false` | Allow `http://` to a non-loopback host |
| `dry_run` | `false` | Same as `--dry-run` |

## What it does each run

| Finding in this run | Issue in Jira | Action |
|---|---|---|
| new / open / regressed, at or above `min_severity` | none | **create** |
| new / open | open | nothing |
| regressed | open | **comment**: present again |
| new / open / regressed | closed | **reopen** with a comment (or comment / ignore) |
| new / open / regressed | closed with a respected resolution | nothing; an info line suggests a `[[suppress]]` entry |
| suppressed (accepted risk) | open | **close** with "Accepted risk: reason" |
| gone | open | **close** with "No longer present in Pathwarden run ..." |

"Open" and "closed" follow the status *category* (To Do / In Progress vs
Done), so custom workflows work as long as some transition leads to a Done
status. Closing posts the comment first, then transitions.

New issues have the rule's title as their summary (`Account or group
outside Tier Zero controls a Tier Zero object`; severity is in the priority)
and a description that opens with the change to make (`Remove the Group
Policy security permissions EVERYONE holds on DEFAULT DOMAIN POLICY.`), then
the domain, the finding ID, the user exposure, why it matters, how to fix it,
the accepted-risk route, the path as text, the severity, affected objects,
references and the rule's step-by-step guide. Text is sent as plain text (paragraphs in
Atlassian Document Format on Cloud), never as wiki markup or Markdown, so
an object name can't add links or formatting.

## Security

- **Transport:** `https://` only; plain `http://` only to `localhost`,
  `127.0.0.0/8` or `::1`, or with `allow_insecure_http = true`. Redirects
  are not followed, so the `Authorization` header never goes to another
  host. TLS uses the operating system's certificate store and honors
  `HTTPS_PROXY` / `HTTP_PROXY` for an `https://` instance that `NO_PROXY`
  doesn't name. A loopback or plain `http://` instance never goes through a
  proxy.
- **Credentials:** only environment variable *names* are in the settings.
  The URL may not hold a user name or password, a backslash, a query or a
  fragment. The auth header is built in memory that is zeroed on drop.
  Errors print Jira's own messages and never the request or a URL's
  credentials.
- **Injection:** the project key, scope, `created_by`, transition and
  resolution names are checked against strict character sets before they
  reach JQL or a URL, and quoted in JQL. Issue keys and transition IDs read
  back from Jira are checked before they are used in a URL path.
- **Who can stand in for an issue:** labels can be edited by anyone who can
  edit an issue, so someone could label an unrelated issue as a finding's
  issue (closed as "Won't Do", it keeps the real finding from being raised).
  So only issues the integration account created are used. Without
  `created_by`, that is the account the plugin signs in as (Cloud: its
  account ID; Data Center: its user name, both from `GET .../myself`).
  Issues another account created are left alone (never closed, reopened or
  commented on) and named in a warning, and `max_resolve_percent` counts
  this account's issues only. Jira's `creator` field, unlike `reporter`,
  can't be edited. When Jira doesn't say who the account is, issues are
  matched by their labels alone, as before, with a warning. Set
  `created_by` to choose the account yourself, for example the one that
  created the existing issues after the integration account changed; the
  search then asks for `creator = "<account>"` and the plugin checks the
  creator again itself. An issue with two `pwfp-` labels is ignored.
- **Safety limits:** the same `max_resolve_percent` / `max_create` guards as
  the ServiceNow plugin, and an event without `findings` or `run.run_id` is
  refused before any call.

## Permissions

The account needs Browse Projects, Create Issues, Add Comments, Transition
Issues and (for `close_resolution`) Resolve Issues in the project. A
dedicated integration account with only these rights is best.

## Trying it

```powershell
$env:PATHWARDEN_JIRA_USER = "svc-pathwarden@contoso.com"
$env:PATHWARDEN_JIRA_TOKEN = "..."
pathwarden-output-jira --settings jira.json --dry-run < event.json
```

Without credentials, a dry run is an offline preview: existing issues are
not read, so every finding at or above `min_severity` is listed as a create.

## Not implemented

- Correlation through a custom field instead of labels (labels need no
  admin setup and are searchable with JQL on every edition).
- Updating an open issue's description when the finding's details change;
  the description is written once, at creation.
