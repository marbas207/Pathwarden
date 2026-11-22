# File formats and upgrades

Every file Pathwarden writes and reads back later, on this computer or on
another one through a run history: where it lives, its version, and
what a Pathwarden older or newer than the writer does with it.

## The upgrade policy

**Every file another version may read carries a format number.** That is
every data file in the history, `pathwarden.toml`, the run folder files
whose meaning could change, and the documents other programs read. The
files marked "No number" below carry none: pages and markers, files whose
fields are all optional, files that never leave this computer, and this
account's `history-pins` records and stored passphrases (never shared). A
file without a number gains one the first time a change to it would be
misread by an older version.

A format number is a whole number, starting at 1; a file written before it
had one reads as format 1. It sits inside the file (`"version": 1`), in a
schema name (`pathwarden.event.v1`), or, for a run folder, in its summary's
file name. Anything else where the number should be (0, a string, a
fraction) is a format this version doesn't know. One exception: in a file
read straight into its fixed shape, a `version` of 0 is what a missing one
reads as, so it reads as 1. No Pathwarden ever wrote 0.

**Same or older format: read.** Pathwarden reads every format it ever
wrote, and makes up in memory for what an older file lacks. When it writes
the file again, it writes its own format.

**Newer format: never trusted, never overwritten.** A file of a format this
version doesn't know is never read as if it were one it knows, and never
rewritten, deleted or "repaired". Pathwarden does one of two things:

- **It skips the file** when the rest can go on without it, and says so in
  one sentence where you would otherwise miss something (a run, a history
  point, the shared settings, `last-run.json`): "1 run on this computer was
  saved by a newer Pathwarden. Update Pathwarden to open it." A file that
  only adds detail to a run (its graph, retest data, timings) is left out
  quietly, as if it were missing.
- **It refuses the whole operation** when it can't: "findings.json was
  saved by a newer Pathwarden (state version 2). Update Pathwarden to use
  this history."

Removing a run (`history --forget`, **Delete** in the app) removes its
point and full run whatever their format, because you asked. Removing an
environment leaves its run folders of a newer format in the workspace's
`runs\` folder, still naming the removed environment, for a newer
Pathwarden to find.

**What raises the format.**

- A field may be added when an older reader that ignores it still reads
  the file correctly. It is optional (`#[serde(default)]`; absent means
  "not recorded"), and readers never refuse fields they don't know (no
  `deny_unknown_fields` on files that travel).
- The format goes up when an older reader would misread the file: a field
  that changes meaning, a removed or renamed field, a new value in a field
  older readers act on, a new file in a full run, or anything a reader must
  understand to stay correct.

**The writer writes the oldest format that holds what it writes.** A run
analysed here is still a format 1 run folder, which every release reads.
Only a run loaded from a run history is format 2, because releases
before 0.1.9 would take it for one of their own.

**Releases already published can't learn this.** Where one reads a newer
file without checking its format, a change it would misread gets a new file
name instead of a new number while that release is supported
([Older releases](#what-older-releases-do-with-newer-files)).

### Renamed keys

From 1.0 the Tier Zero status and the protected share have names after
what they hold. Every file and `--json` output that had the old keys
carries the new ones beside them, with the same values: the event
document's posture, a run's `history/<run>.json` point, `summary.json`,
`posture --json`, `history --changes --json` and `/api/history/since`.
This is additive, so no format changes. Readers take the new key when it
is there.

| Deprecated key | Use |
|---|---|
| `exposure_grade` | `exposure_status`. Written until 2.0. |
| `grade_reason` | `status_reason`. Written until 2.0. A run's `summary.json` already had its own `status_reason` (the same reason as a sentence), which it keeps. |
| `protection_score` | `protected_percent`. Written until 2.0. |
| `tier_zero_grade` | `tier_zero_status`. Written until 2.0. |
| `grade` (a zone's point, a zone's change, a run's summary) | `status`. Written until 2.0. |

### Semantic versioning from 1.0

From Pathwarden 1.0, versions follow [semantic versioning](https://semver.org):

- A format change that a release of the same major version can't read is
  breaking, and needs 2.0. A 1.x Pathwarden reads every file any 1.x
  wrote, and refuses (never misreads) one a later 1.x wrote in a newer
  format.
- A new file that older versions ignore, or a new optional field, isn't
  breaking.
- The event document and the run bundle keep their schema names
  (`pathwarden.event.v1`, `pathwarden.run-bundle.v1`) through 1.x. A `v2`
  schema is a 2.0 change.

Before 1.0, a minor release (0.2, 0.3) may raise a format. Its release
notes say so under **Upgrade notes**.

## The formats

### Settings

| File | Where | Format | A newer one |
|---|---|---|---|
| `pathwarden.toml` | Beside the command (`-c`), or in each environment of the app's workspace. | `format = N` at the top, absent means 1. This version reads 1, and doesn't write the key while 1 is the only format. | Refused by every command, with "This pathwarden.toml was saved by a newer Pathwarden (format N). Update Pathwarden to read it." It is never rewritten. |
| Unknown keys | `pathwarden.toml`. | Not a format change. | A near miss of a known key or section is refused as a typo everywhere: "[state]: unknown key `encryped`. Did you mean `encrypted`?". A near miss is one letter away from a known key, the same name without underscores (`tierzero`), its plural or singular (`outputs`, `zones`, `rule`), or a key holding the stem of a setting whose loss would weaken Pathwarden: `encrypt` or `push` anywhere in a `[state]` key (`encryption`, `no_push`), `tier` at the start of a top-level key (`tier0`). Any other unknown key: in the shared sections (`tier_zero`, `settings_folders` (from 0.3), `[rules]`, `[[suppress]]`, `[[zone]]`, `[management_planes]`, `[[mapping]]`) it is kept, named in a warning, and its entry is not applied; at the top level and in `[state]`, `[ingest]`, `[opengraph]` and `[collect]` it is named in a one-line warning and ignored: "[state]: `soon` is not a key this version of Pathwarden knows (a newer one may have written it); it is kept in the file and ignored." In `[[output]]` it goes to the plugin, and in `[[action]]` to the program; a singular or plural of the block's own keys (`rule` beside `rules`) is named in a warning, as it may have been meant as the filter. A newer version keeps its new keys out of typo range. The command line prints each warning; the app lists them on **Settings** under "pathwarden.toml has keys this version doesn't know, so they are ignored.", followed by notices that name no key. Pathwarden 0.1.9 and earlier refuse such a key, so a new key is written only when it isn't the default. |

### The history (a folder or a git repository)

| File | Format | A newer one |
|---|---|---|
| `findings.json` | `"version"`: 1. An encrypted history keeps a plain stub at 1000. | Refused before anything is written. The stub makes 0.1.6 and earlier refuse an encrypted history the same way. |
| `last-run.json` | `"version"`: 1. Additive within 1: `hosts` (optional, from 0.3) is one string of name-free units separated by spaces (a list is read too). A unit is a mark, a 64-bit hash of a computer's ID in 16 hex digits and a list letter: `s:` sessions (`s` sessions, `p` privileged, `r` registry), `l:` local groups (`a` Administrators, `r` Remote Desktop Users, `d` Distributed COM Users, `p` Remote Management Users), `*` for any list of the kind, `~` for a computer recorded on the first run after an upgrade; `h:…` units are stored credentials. It lists the computers whose session, local group right or stored credential led to Tier Zero that run, and those an earlier run listed that weren't read again since. A computer stays listed until every list read before is read again, it is deleted or disabled, or it isn't active by the exposure rule (no logon within `[rules] stale_days`, or never). A list the collection wasn't asked for (a Default SharpHound run after an All one) is not targeted: it holds what rests on it with the not-targeted words and isn't carried. A file without `hosts` (0.2 and earlier): the next run holds the findings, other than PW-001, PW-006 and PW-032, that rest on sessions or local groups while an active computer of the kind isn't read, and records those computers once (`~`). Size: about 20 bytes a unit, up to 7 units a computer (SharpHound All reads 3 session and 4 local group lists) and 2 seeded on an upgrade: at most about 11 MB for 80,000 computers all on a path to Tier Zero, usually a few kB (tens to a few hundred computers), plus on the upgrade run the active computers that weren't read. `settings_files` (from 0.3, optional) lists the Tier Zero settings files the run used: `file_name` (never a folder), `server`, `kind` (`dc` or `ca`), `read_at`, `stale`, `applied`. Older versions ignore it; a run without it has no files to compare. | Not taken as the last run, and not written over: a run's point says what it found, and the run says "last-run.json was saved by a newer Pathwarden, so it is left as it is." |
| `history/<run>.json` | `"version"`: 1. | Skipped and named ("…: it was saved by a newer Pathwarden. Update Pathwarden to read it."), not counted in trends, and left in the history. |
| `timings/<run>.json` | `"version"`: 1. | Not read: the run shows no collection performance. |
| `exposed/<run>.json` | `"version"`: 1 (from 0.2). | Not read: "Which accounts are new isn't known: a newer Pathwarden recorded the last run's accounts." Never removed by the trim of old runs. |
| `runs/<run>/` | A full run: see [The run bundle](#the-run-bundle-pathwardenrun-bundlev1). | Not loaded. "Run ID was recorded by Pathwarden X: update Pathwarden to open it." Never removed by the trim to the latest `full_runs_kept`. |
| `settings/pathwarden.toml` | `format = N`, absent means 1. | Refused whole: nothing of it is applied, and nothing is pushed over it, not even with `config sync --keep-local`. Every page and command says "The repository's settings were saved by a newer Pathwarden. Update Pathwarden to sync them." |
| `settings/environment.json` | `"format"`: 1 (from 0.2; absent means 1). | Not read, and never written over: a change to the shared settings is refused with "The repository's settings/environment.json was saved by a newer Pathwarden. Update Pathwarden to change the shared settings." |
| `settings/last-change.json` | `"format"`: 1 (from 0.2; absent means 1). Every other field is optional and only shown. | Not shown: the settings commit says what changed instead. |
| `actions.json` | `"version"`: 1 (from 1.0.0-rc.3; absent means 1). What finding actions did: see [What actions did](#what-actions-did-actionsjson). | Not read, and never written over: running an action works, and saving what it did says "The history's actions.json was saved by a newer Pathwarden, so what actions do can't be saved here. Update Pathwarden to save it." Findings carry no `actions`. One in the other form than the history (an older release changed how the history is stored, see [What older releases do](#what-older-releases-do-with-newer-files)): not read and never written over, with a sentence that says so; the rest of the history works. A plain `actions.json` in an encrypted history is never read or removed; `pathwarden action log import` takes it in on purpose. |
| `.pathwarden-encryption` | `"format"`: 2, every file bound to its place (0.2). 1 is a history encrypted by 0.1.7 to 0.1.9. | "This history was encrypted by a newer Pathwarden (encryption format N). Update Pathwarden to read it." |
| `<file>.age` binding line | Binding version 1. | Refused: "needs a newer Pathwarden". |
| `.pathwarden-state` | A marker. Its text is for people. | Nothing to read. |
| `.pathwarden.lock`, `.pathwarden-last-pull.json` | This computer's, never committed. | A lock is respected while fresh, whoever wrote it. |
| `.git/pathwarden-settings-base.json` | This computer's, never committed: each shared section as it was at the last sync (`digest`, and `value` as JSON). The three-way merge compares each entry here, in this computer's `pathwarden.toml` and in `settings/pathwarden.toml`. An entry with two values is recorded as it was before both changes, so it stays a clash until someone chooses. A section with no `value` (or a file that can't be read) is settled whole. | Read as far as it reads; a section it can't read is settled whole. |
| `.git/pathwarden-settings-dismissed.json` | This computer's: the clashes the app's note was dismissed for (`key`, a hash of each clash and both sides' values). | Ignored. |
| `.git/pathwarden-settings-merged.json` | This computer's (from 1.0.0-rc.3): what the last merge brought here (`entries`: `section`, `id`, `label`, `added`, `words`), who made the shared change and when (`by`, `on`, `changed_at`), and whether the app said it (`seen`, `dismissed`). Replaced by the next sync that merges entries in. | Ignored. |

The merge never changes `settings/pathwarden.toml`'s form: each merged
entry is written into the sections older releases read, and the file stays
at format 1, so a release on the same history that settles sections whole
still reads a valid file (it sees the merged result as one change).

### The app's workspace (`%LOCALAPPDATA%\Pathwarden`)

| File | Format | A newer one |
|---|---|---|
| `runs/<run>/` | The summary's file name: `summary.json` is format 1, a run analysed here. `summary.v2.json` is format 2, a run loaded from a history's full runs, with the `loaded-from-history` marker beside it. A run 0.1.9 loaded (`summary.json` beside the marker, or saying `shared`) is moved to `summary.v2.json` the first time this version looks. Optional `collection` fields from 1.0 (format 1 still), left out when false: `plain_allowed` (plain LDAP was allowed, so a schedule of the run allows it too) and `plain_fallback` (LDAPS was asked for but a domain controller was read over plain LDAP; `ldaps` stays what was asked). Optional summary fields from 0.3 (format 1 still): `settings_files` (as in `last-run.json`), `settings_folders_unread` (how many Tier Zero settings folders couldn't be opened, never which), and `history.settings_fewer` (the servers the last run had a settings file for and this one has not). | A folder holding `summary.vN.json` with N above 2 (however large) is never listed, opened, written into or changed. The Runs page and `pathwarden runs list` say "N runs on this computer were saved by a newer Pathwarden. Update Pathwarden to open them." (`newer_runs` in `--json`), and a sync that would load a full run into such a folder says the same and leaves it. |
| `runs/<run>/report.html` | No number: the page as written. | A loaded run's report is served under a strict content policy ([threat model](threat-model.md)). |
| `runs/<run>/objects.json.gz` | `"version"`: 1. | Not read: no graph for the run. |
| `runs/<run>/graph.bin.gz` | A version byte: 1, or 2 with node and edge kinds. | "explorer data version N is not supported". |
| `runs/<run>/props.json.gz` | `"version"`: 1. Each object's analysis fields, for Cypher queries on the run (the Query tab, `pathwarden query --run`). Runs saved before have none: "This run was saved without its objects' properties, so they read as null. Analyze its data again to query them." | Not read: the run's properties read as null, and its queries say "This run's properties were saved by a newer Pathwarden, so they read as null. Update Pathwarden to query them." |
| `runs/<run>/retest.json.gz` | `"version"`: 1. | Not read: no targeted retest for the run. |
| `runs/<run>/event.json.gz` | The event document. | Every reader (findings, Home, Progress, evidence, exports, imports, diagnostics, a plugin's test) refuses a schema other than `pathwarden.event.v1`: "A newer Pathwarden saved this run's findings. Update Pathwarden to read them." where a page names the problem. |
| `runs/<run>/exposed.json.gz` | `"version"`: 1 (from 0.2). | "A newer Pathwarden wrote this run's account lists." |
| `runs/<run>/timings.json` | `"version"`: 1. Fields are optional: `cache_entries` and `cache_bytes` (from 0.3) are what the built-in collector's read took on disk, for the next collection's free-space check; `read_counts` (from 0.3) its entries by type, and with `entries` the next read's expected size; `read_streams` (from 0.3) the connections the read used at the start and at the end. | Not read: no collection performance. |
| `runs/<run>/coverage.json.gz` | No number. Fields are optional. | Read as far as it goes. |
| `runs/<run>/retests.json` | `"version"`: 1. | Not read, and a retest isn't recorded into it: "A newer Pathwarden saved this run's retests. Update Pathwarden to record one here." It is never rewritten. |
| `owned.json` (in each environment's folder) | `"version"`: 1. The objects marked as owned (Explore's Mark as owned, `pathwarden owned`). | Not read, and never written over: queries run with no owned objects and say "owned.json was saved by a newer Pathwarden. Update Pathwarden to change the owned marks." Marking and `pathwarden owned` refuse with the same sentence. |
| `environments.json`, `run-labels.json`, `history-hidden.json`, `history-local.json` | No number. Fields are optional. | Read as far as they go. These never leave this computer. |
| `runs/<run>/loaded-from-history` | No number: a marker. | Nothing to read. |
| `.pathwarden-folders-reviewed.json` (next to each `pathwarden.toml`, from 0.3) | No number. `folders`: `path`, `at` (optional). The Tier Zero settings folders used on this computer. | Read as far as it goes; one that can't be read counts as no review, so every folder waits again. Never committed. |
| `collect-cache/<domain>/checkpoint.json` | `"format"`: 3 (from 0.3; 2 had no `rest` chunk, 1 no key and no plan). Also `pathwarden` (the version that wrote it); the read's key: `domain`, `dc_host`, `ds_service_name`, `invocation_id` (hex), `account` and `sign_in` (HMAC-SHA256 with the key in `collect-cache/read-key`, never the name), `filter`, `attributes` (a SHA-256 hash of the list asked for: the attributes RustHound-CE reads, or `*` with `--all-attributes` and before 0.3); `domain_nc`, `highest_usn` (the snapshot), `started` and `updated` (UTC), `expected` (optional: the entries expected); the plan, `chunks`: `id`, `nc`, `kind` (`head`, `window`, `whole`, `delta` or `rest`: the objects no range returned, read last), `usn_lo` and `usn_hi` (optional), `state` (`todo` or `done`), `entries`, `bytes`, `counts` (optional: entries by type); and `totals`: `chunks`, `done`, `entries`, `bytes`. Written to `checkpoint.json.tmp`, synced, then renamed over the old one, each time a chunk is done. `checkpoint.json.lock` is locked while the read runs. | An older format is a read this version can't use: removed with its chunks, and the read starts over. A newer one is never trusted or rewritten: kept until a collection of that domain starts over, which removes it. A read is resumed only on the same key, within 24 hours of `started`. |
| `collect-cache/read-key` | 32 random bytes, hex: the key of the HMACs in this cache's checkpoints. Made when the first read starts; never leaves this computer. | Unreadable or damaged: replaced, and the reads keyed with the old one start over. |
| `collect-cache/<domain>/chunk-NNNN.seg` | RustHound-CE 2.5.30's `DiskStorage` records (a little-endian `u32` length, then the entry in bincode 2). `chunk-NNNN.part` while it is written (one at a time per connection reading, from 0.3; removed when its read fails); renamed to `.seg` once synced. The checkpoint's shape is the same with several connections: format 3. Beside the head's, the windows' and the delta's `.seg`, from format 3, `chunk-NNNN.dns`: each entry's DN key in order (the first 16 bytes of the SHA-256 of its DN in lower case, little-endian), written and synced before the rename, so a resumed read knows what was read without reading the `.seg` again. | Only a chunk the checkpoint says is done is read, and only as `.seg`; its count must match. A `.part`, or a `.seg` the checkpoint doesn't call done, is read again on resume. A `.dns` whose size isn't 16 bytes an entry is not used: the `.seg` is read instead. The folder is removed once the read is parsed; a read that stopped keeps it for 24 hours. |

`history-pins` (what this computer read from an encrypted history) and the
stored passphrases are this account's own: no number, never shared.

### Documents for other programs

| Document | Schema | Compatibility |
|---|---|---|
| The event document (`--event`, output plugins) | `pathwarden.event.v1` | It only grows: a field is never removed or changed in meaning within v1. [Fields](#the-event-document-pathwardeneventv1). |
| Finding actions: describe, request and result | `pathwarden.action-describe.v1`, `pathwarden.action-request.v1`, `pathwarden.action-result.v1` | They only grow. A program ignores fields it doesn't know, and so does Pathwarden. [Fields](#finding-actions-pathwardenaction-v1). |
| An output plugin's result file | `pathwarden.output-result.v1` | It only grows; Pathwarden ignores fields it doesn't know. [Fields](#the-output-result-file-pathwardenoutput-resultv1). |
| The run bundle (`runs/<run>/run.json`) | `pathwarden.run-bundle.v1`, `"format"`: 2 | [Fields](#the-run-bundle-pathwardenrun-bundlev1). |
| Evidence packs | `pathwarden.evidence.v1` | A verifier refuses another schema. [The format](../evidence.md#the-format). |
| SARIF and DefectDojo exports | The receiver's own. | [Integrations](../integrations.md). |

### Files beside the collector data

Pathwarden reads these from a collection's folder or zip. Each names its
schema; a file of another schema, too large, or not JSON is refused whole
and named in the run's skipped files, and the rest of the collection is
read. Fields a reader doesn't know are ignored, so they only grow.

| File | Schema | Compatibility |
|---|---|---|
| `pathwarden-sysvol.json` (the built-in collector's SYSVOL and NETLOGON results) | `pathwarden.sysvol.v1` | Optional fields only within v1. A part this version doesn't know is not read. [SYSVOL and NETLOGON](../collect.md#what-each-method-collects). |
| `pathwarden-storedcreds.json` (the accounts services run as and scheduled tasks store) | `pathwarden.storedcreds.v1` | Additive within v1: optional fields (`turned_off`; for scheduled tasks, slice 2, `tasks` and `tasks_turned_off` on the file, `tasks` on each computer, `enabled` and `logon_type` on each entry), and new values of an entry's `via` (`service`, and `task` since slice 2). A reader drops entries whose `via` it doesn't know, and `task` entries in a file without `tasks`, each with a note. A file without `tasks` is from before tasks were read: the run then has no tasks source. Account names only; it has no field for a secret, and fields it doesn't know are dropped while it is read. [Stored credentials](../collect.md#what-each-method-collects), [scheduled tasks](../collect.md#what-each-method-collects). |
| `pathwarden-tierzero-<HOST>.<domain>.json` (Tier Zero settings: domain controllers and CAs) | `pathwarden.tierzero.v2` (0.3), `pathwarden.tierzero.v1` | v2 adds the `agents` part (the management agents on the host); this version reads both, and ignores `agents` in a v1 file. Pathwarden 0.2.0 and earlier skip a v2 file whole (named in the skipped files); for them, keep a file from the v1 script. Optional fields only within v1. The `cas` array (0.3) is one: older versions ignore it and read the DC values as before. A CA-only host's file (empty `values`, from 0.3) is matched by 0.2.0 to its computer and noted "not a domain controller": harmless, nothing is applied. [Tier Zero settings](../tier-zero-settings.md). |
| `<payload>.coverage.json`, `pathwarden-coverage.json` (what an OpenGraph collector covered) | `pathwarden.coverage.v1` | Bound to its payload by SHA-256. [Coverage files](../opengraph.md#coverage-files). |

#### `gpo_local_groups` in `pathwarden-sysvol.json`

An optional list, added within v1: which GPO, through which setting,
puts members in a local group. The built-in collector writes it with
`--user`. It is absent in older files and in runs as the current Windows
user, and then fixes list the linked GPOs as candidates.

```json
"gpo_local_groups": [
  {
    "guid": "{AAAA0000-0000-0000-0000-000000000001}",
    "object_id": "AAAA0000-0000-0000-0000-000000000001",
    "setting": "restricted_groups",
    "group": "administrators",
    "members": ["S-1-5-21-1000-1000-1000-1104"]
  }
]
```

| Field | Meaning |
|---|---|
| `guid` | The GPO's folder name in SYSVOL. |
| `object_id` | The GPO's ObjectIdentifier in the collection. |
| `setting` | `restricted_groups` (Security Settings: Restricted Groups) or `gpp` (Preferences: Local Users and Groups). |
| `group` | `administrators`, `remote_desktop`, `dcom` or `ps_remote`. |
| `item_level_targeting` | `true` when only items with item-level targeting add these members. Absent otherwise. |
| `members_truncated` | `true` when the collector cut `members` at the cap. Absent otherwise. |
| `members` | Object IDs, as in `GPOChanges`. |

All or nothing, so a fix never names one GPO where another also sets the
member:

- Over 100,000 entries, the collector writes none, and a reader skips the
  whole list.
- An entry over 1,000 members is cut and marked `members_truncated`.
- A GPO with a cut entry, a malformed member, or an entry that doesn't read
  (a wrong type, a `guid` that isn't one, a `setting` or `group` this version
  doesn't know) names nobody. At every OU or domain it is linked to, the fix
  lists the linked GPOs as candidates.
- An entry whose GPO can't be told (not an object, no `object_id`) or a
  value that isn't a list: no GPO is named anywhere.

Each skipped entry is noted. Only the GPO names in the fixes are lost, never
the rest of the file.

#### WSUS and SCCM parts in `pathwarden-sysvol.json`

Added within v1. Every field is optional and older readers ignore
them, so the schema stays `pathwarden.sysvol.v1`. A file without them is
from before they were read: the WSUS and SCCM findings that need them are
then held, not resolved.

```json
"checks": {
  "registry_pol": { "status": "partial", "read": 41, "failed": 1, "reason": "1 item could not be read, first: ..." },
  "sccm_sites": { "status": "complete", "read": 2 }
},
"registry_policy": [
  {
    "guid": "{AAAA0000-0000-0000-0000-000000000001}",
    "object_id": "AAAA0000-0000-0000-0000-000000000001",
    "values": [
      { "key": "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\WINDOWSUPDATE", "name": "WUSERVER", "text": "https://wsus01.example.test:8531" },
      { "key": "SOFTWARE\\POLICIES\\MICROSOFT\\WINDOWS\\WINDOWSUPDATE\\AU", "name": "USEWUSERVER", "number": 1 }
    ]
  }
],
"registry_pol_failed": [
  { "guid": "{BBBB0000-0000-0000-0000-000000000002}", "object_id": "BBBB0000-0000-0000-0000-000000000002" }
],
"sccm": {
  "sites": [{ "site_code": "P01", "owner": "S-1-5-21-1000-1000-1000-1150" }],
  "management_points": [{ "site_code": "P01", "host": "cm01.example.test", "default": true }]
},
"disabled_gp_links": [
  { "container": "OU=SERVERS,DC=EXAMPLE,DC=TEST", "gpo": "AAAA0000-0000-0000-0000-000000000001" }
],
"machine_quota_computers": ["S-1-5-21-1000-1000-1000-1150"]
```

| Field | Meaning |
|---|---|
| `checks.registry_pol` | How the GPOs' `Machine\Registry.pol` files were read, as the other checks. |
| `checks.sccm_sites` | Whether SCCM's site objects under `CN=System Management` were read. Absent: not read, so `sccm` says nothing. |
| `registry_policy` | Per GPO (`guid`, `object_id`), the Windows Update and SCCM client setup values its `Registry.pol` sets. Only GPOs with such values are listed. |
| `values[].key` | The registry key, upper case: `...\WINDOWSUPDATE`, `...\WINDOWSUPDATE\AU` or `...\CCMSETUP`. Other keys are not kept. |
| `values[].name` | The value name, upper case, at most 256 characters. `*` with `delete` means every value of the key. |
| `values[].text`, `number`, `delete` | Exactly one: a string (at most 1,024 characters), a number, or `true` when the GPO deletes the value (a policy set to Disabled). |
| `registry_pol_failed` | The GPOs whose `Registry.pol` couldn't be read or parsed. Empty when the read ran out of time. |
| `sccm.sites[]` | A site object: `site_code` (three letters or digits) and `owner`, the SID of the account that created it. |
| `sccm.management_points[]` | A management point: `site_code`, `host` (its DNS name) and `default`. |
| `disabled_gp_links` | The GPO links whose `gPLink` option marks them disabled: the OU's or domain's DN and the GPO's ID. Absent: the links' status was not read. |
| `machine_quota_computers` | The SIDs of computers that have `mS-DS-CreatorSID` set, so were created through the machine account quota. |

How a reader uses them:

- A `Registry.pol` over 4 MiB, or with more than 64 kept values, is not
  read and counts as failed.
- A failure makes `registry_pol` partial only when that GPO is linked above
  a domain controller or CA host. A GPO the collection doesn't have, or a
  read that ran out of time, keeps it partial.
- Without `disabled_gp_links`, a GPO that deletes a value doesn't override
  a lower GPO's value for sure: both are kept as possible.
- A WSUS or management point host matches a computer only by its full DNS
  name, or by its short name within the domain. A host that matches no
  computer, or one in `machine_quota_computers`, is reported for review
  (PW-028) and never made Tier Zero.
- Two site objects with one site code, or an owner and a management point
  that name different computers, narrow nothing: every site server of the
  forest stays a candidate, and the client is reported for review.
- An entry that doesn't read is dropped and noted, and `registry_pol`
  becomes partial.

## The run bundle (`pathwarden.run-bundle.v1`)

A full run in the history is a folder `runs/<run ID>/`, beside the run's
point `history/<run ID>.json`. It holds these files and no others (no
folders):

| File | Contents |
|---|---|
| `run.json` | The manifest, below. |
| `summary.json` | The run's summary as the Runs page shows it, without anything of the recording computer's. |
| `report.html.gz` | The HTML report, gzipped. |
| `graph.bin.gz` | The Explore graph. |
| `objects.json.gz` | The object index: every object's ID, name, kind and group memberships. |
| `event.json.gz` | The [event document](#the-event-document-pathwardeneventv1). |
| `retest.json.gz` | What a targeted retest needs. |
| `exposed.json.gz` | The accounts that reach Tier Zero, with their paths (format 2). |
| `opengraph.json` | The OpenGraph sources the run read. |
| `settings.toml` | The shared sections of `pathwarden.toml` the run was analysed with. A snapshot, never applied. |

`run.json`:

```json
{
  "schema": "pathwarden.run-bundle.v1",
  "format": 2,
  "run_id": "20261030T151733.132Z",
  "pathwarden": "0.2.0",
  "recorded_by": "SCALE\\analyst",
  "recorded_on": "PW-DEMO-01",
  "recorded_from": "cli",
  "finished_at": 1793373453,
  "settings_sha256": "<64 lowercase hex>",
  "files": [
    { "name": "summary.json", "bytes": 1163, "sha256": "<64 lowercase hex>" }
  ],
  "left_out": [
    { "name": "graph.bin.gz", "bytes": 120000000, "why": "over the 75 MB per-file limit" }
  ],
  "max_file_bytes": 78643200
}
```

| Field | Meaning |
|---|---|
| `schema` | Always `pathwarden.run-bundle.v1`. A reader leaves a folder with another schema alone. |
| `format` | 1 (0.1.9) or 2 (0.2, which added `exposed.json.gz`). A reader refuses a full run of a format above its own, and one that names a file it doesn't know. A file added to the list above raises the format. |
| `run_id` | The history's run ID. It must be the folder's name. |
| `pathwarden` | The version that wrote it. |
| `recorded_by`, `recorded_on` | The account (`DOMAIN\user`, or a scheduled task's gMSA) and the computer that recorded the run. Optional. |
| `recorded_from` | `ui` (the app), `schedule`, `cli` (the command line) or `import`. |
| `folder` | The recording computer's own folder ID for the run. Optional, for reference only. |
| `finished_at` | When the analysis finished, in Unix seconds. |
| `settings_sha256` | The SHA-256 of `settings.toml`, when there is one. Optional. |
| `files` | Every file of the full run but `run.json`, with its size in bytes and its SHA-256. A reader checks both before it uses a file. |
| `left_out` | Files the run had that aren't here (over `max_file_bytes`), with their size and why. A run whose object index or graph is left out opens on other computers, but not in Explore. |
| `max_file_bytes` | The largest file the run was written to take, in bytes: `[state] full_run_file_mb` of the computer that recorded it (75 MB by default; at most 95 MB on GitHub); written by versions after 0.3.0. A reader refuses a file over it, or over the size `files` gives, before reading it; a full run without it is held to 45 MB, the limit before; none is held to more than 2 GB. Optional: a reader that doesn't know it ignores it, so the format stays 2 (an older reader refuses a file over 45 MB as too large). |

In an encrypted history every file is `<name>.age`, encrypted and bound
like the rest of the history.

## The event document (`pathwarden.event.v1`)

`pathwarden run --event FILE` writes it, and output plugins receive it on
standard input. It is one JSON object. Fields marked optional may be
absent; a plugin should ignore fields it doesn't know.

| Field | Meaning |
|---|---|
| `schema` | Always `pathwarden.event.v1`. |
| `run` | The run: `version` (1), `run_id`, `started_at`, `finished_at` and `collected_at` (Unix seconds; `collected_at` may be null), `pathwarden` (the version), `collector_files`, `domains` (collected), `trusted_domains`, `objects`, `changes` (counts: `new`, `open`, `regressed`, `suppressed`, `resolved`, `held`, `unchecked`), `sources_exact`, `sources` and `hosts` (optional, as in `last-run.json`), `settings_files` (optional, from 0.3: the Tier Zero settings files the run used, as in `last-run.json`). |
| `posture` | `tier_zero` (`objects`, `population`, `relevant_population`, `exposed`, `exposure_percent`, `exposure_status`, `status_reason`, `objects_with_findings`, `protected_percent`, and the deprecated `exposure_grade`, `grade_reason` and `protection_score`: see [Renamed keys](#renamed-keys)), `zones` (the same for each Privilege Zone), `findings` (counts by category and severity, `open_by_rule`), `completeness` (per domain, see [The event document](../#the-event-document-pathwardeneventv1)), `exposure_basis`, `plan` (`steps`, `exposed_after`). |
| `findings` | Every finding in this run. Each has `change` (`new`, `open`, `regressed`, `suppressed`), `first_seen`, `times_seen`, `rule`, `category`, `severity`, `rule_severity`, `severity_default` (optional), `exposure` (`scope`, `principals`, `population`, `percent`, or null), `fingerprint`, `title`, `domain`, `summary`, `remediation`, `affected` (`id`, `name`, `kind`, `detail`), `path` (`source`, `target`, `steps` with `from`, `from_kind`, `edge`, `to`, `to_kind`, or null), `references`, `suppressed` (the reason, or null), `accepted` (who accepted the risk, when, its review date and notes; optional), `actions` (optional, from 1.0.0-rc.3: what finding actions did on it, from the history's `actions.json` when the run was recorded: `records`, each as in [What actions did](#what-actions-did-actionsjson), and `activity_count`, how many runs it keeps; absent when none ran), `sources` and `requires` (optional; from 0.3 `requires` also holds the units, as in `last-run.json`'s `hosts`, of the computers whose sessions or local groups the finding rests on: one per list read on each computer, capped at 256 computers per kind, past which `s:*` or `l:*` stands for every computer of that kind the last run listed), `rests_on` (`sessions`, `local_groups`). |
| `resolved` | Findings that were open last run and are gone: `fingerprint`, `rule`, `severity`, `first_seen`, `resolved_at`, `title` (optional), `actions` (optional, as on `findings`). |
| `held` | Findings this run couldn't check: `fingerprint`, `rule`. Not fixed: a plugin that closes tickets for missing findings leaves these open. |
| `plan` | The remediation path: `exposed_before`, `exposed_after`, `exposure_before`, `exposure_after`, `exposure_delta`, `relevant_population`, `relevant_population_after`, `first_fix_exposure_after`, `total_cost`, and `fixes` (`from`, `from_kind`, `edges`, `to`, `to_kind`, `cost`, `principals_through`, `shortest_paths_through`, `sdprop_copies`, `inherited_by`, `action`). |
| `guides` | The step-by-step guide (Markdown) for every rule with findings, by rule ID. |
| `superseded` | Optional, only when true: a newer run was recorded first, so what this says changed is older than the history's state. |

The event carries names and details. Treat it like the collector output:
write it to the run's working folder and delete it afterwards.

## The output result file (`pathwarden.output-result.v1`)

On a real run of `pathwarden run` (not Test, and not when the plugin's
settings have `dry_run = true`), Pathwarden names a fresh file in the
plugin's private folder in `PATHWARDEN_OUTPUT_RESULT`. A plugin may write
one JSON object there: the tickets it keeps for the event's findings.
Pathwarden reads it once the plugin exited 0, then removes it.

| Field | Meaning |
|---|---|
| `schema` | Should be `pathwarden.output-result.v1`: a missing one is noted, another refuses the file. |
| `records` | Required, a list: at most 10,000 are read. Each is a [result's record](#finding-actions-pathwardenaction-v1) (`id` required, `kind`, `label`, `number`, `url`, `status`, `open`, `fields`) plus `fingerprint` (required): the finding it is on. At most 5 per finding; one of the same `fingerprint` and `id` as an earlier one is left out. |

The checks are a result's: text is never read as HTML, control characters
are dropped, texts are cut to the same caps, and a `url` that isn't
`https://` is left out. The file is at most 8 MiB and must be a plain file
(not a link or a pipe). A record on a fingerprint that is neither in the
event nor in the history's findings is left out. A file that can't be read
(not JSON, another schema, no `records`) is a warning in the run log, and
so is a part left out; the plugin and the run still count as succeeded.
A plugin that writes no file changes nothing.

The records are saved on their findings in the history's
[`actions.json`](#what-actions-did-actionsjson) as records whose `action`
is `plugin:<plugin>` (the `[[output]]` block's `plugin`, such as
`plugin:servicenow`): no `[[action]]` block can have that name, so such a
record has no follow-ups, and it counts for every action's `once`.
Only what changed is saved: a new record (with `by`, `on` and `at` of the
run), or one whose fields changed (`updated_at` set, who first made it
kept). A record seen again unchanged writes nothing. A finding gets one
entry of activity for a run when a ticket is first seen ("INC0012345 ·
Open"), closed ("Closed INC0012345 · Resolved") or reopened, labelled
with the plugin and shown with it ("ServiceNow plugin: INC0012345 ·
Open"). The save is one commit with the
fixed message `pathwarden: save the tickets output plugins keep`, made
again on what another computer pushed first, and kept on this computer
when the push fails, as a finding action's is. A run with `--no-push`, or
`[state] push = false`, doesn't save them. A plugin's record someone
removes comes back with the plugin's next run, as long as the plugin
still reports it.

## Finding actions (`pathwarden.action-*.v1`)

An `[[action]]` block in `pathwarden.toml` names a program someone runs
for one finding, when they ask. [Writing an action](../actions.md) is the
guide, and the [Action reference](../action-reference.md) has every field,
with JSON Schemas in [docs/schemas](../schemas/). Pathwarden writes one JSON request to
the program's stdin and names its kind, `describe` or `run`, in
`PATHWARDEN_ACTION_REQUEST`. The program writes one JSON answer to the
file named in `PATHWARDEN_ACTION_RESULT`. Each line it prints to stdout is
a progress line (the latest 200 are kept, each cut to 500 characters);
stderr is kept for the details. Both sides ignore fields they don't know.

The request (`pathwarden.action-request.v1`):

| Field | Meaning |
|---|---|
| `schema` | Always `pathwarden.action-request.v1`. |
| `kind` | `describe` or `run`. A describe request carries only `settings`. |
| `action` | The ID of the action to run, from the program's describe. |
| `inputs` | The inputs by ID, checked against their types: text, or true or false for `bool`. |
| `dry_run` | True when the program must change nothing. |
| `settings` | The block's other keys. Secrets are named by `*_env` settings, and those variables are in the environment. |
| `run` | `run_id`, `domains`, `pathwarden` (the version that analyzed it). |
| `finding` | The finding as the [event document](#the-event-document-pathwardeneventv1) has it, plus `guide` (the rule's Markdown guide, or null) and `status` (`open`, `fixed`, `held` or `accepted`). A fixed or held finding has only the fields of `resolved` or `held`. |
| `record` | For a follow-up, the record it runs on, else null. |
| `requested_by` | `by` (the user) and `on` (the computer), each null when unknown. |

The describe answer (`pathwarden.action-describe.v1`): `schema`, which
should be `pathwarden.action-describe.v1` (a missing one is noted,
another is refused), and
`actions`, at most 20, each:

| Field | Meaning |
|---|---|
| `id` | Lowercase letters, digits, `-` and `_`, at most 40. The action is addressed as `<name>/<id>`. |
| `label` | The button, at most 80 characters. |
| `description` | Optional, at most 300 characters. |
| `sends` | What leaves the computer, in plain words, at most 500 characters. |
| `applies_to` | Optional: `min_severity`, `rules`, `categories` (`attack_path`, `hygiene`), on top of the block's own filters. A fixed or held finding is rated by its rule: its category, and for a held one the highest severity the rule gives. |
| `inputs` | At most 20, each `id`, `label`, `type` (`text`, `textarea`, `choice` or `bool`), `required`, `max` (text: 200 by default, at most 1,000; textarea: 2,000, at most 4,000), `choices` (for `choice`, at most 50) and `default`. |
| `once` | True to hide the action while the finding has an open record from it, or an open ticket an output plugin reported (from 1.0.0-rc.4). |
| `follow_ups` | IDs of this program's `for: "record"` actions, offered on the records this one returns. |
| `for` | `"record"`: only offered as a follow-up on a record. |
| `when` | Optional: where the finding must stand for the action to be offered, a list of `open`, `held`, `accepted` and `fixed` (one value alone is a list of one, so `"fixed"` still reads). Without it: open, held and accepted findings, not fixed ones; a follow-up (`for: "record"`) without it is offered on a record however the finding stands. A fixed finding is offered only the actions that list `fixed`, and the follow-ups on its records. |

An action with a problem in its `id`, `label`, filters, inputs, `for` or
`when` isn't offered; a text that is too long is cut.

The result (`pathwarden.action-result.v1`):

| Field | Meaning |
|---|---|
| `schema` | Should be `pathwarden.action-result.v1`: a missing one is noted, another fails the run. |
| `ok` | Required: whether the action worked. |
| `message` | At most 2,000 characters, shown as text. |
| `links` | At most 5, each `label` and `url`. |
| `records` | At most 5, each `id` (required; a follow-up returns the same one to update it), `kind`, `label`, `number`, `url`, `status`, `open` (true while it is open in the other system) and `fields` (at most 20, each value at most 200 characters). |

Text is never read as HTML, and control characters are dropped. Every
`url` must be `https://`, without a user name or password; another is
left out. A missing result file, one that isn't JSON or has no `ok`, or
a non-zero exit is a failed run, shown with the program's output.

### What actions did (`actions.json`)

Every run of a finding action that isn't a dry run is saved at once on
its finding in the history's `actions.json`, a state file like the others
(encrypted with the history, committed and pushed with the fixed message
`pathwarden: save what a finding action did`). It is a file of its own
because `findings.json` is rebuilt every run.

```json
{ "version": 1,
  "findings": { "PW-001-8ae0b31a46eacada": {
    "activity": [ { "at": "2026-11-18T14:02:11.123Z", "by": "NORTH\\eddard.stark",
                    "on": "SECOPS-WS02", "run_id": "20261118T140200.000Z",
                    "action": "service-desk/open", "label": "Open a service request",
                    "ok": true, "message": "Opened RITM10816190.",
                    "record_ids": ["4f1c"], "dry_run": false } ],
    "records": [ { "action": "service-desk/open", "id": "4f1c", "kind": "request",
                   "number": "RITM10816190", "status": "Open", "open": true,
                   "url": "https://example.service-now.com/...", "fields": {},
                   "by": "NORTH\\eddard.stark", "on": "SECOPS-WS02",
                   "at": "2026-11-18T14:02:11.123Z",
                   "updated_at": "2026-11-18T14:02:11.123Z" } ] } } }
```

| Field | Meaning |
|---|---|
| `findings` | By fingerprint, as the event has it. |
| `activity` | Oldest first; the latest 100 of a finding are kept. Each: `at` (RFC 3339, UTC, with milliseconds), `by` and `on` (the user and computer, each optional), `run_id` (the run the finding was in, optional), `action` (`<name>/<id>`), `label` (the action's then), `ok`, `message` (the result's, or what went wrong), `record_ids` (the records it made, changed or removed), `dry_run` (always false), `kind` (absent for a run; `remove` when someone removed a record, with `action` the record's) and `outcome` (optional: `cancelled` for a run someone stopped with Ctrl-C or Cancel, then with `ok` false and the message "Cancelled"; it is saved in one quick try without the network, and goes to the repository with the next pull and push). |
| `records` | What the actions returned (a [result's record](#finding-actions-pathwardenaction-v1)), plus `action` (the action that made it; `plugin:<plugin>` for a ticket an output plugin reported, see [the output result file](#the-output-result-file-pathwardenoutput-resultv1)), `by`, `on` and `at` (who first made it, where and when) and `updated_at`. A follow-up that returns the same `id` updates the record of its block, keeping when and by whom it was first made. A record stays until someone removes it (`pathwarden action records remove`), which is logged as activity. |
| `removed` | Optional: the records someone removed, each `action`, `id`, `at` (when), `by` and `record_at` (when the record removed was made). A record of that `action` and `id` made no later than `at` or `record_at`, whichever is later (two computers' clocks may disagree), never comes back (a follow-up that started before the removal, a computer that hadn't seen it); one a later run makes anew does. The latest 100 of a finding are kept. |

When another computer pushed first, the change is made again on what it
left, finding by finding: activity is the union of both (one entry per
`at`, `by` and `action`), and records are matched by `action` and `id`,
the newer `updated_at` winning; a removal on either side wins over any
record made before it. Fields this version doesn't know, in the file, a
finding, an entry or a record, are kept as they are, and so is a `kind`
it doesn't know, whatever its JSON (shown by the entry's `label`). A
record's unknown fields, at most 8 KB of them, are passed on as they are:
to a follow-up's program in its request's `record`, and in the event.

A save whose push failed is kept on that computer (in the working copy's
`.git`, never committed, in `pathwarden-actions-pending.json`: finding
actions' saves in `changes`, output plugins' in `records`, one entry per
finding however many runs add to it; encrypted with the history's key when the
history is encrypted, and written again in the new form when the history
is encrypted, decrypted or given a new passphrase), made again on what
every later pull brings, and dropped once a push carried it (the file is
removed when none is left): it goes with the next save or run that
pushes; until then `action run` says "Saved on this computer; not pushed
yet: it will be retried with the next sync." (`"pushed": false` in its
JSON). A save the log refused (a newer, damaged or unreadable file, also
when the remote's file turns out so on a retry) is not kept, and is the
error. A file of waiting saves that can't be opened (sealed in a history
decrypted since, sealed with another key, damaged) is moved aside to
`pathwarden-actions-pending.json.unreadable-<date>` in `.git` (`-2`, `-3`
… when that name is taken), the next save or pull says so naming the
file, and saves go on.

`pathwarden export --run` (and the app's export of a run) exports the
records as they were when that run was recorded: a snapshot, from the
run's event.

Anyone who can push to the history can write this file, so it is read as
untrusted: at most 16 MiB, every text cut to a result's caps, and a
record's `url` dropped unless it is `https://`.

## What older releases do with newer files

The published releases can't follow the policy where they predate it.
What each does with what 0.2 writes:

| Release | Newer files it reads anyway, or refuses |
|---|---|
| 0.1.5, 0.1.6 | Refuse `findings.json` above version 1, and an encrypted history (the stub). Read history points, `last-run.json` and run files without checking their version. Never see full runs, settings in the repository, or a loaded run (`summary.v2.json`). Refuse a top-level or `[state]` key they don't know in `pathwarden.toml`, so `format = 2` too. |
| 0.1.7 | As 0.1.6, and reads an encrypted history of marker format 1 only: it refuses format 2. Refuses `[state]` keys it doesn't know (for example `full_runs_kept`, `refresh`). |
| 0.2.0 | Ignores `last-run.json`'s `hosts` and drops it when it writes the file, so the next run of 0.3 treats that run as an upgrade (see `last-run.json`). Holds a finding whose `requires` has session or local group units (`s:`, `l:`) it doesn't know, with the wrong reason ("its source did not report covering the affected host this run"), until a run sees the finding again. Ignores the paths' `edge_hosts`. A `last-run.json` written by a development build between 0.2.0 and 0.3 with stored credential units (`h:`) in `sources` makes 0.2.0 hold every attack path for one run, as a missing source. |
| 1.0.0-rc.2 and earlier | Keep `actions.json` as the repository has it when they record runs, pull and share settings: they commit only the files they know, and their pull cleans only files no commit holds. They don't read it, so their runs' findings carry no `actions`. They don't rewrite it when they change how the history is stored: turning encryption off leaves `actions.json.age` (which 1.0.0-rc.3 then can't open, so what actions did is unavailable), changing the passphrase leaves it under the old key (the same), and turning encryption on leaves it plain. 1.0.0-rc.3 never reads a plain `actions.json` in an encrypted history (anyone who can push could have put it there), never removes it, and says so: "A plain actions.json is in this encrypted history and wasn't read. If an older Pathwarden left it when encryption was turned on, import it with `pathwarden action log import`." That command pulls, shows what the file holds (counts, every record with its number, status and link's host, at most 20 lines, and the latest activity), asks, and then takes in exactly those bytes (a file that changed since is refused), encrypted, removing the plain copy in the same commit. Decrypting a history moves such a file aside, so it never becomes the plain history's log: into the working copy's `.git` as `pathwarden-actions.json.leftover-<date>` (where no commit picks it up), or beside a folder history as `actions.json.leftover-<date>`. In each case 1.0.0-rc.3 keeps working with the rest of the history and never writes over the file. **Upgrade every computer to 1.0.0-rc.3 before changing how a history is stored** (`pathwarden history storage set`, or the History storage page). |
| 1.0.0-rc.3 | Read a plugin's record (`action` `plugin:<plugin>`) as a record of an action they don't know: it shows as a chip, counts for Has a record and Fixed, ticket still open, is listed by `pathwarden action records` (by `plugin:<plugin>`) and goes in the event and exports, with no follow-ups. Their `once` counts only the action's own records, so they still show a `once` button on a finding with an open plugin ticket. They don't read the plugin saves kept on a computer for a push in `pathwarden-actions-pending.json` (the `records` list), and drop them when they write that file again; the plugin's next run reports the tickets again. The file's `version` stays 1. |
| 0.1.9 | Leaves full runs of format 2 alone and says to update. Refuses an encrypted history of marker format 2. Reads `settings/pathwarden.toml` without checking `format`, keeping the keys it doesn't know aside. Doesn't see runs loaded by 0.2. |

**Going back to 0.1.9 on a computer that loaded full runs with 0.2.** 0.1.9
doesn't see those runs (`summary.v2.json`), so every sync tries to load each
format 1 full run into the same folder again and fails with "Couldn't load
the full run of RUN" and the system's error (on Windows, "Access is
denied"), and may leave a hidden `.<folder>` beside it. Nothing is lost; the
runs open again once Pathwarden is updated. To silence it on 0.1.9, hide
those runs, or remove their folders from the workspace's `runs\`.

While these releases are supported, a change they would misread in a
history point, `last-run.json`, a run folder file or the shared settings
gets a new file name, not a higher number.

## Compatibility tests

`crates/pathwarden-cli/tests/compat.rs` loads what each published release
wrote: 0.1.5, 0.1.6, 0.1.7 and 0.1.9 (0.1.8 was never published). Each
release's own `pathwarden.exe` ran on the synthetic MGMT.LOCAL test data;
its files are in `crates/pathwarden-core/tests/fixtures/compat/<version>/`,
trimmed and with paths and names replaced. The tests check that:

- each release's `pathwarden.toml`, history, event document and app run
  read, and a run of this version continues the history without losing a
  finding's first sighting or a field of the event;
- 0.1.9's full run loads as a run of the history's, out of older
  releases' sight, and stays so when its label is edited;
- a newer `findings.json`, `pathwarden.toml`, history point,
  `last-run.json`, full run, run folder or run file is refused or skipped,
  and left as it was, and a full run is never loaded into a newer run
  folder;
- the Runs page and `pathwarden runs list` say the same sentence of run
  folders a newer version saved.

`crates/pathwarden-cli/tests/settings_sync.rs` checks that newer shared
settings and a newer `environment.json` are never replaced, not even with
`config sync --keep-local`.

Full runs exist from 0.1.9, settings in the repository from 0.1.9 (with a
git history only, so they have no fixture), encryption from 0.1.7, and the
account lists (`exposed/`) from 0.2.
