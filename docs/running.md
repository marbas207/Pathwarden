# Running Pathwarden

How to run Pathwarden from the command line and on a server.
`pathwarden <command> --help` lists every option.

## Run once (`pathwarden run`)

`pathwarden run` analyzes a collection and records it in the run history.

```powershell
pathwarden run -i .\collect -c pathwarden.toml --report report.html
```

```
Run 20261009T021540.231Z
  3 new, 0 back, 14 fixed, 11 still open, 1 accepted risk.
  Tier Zero Critical · Tier Zero protected: 104 of 125 objects (83.20%)
  Run history pathwarden-state (git https://github.com/you/pathwarden-history.git @ main), pushed.
  Report report.html
```

Use `--env NAME` instead of `-c` for an environment of the app
([Environments](ui.md#environments)). `--fail-on high` exits with 1 when a
high or critical finding is open.

## Keep a run history

The run history keeps each run's numbers and every finding's status, so the
next run can say what changed. In the app, this is **History storage**
([ui.md](ui.md#history-storage)).

In a folder (a share works too; only the accounts that run Pathwarden
should write to it):

```toml
[state]
backend = "local"
path = "pathwarden-state"
```

In a private git repository that holds only the run history, so a server,
a pipeline and your computer can record into one history:

```toml
[state]
backend = "git"
remote = "https://git.example.com/sec/pathwarden-history.git"
branch = "main"
path = "pathwarden-state"
```

- Point `path` at an empty folder. Keep `pathwarden.toml` outside it.
- Never put a password or token in `remote`. Run `pathwarden history storage
  sign-in` once as the account that runs Pathwarden, or use an SSH key.

For an app environment, `pathwarden history storage show`, `set --folder
PATH`, `set --git URL --branch main` and `sync` do the same.

### Encrypt the history

```powershell
pathwarden history storage set --encrypt --yes
```

The passphrase needs at least 12 characters. Each computer and account keeps
its own copy, never in `pathwarden.toml` or the history. In automation, set
`PATHWARDEN_HISTORY_PASSPHRASE`.

### Open a run history on another computer

```powershell
pathwarden env create --from-git https://git.example.com/sec/pathwarden-history.git --use
pathwarden env create --from-folder \\files\pathwarden\history --name Lab
```

Add `--read-only` to only read it. In the app, this is **Connect to a run
history** ([ui.md](ui.md#connect-to-a-run-history)). With full runs and
settings, the first sync takes the history's shared settings. When they
replace settings this computer had, its `pathwarden.toml` and any mapping
pack replaced are saved first, as `<file>.before-connect-<date>` next to
them.

### Shared settings

With full runs and settings in a git history, Tier Zero additions, Tier
Zero settings folders, rule settings, accepted risks, zones, management
planes and mapping packs are shared. Every save, run and pull syncs them;
`pathwarden config sync` does it on demand, and `--status` shows each
section.

When two computers change them between syncs, the changes are merged entry
by entry: different entries changed on each side are all kept, and an entry
removed on one side and untouched on the other is removed. Comments and
hand edits in `pathwarden.toml` stay. Only the same entry changed to
different values on both sides, or changed on one and removed on the other,
has two values:

```text
$ pathwarden config sync
Merged from the shared settings: APP01$ added to Tier Zero.
Shared from this computer: VAULT02$ added to Tier Zero.

1 setting has two values:

  Stale Tier Zero account (rules.stale_days)
    This computer   30 days
    Shared          60 days   CORP\a.admin on ADMIN-WS01, Nov 18, 2026, 5:55 PM

Until you choose, runs here use 30 days. Everything else is up to date.
```

Until you choose, runs on this computer use its own value for that entry
only. Then:

- `pathwarden config sync --use-repo` takes the shared value for every
  setting with two values, and prints each one;
- `pathwarden config sync --keep-local` keeps this computer's and shares it
  (not on a read-only computer, which only takes the shared ones; there,
  `--use-repo` also drops the changes made only here);
- `--section rules.stale_days` (the name `config sync` prints) settles one
  setting; `--section rules` settles a whole section. Repeat it for more.

`config sync` exits with code 2 while a setting has two values.

## Exit codes

| Code | Meaning |
|---|---|
| **0** | Done. Nothing at or above `--fail-on`, and every retested finding is fixed. |
| **1** | A finding at or above `--fail-on` is open, or a retested finding is still open. |
| **2** | An error, or a run recorded here but not pushed. |
| **3** | Can't tell: some findings' domains weren't collected. |

## Retest after a fix

In the app, click **Retest** on a finding's row
([ui.md](ui.md#retesting-a-finding)).

```powershell
pathwarden retest -i .\collect -c pathwarden.toml
pathwarden retest targeted --finding PW-006-8ae0b31a46eacada --env Lab
```

`retest` compares a new collection with the last run. Each finding is
**Fixed**, **Still open** or **Can't tell**. It records nothing unless you
add `--record`.

`retest targeted` re-reads one finding's objects and the computers on its
path, with the built-in collector, as the current Windows account. With
`--user`, it needs `--ldaps` and the password in
`PATHWARDEN_COLLECT_PASSWORD`. For an auditor's record, use
[evidence packs](evidence.md).

## See what changed

- `pathwarden history -c pathwarden.toml`: what changed since the last run,
  and each run's numbers.
- `pathwarden changes --since 7d`: what is new over a period.
  `--fail-on new` exits with 1 when anything is, for an alert.
- `pathwarden history --forget RUN`: remove a broken run from the history.

## Run on a schedule

`pathwarden schedule` writes the files for a nightly run, as the app's
**Schedule** page does. It creates no task.

```powershell
pathwarden schedule --domain scale.local --account 'SCALE\svc-pathwarden$' --at 02:00 --output .\schedule
pathwarden schedule --os linux --domain scale.local --user svc-pathwarden --output ./schedule
```

A run collected with **Allow plain LDAP** is scheduled with it on Linux
(`--allow-unencrypted-ldap`): a domain controller whose LDAPS fails is read
over plain LDAP, as in [collect.md](collect.md#plain-ldap-when-ldaps-fails).

### Windows Task Scheduler with a gMSA

The gMSA needs the grant in [collector-account.md](collector-account.md),
and must not be in Tier Zero or a local admin anywhere.

1. Run `check-gmsa.ps1` on the server.
2. Run `setup-folder.ps1` as an administrator, before you copy anything.
   It creates `C:\Pathwarden` so that only administrators can change it.
3. Copy the files and `pathwarden.exe` into `C:\Pathwarden`.
4. Run `setup-folder.ps1` again. Run it again whenever you replace a file.
5. Run `register-task.ps1`.
6. Run `test-task.ps1` and check the result.

`setup-folder.ps1` refuses a folder that already exists if anyone other
than an administrator could have changed it or anything in it, and any
junction or link on the way. Delete what it lists, or start over with a new
folder. It also refuses a folder that isn't empty and has no Pathwarden in
it, and the Schedule page and `pathwarden schedule` refuse a drive or a
Windows folder such as `C:\Program Files`.

For an encrypted history, `setup-folder.ps1` asks for the passphrase.

### Linux systemd timer

1. Copy the files and `pathwarden` to `/opt/pathwarden`.
2. Run `sudo sh setup.sh` there. It creates the user, stores the password
   for root only and turns on the timer.
3. Run `sh test.sh`.

For an encrypted history, store the passphrase with `systemd-creds encrypt
--name=pathwarden-history-passphrase` and add `LoadCredentialEncrypted=` to
`[Service]`.

### In a pipeline

Use a self-hosted runner inside your network. Check out the run history
branch into the `[state] path` folder, collect into a temporary folder, run
`pathwarden run`, keep the report briefly, and delete the collection even
when a step fails. Never run two jobs at once. Anyone who can push to the
repository can run code on the runner.

## Large directories

Plan for about 3 GB of memory for a million users and computers. Short of
disk space, `pathwarden collect --no-cache` keeps the read in memory. Objects
over 128 MiB are skipped and listed on **Run details**; raise the limit with
`[ingest] max_object_mib` for a trusted collection.

## Logs and crash reports

Pathwarden keeps a log of each app session and each job: a collection (with
the collector's output and exit code), an analysis, `run`, a retest, a
history sync, each finding action. Every line has the time, the job and
what started it (`app`, `command line` or `schedule`), and is written as it
happens, so the last lines survive a crash:

```
09:42:11.204 [collect, app] Collection SCALE.LOCAL started in the app
09:42:12.018 [collect, app] Running C:\Tools\SharpHound.exe
09:46:58.902 [collect, app] SharpHound exited with exit code: 3
09:46:58.903 [collect, app] result: failed: The collection failed: ...
```

They are in `%LOCALAPPDATA%\Pathwarden\logs` on Windows,
`$XDG_STATE_HOME/pathwarden/logs` (or `~/.local/state/pathwarden/logs`) on
Linux, private to your account like the workspace: `job-<time>-<kind>.log`,
`session-<time>.log` and `crash-<time>.txt`. They are kept 30 days, at most
200 MB in all; the oldest go first. Passwords, tokens, cookies and the
values of secret environment variables are never written (the same
redaction as the collector's output). Logs do name domains, hosts and
accounts: share them as you would a report.

When Pathwarden stops on an internal error, it writes a crash report: the
message, where it happened, the backtrace, the version, the job that was
running and that job's last 200 lines. The next time the app starts, an
amber dot shows by **Settings**, and **Settings › Logs** says when it
stopped and during what, with **Open crash report** and **Dismiss**.

```powershell
pathwarden logs              # the latest 6 jobs (--all for every log)
pathwarden logs --last       # the latest job's last lines
pathwarden logs --crash      # the latest crash report
pathwarden logs --dismiss    # dismiss it, as Dismiss in the app
pathwarden logs --last --open
```

`--open` opens the logs folder, or with `--last` or `--crash` that file, in
the default app. In the app, **Open logs folder** is on **Settings › Logs**,
and a failed collection or action has **Open log**.

**Download diagnostics** on a run's performance page, and `pathwarden
diagnose --bundle`, add the logs of that run's own jobs (its collection,
analysis, retests and the actions on its findings), and the app's session
logs and crash reports of the last 7 days: at most 20 MB, every name
replaced like the rest of the zip.

A hard crash (the process killed, out of memory, a crash in a system
library) may leave no crash report. On Windows, look in **Event Viewer ›
Windows Logs › Application** for an error from `pathwarden.exe` at that
time; on Linux, `journalctl --since "1 hour ago"` (or the unit's journal for
a systemd timer). The job's log still has its lines up to the crash.

## When something goes wrong

| What you see | What to do |
|---|---|
| "another pathwarden run is using ..." | Wait for the other run. A stale lock is taken over at once on the same computer, after 6 hours from another. |
| "This run is recorded here, but the change couldn't be pushed" | Run `pathwarden history storage sign-in` as the task's account. The run goes with the next push. |
| "git fetch failed: ..." | Check the network and the sign-in, then run again. |
| "... less than half of the last run's" | Check the collection. If the directory really shrank, run with `--accept-shrink`. |
| "This history is encrypted ..." | Run `pathwarden history storage passphrase set`, or set `PATHWARDEN_HISTORY_PASSPHRASE`. |
| "branch main of ... is not Pathwarden state" | Use a repository or branch for the history only. |
| `run.ps1` refuses to start | Run `setup-folder.ps1` again. |
| Task Scheduler shows a failed run | Read the newest log in `C:\Pathwarden\reports\logs`, or `pathwarden logs --last` as the task's account. |
| A collection or action failed in the app | Click **Open log** beside the error, or run `pathwarden logs --last`. |
| Pathwarden stopped unexpectedly | `pathwarden logs --crash`; with no report, see [Logs and crash reports](#logs-and-crash-reports). |

Add `-v` to see each step.
