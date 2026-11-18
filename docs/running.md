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
settings, the first sync takes the history's shared settings and saves this
computer's `pathwarden.toml` first, as
`pathwarden.toml.before-connect-<date>` next to it.

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
| Task Scheduler shows a failed run | Read the newest log in `C:\Pathwarden\reports\logs`. |

Add `-v` to see each step.
