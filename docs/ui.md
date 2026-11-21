# The app

The app runs the same analysis as the command line, in a window. Step-by-step
tasks are in [tasks.md](tasks.md).

![Trying the demo in the app](images/ui-demo.gif)

## Open the app

```powershell
pathwarden ui
```

The app opens in its own window, or in a browser with a link that works
once; press Enter in the Pathwarden window for a new one. In a browser,
click **Stop Pathwarden** at the bottom of the rail when you are done. The
app listens on 127.0.0.1 only. `pathwarden ui --help` lists the options.

### The desktop window

The Windows full release opens a native window with no network port. It
needs the WebView2 Runtime, which Windows 11 includes. On Windows Server,
install it (`winget install Microsoft.EdgeWebView2Runtime`) and run
`pathwarden ui --window`. Closing the window stops Pathwarden. On Linux there
is no window: `pathwarden ui` opens the app in your browser.

## Environments

An environment is a set of domains with its own settings, run history and
schedule. Accepted risks, zones and rules never cross between environments.

- Switch with the menu at the top of the rail.
- The first collection of a new domain makes an environment for it. A run
  goes to the environment that lists its domains. When two match, the page
  asks "Where should this run go?".
- **Change domains or remove** › **Remove environment…** moves its files to
  `environments/removed/`. Remove its schedule on the server yourself.

## Analyze or collect

Click **Analyze** in the rail, then **A previous collection** (drop a
SharpHound or RustHound-CE `.zip`) or **Collect from Active Directory**. One
job runs at a time; Home links back to it.

### The Collect wizard

1. **Where**: the domain and its domain controller. **Trusted domains**
   adds other domains to the run.
2. **Who**: **Use my Windows account** or **Enter a user and password**
   (needs **Encrypt with LDAPS (port 636)**, unless **Advanced** ›
   **Allow plain LDAP** is ticked:
   [plain LDAP when LDAPS fails](collect.md#plain-ldap-when-ldaps-fails)).
   Leave **Kerberos only** and **Require SMB signing** on.
3. **How deep**: **Quick** reads the directory only. **Full** adds sessions
   and local groups from every computer.
4. **Check**: a connection check. A failure says which screen to fix.
5. **Collect**: **Start collecting**. **Keep the raw collection** keeps the
   files; **Analyze other data with it** adds AzureHound or OpenGraph files.

What each choice reads: [collect.md](collect.md#what-each-method-collects).

## Read the results

| Page | What it is for |
|---|---|
| **Home** | The latest run's status, what changed and the next step. |
| **Runs** | Every run, newest first. |
| A run's page | The report: **Overview**, **Remediation path**, **Findings**, **Collection** and **Run details**. |
| **Explore** | The run's graph. |
| **Progress** | How the environment changes from run to run. |

Above the report, **Download** gives the report, a findings file or an
evidence pack.

### Exploring a run

**Explore** opens on the run's first finding. **Previous** and **Next** page
through the findings. Search for an object and double-click it to expand
it. **Path to Tier Zero** draws its shortest path, **Who can reach it**
lists everything with a path to it, and **Query** runs **Prepared** queries
or your own **Cypher**. **Suggested zones** proposes Tier 1 and Tier 2
objects for a zone.

## Configure

**Settings** (Tier Zero additions, **Rules**, **Accepted risks**), **Zones**
and **Mappings** ([opengraph.md](opengraph.md)) edit the environment's
`pathwarden.toml` (its folder is on **Environments**). Changes apply from
the next analysis. A page says something at its top only when there is
something to do: the file can't be loaded, the shared settings can't be
read, or a setting has two values.

**Settings › Logs** keeps this computer's logs and crash reports: **Open
logs folder** opens it. After Pathwarden stopped unexpectedly, the card
says when and during what, with **Open crash report** and **Dismiss**, and
the amber dot shows by **Settings** in the sidebar and on the card's link
(the same dot as for settings that differ). **Dismiss** clears both, on
this computer. A failed collection, and a failed action's Activity entry,
have **Open log**, which opens the job's log in your text editor. See
[Logs and crash reports](running.md#logs-and-crash-reports).

In a git history that keeps **Full runs and settings**, these settings are
shared; **History storage** says where the history is and whether it is
encrypted. When this computer and another both changed shared settings
since this computer last synced, they are merged entry by entry: a Tier
Zero object, an accepted risk, a Tier Zero settings folder, a zone, a
management plane, a mapping pack, or a single rule setting. Changes to
different entries are kept on both sides without asking; a line under the
page's title says what came ("Merged from the shared settings: APP01$
added to Tier Zero."), and each entry that came is marked **shared** with
who shared it and when, until a later sync brings others.

Only a real clash asks: the same entry changed to different values on both
computers, or changed on one and removed on the other. The note names it
("Stale Tier Zero account has two values.", or "… and 2 more have two
values"; its ⓘ lists them all), and the choice is next to the setting:
**Use 60** takes the shared value, **Keep 30** keeps this computer's and
shares it (a **Read only** computer has only **Use**). Until you choose,
runs here use this computer's value for that entry only; everything else
is merged. The section's tag says how many settings have two values, and an
amber dot marks its link at the top of Settings and **Settings** in the
sidebar on every page. **Dismiss** on the note hides the dots and the merged
line on this computer until a new clash appears; the note stays as one
line. A section this version can't take apart entry by entry, or whose last
sync isn't known, shows both sides whole, with **Use shared** and
**Keep this computer's**. The CLI equivalent is `pathwarden config sync`
([running.md](running.md#shared-settings)).

## Act on a finding

### Actions on a finding

A finding's action bar has **Retest**, **Accept risk** (a **Reason** and an
optional **Review by** date), **Add a note**, **Open in Explore** and **Copy
ID**. After the review date an accepted risk counts as open again. A
downloaded report has no actions. Your own buttons, such as **Open a
ticket**, are finding actions: [Writing an action](actions.md).

### Finding actions

Finding actions you set up on **Plugins and actions** come after those
buttons, behind a thin line; past three, the rest are under **More
actions**. A button that makes a record once (such as a ticket) is hidden
while that record is open.

1. Click the action. The dialog shows what it asks for and one line of
   what **Leaves this computer**; **See exactly what's sent** shows the
   request the program gets, with your inputs.
2. Turn on **Test only** for a dry run: the program is asked to change
   nothing, and nothing is saved.
3. Click **Start**. The program's lines show as it writes them, with the
   time so far; **Cancel** stops it.
4. The result shows each record it made (`RITM10816190 · Open`) with
   **Open** and **Copy**; a failure has **Show details** with the
   program's output.

What it did is saved on the finding in the run history, for everyone who
shares it: a run that couldn't be shared yet says it is saved on this
computer and goes with the next sync. A cancelled run shows as cancelled.

The record's chip sits under the finding's title. In the finding, one box
holds its records with their follow-ups (such as **Check status**) and
the latest three entries of **Activity** (**Show all** for the rest).
Once a finding is fixed, its chip turns amber (`Fixed — RITM10816190
still Open`) and a follow-up meant for that (such as **Close request**)
comes first. The saved report leaves fixed findings out, so its Findings
tab lists those whose ticket is still open in a **Fixed, ticket still
open** card.

On **Findings**, **Records** (**Any**, **Has a record**, **No record**)
filters by records; on the Overview, the **Open findings** tile links
"N findings have records" to that filter. One action runs at a time, and
none during a collection or an analysis. `pathwarden action` does the
same from the command line.

### Retesting a finding

Make the change, then:

1. On the run page, click **Retest** on the finding's row.
2. Sign in as in the Collect wizard.
3. Click **Retest now**.

The row shows **Fixed ✓**, **Still open** or **Can't tell**. A retest
re-reads only the finding's objects and the computers on its path, so it
can't find a new path around them. The next collection checks everything.

## Automate

**Schedule** writes the files for a nightly run on a server; an
administrator copies them and runs the commands shown
([Schedule nightly runs](tasks.md#schedule-nightly-runs)). The page then
shows the last scheduled run and says when it is late.

**Plugins and actions** has two sections. The **Plugins** section sends results
to ServiceNow, Jira or a script on scheduled runs; Analyze in the app
doesn't run them. ServiceNow and Jira each have a form, with
**Safety limits** on how many tickets one run may open or close. Give the
name of an environment variable for each secret, never the secret.
**Finding actions** lists each action program, its actions with their
inputs, what they send and which findings they apply to, and **Test** (a
dry run on the first matching finding of the latest analysis). **Add a
finding action** and **Remove** are turned off with `--lock-destinations`
([Safety locks](#safety-locks)); the name, time limit and filters can
still change.

### History storage

**History storage** sets where the run history lives. The app and the
command line record into the same one.

| Choice | When to use it |
|---|---|
| **On this computer** | You work alone. |
| **Connect to a run history** | A teammate or a server already records one. |
| **Start a new run history** | You want to share runs through a folder or git. |

**What the history keeps** is **Numbers with names** (the default) or
**Full runs and settings**. **Encrypt the history with a passphrase** is
optional. **Sync now** syncs at once.

Moving the history (another repository, branch or folder), keeping full
runs in a history that isn't encrypted, and connecting to a run history
are turned off in an app started with `pathwarden ui --lock-destinations`.
Then use `pathwarden history storage set` or `pathwarden env create
--from-git`.

### Connect to a run history

This is turned off with `pathwarden ui --lock-destinations` (see above).

1. **Where it is**: the repository URL and branch, or a shared folder.
   Click **Check it**. Pathwarden downloads a copy to show what the history
   holds; a large one can take a few minutes. Never put a password in the URL.
2. **What it holds**: for an encrypted history, enter the passphrase.
3. **Open and sync**: name the environment, choose **Share runs from this
   computer** or **Read only**, and click **Connect and sync**.

With **Full runs and settings**, the first sync takes the history's shared
settings (rules, Tier Zero additions, accepted risks, zones, management
planes, mapping packs). Settings only this computer has are kept and
shared; on a **Read only** computer they stay, and a shared version that
arrives later is merged with them entry by entry. When the history's replace settings
this computer had, its `pathwarden.toml` is saved first, next to it, as
`pathwarden.toml.before-connect-<date>`, and so is each mapping pack it
replaces (`packs/<name>.toml.before-connect-<date>`). If a copy can't be
saved, nothing is replaced. Runs shows one line saying what was taken and
where the copies are. The CLI does the same (`pathwarden env create
--from-git`, `pathwarden config sync`); `pathwarden config sync
--keep-local` on a first sync keeps this computer's settings instead and
shares them.

## Safety locks

Some changes let a page choose a program for Pathwarden to run, or where
findings and runs go. The app makes them unless it was started with
`pathwarden ui --lock-destinations`. Then the page
says safety locks are on, with an (i) that links here:

- adding or changing a plugin's program;
- a plugin's destination: its instance, Jira `project`, ServiceNow
  `table`, `allow_insecure_http` and the environment variables it reads;
- turning the ticket close limit off (100%);
- **Connect to a run history**, and moving the run history;
- adding, changing or removing a finding action's program or settings.

The command line can make all of these (`pathwarden plugins`,
`pathwarden action`, `pathwarden history storage set`, `pathwarden env
create --from-git`), as can editing `pathwarden.toml`.

Lock them when people other than you may reach the app's page, or when
only `pathwarden.toml` should decide where findings go. Before 1.0.0-rc.3
the app was locked unless started with `--allow-destinations`; that flag
is still accepted and changes nothing.

## Where your data goes

Everything stays in the workspace, private to your account:
`%LOCALAPPDATA%\Pathwarden` on Windows, `~/.local/share/pathwarden` on
Linux. Uploads are deleted after the analysis. Passwords are never saved.
The app connects only to your domain controllers, the computers a Full
collection or retest reads, and a git history's repository.

## When something goes wrong

| Problem | Fix |
|---|---|
| The link has expired. | Press Enter in the Pathwarden window for a new one. |
| The Check step fails. | Read the reason and fix that screen. |
| A retest says **Can't tell**. | Retest as a local admin on the computers it names, or collect again. |
| "Not signed in to the repository". | On **History storage**, click **Sign in**. |
| "Couldn't sync with the repository". | Check the network, then click **Sync now**. |
| "This page is out of date: reload it." | Reload and make the change again. |
| A run went to the wrong environment. | Fix the domain lists on **Environments**. |
| A collection or action failed. | Click **Open log** beside it, or **Open logs folder** on **Settings › Logs**. |
