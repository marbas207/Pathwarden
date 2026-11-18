# Threat model

What Pathwarden protects, from whom, and where it stops. Each area lists
what is defended, with the code and tests that hold it, then what is not
defended. Known gaps close the page.

Paths are relative to the repository root. Tests are `file::function`;
`inline` means a `#[cfg(test)]` module in the named source file. Line
numbers are left out; search for the function. Windows first; Linux is
mentioned where it differs.

## Contents

1. [Scope and assumptions](#1-scope-and-assumptions)
2. [Assets](#2-assets)
3. [Attackers](#3-attackers)
4. [The history repository and other writers](#4-the-history-repository-and-other-writers)
5. [Shared settings, accepted risks and mapping packs](#5-shared-settings-accepted-risks-and-mapping-packs)
6. [Shared reports](#6-shared-reports)
7. [The passphrase and encryption](#7-the-passphrase-and-encryption)
8. [Git invocation](#8-git-invocation)
9. [Locks](#9-locks)
10. [The local web UI and its port](#10-the-local-web-ui-and-its-port)
11. [The desktop window](#11-the-desktop-window)
12. [Collector credentials, schedules and the gMSA](#12-collector-credentials-schedules-and-the-gmsa)
13. [Retest network contact](#13-retest-network-contact)
14. [Ingest of untrusted collector files](#14-ingest-of-untrusted-collector-files)
15. [Output plugins](#15-output-plugins)
16. [Supply chain](#16-supply-chain)
17. [The evidence signing key](#17-the-evidence-signing-key)
18. [Gaps](#18-gaps)

## 1. Scope and assumptions

Pathwarden collects Active Directory data (its built-in collector based on
RustHound-CE, SharpHound, or an external `rusthound-ce`), finds attack paths
to Tier Zero, and keeps a run history in a folder or a git repository. It
serves pages from a loopback web server or a WebView2 window, retests
findings by contacting hosts, runs output plugins, reads OpenGraph data, and
runs on a schedule under a gMSA.

Assumptions:

- **The account that runs Pathwarden is trusted, and so is anything running
  as it.** Such a program can already read the workspace, the stored
  passphrase, the browser profiles and the console (docs/ui.md, "Security
  model").
- **Local administrators are trusted.** They can read any user's DPAPI
  secrets and run programs as a gMSA.
- **The domain is the one being assessed.** Its objects are not trusted:
  anyone who can create an object chooses its name.
- **The history repository's host enforces access**: who can read and push,
  protected branches, signed commits.
- **The local `pathwarden.toml` is trusted.** Whoever writes it chooses which
  programs Pathwarden runs. Settings that arrive through the history are not
  (section 5).

Out of scope: denial of service by someone who can delete the history or the
workspace, attacks on Windows itself, and the security of the Jira or
ServiceNow instances.

## 2. Assets

| Asset | Where | Why it matters |
|---|---|---|
| Collector output | `uploads/`, `collections/`, `--output` folders | A map of the directory for an attacker: accounts, groups, rights, trusts. |
| Reports and run files | `runs/<id>/` in the workspace and in a full-run history | Name every path to Tier Zero and how to walk it. |
| The run history | State folder or git repository | Findings, accepted risks and who accepted them, Tier Zero, run times; the keys of the accounts with a path to Tier Zero (`exposed/<run>.json`, pseudonymous, section 4). |
| Collector credentials | Typed in the UI, `PATHWARDEN_COLLECT_PASSWORD`, the current account's Kerberos tickets, the gMSA | Read the whole directory; with Full collection, sign in to every computer. |
| The history passphrase | Credential Manager, a DPAPI-NG file, `PATHWARDEN_HISTORY_PASSPHRASE` | Opens every encrypted run. |
| The evidence signing key | `evidence-key/evidence.key` in the workspace, a `keygen` folder, `PATHWARDEN_EVIDENCE_KEY` | Signs evidence packs in the organization's name (section 17). |
| The UI session | Cookie in the app window's profile or the default browser | Reads every report, queries AD as the user, starts programs (section 10). |
| Plugin secrets | Environment variables named by `*_env` settings | Write access to the ticketing system. |
| Integrity of findings | Analysis, history, shared settings | A finding hidden or closed by mistake leaves a real path open. |

## 3. Attackers

| Name | Who | Typical goal |
|---|---|---|
| **Writer** | Someone who can push to the history repository or write to the history folder: a teammate, a compromised teammate account, a CI job. May or may not have the passphrase. | Hide findings, read encrypted runs, run code on readers' machines, mislead. |
| **Local user** | Another, unprivileged account on the same computer. | Read the workspace or the passphrase, use the UI session, swap files a scheduled task runs. |
| **Web page** | A page open in the user's browser. | Reach the loopback UI, start actions, read reports. |
| **Plugin endpoint** | A malicious or compromised Jira or ServiceNow server. | Exhaust or confuse the plugin, read secrets. |
| **Network** | An attacker on the network or in the domain who can register DNS names (ADIDNS) or spoof name resolution. | Capture or relay the credentials Pathwarden uses to contact hosts. |
| **Collector file** | Whoever produced a collector zip or OpenGraph file, or an AD object with a hostile name or attributes. | Crash or exhaust ingest, inject markup, forge or hide paths. |
| **Supply chain** | Someone who can change a dependency, the build machine or a release archive. | Ship code that runs as every user. |

## 4. The history repository and other writers

Attackers: Writer, Local user (for a folder history).

### Defended

| Defence | Code | Tests |
|---|---|---|
| Pathwarden only works in a working copy it cloned and marked (`pathwarden.workingcopy`), whose `origin` is the configured remote. | `store.rs` `verify_owned`, `clone_into_place` | `crates/pathwarden-core/tests/git_state.rs::only_a_working_copy_pathwarden_cloned_is_reset`, `crates/pathwarden-cli/tests/robustness.rs::git_backend_refuses_to_take_over_an_existing_repository` |
| A branch that is not Pathwarden state (no marker, other files), or that holds Pathwarden's own file names (`.pathwarden.lock`), is refused before checkout. | `store.rs` `check_state_branch` | `crates/pathwarden-core/tests/git_state.rs::only_a_state_branch_is_used`, `crates/pathwarden-cli/tests/git_state.rs::a_foreign_repository_is_refused` |
| Only known file names are read or written: `STATE_FILES`, `BUNDLE_FILES`; run IDs are at most 64 characters of `[A-Za-z0-9._-]`, no leading dot. | `store.rs` `check_rel`, `is_state_rel`, `is_run_id` | `store.rs` inline `forget_removes_one_point_and_refuses_paths`, `crates/pathwarden-ui/tests/server.rs::run_id_traversal_is_rejected` |
| Symlinks are never followed: git runs with `core.symlinks=false`, a committed link (`120000` entry) is refused, state folders and files that are links or junctions are refused, writes refuse paths that resolve outside the folder. | `store.rs` `run_git_env`, `sync`, `check_no_links`, `read_as`, `write_atomic` | `crates/pathwarden-cli/tests/robustness.rs::committed_symlinks_in_the_state_repo_are_refused`, `store.rs` inline `state_is_not_written_through_links`, `crates/pathwarden-core/tests/encryption.rs::a_link_swapped_in_for_an_encrypted_folder_is_refused` |
| A history point whose `run_id` differs from its file name is left out and named. | `history.rs` `load` | `crates/pathwarden-core/tests/encryption.rs::a_swapped_point_is_left_out_and_named` |
| A malformed history point is skipped and named. | `history.rs` `load` | `history.rs` inline `loads_sorted_and_skips_junk` |
| A history file, full run or `pathwarden.toml` of a newer format is never read as this version's or written over: skipped and named, or the operation is refused ([File formats and upgrades](formats.md)). | `store.rs` `load`, `last_run`; `history.rs` `load`; `config.rs` `check_format`; `settings_sync.rs` `repo_side`, `environment` | `crates/pathwarden-cli/tests/compat.rs` (`a_newer_*`, `newer_points_and_last_run_are_not_taken`, `newer_run_files_are_not_read`, `a_full_run_is_not_loaded_into_a_newer_folder`); `crates/pathwarden-cli/tests/settings_sync.rs::newer_shared_settings_are_never_replaced` |
| A run loaded from the history keeps its summary as `summary.v2.json`, so Pathwarden 0.1.7 and earlier (which look for `summary.json`) never list it or serve its report as their own. A run 0.1.9 loaded is moved to that name. | `crates/pathwarden-ui/src/workspace.rs` `summary_name`, `migrate_loaded` | `crates/pathwarden-cli/tests/compat.rs::a_full_run_from_0_1_9_loads_out_of_older_versions_sight` |
| A full run's `run.json` must name its own folder; each file's size and SHA-256 must match the manifest; damaged or newer-format runs are named, not loaded. | `crates/pathwarden-ui/src/shared_runs.rs` `mirror`, `checked_file`, `read_manifest` | `crates/pathwarden-ui/tests/shared_runs.rs::changed_damaged_and_newer_full_runs` |
| Size caps, checked before and while reading: a full-run file no larger than its `run.json` lists and the limit it recorded (`max_file_bytes`; 45 MB when none; 2 GB at most), `run.json` 1 MiB, gzip inflate 2 GiB, `settings/pathwarden.toml` 4 MiB, `environment.json` 64 KiB, 32 mapping packs of at most 1 MiB, `findings.json` 1 GiB, `last-run.json` 64 MiB, each `history/*.json` and `timings/*.json` 16 MiB (a point or timings over it are skipped and named). | `shared_runs.rs` `MAX_FILE_BYTES`, `Manifest::file_limit`, `checked_file`; `exposed.rs` `full_run_sizes`; `run_data.rs` `MAX_GZ_BYTES`; `settings_sync.rs` limits; `store.rs` `max_state_bytes`, `read_capped` | `crates/pathwarden-ui/tests/shared_runs.rs::a_file_over_the_limit_is_left_out_and_named`, `a_run_without_its_object_index_says_so`, `exposed.rs` inline `a_full_run_is_held_to_its_own_manifest`, `settings_sync.rs` inline `repository_files_have_limits`, `store.rs` inline `history_files_have_size_caps` |
| A `findings.json` that can't be read (cut short, not JSON, over its cap) is reported; the run is compared with no earlier findings and recorded, which replaces it, so every finding of that run counts as new. A newer version or a refused binding still stops the run. | `store.rs` `load_for_run`, `DamagedFindings`; `record.rs` `save_and_publish`; CLI `run`; UI `history_ui.rs` | `crates/pathwarden-core/tests/git_state.rs::a_malformed_pushed_findings_state_is_reported_not_fatal`, `store.rs` inline `history_files_have_size_caps` |
| A loaded run's dates are capped at the current time. | `shared_runs.rs` `load_one` | `crates/pathwarden-ui/tests/shared_runs.rs::a_loaded_run_from_the_future_and_the_schedule_picker` |
| Runs recorded on this computer are never replaced by a mirrored one. | `shared_runs.rs` `mirror` | `crates/pathwarden-ui/tests/shared_runs.rs::a_reader_opens_the_full_runs_another_computer_recorded` |
| Two runs with the same ID never overwrite each other; a push race records both runs, never merges state files. | `store.rs` `publish_with` | `crates/pathwarden-core/tests/git_state.rs::two_runs_with_one_id_never_overwrite_each_other`, `a_run_another_run_pushed_before_is_recorded_on_top_of_it`, `a_run_gives_up_after_four_rejected_pushes` |
| A half-done rebase or merge is aborted; the working copy is reset to the remote; `git clean` touches only the state folders. | `store.rs` `sync` | `crates/pathwarden-cli/tests/robustness.rs::fresh_clone_is_marked_and_a_stuck_rebase_is_recovered`, `crates/pathwarden-cli/tests/git_state.rs::a_dirty_working_copy_is_reset` |
| Encryption-specific attacks by a writer without the passphrase (planted plain files, stripped marker, replaced key). | Section 7 | Section 7 |

### Not defended

- **A plain history has no integrity and no rollback protection.** Anyone
  who can push can rewrite or restore any file; the remote is the source of
  truth, and a rollback or deleted run is followed
  (`crates/pathwarden-core/tests/git_state.rs::a_remote_rolled_back_stays_rolled_back`).
  Only points and full-run manifests are bound to their run ID; an encrypted
  history binds every file (section 7). docs/running.md names protected
  branches and signed commits as the control.
- **Full-run manifests and `recorded_by` / `recorded_on` are the writer's.**
  The hashes catch damage, not forgery.
- **A malformed `findings.json` pushed by a writer resets the findings
  state**: the next run counts all its findings as new (first-seen dates
  restart, plugins see them opened).
- **A state branch may hold other files**, checked out but never read or
  committed.
- **Run labels** travel in `summary.json` and points and are shown escaped
  (`pages::esc`), on the terminal without control or bidi characters
  (`history.rs` inline `hostile_labels_are_printed_as_plain_text`), and in a
  report's file name as letters, digits, dots and dashes only
  (`workspace.rs` inline `hostile_labels_are_refused_or_made_harmless`).
- **The account keys are pseudonymous, not anonymous.** `exposed/<run>.json`
  (per account with a path to Tier Zero) and the findings state (per object
  a finding lists) hold an unsalted FNV-1a 64-bit hash of the SID or GUID.
  Anyone who reads a plain history and lists the domain's SIDs (any domain
  user can) can tell which accounts had a path in each run; encrypt when
  that matters. The keys file's count must match the run's point
  (`exposed.rs` `ExposedRecord::tier_zero_for`; inline
  `mismatches_are_not_used`).
- **A writer can plant an earlier run's graph.** The previous full run is read
  (`exposed.rs` `read_full_run`) when that run kept no keys, and whenever an
  account no longer reaches Tier Zero (for its path). Then a planted
  `objects.json.gz` sets the names of "No longer in the directory" rows and a
  planted `graph.bin.gz` the paths shown; only the no-keys case is checked
  against the point's count, and a writer of both can make them agree.
  Bounds: files over run.json's size or its recorded limit (45 MB when none)
  are refused; inflation at most 32 times the size (8 MiB at least, 1 KiB per
  object the point allows, 1 GiB at most); a graph over 16 times the users,
  computers and Tier Zero objects the point counts (plus 100,000), or twice
  the objects its `summary.json` collected (plus 100,000) if more, or under
  its population, is refused before its objects are made; over 256 edges per
  object (plus 1,048,576) before its edges are (`explore.rs` `edge_budget`);
  the object index is read no further than the graph's objects. Refused
  files aren't read again by the same process while unchanged (unlike
  files waiting for a passphrase). Explore and `pathwarden reach` use the
  same bounds (`explore_ui.rs` `load`). A lying summary or point widens them
  up to the inflate caps (1 GiB, 2 GiB for Explore), with memory several
  times that. Tests: `exposed.rs` inline
  `an_earlier_run_without_keys_is_read_from_its_full_run`,
  `an_oversized_full_run_is_not_read`,
  `a_zip_bomb_in_a_full_run_is_refused_early_and_once`,
  `a_full_run_that_disagrees_with_its_point_is_refused`,
  `an_edge_bomb_with_a_real_sized_point_is_refused`,
  `a_large_opengraph_full_run_is_not_refused`; `explore.rs` inline
  `an_edge_bomb_is_refused_before_it_is_made`;
  `crates/pathwarden-ui/tests/explore.rs::explore_refuses_a_planted_graph`;
  `crates/pathwarden-core/tests/exposed.rs::an_encrypted_history_gives_its_full_run_too`.

**Residual risk:** a writer can make readers see a history that is wrong but
well formed. Use a private repository with protected branches, and treat an
unexpected change as an incident: the commit names its author.

## 5. Shared settings, accepted risks and mapping packs

With `[state] keep = "full"`, the shared sections of `pathwarden.toml`
travel through the history and are applied on every reader when it pulls.
Attackers: Writer.

### Defended

| Defence | Code | Tests |
|---|---|---|
| Only `SHARED_SECTIONS` travel: `tier_zero`, `rules`, `suppress`, `zone`, `management_planes`, `mapping`. `[state]`, `[[output]]`, `[ingest]`, `[opengraph]` and `[collect]` are never written and, if the repository holds them, ignored and named, so a writer cannot choose a program, a remote, a plugin target or pack trust for a reader. | `config_edit.rs` `SHARED_SECTIONS`, `NEVER_SHARED`, `shared_text`; `settings_sync.rs` `repo_side`, `apply_repo` | `config_edit.rs` inline `shared_sections_travel_and_the_rest_stays`, `crates/pathwarden-core/tests/settings_sync.rs::sections_never_shared_are_ignored_on_pull` (a pushed `[[output]]` command, `[ingest]`, `[opengraph]` limits and trust, `[collect]`), `a_newer_writers_settings_are_read`, `accepted_risks_travel_with_who_accepted_them` |
| The merged settings are validated as a whole before they are written; an accepted risk with unknown keys is not applied; one bad entry stops nothing else. | `settings_sync.rs` `apply_repo`, `config_edit::check`; `config.rs` `Suppression::unknown_keys` | `crates/pathwarden-core/tests/settings_sync.rs::one_bad_entry_stops_nothing_else` |
| Each section is settled on its own; a conflict is reported rather than overwritten. A computer's first sync of a section has nothing to compare against, so the history's settings replace its own; its `pathwarden.toml` and every mapping pack replaced are saved first (`.before-connect-<date>`, never overwriting a file, private to this account from creation; if a copy fails, or its permissions are refused, nothing is replaced, and on a file system with no permissions to set it keeps the folder's and the sync says so; a pack file that can't be read as text is never replaced) and the sync says so. A base file that is there but can't be read is not a first sync: a section that differs is shown as differing from the shared ones. A section a reader keeps only here is recorded as absent, so a shared version that arrives later is shown as differing too, never taken. | `settings_sync.rs` `compare`, `Base::read`, `save_before_connect`, `apply_repo` | `crates/pathwarden-core/tests/settings_sync.rs::each_section_is_settled_on_its_own`, `keep_local_never_undoes_the_repositorys_change`, `a_new_computer_takes_the_historys_settings`, `a_damaged_base_is_not_a_first_sync`, `a_readers_own_section_is_not_replaced_later`, `keep_local_on_a_first_sync_keeps_this_computers`; `settings_sync_tests.rs` `the_copy_never_overwrites_one`, `a_first_sync_saves_the_packs_it_replaces`, `a_copy_that_fails_replaces_nothing`, `a_file_system_without_permissions_keeps_the_copy`, `a_pack_file_that_isnt_text_is_never_replaced` |
| A history refused here (section 7) syncs no settings. | `settings_sync.rs` | `crates/pathwarden-core/tests/settings_sync.rs::a_refused_history_syncs_no_settings` |
| **Mapping-pack trust never travels.** A pack from the repository is untrusted on every machine, the pusher's included, until reviewed there; trust holds for the reviewed text's SHA-256 only. Its own `trusted = true` and `[opengraph] trust` count for nothing. | `config.rs` `read_user_packs`, `packs`; `pack_origin.rs`; `settings_sync.rs` `repo_pack_paths` | `crates/pathwarden-core/tests/settings_sync.rs::mapping_packs_travel_but_trust_does_not`, `pack_origin.rs` inline `trust_holds_for_the_reviewed_text_only`, `crates/pathwarden-cli/tests/settings_sync.rs::packs_from_the_repository_are_trusted_at_the_reviewed_text`, `crates/pathwarden-core/tests/opengraph.rs::an_untrusted_pack_changes_nothing` |
| Packs land only at `packs/<plain name>.toml`, never through a link, in the history folder or over a file that is not a pack, and only after the checks a loaded pack gets. | `settings_sync.rs` `pack_path`, `has_link`, `apply_repo` | `settings_sync.rs` inline `pack_paths_stay_in_the_packs_folder`, `crates/pathwarden-core/tests/settings_sync.rs::packs_never_land_in_the_history_folder` |
| **Using a Tier Zero settings folder never travels.** `settings_folders` is shared, but a machine reads only folders added or reviewed on it; any other waits for someone there to choose Use. The allow-list is next to `pathwarden.toml`, never committed; lost or broken, every folder waits again. A config read from text alone reads no folder. Only plain shares and local paths (no `\\?\` or `\\.\` device paths, WebDAV or `@SSL`/`@port` shares, URLs), so a writer can't point readers' sign-ins at a WebDAV host. | `folder_origin.rs`; `config.rs` `from_file`, `settings_folder_paths`; `config_edit.rs` `check_settings_folder` | `folder_origin.rs` inline `a_folder_from_the_repository_waits_for_a_review_here`, `crates/pathwarden-core/tests/tierzero_settings.rs::folders_from_the_repository_wait_for_a_review_here`, `only_plain_shares_and_local_paths_are_folders`, `analyze_reads_the_configured_folders_as_if_the_files_were_dropped_in` |
| **A settings folder's file can't clear a finding unless it proves who wrote it.** Otherwise it only confirms weaknesses, as a stale file can: no fill toward strong, no stronger value (weaker is allowed: a false positive at worst), and its OS build opens findings, never closes them. Only applied or verified files make a row current or count in the run's settings files. A file clears only when, read from the opened handle (Windows), its owner is the server it describes or a Tier Zero principal of its forest (a bare SYSTEM or Administrators owner only on a share on that server), and every SID its DACL lets write, append, change permissions or owner, or delete is the owner or such a principal; the file server's SYSTEM and Administrators count only when that file server is Tier Zero. An untrusted file also can't promote a server, choose an SCCM site, raise PW-038 or show an agent gone. A CA entry also needs the collection to put the CA on the file's host. Folder reads are bounded (names, links, size, count, bytes, 30 s per folder). | `dcsettings.rs` `Origin`, `authoritative`, `apply_all`, `apply_cas`; `ingest/mod.rs` `read_settings_folder`; `perms.rs` `file_security` | `dcsettings.rs` inline `an_unverified_folder_file_confirms_weaknesses_only` (a member server's share whose local admins can write), `crates/pathwarden-core/tests/tierzero_settings.rs::a_forged_folder_file_does_not_close_a_collected_weakness`, `folder_names_caps_and_timeouts` |
| The run's own `settings.toml` snapshot in a full run is shown, never applied. | `store.rs` `settings_snapshot` | `crates/pathwarden-ui/tests/shared_runs.rs::a_reader_opens_the_full_runs_another_computer_recorded` |

### Not defended

- **Any writer can add an accepted risk, disable a rule, change a severity,
  or edit Tier Zero, zones or management planes, and it applies on every
  reader at the next pull without review.** Accepted findings stop counting
  and the Jira and ServiceNow plugins close their tickets. The only brakes
  are the one-time "applied" notice, review dates, and the plugins'
  `max_resolve_percent` guard. No test pushes an accepted risk from another
  writer and checks that it hides a finding here.
- **A settings share is only as trusted as its file server.** Anyone with
  SeRestorePrivilege there (its local Administrators, Backup Operators) can
  set any owner and permissions, so a file can look written by the DC. Who
  can write the folder can always confirm weaknesses, never clear one.
- **Rename replay.** The folder's own permissions are not checked, and a
  move within it keeps a file's owner and DACL: someone with delete,
  delete-child or rename rights there can set the server's verified file
  aside, wait for a newer (weak) one, delete it and rename the old one back.
  It reads as verified and fresh for up to 90 days. Read times are not
  compared with the previous run's. docs/tier-zero-settings.md gives the
  folder ACL (only the servers' accounts, SYSTEM, Administrators and Tier
  Zero).
- **DFS and SMB identity.** The share host is taken as written. A DFS
  namespace path may lead to another server, and a spoofed file server can
  return any owner: use the file server's full DNS name, a real share, and
  SMB signing on both sides.
- **Attribution is a record, not a proof.** `accepted_by`, `accepted_on`,
  `Changed-by` and the git author are written by the writer (docs/running.md
  says so).

**Residual risk:** sharing settings means trusting every writer with the
findings. Limit push access to the people who may accept risks.

## 6. Shared reports

A full run carries the writer's `report.html.gz`, opened in the app.
Attackers: Writer, Collector file (hostile object names in any report).

### Defended

| Defence | Code | Tests |
|---|---|---|
| A report is served in a CSP sandbox (opaque origin), so it cannot reach the app, its cookie or its API. | `crates/pathwarden-ui/src/security.rs` `REPORT_CSP`; `server.rs` `report` | `crates/pathwarden-ui/tests/shared_runs.rs::a_loaded_run_is_shown_not_trusted` |
| A loaded report may run only a script whose hash is a known Pathwarden report script; otherwise `script-src 'none'`. A run counts as local only when every check passes (fails closed). | `retest_ui.rs` `report_csp_for`, `embed_report`, `known_report_script`; `shared_runs.rs` `trusted_run_dir` | `retest_ui.rs` inline `only_report_scripts_pathwarden_wrote_are_trusted`, `the_report_script_change_keeps_earlier_reports_retestable`; `crates/pathwarden-ui/tests/shared_runs.rs::a_loaded_run_is_shown_not_trusted` (hostile hero, meta refresh, form, `<img onerror>`, `<script>`, edited script) |
| The report talks to the app only by `postMessage`, checked against the frame, and can only open the Retest, Accept risk, Add a note or Explore dialog for one of the run's findings. The Retest dialog is not pre-filled with the writer's domain controller. | `assets/retest.js`, `assets/run.js`, `assets/report-retest.js` | `crates/pathwarden-ui/tests/shared_runs.rs::a_loaded_run_is_shown_not_trusted` |
| App pages never embed the repository's HTML; a loaded run's overview is built from its data and escaped. | `server.rs` `home`; `home_overview.rs` | `crates/pathwarden-ui/tests/shared_runs.rs::home_shows_a_loaded_run_s_overview_from_its_data` |
| Terminal output escapes control characters in names from the history. | `crates/pathwarden-cli` `ui::safe` | `crates/pathwarden-cli/tests/full_runs.rs::history_storage_pull_loads_full_runs`, `crates/pathwarden-cli/tests/robustness.rs::hostile_names_are_escaped_on_the_terminal` |
| A loaded run's report saved with Download carries its own policy in a `<meta>` before anything else (no script, frame, form or fetch), since a file on disk has no response headers. The Retest data the app adds sits right before its script, which reads only that element, so a meta in the report can't stand in for it. | `server.rs` `with_download_policy`, `DOWNLOAD_POLICY`; `retest_ui.rs` `embed_report`; `report-retest.js` | `server.rs` inline `a_downloaded_loaded_report_carries_its_policy_first`; `crates/pathwarden-ui/tests/retest.rs` |
| A loaded run never picks where this computer signs in: Collect's domain, its ticked trusted domains and a run's "Collect them" come from this computer's own runs only. | `collect/mod.rs` `prefill`, `trusted_for`, `collect_again_href` | `collect/mod.rs` inline `the_page_starts_from_a_link_or_the_last_run` |
| Loading a run replaces only a folder that holds a loaded run, never one with this computer's own run. | `shared_runs.rs` `load_one`, `loaded_run_dir` | `shared_runs.rs` inline `only_a_loaded_run_folder_is_replaced` |
| What a loaded run's report opens stays sandboxed: no `allow-popups-to-escape-sandbox`, in the frame's `sandbox` and in the report's CSP, embedded or not. This computer's own reports keep it, so their documentation links open normally. | `security.rs` `LOADED_REPORT_SANDBOX`, `loaded_report_csp`; `retest_ui.rs` `embed_report`, `report_csp_for` | `crates/pathwarden-ui/tests/shared_runs.rs` (`sandbox allow-scripts allow-popups`) |
| The schedule's report (`reports/latest.html` beside the history folder, `/history/report`) is served as a loaded run's: only a known report script runs, and what it opens stays sandboxed. | `history_ui.rs` `scheduled_report_page`; `retest_ui.rs` `report_csp_for` | `crates/pathwarden-ui/tests/automate.rs::scheduled_runs_show_on_runs_and_progress_with_their_report` |
| Names, rule IDs (PingCastle's come from its report), edge and object kinds, and trust details are escaped in the report; the findings search text is escaped once. | `crates/pathwarden-core/src/report.rs` `esc`, `object_chip`, `edge_chip`, `way_filtering`, `search_text` | `crates/pathwarden-core/tests/report.rs` |

### Not defended

- **Inline CSS and markup render inside the sandbox.** A hostile report can
  show false numbers or instructions. The line above the frame says whose
  report it is.
- **Links in a loaded run's report still open** (`allow-popups`), in a
  sandboxed window, so a phishing link works if clicked. In the desktop
  window, links to other sites open in the default browser, outside any
  sandbox; a new window for an app page with a query string is not opened
  (section 11).
- Not verified: whether report CSS can overlay the app's controls next to
  the frame, misleading a reader into clicking.

## 7. The passphrase and encryption

Assets: confidentiality of the history; each encrypted file's place and
version; the passphrase. Attackers: Writer without the passphrase, Writer
with it, Local user, anyone who can read the repository.

### How it works

`crates/pathwarden-core/src/crypt.rs` (module doc). A random age X25519 key
in `.pathwarden-key.age` is wrapped with the passphrase by age's scrypt at
work factor 2^18 (`WORK_FACTOR`); each file is encrypted to it as
`<name>.age`. The public key is never stored, so a writer without the
passphrase can't make Pathwarden encrypt to a key of theirs. Each file
starts, inside the encryption, with a versioned binding line (path, run,
sequence number; `crates/pathwarden-core/src/binding.rs` module doc); the
marker's format is 2 once every file has one. For users: docs/running.md,
"Encrypting the history with a passphrase".

### What is encrypted and what is not

| Encrypted | Visible to anyone who can read the repository |
|---|---|
| `findings.json`, `last-run.json`, `history/<run>.json`, `timings/<run>.json`, `exposed/<run>.json` | File names and layout: each run's ID, which is the time it started; the number of runs; which full-run files each run has |
| `settings/pathwarden.toml` (Tier Zero, rules, accepted risks with reasons and who accepted them), `settings/environment.json`, `settings/last-change.json` | File sizes (no padding) |
| Every full-run file under `runs/<run>/`, the manifest included | Commit times (author and committer dates are not neutralised) |
| | Commit messages, reduced to `pathwarden run <id>`, `pathwarden settings` and a few fixed texts (`store.rs` `neutral_message`) |
| | Commit author and committer, set to `Pathwarden <pathwarden@invalid>` (`store.rs` `NEUTRAL_AUTHOR`) |
| | `.pathwarden-encryption` (format, scrypt work factor), `.pathwarden-key.age` (open to offline guessing), the `findings.json` stub, `.pathwarden-state` |
| | Every commit made before encryption was turned on |

Never encrypted: the local workspace (reports and run files analysed here,
the local `pathwarden.toml` with its accepted risks, uploads, kept
collections).

Tests: `crates/pathwarden-core/tests/encryption.rs::a_folder_history_is_encrypted_and_decrypted_in_place`,
`a_git_history_through_on_change_and_off` (scans every git object for
plaintext: a few known strings, so a strong hint, not a proof),
`two_machines_race_on_an_encrypted_repository`,
`a_plain_run_racing_the_switch_never_lands_plain`;
`crates/pathwarden-cli/tests/encryption.rs::full_runs_and_settings_with_encrypt_shares_nothing_plain`;
`crates/pathwarden-ui/tests/shared_runs.rs::an_encrypted_history_keeps_every_full_run_file_encrypted`;
`store.rs` inline `encrypted_histories_get_neutral_commit_messages`;
`crates/pathwarden-core/tests/settings_sync.rs::settings_travel_encrypted`.

### Defended against a writer without the passphrase

| Attack | Response | Code | Tests |
|---|---|---|---|
| Plain files planted in an encrypted history | Never read, named, removed by the next commit | `store.rs` `planted_files`, `Store::pull` | `crates/pathwarden-core/tests/encryption.rs::a_planted_plain_file_is_named_and_removed` |
| Marker removed, history turned plain by a force push, a deleted branch, a merge, an interrupted pull | Refused, with the commit and its author, until the user accepts the decrypt on this computer | `store.rs` `mode`, `check_expected`, `record_location_pin` | `encryption.rs::a_removed_marker_is_refused_not_written_plain`, `a_fully_stripped_history_is_refused_by_the_pin`, `a_fresh_clone_refuses_a_stripped_history_until_accepted`, `a_fresh_clone_refuses_a_marker_dropped_by_a_merge`, `the_encrypted_setting_refuses_a_plain_history`, `a_force_push_after_an_interrupted_pull_is_refused`, `a_deleted_branch_is_refused_not_started_plain`, `a_damaged_git_folder_fails_closed`, `a_plain_history_with_a_passphrase_here_is_refused`, `an_empty_marker_records_nothing`, `a_new_remote_at_the_same_folder_is_another_history` |
| Key file replaced with one the passphrase here does not open | Named, with the commit | `store.rs` `key` | `encryption.rs::a_replaced_key_is_named` |
| Key file asking for a huge scrypt cost | Refused above 2^19, before any of the work | `crypt.rs` `MAX_WORK_FACTOR`, `open_key` | `crypt.rs` inline `a_key_file_asking_too_much_work_is_refused` |
| Key file rewrapped with little scrypt work (cheap offline guessing for every reader), by someone with the passphrase or a modified client | Refused below 2^18 (`WORK_FACTOR`, all Pathwarden has written), before any of the work | `crypt.rs` `scrypt_work_factor`, `open_key` | `crypt.rs` inline `a_key_file_asking_too_little_work_is_refused` |
| Another history's key file copied in (history A moved onto history B's key, which this process opened or this account keeps B's passphrase for) | Not opened with B's key: a key opened in this process is reused only for a history whose own passphrase is the one that opened it (`opened_in`, `key_for`). A history pinned to another key is offered no other history's passphrase (`known_passphrase`), so the key change is named as a replaced key | `crypt.rs` `key_for`, `known_passphrase`; `store.rs` `pinned_key` | `crypt.rs` inline `a_key_opened_for_one_history_never_opens_another` |
| A newer marker format or unknown cipher | Refused | `crypt.rs` `marker` | `encryption.rs::the_marker_says_how_and_a_newer_one_is_refused` |
| One file moved or copied into another's place (a point or full-run file over another run's, `last-run.json` over `findings.json`) | Refused: each file's binding names its path and run. A point is left out and named. | `binding.rs`; `store.rs` `decode_state`; `history.rs` `load` | `encryption.rs::a_swapped_point_is_left_out_and_named`, `a_file_moved_into_another_place_is_refused`; `binding.rs` inline `a_binding_wraps_and_parses_back` |
| An older copy of a file put back (rollback) | Refused where this computer read a newer sequence at that path. Sequences are kept per history folder and key in `history-pins/sequences`, outside the repository; in git only once the remote holds the file as read (`store.rs` `on_remote`), so another computer winning a push race is no rollback. After a deliberate restore, the user accepts the history as it is on this computer (app button with a confirm dialog, or `history storage accept`): only while reading meets such a refusal (`find_refusal`, or the refusals this process met), in the app only for that page's environment; only that history's records are reset, and never for a file without a binding at format 2 | `binding.rs` `advance`, `last_seen`, `BindingError::acceptable`, `note_refused`; `store.rs` `decode_state`, `next_seq`, `remember_remote_tree`, `accept_history`; UI `history_ui.rs` `accept_api` (POST: session and Origin, as every POST) | `encryption.rs::an_older_copy_put_back_is_refused`, `accepting_a_history_resets_its_records_only`, `writes_that_never_reach_the_remote_are_no_rollback`, `off_on_and_a_new_passphrase_start_the_sequences_again`; `binding.rs` inline `a_record_keeps_the_highest_and_reads_back`; CLI `encryption.rs::accept_takes_a_restored_history_as_it_is`; UI `accept_history.rs::an_older_copy_is_accepted_from_the_pages` |
| A file without a binding (from before 0.2) put back, or the marker set back to format 1 | Refused once the marker says format 2. The marker set back is refused for reads and writes alike (a write would bind the old copies) where this computer saw format 2: read under this key, or the remote's marker parsed at a pull or push (a per-folder mark in `history-pins/sequences`, under any key). A format-1 history is read unbound and bound on its first write; a file that can't be written leaves the marker at 1 for the next write to finish, and the write goes on, with a note in the run's warnings or the sync's notes | `store.rs` `decode_state`, `check_marker_format`, `upgrade_binding`, `remember_remote_tree`; `binding.rs` `format2_mark_for`; `crypt.rs` `FORMAT`, `UNBOUND_FORMAT` | `encryption.rs::a_history_encrypted_before_the_binding_is_read_then_bound`, `a_marker_set_back_in_git_is_refused_whatever_its_line_endings`, `an_upgrade_that_fails_partway_goes_on_and_tries_again`, `a_partial_upgrade_is_a_note_on_the_run`, `accepting_a_history_resets_its_records_only`, `two_computers_upgrading_at_once_bind_once` |
| Ciphertext from another history | Fails to decrypt | age | `crypt.rs` inline `a_key_opens_with_its_passphrase_only` |

### Key storage

| Source (lookup order) | Who else can read it | Code | Tests |
|---|---|---|---|
| A passphrase typed in this process | This process only; cached until the last UI session ends or the process exits | `crypt.rs` `passphrase_for`, `forget_all_in_process` | `crates/pathwarden-ui/tests/encryption.rs::the_passphrase_from_the_pages` |
| `PATHWARDEN_HISTORY_PASSPHRASE` | Anything that can read the parent's environment. Pathwarden removes it from its own environment at start, so no child inherits it, and a plugin cannot name it. The same holds for `PATHWARDEN_EVIDENCE_KEY` and `PATHWARDEN_COLLECT_PASSWORD` (`SECRET_ENV`). | `keystore.rs` `SECRET_ENV`, `take_env`, `secret_env`, `scrub_env`, `is_secret_env` | `keystore.rs` inline `children_never_get_the_passphrase`, `crates/pathwarden-cli/tests/encryption.rs::git_children_never_see_the_passphrase`, `the_environment_variable_encrypts_and_opens_the_history` |
| Windows Credential Manager, generic credential `Pathwarden history <full path>`, local persistence | Any program running as the user; an administrator through the user's DPAPI keys | `keystore.rs` `win::cred_write`, `target` | `keystore.rs` inline `win::tests::credential_manager_round_trip` |
| DPAPI-NG file `<folder>.passphrase.<SID>.dpapi` beside the history folder (`SID=` for a gMSA, `LOCAL=user` as a fallback) | The account named; any local administrator of a computer allowed to retrieve the gMSA's password. Anyone can protect a passphrase to an account, so the file is read only when its owner and everyone who may change it are this account, Administrators or SYSTEM; otherwise it is refused, with who else can. One written for another account is owned by Administrators, which needs an elevated prompt. | `keystore.rs` `protected_file`, `write_protected_file`, `store_for_account`, `check_protected_file`; `perms.rs` `untrusted_holders`, `make_file_admin_owned_for` | `keystore.rs` inline `win::tests::dpapi_ng_round_trip` (`LOCAL=user` only), `win::tests::the_protected_file_is_private_to_its_account` (its own access list: this account, Administrators and SYSTEM, read only for the account it is for; another's owned by Administrators; one others may change is refused; an unknown `--for-account` is named); `perms.rs` inline `untrusted_holders_are_named` |
| Linux: Secret Service through `secret-tool` (over stdin), systemd credential | The user's session; root | `keystore.rs` `linux` | none |

There is no `--passphrase` flag: a passphrase comes from a hidden prompt,
stdin's first line or `--from-env` (`crates/pathwarden-cli/src/passphrase.rs`).
Input buffers and decrypted key text are `Zeroizing`; UI request bodies are
zeroed after parsing (`crates/pathwarden-ui/src/secret_json.rs`, inline
`body_is_zeroed_and_errors_do_not_quote_it`). The pages never echo a
passphrase (`crates/pathwarden-ui/tests/encryption.rs::the_passphrase_from_the_pages`).

### Passphrase reuse across histories

A new history is tried with the passphrases this account keeps for others
(`crypt.rs` `known_passphrase`, `keystore.rs` `stored_passphrases`), each
only on the key file it was recorded with; one stored before 0.2 (no key
digest) never is, and the history asks once: "Passphrases saved on
this computer before Pathwarden 0.2 are no longer tried on other histories.
Enter this history's passphrase once." (`connect.rs` `OLD_PASSPHRASES`). A
history opened this way says "This history opens with the passphrase kept on
this computer for another history"
(`crates/pathwarden-core/src/connect.rs` `ANOTHER_PASSPHRASE`;
`crates/pathwarden-ui/src/encryption_ui.rs`). Tests:
`crates/pathwarden-cli/tests/connect.rs::a_passphrase_kept_here_connects_a_new_environment`,
`crates/pathwarden-ui/tests/connect_remembered.rs::a_passphrase_kept_here_opens_and_connects`.
The docs and `history storage set --encrypt` say "Give each history its own
passphrase.".

### Rotation and removal

`passphrase change` makes a new key and re-encrypts the tip in one commit
(`store.rs` `change_passphrase`); **older commits stay readable with the old
passphrase**. Turning encryption off writes the tip plain and removes the
passphrase here (`store.rs` `decrypt`). Neither purges git history; the docs
say to start a new repository. Tests:
`encryption.rs::a_git_history_through_on_change_and_off`,
`a_reader_accepts_a_decrypt_made_elsewhere`,
`crates/pathwarden-cli/tests/encryption.rs::the_passphrase_is_stored_checked_changed_and_forgotten`.

### Wrong passphrase, guessing, strength

A wrong passphrase changes nothing and is reported with its source
(`encryption.rs::a_wrong_or_missing_passphrase_is_refused_and_changes_nothing`);
`passphrase set` refuses one that doesn't open the history. Offline guessing
costs about 0.7 seconds per guess per CPU core (scrypt 2^18). The only
strength rule is 12 characters or more (`crypt.rs` `check_passphrase`; inline
`short_passphrases_are_refused`,
`encryption.rs::short_passphrases_are_refused_before_anything_changes`). The
UI's unlock and check endpoints need a session but have no rate limit.

### Not defended

- **The binding trusts on first use, and covers files, not the history.** A
  writer can delete runs or files. A new computer, a clone in another
  folder, or a file this computer never read (or read only from its own
  unpushed write) can be given an older copy. A record that can't be written
  (no account data, a full disk) silently remembers less. Moving the branch
  back to the last state under an earlier key the passphrase still opens
  (encryption off and on with the same passphrase) is not noticed.
- **Some git setups never advance the record.** A sequence is remembered
  only when a file's bytes on disk are the blob `origin/<branch>` holds
  (`store.rs` `on_remote`), never true for a reftable git folder or linked
  worktree, a remote not named `origin`, `.age` files in Git LFS, or a
  `.gitattributes` rule changing `.age` bytes on checkout (`eol`, `filter`).
  The path binding still applies, and the marker is compared by its parsed
  format (`store.rs` `remember_remote_tree`, `check_marker_format`;
  `encryption.rs::a_marker_set_back_in_git_is_refused_whatever_its_line_endings`).
- **Writers outside the history's lock** (`store.rs` `next_seq` reads then
  writes) could give two writes one sequence and, in a folder history, make
  a computer refuse the other's copy as older. Every Pathwarden writer holds
  the lock.
- **A plain history has no integrity** (section 4).
- **A new clone or folder history this computer hasn't pinned** opens with
  a passphrase kept here for another history when its key file is that
  history's (Passphrase reuse across histories, below): a writer who copied
  that key file in before this computer first opened the history isn't
  noticed.
- **Anyone with the passphrase can write.**
- **A computer that has never seen the history encrypted** (no record, no
  `[state] encrypted = true`) can't tell an unencrypted orphan rewrite from
  a never-encrypted history.
- **A replaced key that a passphrase this account has opens is followed**
  (`store.rs` `key`: "one it opens is pinned"), as a change made elsewhere
  must be. Someone who can push a key file and plant a passphrase source
  this account reads could make it encrypt to their key. The next pull says
  so once: "The history's key was replaced (commit … by …), and the
  passphrase this computer has opens the new one. If nobody changed the
  passphrase, revert … and check where this computer keeps the passphrase."
  (`store.rs` `follow_key`, `take_key_note`;
  `crates/pathwarden-core/tests/encryption.rs::a_followed_key_change_is_told_once`),
  a note, not a refusal, when someone runs it by hand. A scheduled run
  (`PATHWARDEN_SCHEDULED`) refuses a key it hasn't pinned instead (
  `store.rs` `follow_key_as`; inline `a_scheduled_run_refuses_a_replaced_key`):
  after a real passphrase change, someone opens the history by hand once.
  The DPAPI-NG file is read only when nobody but this account,
  Administrators and SYSTEM owns or may change it (Key storage above);
  whoever can change the folder above can still replace it with one they
  own, which is then refused, and `run.ps1`'s writer check (section 12)
  closes the folder for a scheduled task.
- The UI tip "Everything Pathwarden writes to the folder or repository is
  encrypted, except a small marker that says so" (`encryption_ui.rs`)
  understates what stays visible.

## 8. Git invocation

Assets: the user's machine and git credentials. Attackers: Writer, Local
user. Every git command goes through `store.rs` `run_git_env`, which starts
git through `spawn::quiet` (no console window, no shell).

### Defended

| Defence | Code | Tests |
|---|---|---|
| No git command runs outside the spawn helper. | `crates/pathwarden-core/src/spawn.rs` | `crates/pathwarden-core/tests/no_bare_spawns.rs::every_spawn_goes_through_the_quiet_helper` |
| Variables that point git at another repository are removed (`GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_CONFIG_PARAMETERS`, `GIT_OBJECT_DIRECTORY`, and the rest of `GIT_LOCAL_ENV`). | `store.rs` `GIT_LOCAL_ENV` | `crates/pathwarden-cli/tests/git_state.rs::git_variables_of_another_repository_are_ignored` (`GIT_DIR`, `GIT_WORK_TREE`) |
| The history passphrase variables never reach git, its hooks or credential helpers. | `keystore.rs` `scrub_env` | `crates/pathwarden-cli/tests/encryption.rs::git_children_never_see_the_passphrase` |
| No terminal prompt: `GIT_TERMINAL_PROMPT=0`, stdin from the null device, `GIT_SSH_COMMAND="ssh -o BatchMode=yes"` unless the machine sets its own SSH command. | `store.rs` `git_command` | `store.rs` inline `git_never_prompts` |
| Git Credential Manager may show its sign-in window when a person is there, never for background work (`GCM_INTERACTIVE=never` under `non_interactive` and `background`). | `store.rs` `non_interactive`, `background` | `store.rs` inline `git_never_prompts` |
| A `.gitattributes` anywhere on the branch may only set line endings and `binary` (`text`, `text=auto`, `eol=lf` or `crlf`, `binary`, `diff`, `merge`, `merge=` `text`, `binary` or `union`, any attribute unset or unspecified). Anything else (`filter`, a named `diff` or `merge` driver, `ident`, `working-tree-encoding`, a macro) stops the pull before checkout, so a writer can't make git run a filter or driver the computer's git settings name. | `store.rs` `check_state_branch`, `unsafe_attribute` | `crates/pathwarden-core/tests/git_state.rs::a_gitattributes_that_runs_programs_is_refused`, `store.rs` inline `only_line_ending_attributes_are_allowed` |
| `core.symlinks=false` and `core.autocrlf=false` on every command and in the clone's config. | `store.rs` `run_git_env`, `clone_into_place` | `crates/pathwarden-cli/tests/robustness.rs::committed_symlinks_in_the_state_repo_are_refused` |
| Pushes are never forced; fetch uses an explicit refspec; arguments that take a remote or path are preceded by `--`. The branch name is `[A-Za-z0-9._/-]` without `..`, `//`, `.lock` or a leading `-`; a remote may not start with `-`. | `store.rs` `publish_with`, `sync`; `config.rs` `validate_branch`, `validate_remote` | `store.rs` inline `validates_git_inputs`, `config_edit.rs` inline `invalid_values_are_rejected` |
| A password or token in the remote URL is refused by the UI, `connect` and every use of the history (`Store::new`, so a hand-edited `pathwarden.toml` too), and redacted from every message. | `config.rs` `remote_has_password`, `remote_has_token`, `redact_urls`; `config_edit.rs` `set_state`; `connect.rs` `probe_git`; `store.rs` `Store::new` | `store.rs` inline `a_remote_with_a_password_or_token_is_refused`, `config.rs` inline `every_url_is_redacted_and_passwords_are_noticed`, `store.rs` inline `redacts_credentials`, `connect.rs` inline `a_user_name_in_the_url_is_fine_a_token_is_not`, `crates/pathwarden-ui/tests/config_pages.rs::state_remote_credentials_are_hidden_and_kept` |
| A git that shows no progress for 10 minutes (45 seconds in the background) is stopped with every process it started, and the `.lock` files it left are removed. | `store.rs` `GIT_IDLE`, `stop_tree`, `remove_stale_locks` | `store.rs` inline `a_silent_git_is_stopped_with_everything_it_started`, `a_background_pull_gives_up_on_a_silent_git_early`, `locks_are_kept_while_a_process_git_started_lives`, `locks_a_stopped_git_left_are_removed` |
| A first clone is made in `.pathwarden-cloning` and moved into place only when complete. | `store.rs` `clone_into_place` | `crates/pathwarden-cli/tests/robustness.rs::fresh_clone_is_marked_and_a_stuck_rebase_is_recovered` |
| Git's output is capped (256 MiB; error output 1 MiB) and more is an error, not a cut answer; a small file read from the repository (the marker, a `.gitattributes`) is read only after `cat-file -s` says it is at most 1 MiB. | `store.rs` `MAX_GIT_OUTPUT`, `MAX_GIT_ERRORS`, `run_git_child`, `small_blob` | `store.rs` inline `large_blobs_are_not_read` |

### Not defended

- **Hooks are not disabled.** A clone never receives hooks from the remote,
  so a writer cannot plant one; a local user who can write the working
  copy's `.git` can. A test relies on a pre-push hook running
  (`crates/pathwarden-cli/tests/git_state.rs::a_run_that_loses_the_race_is_still_recorded`).
- **The user's global and system git configuration is trusted**:
  `url.insteadOf`, `credential.helper`, `core.hooksPath`, `core.askPass`,
  filters, `GIT_ASKPASS`, `GIT_CONFIG_GLOBAL`, protocol settings (this is
  how Git Credential Manager and SSH keys work), and so are
  `core.attributesFile` and `.git/info/attributes`: the attribute check
  reads the branch's `.gitattributes` files only.
- **Protocols** rely on git's defaults (`ext::` off; `file://` and local
  paths allowed). `safe.directory` and `core.fsmonitor` are not set.

## 9. Locks

`.pathwarden.lock`, inside the state folder, records host, process and a
random token, so two runs on one machine don't use the same folder
(`store.rs` `Store::lock`).

| Defence | Code | Tests |
|---|---|---|
| Created with `create_new`; removed on drop only if the token still matches. | `store.rs` `Store::lock`, `Lock` | `crates/pathwarden-cli/tests/git_state.rs::a_stale_lock_is_replaced_and_a_live_one_is_not` |
| Older than 6 hours counts as stale and is replaced atomically; a held lock is refreshed every 10 minutes. | `store.rs` `STALE_LOCK`, `LOCK_REFRESH`, `renew_lock` | `a_stale_lock_is_replaced_and_a_live_one_is_not`; `store.rs` inline `a_held_lock_is_kept_fresh` |
| Never committed, excluded in `.git/info/exclude`; a state branch holding a file of that name is refused, so a writer cannot plant one. | `store.rs` `exclude_own_files`, `check_state_branch` | `crates/pathwarden-core/tests/git_state.rs::the_lock_inside_the_state_folder_is_never_committed_or_reset` |
| A lock 0.1.6 kept beside the folder is respected while fresh and never deleted. | `store.rs` `check_old_lock` | `crates/pathwarden-core/tests/git_state.rs::a_lock_an_older_version_holds_beside_the_folder_is_respected` |

Not defended: anyone who can write the state folder can hold a lock forever,
delete it, or backdate it to force a takeover. The lock is advisory and per
machine; machines meet at the push (section 4).

## 10. The local web UI and its port

`pathwarden ui` without the desktop window serves the pages from a loopback
HTTP server (docs/ui.md, "Security model").

Assets: the UI session, which can read every report, query AD as the user
(Collect, Retest), change settings, start the collector program, and, with
`--allow-destinations`, choose programs for plugins. Attackers: Web page,
Local user.

### Defended

| Defence | Code | Tests |
|---|---|---|
| Binds `127.0.0.1` only; no option chooses another address. Port is any free one unless `--port`. On Windows the socket is exclusive (`SO_EXCLUSIVEADDRUSE`): no other socket binds `127.0.0.1` on that port beside it, even with `SO_REUSEADDR`. (Windows still lets a socket bind `0.0.0.0` on the port; connections to `127.0.0.1` go to the more specific socket, Pathwarden's.) | `crates/pathwarden-ui/src/lib.rs` `run`, `bind_addr`, `listen` | `lib.rs` inline `the_listener_is_loopback_only_and_exclusive` |
| Browsers try `[::1]` first for `localhost`: `[::1]` on the same port is held (bound, exclusive on Windows, never listening), so no local program can listen there. When another program holds it already, `Host: localhost:PORT` is refused. | `lib.rs` `reserve_v6`; `security.rs` `allowed_host` (`localhost_host`) | `lib.rs` inline `the_ipv6_loopback_port_is_held` |
| One-time link: 32 random bytes, works once, expires after 2 minutes, a wrong guess does not burn it, Enter in the console makes a new one. Constant-time comparison. | `security.rs` `Token`, `Sessions::exchange`, `new_link` | `security.rs` inline `token`; `crates/pathwarden-ui/tests/server.rs::the_link_works_once`, `the_link_expires` |
| The link is exchanged for a separate session secret in an `HttpOnly; SameSite=Strict` cookie named per port; the browser is redirected to a local path without the token. | `security.rs` `start`, `session_set_cookie`, `clean_target` | `server.rs::token_exchange_sets_a_separate_session_cookie`, `requests_without_the_cookie_are_rejected`, `the_exchange_redirects_only_to_local_paths`, `a_link_opened_from_the_launcher_file_moves_on_from_the_page` |
| The token is never on a command line: the browser opens a private launcher file that is deleted when used, expired, replaced or on stop. | `launch.rs` `write`, `app_args`, `open_file` | `launch.rs` inline `app_window_command_line_has_no_token`, `launcher_is_private_and_cleaned_up` |
| Sessions end after 8 hours idle, 24 hours in all, or on Stop; at most 32 sessions, the oldest ending first (its page says so). Background polling keeps no session alive. The last session ending forgets the passphrases held in memory. | `security.rs` `SessionPolicy`, `start`, `prune`, `end_all` | `server.rs::sessions_end_when_idle_and_after_the_limit`, `stop_signs_out_and_stops_the_server`; `security.rs` inline `asking_in_the_background_keeps_no_session_alive`, `the_oldest_session_makes_room` |
| **DNS rebinding**: a `Host` other than `127.0.0.1:PORT` or `localhost:PORT` gets 421, before anything else. | `security.rs` `allowed_host`, `guard` | `server.rs::wrong_host_is_rejected` |
| **CSRF**: changes must be POST, PUT or DELETE and say they come from this server's pages: an `Origin` naming it, or, without one, `Sec-Fetch-Site: same-origin`; anything else gets 403. The cookie is not sent cross-site; the Collect wizard takes JSON only. | `security.rs` `allowed_origin`, `own_page`, `guard` | `server.rs::changes_must_say_they_come_from_this_server`, `state_changes_from_other_origins_are_refused`, `crates/pathwarden-ui/tests/config_pages.rs::changes_from_other_origins_are_refused`, `crates/pathwarden-ui/tests/collect.rs::the_api_needs_the_session_and_same_origin` |
| No CORS headers; `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy: same-origin`; `X-Frame-Options: DENY`; `nosniff`; `no-store`; app CSP with `script-src 'self'`, no inline scripts, `frame-ancestors 'none'`. | `security.rs` `harden`, `APP_CSP` | `server.rs::requests_without_the_cookie_are_rejected` |
| Untrusted strings (AD names, history data) are escaped; scripts insert them as text; Explore draws labels on a canvas. | `pages.rs` `esc`, `attr`, `json_attr` | `pages.rs` inline `esc_shows_bidi_controls`, `json_attributes_survive_bidi_controls`; `crates/pathwarden-ui/tests/opengraph.rs::hostile_names_are_escaped`; `crates/pathwarden-ui/tests/explore.rs::names_that_look_like_markup_stay_text`; `crates/pathwarden-ui/tests/config_pages.rs::search_is_capped_and_names_are_escaped`; JS tests through `crates/pathwarden-ui/tests/page_scripts.rs::page_scripts_pass_their_node_tests` |
| Upload and field limits: 4 GiB a file, 16 GiB an analysis, 32 KiB path field, 1 KB short fields; `.zip` and `.json` names only, sanitised. Run folder names must match `YYYYMMDD-HHMMSS-xxxxxx`. | `server.rs` `Limits`, `receive`, `safe_file_name` | `server.rs::upload_limits_are_enforced`, `bad_input_fails_plainly`, `run_id_traversal_is_rejected`; `server.rs` inline `file_names`, `paths` |
| Network paths (`\\server\...`, `//server/...`, `\\?\...`) and paths on mapped network drives are refused before any file access in the analysis's path field, the SharpHound program field and plugin commands, so no field can make Windows sign in to another server. A shared history folder is meant to be on a share and isn't checked. | `plugins.rs` `is_network_path`, `is_network_drive`, `is_remote_path`; `server.rs` `receive`; `collect/mod.rs` | `security.rs` inline `network_paths`, `network_drives` |
| Plugin programs cannot be added or changed from the pages without `--allow-destinations`, nor can a plugin's `instance`, `project`, `table`, `allow_insecure_http` or `*_env` settings, nor can the resolve limit be turned off (`max_resolve_percent` 100) (section 15). Nor can the History storage page move the history (another backend, repository, branch or folder) or keep full runs in a history that isn't encrypted: future runs, full reports included, would go there. Nor can Connect look at, open or connect to a history (it would reach, and maybe sign in to, a place the session named). The flag was `--allow-plugin-commands` before 1.0.0-rc.1, kept as a hidden alias. | `plugin_form.rs` `check_command`, `turns_resolve_guard_off`; `settings.rs` `check_history_lock`, `history_lock_refusal`; `connect_ui.rs` `locked`; `encryption_ui.rs` `save_and_encrypt`; `config_edit.rs` `state_moves` | `crates/pathwarden-ui/tests/config_pages.rs::plugin_commands_need_the_flag`, `plugin_commands_refuse_network_paths`, `the_history_place_needs_the_flag`; `connect.rs::connect_needs_the_flag`; `plugin_form.rs` inline `destinations_need_the_flag`, `the_resolve_check_stays_on_without_the_flag` |
| The workspace is private to the account (protected access list on Windows, mode 700 on Linux). | `lib.rs` `secure_workspace`; `perms.rs` | `perms.rs` inline `private_dirs_are_private` |

### What each attacker can do

- **Web page.** It cannot read responses, frame the UI, send the cookie,
  pass the Host check through a rebound name, or guess the 256-bit link.
- **Local user.** It can connect to the port and gets 401 or 421. It cannot
  read the launcher file or the default workspace. With a fixed `--port` it
  can take the port first; Pathwarden then fails to start rather than talk
  to it. **Cookies are not separated by port**: a server another user runs
  on `127.0.0.1` receives the session cookie when the user's browser visits
  it, and can replay it to Pathwarden's port (docs/ui.md says so). The app
  window's own profile keeps the cookie out of the everyday browser;
  `--browser default` does not.
- **Same account.** Everything. Out of scope (section 1).

### Not defended

- **There is no CSRF token.** Changes rest on `Origin` or `Sec-Fetch-Site`
  and the `SameSite=Strict` cookie; a non-browser client that sends neither
  needs the session cookie anyway.
- **The Collect wizard runs any absolute local file as "SharpHound"** for a
  session holder, with no flag like `--allow-destinations`. docs/ui.md
  says a session can run a program "if you started with
  `--allow-destinations`", which understates it.
- **Confirmations for destructive actions** (delete a run, stop, settings)
  run in the browser only. Removing an environment checks the typed name on
  the server; trusting a pack needs `confirm: true`.
- No `Secure` flag, HSTS or Permissions-Policy (plain HTTP on loopback).
- An existing `--workspace` keeps its permissions on Windows; Pathwarden only
  warns.
- Escaping is by hand (`format!` with `esc`), not a template engine; the CSP
  is the backstop.

## 11. The desktop window

Builds with the `desktop` feature open a WebView2 window on Windows client
editions (docs/ui.md, "The desktop window").

**No listening port.** The window loads `pathwarden://` (shown as
`https://pathwarden.localhost`) through a wry custom protocol handler; each
request goes in process to the same router (`crates/pathwarden-desktop/src/bridge.rs`
`serve`, `to_router`; `window.rs` `open_window`). It is not a WebView2
virtual-host mapping and opens no socket. There is no link, token or cookie:
only that window can make a request.

### Defended

| Defence | Code | Tests |
|---|---|---|
| Nothing listens: the demo runs in the window and `netstat` shows no listener. | `bridge.rs`, `window.rs` | `crates/pathwarden-cli/tests/desktop_smoke.rs::window_runs_the_demo_without_a_port` (`#[ignore]`, run by hand) |
| Changes need the window's own origin when an `Origin` is sent; `Origin: null` (a sandboxed report) is refused. | `security.rs` `embedded_guard` | `crates/pathwarden-ui/tests/embedded.rs::changes_from_other_origins_are_refused`, `other_hosts_are_refused`, `pages_need_no_link_or_cookie`; `bridge.rs` inline `changes_need_the_window_origin`, `pages_and_assets_come_through` |
| Request bodies over 64 MiB are refused (they come through the webview in memory). Collector files are read where they are, not uploaded. | `bridge.rs` `MAX_BODY` | `bridge.rs` inline `large_bodies_are_refused` |
| The window never navigates away: other URLs open in the default browser, and only `http`, `https` and `mailto` are passed on. New-window requests are denied (an app page by its path alone gets an app window; one with a query string, which a loaded report could pick, isn't opened); downloads of app URLs go through a Save dialog under a plain file name, others are dropped. | `guard.rs` `navigation_allowed`, `new_window`, `download`, `web_link`, `save_path`, `save_name`; `window.rs` handlers, `open_elsewhere` | `bridge.rs` inline `internal_urls`; `guard.rs` inline `the_window_never_leaves_the_app`, `new_windows_and_downloads`, `only_web_and_mail_links_go_to_the_browser`, `saves_fetch_an_app_path_under_a_plain_name` |
| No script bridge object: JavaScript reaches Rust only through `fetch` to `/__desktop/pick-file`, `pick-folder` and `save`, which need POST and, when an `Origin` is sent, the window's; a save is only of an app path. Rust calls into the page only to pass dropped paths, as JSON. | `guard.rs` `desktop_request`, `save_target`; `window.rs` `Shared::window_request`; `desktop.js` | `guard.rs` inline `desktop_requests_need_a_post_from_the_window`, `a_save_is_only_of_an_app_path` |
| Developer tools are off in release builds; extensions and autofill are off; release builds remove `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` before WebView2 starts. The WebView2 profile is in the private workspace. | `guard.rs` `DEVTOOLS`; `window.rs` `run`, `open_window` | `guard.rs` inline `developer_tools_follow_the_build` (asserts off under `cargo test --release`) |
| The no-port smoke test is in the pre-release checklist (docs/dev/building.md, "Release builds"). | | `desktop_smoke.rs::window_runs_the_demo_without_a_port`, by hand |

### Not defended

- Anything running as the user can start WebView2 with remote debugging by
  other means (its per-user registry policy) and can read the workspace
  (docs/ui.md says so).
- A debug build honours `PATHWARDEN_DESKTOP_TEST_DEBUG_PORT`, which opens a
  remote debugging port. Release builds do not.
- A change with no `Origin` is accepted in the window, unlike on the
  loopback server: no other site can reach the custom protocol, and WebView2
  is not relied on to pass its fetches' `Origin` to the handler.
- The handlers' decisions are unit-tested (`guard.rs`); that wry calls them
  for every navigation, new window and download is covered only by the
  smoke test, run by hand. Whether wry's navigation handler sees sub-frame
  navigations was not checked; the CSP's `frame-src 'self'` limits what a
  frame can load.

## 12. Collector credentials, schedules and the gMSA

Assets: the collector account's password or tickets; the gMSA; collector
output; the scheduled task's folder. Attackers: Local user, Network,
Collector file (a hostile domain controller).

### How credentials are supplied

| Mode | Where it comes from | Code |
|---|---|---|
| Current account (Kerberos through SSPI) | The Windows logon, or the gMSA for a scheduled task | `crates/pathwarden-collect/src/lib.rs` `Auth::CurrentUser` |
| Password | `PATHWARDEN_COLLECT_PASSWORD`, a no-echo prompt, or the Collect wizard's form. There is no `--password` flag. | `crates/pathwarden-collect/src/cli.rs` `read_password`; `crates/pathwarden-ui/src/collect/mod.rs` `CollectForm` |
| Kerberos ticket cache | External `rusthound-ce` only | `Auth::KerberosCache` |

### Defended

| Defence | Code | Tests |
|---|---|---|
| No password flag; the password is a `Secret` (redacted `Debug`, no `Display`, `Serialize` or `Clone`, zeroed on drop); the environment variable is removed after it is read. | `cli.rs`; `crates/pathwarden-collect/src/secret.rs` | `cli.rs` inline `no_password_flag_exists`; `secret.rs` inline `debug_is_redacted`, `redacted_inside_derived_debug`, `deserializes_from_json`; `crates/pathwarden-cli/tests/retest.rs::retest_targeted_never_prompts` |
| The wizard's password is never stored, logged, echoed or written to a job status, page or workspace file. | `collect/mod.rs`; `secret_json.rs` | `crates/pathwarden-ui/tests/collect.rs::the_password_never_leaks`, `collect/mod.rs` inline `password_rules` |
| External collectors never get a password, because it could only go on their command line. | `crates/pathwarden-collect/src/external.rs` `sharphound_invocation`, `rusthound_invocation` | `external.rs` inline `sharphound_never_takes_a_password`, `rusthound_refuses_password_on_argv`, `no_argument_ever_holds_the_secret` |
| The collector password and the passphrase variables are removed from an external collector's environment; what its invocation sets (the ticket cache) still reaches it. | `external.rs` `run`, `SECRET_ENV`, `without_secrets` | `external.rs` inline `collectors_never_get_the_secrets` |
| Pathwarden binds to LDAP itself, because RustHound-CE's own bind logs the password at debug level. LAPS values and password-looking lines are filtered out of every log. | `crates/pathwarden-collect/src/builtin.rs`; `redact.rs` `log_line` | `redact.rs` inline `laps_values_never_pass`, `ordinary_lines_pass_unchanged`; `builtin.rs` inline `log_bridge_hides_laps_passwords`; `lib.rs` inline `reporter_logs_never_carry_laps_passwords`, `password_errors_never_contain_the_password` |
| A password is refused over plain LDAP unless `--allow-unencrypted-ldap` (CLI only). Kerberos binds ask for sealing on LDAP and send channel binding on LDAPS. TLS certificates are checked unless turned off, with a warning. | `builtin.rs` `plan`, `open`; `vendor/ldap3/src/ldap.rs` | `builtin.rs` inline `password_requires_ldaps_unless_allowed`, `skip_verify_warns`, `certificate_hint_names_both_the_app_and_the_flag`, `name_mismatch_lists_only_readable_names` |
| The domain controller's unauthenticated RootDSE name is used for the Kerberos SPN only if it is inside the domain and resolves to the connected address; a DC of another domain is refused. | `builtin.rs` `spn_source`, `dc_host`, `wrong_domain` | `builtin.rs` inline `spn_host_is_not_taken_blindly_from_the_root_dse`, `spn_host_must_resolve_to_the_connected_address`, `a_dc_of_another_domain_is_refused` |
| Domain and DC names typed for external tools cannot become options: no leading `-`, only `[A-Za-z0-9._:-]`. | `lib.rs` `is_host_like` | `lib.rs` inline `host_names` |
| GPP `cpassword` values are found but never decrypted, copied or written. | `builtin/gpp.rs` | `gpp.rs` inline `finds_the_account_never_the_value` |
| Output folders are created private; an existing folder others can read gets a warning and private files. | `crates/pathwarden-collect/src/output.rs` `prepare_dir`; `perms.rs` | `output.rs` inline `new_output_dirs_are_private_and_staged_files_keep_private`, `exposure_warning_names_who`; `perms.rs` inline `output_dirs_and_files_are_private`, `others_who_can_read_are_named` |
| The Collect wizard's SharpHound path must be an absolute local file; network paths are refused before they are looked at. | `collect/mod.rs`; `security::is_network_path` | `collect/mod.rs` inline `sharphound_path_is_checked` |
| External collectors run in a kill-on-close Job Object, so cancelling or stopping Pathwarden stops them and their children. | `spawn.rs` `contain` | `spawn.rs` inline `a_contained_child_dies_with_its_holder`, `external.rs` inline `cancel_kills_the_program` |
| Kerberos only (default): with a password, computers are signed in to with a TGT from the domain controller already verified over LDAPS, never with NTLM; RustHound-CE's modules get a ticket cache instead of the password. No TGT (clock, port 88, password, no AES keys): nothing is collected, with the reason. | `builtin.rs` `kerberos_hosts`; `builtin/krb.rs` `request_tgt` | `krb.rs` inline `kdc_errors_in_plain_words`, `a_fake_kdc_clock_error`, `an_unreachable_kdc_is_port_88` |
| Kerberos only with an account from another domain or forest: the TGT comes from the account's own domain, whose AS-REQ carries pre-authentication data (crackable offline), so it goes only to a domain controller checked as the collected domain's is, over LDAPS only (plain LDAP refuses first). That domain's DNS name comes from the collected domain's directory over its checked LDAPS connection: `crossRef` partitions, then `trustedDomain` objects whose `trustDirection` includes outbound (inbound-only is refused). A DNS domain typed in the user name (`user@dns`, `DNS\user`) must be the one found; a domain the directory doesn't name is refused, never guessed. The controller is the one `--server DOMAIN=HOST` names, else up to three found through DNS (`DsGetDcName`, the SRV record), by full name inside that domain. Each is checked over LDAPS before any AS-REQ (name resolved once, TLS to that address, certificate chaining to a trusted root and matching the name, RootDSE naming the domain), and both AS-REQs go to the address that passed, port 88; if none passes nothing is sent ("no domain controller of the account's domain ... passed the domain controller check, so the password wasn't sent to it"). The AS-REP is checked (nonce, AES256, the account and realm asked, `krbtgt/REALM` in its encrypted part). Computers' tickets follow referrals from that controller (each hop's nonce, encrypted service name and realm, AES256; no realm twice; at most 4 hops), and the KDC relay forwards the modules' requests to it. An RC4-only trust skips the computers ("set the trust to use AES"). LDAP-only runs ask for no ticket. `--insecure-skip-tls-verify` turns the certificate check off here too, with a warning that a fake domain controller would get the Kerberos sign-in; the RootDSE check stays. | `builtin/ownrealm.rs` `own_realm_ticket`, `verify_ldaps`, `pick_realm`, `realm_of`, `typed_dns_domain`; `builtin.rs` `needs_own_realm`, `own_realm_for`, `account_realm`, `trusted_domains`, `trust_entry`, `own_realm_home`, `kerberos_hosts`, `check_foreign`, `check_async`; `builtin/krb.rs` `decrypt`; `locate.rs` `candidates`, `in_domain`; `domains.rs` `names_account_domain`; `builtin/krbref.rs` `follow` | `builtin/ownrealm_tests.rs` `a_parent_domain_account_collects_a_child_domain`, `a_wrong_password_is_refused_by_the_pre_auth`, `a_trusted_forest_account_collects_this_forest`, `a_home_dc_that_fails_the_ldaps_check_gets_no_as_req`, `up_to_three_located_controllers_are_checked`, `a_named_controller_is_checked_and_used`, `the_real_ldaps_check_fails_closed`, `the_kdc_is_the_address_checked`, `a_referral_loop_or_a_bad_hop_is_refused`, `an_rc4_only_trust_is_skipped`, `kerberos_only_uses_the_accounts_own_domain`, `no_foreign_ticket_over_plain_ldap_or_a_refused_domain`, `the_check_gets_the_ticket_from_the_accounts_own_domain`, `the_accounts_domain_comes_from_the_directory`, `trust_entries_are_read_with_their_direction`; `krb.rs` inline `an_as_rep_is_checked_before_its_ticket_is_kept`; `locate.rs` inline `candidates_are_every_name_in_the_domain`; `domains.rs` inline `a_server_for_the_accounts_domain` |
| The ticket cache goes in a new folder private to the account (protected DACL, `0600` on Unix) inside `pathwarden-krb` in the temp folder, used only if that parent is owned by and private to the account (else the temp folder itself); overwritten and deleted when the collection ends. Stale caches of killed runs are deleted, never overwritten, only inside that parent. Never logged: with `RUST_LOG=debug` the `builtin::krb*` lines name realms, KDCs and errors, never keys, paths or tickets. | `krb.rs` `TicketCache`, `CcacheEnv` | `krb.rs` inline `the_cache_is_private_and_deleted`, `the_variable_is_restored`, `the_cache_is_a_v4_ccache` |

### Schedules and the gMSA

Pathwarden never creates a scheduled task; it writes the files
(`crates/pathwarden-ui/src/collect/schedule.rs`, `pathwarden schedule`). The
generated `run.ps1` refuses to run if anyone but Administrators or SYSTEM can
change its folder, collects into a new folder with a random name in the
gMSA's temp folder (refused if it exists), and deletes the collection
afterwards. The folder setup gives a protected access list:
Administrators and SYSTEM full control, the gMSA read and execute, and
modify only on `reports` and `pathwarden-state`. A gMSA reads the history
passphrase from a DPAPI-NG file protected to its SID (section 7).

What the guard (`Find-PathwardenWriters`, `Find-PathwardenParentWriters`)
counts as "can change":

- any allow entry with a write, delete, permission or owner right for
  someone else;
- a foreign owner, unless an OWNER RIGHTS entry applies to the item itself
  (an inherit-only one doesn't);
- a junction or symbolic link at the folder, inside it or at any folder
  above it: refused and never followed, so the permissions checked are the
  real folder's;
- a folder that isn't on a local fixed drive.

The setup runs before anything is copied in. A missing folder is created
with the protected access list already on it. An existing folder is not
adopted when the guard finds anything in it, `reports` and the state
folder's contents included, with the setup's own account accepted as
owner: someone else's file would otherwise become Administrators-owned
and pass. Nothing is changed before the folders above and the existing
contents pass. A folder that isn't empty and holds no Pathwarden is
refused, and the page and `pathwarden schedule` refuse a drive or a Windows
folder. The setup runs `pathwarden.exe history storage passphrase set`,
which reads the key file in the gMSA-writable state folder but runs no git.

Tests: `schedule.rs` inline `folder_setup_locks_the_folder_down`,
`acl_guard_checks_every_write_right`, `powershell_parses_the_scripts_and_the_guard_works`
(real PowerShell on a temp folder),
`the_guard_refuses_links_and_inherit_only_owner_rights` (junctions at,
inside and above the folder and in `reports`, OWNER RIGHTS inherit-only and
applying, an administrators-only folder, the setup refusing before it
creates anything, `run.ps1` refusing a junction), `windows_script_follows_the_run`,
`typed_values_are_checked`, `linux_files`, `the_command_line_is_checked`;
`crates/pathwarden-cli/tests/schedule.rs::windows_files_match_the_page`,
`linux_files_match_the_page`, `bad_arguments_exit_2_and_write_nothing`;
`crates/pathwarden-ui/tests/collect.rs::the_schedule_page_and_files`.

### Not defended

- **With `--allow-ntlm`, RustHound-CE's SMB modules get a plain copy of the
  password** in Full collections, which Pathwarden can't zero.
- **The LDAP sign-in is still NTLM** over LDAPS with a checked certificate.
  Without the check, a fake DC gets that sign-in and the Kerberos requests
  (an encrypted timestamp to crack); the app warns. Moving the bind to the
  ticket is a follow-up.
- **The account's own domain's controller is trusted on its
  certificate.** Anyone with a trusted certificate for a name in that domain
  (say a computer account enrolled through its CA) who can spoof the DNS
  locator gets the AS-REQ's timestamp. The RootDSE isn't authenticated. The
  collected domain's controller, reached by name, is exposed the same way;
  `--server DOMAIN=HOST` names it by hand (still checked).
- **A spoofed domain controller can forge the directory and close
  findings**. Without `--server` naming the DC by its full name,
  DNS picks it, and the Kerberos name it is checked against comes from its
  own unauthenticated RootDSE (`dnsHostName`). An attacker who can answer
  for the domain's DNS and has made a computer account in the domain (the
  machine account quota allows ten) can give that computer the SPN, pass
  the checks and return a clean directory: findings resolve as fixed. The
  run warns ("The domain controller wasn't named by its full name ...",
  `builtin.rs` `unnamed_dc_warning`; inline
  `a_dc_not_named_by_its_full_name_warns`). Mitigation: `--server` with the
  DC's full name. Checking that the server is a DC (its DRS SPN under the
  `dsServiceName` GUID) is a follow-up.
- **Accepted: the admins of a domain the collected domain trusts**
  control their controllers, certificates, DNS and trust NetBIOS name, so a
  `NAME\user` account whose NetBIOS name their trust claims sends its AS-REQ
  to them. Typed DNS domains must match, inbound-only trusts are refused, and
  the collected domain already accepts that forest's tickets.
- **The collected domain's port 88 is looked up again** after its LDAPS
  connection; for the account's own domain one resolved address serves all.
- **An account from a child domain of a trusted forest is refused**:
  `trustedDomain` names the forest root only and `msDS-TrustForestTrustInfo`
  isn't read. The refusal says so before anything is sent.
- **External `rusthound-ce` never validates LDAPS certificates**, and
  RustHound's ESC8 probe doesn't check the CA's HTTPS certificate. Documented;
  not fixable in Pathwarden.
- **The docs suggest `$env:PATHWARDEN_COLLECT_PASSWORD = '...'`**
  (docs/running.md and the lab notes), which PSReadLine saves and the shell
  keeps. No warning.
- **A collector program runs whatever it is.** `--sharphound` and
  `--rusthound` must be local paths with a folder; the UI pre-fills
  only a `SharpHound.exe` beside `pathwarden.exe`. A SharpHound not validly
  signed by "SpecterOps" gets a warning and still runs. No hash is pinned;
  `rusthound-ce` isn't checked.
- **The scheduled task's own permissions are Windows' defaults**, documented
  in docs/running.md. `run.ps1` and the folder setup check every folder
  above the task folder (`schedule.rs` `Find-PathwardenParentWriters`:
  delete, change permissions or owner, GENERIC_ALL or GENERIC_WRITE, a
  foreign owner; not creating folders beside it or inherit-only entries);
  `schedule.rs` inline `powershell_parses_the_scripts_and_the_guard_works`.
- **Files adopted by an earlier setup can't be told apart.** Before this
  check, the setup made everything in the folder Administrators-owned, so a
  file someone planted before an older setup passes now. Copy the release
  in again after upgrading.
- **No signature check on the programs the task runs.** `run.ps1` checks
  who can change `pathwarden.exe`, the plugins and `SharpHound.exe`, not
  their Authenticode signature.
- **Only the setup's own account is accepted as an owner.** A file another
  administrator copied in (on Windows client, files an administrator makes
  are owned by their account) is refused until that administrator runs the
  setup or the file is copied in again.
- **`icacls /T` follows junctions.** The setup checks `reports` and the
  state folder for links just before it resets them; a link the gMSA
  creates in between would be followed.
- On Linux the service hands the password from a root-only file
  (`LoadCredential=`), not an encrypted credential. `pathwarden run` warns
  when group or others can change its install folder or `plugins`,
  but not about another ordinary user's folder, and runs anyway.
- docs/collect.md says cancelling doesn't kill an external collector's
  children (the Job Object does); docs/running.md, "Lock the folder down",
  assumes a gMSA that is local admin everywhere instead of pointing to
  docs/collector-account.md.

**Residual risk:** the collector account reads the whole directory, and with
Full collection signs in to every computer. Use a dedicated account or gMSA
with the least-privilege setup in docs/collector-account.md, never a Domain
Admin.

## 13. Retest network contact

A targeted retest re-reads one finding's objects over LDAP and reads the
computers on its path over SMB and RPC (port 445). A quick retest
(`retest/mod.rs`) only compares findings and contacts nothing.

Assets: the retest account's credentials. Attackers: Network, Writer (a
shared run names the objects), Collector file.

### Defended

| Defence | Code | Tests |
|---|---|---|
| A retest takes only a finding fingerprint and sign-in details; what to read comes from the run's files, and object IDs become escaped binary LDAP filters. | `crates/pathwarden-core/src/retest/targeted.rs` | `targeted.rs` inline `ids_that_can_be_looked_up` |
| Hosts are chosen by SID or GUID from the finding's path; the name comes from a fresh LDAP read, not from the saved run. | `targeted.rs` `finding_hosts`; `crates/pathwarden-collect/src/builtin/targeted.rs` `with_hosts` | `targeted.rs` inline `a_path_through_a_session_is_checked_on_its_computer`, `tier_zero_sessions_are_read_on_their_hosts` |
| Only plain DNS names inside the collected domain are contacted: no IP address, no `localhost`, no UNC path, URL or look-alike suffix. | `builtin/hosts.rs` `contactable`, `valid_host`; `builtin/targeted.rs` `only_in_domain`; `winhosts.rs` `read_hosts` | `hosts.rs` inline `only_names_in_the_domain_are_contacted`; `targeted.rs` inline `stored_tests::only_computers_named_in_the_domain_are_contacted` (the filter both readers get); `winhosts.rs` inline `host_names_must_be_plain_dns_names` |
| At most 50 computers per retest; 10 at a time; 1.5 s port check, 18 s per host (60 s more for each of its services and tasks reads), 240 s overall; stale or inactive machine accounts are skipped. | `targeted.rs` `MAX_HOSTS`; `winhosts.rs` `AT_ONCE`, `PORT_TIMEOUT`, `HOST_TIMEOUT` | `targeted.rs` inline `at_most_fifty_computers_are_read`; `winhosts.rs` inline `every_computer_is_read_ten_at_a_time`, `a_hung_computer_is_abandoned_and_keeps_what_finished`, `nothing_is_waited_for_after_the_deadline`, `abandoned_threads_are_counted_until_they_end` |
| One retest at a time, never during a collection or analysis. Its files stay in the private workspace and are removed afterwards. | `crates/pathwarden-ui/src/retest_ui.rs` | `crates/pathwarden-collect/src/builtin/targeted.rs` inline `a_refused_connection_fails_cleanly`; `crates/pathwarden-ui/tests/retest.rs::a_retest_reads_the_computers_on_the_path` |
| Host names in error messages do not change how an error is classified. | `hosts.rs` `without_host`, `reason_on` | `hosts.rs` inline `host_names_dont_decide_the_kind`; `winhosts.rs` inline `host_names_dont_change_the_reason` |
| Kerberos only (default), Full collection and retest alike: a computer's `cifs/<name>` ticket is asked for before it is contacted. A name the domain has no Kerberos name (SPN) for, as one added to ADIDNS, is never connected to, not even on port 445, and counts as not collected. With a password nothing falls back to NTLM: the modules get a ticket cache, and Remote Registry (sessions, CA flags) is bound without NTLM over the Kerberos SMB session. | `builtin/hostauth.rs` `precheck`, `take`; `builtin/krb.rs` `service_ticket`; `builtin/krbreg.rs` | `hostauth.rs` inline `a_computer_without_a_kerberos_name_is_never_contacted`, `skipped_ones_go_out_and_back_in_their_places`; `krb.rs` inline `service_ticket_errors` |
| Trusted domains of a run: the TGT is the first domain's, verified over LDAPS, kept in the run's private ticket cache and deleted at the end. A trusted domain's `cifs/` tickets are asked of that controller and follow referrals to each realm's KDC by DNS name; every reply's nonce, encrypted service name and realm, and AES256 are checked, so a machine answering for a trusted realm can't hand over a ticket (no session key). RustHound-CE's modules go through the KDC relay below. A computer with no ticket through the trust (RC4-only, no Kerberos name) is skipped and counted, with the reason. No NTLM fallback. | `builtin.rs` `kerberos_hosts`, `HomeTicket`; `lib.rs` `RunSignIn`; `builtin/hostauth.rs` `precheck`; `builtin/krbref.rs` `service_ticket`, `follow` | `builtin.rs` inline `a_trusted_domain_uses_the_first_domains_ticket`; `hostauth.rs` inline `a_trusted_domains_computers_go_to_the_modules`; `krbref.rs` inline `a_referral_is_followed_to_the_computers_realm`, `no_aes_names_the_trust` |
| RustHound-CE's modules' own service tickets: the sessions, local groups and WebClient modules ask for `cifs/<host>` themselves, and their ticket code checks neither the nonce nor the service in the reply. With Kerberos only their KDC is a relay inside Pathwarden on 127.0.0.1 (a system-picked port per run; other addresses dropped). It takes only a TGS-REQ for `cifs/<computer>` in the run's realm, shaped as RustHound-CE sends it (one PA-TGS-REQ, its KDC options), presenting the run's own TGT with an authenticator that opens with its session key, names the run's account and is under 5 minutes old; anything else (an AS-REQ, extra tickets) is refused. 32 connections at once, 8 seconds each; requests without the run's ticket are refused quietly and counted in one log line at the end. It strips RC4 and forwards to the domain controller verified over LDAPS. A reply goes back only if its nonce is the request's, its ticket is from the run's realm, its encrypted part names the computer and the ticket's service, and it and the new session key are AES256; a KDC error goes back as is. The relay follows referrals, each hop checked the same way, and hands the ticket back in a TGS-REP under the key of the module's request. A refused reply is logged and the module gets a KDC error, so that computer isn't read. The relay stops when the modules finish. | `builtin/krbrelay.rs` `KdcRelay`, `check_presented`, `relay`, `reencrypt`; `builtin/krbref.rs` `check_rep`, `follow`; `builtin/hostauth.rs` `relay`; `builtin/sysvol.rs` `run_modules`; `builtin/targeted.rs` `smb_reads` | `builtin/krbrelay_tests.rs` (RustHound-CE's own ticket code against fake KDCs): `a_good_reply_passes_and_rc4_is_not_asked_for`, `bad_replies_are_refused`, `only_this_runs_ticket_requests_pass`, `malformed_requests_are_refused`, `the_relay_listens_on_loopback_only`, `idle_connections_and_a_silent_kdc_cost_one_deadline`, `one_referral_is_followed_and_encrypted_again`, `a_subkey_gets_its_reply_under_the_subkey`, `two_referrals_and_a_forged_hop`, `a_referral_home_and_too_many_hops_are_refused` |
| A realm whose KDC can't be reached (no connection or answer, not a KDC error): after 3 of its computers, the rest are skipped unasked, each counted with one reason ("Couldn't reach FABRIKAM.COM's domain controller for Kerberos."). | `builtin/hostauth.rs` `precheck`, `TRIPS`; `builtin/krb.rs` `NoTicket::Unreachable` | `hostauth.rs` inline `an_unreachable_realm_is_skipped_after_a_few` |
| Stored credentials in services: metadata only. In a Full collection over Kerberos, each reached computer's `Services` keys are listed over its Kerberos, signed Remote Registry session, and only `ObjectName`, `Start` and `Type` are queried (each service key KEY_QUERY_VALUE, the services key KEY_ENUMERATE_SUB_KEYS): never `ImagePath`, `Parameters` or below, LSA secrets, SAM, DPAPI or Credential Manager. Domain accounts only; at most 4,096 services and 60 s per computer; names cut to 256 characters; nothing with NTLM. The sidecar has no field for a secret; unknown fields are dropped on read. | `builtin/storedcreds.rs` `read_services`, `collect`; `crates/pathwarden-core/src/storedcreds.rs` `Sidecar::parse` | `storedcreds.rs` (collect) inline `only_domain_accounts_and_only_three_values`, `access_denied_is_not_collected`, `failures_and_limits_are_partial`, `hostile_answers_are_bounded`; `crates/pathwarden-core/tests/storedcreds.rs::a_hostile_file_leaks_nothing` |
| Stored credentials in scheduled tasks: metadata only. In a Full collection over Kerberos, each reached computer's registered tasks (`TaskCache\Tree`, Remote Registry, KEY_ENUMERATE_SUB_KEYS only) are listed first; then `C$` on the same signed, Kerberos-only SMB session, where only `Windows\System32\Tasks` is listed and only the files the list names are read, so a file planted in that user-writable folder (a fake Tier Zero principal, a parser bomb) is never parsed. A file is read only when it matches the SHA-256 its registration records (`TaskCache\Tasks\{Id}` value `Hash`, KEY_QUERY_VALUE, only `Id` and `Hash`), so a rewritten own task or a leftover Tree entry gives nothing; no SHA-256 is partial. Links are opened as themselves (FILE_OPEN_REPARSE_POINT), never followed. At most 8 folders deep, 20,000 entries, 5,000 files, 60 s per computer and 1 MiB per file (`read_file_max`, `list_directory_max` in the patched `vendor/smb2-client`). Strict decoding (UTF-16 by BOM, or UTF-8); refused before parsing on a DTD, nesting over 64, over 256 attributes on an element, or per-file limits where parser work grows faster than the file (1,024 attributes, 4 namespace declarations per element and 16 per file, 32 CDATA sections, 4,096 references, 64 KiB text). Parsed on `spawn_blocking` with DTDs refused and a 20,000-node limit; only `UserId`, `LogonType` and `Settings/Enabled` are looked at, never actions, arguments or description; errors name a line, never text. Only `Password` and `InteractiveTokenOrPassword` tasks of domain accounts are kept; nothing with NTLM; DPAPI and Credential Manager untouched. Own switch (`--no-task-reads`, `[collect] task_reads`, the app's "Read scheduled tasks"), since `C$` access is logged (5140, 5145). | `builtin/tasks.rs` `read_tasks`, `collect`; `crates/pathwarden-core/src/taskxml.rs` `stored_account`; `vendor/smb2-client/src/client.rs` `read_file_max`, `list_directory_max` | `tasks_tests.rs` `only_the_tasks_tree_and_only_stored_passwords`, `a_file_task_scheduler_never_registered_is_ignored`, `a_file_that_doesnt_match_its_registration_is_ignored`, `links_are_not_followed`, `a_parser_bomb_costs_nothing`, `the_tree_lists_the_registered_tasks`, `hostile_answers_are_bounded_and_partial`, `limits_are_partial`, `a_denied_tasks_folder_is_not_collected`; `taskxml.rs` inline `hostile_files_are_refused`, `quadratic_shapes_are_refused_fast`, `only_logon_types_that_store_a_password`; `client.rs` inline `a_capped_read_keeps_at_most_max`, `a_listing_that_never_ends_stops`; `crates/pathwarden-core/tests/storedcreds.rs::hostile_task_entries_leak_nothing` |
| Stored credentials in a targeted retest of PW-033: metadata only, from the computers that stored the finding's password (at most 50), each part with its switch (`[collect] service_reads`, `task_reads`; `--no-service-reads`, `--no-task-reads`). With a password: the Full collection's walks, on the retest's own signed Kerberos session; nothing with NTLM. As the Windows account: the same walks (`read_services`, `registered_tasks`, `read_tasks`, same values, rights, SHA-256 check, limits, refusals and `spawn_blocking`) through Windows' Remote Registry (`RegConnectRegistryW` on HKLM, values at most 64 KiB) and UNC reads of `\\HOST\C$\Windows\System32\Tasks` (folders opened with FILE_FLAG_BACKUP_SEMANTICS and FILE_FLAG_OPEN_REPARSE_POINT and refused if a link, files with FILE_FLAG_OPEN_REPARSE_POINT, at most 1 MiB), only after Windows got the computer's `cifs/` ticket (`HostApi::cifs_ticket`, on the computer's own thread), even with NTLM allowed for sessions. With a password, 16 computers at once, stopping 20 s before the retest's limit. A computer counts as read only when its services and tasks were both read in full, so a part denied or switched off is "can't tell"; an account stored under its old name (renamed since) is resolved against the run's names and keeps the finding open. Never `ImagePath`, `Parameters`, task actions, arguments, description or raw XML, `SECURITY`, `SAM`, DPAPI, Credential Manager or `\pipe\atsvc`. 60 s more per part per computer, within the retest's 240 s; anything not read in full is "can't tell", never "fixed". | `builtin/winhosts.rs` `stored`, `stored_record`; `builtin/winnet.rs` `WinRegistry`, `WinShare`; `builtin/targeted.rs` `windows_reads`, `stored_reads`, `stored_read`, `needs_netbios`; `crates/pathwarden-core/src/retest/targeted.rs` `retest_with`, `merged_with` | `winhosts_stored_tests.rs` `services_and_tasks_are_read_as_a_full_collection_reads_them`, `access_denied_is_not_collected`, `only_the_parts_asked_are_read`, `an_unreachable_computer_is_not_collected`, `hostile_answers_are_bounded`; `no_kerberos_ticket_reads_nothing`; `targeted.rs` inline `a_computers_stored_reads_tell_the_retest_why`, `without_netbios_names_a_domain_user_is_partial`; `crates/pathwarden-core/tests/storedcreds.rs::a_stored_password_is_retested_on_the_computers_that_store_it`, `a_stored_task_password_needs_the_tasks_read`, `a_part_not_read_is_a_gap`, `a_renamed_account_is_still_stored`; `pathwarden-cli` inline `retest_stored_reads_switches_are_the_dialogs`; live: checked in a lab |
| As the Windows account, SSPI's Kerberos package (not Negotiate) is asked for the `cifs/` ticket first; a computer without one is skipped, so Windows never signs in to it. | `builtin/winkrb.rs` `cifs_ticket`; `targeted.rs` `windows_reads`; `sysvol.rs` `current_user` | none (needs a domain; checked in a lab) |
| Required SMB signing (default): every SMB client asks the server to sign and checks the signature of every reply after sign-in (the patched `vendor/smb2-client`). With Kerberos a look-alike has no session key, so it can't sign and is refused; a computer whose replies aren't validly signed is skipped. The computer needn't require signing. | `vendor/smb2-client/src/client.rs` `call`, `header.rs` `verify`; `builtin.rs` `Signing`; `hostauth.rs` `unsigned` | `builtin/signing_tests.rs` (fake server: signed, unsigned, other key, tampered); `vendor/smb2-client/src/header.rs` inline `verify_accepts_signed_and_refuses_unsigned_or_tampered`; `hostauth.rs` inline `unsigned_replies_are_a_skip` |

### Not defended

- **`--allow-ntlm` (or "Kerberos only" off) brings the old exposure back:**
  with a password, a computer without a Kerberos name gets an NTLMv2
  response that an ADIDNS or name-resolution spoofer can crack or relay. The
  run records it, with a warning.
- **As the Windows account, a spoofed name of a *real* computer** that turns
  Kerberos down could still get NTLM from Windows' SMB client, which can't
  refuse NTLM per connection; likewise a retest's Remote Registry and `C$`
  reads, which sign in through Negotiate after the `cifs/`
  check. "Network security: Restrict NTLM: Outgoing NTLM traffic to remote
  servers" (Deny all, with exceptions) or SMB NTLM blocking (Windows 11 24H2,
  Server 2025) closes it. Reply signatures there are Windows' policy (required
  by default on Windows 11 24H2 and Server 2025).
- **A tasks folder swapped for a link between check and listing** (a race by
  the computer's own administrator) could be listed; the files read are
  still only those registered with a matching hash.
- **The KDC relay trusts whoever can read the run's ticket cache**: the same
  account, Administrators and SYSTEM. They gain nothing the cache doesn't
  already give: only `cifs/` tickets for the run's account pass.
- **Other local users can connect to the relay** but can't pass its checks;
  at most they slow it (32 connections, 8 seconds each).
- **A machine in the middle on port 88 can forge a KDC error** (KRB-ERROR
  isn't protected): that computer isn't read. No NTLM fallback.
- **The relay keeps no replay cache.** A replay within 5 minutes needs a
  loopback sniff, and its reply is under keys the replayer lacks.
- **A trusted realm's KDC is found by DNS name, not verified**. Its
  replies can't be forged without the referral's session key, but a machine
  answering on port 88 can refuse the request: the computers are skipped,
  with the reason. The LDAP sign-in to a trusted domain is NTLM over checked
  LDAPS, as the first domain's.
- **Collecting several domains reaches more of the network**: each trusted
  domain's controllers with the same account, and with Full and NTLM, their
  computers. The app's Check step does so too, before the confirmation; step
  1 says "Only collect from domains you are authorized to assess." once one
  is ticked, and the confirmation repeats it. `pathwarden collect` asks
  before contacting any domain. A trust that doesn't let the account in is
  never ticked. With Kerberos only and a password, no trusted domain is
  contacted when the first gave no ticket ("The first domain gave no
  Kerberos ticket."), and the check asks a ticket only of the account's own
  domain.
- **A failed domain's detail is kept in the run**, with user names (any
  `DOMAIN\user`, typed or reported) replaced by "the account" and no local
  paths; a shared run's summary drops paths again.
- **External collectors aren't covered.** SharpHound falls back to NTLM;
  external `rusthound-ce --kerberos` doesn't check reply signatures. The app
  notes it and the run records "not enforced".
- **The in-domain name filter applies to targeted retests only.** A Full
  collection contacts every computer by the name AD gives (with Kerberos
  only, names with a Kerberos name).
- **Reading services is admin activity on every computer**: a local admin
  account, Remote Registry over `IPC$` (a Kerberos network logon; with
  detailed share auditing a 5145 for `\winreg`), and EDR may flag it.
  Service account names are in the zip, as session names are.
- **A computer can lie about its services**: hide one (the finding resolves)
  or name an account it doesn't store (a false path). Its administrators,
  whom the finding is about, control both.
- No end-to-end test shows `with_hosts` dropping a refused name (needs
  LDAP); Kerberos and signing are tested against fake servers, and against a real domain
  only in a lab.

**Residual risk:** retest and Full collection still sign in to every computer
they read, now with Kerberos tickets that can't be relayed or cracked like an
NTLM response. Keep the account out of privileged groups and put it in
Protected Users (password mode works with it: AES keys, no NTLM). Where
Windows accounts read computers, restrict outgoing NTLM.

## 14. Ingest of untrusted collector files

Assets: the analysing machine's memory and disk; the correctness of
findings. Attackers: Collector file.

### Defended

| Defence | Code | Tests |
|---|---|---|
| Files are streamed one object at a time, never read whole. | `crates/pathwarden-core/src/ingest/stream.rs` | `stream.rs` inline `streams_each_object_and_tolerates_null_data`, `oversized_objects_arrive_as_stubs` |
| Size budgets: 4 GiB per file or zip entry, 128 MiB per object (twice that fails the file), 64 GiB per archive, 4096 entries per archive. | `ingest/mod.rs` `MAX_ENTRY_BYTES`, `IngestLimits`; `budget.rs` | `ingest/hardening_tests.rs` inline `oversized_objects_are_skipped_and_reported`, `an_object_far_over_budget_fails_the_file`, `zip_entry_count_is_capped`, `archive_size_is_counted_not_declared`, `unknown_properties_cost_nothing`; `budget.rs` inline `lists_stop_at_the_budget`, `keeps_known_properties_and_skips_the_rest` |
| Zip bombs: an entry over 64 MiB at more than 200:1 is refused; real decompressed bytes are counted as read. | `ingest/mod.rs` `MAX_RATIO`, `ingest_zip` | `hardening_tests.rs` inline `archive_size_is_counted_not_declared`; `crates/pathwarden-core/tests/opengraph.rs::an_opengraph_zip_bomb_is_refused` |
| Zip entries are never extracted to disk, so entry names cannot traverse paths or plant links. Only `.json` entries and known sidecars are read. | `ingest/mod.rs` `ingest_zip` | (by construction) |
| Folders are walked once without following links or junctions. | `ingest/mod.rs` `input_files` | `hardening_tests.rs` inline `folders_are_walked_once_without_following_links` (makes a real junction) |
| Object names are escaped wherever they are shown (sections 6 and 10). | `pages.rs`; `ui::safe` | as listed there |
| OpenGraph limits per source: 2M nodes, 10M edges, 512 kinds, 64 MiB of kept properties (estimated; AzureHound 16 times that, its kept fields being a fixed list of values of at most 1 KiB), 16 MiB per record, 1000 sources. Over a limit, a source is incomplete: it can open findings but never resolve them. | `ingest/opengraph.rs` `OgLimits` | `crates/pathwarden-core/tests/opengraph.rs::ten_thousand_kinds_are_capped`, `node_and_edge_caps_mark_the_source_incomplete`, `huge_properties_are_cut_or_refused`, `the_kept_properties_cap_keeps_the_name` |
| OpenGraph never makes anything Tier Zero; native AD edges in an OpenGraph file are dropped unless the pack lists them; secret-looking properties are dropped; untrusted or unmapped sources change no finding, exposure or plan. | `ingest/opengraph.rs`; `opengraph/pack.rs` | `opengraph.rs::opengraph_never_makes_anything_tier_zero`, `unmapped_and_untrusted_sources_change_no_finding_exposure_or_plan`, `an_untrusted_pack_changes_nothing`; `crates/pathwarden-core/tests/opengraph_packs.rs::untrusted_sql_and_sccm_change_nothing` |
| AzureHound data stays in its lane: it never marks an AD object Tier Zero, and an ID that clashes with an existing object is skipped. | `ingest/azurehound.rs`; `entra.rs` | `crates/pathwarden-core/tests/entra.rs::hostile_azurehound_input_stays_in_its_lane`, `an_opengraph_file_cannot_forge_entra_paths` |
| A coverage sidecar is bound to its payload by SHA-256. | `opengraph/coverage.rs` `binds` | `crates/pathwarden-core/tests/opengraph.rs::a_declared_coverage_binds_the_payload`, `a_mismatched_sidecar_is_reported` |
| Mapping packs are data, never code; an invalid pack is refused whole; at most 1 MiB; network and `file:` paths refused. | `opengraph/pack.rs`; `config.rs` `check_pack_path`, `read_pack` | `pack.rs` inline `invalid_packs_are_refused_whole`, `untrusted_packs_are_context_only`, `new_packs_are_untrusted_until_validated` |

### Not defended

- **Collector files have no authenticity.** A forged but well-formed
  collection that claims to be complete resolves every finding in its
  domains. The plugins' `max_resolve_percent` guard limits what that closes
  in a ticketing system.
- **Trusted packs act on whatever file matches them.** TaskHound ships
  trusted, so a TaskHound-shaped file can add traversable edges into Tier
  Zero objects (false findings, raised exposure). The coverage binding shows
  the two files belong together, not who made them.
- A local pack with `trusted = true` in its own text is trusted (packs from
  the history are not; section 5).
- The CLI has no total budget across many inputs and no cap on the number of
  AD objects.
- Nested zips are skipped without a message (never opened:
  `hardening_tests.rs::nested_zips_are_not_opened`). Deeply nested and
  truncated collector JSON fail the file or pass over the property, with no
  stack overflow (`deep_or_truncated_json_fails_plainly`); a pack on a
  network path is refused before it is opened (`config.rs` inline
  `packs_on_network_paths_are_refused`).

## 15. Output plugins

A plugin is a program Pathwarden runs after a run, with the run's event on
stdin (docs/plugins.md). A finding action is a program someone runs for
one finding, with that finding on stdin (docs/dev/formats.md, "Finding
actions"); it is held to the same rules.

Assets: the event (every finding, path, object name and SID, accepted risks
with who accepted them and why); plugin secrets; the account plugins run as.
Attackers: Writer, Local user, Plugin endpoint, Web page (through a session).

### Defended

| Defence | Code | Tests |
|---|---|---|
| All process creation goes through one helper, with no shell; argv is passed as given. | `crates/pathwarden-core/src/spawn.rs` | `crates/pathwarden-core/tests/no_bare_spawns.rs::every_spawn_goes_through_the_quiet_helper` |
| A built-in plugin (`pathwarden-output-<name>`) is found only beside `pathwarden.exe` or in `plugins\` beside it, never on PATH or in the current folder. | `plugins.rs` `plugin_dirs`, `locate` | `plugins.rs` inline `interpreters_and_absolute_paths_only` |
| A `command` must be an absolute local path or a known interpreter, never a network or device path or one on a mapped network drive (checked before the file system is touched, also for one written into `pathwarden.toml` by hand); interpreters are taken only from PATH folders under the Windows or Program Files folders as the system names them (`SHGetKnownFolderPath`, not the environment) that nobody but this account, Administrators, SYSTEM and TrustedInstaller may change. | `plugins.rs` `check_program`, `is_remote_path`, `resolve_interpreter`, `trusted_dir`, `system_folders` | `plugins.rs` inline `interpreters_and_absolute_paths_only`, `network_programs_are_refused`, `interpreters_come_from_system_folders_only`; `crates/pathwarden-cli/tests/robustness.rs::relative_plugin_commands_are_rejected` |
| A `command`'s arguments may not name a network path (`\\` or `//` anywhere outside a URL, a value after `=` or `-File:`) or a mapped network drive, nor a script by a relative path; checked when saved and again at each run. | `plugins.rs` `check_args`, `reaches_network`, `relative_path_in`, `command_for` | `plugins.rs` inline `arguments_are_checked` |
| A plugin starts in a private folder of its own (`%LOCALAPPDATA%\Pathwarden\plugin-work`), never the current folder, and refused when someone else may open it; on Windows it gets `NoDefaultCurrentDirectoryInExePath=1`, so a program it names isn't looked for in that folder first. | `plugins.rs` `work_dir`, `apply_env`, `run` | `plugins.rs` inline `plugins_start_in_their_own_folder`, `a_shared_work_folder_is_refused` |
| The pages cannot add or change a command without `--allow-destinations`, nor change where a plugin sends findings or its credentials or which secrets it reads: its `instance`, Jira `project`, ServiceNow `table`, `allow_insecure_http` and `*_env` settings, nor turn the resolve limit off. The UI and CLI editors refuse network paths, and check the Jira plugin's instance as the ServiceNow form does. | `plugin_form.rs` `check_command`, `destinations_after`, `check_instance`; `plugins_ui.rs` `save` | `crates/pathwarden-ui/tests/config_pages.rs::plugin_commands_need_the_flag`, `plugin_commands_refuse_network_paths`; `plugin_form.rs` inline `destinations_need_the_flag`, `the_jira_instance_is_checked`; `crates/pathwarden-cli/tests/zones_mappings_plugins.rs::plugins_are_added_tested_and_removed` |
| A plugin's environment is cleared, then given a short base list (no `SSL_CERT_FILE` or `SSL_CERT_DIR`, which would replace the trusted certificates) plus only the variables its `*_env` settings name. Pathwarden's own secrets (`SECRET_ENV`: the history's passphrases, the evidence signing key, the collection password) can never be named, and are out of its own environment from the start. | `plugins.rs` `apply_env`, `BASE_ENV`; `keystore.rs` `SECRET_ENV`, `is_secret_env`, `take_env` | `plugins.rs` inline `settings_drive_timeout_and_env_names`; `keystore.rs` inline `children_never_get_the_passphrase`; `crates/pathwarden-cli/tests/robustness.rs::plugins_only_see_the_environment_they_name` |
| Secrets live only in environment variables; settings whose names look like secrets are refused in favour of `<name>_env`. | `plugin_form.rs` `looks_secret`; `config_edit.rs` `check` | `plugin_form.rs` inline `secret_looking_settings`; `crates/pathwarden-ui/tests/config_pages.rs::plugins_dry_run_on_the_latest_run_and_secrets_stay_out` |
| Timeout (default 600 s) stops the whole process tree; stdout and stderr are capped at 4 MiB each; stdin is written on its own thread. | `plugins.rs` `timeout_of`, `MAX_OUTPUT`, `read_capped` | `plugins.rs` inline `timeout_stops_the_whole_process_tree`, `output_is_capped_with_a_note`; `crates/pathwarden-cli/tests/robustness.rs::hung_plugin_is_stopped_at_its_timeout`, `plugin_that_writes_before_reading_does_not_deadlock` |
| Plugin output is escaped on the terminal and inserted as text in the pages. | `crates/pathwarden-cli/src/outputs.rs`; `assets/config.js` | `crates/pathwarden-cli/tests/robustness.rs::hostile_names_are_escaped_on_the_terminal` |
| `[[output]]` never travels through the history, so a writer cannot make a reader run a program (section 5). | `config_edit.rs` `NEVER_SHARED` | `config_edit.rs` inline `shared_sections_travel_and_the_rest_stays` |
| Finding actions (`[[action]]`) run only when someone asks, never from `pathwarden run` or a scheduled task (`PATHWARDEN_SCHEDULED`), and the command line asks before each run unless `--yes` (`action check` asks too whenever a real finding could be sent, for a block that is set up or with `--fingerprint`; on a program given by its path with the built-in sample finding it doesn't ask: it only sends describe and dry runs). Ctrl-C (and SIGTERM on Unix) cancels a run, which stops the whole tree: the program's own process group or Job Object doesn't get the signal. Their program is found, checked, started and stopped as a plugin's (the same program and argument checks, cleared environment plus `*_env`, private folder, process-tree kill at `timeout_seconds`, at most 1800, or on Cancel). `[[action]]` never travels through the history, and without `--allow-destinations` a page can change only a block's name, `timeout_seconds` and filters: not add one, change its program, or set or remove any program setting (where it sends, `*_env`). An unnamed block the editor writes gets a name, so actions stay addressed the same when blocks move. The answer file is read only when it is a plain file, without waiting on a pipe. The program's answers are checked strictly: text capped and never read as HTML, control characters dropped, links `https://` only, at most 5 records; a missing or broken answer is a failed run. | `actions.rs` `exec`, `parse_describe`, `parse_result`, `https_url`; `plugins.rs` `command_for_action`, `run_streaming`, `CancelHandle`; `crates/pathwarden-cli/src/interrupt.rs`; `plugin_form.rs` `check_action`; `config_edit.rs` `NEVER_SHARED`; `crates/pathwarden-ui/src/actions_ui.rs` `prepare` | `actions_tests.rs` `programs_and_secrets_of_actions_need_the_flag`, `results_are_read_strictly_and_capped`, `links_must_be_https`, `cancel_kills_the_whole_tree`, `a_missing_or_broken_result_is_a_failed_run_with_its_output`, `a_result_that_isnt_a_file_is_refused` (Unix); `crates/pathwarden-cli/tests/actions.rs::actions_are_added_run_checked_and_removed`, `interrupting_a_run_cancels_it` (Unix) |
| What finding actions did is kept in the history's `actions.json`, a state file like the rest: encrypted with the history, bound to its place, and committed with a fixed message that names no finding or person (`neutral_message`). It holds, per finding: who ran which action, on which computer and when, whether it worked and its message, and the records the program returned (ticket numbers, statuses, `https://` links and up to 20 short fields). Only the checked result goes in (the caps of `parse_result`), never the request, the inputs or the program's output; dry runs aren't kept, and a finding keeps its latest 100 runs. Everyone who can read the history can read it, as they can the findings; whoever can write the history can write it (section 5): a forged entry or record misleads people, it runs nothing, and its text and links are shown as text (the report escapes them; links are only `https://`). A file a newer Pathwarden wrote is neither read nor written over. | `action_log.rs` `save`, `parse`, `run_change`, `NEWER_WORDS`; `store.rs` `STATE_FILES`, `neutral_message`; `report.rs` `action_chips`, `action_activity` | `action_log_tests.rs` `the_file_reads_back_the_same`, `a_newer_or_damaged_file_is_refused`, `a_finding_keeps_its_latest_activity`, `a_dry_run_is_not_kept`; `crates/pathwarden-core/tests/action_log.rs::two_computers_saving_at_once_keep_both`, `a_newer_file_is_never_written_over`, `a_run_carries_what_actions_did` |
| An inserted (superseded) run never runs its plugins, so it cannot close tickets a newer run keeps open. | `store.rs` | `crates/pathwarden-core/tests/git_state.rs::a_run_another_run_pushed_before_is_recorded_on_top_of_it` |
| Jira and ServiceNow: `https://` only (http for loopback or an explicit opt-in), no credentials, query or fragment in the instance URL; auth headers in zeroed memory; credentials redacted from errors. | `pathwarden-output-jira/src/settings.rs`, `api.rs`; `pathwarden-output-servicenow/src/settings.rs`, `api.rs` | Jira: `https_required_and_no_credentials_in_the_url`, `auth_headers_are_zeroizing`, `errors_hide_credentials`; ServiceNow: `https_required_except_loopback_or_explicit_opt_in`, `credentials_in_the_instance_are_refused`, `auth_header_is_built_in_zeroizing_memory`, `transport_errors_hide_credentials`; core: `plugin_form.rs` inline `instances_need_https_and_no_credentials` |
| Against a hostile ticketing server: neither plugin follows a redirect (a 3xx is an error naming it), each reads at most 1000 pages, and answers are capped (32 MiB, error answers 64 KiB) and refused, not cut, when larger. A certificate this computer doesn't trust is refused before anything is sent. | `pathwarden-output-servicenow/src/api.rs` `agent`, `body`, `MAX_PAGES`, `MAX_RESPONSE`; `pathwarden-output-jira/src/api.rs` `body`, `MAX_RESPONSE` | ServiceNow inline `redirects_are_not_followed`, `paging_stops_at_the_cap`, `answers_are_capped`, `an_untrusted_certificate_is_refused` (a local TLS server with a self-signed certificate) |
| Against a hostile ticketing server: issue keys, transition IDs and `sys_id`s read back are checked before they go into a URL; queries are built from checked values; mass-resolve and create caps limit what a bad answer can do. | `pathwarden-output-jira/src/api.rs`, `reconcile.rs`; `pathwarden-output-servicenow/src/api.rs`, `reconcile.rs` | Jira: `jql_is_built_from_checked_values`, `issue_keys`, `guards`; ServiceNow: `sys_id_validation`, `created_by_is_validated`, `scope_marks_and_validates`, `mass_resolve_guard`, `create_cap` |
| A ticket someone else labelled as a finding's can't stand in for it: `created_by` defaults to the account the plugin signs in as (Jira's `accountId` from `/myself`; ServiceNow's user name, which `sys_created_by` holds), tickets other accounts created are never resolved, reopened or commented on and are named in a warning, and `max_resolve_percent` counts this account's tickets only. When the account can't be told, tickets are matched as before, with a warning. | Jira `main.rs`, `reconcile.rs` `own_issues`; ServiceNow `main.rs`, `api.rs` `me`, `reconcile.rs` `own_tickets` | Jira inline `issues_of_other_accounts_are_left_out_and_named`, `the_resolve_guard_counts_own_issues`, `tests/mock_jira.rs::issues_created_by_others_are_ignored_with_created_by`; ServiceNow inline `foreign_tickets_are_left_out_and_named`, `the_resolve_guard_counts_own_tickets`, `the_account_is_known` |
| A directory name can't add a line of its own to a ticket or hide or reorder text: names and domains are put on one line as the directory is read (line breaks, including U+0085 and the Unicode line and paragraph separators, become spaces; other control characters stay and are shown escaped on the terminal), so remediation text that quotes them can't either; in the ticket, names, domains, paths and accepted-risk reasons go in on one line, the remediation keeps only its own line breaks, and bidirectional and zero-width characters are removed from the whole ticket text. ServiceNow text never opens a `[code]` tag. | `lib.rs` `names_on_one_line`; `text.rs` `one_line`; Jira and ServiceNow `reconcile.rs` `one_line`, `lines`, `is_invisible`, `description`; ServiceNow `no_code_tag` | `crates/pathwarden-core/tests/findings.rs::a_name_with_a_line_break_stays_on_one_line`; Jira and ServiceNow inline `names_stay_on_their_line_and_visible`, `reasons_and_remediation_add_no_lines` (ServiceNow `..._or_code_tags`) |
| The environment's proxy is used only for an `https://` instance `NO_PROXY` doesn't name, never for loopback or plain `http://` (ureq doesn't read `NO_PROXY`). | Jira and ServiceNow `api.rs` `env_proxy_for` | inline `the_proxy_skips_loopback_http_and_no_proxy` |
| Exports (`pathwarden export`): DefectDojo shows its fields as Markdown, so names and Pathwarden's own sentences go in escaped (no link, image, HTML, heading or list of their own); only the rule guides, which are Markdown, go in as they are. SARIF is JSON read by tools, with text in `message.text`. | `crates/pathwarden-export/src/defectdojo.rs` `md`, `md_lines` | `defectdojo.rs` inline `text_is_escaped_for_markdown`; `crates/pathwarden-export/tests/formats.rs` |

### Not defended

- **A plugin is not sandboxed.** It runs with the full rights of the account
  that runs Pathwarden and receives the whole event. The environment filter
  prevents accidental leaks, not a hostile plugin.
- **A finding action is not sandboxed either.** It receives one finding
  with its names, path and guide, and does what its program does; the
  dry run (`dry_run`) is a request the program may ignore.
- **What `actions.json` says is what the programs and people said.** Who
  ran an action is the account and computer name of the process, as for
  accepted risks (`identity.rs`), not a proof; a record's status is the
  program's last answer, not the other system's state now.
- **Plugin folders are checked, not locked.** Whoever can write the folder
  holding `pathwarden.exe` (or its `plugins\`) can plant a
  `pathwarden-output-*.exe`, and could equally replace `pathwarden.exe`.
  `pathwarden run` warns at the start when anyone but this account,
  Administrators and SYSTEM (root on Unix) can change either (
  `plugins.rs` `folder_warnings`; inline `folders_others_can_change_are_named`),
  and runs anyway; `run.ps1` refuses the scheduled-task folder. On Unix a
  folder owned by another ordinary user isn't flagged. The UI's start-up
  doesn't check.
- The "confirm before testing your own script" step is in the browser only.
- Without `--allow-destinations`, a session can still change a plugin's
  other settings (a script's `webhook` address that isn't a secret, the
  ticket `fields`, such as watchers or an assignee, who are then e-mailed
  findings), and the Ticketing page doesn't say before a save that the
  instance, project, table and environment variables are locked: the save
  is refused with why.
- **Script files are checked for writers, not locked.** `pathwarden run`
  warns when someone else can change a program or script a plugin's
  `command` names, or its folder (`plugins.rs` `command_warnings`); a
  scheduled run (`PATHWARDEN_SCHEDULED`) refuses to start that plugin
  (`command_for`). Inline `scripts_others_can_change_are_named`.
- ServiceNow with a token: the account is asked of
  `/api/now/ui/user/current_user`, not checked against a live instance.
- **Secrets are suggested via `setx`**, which stores them in plain text in
  the user's profile (`HKCU\Environment`). Credential Manager is not
  supported for plugin secrets.
- **Jira Data Center's rendering is not verified against a live server.**
  Descriptions and comments are escaped for wiki markup (`api.rs`
  `wiki_escape`, inline `wiki_markup_in_names_stays_text`): special
  characters with a backslash, a backslash as `&#92;`, a heading or quote
  line's first letter as an entity; plain `https://` addresses stay links.
- The TLS-rejection test is ServiceNow's only; Jira uses the same ureq
  settings.

## 16. Supply chain

Attackers: Supply chain.

### What holds

- **RustHound-CE is pinned exactly** (`rusthound-ce = "=2.5.30"`,
  `dcerpc = "=0.2.11"`, in `crates/pathwarden-collect/Cargo.toml`), with
  checksums in `Cargo.lock`. No git dependencies. Workarounds for upstream
  behaviour (LAPS logging, disabled certificate checks) live in Pathwarden's
  code. RustHound-CE itself is vendored (`vendor/rusthound-ce`) only to bump
  its vulnerable dependencies (zip, quick-xml, the DNS resolver); its
  manifest's header lists every change.
- **ldap3 is vendored** (`vendor/ldap3`, 0.12.1 with a sealed-decoder fix and
  a public `sasl_bind`) through `[patch.crates-io]` in the root `Cargo.toml`,
  reviewed in this repository.
- **CI** (`.github/workflows/ci.yml`) runs fmt, `cargo deny check`
  (advisories, licenses, sources; `deny.toml` gives each accepted advisory's
  reason) and clippy with `--locked` and `-D warnings` on every push, with a
  read-only token, actions pinned to commit SHAs and
  `persist-credentials: false`; tests on demand. `rust-toolchain.toml` pins
  the toolchain.
- **Releases are built locally** with `scripts/package.ps1`: clean tree,
  `--locked`, pinned toolchain, a smoke check, license texts
  (`THIRD-PARTY-LICENSES.md`, cargo-about) and CycloneDX SBOMs in each zip,
  checked entry names, a fresh `SHA256SUMS.txt`, and Azure Artifact Signing
  (Authenticode) of the Windows executables when `PW_SIGN_*` are set.
  `.github/workflows/sign-sums.yml` checks the uploaded release against
  `SHA256SUMS.txt` and signs it with Sigstore.
  `.github/workflows/release.yml`, dispatched by hand, also builds Linux
  archives and records provenance for every file. It runs only from a tag,
  and never replaces a file a release already holds, published or draft
  (a draft may hold the locally signed archives): it stops and names them.
- Bundled third-party code (Cytoscape.js) is listed with its hash in
  `THIRD-PARTY-NOTICES.md` and served by the app; pages load nothing from
  the internet.

### Not defended

- **Local builds have no provenance**, and the signature over their sums
  shows the archives are the ones the release holds, not who built them
  (docs/dev/building.md, "Verifying a download"). The Authenticode
  signature covers who built the Windows executables; the Linux archives
  of a local build have nothing that does. Provenance needs the release
  workflow and a public repository. Branch and tag protection come with the public repository.
- **The vendored ldap3, smb2-client and rusthound-ce have no lockfile
  checksum** (path dependencies); they rest on review.
- **Known advisories without a fix** (`deny.toml` and `.cargo/audit.toml`
  give each one's reason):
  - rsa 0.9, Marvin attack (RUSTSEC-2023-0071), through picky in
    RustHound-CE and in sspi (ldap3's NTLM and Kerberos library). The attack
    needs many timed RSA private-key operations by Pathwarden. Pathwarden
    holds no RSA private key: those operations happen only in Kerberos
    PKINIT or certificate sign-in, and the built-in collector always sets no
    certificate (`pfx: None`). The TLS stack (rustls with ring) does not use
    this crate. rsa 0.10.0 has the fix; no picky release takes it yet.
  - crypto-bigint 0.5, non-constant-time arithmetic (RUSTSEC-2026-0387),
    through elliptic-curve: age 0.12 (the latest) links p256 for recipient
    types Pathwarden does not use (it encrypts with a scrypt passphrase or
    x25519), and picky uses it only for the certificate sign-in above.
  - glib 0.18, unsound `VariantStrIter` (RUSTSEC-2024-0429): wry's GTK
    backend, built only for a Linux desktop window, which no release ships.
- Nothing checks the Cytoscape.js hash in the notices.

## 17. The evidence signing key

Evidence packs ([evidence.md](../evidence.md)) are signed with a long-lived
Ed25519 key whose fingerprint auditors check every pack against. Whoever
holds it can sign packs saying any finding was fixed.

### Where it lives and who can read it

- The app's key: `evidence-key/evidence.key` (with `evidence.pub`) in the
  private workspace, made by **Settings** › **Evidence signing key** or
  `pathwarden evidence key new`, in a folder only the account reads
  (Windows: a protected access list for the user and SYSTEM; Linux: mode 700,
  the key 600).
- Your own: the folder `pathwarden evidence keygen --output DIR` makes, same
  permissions, used with `--key`.
- In a pipeline: `PATHWARDEN_EVIDENCE_KEY`, a secret variable with the key's
  base64 line.

The key is unencrypted, like an SSH key without a passphrase: the account
and the computer's administrators can read it.

### Defended

- A link or junction in place of `evidence-key/` is refused. A folder or key
  file others can read is made private again on create, use or replace;
  Settings says when it finds one open, and the CLI warns when `--key` names
  one.
- A new key is written in a private folder beside the old and renamed over,
  so the old is never deleted before the new is whole. Old packs keep
  checking against the old fingerprint.
- The key is never copied into full runs, the history, diagnostics bundles
  or packs (a pack holds the public key only).
- A run loaded from a shared history gets no pack and is never the run
  compared with, in the app and `pathwarden evidence --run`: its findings
  and report came from whoever can write the history, and this computer's
  signature would vouch for them (`evidence_ui.rs` `pack_blocked`,
  `build_pack`, `earlier_runs`; `crates/pathwarden-ui/tests/evidence.rs::a_run_loaded_from_the_history_gets_no_pack`).
- Checking needs only the public key or fingerprint. A pack checked without
  one is shown as unchanged but not trusted, its claims not as fact. An
  uploaded pack is refused over 64 MB or 1 GB unpacked, and no entry is read
  past its declared size.

### Not defended

- Anyone acting as the account, or an administrator, can copy the key and
  sign packs. If that may have happened, rotate it (**Replace with a new
  key**, `evidence key new --replace`), publish the new fingerprint, and tell
  auditors from when the old one stops counting.
- A pack's times come from the signing computer's clock, not a trusted
  timestamp.
- Backups are yours to make, and as sensitive as the key.

## 18. Gaps

Things claimed nowhere, not defended where a reader might expect it, or not
tested. Severity is for a typical deployment (a dedicated collector account,
a private history repository with a few writers). A closed gap's details are
in the section named; "Left" is what remains.

| # | Gap | Area | Severity | Suggested fix |
|---|---|---|---|---|
| 1 | Closed by default (2026-10-29): Kerberos only, signed SMB. Left: `--allow-ntlm`; as the Windows account, a spoofed real computer refusing Kerberos can get NTLM from Windows; external collectors; the LDAP bind is NTLM over a checked certificate. | 12, 13 | Medium | Move the LDAP bind to the ticket; check Windows' outgoing NTLM policy and say so when it is open. |
| 2 | Accepted risks, disabled rules, severities and Tier Zero from any writer apply on every reader at the next pull without review; attribution is self-asserted; plugins then close tickets. No test that a pushed accepted risk hides a finding here. | 5 | Medium | Hold settings changes made elsewhere for review on readers (at least `suppress` and `rules`), list them with their commit and author, and test the apply path. |
| 3 | Closed (2026-11-07): never-shared sections pushed through the repository are tested not to reach the reader. | 5, 15 | Medium | Done. |
| 4 | Closed (2026-11-07): SharpHound's Authenticode signature is checked (`WinVerifyTrust`, cache only, no revocation check; `pathwarden-collect` `signature.rs`); unless "SpecterOps" (common name or organization) validly signed it, a warning: "C:\Tools\SharpHound.exe isn't signed by SpecterOps. Run it only if you trust where it came from." (or "is signed by NAME, not SpecterOps", "has a signature that isn't valid"). Left: a warning by the owner's choice; the subject isn't pinned. | 10 | Medium | Done. |
| 5 | Docs suggest `$env:PATHWARDEN_COLLECT_PASSWORD = '...'`, which lands in PSReadLine history and stays in the shell. | 12 | Medium | Fixed in the docs (2026-10-27). |
| 6 | Mostly closed (2026-11-07), section 16. Left: code signing (package.ps1's hook is ready) and provenance for local builds. | 16 | Medium | Signing turned on for 1.0 (Azure Artifact Signing). |
| 7 | Closed (2026-11-07): `guard.rs` unit tests; the smoke test in the pre-release checklist. Left: that wry calls the handlers is tested only by hand. | 11 | Medium | Done. |
| 8 | No rollback or path binding in an encrypted history; a plain history has no integrity at all. | 4, 7 | Medium | Fixed (2026-10-28): the binding, with trust on first use (section 7); docs/running.md says to protect the branch. |
| 9 | Closed (2026-11-07): history size caps; an unreadable `findings.json` doesn't fail every run (section 4). | 4 | Low | Done. |
| 10 | Closed (2026-11-07): a followed key change is told once; the DPAPI-NG file has its own access list. Left: a note, not a refusal. | 7 | Low | Done. |
| 11 | Closed (2026-11-07): one passphrase per history advised; pre-0.2 passphrases aren't tried elsewhere (`crypt.rs` `known_passphrase`). | 7 | Low | Done. |
| 12 | The encryption page's tip says everything is encrypted "except a small marker"; file names, run times, sizes and commit times stay visible. The local workspace is never encrypted and no doc says so. | 7 | Low | Fixed (2026-10-27). |
| 13 | Closed (2026-11-07): `Origin` / `Sec-Fetch-Site` on the loopback server, tested. Left: the desktop window takes a change without `Origin`. | 10 | Low | Done. |
| 14 | Closed (2026-11-07): loopback-only exclusive listener and session cap tested. | 10 | Low | Done. |
| 15 | Closed (2026-11-07): git's environment tested; unsafe `.gitattributes` refused; `Store::new` refuses credentials in the URL. | 8 | Low | Done. |
| 16 | Closed (2026-11-07): install and `plugins` folder warning; `check_program` refuses network and device paths. Left: a warning; the UI's start-up doesn't check. | 15 | Low | Done. |
| 17 | Closed (2026-11-07): plugin redirect, paging, answer and certificate limits; Jira wiki escaping. Left: not verified on a live Data Center. | 15 | Low | Done. |
| 18 | Closed (2026-11-07): `--sharphound` and `--rusthound` take a full local path or one with a folder (`.\SharpHound.exe`, as pre-0.3 tasks give it), made full before the signature check; bare names, network and device paths are refused before the file system is touched (`pathwarden-collect` `resolve_program`, `check_program`). `run.ps1` passes `(Join-Path $folder 'SharpHound.exe')`; `pathwarden collect` prints gap 4's warning (`warning: ...`, left out by `-q`). Left: no SHA-256 pinned; external `rusthound-ce` unchecked. | 12 | Low | Done. |
| 19 | Closed (2026-11-07): task permissions documented; folders above the task folder checked; install folder warning on Linux. Left: Linux warns but runs, and misses another ordinary user's folder. | 12 | Low | Done. |
| 20 | Mostly closed (2026-11-07): loaded reports' popups stay sandboxed; the header tags the run "From the repository" (the owner chose the tag alone). Left: CSS in the frame can show anything; its links open. | 6 | Low | Done. |
| 21 | Accepted by the owner (2026-11-07): plugin secrets are kept with `setx` in plain text; a session can hand an existing command plugin any environment variable. Reason: existing plugin setups keep working; secrets are in user environment variables, as documented. | 15 | Low | None planned. |
| 22 | Mostly closed (2026-11-07): tests for lock refresh, the `MAX_WORK_FACTOR` refusal, nested zips, deep or truncated JSON, the pack network-path refusal, hostile run labels, env removal for external collectors, the host-name filter, and the DPAPI-NG file's access list. Left untested: `--for-account` with a real gMSA (`SID=` needs a domain), Linux keyring paths, a retest end to end against a directory. | several | Low | Add the rest where a live system is at hand. |
| 23 | Doc drift: docs/collect.md says cancelling does not kill an external collector's children (the Job Object does); docs/running.md assumes a gMSA that is local admin everywhere. | 12 | Low | Fixed (2026-10-27). |
| 24 | No guidance on Protected Users or "sensitive and cannot be delegated" for the collector account. | 12, 13 | Low | Fixed (2026-10-27) in docs/collector-account.md; docs/collect.md points to it (2026-11-07). |
