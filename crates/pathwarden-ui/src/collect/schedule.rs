//! The files to run a collection every night: a PowerShell script and the
//! Task Scheduler command for a gMSA on Windows, or a script, systemd unit
//! and timer on Linux (as in `docs/running.md` and `docs/collect.md`).
//!
//! Only text is produced here. The UI never creates a task or runs
//! anything elevated: an administrator copies and runs these.

use serde::Deserialize;

use super::{host_like, Detected, BUILTIN};
use crate::pages::esc;
use crate::workspace::{CollectionInfo, RunSummary};

/// Query parameters of the schedule page and its downloads.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct Params {
    pub run: Option<String>,
    /// `windows` or `linux`.
    pub os: Option<String>,
    /// Where Pathwarden lives on the server.
    pub folder: Option<String>,
    /// The gMSA (Windows), `DOMAIN\name$`.
    pub account: Option<String>,
    /// Time of day, `HH:MM`.
    pub at: Option<String>,
    /// The account the Linux job binds as.
    pub user: Option<String>,
}

/// Everything the scripts need, checked.
#[derive(Debug, Clone)]
pub struct Target {
    pub linux: bool,
    pub run: Option<String>,
    /// The domain the run was collected from (`--server` applies to it).
    pub domain: String,
    /// The run's other domains, collected one after another with the same
    /// settings but no `--server` (DNS finds one of their DCs).
    pub extra_domains: Vec<String>,
    pub server: Option<String>,
    pub ldaps: bool,
    /// The nightly run collects with SharpHound (else built-in).
    pub sharphound: bool,
    /// Sessions and local groups too.
    pub full: bool,
    pub folder: String,
    pub account: String,
    pub at: String,
    pub user: String,
    /// Why the nightly run differs from the run it was made from.
    pub notes: Vec<String>,
    /// The environment the schedule is for ([`crate::environments`]):
    /// `None` for Default. Another environment's schedule has its own task
    /// or timer name and its own folders, so each keeps its own config and
    /// history on the server.
    pub env: Option<String>,
}

/// What `pathwarden schedule` gives in place of a run: the collection to
/// repeat every night.
#[derive(Debug, Default, Clone)]
pub struct Spec {
    /// Every domain to collect; the first is the one `server` serves.
    pub domains: Vec<String>,
    pub server: Option<String>,
    /// Windows: connect with LDAPS (Linux always does).
    pub ldaps: bool,
    /// Windows: collect with SharpHound.
    pub sharphound: bool,
    /// Sessions and local groups too (`--scope all`).
    pub full: bool,
    /// The environment's ID ([`crate::environments`]), `None` for Default.
    pub env: Option<String>,
}

/// What a schedule is made from: a run's ID, how it was collected and its
/// domains (each may be missing).
struct Source<'a> {
    run: Option<String>,
    info: Option<&'a CollectionInfo>,
    domains: &'a [String],
    /// From `pathwarden schedule`: the files depend only on its options,
    /// never on what this build of Pathwarden includes.
    cli: bool,
}

/// `os=linux`, `os=windows`, else this computer's system.
fn is_linux(p: &Params) -> bool {
    match p.os.as_deref() {
        Some("linux") => true,
        Some("windows") => false,
        _ => !cfg!(windows),
    }
}

const BAD_LINUX_FOLDER: &str =
    "The folder must be a full path like /opt/pathwarden (letters, digits, _ . - /).";
const BAD_WINDOWS_FOLDER: &str = r"The folder must be a full path like C:\Pathwarden (letters, digits, spaces, _ . - and \), in a folder of its own: not a drive or a Windows folder such as C:\Windows, C:\Program Files or C:\Users.";
const BAD_GMSA: &str = r"Enter the gMSA as DOMAIN\name$ (a gMSA's name ends with $).";
const BAD_TIME: &str = "Enter the time as HH:MM, like 02:00.";
const BAD_USER: &str = "Enter the user name like svc-pathwarden or svc-pathwarden@scale.local.";

/// The typed fields that were refused, each with its problem (as
/// [`Target::resolve`] reports it): `folder`, `account` or `user`, then
/// `at`, the order of the form. The form marks each one and points it at
/// its own message.
pub fn invalid_fields(p: &Params) -> Vec<(&'static str, &'static str)> {
    let linux = is_linux(p);
    fn given(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|s| !s.is_empty())
    }
    let mut out = Vec::new();
    let folder = p.folder.as_deref().map(|f| {
        if linux {
            f.trim()
        } else {
            f.trim().trim_end_matches('\\')
        }
    });
    if given(folder).is_some_and(|f| {
        if linux {
            !valid_linux_folder(f)
        } else {
            !valid_windows_folder(f)
        }
    }) {
        out.push((
            "folder",
            if linux {
                BAD_LINUX_FOLDER
            } else {
                BAD_WINDOWS_FOLDER
            },
        ));
    }
    if given(p.account.as_deref()).is_some_and(|a| !valid_gmsa(a)) {
        out.push(("account", BAD_GMSA));
    }
    if given(p.user.as_deref()).is_some_and(|u| !valid_user(u)) {
        out.push(("user", BAD_USER));
    }
    if given(p.at.as_deref()).is_some_and(|a| !valid_time(a)) {
        out.push(("at", BAD_TIME));
    }
    out
}

fn valid_windows_folder(s: &str) -> bool {
    let b = s.as_bytes();
    s.is_ascii()
        && b.len() >= 3
        && b.len() <= 200
        && b[0].is_ascii_alphabetic()
        && &s[1..3] == ":\\"
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || " _.-\\():".contains(c))
        && s[2..].chars().all(|c| c != ':')
        && !windows_system_folder(s)
}

/// A drive, or a folder Windows owns (or one inside it), where the folder
/// setup's protected permissions and new owner would break the system.
fn windows_system_folder(s: &str) -> bool {
    const SYSTEM: [&str; 10] = [
        "windows",
        "program files",
        "program files (x86)",
        "programdata",
        "users",
        "documents and settings",
        "$recycle.bin",
        "system volume information",
        "recovery",
        "boot",
    ];
    let rest = s[3..].trim_matches('\\').to_ascii_lowercase();
    let first = rest
        .split('\\')
        .next()
        .unwrap_or_default()
        .trim_end_matches(['.', ' ']);
    rest.is_empty() || SYSTEM.contains(&first)
}

fn valid_linux_folder(s: &str) -> bool {
    s.starts_with('/')
        && s.len() <= 200
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
}

/// `DOMAIN\name$`: what Task Scheduler takes for a gMSA.
fn valid_gmsa(s: &str) -> bool {
    let ok = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
    };
    match s.split_once('\\') {
        Some((dom, name)) => {
            ok(dom) && name.len() > 1 && name.ends_with('$') && ok(&name[..name.len() - 1])
        }
        None => false,
    }
}

fn valid_user(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 120
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-@\\".contains(c))
}

fn valid_time(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 5
        && b[2] == b':'
        && s[..2]
            .parse::<u8>()
            .is_ok_and(|h| h < 24 && b[0].is_ascii_digit() && b[1].is_ascii_digit())
        && s[3..]
            .parse::<u8>()
            .is_ok_and(|m| m < 60 && b[3].is_ascii_digit() && b[4].is_ascii_digit())
}

/// The state folder `pathwarden run` uses by default, relative to the task's
/// working directory.
const STATE_FOLDER: &str = "pathwarden-state";

/// PowerShell: `Find-PathwardenWriters <folder> <sids>` lists everything in
/// the task folder that someone other than Administrators and SYSTEM could
/// change (plus `<sids>` in `reports` and the state folder, whose contents
/// are not walked). Shared by the setup, which checks its own work, and
/// `run.ps1`, which refuses to run otherwise. The mask is every right that
/// allows a change: write and append data, write attributes, delete (also
/// children), change permissions, take ownership, GENERIC_ALL and
/// GENERIC_WRITE. An owner counts as a writer (it may rewrite the DACL)
/// unless an OWNER RIGHTS entry that applies to the item itself (not
/// inherit-only) takes that away. A junction or symbolic link anywhere in
/// the folder is refused and never followed: its own permissions say
/// nothing about where it points. `-Owners` adds owners accepted anywhere
/// (the setup's own account, before it hands everything to
/// Administrators), and `-Deep` walks `reports` and the state folder too.
///
/// `Find-PathwardenParentWriters <folder>` lists the folders above it that
/// someone other than Administrators, SYSTEM and TrustedInstaller could
/// use to rename or replace it: delete it or its subfolders, change
/// its permissions or owner, GENERIC_ALL or GENERIC_WRITE, or a foreign
/// owner. Creating new folders beside it (as Users may in `C:\`) doesn't
/// count, nor do entries only folders inside inherit. A folder above that is
/// a junction or symbolic link is refused, so the path checked is the real
/// one, and so is a folder that isn't on a local fixed drive. Folders above
/// that don't exist yet are skipped (the setup creates them locked down).
const ACL_GUARD_PS: &str = r#"function Find-PathwardenWriters([string]$Folder, [string[]]$Writers, [string[]]$Owners = @(), [switch]$Deep) {
    $mask = 0x500D0156
    $admins = @('S-1-5-32-544', 'S-1-5-18')
    $writable = @('reports', 'pathwarden-state')
    $sids = [System.Security.Principal.SecurityIdentifier]
    $link = [System.IO.FileAttributes]::ReparsePoint
    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $top = Get-Item -LiteralPath $Folder -Force
    $items = @(@{ Item = $top; Writers = $admins })
    if (($top.Attributes -band $link) -eq 0) {
        foreach ($child in @(Get-ChildItem -LiteralPath $Folder -Force)) {
            $open = $child.PSIsContainer -and ($child.Attributes -band $link) -eq 0
            if ($child.PSIsContainer -and $writable -contains $child.Name) {
                $items += @{ Item = $child; Writers = $admins + $Writers }
                if ($Deep -and $open) {
                    foreach ($sub in @(Get-ChildItem -LiteralPath $child.FullName -Recurse -Force)) {
                        $items += @{ Item = $sub; Writers = $admins + $Writers }
                    }
                }
                continue
            }
            $items += @{ Item = $child; Writers = $admins }
            if ($open) {
                foreach ($sub in @(Get-ChildItem -LiteralPath $child.FullName -Recurse -Force)) {
                    $items += @{ Item = $sub; Writers = $admins }
                }
            }
        }
    }
    foreach ($entry in $items) {
        $path = $entry.Item.FullName
        if (($entry.Item.Attributes -band $link) -ne 0) {
            "$path is a link (a junction or symbolic link)"
            continue
        }
        $acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue
        if (-not $acl) {
            "$path permissions can't be read"
            continue
        }
        $rules = @($acl.GetAccessRules($true, $true, $sids))
        $owner = $acl.GetOwner($sids).Value
        $ownerRights = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-3-4' -and $_.AccessControlType -eq 'Allow' -and ($_.PropagationFlags -band $inheritOnly) -eq 0 }).Count -gt 0
        if (($entry.Writers + $Owners) -notcontains $owner -and -not $ownerRights) {
            "$path is owned by $owner"
        }
        foreach ($rule in $rules) {
            $who = $rule.IdentityReference.Value
            if ($rule.AccessControlType -eq 'Allow' -and (([int]$rule.FileSystemRights) -band $mask) -ne 0 -and $entry.Writers -notcontains $who) {
                "$path can be changed by $who"
            }
        }
    }
}
function Find-PathwardenParentWriters([string]$Folder) {
    $mask = 0x500D0040
    $trusted = @('S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $sids = [System.Security.Principal.SecurityIdentifier]
    $link = [System.IO.FileAttributes]::ReparsePoint
    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $full = [System.IO.Path]::GetFullPath($Folder)
    if ($full.Length -gt 3) { $full = $full.TrimEnd('\') }
    $root = [System.IO.Path]::GetPathRoot($full)
    if (-not $root -or $root.StartsWith('\\') -or (New-Object System.IO.DriveInfo($root)).DriveType -ne 'Fixed') {
        "$full is not on a local fixed drive"
    }
    $parent = (New-Object System.IO.DirectoryInfo($full)).Parent
    while ($parent) {
        $path = $parent.FullName
        if (-not $parent.Exists) {
            $parent = $parent.Parent
            continue
        }
        if (($parent.Attributes -band $link) -ne 0) {
            "$path is a link (a junction or symbolic link)"
        }
        $acl = Get-Acl -LiteralPath $path -ErrorAction SilentlyContinue
        if (-not $acl) {
            "$path permissions can't be read"
        } else {
            $rules = @($acl.GetAccessRules($true, $true, $sids))
            $owner = $acl.GetOwner($sids).Value
            $ownerRights = @($rules | Where-Object { $_.IdentityReference.Value -eq 'S-1-3-4' -and $_.AccessControlType -eq 'Allow' -and ($_.PropagationFlags -band $inheritOnly) -eq 0 }).Count -gt 0
            if ($trusted -notcontains $owner -and -not $ownerRights) {
                "$path is owned by $owner"
            }
            foreach ($rule in $rules) {
                if (($rule.PropagationFlags -band $inheritOnly) -ne 0) { continue }
                $who = $rule.IdentityReference.Value
                if ($rule.AccessControlType -eq 'Allow' -and (([int]$rule.FileSystemRights) -band $mask) -ne 0 -and $trusted -notcontains $who) {
                    "$path can be changed by $who"
                }
            }
        }
        $parent = $parent.Parent
    }
}"#;

/// Where `run.ps1` writes its log, under the task folder: inside `reports`,
/// which the gMSA can already write (the setup grants it, and the guard
/// lets it, without walking what is inside).
const LOG_FOLDER: &str = r"reports\logs";

/// How many run logs `run.ps1` keeps.
pub(crate) const LOGS_KEPT: usize = 30;

/// PowerShell for `run.ps1`'s log (`$log`): `Write-PathwardenLog <text>`
/// adds a timestamped line, and `Invoke-PathwardenLogged { ... }` runs a
/// block, writing what its programs print (stdout and stderr) to the log
/// while `$LASTEXITCODE` keeps the exit code. Windows PowerShell turns a
/// program's redirected stderr into error records, which would stop the
/// script under `$ErrorActionPreference = 'Stop'`: the block runs with
/// `Continue`. A log that can't be written never stops the run.
const LOG_PS: &str = r#"function Write-PathwardenLog([string]$Text) {
    if (-not $log) { return }
    try {
        Add-Content -LiteralPath $log -Encoding UTF8 -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $Text)
    } catch {}
}
function Invoke-PathwardenLogged([scriptblock]$Run) {
    $ErrorActionPreference = 'Continue'
    & $Run 2>&1 | ForEach-Object { Write-PathwardenLog "$_" }
}"#;

/// `text` with every line indented by `by`.
fn indent(text: &str, by: &str) -> String {
    text.lines()
        .map(|l| format!("{by}{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A string inside PowerShell single quotes (no expansion; `'` doubled).
fn ps(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A string inside POSIX shell single quotes.
fn sh(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Target {
    /// Settles every value: what the user typed if it is valid, else the
    /// run's settings, else a sensible default. Returns the problems with
    /// what was typed.
    pub fn resolve(p: &Params, run: Option<&RunSummary>, d: &Detected) -> (Target, Vec<String>) {
        Self::resolve_in(p, run, d, None)
    }

    /// [`Target::resolve`] for environment `env` (`None` or `default` for
    /// the Default environment).
    pub fn resolve_in(
        p: &Params,
        run: Option<&RunSummary>,
        d: &Detected,
        env: Option<&str>,
    ) -> (Target, Vec<String>) {
        Self::resolve_from(
            p,
            Source {
                run: run.map(|r| r.id.clone()),
                info: run.and_then(|r| r.collection.as_ref()),
                domains: run.map(|r| r.domains.as_slice()).unwrap_or_default(),
                cli: false,
            },
            d,
            env,
        )
    }

    /// For `pathwarden schedule`: what the command line gives in place of
    /// a run. Only the system defaults to this computer's; nothing else is
    /// detected here or depends on this build. Every value is
    /// checked as the Schedule page checks it, and a value that doesn't
    /// apply to the chosen system is an error rather than ignored. Returns
    /// the problems; the target is only meant to be used without any.
    pub fn for_command_line(p: &Params, spec: &Spec) -> (Target, Vec<String>) {
        let mut errors = Vec::new();
        let linux = is_linux(p);
        let domains: Vec<String> = spec
            .domains
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        if domains.is_empty() {
            errors.push("Enter the domain, like scale.local.".to_string());
        }
        for d in domains.iter().filter(|d| !host_like(d)) {
            errors.push(format!(
                "{d:?} isn't a domain name: use letters, digits, . - and _, like scale.local."
            ));
        }
        let server = spec
            .server
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        if server.is_some_and(|s| !host_like(s)) {
            errors.push(
                "Enter the domain controller's name, like dc01.scale.local (letters, digits, . - and _)."
                    .to_string(),
            );
        }
        let os = if linux { "Linux" } else { "Windows" };
        let wrong = |what: &str, instead: &str| {
            format!(
                "{what} is for {} servers; {instead}.",
                if linux { "Windows" } else { "Linux" }
            )
        };
        if linux && p.account.is_some() {
            errors.push(wrong(
                "--account (the gMSA)",
                "on Linux, --user is the account the job signs in as",
            ));
        }
        if !linux && p.user.is_some() {
            errors.push(wrong(
                "--user",
                "on Windows, the task runs as the gMSA in --account",
            ));
        }
        if linux && spec.ldaps {
            errors.push(format!(
                "--ldaps is for Windows servers: on {os}, the job always connects with LDAPS."
            ));
        }
        if linux && spec.sharphound {
            errors.push(format!(
                "SharpHound runs on Windows only: on {os}, Pathwarden collects with its built-in collector."
            ));
        }
        // A gMSA has no password to hand over, so a Windows Full collection
        // is SharpHound's (as the page schedules a Full run).
        let sharphound = spec.sharphound || (!linux && spec.full);
        let info = CollectionInfo {
            read_started: None,
            method: if sharphound { "sharphound" } else { "builtin" }.into(),
            scope: if spec.full { "all" } else { "dc-only" }.into(),
            domain: domains.first().cloned().unwrap_or_default(),
            server: server.map(str::to_string),
            ldaps: spec.ldaps,
            current_user: true,
            warnings: vec![],
            kept: None,
            kerberos_only: None,
            smb_signing: None,
            domains: Vec::new(),
        };
        let (target, more) = Self::resolve_from(
            p,
            Source {
                run: None,
                info: Some(&info),
                domains: &domains,
                cli: true,
            },
            &Detected::default(),
            spec.env.as_deref(),
        );
        errors.extend(more);
        if spec
            .env
            .as_deref()
            .is_some_and(|e| !crate::environments::valid_id(e))
        {
            errors.push(
                "An environment's ID has lower-case letters, digits and dashes only.".to_string(),
            );
        }
        (target, errors)
    }

    fn resolve_from(
        p: &Params,
        src: Source,
        d: &Detected,
        env: Option<&str>,
    ) -> (Target, Vec<String>) {
        let env = env
            .filter(|e| *e != crate::environments::DEFAULT_ENV && crate::environments::valid_id(e))
            .map(str::to_string);
        let mut errors = Vec::new();
        let info = src.info;
        let linux = is_linux(p);
        let domain = info
            .map(|i| i.domain.clone())
            .or_else(|| src.domains.first().map(|d| d.to_ascii_lowercase()))
            .or_else(|| d.domain.clone())
            .filter(|s| host_like(s))
            .unwrap_or_else(|| "scale.local".into());
        // A forest run covers several domains: the nightly run must collect
        // every one of them, or their findings would all look fixed.
        let mut extra_domains: Vec<String> = Vec::new();
        for d in src.domains {
            let d = d.trim().to_ascii_lowercase();
            if host_like(&d) && !d.eq_ignore_ascii_case(&domain) && !extra_domains.contains(&d) {
                extra_domains.push(d);
            }
        }
        let server = info
            .and_then(|i| i.server.clone())
            .or_else(|| d.dc.clone().filter(|_| info.is_none()))
            .filter(|s| host_like(s));
        let full = info.is_some_and(|i| i.scope == "all");
        let used_sharphound = info.is_some_and(|i| i.method == "sharphound");
        let mut notes = Vec::new();
        if !extra_domains.is_empty() {
            notes.push(format!(
                "This run covers {} domains, so the nightly run collects each of them in turn: \
                 {}. Only {domain} uses the domain controller you chose; the others use one \
                 that DNS finds. If one collection fails, that night's run stops rather than \
                 report a partial forest.",
                extra_domains.len() + 1,
                std::iter::once(domain.as_str())
                    .chain(extra_domains.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }

        // The page schedules the build it runs in, so a build without the
        // built-in collector schedules SharpHound. The command line writes
        // the same files from any build and says so in a note instead.
        let sharphound = !linux && (used_sharphound || full || (!src.cli && !BUILTIN));
        if !linux && full && !used_sharphound {
            notes.push(
                "This run used the built-in collector with a password. The scheduled task runs \
                 as a gMSA, which has no password to hand over, so the nightly Full collection \
                 uses SharpHound. The gMSA needs local admin rights on the computers to see \
                 sessions and local groups."
                    .to_string(),
            );
        } else if !linux && !sharphound && info.is_some_and(|i| !i.current_user) {
            notes.push(
                "This run signed in with a password. The scheduled task signs in as the gMSA \
                 instead (Kerberos through Windows), so no password is stored anywhere."
                    .to_string(),
            );
        }
        if !linux && !sharphound && !BUILTIN {
            notes.push(
                "These files collect with the built-in collector, which this build of \
                 Pathwarden doesn't include. Use the full build of Pathwarden on the server, \
                 or pass --sharphound."
                    .to_string(),
            );
        }
        if linux && !BUILTIN {
            notes.push(
                "On Linux, Pathwarden collects with its built-in collector, which this build \
                 doesn't include. Use the full build of Pathwarden on the server."
                    .to_string(),
            );
        }
        if linux && server.is_none() {
            notes.push(
                "LDAPS checks the domain controller's certificate against the name it connects \
                 to. If the domain name isn't on the certificate, add <code>--server</code> with \
                 the domain controller's full name to <code>run.sh</code>."
                    .to_string(),
            );
        }

        let pick = |given: &Option<String>,
                    valid: &dyn Fn(&str) -> bool,
                    default: String,
                    problem: &str,
                    errors: &mut Vec<String>| {
            match given.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(v) if valid(v) => v.to_string(),
                Some(_) => {
                    errors.push(problem.to_string());
                    default
                }
                None => default,
            }
        };
        let folder = if linux {
            pick(
                &p.folder,
                &valid_linux_folder,
                match &env {
                    Some(id) => format!("/opt/pathwarden/{id}"),
                    None => "/opt/pathwarden".into(),
                },
                BAD_LINUX_FOLDER,
                &mut errors,
            )
        } else {
            pick(
                &p.folder
                    .as_ref()
                    .map(|f| f.trim().trim_end_matches('\\').to_string()),
                &valid_windows_folder,
                match &env {
                    Some(id) => format!(r"C:\Pathwarden\{id}"),
                    None => r"C:\Pathwarden".into(),
                },
                BAD_WINDOWS_FOLDER,
                &mut errors,
            )
        };
        let netbios = d.netbios.clone().unwrap_or_else(|| {
            domain
                .split('.')
                .next()
                .unwrap_or("SCALE")
                .to_ascii_uppercase()
        });
        let account = pick(
            &p.account,
            &valid_gmsa,
            format!("{netbios}\\svc-pathwarden$"),
            BAD_GMSA,
            &mut errors,
        );
        // In the order of the form, so the error list reads the same way.
        let user = pick(
            &p.user,
            &valid_user,
            "svc-pathwarden".into(),
            BAD_USER,
            &mut errors,
        );
        let at = pick(&p.at, &valid_time, "02:00".into(), BAD_TIME, &mut errors);
        let target = Target {
            linux,
            run: src.run,
            domain,
            extra_domains,
            server,
            // Linux binds with a password, which needs LDAPS.
            ldaps: linux || info.is_some_and(|i| i.ldaps),
            sharphound,
            full,
            folder,
            account,
            at,
            user,
            notes,
            env,
        };
        (target, errors)
    }

    /// The query string that reproduces these settings (for links).
    pub fn query(&self, os_override: Option<bool>) -> String {
        let linux = os_override.unwrap_or(self.linux);
        let mut q = vec![format!("os={}", if linux { "linux" } else { "windows" })];
        if let Some(run) = &self.run {
            q.push(format!("run={}", encode(run)));
        }
        // The time carries over to the other system; the folder and the
        // account are each system's own.
        q.push(format!("at={}", encode(&self.at)));
        if os_override.is_none() || os_override == Some(self.linux) {
            q.push(format!("folder={}", encode(&self.folder)));
            if linux {
                q.push(format!("user={}", encode(&self.user)));
            } else {
                q.push(format!("account={}", encode(&self.account)));
            }
        }
        q.join("&")
    }

    /// A downloadable file by name; `None` for any other name.
    pub fn file(&self, name: &str) -> Option<String> {
        let unit = self.unit();
        match (self.linux, name) {
            (false, "run.ps1") => Some(self.run_ps1().replace('\n', "\r\n")),
            (true, "run.sh") => Some(self.run_sh()),
            (true, n) if n == format!("{unit}.service") => Some(self.service()),
            (true, n) if n == format!("{unit}.timer") => Some(self.timer()),
            _ => None,
        }
    }

    /// The Windows scheduled task's name: `Pathwarden`, or
    /// `Pathwarden-<environment>`.
    pub fn task_name(&self) -> String {
        match &self.env {
            Some(id) => format!("Pathwarden-{id}"),
            None => "Pathwarden".into(),
        }
    }

    /// The systemd units' name: `pathwarden`, or `pathwarden-<environment>`.
    pub fn unit(&self) -> String {
        match &self.env {
            Some(id) => format!("pathwarden-{id}"),
            None => "pathwarden".into(),
        }
    }

    /// Linux: where the password and `pathwarden.toml` live.
    pub fn etc_dir(&self) -> String {
        match &self.env {
            Some(id) => format!("/etc/pathwarden/{id}"),
            None => "/etc/pathwarden".into(),
        }
    }

    /// Linux: the service's state directory, under `/var/lib`.
    fn state_directory(&self) -> String {
        match &self.env {
            Some(id) => format!("pathwarden/{id}"),
            None => "pathwarden".into(),
        }
    }

    /// Linux: where the history and the report are written.
    pub fn var_dir(&self) -> String {
        format!("/var/lib/{}", self.state_directory())
    }

    /// Every domain the nightly run collects, the run's own first.
    pub fn domains(&self) -> Vec<&str> {
        std::iter::once(self.domain.as_str())
            .chain(self.extra_domains.iter().map(String::as_str))
            .collect()
    }

    /// The Linux bind account. With several domains an unqualified name is
    /// qualified with the run's domain, where the account lives: otherwise
    /// each collection would look for it in the domain it reads.
    fn bind_user(&self) -> String {
        if self.extra_domains.is_empty() || self.user.contains(['@', '\\']) {
            self.user.clone()
        } else {
            format!("{}@{}", self.user, self.domain)
        }
    }

    /// `pathwarden collect` arguments (after the program) for `domain`.
    /// Groups of (option, value) for one line each; values already quoted.
    fn collect_args(
        &self,
        domain: &str,
        out: &str,
        quote: fn(&str) -> String,
    ) -> Vec<(&'static str, Option<String>)> {
        let mut a = vec![("--domain", Some(quote(domain)))];
        // The chosen DC serves the run's own domain only.
        if let Some(s) = self.server.as_ref().filter(|_| domain == self.domain) {
            a.push(("--server", Some(quote(s))));
        }
        if self.ldaps {
            a.push(("--ldaps", None));
        }
        if self.linux {
            a.push(("--user", Some(quote(&self.bind_user()))));
        }
        a.push(("--out", Some(out.to_string())));
        if self.sharphound {
            // A full path: `pathwarden collect` never looks in the current
            // folder. SharpHound runs on Windows only, so this is
            // run.ps1's, where `$folder` is the install folder.
            a.push((
                "--sharphound",
                Some(format!("(Join-Path $folder {})", quote("SharpHound.exe"))),
            ));
            if !self.full {
                a.push(("--scope", Some(quote("dc-only"))));
            }
        } else if self.full {
            a.push(("--scope", Some(quote("all"))));
        }
        a
    }

    /// The arguments as a PowerShell array, one option per line.
    fn ps_args(&self, domain: &str, out: &str) -> String {
        self.collect_args(domain, out, ps)
            .into_iter()
            .map(|(opt, v)| match v {
                Some(v) => format!("    {}, {v}", ps(opt)),
                None => format!("    {}", ps(opt)),
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The arguments for a shell command, one option per continued line.
    fn sh_args(&self, domain: &str, out: &str) -> String {
        self.collect_args(domain, out, sh)
            .into_iter()
            .map(|(opt, v)| match v {
                Some(v) => format!("{opt} {v}"),
                None => opt.to_string(),
            })
            .collect::<Vec<_>>()
            .join(" \\\n    ")
    }

    /// The `pathwarden collect` calls in `run.ps1`, inside its `try`. One
    /// domain collects straight into `$collect`; several each into their own
    /// subfolder of it (`pathwarden run -i` reads subfolders too).
    fn ps_collects(&self) -> String {
        let domains = self.domains();
        if domains.len() == 1 {
            return format!(
                "    $collectArgs = @(\n{}\n    )\n    \
                 Invoke-PathwardenLogged {{ .\\pathwarden.exe collect @collectArgs }}\n    \
                 if ($LASTEXITCODE -ne 0) {{ throw \"pathwarden collect failed (exit code $LASTEXITCODE)\" }}\n",
                indent(&self.ps_args(&self.domain, "$collect"), "    ")
            );
        }
        domains
            .iter()
            .map(|d| {
                let out = format!("(Join-Path $collect {})", ps(d));
                format!(
                    "    # {d}\n    Write-PathwardenLog {said}\n    $collectArgs = @(\n{}\n    )\n    \
                     Invoke-PathwardenLogged {{ .\\pathwarden.exe collect @collectArgs }}\n    \
                     if ($LASTEXITCODE -ne 0) {{ throw \"pathwarden collect failed for {d} (exit code $LASTEXITCODE)\" }}\n",
                    indent(&self.ps_args(d, &out), "    "),
                    said = ps(&format!("Collecting {d}")),
                )
            })
            .collect()
    }

    pub fn run_ps1(&self) -> String {
        format!(
            r#"# Pathwarden: nightly collection and analysis for {domains}.
# Generated by the Pathwarden UI. Collects into a temporary folder, analyzes
# it with `pathwarden run`, then deletes the collection (a full map of the
# domain) whatever happens.
$ErrorActionPreference = 'Stop'
$folder = {folder}
{guard}
# The task runs as a gMSA with wide rights: refuse to run anything that
# someone other than an administrator could have changed.
$self = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$problems = @(Find-PathwardenWriters $folder @($self)) + @(Find-PathwardenParentWriters $folder)
if ($problems.Count -gt 0) {{
    throw ("Refusing to run: these could be changed by someone other than an administrator. Run the folder setup again.`n" + ($problems -join "`n"))
}}
Set-Location -LiteralPath $folder
# A log per run in {logs} (the newest {kept} are kept): what Pathwarden
# prints and why a run failed. Nothing secret: the task signs in as the
# gMSA, and Pathwarden hides passwords from its output. A refusal above is
# not logged (the folder can't be trusted); run the folder setup to see it.
$log = $null
{log_fns}
try {{
    $logs = Join-Path $folder {logs_ps}
    New-Item -ItemType Directory -Force -Path $logs | Out-Null
    @(Get-ChildItem -LiteralPath $logs -Filter 'pathwarden-*.log' -File | Sort-Object Name -Descending | Select-Object -Skip {older}) | Remove-Item -Force
    $log = Join-Path $logs ('pathwarden-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
}} catch {{}}
Write-PathwardenLog "Started as $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
# A name nobody can guess, so nobody can create it (or a link there) first,
# even when this account's temp folder is the shared C:\Windows\Temp.
$collect = Join-Path $env:TEMP ('pathwarden-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $collect) {{ throw "Refusing to collect into $collect`: it already exists" }}
# Not created here: `pathwarden collect` creates its output folder with its
# own permissions (this account, Administrators and SYSTEM only).
$config = @()
if (Test-Path -LiteralPath '.\pathwarden.toml') {{ $config = @('-c', '.\pathwarden.toml') }}
# Marks the run as scheduled in the history, so the UI shows it as such.
$env:PATHWARDEN_SCHEDULED = '1'
try {{
{collects}    Invoke-PathwardenLogged {{ .\pathwarden.exe run -i $collect @config --report '.\reports\latest.html' }}
    if ($LASTEXITCODE -ne 0) {{ throw "pathwarden run failed (exit code $LASTEXITCODE)" }}
    Write-PathwardenLog 'Finished'
}} catch {{
    Write-PathwardenLog ('Failed: ' + $_.Exception.Message)
    throw
}} finally {{
    Remove-Item -LiteralPath $collect -Recurse -Force -ErrorAction SilentlyContinue
}}
"#,
            domains = self.domains().join(", "),
            folder = ps(&self.folder),
            guard = ACL_GUARD_PS,
            logs = LOG_FOLDER,
            logs_ps = ps(LOG_FOLDER),
            kept = LOGS_KEPT,
            older = LOGS_KEPT - 1,
            log_fns = LOG_PS,
            collects = self.ps_collects(),
        )
    }

    /// Locks the folder down for the task (as an administrator, run again
    /// at any time: it rebuilds the permissions and checks them).
    ///
    /// Without this, a folder made under `C:\` inherits the drive's ACL
    /// (Authenticated Users: Modify on Windows 10/11, Users: create files on
    /// Server), so any local user could replace `run.ps1` or a program, or
    /// plant a DLL next to one, and run code as the gMSA. The folder's
    /// inheritance is cut and its owner set to Administrators: Administrators
    /// and SYSTEM get full control, the gMSA read and execute, and only
    /// `reports` and the state folder are writable by the gMSA.
    ///
    /// It runs before anything is copied in: a missing folder is created
    /// with that ACL already on it, so nobody else can put a file there
    /// first. An existing folder is never adopted if someone other than an
    /// administrator could have changed it or anything in it (a file they
    /// replaced would otherwise become Administrators-owned and pass the
    /// guard), nor if it or anything in it is a junction or symbolic link.
    /// Nothing is changed before those checks pass.
    pub fn acl_command(&self) -> String {
        format!(
            r#"$ErrorActionPreference = 'Stop'
$folder = {folder}
$gmsa   = {account}
$sid    = (New-Object System.Security.Principal.NTAccount($gmsa)).Translate([System.Security.Principal.SecurityIdentifier]).Value
$me     = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
{guard}
# The folders above: whoever can rename or replace $folder could swap in their own.
$above = @(Find-PathwardenParentWriters $folder)
if ($above.Count -gt 0) {{ throw ("A folder above $folder can be changed by someone other than an administrator, or is a link. Move the task folder, or let only administrators change these:`n" + ($above -join "`n")) }}
# A fresh ACL on the folder: owned by Administrators, nothing inherited from the drive.
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')
# OWNER RIGHTS: whoever owns a file gets no hidden right to change its permissions.
foreach ($grant in @(@('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'), @($sid, 'ReadAndExecute'), @('S-1-3-4', 'ReadAndExecute'))) {{
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.SecurityIdentifier]$grant[0], $grant[1], 'ContainerInherit, ObjectInherit', 'None', 'Allow')))
}}
# A new folder is created with that ACL, so nobody else can put anything in it first.
if (-not (Test-Path -LiteralPath $folder)) {{ [void][System.IO.Directory]::CreateDirectory($folder, $acl) }}
# Never adopt what someone else could have changed: their files would become Administrators' own.
$before = @(Find-PathwardenWriters $folder @($sid) @($me) -Deep)
if ($before.Count -gt 0) {{ throw ("Not adopting $folder`: someone other than an administrator could have changed what is listed below, so it can't be trusted. Delete what is listed (or rename the folder to start over), run this again, then copy Pathwarden in again:`n" + ($before -join "`n")) }}
# Its permissions and owners are replaced: never on a folder that isn't the task's own.
$children = @(Get-ChildItem -LiteralPath $folder -Force)
if ($children.Count -gt 0 -and @($children | Where-Object {{ @('pathwarden.exe', 'run.ps1', 'reports', '{state}') -contains $_.Name }}).Count -eq 0) {{
    throw "$folder isn't empty and has no Pathwarden in it: give the task a new folder of its own."
}}
Set-Acl -LiteralPath $folder -AclObject $acl
New-Item -ItemType Directory -Force -Path "$folder\reports", "$folder\{state}" | Out-Null
# Everything inside: owned by Administrators, only the inherited permissions.
icacls "$folder\*" /reset /T /C /Q
icacls $folder /setowner '*S-1-5-32-544' /T /C /Q
# The gMSA writes reports (run logs in reports\logs too) and the run history, nothing else.
icacls "$folder\reports" /grant "*${{sid}}:(OI)(CI)M" /C /Q
icacls "$folder\{state}" /grant "*${{sid}}:(OI)(CI)M" /C /Q
$problems = @(Find-PathwardenWriters $folder @($sid)) + @(Find-PathwardenParentWriters $folder)
if ($problems.Count -gt 0) {{ throw ("Still writable by others:`n" + ($problems -join "`n")) }}
"Permissions OK: only Administrators and SYSTEM can change $folder; $gmsa can write reports and {state} only."
if (-not (Test-Path -LiteralPath "$folder\pathwarden.exe")) {{
    "Now copy Pathwarden and run.ps1 into $folder, then run this again to check them."
}} elseif ((Test-Path -LiteralPath "$folder\{state}\.pathwarden-encryption") -and -not (Test-Path -LiteralPath "$folder\{state}.passphrase.$sid.dpapi")) {{
    # An encrypted history: its passphrase, stored once for the gMSA only (DPAPI-NG).
    Push-Location $folder
    try {{ & "$folder\pathwarden.exe" history storage passphrase set -c "$folder\pathwarden.toml" --for-account $gmsa }} finally {{ Pop-Location }}
}}
"#,
            folder = ps(&self.folder),
            account = ps(&self.account),
            state = STATE_FOLDER,
            guard = ACL_GUARD_PS,
        )
    }

    /// The gMSA's short name, for `Test-ADServiceAccount`.
    pub fn gmsa_name(&self) -> &str {
        let name = self.account.rsplit('\\').next().unwrap_or(&self.account);
        name.strip_suffix('$').unwrap_or(name)
    }

    pub fn gmsa_check(&self) -> String {
        format!(
            "Install-ADServiceAccount -Identity {name}\nTest-ADServiceAccount -Identity {name}   # should print True",
            name = ps(self.gmsa_name())
        )
    }

    pub fn register_command(&self) -> String {
        let script = format!(
            r#"-NoProfile -ExecutionPolicy Bypass -File "{}\run.ps1""#,
            self.folder
        );
        format!(
            "$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument {arg} -WorkingDirectory {folder}\n\
             $trigger   = New-ScheduledTaskTrigger -Daily -At {at}\n\
             $principal = New-ScheduledTaskPrincipal -UserId {account} -LogonType Password\n\
             Register-ScheduledTask -TaskName {task} -Action $action -Trigger $trigger -Principal $principal",
            task = ps(&self.task_name()),
            arg = ps(&script),
            folder = ps(&self.folder),
            at = ps(&self.at),
            account = ps(&self.account),
        )
    }

    pub fn test_command(&self) -> String {
        format!(
            "Start-ScheduledTask -TaskName {task}\n\
             Get-ScheduledTaskInfo -TaskName {task}   # LastTaskResult 0 means it worked\n\
             Get-ChildItem -LiteralPath {logs} -Filter 'pathwarden-*.log' | Sort-Object Name | Select-Object -Last 1 | Get-Content   # the latest run's log, so far",
            task = ps(&self.task_name()),
            logs = ps(&self.log_dir()),
        )
    }

    /// Where `run.ps1` writes its logs.
    pub fn log_dir(&self) -> String {
        format!("{}\\{LOG_FOLDER}", self.folder.trim_end_matches('\\'))
    }

    /// The `pathwarden collect` calls in `run.sh` (see [`Self::ps_collects`]).
    fn sh_collects(&self) -> String {
        let domains = self.domains();
        let one = |d: &str, out: &str| {
            format!(
                "PATHWARDEN_COLLECT_PASSWORD=$(cat \"$CREDENTIALS_DIRECTORY/collect-password\") \\\n  \
                 {}/pathwarden collect \\\n    {}\n",
                self.folder,
                self.sh_args(d, out)
            )
        };
        if domains.len() == 1 {
            return one(&self.domain, "\"$collect\"");
        }
        domains
            .iter()
            .map(|d| format!("# {d}\n{}", one(d, &format!("\"$collect/{d}\""))))
            .collect()
    }

    pub fn run_sh(&self) -> String {
        format!(
            r#"#!/bin/sh
# Pathwarden: nightly collection and analysis for {domains}.
# Generated by the Pathwarden UI. Collects into a temporary folder, analyzes
# it with `pathwarden run`, then deletes the collection (a full map of the
# domain) whatever happens. The password comes from the systemd credential
# collect-password and is never written to a file by this script.
set -eu
umask 077
# Marks the run as scheduled in the history, so the UI shows it as such.
export PATHWARDEN_SCHEDULED=1
collect=$(mktemp -d)
trap 'rm -rf "$collect"' EXIT
{collects}mkdir -p reports
if [ -f {etc}/pathwarden.toml ]; then
  {folder}/pathwarden run -i "$collect" -c {etc}/pathwarden.toml --report reports/latest.html
else
  {folder}/pathwarden run -i "$collect" --report reports/latest.html
fi
"#,
            domains = self.domains().join(", "),
            folder = self.folder,
            etc = self.etc_dir(),
            collects = self.sh_collects(),
        )
    }

    pub fn service(&self) -> String {
        format!(
            "[Unit]\n\
             Description=Pathwarden nightly collection and analysis\n\
             Wants=network-online.target\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             Type=oneshot\n\
             User=pathwarden\n\
             StateDirectory={state}\n\
             StateDirectoryMode=0700\n\
             UMask=0077\n\
             WorkingDirectory={var}\n\
             LoadCredential=collect-password:{etc}/collect-password\n\
             ExecStart={folder}/run.sh\n",
            state = self.state_directory(),
            var = self.var_dir(),
            etc = self.etc_dir(),
            folder = self.folder
        )
    }

    pub fn timer(&self) -> String {
        format!(
            "[Unit]\n\
             Description=Run Pathwarden every night\n\
             \n\
             [Timer]\n\
             OnCalendar=*-*-* {}:00\n\
             Persistent=true\n\
             \n\
             [Install]\n\
             WantedBy=timers.target\n",
            self.at
        )
    }

    pub fn linux_setup(&self) -> String {
        format!(
            "sudo useradd --system --no-create-home --shell /usr/sbin/nologin pathwarden\n\
             sudo install -d -m 700 {etc}\n\
             sudo sh -c 'umask 077; cat > {etc}/collect-password'   # type the password, Enter, then Ctrl+D\n\
             sudo chown -R root:root {folder}\n\
             sudo chmod -R go-w {folder}\n\
             sudo chmod 755 {folder} {folder}/run.sh {folder}/pathwarden\n\
             sudo cp {unit}.service {unit}.timer /etc/systemd/system/\n\
             sudo systemctl daemon-reload\n\
             sudo systemctl enable --now {unit}.timer",
            folder = self.folder,
            etc = self.etc_dir(),
            unit = self.unit(),
        )
    }

    pub fn linux_test(&self) -> String {
        format!(
            "sudo systemctl start {unit}.service\njournalctl -u {unit}.service -e",
            unit = self.unit()
        )
    }

    /// What an administrator does, in order: the Schedule page shows these,
    /// and `pathwarden schedule` prints them and writes their code blocks.
    pub fn steps(&self) -> Vec<Step> {
        let block = |id, label: &str, file: String, text: String, download| Block {
            id,
            label: label.to_string(),
            file,
            text,
            download,
        };
        if self.linux {
            let (service, timer) = (
                format!("{}.service", self.unit()),
                format!("{}.timer", self.unit()),
            );
            vec![
                Step {
                    title: "Copy Pathwarden to the server",
                    text: format!(
                        "Copy the Linux <code>pathwarden</code> program into <code>{}</code> on a server that can reach your domain controllers. If you set up rules or zones, copy this environment's <code>pathwarden.toml</code> to <code>{}/</code>.",
                        esc(&self.folder),
                        esc(&self.etc_dir())
                    ),
                    blocks: vec![],
                },
                Step {
                    title: "Save run.sh",
                    text: format!(
                        "It collects into a temporary folder, analyzes, and deletes the collection, even when something fails. Save it as <code>{}/run.sh</code>.",
                        esc(&self.folder)
                    ),
                    blocks: vec![block("code-run", "run.sh", "run.sh".into(), self.run_sh(), true)],
                },
                Step {
                    title: "Save the service and the timer",
                    text: "The service runs the script as a <code>pathwarden</code> system user and hands it the password as a systemd credential, so the password is never in the script or the unit.".into(),
                    blocks: vec![
                        block("code-service", &service, service.clone(), self.service(), true),
                        block("code-timer", &timer, timer.clone(), self.timer(), true),
                    ],
                },
                Step {
                    title: "Turn it on",
                    text: format!(
                        "Run these as root in the folder with the two unit files. The password is the one for <code>{}</code>; it is stored readable by root only.",
                        esc(&self.user)
                    ),
                    blocks: vec![block("code-setup", "Commands", "setup.sh".into(), self.linux_setup(), false)],
                },
                Step {
                    title: "Try it once",
                    text: format!(
                        "Start a run now and watch its output. The report is written to <code>{}/reports/latest.html</code>.",
                        esc(&self.var_dir())
                    ),
                    blocks: vec![block("code-test", "Commands", "test.sh".into(), self.linux_test(), false)],
                },
            ]
        } else {
            let admin = "PowerShell (as administrator)";
            let copy = if self.sharphound {
                "Copy <code>pathwarden.exe</code> and <code>SharpHound.exe</code>"
            } else {
                "Copy <code>pathwarden.exe</code>"
            };
            vec![
                Step {
                    title: "Prepare the gMSA and the folder",
                    text: format!(
                        "The task runs as <code>{}</code>, so no password is stored anywhere. If it doesn't exist yet, a domain admin creates it and allows this server to use it (see Running on a schedule in the documentation). Then, on a domain-joined server, check it works and create the folder, before you copy anything there. A folder made under <code>C:\\</code> lets every local user change it, and whatever they put there would run as the gMSA. The second block creates <code>{}</code> so that only administrators can change it; the gMSA can read it and write only to <code>reports</code> and <code>pathwarden-state</code>. It refuses a folder that already exists if someone else could have changed it, and a junction or link. You can run it again at any time, for example after copying in a new <code>pathwarden.exe</code>. <code>run.ps1</code> refuses to run if anyone else can change the folder.",
                        esc(&self.account),
                        esc(&self.folder)
                    ),
                    blocks: vec![
                        block("code-gmsa", admin, "check-gmsa.ps1".into(), self.gmsa_check(), false),
                        block("code-acl", admin, "setup-folder.ps1".into(), self.acl_command(), false),
                    ],
                },
                Step {
                    title: "Copy Pathwarden to the server",
                    text: format!(
                        "{copy} into <code>{}</code>. If you set up rules or zones, copy this environment's <code>pathwarden.toml</code> (its path is on Settings) there too.",
                        esc(&self.folder)
                    ),
                    blocks: vec![],
                },
                Step {
                    title: "Save run.ps1",
                    text: format!(
                        "It collects into a temporary folder, analyzes, and deletes the collection, even when something fails. Save it as <code>{}\\run.ps1</code>, then run the folder setup again to check what you copied.",
                        esc(&self.folder)
                    ),
                    blocks: vec![block("code-run", "run.ps1", "run.ps1".into(), self.run_ps1(), true)],
                },
                Step {
                    title: "Register the task",
                    text: format!(
                        "Run this in PowerShell as an administrator. It runs <code>run.ps1</code> every day at {}.",
                        esc(&self.at)
                    ),
                    blocks: vec![block("code-register", admin, "register-task.ps1".into(), self.register_command(), false)],
                },
                Step {
                    title: "Try it once",
                    text: format!(
                        "Start it now. The report is written to <code>{}\\reports\\latest.html</code>, and each run's output, and why it failed if it did, to a log in <code>{}</code> (the last {} are kept).",
                        esc(&self.folder),
                        esc(&self.log_dir()),
                        LOGS_KEPT
                    ),
                    blocks: vec![block("code-test", "PowerShell", "test-task.ps1".into(), self.test_command(), false)],
                },
            ]
        }
    }

    /// Every code block of [`Self::steps`] as a file, in order (what
    /// `pathwarden schedule` writes). A download is exactly what the
    /// Schedule page serves ([`Self::file`]); the other blocks are their
    /// text with a final newline, and CRLF line ends in `.ps1` files, as
    /// `run.ps1` has.
    pub fn files(&self) -> Vec<(String, String)> {
        self.steps()
            .into_iter()
            .flat_map(|s| s.blocks)
            .map(|b| {
                let text = match self.file(&b.file) {
                    Some(served) if b.download => served,
                    _ => {
                        let text = format!("{}\n", b.text);
                        if b.file.ends_with(".ps1") {
                            text.replace('\n', "\r\n")
                        } else {
                            text
                        }
                    }
                };
                (b.file, text)
            })
            .collect()
    }
}

/// One step of the schedule set-up.
#[derive(Debug, Clone)]
pub struct Step {
    pub title: &'static str,
    /// HTML: values escaped, `<code>` around names.
    pub text: String,
    /// The code to save or run in this step, in order.
    pub blocks: Vec<Block>,
}

/// A script or file of a [`Step`].
#[derive(Debug, Clone)]
pub struct Block {
    /// The element ID on the Schedule page.
    pub id: &'static str,
    /// The name above the code on the page.
    pub label: String,
    /// The file name `pathwarden schedule` writes it to (for a download,
    /// also the name the page serves it under).
    pub file: String,
    pub text: String,
    /// The page offers it as a download ([`Target::file`]).
    pub download: bool,
}

/// A step's text or a note for a terminal: the tags dropped and the
/// entities [`esc`] writes turned back into characters.
pub fn plain_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            c if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::CollectionInfo;

    fn summary(info: CollectionInfo) -> RunSummary {
        summary_of(info, &["CONTOSO.LOCAL"])
    }

    fn summary_of(info: CollectionInfo, domains: &[&str]) -> RunSummary {
        let json = serde_json::json!({
            "id": "20261009-020000-abcdef", "created_at": 0, "collected_at": null,
            "source": "x", "demo": false, "domains": domains, "objects": 0,
            "files": 1, "exposure_percent": 0.0, "exposed": 0, "population": 0,
            "protection_score": null, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "info": 0, "suppressed": 0, "plan_steps": 0, "pathwarden": "0.1.0",
            "collection": info,
        });
        serde_json::from_value(json).unwrap()
    }

    fn info(method: &str, scope: &str) -> CollectionInfo {
        CollectionInfo {
            read_started: None,
            method: method.into(),
            scope: scope.into(),
            domain: "contoso.local".into(),
            server: Some("dc01.contoso.local".into()),
            ldaps: true,
            current_user: true,
            warnings: vec![],
            kept: None,
            kerberos_only: None,
            smb_signing: None,
            domains: Vec::new(),
        }
    }

    fn windows() -> Params {
        Params {
            os: Some("windows".into()),
            ..Params::default()
        }
    }

    #[test]
    fn windows_script_follows_the_run() {
        let s = summary(info("builtin", "dc-only"));
        let (t, errors) = Target::resolve(&windows(), Some(&s), &Detected::default());
        assert!(errors.is_empty());
        let script = t.run_ps1();
        if BUILTIN {
            assert!(
                script.contains(
                    "    $collectArgs = @(\n        '--domain', 'contoso.local'\n        '--server', 'dc01.contoso.local'\n        '--ldaps'\n        '--out', $collect\n    )\n"
                ),
                "{script}"
            );
        } else {
            assert!(
                script.contains(
                    "'--sharphound', (Join-Path $folder 'SharpHound.exe')\n        '--scope', 'dc-only'\n    )"
                ),
                "{script}"
            );
        }
        // The guard runs before anything else in the folder.
        let guard = script.find("Find-PathwardenWriters $folder").unwrap();
        assert!(guard < script.find("Set-Location").unwrap(), "{script}");
        assert!(guard < script.find("pathwarden.exe collect").unwrap());
        assert!(script.contains("throw (\"Refusing to run"));
        assert!(
            script.contains("Invoke-PathwardenLogged { .\\pathwarden.exe collect @collectArgs }\n")
        );
        assert!(script.contains(
            "Invoke-PathwardenLogged { .\\pathwarden.exe run -i $collect @config --report '.\\reports\\latest.html' }\n"
        ));
        assert!(script.contains("Remove-Item -LiteralPath $collect"));
        // The log: in reports\logs, set up only once the guard passed, the
        // newest 30 kept, and a failure's message written before rethrowing.
        let log = script
            .find("$logs = Join-Path $folder 'reports\\logs'")
            .unwrap();
        assert!(guard < log && log < script.find("pathwarden.exe collect").unwrap());
        assert!(script.contains(
            "Sort-Object Name -Descending | Select-Object -Skip 29) | Remove-Item -Force"
        ));
        assert!(script.contains(
            "} catch {\n    Write-PathwardenLog ('Failed: ' + $_.Exception.Message)\n    throw\n} finally {"
        ));
        assert!(script.contains(LOG_PS));
        assert!(t.test_command().contains(
            "Get-ChildItem -LiteralPath 'C:\\Pathwarden\\reports\\logs' -Filter 'pathwarden-*.log'"
        ));
        assert!(script.is_ascii());
        let reg = t.register_command();
        assert!(
            reg.contains("-UserId 'CONTOSO\\svc-pathwarden$' -LogonType Password"),
            "{reg}"
        );
        assert!(reg.contains(r#"-File "C:\Pathwarden\run.ps1""#), "{reg}");
        assert!(t.file("run.ps1").unwrap().contains("\r\n"));
        assert!(t.file("../secret").is_none());
        assert!(t.file("run.sh").is_none());

        // A full built-in run is scheduled with SharpHound (a gMSA has no password).
        let s = summary(info("builtin", "all"));
        let (t, _) = Target::resolve(&windows(), Some(&s), &Detected::default());
        assert!(t.sharphound && t.full);
        assert!(t
            .run_ps1()
            .contains("'--sharphound', (Join-Path $folder 'SharpHound.exe')\n    )"));
        assert!(!t.notes.is_empty());
    }

    /// H1: the setup cuts inheritance from the drive, makes Administrators
    /// the owner, gives the gMSA read and execute on everything and Modify
    /// on `reports` and the state folder only, then verifies (so running it
    /// again repairs and re-checks the permissions).
    #[test]
    fn folder_setup_locks_the_folder_down() {
        let s = summary(info("builtin", "dc-only"));
        let (t, _) = Target::resolve(&windows(), Some(&s), &Detected::default());
        let acl = t.acl_command();
        assert!(acl.is_ascii());
        let order = [
            "$folder = 'C:\\Pathwarden'",
            "$gmsa   = 'CONTOSO\\svc-pathwarden$'",
            "function Find-PathwardenWriters",
            // Nothing is created or changed before the folders above pass.
            "$above = @(Find-PathwardenParentWriters $folder)",
            "if ($above.Count -gt 0) { throw",
            "$acl.SetAccessRuleProtection($true, $false)",
            "$acl.SetOwner([System.Security.Principal.SecurityIdentifier]'S-1-5-32-544')",
            "@(@('S-1-5-32-544', 'FullControl'), @('S-1-5-18', 'FullControl'), @($sid, 'ReadAndExecute'), @('S-1-3-4', 'ReadAndExecute'))",
            "'ContainerInherit, ObjectInherit', 'None', 'Allow'",
            // A new folder gets the ACL as it is created.
            "if (-not (Test-Path -LiteralPath $folder)) { [void][System.IO.Directory]::CreateDirectory($folder, $acl) }",
            // An existing one is checked, contents included, before anything changes.
            "$before = @(Find-PathwardenWriters $folder @($sid) @($me) -Deep)",
            "if ($before.Count -gt 0) { throw",
            "isn't empty and has no Pathwarden in it",
            "Set-Acl -LiteralPath $folder -AclObject $acl",
            "New-Item -ItemType Directory -Force -Path \"$folder\\reports\", \"$folder\\pathwarden-state\"",
            "icacls \"$folder\\*\" /reset /T /C /Q",
            "icacls $folder /setowner '*S-1-5-32-544' /T /C /Q",
            "icacls \"$folder\\reports\" /grant \"*${sid}:(OI)(CI)M\" /C /Q",
            "icacls \"$folder\\pathwarden-state\" /grant \"*${sid}:(OI)(CI)M\" /C /Q",
            "$problems = @(Find-PathwardenWriters $folder @($sid)) + @(Find-PathwardenParentWriters $folder)",
            "if ($problems.Count -gt 0) { throw",
            "Permissions OK",
            "history storage passphrase set",
        ];
        // The folder is never created with the drive's permissions.
        assert!(!acl.contains("-Path $folder,"), "{acl}");
        assert_eq!(acl.matches("New-Item").count(), 1, "{acl}");
        let mut at = 0;
        for want in order {
            let found = acl[at..]
                .find(want)
                .unwrap_or_else(|| panic!("missing or out of order: {want}\n{acl}"));
            at += found + want.len();
        }
        // The gMSA never gets more than read and execute on the folder itself,
        // and the old blanket Modify grant is gone.
        assert!(!acl.contains("(OI)(CI)M\" /C /Q\nicacls $folder"));
        assert!(!acl.contains(":(OI)(CI)M' "));
        assert_eq!(acl.matches("(OI)(CI)M").count(), 2, "{acl}");
        assert!(!acl.contains("/grant $folder"));
        // Only these principals are granted anything.
        for line in acl.lines().filter(|l| l.contains("/grant")) {
            assert!(line.contains("*${sid}:"), "{line}");
        }
        // The guard's writable folders are the ones the setup grants.
        assert!(ACL_GUARD_PS.contains(&format!("$writable = @('reports', '{STATE_FOLDER}')")));
        // run.ps1's logs go inside one of them, so the gMSA can write them
        // and the guard doesn't walk them.
        assert_eq!(LOG_FOLDER.split('\\').next(), Some("reports"));
        // A typed folder and account are quoted for PowerShell.
        let p = Params {
            folder: Some(r"D:\Tools\Path warden".into()),
            account: Some(r"CORP\gmsa-pw$".into()),
            ..windows()
        };
        let (t, errors) = Target::resolve(&p, None, &Detected::default());
        assert!(errors.is_empty(), "{errors:?}");
        let acl = t.acl_command();
        assert!(
            acl.contains("$folder = 'D:\\Tools\\Path warden'\n"),
            "{acl}"
        );
        assert!(acl.contains("$gmsa   = 'CORP\\gmsa-pw$'\n"), "{acl}");
        assert!(t.run_ps1().contains("$folder = 'D:\\Tools\\Path warden'\n"));
    }

    /// The guard flags write rights, foreign owners without OWNER RIGHTS, and
    /// lets the given SIDs write `reports` and the state folder only.
    #[test]
    fn acl_guard_checks_every_write_right() {
        let g = ACL_GUARD_PS;
        // WriteData|AppendData|WriteExtendedAttributes|DeleteSubdirectoriesAndFiles
        // |WriteAttributes|Delete|ChangePermissions|TakeOwnership|GenericAll|GenericWrite
        let mask = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000;
        let mask = mask | 0x1000_0000 | 0x4000_0000;
        assert_eq!(mask, 0x500D_0156);
        assert!(g.contains("$mask = 0x500D0156"));
        assert!(g.contains("$admins = @('S-1-5-32-544', 'S-1-5-18')"));
        assert!(g.contains("Writers = $admins + $Writers"));
        assert!(g.contains("-Recurse -Force"));
        assert!(g.contains("$rule.AccessControlType -eq 'Allow'"));
        assert!(g.contains("'S-1-3-4'"));
        assert!(g.contains("is owned by"));
        assert!(g.is_ascii());
    }

    /// Windows PowerShell parses every generated script, and the guard
    /// really finds a writable folder (a temp folder: the current user can
    /// write it) and accepts the writer it is told about.
    #[cfg(windows)]
    #[test]
    fn powershell_parses_the_scripts_and_the_guard_works() {
        let dir = std::env::temp_dir().join(format!("pw-sched-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("task").join("reports")).unwrap();
        std::fs::create_dir_all(dir.join("task").join("bin")).unwrap();
        std::fs::write(dir.join("task").join("bin").join("x.dll"), b"x").unwrap();
        let s = summary_of(
            info("builtin", "dc-only"),
            &["CONTOSO.LOCAL", "FABRIKAM.LOCAL"],
        );
        let (t, _) = Target::resolve(&windows(), Some(&s), &Detected::default());
        let files = [
            ("run.ps1", t.file("run.ps1").unwrap()),
            ("setup.ps1", t.acl_command()),
            ("register.ps1", t.register_command()),
            ("guard.ps1", ACL_GUARD_PS.to_string()),
        ];
        for (name, text) in &files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        let ps = |script: String| {
            // A PowerShell 7 parent (as on CI runners) leaves its module
            // path behind, and Windows PowerShell then can't load Get-Acl.
            pathwarden_core::spawn::quiet("powershell.exe")
                .env_remove("PSModulePath")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .expect("powershell runs")
        };
        for (name, _) in &files {
            let path = dir.join(name);
            let out = ps(format!(
                "$e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile('{}', [ref]$null, [ref]$e); if ($e.Count) {{ $e | ForEach-Object {{ $_.ToString() }}; exit 1 }}",
                path.display()
            ));
            assert!(
                out.status.success(),
                "{name}: {}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let task = dir.join("task");
        let out = ps(format!(
            ". '{guard}'; $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
             $all = @(Find-PathwardenWriters '{task}' @()); \
             $mine = @(Find-PathwardenWriters '{task}' @($me)); \
             \"me=$me\"; \"all=$($all.Count)\"; $all; \"mine=$($mine.Count)\"; $mine",
            guard = dir.join("guard.ps1").display(),
            task = task.display()
        ));
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let me = text
            .lines()
            .find_map(|l| l.strip_prefix("me="))
            .unwrap()
            .to_string();
        let all = text.split("mine=").next().unwrap();
        let mine = text.split("mine=").nth(1).unwrap();
        let sep = std::path::MAIN_SEPARATOR;
        let by_me = |lines: &str, item: &str| {
            lines.lines().any(|l| {
                l.trim_end()
                    .ends_with(&format!("{sep}{item} can be changed by {me}"))
            })
        };
        // Without trusted writers, the folder, a subfolder, a DLL in it and
        // `reports` are all flagged.
        for item in ["task", "bin", "x.dll", "reports"] {
            assert!(by_me(all, item), "{item} not flagged:\n{text}");
        }
        // Allowed to write `reports`, the same user is still flagged elsewhere.
        assert!(!by_me(mine, "reports"), "{text}");
        assert!(
            !mine.contains(&format!("reports is owned by {me}")),
            "{text}"
        );
        assert!(by_me(mine, "x.dll"), "{text}");
        assert!(by_me(mine, "task"), "{text}");

        // The folders above: the one this user made is flagged;
        // Windows' own, where users may only create folders, are not.
        let out = ps(format!(
            ". '{guard}'; @(Find-PathwardenParentWriters '{task}'); '---'; \
             @(Find-PathwardenParentWriters (Join-Path $env:SystemRoot 'System32\\drivers'))",
            guard = dir.join("guard.ps1").display(),
            task = task.display()
        ));
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let (mine, system) = text.split_once("---").unwrap();
        assert!(
            mine.lines()
                .any(|l| l.trim_end() == format!("{} can be changed by {me}", dir.display())),
            "{text}"
        );
        for everyone in ["S-1-5-11", "S-1-5-32-545", "S-1-1-0"] {
            assert!(!system.contains(everyone), "{everyone}: {text}");
        }

        // The log: a program's stdout and stderr both reach it, its exit
        // code stays in $LASTEXITCODE, and its stderr doesn't stop a script
        // that runs with 'Stop'.
        std::fs::write(dir.join("log.ps1"), LOG_PS).unwrap();
        let log = dir.join("run.log");
        let out = ps(format!(
            "$ErrorActionPreference = 'Stop'; $log = '{log}'; . '{fns}'; \
             Write-PathwardenLog 'Started'; \
             Invoke-PathwardenLogged {{ cmd /c 'echo to-stdout& echo to-stderr 1>&2& exit 3' }}; \
             \"code=$LASTEXITCODE\"",
            log = log.display(),
            fns = dir.join("log.ps1").display(),
        ));
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success() && text.contains("code=3"),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let logged = std::fs::read_to_string(&log).unwrap();
        for want in ["  Started", "  to-stdout", "  to-stderr"] {
            assert!(logged.contains(want), "{want}: {logged}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the guard checks, in real Windows PowerShell on folders this
    /// test makes: a junction as the task folder, inside it, above it or in
    /// `reports` (the setup's deep walk) is refused and not followed; an
    /// inherit-only OWNER RIGHTS entry leaves a foreign owner flagged, one
    /// that applies doesn't; a folder only administrators can change passes.
    /// The setup refuses before it creates anything, and `run.ps1` refuses a
    /// junction.
    #[cfg(windows)]
    #[test]
    fn the_guard_refuses_links_and_inherit_only_owner_rights() {
        const SCRIPT: &str = r#"$ErrorActionPreference = 'Stop'
$dir = '{DIR}'
. (Join-Path $dir 'guard.ps1')
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
"me=$me"
function Lock([string]$Path, $Grants) {
    $a = New-Object System.Security.AccessControl.DirectorySecurity
    $a.SetAccessRuleProtection($true, $false)
    foreach ($g in $Grants) {
        $a.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.SecurityIdentifier]$g[0], $g[1], 'ContainerInherit, ObjectInherit', $g[2], 'Allow')))
    }
    (Get-Item -LiteralPath $Path -Force).SetAccessControl($a)
}
function Show([string]$Name, $Lines) { "[$Name]"; $Lines; "[/$Name]" }
New-Item -ItemType Directory -Force -Path "$dir\real\inner" | Out-Null
Set-Content -LiteralPath "$dir\real\inner\hidden.ps1" -Value x
New-Item -ItemType Junction -Path "$dir\jtask" -Target "$dir\real" | Out-Null
New-Item -ItemType Directory -Path "$dir\task2" | Out-Null
New-Item -ItemType Junction -Path "$dir\task2\plugins" -Target "$dir\real\inner" | Out-Null
New-Item -ItemType Junction -Path "$dir\jparent" -Target "$dir\real" | Out-Null
New-Item -ItemType Directory -Force -Path "$dir\task3\reports" | Out-Null
New-Item -ItemType Junction -Path "$dir\task3\reports\out" -Target "$dir\real" | Out-Null
Show 'junction-task' @(Find-PathwardenWriters "$dir\jtask" @())
Show 'junction-inside' @(Find-PathwardenWriters "$dir\task2" @())
Show 'junction-above' @(Find-PathwardenParentWriters "$dir\jparent\inner")
Show 'reports-shallow' @(Find-PathwardenWriters "$dir\task3" @($me))
Show 'reports-deep' @(Find-PathwardenWriters "$dir\task3" @($me) -Deep)
New-Item -ItemType Directory -Path "$dir\owned-io", "$dir\owned-or", "$dir\good" | Out-Null
Set-Content -LiteralPath "$dir\good\pathwarden.exe" -Value x
$admins = @(@('S-1-5-32-544', 'FullControl', 'None'), @('S-1-5-18', 'FullControl', 'None'), @($me, 'ReadAndExecute', 'None'))
Lock "$dir\owned-io" ($admins + @(, @('S-1-3-4', 'ReadAndExecute', 'InheritOnly')))
Lock "$dir\owned-or" ($admins + @(, @('S-1-3-4', 'ReadAndExecute', 'None')))
Lock "$dir\good" $admins
Show 'owner-rights-inherit-only' @(Find-PathwardenWriters "$dir\owned-io" @())
Show 'owner-rights' @(Find-PathwardenWriters "$dir\owned-or" @())
Show 'good' @(Find-PathwardenWriters "$dir\good" @() @($me))
Show 'good-no-owner' @(Find-PathwardenWriters "$dir\good" @())
Lock "$dir\good" ($admins + @(, @($me, 'FullControl', 'None')))
"#;
        let dir = std::env::temp_dir().join(format!("pw-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("guard.ps1"), ACL_GUARD_PS).unwrap();
        let d = dir.display().to_string();
        std::fs::write(dir.join("test.ps1"), SCRIPT.replace("{DIR}", &d)).unwrap();
        let powershell = |file: &std::path::Path| {
            pathwarden_core::spawn::quiet("powershell.exe")
                .env_remove("PSModulePath")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(file)
                .output()
                .expect("powershell runs")
        };
        let out = powershell(&dir.join("test.ps1"));
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "{text}{err}");
        let me = text
            .lines()
            .find_map(|l| l.strip_prefix("me="))
            .unwrap()
            .trim()
            .to_string();
        let section = |name: &str| -> Vec<String> {
            let start = format!("[{name}]");
            let end = format!("[/{name}]");
            text.lines()
                .map(str::trim_end)
                .skip_while(|l| *l != start)
                .skip(1)
                .take_while(|l| *l != end)
                .map(str::to_string)
                .collect()
        };
        let link = |p: &str| format!("{d}\\{p} is a link (a junction or symbolic link)");
        // The junction itself is refused, and nothing behind it is read.
        let s = section("junction-task");
        assert_eq!(s, [link("jtask")], "{text}");
        let s = section("junction-inside");
        assert!(s.contains(&link("task2\\plugins")), "{text}");
        assert!(!s.iter().any(|l| l.contains("hidden.ps1")), "{text}");
        let s = section("junction-above");
        assert!(s.contains(&link("jparent")), "{text}");
        // In `reports` only the setup's deep walk finds it.
        assert!(
            !section("reports-shallow")
                .iter()
                .any(|l| l.contains("is a link")),
            "{text}"
        );
        assert!(
            section("reports-deep").contains(&link("task3\\reports\\out")),
            "{text}"
        );
        // OWNER RIGHTS for folders inside only: the owner can still change
        // the permissions.
        assert_eq!(
            section("owner-rights-inherit-only"),
            [format!("{d}\\owned-io is owned by {me}")],
            "{text}"
        );
        assert!(section("owner-rights").is_empty(), "{text}");
        // Only administrators and SYSTEM can change it: nothing to report
        // once its owner is accepted, and the owner is what is left.
        assert!(section("good").is_empty(), "{text}");
        let s = section("good-no-owner");
        assert!(s.contains(&format!("{d}\\good is owned by {me}")), "{text}");
        assert!(
            s.iter().all(|l| l.ends_with(&format!("is owned by {me}"))),
            "{text}"
        );

        // The setup, for a new folder here: it refuses at the folders
        // above (this user can change them) and creates nothing.
        let s = summary(info("builtin", "dc-only"));
        let (t, _) = Target::resolve(&windows(), Some(&s), &Detected::default());
        let new = format!("{d}\\newtask");
        let swap = |script: String, folder: &str| {
            let was = "$folder = 'C:\\Pathwarden'\n";
            assert!(script.contains(was));
            let script = script
                .replace(was, &format!("$folder = {}\n", ps(folder)))
                .replace(
                    "$gmsa   = 'CONTOSO\\svc-pathwarden$'",
                    "$gmsa   = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name",
                );
            assert!(!script.contains("C:\\Pathwarden"), "{script}");
            script
        };
        std::fs::write(dir.join("setup.ps1"), swap(t.acl_command(), &new)).unwrap();
        let out = powershell(&dir.join("setup.ps1"));
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!out.status.success(), "{all}");
        assert!(all.contains("A folder above"), "{all}");
        assert!(!std::path::Path::new(&new).exists());
        // run.ps1 on a junction: refused before anything runs.
        let run = t.file("run.ps1").unwrap().replace("\r\n", "\n");
        std::fs::write(
            dir.join("run.ps1"),
            swap(run, &format!("{d}\\jtask")).replace('\n', "\r\n"),
        )
        .unwrap();
        let out = powershell(&dir.join("run.ps1"));
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!out.status.success(), "{all}");
        assert!(all.contains("Refusing to run"), "{all}");
        assert!(all.contains("jtask is a link"), "{all}");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!dir.exists(), "test folder left behind: {}", dir.display());
    }

    /// P1: a forest run collects every domain, each into its own subfolder,
    /// with `--server` only for the domain it was chosen for.
    #[test]
    fn every_domain_of_the_run_is_collected() {
        let s = summary_of(
            info("builtin", "dc-only"),
            &["CONTOSO.LOCAL", "EMEA.CONTOSO.LOCAL", "FABRIKAM.LOCAL"],
        );
        let (t, errors) = Target::resolve(&windows(), Some(&s), &Detected::default());
        assert!(errors.is_empty());
        assert_eq!(
            t.domains(),
            ["contoso.local", "emea.contoso.local", "fabrikam.local"]
        );
        assert!(
            t.notes.iter().any(|n| n.contains("3 domains")),
            "{:?}",
            t.notes
        );
        let script = t.run_ps1();
        assert_eq!(
            script
                .matches(".\\pathwarden.exe collect @collectArgs")
                .count(),
            3
        );
        for d in t.domains() {
            assert!(
                script.contains(&format!("'--domain', '{d}'")),
                "{d}\n{script}"
            );
            assert!(
                script.contains(&format!("'--out', (Join-Path $collect '{d}')")),
                "{d}\n{script}"
            );
            assert!(script.contains(&format!("throw \"pathwarden collect failed for {d}")));
        }
        assert_eq!(script.matches("'--server'").count(), 1, "{script}");
        assert!(script
            .contains("'--domain', 'contoso.local'\n        '--server', 'dc01.contoso.local'"));
        // Every collection comes before the one analysis of them all.
        let run = script.find(".\\pathwarden.exe run -i $collect").unwrap();
        assert!(script.rfind("pathwarden.exe collect").unwrap() < run);
        assert_eq!(script.matches("pathwarden.exe run ").count(), 1);
        assert!(script.starts_with(
            "# Pathwarden: nightly collection and analysis for contoso.local, emea.contoso.local, fabrikam.local."
        ));

        // Linux: the same, and the bind account is qualified with the run's domain.
        let p = Params {
            os: Some("linux".into()),
            ..Params::default()
        };
        let (t, _) = Target::resolve(&p, Some(&s), &Detected::default());
        let run = t.run_sh();
        assert_eq!(run.matches("/pathwarden collect").count(), 3, "{run}");
        assert_eq!(run.matches("PATHWARDEN_COLLECT_PASSWORD=$(cat").count(), 3);
        for d in t.domains() {
            assert!(run.contains(&format!("--domain '{d}'")), "{run}");
            assert!(run.contains(&format!("--out \"$collect/{d}\"")), "{run}");
        }
        assert_eq!(
            run.matches("--user 'svc-pathwarden@contoso.local'").count(),
            3,
            "{run}"
        );
        assert_eq!(run.matches("--server").count(), 1);

        // Duplicates and the run's own domain are not collected twice.
        let s = summary_of(
            info("builtin", "dc-only"),
            &[
                "contoso.local",
                "CONTOSO.LOCAL",
                "bad domain!",
                "fabrikam.local",
            ],
        );
        let (t, _) = Target::resolve(&windows(), Some(&s), &Detected::default());
        assert_eq!(t.domains(), ["contoso.local", "fabrikam.local"]);
    }

    #[test]
    fn typed_values_are_checked() {
        let p = Params {
            os: Some("windows".into()),
            folder: Some(r"D:\Tools\Pathwarden\".into()),
            account: Some(r"CORP\gmsa-pw$".into()),
            at: Some("23:30".into()),
            ..Params::default()
        };
        let (t, errors) = Target::resolve(&p, None, &Detected::default());
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(t.folder, r"D:\Tools\Pathwarden");
        assert_eq!(t.account, r"CORP\gmsa-pw$");
        assert_eq!(t.at, "23:30");
        for bad in [
            Params {
                folder: Some("C:\\x'; rm".into()),
                ..windows()
            },
            Params {
                folder: Some("relative\\dir".into()),
                ..windows()
            },
            Params {
                account: Some("CORP\\user".into()),
                ..windows()
            },
            Params {
                account: Some("CORP\\x$'".into()),
                ..windows()
            },
            Params {
                at: Some("25:00".into()),
                ..windows()
            },
            Params {
                at: Some("2am".into()),
                ..windows()
            },
        ] {
            let (t, errors) = Target::resolve(&bad, None, &Detected::default());
            assert_eq!(errors.len(), 1, "{bad:?}");
            assert!(!t.register_command().contains("'; rm"));
        }
        // A drive or a folder Windows owns: the setup would replace its
        // permissions and owners.
        for system in [
            r"C:\",
            r"D:\\",
            r"C:\Windows",
            r"c:\WINDOWS\Temp\pw",
            r"C:\Program Files",
            r"C:\Program Files (x86)\Pathwarden",
            r"C:\ProgramData",
            r"C:\Users",
            r"C:\Users\Public\pw",
            r"C:\Windows.\x",
        ] {
            assert!(!valid_windows_folder(system), "{system}");
            let p = Params {
                folder: Some(system.into()),
                ..windows()
            };
            assert_eq!(invalid_fields(&p), [("folder", BAD_WINDOWS_FOLDER)]);
        }
        for fine in [
            r"C:\Pathwarden",
            r"D:\Tools\Pathwarden",
            r"C:\Windowsx",
            r"E:\Users2",
        ] {
            assert!(valid_windows_folder(fine), "{fine}");
        }
        // The errors read in the order of the form: on Linux, "Sign in as"
        // is above the time.
        let p = Params {
            os: Some("linux".into()),
            folder: Some("relative/dir".into()),
            user: Some("bad user!".into()),
            at: Some("99:00".into()),
            ..Params::default()
        };
        let (_, errors) = Target::resolve(&p, None, &Detected::default());
        let fields = invalid_fields(&p);
        assert_eq!(
            fields.iter().map(|(f, _)| *f).collect::<Vec<_>>(),
            ["folder", "user", "at"]
        );
        let messages: Vec<&str> = errors
            .iter()
            .map(String::as_str)
            .filter(|e| fields.iter().any(|(_, m)| m == e))
            .collect();
        assert_eq!(
            messages,
            fields.iter().map(|(_, m)| *m).collect::<Vec<_>>(),
            "{errors:?}"
        );
    }

    /// `pathwarden schedule` gets the same files as the page does for a run
    /// collected the same way.
    #[test]
    fn the_command_line_matches_a_run() {
        let s = summary_of(
            info("builtin", "dc-only"),
            &["CONTOSO.LOCAL", "FABRIKAM.LOCAL"],
        );
        let spec = Spec {
            domains: vec!["Contoso.local".into(), "fabrikam.local".into()],
            server: Some("dc01.contoso.local".into()),
            ldaps: true,
            ..Spec::default()
        };
        for os in ["windows", "linux"] {
            let p = Params {
                os: Some(os.into()),
                ..Params::default()
            };
            let (page, errors) = Target::resolve(&p, Some(&s), &Detected::default());
            assert!(errors.is_empty());
            // Linux always uses LDAPS, so --ldaps is only for Windows.
            let spec = Spec {
                ldaps: os == "windows",
                ..spec.clone()
            };
            let (cli, errors) = Target::for_command_line(&p, &spec);
            assert!(errors.is_empty(), "{errors:?}");
            if !BUILTIN && os == "windows" {
                // The page schedules SharpHound in a build without the
                // built-in collector; the command line keeps its options.
                assert!(page.sharphound && !cli.sharphound);
                assert!(cli.notes.iter().any(|n| n.contains("--sharphound")));
                continue;
            }
            assert_eq!(page.files(), cli.files(), "{os}");
            assert_eq!(page.notes, cli.notes, "{os}");
        }
    }

    #[test]
    fn files_are_the_page_blocks() {
        for os in ["windows", "linux"] {
            let p = Params {
                os: Some(os.into()),
                ..Params::default()
            };
            let spec = Spec {
                domains: vec!["contoso.local".into()],
                env: Some("client-a".into()),
                ..Spec::default()
            };
            let (t, errors) = Target::for_command_line(&p, &spec);
            assert!(errors.is_empty(), "{errors:?}");
            let files = t.files();
            let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
            if os == "linux" {
                assert_eq!(
                    names,
                    [
                        "run.sh",
                        "pathwarden-client-a.service",
                        "pathwarden-client-a.timer",
                        "setup.sh",
                        "test.sh"
                    ]
                );
            } else {
                assert_eq!(
                    names,
                    [
                        "check-gmsa.ps1",
                        "setup-folder.ps1",
                        "run.ps1",
                        "register-task.ps1",
                        "test-task.ps1"
                    ]
                );
                assert!(t.register_command().contains("'Pathwarden-client-a'"));
            }
            let blocks: Vec<Block> = t.steps().into_iter().flat_map(|s| s.blocks).collect();
            for ((name, text), b) in files.iter().zip(&blocks) {
                if b.download {
                    assert_eq!(Some(text), t.file(name).as_ref(), "{name}");
                } else if name.ends_with(".ps1") {
                    assert_eq!(*text, format!("{}\n", b.text).replace('\n', "\r\n"));
                } else {
                    assert_eq!(*text, format!("{}\n", b.text));
                }
            }
        }
    }

    #[test]
    fn the_command_line_is_checked() {
        let win = windows();
        let linux = Params {
            os: Some("linux".into()),
            ..Params::default()
        };
        let one = |d: &str| Spec {
            domains: vec![d.into()],
            ..Spec::default()
        };
        let cases: Vec<(Params, Spec)> = vec![
            (win.clone(), Spec::default()),
            (win.clone(), one("bad domain")),
            (win.clone(), one("-x.local")),
            (
                win.clone(),
                Spec {
                    server: Some("dc01;calc".into()),
                    ..one("contoso.local")
                },
            ),
            (
                Params {
                    user: Some("svc".into()),
                    ..win.clone()
                },
                one("contoso.local"),
            ),
            (
                Params {
                    account: Some(r"CONTOSO\g$".into()),
                    ..linux.clone()
                },
                one("contoso.local"),
            ),
            (
                linux.clone(),
                Spec {
                    sharphound: true,
                    ..one("contoso.local")
                },
            ),
            (
                linux.clone(),
                Spec {
                    ldaps: true,
                    ..one("contoso.local")
                },
            ),
            (
                win.clone(),
                Spec {
                    env: Some("Client A".into()),
                    ..one("contoso.local")
                },
            ),
            (
                Params {
                    at: Some("24:00".into()),
                    ..win.clone()
                },
                one("contoso.local"),
            ),
        ];
        for (p, spec) in cases {
            let (_, errors) = Target::for_command_line(&p, &spec);
            assert_eq!(errors.len(), 1, "{p:?} {spec:?}: {errors:?}");
        }
        // Defaults come from the domain, not this computer.
        let (t, errors) = Target::for_command_line(&win, &one("north.contoso.local"));
        assert!(errors.is_empty());
        assert_eq!(t.account, r"NORTH\svc-pathwarden$");
        assert_eq!(t.folder, r"C:\Pathwarden");
        // The files don't depend on this build: only a note does.
        assert!(!t.sharphound);
        assert_eq!(t.notes.len(), usize::from(!BUILTIN), "{:?}", t.notes);
        // A Windows Full collection is SharpHound's.
        let (t, _) = Target::for_command_line(
            &win,
            &Spec {
                full: true,
                ..one("contoso.local")
            },
        );
        assert!(t.sharphound && t.notes.is_empty(), "{:?}", t.notes);
    }

    #[test]
    fn plain_text_drops_tags() {
        assert_eq!(
            plain_text("Save <code>C:\\a&amp;b</code> &lt;now&gt; &#39;x&#39; &quot;y&quot;"),
            "Save C:\\a&b <now> 'x' \"y\""
        );
    }

    #[test]
    fn linux_files() {
        let p = Params {
            os: Some("linux".into()),
            user: Some("svc-pw@contoso.local".into()),
            ..Params::default()
        };
        let s = summary(info("builtin", "all"));
        let (t, errors) = Target::resolve(&p, Some(&s), &Detected::default());
        assert!(errors.is_empty());
        let run = t.run_sh();
        assert!(
            run.contains(
                "--ldaps \\\n    --user 'svc-pw@contoso.local' \\\n    --out \"$collect\" \\\n    --scope 'all'\n"
            ),
            "{run}"
        );
        assert!(run.contains("trap 'rm -rf \"$collect\"' EXIT"));
        assert!(run.contains("set -eu\numask 077\n"));
        let service = t.service();
        assert!(service.contains("LoadCredential=collect-password:"));
        // H1: the report and state are readable by the service user only.
        assert!(
            service.contains("StateDirectory=pathwarden\nStateDirectoryMode=0700\nUMask=0077\n")
        );
        let setup = t.linux_setup();
        assert!(setup.contains("sudo chown -R root:root /opt/pathwarden\n"));
        assert!(setup.contains("sudo chmod -R go-w /opt/pathwarden\n"));
        assert!(t.timer().contains("OnCalendar=*-*-* 02:00:00"));
        assert!(t.file("pathwarden.timer").is_some());
        assert!(t.file("run.ps1").is_none());
        assert!(t.query(None).contains("user=svc-pw%40contoso.local"));
    }
}
