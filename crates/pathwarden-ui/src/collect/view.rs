//! The Collect pages: the wizard, the nightly schedule, and the note on the
//! run page. Same rail, cards and tokens as the rest of the app; the extra
//! styles are in `assets/collect.css`.

use std::fmt::Write;

use super::schedule::{Params, Target};
use super::{Detected, Prefill, BUILTIN};
use crate::jobs::Job;
use crate::pages::{esc, icon, shell, Ctx, Nav};
use crate::workspace::{CollectionInfo, RunSummary};

/// Icons the shared sprite does not have.
const SPRITE: &str = r##"<svg class="sprite" width="0" height="0" aria-hidden="true" focusable="false"><defs>
<symbol id="i-globe" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/></symbol>
<symbol id="i-layers" viewBox="0 0 64 64"><defs><mask id="mc-layers" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="32" cy="21" r="7" fill="#000"/></mask></defs><g mask="url(#mc-layers)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M32 9L56 21L32 33L8 21Z" stroke="currentColor"/><path d="M8 33L32 45L56 33" stroke="currentColor"/><path d="M8 44L32 56L56 44" stroke="currentColor"/></g></g><g stroke="none"><circle cx="32" cy="21" r="5" fill="currentColor"/></g></symbol>
<symbol id="i-plug" viewBox="0 0 64 64"><defs><mask id="mc-plug" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="22" cy="10" r="7.25" fill="#000"/><circle cx="42" cy="10" r="7.25" fill="#000"/><circle cx="32" cy="48" r="8.75" fill="#000"/></mask></defs><g mask="url(#mc-plug)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M22 10V27" stroke="currentColor"/><path d="M42 10V27" stroke="currentColor"/><path d="M15 27H49V31A17 17 0 0 1 15 31Z" stroke="currentColor"/><path d="M32 48V58" stroke="currentColor"/></g></g><g stroke="none"><circle cx="22" cy="10" r="5.25" fill="currentColor"/><circle cx="42" cy="10" r="5.25" fill="currentColor"/><circle cx="32" cy="48" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-clock" viewBox="0 0 64 64"><defs><mask id="mc-clock" maskUnits="userSpaceOnUse" x="-8" y="-8" width="80" height="80"><rect x="-8" y="-8" width="80" height="80" fill="#fff"/><circle cx="50.19" cy="22.5" r="7.25" fill="#000"/><circle cx="32" cy="12" r="8.75" fill="#000"/></mask></defs><g mask="url(#mc-clock)"><g fill="none" stroke-width="7" stroke-linecap="round" stroke-linejoin="miter" stroke-miterlimit="2.6"><path d="M50.19 22.5A21 21 0 1 1 32 12" stroke="currentColor"/><path d="M32 23V33H41" stroke="currentColor"/></g></g><g stroke="none"><circle cx="50.19" cy="22.5" r="5.25" fill="currentColor"/><circle cx="32" cy="12" r="6.75" fill="currentColor"/></g></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="8.5" y="8.5" width="11.5" height="11.5" rx="2"/><path d="M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5"/></symbol>
<symbol id="i-stop" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><rect x="9" y="9" width="6" height="6" rx="1"/></symbol>
<symbol id="i-back" viewBox="0 0 24 24"><path d="M20 12H5M10 7l-5 5 5 5"/></symbol>
<symbol id="i-windows" viewBox="0 0 24 24"><path d="M4 5.5 11 4.5v7H4zM13 4.2l7-1v8.3h-7zM4 13h7v7l-7-1zM13 13h7v8l-7-1z"/></symbol>
<symbol id="i-terminal" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M12.5 15H17"/></symbol>
</defs></svg>"##;

const DOCS_COLLECT: &str = "https://pathwarden.org/docs/collect.html#what-each-method-collects";
const SHARPHOUND_RELEASES: &str = "https://github.com/SpecterOps/SharpHound/releases";

const STEPS: [&str; 6] = ["Where", "Who", "How deep", "Check", "Collect", "Results"];

/// The head every Collect page adds to the shell's body.
fn head() -> String {
    format!(r#"<link rel="stylesheet" href="/static/collect.css">{SPRITE}"#)
}

/// A radio "card": a choice with a title, a line of explanation, and an
/// optional reason it is unavailable.
#[allow(clippy::too_many_arguments)]
fn choice(
    name: &str,
    value: &str,
    id: &str,
    checked: bool,
    disabled: Option<&str>,
    title: &str,
    text: &str,
    extra: &str,
) -> String {
    format!(
        r#"<label class="choice{dis}" id="{id}"><input type="radio" name="{name}" value="{value}"{chk}{dattr}><span class="c-mark" aria-hidden="true"></span><span class="c-body"><strong>{title}</strong><span>{text}</span>{extra}<span class="c-why"{why_hidden}>{why}</span></span></label>"#,
        dis = if disabled.is_some() { " disabled" } else { "" },
        chk = if checked { " checked" } else { "" },
        dattr = if disabled.is_some() { " disabled" } else { "" },
        why_hidden = if disabled.is_some() { "" } else { " hidden" },
        why = disabled.map(esc).unwrap_or_default(),
    )
}

fn field_error(id: &str) -> String {
    format!(r#"<p class="field-error" id="{id}-error" role="alert" hidden></p>"#)
}

/// Step 2's default and its explanation: "Use my Windows account" is chosen
/// only when it can work, that is when the signed-in account is a domain
/// account (or this build has no other way to sign in). Returns whether it
/// is the default, its line of text, and a note saying why it isn't.
fn who_defaults(d: &Detected, windows: bool) -> (bool, String, String) {
    if !windows {
        return (false, "Only on Windows.".into(), String::new());
    }
    // Without the built-in collector a password has no use (SharpHound
    // always runs as this account), so the account stays the default.
    let current_default = d.domain_account || !BUILTIN;
    let account = match (&d.account, d.domain_account) {
        (Some(a), true) => format!("You're signed in as {}. No password needed.", esc(a)),
        (Some(a), false) => format!(
            "You're signed in as {}, which isn't a domain account.",
            esc(a)
        ),
        (None, _) => "The account you're signed in with. No password needed.".into(),
    };
    let why = if d.domain_account {
        String::new()
    } else {
        let start = if current_default {
            "The account you're signed in with isn't a domain account, so Active Directory may not accept it."
        } else {
            "Pathwarden chose a user and password because the account you're signed in with isn't a domain account, so Active Directory won't accept it."
        };
        format!(
            r#"<p class="hint auth-why" id="auth-why">{start} It can still work if you started Pathwarden with <code>runas /netonly</code> as a domain user.</p>"#
        )
    };
    (current_default, account, why)
}

/// Step 1's hint under the domain, from what this computer says.
fn detected_hint(d: &Detected) -> String {
    match &d.domain {
        Some(dom) if d.domain_account => format!(
            "Filled in from the account you're signed in with, which is in <strong>{}</strong>.",
            esc(dom)
        ),
        Some(dom) => format!(
            "Filled in from this computer, which is joined to <strong>{}</strong>.",
            esc(dom)
        ),
        None if d.workgroup => "This computer isn't joined to a domain, so enter the domain's full DNS name, like scale.local. Ask your Active Directory team if you're not sure.".into(),
        None => "Its full DNS name, like scale.local. Ask your Active Directory team if you're not sure.".into(),
    }
}

pub fn wizard(
    ctx: &Ctx,
    d: &Detected,
    keep_default: bool,
    job: Option<Job>,
    pre: &Prefill,
) -> String {
    let windows = cfg!(windows);
    let mut b = head();
    let (job_id, job_json) = match &job {
        Some(j) => (
            esc(&j.id),
            crate::pages::json_attr(&serde_json::to_string(j).unwrap_or_default()),
        ),
        None => (String::new(), String::new()),
    };
    let _ = write!(
        b,
        r#"<div class="page-head glow-head"><div><h1 class="panel-title">Analyze</h1>
<p class="lead">Where does the data come from?</p></div></div>
{sources}
<p class="lead src-lead">Pathwarden reads your directory, then analyzes it, all on this computer. A few questions first.</p>
<div class="wiz-layout">
<div class="wizard" id="wizard" data-builtin="{builtin}" data-windows="{windows}" data-job="{job_id}" data-initial="{job_json}" data-pick="{pick}">
{stepper}
<form id="wiz-form" class="wiz-form" autocomplete="off" novalidate>
"#,
        builtin = u8::from(BUILTIN),
        windows = u8::from(windows),
        pick = crate::pages::json_attr(&serde_json::to_string(&pre.pick).unwrap_or_default()),
        stepper = crate::pages::stepper("wiz-progress", &STEPS, false),
        sources = crate::pages::source_switch(true),
    );

    // ---- 1. Where
    // A link's domain, or the environment's last run's, else what
    // this computer says.
    let domain_hint = match (&pre.domain, &pre.from_env) {
        (Some(_), Some(env)) => format!("Filled in from {}'s last run.", esc(env)),
        _ => detected_hint(d),
    };
    let domain_value = pre
        .domain
        .as_deref()
        .or(d.domain.as_deref())
        .unwrap_or_default();
    // The domain controller this computer signed in through serves its own
    // domain only.
    let dc_detected = d.dc.as_ref().filter(|_| {
        pre.domain.as_deref().is_none_or(|p| {
            d.domain
                .as_deref()
                .is_some_and(|o| o.eq_ignore_ascii_case(p))
        })
    });
    let mut dc_choices = String::new();
    if let Some(dc) = dc_detected {
        dc_choices.push_str(&choice(
            "dcmode",
            "detected",
            "dc-detected",
            true,
            None,
            &esc(dc),
            "The domain controller this computer signed in through.",
            "",
        ));
    }
    dc_choices.push_str(&choice(
        "dcmode",
        "auto",
        "dc-auto",
        dc_detected.is_none(),
        None,
        "Find through DNS",
        "Pathwarden looks up the domain's name in DNS when it checks the connection, and connects to the domain controller it finds.",
        "",
    ));
    dc_choices.push_str(&choice(
        "dcmode",
        "choose",
        "dc-choose",
        false,
        None,
        "I'll choose",
        "Enter a domain controller's full name.",
        "",
    ));
    let _ = write!(
        b,
        r##"<section class="wiz-step card" data-step="1" aria-labelledby="s1-title">
  <header class="ws-head"><span class="ws-ic">{i_globe}</span><div><h2 class="sub" id="s1-title" tabindex="-1">Where is your directory?</h2><p class="muted">Which Active Directory domain to read, and which domain controller to ask.</p></div></header>
  <div class="field">
    <label for="domain">Domain</label>
    <input type="text" id="domain" value="{domain}" placeholder="scale.local" spellcheck="false" autocapitalize="off" aria-describedby="domain-hint">
    <p class="hint" id="domain-hint">{domain_hint}</p>
    {domain_err}
  </div>
  <fieldset class="field">
    <legend>Domain controller</legend>
    <div class="choices" data-dc="{dc}">{dc_choices}</div>
    <div class="sub-field" id="server-field" hidden>
      <label class="sr-only" for="server">Domain controller name</label>
      <input type="text" id="server" placeholder="dc01.scale.local" spellcheck="false" autocapitalize="off">
      {server_err}
    </div>
  </fieldset>
  <fieldset class="field" id="trusted" hidden>
    <div class="td-head"><legend>Trusted domains {tip_td}</legend><span class="td-count"><span id="td-count"></span><button type="button" class="td-all" id="td-all">Untick all</button></span></div>
    <p class="hint" id="td-hint"></p>
    <ul class="td-list" id="td-list"></ul>
    <p class="hint td-auth" id="td-auth" hidden>Only collect from domains you are authorized to assess.</p>
    {trusted_err}
  </fieldset>
</section>
"##,
        i_globe = icon("i-globe"),
        domain = crate::pages::attr(domain_value),
        dc = esc(dc_detected.map(String::as_str).unwrap_or_default()),
        domain_err = field_error("domain"),
        server_err = field_error("server"),
        trusted_err = field_error("trusted"),
        tip_td = crate::pages::tip(
            "tip-td",
            "Trusted domains",
            "A trusted domain can be read when it trusts yours: a two-way trust, or a one-way trust from its side. Accounts from your domain then sign in there as ordinary users, and ordinary users can read the directory. SID filtering doesn't stop that. The Check step signs in to each ticked domain before anything is collected."
        ),
    );

    // ---- 2. Who
    let (current_default, account, auth_why) = who_defaults(d, windows);
    let _ = write!(
        b,
        r##"<section class="wiz-step card" data-step="2" aria-labelledby="s2-title" hidden>
  <header class="ws-head"><span class="ws-ic">{i_user}</span><div><h2 class="sub" id="s2-title" tabindex="-1">Who should Pathwarden sign in as?</h2><p class="muted">It only reads. Nothing in your directory is changed.</p></div></header>
  <fieldset class="field">
    <legend class="sr-only">Sign in as</legend>
    <div class="choices" data-account="{account_attr}">{current}{password}</div>
    {auth_why}
    {auth_err}
  </fieldset>
  <div class="grid2" id="cred-fields" hidden>
    <div class="field"><label for="user">User</label><input type="text" id="user" placeholder="svc-pathwarden or SCALE\svc-pathwarden" spellcheck="false" autocapitalize="off" autocomplete="off">{user_err}</div>
    <div class="field"><label for="password">Password</label><input type="password" id="password" autocomplete="new-password">{password_err}</div>
  </div>
  <div class="note">{i_lock}<p><strong>Permissions.</strong> A normal domain user can read everything Pathwarden needs from the directory. Seeing who is logged on where, and who is a local admin, needs admin rights on those computers.</p></div>
  <fieldset class="field">
    <legend>Connection</legend>
    <label class="toggle"><input type="checkbox" id="ldaps"><span class="t-body"><strong>Encrypt with LDAPS (port 636)</strong><span id="ldaps-hint"></span></span></label>
    {ldaps_err}
    <label class="toggle"><input type="checkbox" id="kerberos-only" checked><span class="t-body"><strong>Kerberos only{tip_krb}</strong><span>Computers get a Kerberos ticket, never an NTLM response. A computer without a Kerberos name is skipped.</span></span></label>
    <label class="toggle"><input type="checkbox" id="smb-signing" checked><span class="t-body"><strong>Require SMB signing{tip_sign}</strong><span>Every reply from a computer must be signed. A computer whose replies aren't is skipped.</span></span></label>
    <div class="note warn" id="ntlm-note" hidden>{i_alert}<p><strong>NTLM allowed.</strong> A computer without a Kerberos name gets an NTLM response from this account. Anyone who can add a name to the domain's DNS can capture or relay it.</p></div>
    <div class="note warn" id="unsigned-note" hidden>{i_alert}<p><strong>SMB signing not required.</strong> Anyone on the network path could change what a computer answers.</p></div>
    <details class="advanced" id="advanced">
      <summary>Advanced</summary>
      <label class="toggle"><input type="checkbox" id="skip-verify" disabled><span class="t-body"><strong>Don't check the certificate</strong><span>For test labs only. Anyone on the network could pretend to be your domain controller and capture the sign-in. Needs LDAPS.</span></span></label>
      <div class="note warn" id="krb-cert-note" hidden>{i_alert}<p><strong>Certificate not checked.</strong> A machine pretending to be your domain controller would also get the Kerberos sign-in.</p></div>
      <label class="toggle"><input type="checkbox" id="allow-plain"><span class="t-body"><strong>Allow plain LDAP</strong><span>When LDAPS fails, or with LDAPS unticked. For domain controllers without a working LDAPS certificate.</span></span></label>
      <div class="note warn" id="plain-note" hidden>{i_alert}<p><strong>Plain LDAP allowed.</strong> Over plain LDAP, the directory and the sign-in cross the network unencrypted. Domain controllers that require LDAP signing refuse it. {plain_docs}</p></div>
    </details>
  </fieldset>
</section>
"##,
        i_user = icon("i-user"),
        i_lock = icon("i-lock"),
        i_alert = icon("i-alert"),
        plain_docs = crate::pages::repo_link(
            "docs/collect.md#plain-ldap-when-ldaps-fails",
            "When LDAPS fails"
        ),
        tip_krb = crate::pages::tip(
            "tip-krb",
            "Kerberos only",
            "An NTLM sign-in can be captured or relayed by anyone who can add a name to the domain's DNS. Kerberos only signs in to computers the domain has a Kerberos name for, so a name someone added gets nothing."
        ),
        tip_sign = crate::pages::tip(
            "tip-sign",
            "Require SMB signing",
            "Pathwarden signs its requests and checks the signature on every reply. With Kerberos, only the real computer can sign, so a look-alike is refused. Every Windows computer can sign; this doesn't need the computer to require it."
        ),
        current = choice(
            "auth",
            "current",
            "auth-current",
            current_default,
            (!windows).then_some("Only on Windows."),
            "Use my Windows account",
            &account,
            "",
        ),
        password = choice(
            "auth",
            "password",
            "auth-password",
            !current_default,
            None,
            "Enter a user and password",
            "For example a service account. The password is used for this collection only and is never saved.",
            "",
        ),
        account_attr = esc(d.account.as_deref().unwrap_or_default()),
        auth_why = auth_why,
        auth_err = field_error("auth"),
        user_err = field_error("user"),
        password_err = field_error("password"),
        ldaps_err = field_error("ldaps"),
    );

    // ---- 3. How deep
    let builtin_why = (!BUILTIN).then_some(
        "Not included in this version of Pathwarden. Use SharpHound, or collect elsewhere and upload the file.",
    );
    let sharphound_why = (!windows).then_some("Runs on Windows only.");
    let none_available = !BUILTIN && !windows;
    let _ = write!(
        b,
        r##"<section class="wiz-step card" data-step="3" aria-labelledby="s3-title" hidden>
  <header class="ws-head"><span class="ws-ic">{i_layers}</span><div><h2 class="sub" id="s3-title" tabindex="-1">How much should Pathwarden collect?</h2><p class="muted">You can start quick and run a full collection later.</p></div></header>
  <fieldset class="field">
    <legend class="sr-only">Depth</legend>
    <div class="choices two">{quick}{full}</div>
  </fieldset>
  <fieldset class="field">
    <legend>Collect with</legend>
    <div class="choices">{c_builtin}{c_sharphound}</div>
    {collector_err}
    {none}
    <label class="toggle" id="service-reads-field" hidden><input type="checkbox" id="service-reads"{service_reads}><span class="t-body"><strong>Read service accounts{tip_svc}</strong><span>Finds domain passwords stored on computers. Reads account names only.</span></span></label>
    <div class="note warn" id="service-reads-note" hidden>{i_alert}<p>Service accounts won't be read, so passwords stored on computers aren't checked.</p></div>
    <label class="toggle" id="task-reads-field" hidden><input type="checkbox" id="task-reads"{task_reads}><span class="t-body"><strong>Read scheduled tasks{tip_task}</strong><span>Finds domain passwords saved in scheduled tasks. Reads account names only.</span></span></label>
    <div class="note warn" id="task-reads-note" hidden>{i_alert}<p>Scheduled tasks won't be read, so passwords saved in them aren't checked.</p></div>
  </fieldset>
  <div class="field" id="sharphound-field" hidden>
    <label for="sharphound">Where is SharpHound.exe?</label>
    <div class="pathfield card">{i_folder}<input type="text" id="sharphound" value="{sharphound}" placeholder="C:\Tools\SharpHound.exe" spellcheck="false" autocomplete="off"></div>
    <p class="hint">SharpHound v2, for BloodHound CE. <a href="{releases}" target="_blank" rel="noopener noreferrer">Download it from SpecterOps</a> if you don't have it.</p>
    {sharphound_err}
  </div>
  <div class="note warn" id="sharphound-krb-note" hidden>{i_alert}<p><strong>Kerberos only and SMB signing don't apply.</strong> SharpHound signs in to computers its own way, as your Windows account, and falls back to NTLM where Kerberos fails.</p></div>
  <div class="note means" id="means-quick">{i_alert}<p><strong>What this means for your results.</strong> Without sessions and local groups, paths that go through a logged-on admin or a local admin right are missing, so the counts can read low. The report says so on its Collection tab, under Collection completeness. <a href="{docs}" target="_blank" rel="noopener noreferrer">What each method collects</a></p></div>
  <div class="note means" id="means-full" hidden>{i_alert}<p><strong>What this means for your results.</strong> Sessions are a snapshot of who was logged on during the collection. Computers that were off or refused the connection show as not collected on the report's Collection tab, under Collection completeness. <a href="{docs}" target="_blank" rel="noopener noreferrer">What each method collects</a></p></div>
</section>
"##,
        i_layers = icon("i-layers"),
        i_folder = icon("i-folder"),
        i_alert = icon("i-alert"),
        quick = choice(
            "depth",
            "quick",
            "depth-quick",
            true,
            None,
            r#"Quick <span class="tag">Recommended</span>"#,
            "Directory only. Takes minutes and only talks to a domain controller.",
            r#"<span class="c-miss">Misses who is logged on where, and who is a local admin.</span>"#,
        ),
        full = choice(
            "depth",
            "full",
            "depth-full",
            false,
            None,
            "Full",
            "Adds sessions and local groups. Contacts every computer and takes longer.",
            r#"<span class="c-miss">Security tools (EDR) may flag it.</span>"#,
        ),
        c_builtin = choice(
            "collector",
            "builtin",
            "collector-builtin",
            BUILTIN,
            builtin_why,
            "Pathwarden's built-in collector",
            "Nothing else to install.",
            "",
        ),
        c_sharphound = choice(
            "collector",
            "sharphound",
            "collector-sharphound",
            !BUILTIN && windows,
            sharphound_why,
            "SharpHound",
            "BloodHound's collector. Runs as your Windows account.",
            "",
        ),
        collector_err = field_error("collector"),
        service_reads = if pre.service_reads { " checked" } else { "" },
        tip_svc = crate::pages::tip(
            "tip-svc",
            "Read service accounts",
            "A service that runs as a domain account keeps its password on the computer, where any \
             of its administrators can read it. Pathwarden reads only the account each service runs \
             as, over the same Kerberos sign-in, never the password. Needs local admin rights on the \
             computers.",
        ),
        task_reads = if pre.task_reads { " checked" } else { "" },
        tip_task = crate::pages::tip(
            "tip-task",
            "Read scheduled tasks",
            "A scheduled task set to run whether its user is logged on or not keeps that user's \
             password on the computer, where any of its administrators can read it. Pathwarden reads \
             only the account each task runs as, from the task files on the computer's C$ share over \
             the same Kerberos sign-in, never the password or what the task runs. Windows logs the \
             share access. Needs local admin rights on the computers.",
        ),
        none = if none_available {
            r#"<p class="field-error">This version of Pathwarden can't collect on this computer. Collect with SharpHound or RustHound-CE elsewhere, then <a href="/analyze">upload the file</a>.</p>"#
        } else {
            ""
        },
        sharphound = crate::pages::attr(
            &d.sharphound
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        releases = SHARPHOUND_RELEASES,
        docs = DOCS_COLLECT,
        sharphound_err = field_error("sharphound"),
    );

    // ---- 4. Check
    let _ = write!(
        b,
        r##"<section class="wiz-step card" data-step="4" aria-labelledby="s4-title" hidden>
  <header class="ws-head"><span class="ws-ic">{i_plug}</span><div><h2 class="sub" id="s4-title" tabindex="-1">Check the connection</h2><p class="muted" id="check-intro">Pathwarden signs in and reads a little, without collecting anything yet.</p></div></header>
  <dl class="recap" id="recap"></dl>
  <div class="check card" id="check" aria-live="polite">
    <div class="check-state" id="check-idle"><button type="button" class="btn" id="check-run">{i_plug} <span id="check-label">Check the connection</span></button></div>
    <div class="check-state" id="check-busy" hidden><span class="spinner" aria-hidden="true"></span><span>Checking. This usually takes a few seconds, and at most a minute.</span></div>
    <div class="check-state ok" id="check-ok" hidden>{i_check}<div><strong>Ready to collect</strong><ul id="check-lines"></ul><ul class="warn-list" id="check-warnings" hidden></ul><div id="check-unchecked-box" hidden><p class="check-sub">Not checked</p><ul class="unchecked" id="check-unchecked"></ul></div></div></div>
    <div class="check-state bad" id="check-bad" hidden>{i_alert}<div><strong id="check-error"></strong><p class="detail" id="check-detail" hidden></p><p class="check-actions"><button type="button" class="btn" id="check-fix">{i_back} Fix</button><button type="button" class="btn" id="check-again">Try again</button></p></div></div>
  </div>
</section>
"##,
        i_plug = icon("i-plug"),
        i_check = icon("i-check"),
        i_alert = icon("i-alert"),
        i_back = icon("i-back"),
    );

    // ---- 5. Collect
    let _ = write!(
        b,
        r##"<section class="wiz-step card" data-step="5" aria-labelledby="s5-title" hidden>
  <div id="collect-ready">
    <header class="ws-head"><span class="ws-ic">{i_radar}</span><div><h2 class="sub" id="s5-title" tabindex="-1">Ready to collect</h2><p class="muted" id="ready-summary"></p></div></header>
    <label class="toggle"><input type="checkbox" id="keep"{keep}><span class="t-body"><strong>Keep the raw collection</strong><span>Kept on this computer, with this environment's runs. Otherwise it's deleted after the analysis, because it maps your whole domain.</span></span></label>
    <div class="also" id="also">
      <h3>Analyze other data with it <span class="muted small">(optional)</span></h3>
      <p class="muted small">AzureHound, OpenGraph or SharpHound files. They are read with the collection when it finishes.</p>
      <label class="dropzone" id="also-drop"><input type="file" id="also-files" multiple accept=".zip,.json" aria-label="Files to analyze with the collection"><span class="dz-icon">{i_upload}</span><span class="dz-title">Drop files here, or <span class="link">browse</span></span><span class="dz-hint">.zip, .json or a folder</span></label>
      <ul class="filelist" id="also-list" hidden></ul>
    </div>
    <div class="env-where" id="ew" data-state="loading"></div>{label_field}
    <div class="note resume-note" id="resume-note" hidden>{i_clock}<p><strong id="resume-text"></strong></p></div>
    <div class="form-actions"><button type="button" class="btn primary" id="collect-resume" hidden>Resume {i_arrow}</button><button type="button" class="btn" id="collect-over" hidden>Start over</button><button type="button" class="btn primary" id="collect-start">Start collecting {i_arrow}</button><span class="muted small">You can leave the page once it starts.</span></div>
  </div>
  <div id="collect-run" hidden>
    <div class="progress-head"><span class="spinner" aria-hidden="true" id="run-spinner" hidden></span><div><h2 class="sub" id="run-title">Collecting</h2><p class="muted small" id="run-phase"></p></div><span class="elapsed muted" id="run-elapsed"></span></div>
    <ol class="doms" id="run-doms" aria-label="Domains">
      <li class="dg" id="run-done" hidden><div class="dg-row"><span class="st done"></span><span class="dg-n" id="run-done-n"></span><span class="dg-names" id="run-done-names"></span><button type="button" class="linkish dg-show" aria-expanded="false" aria-controls="run-done-list">Show</button></div><ol class="dg-list" id="run-done-list" hidden></ol></li>
      <li class="dg fail" id="run-skipped" hidden><div class="dg-row"><span class="st fail"></span><span class="dg-n" id="run-skipped-n"></span><span class="dg-names" id="run-skipped-names"></span><span class="tip"><button type="button" class="tip-btn" aria-label="About: skipped domains" aria-describedby="run-skipped-tip">{i_info}</button><span class="tip-text" role="tooltip" id="run-skipped-tip">A domain that fails is skipped. The others are still analyzed.</span></span><button type="button" class="linkish dg-show" aria-expanded="false" aria-controls="run-skipped-list">Show</button></div><ol class="dg-list" id="run-skipped-list" hidden></ol></li>
      <li class="cur" id="run-cur"><div class="cprog" id="cprog">
        <div class="cp-row">
          <p class="cp-what"><span class="st active" id="cp-st"></span><strong class="cp-dom" id="cp-dom" hidden></strong><span class="cp-phase" id="cp-phase">Starting</span><span class="muted cp-step" id="cp-step"></span></p>
          <div class="seg" role="radiogroup" aria-label="How much to show" id="verb">
            <button type="button" role="radio" data-verb="summary" aria-checked="false" title="The step and the progress bar">Summary</button>
            <button type="button" role="radio" data-verb="details" aria-checked="true" title="Also the objects found so far, by type">Details</button>
            <button type="button" role="radio" data-verb="log" aria-checked="false" title="Also every line the collector writes">Full log</button>
          </div>
        </div>
        <div class="cp-bar" id="cp-bar" role="progressbar" aria-label="Collection progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><span id="cp-fill"></span></div>
        <div class="cp-nums"><strong id="cp-pct">0%</strong><span class="muted cp-units-wrap"><span id="cp-units"></span><span id="cp-streams" hidden></span><span class="tip" id="cp-parts" hidden><button type="button" class="tip-btn" aria-label="About: the parts of the read" aria-describedby="cp-parts-text">{i_info}</button><span class="tip-text" role="tooltip" id="cp-parts-text"></span></span></span><span class="cp-eta" id="cp-eta"></span></div>
        <div class="cp-counts" id="run-counts-line" hidden><p class="cp-kinds" id="run-kinds"></p><button type="button" class="linkish cp-all" id="run-counts-all" aria-expanded="false" aria-controls="run-counts" hidden>All counts</button></div>
        <dl class="counts" id="run-counts" hidden></dl>
        <p class="muted small cp-note" id="run-counts-note" hidden>Entries read so far. The final counts come after processing.</p>
      </div></li>
      <li class="dg" id="run-waiting" hidden><div class="dg-row"><span class="st"></span><span class="dg-n" id="run-waiting-n"></span><span class="dg-names" id="run-waiting-names"></span><button type="button" class="linkish dg-show" aria-expanded="false" aria-controls="run-waiting-list">Show</button></div><ol class="dg-list" id="run-waiting-list" hidden></ol></li>
    </ol>
    <ol class="steps" id="run-steps">
      <li data-step="collect"><span class="st"></span><span class="sl">Collecting from Active Directory</span></li>
      <li data-step="reading"><span class="st"></span><span class="sl">Reading the data <span class="muted" id="run-read-pct"></span></span></li>
      <li data-step="graph"><span class="st"></span><span class="sl">Building the graph</span></li>
      <li data-step="rules"><span class="st"></span><span class="sl">Checking for weaknesses</span></li>
      <li data-step="remediation"><span class="st"></span><span class="sl">Planning the remediation path</span></li>
      <li data-step="report"><span class="st"></span><span class="sl">Writing the report</span></li>
    </ol>
    <div class="notes-row" id="run-notes" hidden><span class="nr-what" id="run-notes-what"><span class="nr-ic" aria-hidden="true">!</span><span id="run-notes-n"></span><button type="button" class="linkish" id="run-notes-show" aria-expanded="false" aria-controls="run-warnings">Show</button></span><button type="button" class="linkish nr-out" id="run-output" aria-expanded="false" aria-controls="run-log-box" hidden>Collector output</button></div>
    <ul class="warn-list" id="run-warnings" hidden></ul>
    <div class="log" id="run-log-box" hidden>
      <div class="log-bar"><span class="log-title">Collector output <span class="muted" id="run-log-n"></span></span><button type="button" class="btn small" id="run-log-copy">{i_copy}<span>Copy log</span></button></div>
      <pre id="run-log" tabindex="0" aria-label="Collector output"></pre>
    </div>
    <div class="also-row" id="run-also" hidden>{i_file}<span><strong>Analyzed with it:</strong> <span class="muted" id="run-also-names"></span></span></div>
    <div class="form-actions" id="run-actions"><button type="button" class="btn danger" id="collect-cancel">{i_stop} Stop collecting</button><span class="muted small" id="run-note">You can leave this page; collecting continues.</span></div>
  </div>
  <div id="collect-stopped" class="ended" hidden>
    <div class="failed-head">{i_stop}<h2 class="sub">Stopped</h2></div>
    <p class="muted" id="stopped-text">The collection was stopped. Nothing was kept.</p>
    <div class="grid2 again-pw" hidden><div class="field"><label for="stopped-password">Password</label><input type="password" id="stopped-password" autocomplete="current-password">{stopped_pw_err}</div></div>
    <div class="check-actions"><button type="button" class="btn primary" id="stopped-resume" hidden>Resume {i_arrow}</button><button type="button" class="btn" id="stopped-over" hidden>Start over</button><button type="button" class="btn" id="collect-restart">Start over</button></div>
  </div>
  <div id="collect-failed" class="ended failed-box" hidden role="alert">
    <div class="failed-head">{i_alert}<h2 class="sub">The collection didn't finish</h2></div>
    <p id="collect-error"></p>
    <div class="grid2 again-pw" hidden><div class="field"><label for="failed-password">Password</label><input type="password" id="failed-password" autocomplete="current-password">{failed_pw_err}</div></div>
    <div class="check-actions"><button type="button" class="btn primary" id="failed-resume" hidden>Resume {i_arrow}</button><button type="button" class="btn" id="failed-over" hidden>Start over</button><button type="button" class="btn" id="collect-retry">{i_back} Back to the check</button></div>
  </div>
</section>
</form>
<dialog id="doms-dialog" class="card doms-dialog" aria-labelledby="doms-title"><form method="dialog"><h2 class="sub" id="doms-title"></h2><p id="doms-who"></p><ul id="doms-list"></ul><p class="muted small">Only collect from domains you are authorized to assess.</p><div class="dialog-actions"><button class="btn" value="cancel">Cancel</button><button class="btn primary" value="go" id="doms-go"></button></div></form></dialog>
<div class="wiz-nav" id="wiz-nav">
  <button type="button" class="btn" id="wiz-back" hidden>{i_back} Back</button>
  <span class="wiz-spacer"></span>
  <button type="button" class="btn primary" id="wiz-next">Next {i_arrow}</button>
</div>
</div>
<aside class="wiz-aside card" aria-label="About collecting">
  <h2 class="sub">How collecting works</h2>
  <ul>
    <li><strong>Checked before it starts.</strong> The wizard checks the connection first, then collects and analyzes in one go.</li>
    <li><strong>Read-only, on this computer.</strong> Pathwarden reads the directory; the data and the report stay here.</li>
    <li><strong>Local admin paths</strong> come from each computer's local groups, which only local administrators may read remotely. The release's <code>scripts\New-PathwardenCollectorGpo.ps1</code> sets up an account that can read them and do nothing else.</li>
    <li><strong>Sessions and local groups:</strong> SharpHound is still the most complete collector for these; you can choose it under How deep.</li>
  </ul>
  <p class="muted small">Only collect from domains you are authorized to assess.</p>
</aside>
</div>
<script src="/static/collect.js" defer></script>
"##,
        i_radar = icon("i-radar"),
        i_arrow = icon("i-arrow"),
        i_clock = icon("i-clock"),
        i_info = icon("i-info"),
        stopped_pw_err = field_error("stopped-password"),
        failed_pw_err = field_error("failed-password"),
        i_stop = icon("i-stop"),
        i_alert = icon("i-alert"),
        i_back = icon("i-back"),
        i_copy = icon("i-copy"),
        i_upload = icon("i-upload"),
        i_file = icon("i-file"),
        keep = if keep_default { " checked" } else { "" },
        label_field = crate::env_where::label_field(),
    );
    shell(ctx, Some(Nav::Collect), "Analyze", "", &b)
}

// ------------------------------------------------------------- run page

/// How a run from the Collect wizard was collected, as Run details says it
/// ([`crate::run_details`]): two sentences ("This run was collected with
/// the built-in collector, Quick (directory only). It read CONTOSO.LOCAL
/// from dc01.contoso.local over LDAPS, signed in as your Windows
/// account.") and a short status ("Quick (directory only)", "Full").
pub fn collected_words(c: &CollectionInfo) -> (String, String) {
    let collector = if c.method == "sharphound" {
        "SharpHound"
    } else {
        "the built-in collector"
    };
    let (depth, short) = if c.scope == "all" {
        ("Full (with sessions and local groups)", "Full")
    } else {
        ("Quick (directory only)", "Quick (directory only)")
    };
    let from = match &c.server {
        Some(s) => format!(" from {s}"),
        None => String::new(),
    };
    // Several domains: how many; each is in the Domains row.
    let from = match c.domains.len() {
        n if n > 1 => {
            return (
                format!(
                    "This run was collected with {collector}, {depth}. It read {n} domains over {}, {}.",
                    connection_words(c),
                    if c.current_user {
                        "signed in as your Windows account"
                    } else {
                        "signed in with a user and password"
                    }
                ),
                short.to_string(),
            )
        }
        _ => from,
    };
    let sign_in = if c.current_user {
        "signed in as your Windows account"
    } else {
        "signed in with a user and password"
    };
    (
        format!(
            "This run was collected with {collector}, {depth}. It read {}{from} over {}, {sign_in}.",
            c.domain,
            connection_words(c)
        ),
        short.to_string(),
    )
}

/// How a run reached its domain controllers: LDAPS, with plain LDAP
/// where it failed; LDAP as the Windows account (signed and encrypted by
/// Kerberos); plain LDAP with a password and LDAPS turned off.
fn connection_words(c: &CollectionInfo) -> &'static str {
    match (c.ldaps, c.current_user) {
        (true, _) if c.plain_fallback => "LDAPS (plain LDAP where it failed)",
        (true, _) => "LDAPS",
        (false, true) => "LDAP",
        (false, false) => "plain LDAP",
    }
}

/// How a run's computers were signed in to, as Run details says it
/// under how it was collected: "Computers were read with Kerberos only and
/// SMB signing required." `None` for runs from before it was recorded.
pub fn computers_sentence(c: &CollectionInfo) -> Option<String> {
    let kerberos = c.kerberos_only?;
    let Some(signing) = c.smb_signing else {
        // As the Windows account, signing is Windows' own.
        let what = if c.scope == "all" {
            "Computers were read"
        } else {
            "SYSVOL was read"
        };
        return Some(format!(
            "{what} with {}; SMB signing was left to Windows.",
            if kerberos {
                "Kerberos only"
            } else {
                "NTLM allowed"
            }
        ));
    };
    if c.method == "sharphound" {
        return Some(
            "Kerberos only and SMB signing weren't enforced: SharpHound signs in to computers \
             its own way."
                .into(),
        );
    }
    let what = if c.scope == "all" {
        "Computers were read"
    } else {
        "SYSVOL was read"
    };
    Some(match (kerberos, signing) {
        (true, true) => format!("{what} with Kerberos only and SMB signing required."),
        (true, false) => format!("{what} with Kerberos only; SMB signing was not required."),
        (false, true) => format!("{what} with NTLM allowed and SMB signing required."),
        (false, false) => format!("{what} with NTLM allowed and SMB signing not required."),
    })
}

// ------------------------------------------------------------- schedule

fn code_block(
    id: &str,
    file: &str,
    text: &str,
    download: Option<String>,
    example: Option<&str>,
) -> String {
    // Files written from example values say so on each block, so none is
    // copied as it is.
    let example = example
        .map(|d| {
            format!(
                r#" <span class="tag code-example">Example for {}</span>"#,
                esc(d)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<div class="code card"><div class="code-bar"><span class="code-name">{i_file}{file}{example}</span><span class="code-actions"><button type="button" class="btn small" data-copy="{id}">{i_copy} <span>Copy</span></button>{dl}</span></div><pre id="{id}" tabindex="0"><code>{text}</code></pre></div>"#,
        i_file = icon("i-file"),
        i_copy = icon("i-copy"),
        file = esc(file),
        text = esc(text),
        dl = download
            .map(|href| format!(
                r#"<a class="btn small" href="{}" download>{} Download</a>"#,
                esc(&href),
                icon("i-download")
            ))
            .unwrap_or_default(),
    )
}

pub fn schedule(
    ctx: &Ctx,
    run: Option<&RunSummary>,
    t: &Target,
    typed: &Params,
    errors: &[String],
    status: &str,
) -> String {
    let mut b = head();
    // No run of this computer's own to repeat: the files use example
    // values, and the page says so.
    let example_for = run.is_none().then_some(t.domain.as_str());
    // With a problem, the form keeps what was typed (to correct it), not
    // the default the files would fall back to.
    let shown = |given: &Option<String>, checked: &str| -> String {
        match given.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(v) if !errors.is_empty() => v.to_string(),
            _ => checked.to_string(),
        }
    };
    // Each refused field is marked and points at its own message.
    let bad = if errors.is_empty() {
        Vec::new()
    } else {
        super::schedule::invalid_fields(typed)
    };
    let invalid = |field: &str| -> String {
        if bad.iter().any(|(f, _)| *f == field) {
            format!(r#" aria-invalid="true" aria-describedby="sf-err-{field}""#)
        } else {
            String::new()
        }
    };
    // The OS links keep what was typed too (a typed value is shown, not
    // the default it would fall back to).
    let mut typed_t = t.clone();
    typed_t.folder = shown(&typed.folder, &t.folder);
    typed_t.at = shown(&typed.at, &t.at);
    typed_t.account = shown(&typed.account, &t.account);
    typed_t.user = shown(&typed.user, &t.user);
    let from = run
        .map(|r| {
            format!(
                r#"<p class="muted small">Based on <a href="/runs/{}">the run of {}</a>.</p>"#,
                esc(&r.id),
                esc(&r.environment())
            )
        })
        .unwrap_or_default();
    // Each environment's schedule has its own task (or timer) and folders
    // (not shown while the folder may be one that was refused).
    let from = if ctx.several_envs() && errors.is_empty() {
        format!(
            r#"{from}<p class="muted small">For the <strong>{}</strong> environment: the {} <code>{}</code> in <code>{}</code>, with this environment's settings and history.</p>"#,
            esc(&ctx.env_name),
            if t.linux { "timer" } else { "task" },
            esc(&if t.linux {
                format!("{}.timer", t.unit())
            } else {
                t.task_name()
            }),
            esc(&t.folder),
        )
    } else {
        from
    };
    let _ = write!(
        b,
        r##"<div class="page-head"><div><p class="eyebrow">Automate</p><h1 class="panel-title">Schedule</h1>
<p class="lead">Set up a server to collect and analyze every night and record each run in the run history. An administrator copies these files to the server and runs the commands.</p>{from}</div></div>
{example_note}{status}<nav class="os-switch" aria-label="Server">
  <a href="/automate/schedule?{q_win}"{win_cur}>{i_windows} Windows server</a>
  <a href="/automate/schedule?{q_linux}"{linux_cur}>{i_terminal} Linux server</a>
</nav>
"##,
        q_win = esc(&typed_t.query(Some(false))),
        q_linux = esc(&typed_t.query(Some(true))),
        win_cur = if t.linux {
            ""
        } else {
            r#" aria-current="page""#
        },
        linux_cur = if t.linux {
            r#" aria-current="page""#
        } else {
            ""
        },
        i_windows = icon("i-windows"),
        i_terminal = icon("i-terminal"),
        example_note = example_for
            .map(|d| format!(
                r#"<div class="note">{}<p><strong>These scripts are examples for {}.</strong> After your first run they use its domain and domain controller.</p></div>"#,
                icon("i-info"),
                esc(d)
            ))
            .unwrap_or_default(),
    );

    // Settings form (GET, so the page and the downloads share one URL).
    let _ = write!(
        b,
        r##"<form class="sched-form card" method="get" action="/automate/schedule">
  <input type="hidden" name="os" value="{os}">{run_field}
  <div class="field"><label for="folder">Folder on the server</label><input type="text" id="folder" name="folder" value="{folder}" spellcheck="false"{folder_invalid}></div>
  {who}
  <div class="field narrow"><label for="at">Time</label><input type="{at_type}" id="at" name="at" value="{at}"{at_invalid}></div>
  <div class="sf-actions"><button type="submit" class="btn">Update the files</button></div>
  {errors}
</form>
"##,
        os = if t.linux { "linux" } else { "windows" },
        run_field = t
            .run
            .as_ref()
            .map(|r| format!(r#"<input type="hidden" name="run" value="{}">"#, esc(r)))
            .unwrap_or_default(),
        folder = crate::pages::attr(&shown(&typed.folder, &t.folder)),
        at = esc(&shown(&typed.at, &t.at)),
        // A time input can't show a refused value like 99:00: plain text
        // until it is corrected.
        at_type = if invalid("at").is_empty() {
            "time"
        } else {
            "text"
        },
        folder_invalid = invalid("folder"),
        at_invalid = invalid("at"),
        who = if t.linux {
            format!(
                r#"<div class="field"><label for="user">Sign in as</label><input type="text" id="user" name="user" value="{}" spellcheck="false"{}></div>"#,
                crate::pages::attr(&shown(&typed.user, &t.user)),
                invalid("user")
            )
        } else {
            format!(
                r#"<div class="field"><label for="account">Service account (gMSA)</label><input type="text" id="account" name="account" value="{}" spellcheck="false"{}></div>"#,
                crate::pages::attr(&shown(&typed.account, &t.account)),
                invalid("account")
            )
        },
        errors = if errors.is_empty() {
            String::new()
        } else {
            format!(
                r#"<ul class="field-error sf-errors" id="sf-errors" role="alert">{}</ul>"#,
                errors
                    .iter()
                    .map(|e| match bad.iter().find(|(_, m)| *m == e.as_str()) {
                        Some((f, _)) => format!(r#"<li id="sf-err-{f}">{}</li>"#, esc(e)),
                        None => format!("<li>{}</li>", esc(e)),
                    })
                    .collect::<String>()
            )
        },
    );

    for n in &t.notes {
        let _ = write!(
            b,
            r#"<div class="note">{}<p>{}</p></div>"#,
            icon("i-alert"),
            // Fixed text from `schedule` (no user input), with <code>.
            n
        );
    }

    // No files for settings that don't work: they would be the defaults'.
    if !errors.is_empty() {
        let _ = write!(
            b,
            r#"<div class="note warn">{}<p>Correct the settings above and choose <strong>Update the files</strong>: the files are written for settings that work.</p></div>"#,
            icon("i-alert")
        );
        b.push_str(r#"<script src="/static/collect.js" defer></script>"#);
        return shell(ctx, Some(Nav::Schedule), "Schedule", "", &b);
    }

    // The steps and their code come from `schedule`, which `pathwarden
    // schedule` prints and writes too.
    let q = t.query(None);
    b.push_str(r#"<ol class="sched-steps">"#);
    for s in t.steps() {
        let code: String = s
            .blocks
            .iter()
            .map(|c| {
                let dl = c
                    .download
                    .then(|| format!("/automate/schedule/{}?{q}", c.file));
                code_block(c.id, &c.label, &c.text, dl, example_for)
            })
            .collect();
        let _ = write!(
            b,
            r#"<li class="card"><h2 class="sub">{}</h2><p>{}</p>{code}</li>"#,
            s.title, s.text
        );
    }
    b.push_str("</ol>");
    b.push_str(r#"<script src="/static/collect.js" defer></script>"#);
    shell(ctx, Some(Nav::Schedule), "Schedule", "", &b)
}

#[cfg(test)]
#[path = "view_tests.rs"]
mod tests;
