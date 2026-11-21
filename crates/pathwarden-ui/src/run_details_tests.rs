use super::*;

#[test]
fn nonces_and_the_delete_line() {
    let n = new_nonce();
    assert!(valid_nonce(&n), "{n}");
    assert_ne!(n, new_nonce());
    for bad in ["", "ABCDEF0123456789abcdef0123456789", "\"><b>", &n[..31]] {
        assert!(!valid_nonce(bad), "{bad}");
    }
    // Only a run with a point says it loses it.
    assert_eq!(Remove::Delete { recorded: false }.words().1, "");
    assert!(Remove::Delete { recorded: true }
        .words()
        .1
        .contains("run history"));
    // No script of Pathwarden's: no tab.
    let html = r##"<a role="tab" href="#environment"><span class="tl">Environment</span></a><main></main><script>x()</script>"##;
    assert!(!can_inject(html));
}

/// The hybrid AzureHound test data analyzed with `toml`, as a run
/// summary. `edit` changes the AzureHound file first.
fn azure_run(name: &str, toml: &str, edit: impl Fn(String) -> String) -> RunSummary {
    let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/entra");
    let dir = std::env::temp_dir().join(format!("pathwarden-ui-og-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let text = std::fs::read_to_string(data.join("azurehound/azurehound_hybrid.json")).unwrap();
    std::fs::write(dir.join("azurehound_hybrid.json"), edit(text)).unwrap();
    let config = pathwarden_core::config::Config::parse(toml).unwrap();
    let a = pathwarden_core::analyze::run(
        &[data.join("ad"), dir.clone()],
        &config,
        &[],
        &mut pathwarden_core::analyze::Quiet,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    RunSummary::new("r1", 1, "test".into(), false, &a)
}

/// An AzureHound read stopped by the kept-properties limit, or with a
/// record too large: an amber row that names the source, why and
/// where the limit is set, never a key or a command; the run page says
/// findings may be missing; the summary keeps it.
#[test]
fn a_source_read_part_way_needs_a_look() {
    let applies = Ok("The next analysis applies: x.".to_string());
    let whole = azure_run("whole", "", |t| t);
    assert!(whole.incomplete_sources.is_empty() && !attention(&whole));
    assert!(!rows(&whole, None, &applies)
        .iter()
        .any(|r| r.title == "Sources read part way"));

    let kept = azure_run("kept", "[opengraph]\nmax_kept_mib = 0\n", |t| t);
    assert!(attention(&kept));
    let all = rows(&kept, None, &applies);
    assert!(needs_a_look(&all));
    let row = all
        .iter()
        .find(|r| r.title == "Sources read part way")
        .unwrap();
    assert!(row.warn);
    assert_eq!(row.status, "AzureHound read part way");
    assert_eq!(
        row.text,
        [
            "AzureHound was read only part way (the limit on kept properties). \
              A higher limit can be set in this environment's settings file. \
              Findings that rest on it aren't marked fixed."
        ]
    );
    let panel = panel_html(&kept, None, &applies, Remove::Hide, "n", None);
    assert!(
            panel.contains(r#"<details class="row env" open><summary><span class="title">Sources read part way</span><span class="aside warn">AzureHound read part way</span></summary>"#),
            "{panel}"
        );
    for never in ["pathwarden.toml", "max_kept_mib", "[opengraph]"] {
        assert!(!panel.contains(never), "{never} in {panel}");
    }
    // The summary JSON carries it, and reads back.
    let v = serde_json::to_value(&kept).unwrap();
    assert_eq!(v["incomplete_sources"][0]["source"], "AzureHound", "{v}");
    assert_eq!(
        v["incomplete_sources"][0]["limits"],
        serde_json::json!(["kept properties"])
    );
    let back: RunSummary = serde_json::from_value(v).unwrap();
    assert_eq!(back.incomplete_sources, kept.incomplete_sources);

    let big = "x".repeat(3 << 19);
    let over = azure_run("record", "[opengraph]\nmax_record_mib = 1\n", |t| {
        t.replace(
            "\"displayName\": \"Partner\"",
            &format!("\"displayName\": \"{big}\""),
        )
    });
    let all = rows(&over, None, &applies);
    let row = all
        .iter()
        .find(|r| r.title == "Sources read part way")
        .unwrap();
    assert!(row.warn && attention(&over));
    assert_eq!(
        row.text,
        [
            "AzureHound was read only part way (1 record too large to load). \
              A higher limit can be set in this environment's settings file. \
              Findings that rest on it aren't marked fixed."
        ]
    );
}

/// A history point recorded by `by`, as a run summary.
fn point(by: &str) -> crate::workspace::RunSummary {
    let p: pathwarden_core::state::HistoryPoint = serde_json::from_value(serde_json::json!({
        "version": 1, "run_id": "r1", "at": 1, "collected_at": null,
        "tier_zero_exposure_percent": 1.0, "tier_zero_exposed": 1,
        "tier_zero_population": 100, "tier_zero_objects": 1,
        "protection_score": null,
        "findings": {"attack_path": 0, "hygiene": 0, "suppressed": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "changes": {"new": 0, "open": 0, "regressed": 0, "suppressed": 0,
            "resolved": 0},
        "recorded_by": by,
    }))
    .unwrap();
    crate::history_ui::point_summary(&p, &[])
}

/// The Repository row's branch is on its own line, with no comma that
/// a narrow screen could start a line with; `runs show` keeps the words.
#[test]
fn the_branch_goes_on_its_own_line() {
    let mut r = point("cli");
    r.shared = Some(crate::shared_runs::SharedFrom {
        remote: "https://git.example/sec/pathwarden-history.git".into(),
        branch: Some("main".into()),
        recorded_by: None,
        recorded_on: None,
        recorded_from: "cli".into(),
        pathwarden: "0.1.7".into(),
        mirrored_at: 1,
        manifest_sha256: String::new(),
        left_out: Vec::new(),
    });
    let repo = facts(&r).into_iter().find(|f| f.0 == REPOSITORY).unwrap();
    assert_eq!(
        repo.1,
        "https://git.example/sec/pathwarden-history.git, branch main"
    );
    let want = r#"<dt>Repository</dt><dd><span class="rd-remote">https://git.example/sec/pathwarden-history.git</span> <span class="rd-branch">branch main</span></dd>"#;
    let applies = Ok("The next analysis applies: x.".to_string());
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    let panel = panel_html(&r, None, &applies, Remove::Hide, &new_nonce(), None);
    for html in [&below, &panel] {
        assert!(html.contains(want), "{html}");
        assert!(!html.contains(", branch"), "{html}");
    }
    assert!(CSS.contains(".rd-branch{display:block}"));
    // A hostile remote and branch are escaped in both renderers.
    {
        let s = r.shared.as_mut().unwrap();
        s.remote = "https://x/<img src=x onerror=1>".into();
        s.branch = Some("<img src=x onerror=1>".into());
    }
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    let panel = panel_html(&r, None, &applies, Remove::Hide, &new_nonce(), None);
    for html in [&below, &panel] {
        assert!(
            html.contains(r#"<span class="rd-remote">https://x/&lt;img"#),
            "{html}"
        );
        assert!(
            html.contains(r#"<span class="rd-branch">branch &lt;img"#),
            "{html}"
        );
        assert!(!html.contains("<img"), "{html}");
    }
    // No branch: the remote alone, escaped.
    r.shared.as_mut().unwrap().branch = None;
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    assert!(
        below.contains("<dt>Repository</dt><dd>https://x/&lt;img src=x onerror=1&gt;</dd>"),
        "{below}"
    );
}

/// A run the repository wanted a sign-in for: the plain words, and Sign
/// in before History storage in both renderers (none with no helper);
/// how a Sign in went under it.
#[test]
fn a_sign_in_row() {
    use crate::sign_in::Outcome;
    let applies = Ok("The next analysis applies: x.".to_string());
    let mut r = point("cli");
    r.history = Some(crate::workspace::HistoryLink {
            not_recorded: Some("Couldn't get the latest history: git fetch failed: fatal: could not read Password for 'https://h': terminal prompts disabled".into()),
            sign_in: true,
            ..Default::default()
        });
    let row = rows(&r, None, &applies)
        .into_iter()
        .find(|r| r.title == HISTORY_ROW)
        .unwrap();
    assert_eq!(
        row.text,
        ["This run is not in the run history. This computer isn't signed in to the repository."]
    );
    assert!(row.sign_in && row.warn);
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    assert!(panel.contains(r##"<div class="rd-row"><button type="button" class="rd-btn" data-pw-run="sign-in"><svg class="ic" aria-hidden="true"><use href="#i-external"/></svg><span>Sign in</span></button><a href="#" data-pw-run="history">History storage</a></div>"##), "{panel}");
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    assert!(below.contains(r##"data-sign-in><svg class="ic" aria-hidden="true"><use href="#i-external"/></svg> Sign in</button><a href="/automate/history">History storage</a>"##), "{below}");
    // The frame gets the icon when its report has none.
    let html =
        format!("<html><body><nav>{ENV_TAB}</nav><main><section></section></main></body></html>");
    assert!(inject(&html, &panel, true, "n").contains(r#"<symbol id="i-external""#));

    let failed = panel_html(&r, None, &applies, Remove::Hide, "n", Some(Outcome::Failed));
    assert!(
        failed.contains(r#"<p class="rd-said bad" role="status">Sign-in didn&#39;t work."#),
        "{failed}"
    );
    assert!(failed.contains("data-pw-run=\"sign-in\""));

    // Recorded here, not pushed, with its full run.
    r.history = Some(crate::workspace::HistoryLink {
            run_id: Some("r1".into()),
            unpushed: Some("This run is recorded here, but the change couldn't be pushed (x); it goes with the next run that pushes.".into()),
            sign_in: true,
            no_helper: true,
            ..Default::default()
        });
    let row = rows(&r, None, &applies)
        .into_iter()
        .find(|r| r.title == HISTORY_ROW)
        .unwrap();
    assert_eq!(row.text, ["This run is recorded here, but not pushed: this computer isn't signed in to the repository. Git here has no sign-in helper. Install Git for Windows with Git Credential Manager, then sync again."]);
    assert!(!row.sign_in, "no helper: nothing to open");

    // After a sign-in that worked, the push took it: recorded.
    r.history = Some(crate::workspace::HistoryLink {
        run_id: Some("r1".into()),
        ..Default::default()
    });
    let ok = below_html(&r, None, &applies, Remove::Hide, Some(Outcome::Ok));
    assert!(
        ok.contains("<p>This run is recorded in the run history.</p>"),
        "{ok}"
    );
    assert!(
        ok.contains(r#"<p class="rd-said good" role="status">Signed in and synced.</p>"#),
        "{ok}"
    );
    assert!(ok.contains(r#"<details class="rd-more" open>"#), "{ok}");

    // Refused: the repository's words, with Sign in to pick another
    // account.
    r.history = Some(crate::workspace::HistoryLink {
        not_recorded: Some(
            "Couldn't get the latest history: remote: HTTP Basic: Access denied".into(),
        ),
        sign_in: true,
        refused: true,
        ..Default::default()
    });
    let row = rows(&r, None, &applies)
        .into_iter()
        .find(|r| r.title == HISTORY_ROW)
        .unwrap();
    assert_eq!(
        row.text,
        ["This run is not in the run history. The repository refused this computer's sign-in."]
    );
    assert!(row.sign_in);
}

/// The rows: a run with nothing to flag has every row closed, no dot
/// and no line above the report; skipped objects, collector warnings,
/// an unpushed point and the comparison's findings are amber and open,
/// in complete sentences, with no command line on the page. The run
/// history row is for runs analysed here only.
#[test]
fn rows_say_what_needs_a_look() {
    let applies = Ok("The next analysis applies: x.".to_string());
    let mut r = point("cli");
    r.pathwarden = "0.1.8".into();
    r.history = Some(crate::workspace::HistoryLink {
        run_id: Some("r1".into()),
        ..Default::default()
    });
    let all = rows(&r, Some(false), &applies);
    assert!(!needs_a_look(&all) && !attention(&r));
    let titles: Vec<_> = all.iter().map(|r| r.title).collect();
    assert_eq!(
        titles,
        [
            "Where it came from",
            "Run history",
            "Collection performance",
            "Settings"
        ]
    );
    assert_eq!(all[0].status, "On this computer · Pathwarden 0.1.8");
    assert_eq!(all[1].text, ["This run is recorded in the run history."]);
    let panel = panel_html(&r, Some(false), &applies, Remove::Hide, "n", None);
    assert!(!panel.contains(" open>") && !panel.contains("aside warn"));

    // An intended Quick run: what its depth and sign-in leave out is
    // information, in today's words and an older run's, not a warning.
    let mut quick = crate::workspace::CollectionInfo {
        read_started: None,
        plain_allowed: false,
        plain_fallback: false,
        method: "builtin".into(),
        scope: "dc-only".into(),
        domain: "CONTOSO.LOCAL".into(),
        server: Some("dc01.contoso.local".into()),
        ldaps: true,
        current_user: true,
        warnings: vec![
            pathwarden_collect::NO_SESSIONS_NOTE.into(),
            // As older runs kept it: a clause.
            "group policy local groups (SYSVOL) are not collected without a password".into(),
        ],
        kept: Some(r"C:\c\x.zip".into()),
        kerberos_only: None,
        smb_signing: None,
        domains: Vec::new(),
    };
    r.collection = Some(quick.clone());
    let all = rows(&r, Some(false), &applies);
    assert!(!needs_a_look(&all) && !attention(&r));
    let how = all
        .iter()
        .find(|r| r.title == "How it was collected")
        .unwrap();
    assert_eq!(how.status, "Quick (directory only)");
    assert!(!how.warn && how.items.is_empty());
    assert_eq!(
        how.text[2],
        "Group policy local groups (SYSVOL) are not collected without a password."
    );
    assert!(!panel_html(&r, Some(false), &applies, Remove::Hide, "n", None).contains("aside warn"));
    // A read that stopped and was resumed: when it started.
    r.collection = Some(crate::workspace::CollectionInfo {
        read_started: Some(1_793_000_000),
        plain_allowed: false,
        plain_fallback: false,
        ..quick.clone()
    });
    let all = rows(&r, Some(false), &applies);
    let how = all
        .iter()
        .find(|r| r.title == "How it was collected")
        .unwrap();
    assert_eq!(how.resumed, Some(1_793_000_000));
    assert!(!how.text.iter().any(|t| t.contains("resumed")));
    assert_eq!(
        resumed_sentence(&resumed_at_local(1_793_000_000)),
        format!(
            "The read was resumed. It started {}.",
            pathwarden_core::time::format_local(1_793_000_000)
        )
    );
    // The page: in local time, as its other times (`app.js`).
    let html = panel_html(&r, Some(false), &applies, Remove::Hide, "n", None);
    assert!(
        html.contains(
            r#"<p>The read was resumed. It started <time data-unix="1793000000" data-fmt="full""#
        ),
        "{html}"
    );
    r.collection = Some(quick.clone());

    r.skipped_objects = 2;
    quick.warnings.push(
            "LDAPS certificates were not checked, so anyone on the network path could read or change the collection.".into(),
        );
    r.collection = Some(quick);
    let h = r.history.as_mut().unwrap();
    h.unpushed = Some("This run is recorded here, but the change couldn't be pushed.".into());
    h.warnings = vec![
        "CHILD.CONTOSO.LOCAL is missing from this collection; the previous run had it.".into(),
        // The history's upgrade, on a row of its own.
        pathwarden_core::store::upgrade_note(2),
    ];
    assert!(attention(&r));
    let all = rows(&r, Some(true), &applies);
    assert!(needs_a_look(&all));
    let panel = panel_html(&r, Some(true), &applies, Remove::Hide, "n", None);
    for want in [
            r#"<details class="row env" open><summary><span class="title">Objects skipped</span><span class="aside warn">2 objects skipped</span></summary>"#,
            "<p>2 objects were too large to read safely. Findings that depend on them may be missing from this run.</p>",
            r#"<span class="aside warn">1 collector warning</span>"#,
            "<p>This run was collected with the built-in collector, Quick (directory only). It read CONTOSO.LOCAL from dc01.contoso.local over LDAPS, signed in as your Windows account.</p>",
            "<p>Group policy local groups (SYSVOL) are not collected without a password.</p>",
            "<li>LDAPS certificates were not checked, so anyone on the network path could read or change the collection.</li>",
            r"<code>C:\c\x.zip</code>. Delete it when you no longer need it, because it is a complete map of your domain.",
            r##"<a href="#" data-pw-run="schedule">Run it every night</a>"##,
            r#"<span class="aside warn">Recorded here, not pushed yet</span>"#,
            r##"<a href="#" data-pw-run="history">History storage</a>"##,
            r#"<span class="aside warn">1 difference to check</span>"#,
            r#"<details class="row env" open><summary><span class="title">History upgrade</span><span class="aside warn">Not finished</span></summary>"#,
            "<p>2 files in the history couldn&#39;t be upgraded. Pathwarden tries again on the next run.</p>",
            r#"<span class="aside warn">Slower than the previous one</span>"#,
            r##"<a href="#" data-pw-run="performance">Collection slower</a>"##,
        ] {
            assert!(panel.contains(want), "{want} in {panel}");
        }
    for never in ["pathwarden summary", "max_object_mib", "pathwarden.toml"] {
        assert!(!panel.contains(never), "{never} in {panel}");
    }
    // The page's own Run details: the same rows, real links.
    let below = below_html(&r, Some(true), &applies, Remove::Hide, None);
    assert!(
        below.contains(
            r#"<details class="rd-r warn" open><summary><span class="rd-t">Objects skipped</span>"#
        ),
        "{below}"
    );
    let schedule = format!(
        r#"<a href="/automate/schedule?run={}">Run it every night</a>"#,
        esc(&r.id)
    );
    assert!(below.contains(&schedule), "{below}");
    assert!(
        below.contains(r#"<a href="/automate/history">History storage</a>"#),
        "{below}"
    );
    assert!(below.contains(r#"class="rd-dot""#), "{below}");
    // The tab's dot.
    let html = r##"<a role="tab" href="#environment"><span class="tl">Environment</span></a><main></main>"##;
    assert!(inject(html, "", true, "n").contains(r#"class="rd-dot""#));
    assert!(!inject(html, "", false, "n").contains("rd-dot"));
    // The point and its full run waiting for the same push: one pair
    // of sentences.
    r.history.as_mut().unwrap().full_run = Some(crate::shared_runs::FullRunLink {
        state: crate::shared_runs::FullRunState::Unpushed,
        why: Some("The full run is committed here, but the change couldn't be pushed.".into()),
        left_out: Vec::new(),
    });
    let all = rows(&r, None, &applies);
    let history = all.iter().find(|r| r.title == "Run history").unwrap();
    assert_eq!(
            history.text,
            ["This run is recorded here, but the change couldn't be pushed. Its full run goes with it."]
        );
    assert!(history.warn);
    // A name keeps its case.
    assert_eq!(
        sentence("dc01.contoso.local was not reached"),
        "dc01.contoso.local was not reached."
    );
    assert_eq!(sentence("plain words"), "Plain words.");
    // The demo has no comparison to look at.
    r.demo = true;
    r.skipped_objects = 0;
    assert!(!attention(&r));

    // A run from the repository: its place in the history isn't this
    // computer's to tell.
    r.demo = false;
    r.shared = Some(crate::shared_runs::SharedFrom {
        remote: "https://git.example/sec/pathwarden-history.git".into(),
        branch: None,
        recorded_by: None,
        recorded_on: None,
        recorded_from: "cli".into(),
        pathwarden: "0.1.7".into(),
        mirrored_at: 1,
        manifest_sha256: String::new(),
        left_out: Vec::new(),
    });
    let all = rows(&r, None, &applies);
    assert!(all.iter().all(|r| r.title != "Run history"));
    assert_eq!(
        all[0].status,
        format!(
            "From the repository · loaded {}",
            pathwarden_core::time::format_local_date(1)
        )
    );
}

/// History storage says who recorded a run in the words the Runs page
/// and Run details use.
#[test]
fn history_points_say_recorded_from() {
    let words = |by: &str| point(by).source;
    assert_eq!(words("cli"), "Recorded from the command line");
    assert_eq!(words("schedule"), "Recorded by the schedule");
    assert_eq!(words("ui"), "Recorded in the app");
    assert_eq!(words("import"), "Imported from the app");
    assert_eq!(words("other"), "Recorded by a run");
}

/// A report made before the tab held Run details' rows
/// (the sample report published through 0.1.8, made by 0.1.6; in
/// tests/data/old-reports) carries the tab: one
/// Run details tab, with Remove, and the nonce on both.
#[test]
fn a_report_from_0_1_8_carries_the_tab() {
    let old = include_str!("../tests/data/old-reports/sample-report-0.1.6.html");
    let html = crate::run_list::report_as_now(old.to_string(), None);
    assert!(can_inject(&html));
    assert!(!html.contains(r#"id="tab-details""#));
    let r = point("ui");
    let nonce = new_nonce();
    let panel = panel_html(
        &r,
        None,
        &Ok(String::new()),
        Remove::FromHistory,
        &nonce,
        None,
    );
    let out = inject(&html, &panel, false, &nonce);
    assert_eq!(out.matches(r#"id="tab-details""#).count(), 1);
    assert_eq!(out.matches("<h3>Remove this run</h3>").count(), 1);
    assert!(out.contains(&format!(r#"data-pw-tab="{nonce}""#)));
    assert!(out.contains(&format!(r#"data-pw-nonce="{nonce}""#)));
}

#[test]
fn the_tab_goes_after_environment_and_the_panel_last() {
    let html = r##"<html><head></head><body><nav><a role="tab" href="#environment"><span class="tl">Environment</span></a></nav><main><section id="environment" class="panel"></section></main></body></html>"##;
    let out = inject(html, "<section id=\"details\"></section>", false, "n");
    let tab = out.find("tab-details").unwrap();
    let env = out.find("Environment</span></a>").unwrap();
    assert!(tab > env);
    let panel = out.find("<section id=\"details\">").unwrap();
    assert!(panel > out.find("id=\"environment\"").unwrap());
    assert!(panel < out.rfind("</main>").unwrap());
    assert!(out.contains(r#"id="i-trash""#), "the icon comes with it");
    // A report that has the icon doesn't get it twice; one without the
    // tab bar is left alone.
    let with = html.replace(
        "<main>",
        r#"<svg><symbol id="i-trash"></symbol></svg><main>"#,
    );
    assert_eq!(
        inject(&with, "<p>x</p>", false, "n")
            .matches("id=\"i-trash\"")
            .count(),
        1
    );
    assert_eq!(
        inject("<main></main>", "<p>x</p>", false, "n"),
        "<main></main>"
    );
    // The footer stays last.
    let footed = html.replace("</main>", "<footer>Generated</footer></main>");
    let out = inject(&footed, "<section id=\"details\"></section>", false, "n");
    assert!(out.find("id=\"details\"").unwrap() < out.find("<footer>").unwrap());
}

fn collected(domains: Vec<crate::workspace::DomainOutcome>) -> crate::workspace::RunSummary {
    let mut r = point("app");
    r.id = "20261027-201900-aaaaaa".into();
    r.objects = 1204;
    r.collection = Some(crate::workspace::CollectionInfo {
        read_started: None,
        plain_allowed: false,
        plain_fallback: false,
        method: "builtin".into(),
        scope: "dc-only".into(),
        domain: "contoso.local".into(),
        server: None,
        ldaps: true,
        current_user: false,
        warnings: Vec::new(),
        kept: None,
        kerberos_only: Some(true),
        smb_signing: Some(true),
        domains,
    });
    r
}

fn outcome(
    name: &str,
    objects: Option<usize>,
    reason: Option<&str>,
) -> crate::workspace::DomainOutcome {
    crate::workspace::DomainOutcome {
        domain: name.into(),
        collected: reason.is_none(),
        objects,
        seconds: Some(61),
        reason: reason.map(str::to_string),
        detail: reason.map(|_| "The domain controller didn't answer in time.".into()),
    }
}

/// A run collected here can be analyzed again with other files,
/// above Remove this run, in the tab and below the report.
#[test]
fn add_other_data_goes_above_remove_this_run() {
    let applies = Ok("The next analysis applies: x.".to_string());
    let dir = std::env::temp_dir().join(format!("pw-rd-add-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut r = collected(Vec::new());
    r.collection.as_mut().unwrap().kept = Some(dir.display().to_string());
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    // In the tab, the button asks the run page; below the report, a
    // link to Analyze with the collection.
    let add = panel
        .find(r#"<div class="rd-add"><h3>Add other data</h3>"#)
        .unwrap();
    assert!(add < panel.find(r#"<div class="rd-remove">"#).unwrap());
    assert!(panel.contains(r#"data-pw-run="add-data"><span>Add files and analyze again</span>"#));
    assert!(panel.contains("Analyzes this run&#39;s collection again with AzureHound, OpenGraph or SharpHound files, as a new run."));
    let add = below
        .find(r#"<h3 class="rd-h" id="rd-add-h">Add other data</h3>"#)
        .unwrap();
    assert!(add < below.find(r#"id="rd-remove-h""#).unwrap());
    assert!(below.contains(r#"<a class="btn" href="/analyze?from=20261027-201900-aaaaaa">Add files and analyze again</a>"#), "{below}");
    // Not kept: greyed out, with why.
    r.collection.as_mut().unwrap().kept = None;
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    assert!(panel.contains(r#"<button type="button" class="rd-btn" disabled><span>Add files and analyze again</span></button><span class="why">The collection wasn&#39;t kept"#), "{panel}");
    assert!(
        below.contains(
            r#"<button type="button" class="btn" disabled>Add files and analyze again</button>"#
        ),
        "{below}"
    );
    assert!(!panel.contains("add-data") && !below.contains("/analyze?from="));
    // Not collected here (an upload, a run from the history): nothing.
    r.collection = None;
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    assert!(!panel.contains("Add other data") && !below.contains("Add other data"));
    assert!(CSS.contains(".rd-btn:disabled{"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A run of several domains says how each went, the attack paths
/// missing through the ones that failed, and links to collect them; the
/// row needs a look.
#[test]
fn the_domains_of_a_run_and_the_ones_that_failed() {
    let applies = Ok("x".to_string());
    let r = collected(vec![
        outcome("CONTOSO.LOCAL", Some(1204), None),
        outcome("CHILD.CONTOSO.LOCAL", Some(988), None),
        outcome("FABRIKAM.COM", Some(4010), None),
        outcome(
            "TAILSPIN.COM",
            None,
            Some("Couldn't reach a domain controller."),
        ),
        outcome("WINGTIP.COM", None, Some("The sign-in was refused.")),
    ]);
    let all = rows(&r, None, &applies);
    let row = all
        .iter()
        .find(|r| r.title == DOMAINS_ROW)
        .expect("a Domains row");
    assert_eq!(row.status, "3 of 5 collected");
    assert!(row.warn && needs_a_look(&all));
    assert_eq!(row.domains[0].text, "Collected · 1,204 objects · 1 min");
    assert_eq!(row.domains[3].text, "Couldn't reach a domain controller.");
    assert!(!row.domains[3].collected);
    assert_eq!(
        row.text,
        [
            "Attack paths through TAILSPIN.COM and WINGTIP.COM are missing. The other 3 domains \
              were analyzed together."
        ]
    );
    assert_eq!(
        row.go_words.as_deref(),
        Some("Collect TAILSPIN.COM and WINGTIP.COM")
    );
    // How it was collected counts them.
    let how = all
        .iter()
        .find(|r| r.title == "How it was collected")
        .unwrap();
    assert!(
        how.text[0].contains("It read 5 domains over LDAPS"),
        "{:?}",
        how.text
    );
    // The tab: each domain on its line, the detail behind an (i), and
    // the link asks the run page.
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    assert!(panel.contains(r#"<ul class="rd-doms"><li><span class="n">CONTOSO.LOCAL</span><span class="ok">Collected · 1,204 objects · 1 min</span></li>"#), "{panel}");
    assert!(
        panel.contains(
            r#"<span class="bad">Couldn&#39;t reach a domain controller.<span class="tip">"#
        ),
        "{panel}"
    );
    assert!(
        panel.contains(
            r##"<p><a href="#" data-pw-run="collect">Collect TAILSPIN.COM and WINGTIP.COM</a></p>"##
        ),
        "{panel}"
    );
    // The run page's own copy links to the Collect page through the run.
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    assert!(below.contains(r#"<a href="/runs/20261027-201900-aaaaaa/collect">Collect TAILSPIN.COM and WINGTIP.COM</a>"#), "{below}");
    assert_eq!(
        crate::collect::collect_again_href(&r).as_deref(),
        Some("/collect?domain=contoso.local&pick=TAILSPIN.COM,WINGTIP.COM")
    );
}

/// After a one-domain run, the trusted domains it didn't collect,
/// with a link to collect them; not a warning. None left out: no row,
/// as for an older run.
#[test]
fn a_one_domain_run_names_the_trusted_domains_left_out() {
    let applies = Ok("x".to_string());
    let mut r = collected(vec![outcome("CONTOSO.LOCAL", Some(1204), None)]);
    r.not_collected = Some(vec!["CHILD.CONTOSO.LOCAL".into(), "FABRIKAM.COM".into()]);
    let all = rows(&r, None, &applies);
    let row = all
        .iter()
        .find(|r| r.title == DOMAINS_ROW)
        .expect("a Domains row");
    assert_eq!(row.status, "1 collected · 2 trusted not collected");
    assert!(!row.warn);
    assert_eq!(row.text, ["2 trusted domains weren't collected."]);
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    assert!(panel.contains(r##"2 trusted domains weren&#39;t collected. <a href="#" data-pw-run="collect">Collect them</a></p>"##), "{panel}");
    assert_eq!(
        crate::collect::collect_again_href(&r).as_deref(),
        Some("/collect?domain=contoso.local&pick=CHILD.CONTOSO.LOCAL,FABRIKAM.COM")
    );
    // An older run reads as its one domain, with the run's own count.
    let mut older = collected(Vec::new());
    older.not_collected = Some(vec!["FABRIKAM.COM".into()]);
    let all = rows(&older, None, &applies);
    let row = all.iter().find(|r| r.title == DOMAINS_ROW).unwrap();
    assert_eq!(row.domains[0].name, "contoso.local");
    assert_eq!(row.domains[0].text, "Collected · 1,204 objects");
    assert_eq!(row.text, ["1 trusted domain wasn't collected."]);
    // Nothing left out: no row.
    let mut all_in = collected(Vec::new());
    all_in.not_collected = Some(Vec::new());
    assert!(rows(&all_in, None, &applies)
        .iter()
        .all(|r| r.title != DOMAINS_ROW));
    assert_eq!(crate::collect::collect_again_href(&all_in), None);
}

/// How it was collected says how computers were signed in to, in
/// one sentence after the first; the skips are collector warnings; an
/// older run says nothing about it.
#[test]
fn how_computers_were_signed_in_to() {
    let applies = Ok(String::new());
    let mut r = point("cli");
    let full = crate::workspace::CollectionInfo {
        read_started: None,
        plain_allowed: false,
        plain_fallback: false,
        method: "builtin".into(),
        scope: "all".into(),
        domain: "scale.local".into(),
        server: Some("dc01.scale.local".into()),
        ldaps: true,
        current_user: false,
        warnings: vec![
            "14 computers were skipped: the domain has no Kerberos name for them. The \
                 collection log names each one."
                .into(),
        ],
        kept: None,
        kerberos_only: Some(true),
        smb_signing: Some(true),
        domains: Vec::new(),
    };
    r.collection = Some(full.clone());
    let all = rows(&r, Some(false), &applies);
    let how = all
        .iter()
        .find(|r| r.title == "How it was collected")
        .unwrap();
    assert_eq!(
        how.text[1],
        "Computers were read with Kerberos only and SMB signing required."
    );
    assert_eq!(how.status, "1 collector warning");
    assert!(how.items[0].starts_with("14 computers were skipped"));

    for (k, s, words) in [
        (
            Some(true),
            Some(false),
            "Computers were read with Kerberos only; SMB signing was not required.",
        ),
        (
            Some(false),
            Some(true),
            "Computers were read with NTLM allowed and SMB signing required.",
        ),
    ] {
        let c = crate::workspace::CollectionInfo {
            kerberos_only: k,
            smb_signing: s,
            ..full.clone()
        };
        assert_eq!(crate::collect::computers_sentence(&c).unwrap(), words);
    }
    let sharphound = crate::workspace::CollectionInfo {
        method: "sharphound".into(),
        kerberos_only: Some(false),
        smb_signing: Some(false),
        ..full.clone()
    };
    assert!(crate::collect::computers_sentence(&sharphound)
        .unwrap()
        .contains("weren't enforced: SharpHound"));
    let windows = crate::workspace::CollectionInfo {
        current_user: true,
        smb_signing: None,
        ..full.clone()
    };
    assert_eq!(
        crate::collect::computers_sentence(&windows).unwrap(),
        "Computers were read with Kerberos only; SMB signing was left to Windows."
    );
    let older = crate::workspace::CollectionInfo {
        kerberos_only: None,
        smb_signing: None,
        ..full
    };
    assert_eq!(crate::collect::computers_sentence(&older), None);
    // The record keeps no field it doesn't know.
    let json = serde_json::to_value(&older).unwrap();
    assert!(json.get("kerberos_only").is_none());
}

fn settings_file(
    server: &str,
    kind: pathwarden_core::dcsettings::ServerKind,
    day: &str,
    stale: bool,
) -> pathwarden_core::dcsettings::SettingsFileUse {
    pathwarden_core::dcsettings::SettingsFileUse {
        file_name: format!("pathwarden-tierzero-{server}.json"),
        server: server.into(),
        kind,
        read_at: pathwarden_core::dcsettings::parse_utc(&format!("{day}T10:00:00Z")),
        stale,
        applied: true,
    }
}

/// The Tier Zero settings files row, between "Where it came from"
/// and "Run history": each file, the oldest, and the link to the
/// settings folders; fewer than the last run said there, not on the
/// Overview.
#[test]
fn the_settings_files_row_lists_each_file() {
    use pathwarden_core::dcsettings::ServerKind::{Ca, Dc};
    let applies = Ok("x".to_string());
    let mut r = point("cli");
    // An older run: no row.
    assert!(!rows(&r, None, &applies)
        .iter()
        .any(|x| x.title == SETTINGS_FILES_ROW));
    r.history = Some(crate::workspace::HistoryLink {
        run_id: Some("r1".into()),
        ..Default::default()
    });
    r.settings_files = vec![
        settings_file("DC01.contoso.local", Dc, "2026-10-29", false),
        settings_file("DC04.contoso.local", Dc, "2026-07-14", true),
        settings_file("CONTOSO-CA", Ca, "2026-10-29", false),
    ];
    let all = rows(&r, None, &applies);
    let titles: Vec<&str> = all.iter().map(|x| x.title).collect();
    let at = titles
        .iter()
        .position(|t| *t == SETTINGS_FILES_ROW)
        .unwrap();
    assert_eq!(titles[at - 1], "Where it came from");
    assert_eq!(titles[at + 1], HISTORY_ROW);
    let row = &all[at];
    assert_eq!(row.status, "3 files, 1 over 90 days old");
    assert!(row.warn);
    assert_eq!(
        row.settings[0].text.text(),
        "Domain controller. Settings read Oct 29, 2026."
    );
    assert_eq!(
            row.settings[1].text.text(),
            "Domain controller. Settings read Jul 14, 2026. Over 90 days old, so it can confirm a weakness but can't show that one was fixed."
        );
    assert_eq!(
        row.settings[2].text.text(),
        "Certification authority. Settings read Oct 29, 2026."
    );
    assert_eq!(
        row.settings[1].detail,
        "File name: pathwarden-tierzero-DC04.contoso.local.json"
    );
    assert_eq!(
        row.dated[0].0.text(),
        "This run used 3 settings files. The oldest is from Jul 14, 2026."
    );
    assert_eq!(row.dated[0].1, Some(SETTINGS_FILES_TIP));
    assert!(row.text.is_empty());
    // The tab: the date in local time on the page, the file name behind
    // an (i), the link asks the run page for the settings folders.
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    assert!(panel.contains(r#"<li><span class="n">DC04.contoso.local</span><span class="bad">Domain controller. Settings read <time data-unix="#), "{panel}");
    assert!(panel.contains(r#"data-fmt="date" datetime="2026-07-14T10:00:00Z" title="Jul 14, 2026, 10:00 AM UTC">Jul 14, 2026</time>. Over 90 days old"#), "{panel}");
    assert!(panel.contains("File name: pathwarden-tierzero-DC04.contoso.local.json"));
    assert!(
        panel.contains(
            r##"<a href="#" data-pw-run="settings-folders">Change the settings folders</a>"##
        ),
        "{panel}"
    );
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    assert!(
        below.contains(r#"<a href="/settings#settings-folders">Change the settings folders</a>"#),
        "{below}"
    );

    // Fewer than the last run, and a folder that couldn't be opened.
    r.settings_files.truncate(2);
    r.history.as_mut().unwrap().settings_fewer =
        vec!["DC03.contoso.local".into(), "CONTOSO-CA".into()];
    r.settings_folders_unread = 1;
    let all = rows(&r, None, &applies);
    let row = all.iter().find(|x| x.title == SETTINGS_FILES_ROW).unwrap();
    assert_eq!(
        row.status,
        "2 files, 1 over 90 days old, 2 fewer than the last run"
    );
    assert_eq!(
            row.text,
            [
                "The last run also had files for DC03.contoso.local and CONTOSO-CA. Findings that relied on them are marked unverified until the files are back. They don't count as fixed.",
                "A settings folder couldn't be opened, so its files weren't read.",
            ]
        );
    // Kept with the run, read back.
    let back: RunSummary = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back.settings_files, r.settings_files);
    assert_eq!(back.settings_folders_unread, 1);
    assert_eq!(
        back.history.unwrap().settings_fewer,
        ["DC03.contoso.local", "CONTOSO-CA"]
    );
    // No folder path anywhere in the record.
    assert!(!serde_json::to_string(&r).unwrap().contains("\\\\"));
}

/// AzureHound's hybrid test data as analyzed, with its OpenGraph
/// statistics where Run details reads them ([`with_sources`]).
fn azure_with_sources() -> RunSummary {
    let data = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/entra");
    let a = pathwarden_core::analyze::run(
        &[data.join("ad"), data.join("azurehound")],
        &pathwarden_core::config::Config::default(),
        &[],
        &mut pathwarden_core::analyze::Quiet,
    )
    .unwrap();
    let mut r = RunSummary::new("r1", 1, "test".into(), false, &a);
    r.other_sources = Some(Box::new(a.stats.opengraph.clone()));
    r
}

/// The "Other sources" row (the run page's former Detected sources
/// panel): right after "Where it came from", closed when nothing needs
/// a look; each source's facts, the retest sentence and the Mappings
/// link, in the tab and in the run page's own copy. A run without
/// OpenGraph data has none.
#[test]
fn other_sources_follow_where_it_came_from() {
    let applies = Ok("The next analysis applies: x.".to_string());
    let r = azure_with_sources();
    let all = rows(&r, None, &applies);
    assert_eq!(all[0].title, "Where it came from");
    let row = &all[1];
    assert_eq!(row.title, OTHER_SOURCES_ROW);
    assert_eq!(row.status, "AzureHound · trusted mapping");
    assert!(!row.warn && !needs_a_look(&all));
    let labels: Vec<&str> = row
        .facts
        .iter()
        .map(|(k, _, _)| *k)
        .filter(|k| *k != "Dropped")
        .collect();
    assert_eq!(
        labels,
        [
            "Source",
            "Objects",
            "Relationships kept",
            "Read",
            "Mapping",
            "Coverage"
        ]
    );
    let get = |k: &str| {
        row.facts
            .iter()
            .find(|(f, _, _)| *f == k)
            .map(|(_, v, _)| v.as_str())
            .unwrap()
    };
    assert!(
        get("Source").starts_with("AzureHound, OpenGraph · 1 file: "),
        "{:?}",
        row.facts
    );
    assert_eq!(get("Read"), "Read whole");
    assert!(get("Mapping").starts_with("Trusted, "), "{:?}", row.facts);
    assert!(
        get("Mapping").ends_with(" pack: its mapped relationships make attack paths and findings.")
    );
    assert_eq!(get("Coverage"), "From the collector: 1 tenant.");
    assert_eq!(
            row.text.last().unwrap(),
            "For retests: Findings that rest on these sources are marked Fixed only when this coverage says the affected host was scanned again."
        );
    assert_eq!(row.go, Some(Go::Mappings));

    // The tab: closed, with the link asking the run page.
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    assert!(
            panel.contains(r#"<details class="row env"><summary><span class="title">Other sources</span><span class="aside">AzureHound · trusted mapping</span></summary>"#),
            "{panel}"
        );
    assert!(panel.contains("<dt>Coverage</dt><dd>From the collector: 1 tenant.</dd>"));
    assert!(panel.contains(
        r##"<p><a href="#" data-pw-run="mappings">Mappings</a> lists what each pack means.</p>"##
    ));
    let at = |h: &str, t: &str| h.find(t).unwrap();
    assert!(at(&panel, "Where it came from") < at(&panel, "Other sources"));
    // The run page's own copy: a real link.
    let below = below_html(&r, None, &applies, Remove::Hide, None);
    assert!(
            below.contains(r#"<details class="rd-r"><summary><span class="rd-t">Other sources</span><span class="rd-s">AzureHound · trusted mapping</span></summary>"#),
            "{below}"
        );
    assert!(
        below.contains(r#"<p><a href="/mappings">Mappings</a> lists what each pack means.</p>"#)
    );
    assert!(fallback_html(&r, None, &applies, Remove::Hide, None).contains("Other sources"));
    assert_eq!(Go::Mappings.href(&r), "/mappings");

    // Not read: no row.
    let mut plain = r.clone();
    plain.other_sources = None;
    assert!(!rows(&plain, None, &applies)
        .iter()
        .any(|x| x.title == OTHER_SOURCES_ROW));
    // Never in the summary file.
    assert!(!serde_json::to_string(&r).unwrap().contains("other_sources"));
}

/// Sources without coverage, untrusted or unmapped, read only partly,
/// with unused coverage files and kinds no pack describes: an amber,
/// open row that keeps every fact the panel had. Names are escaped.
#[test]
fn other_sources_that_need_a_look() {
    let applies = Ok("The next analysis applies: x.".to_string());
    let stats: pathwarden_core::ingest::OpenGraphStats =
        serde_json::from_value(serde_json::json!({
            "sources": [
                { "name": "ContosoHound", "pack": "contoso", "trusted": false,
                  "files": ["uploads/r/1/contoso.json"], "nodes": 1200, "merged": 3,
                  "created": 1190, "placeholders": 7, "edges": 40, "context_edges": 40,
                  "dropped_native": 2, "unresolved": 1, "complete": true,
                  "coverage": { "state": "none" } },
                { "name": "<b>FabrikamHound</b>", "files": ["a.zip!fabrikam.json"],
                  "complete": false, "caps_hit": ["edges"],
                  "coverage": { "state": "sidecar", "asserted_by": "user", "ok": ["S-1"],
                                "all_in_domains": ["FABRIKAM.LOCAL"], "complete": true } }
            ],
            "packs": [{ "name": "contoso", "title": "Contoso", "version": 1, "trusted": false }],
            "unmapped_kinds": { "FB_Knows": 3 },
            "unused_sidecars": ["uploads/r/1/stray.coverage.json"]
        }))
        .unwrap();
    let mut r = azure_with_sources();
    r.other_sources = Some(Box::new(stats));
    let all = rows(&r, None, &applies);
    let row = &all[1];
    assert_eq!(row.title, OTHER_SOURCES_ROW);
    assert!(row.warn && needs_a_look(&all));
    assert_eq!(
        row.status,
        "ContosoHound, <b>FabrikamHound</b> · 2 untrusted mappings"
    );
    let has = |k: &str, v: &str| row.facts.iter().any(|(f, t, _)| *f == k && t == v);
    for (k, v) in [
            ("Source", "ContosoHound, OpenGraph · 1 file: contoso.json"),
            ("Objects", "1,200 read: 3 matched to AD, 1,190 new, 7 unknown"),
            ("Relationships kept", "40 (40 context only)"),
            ("Dropped", "2 AD relationships (only AD data may say them); 1 with an end not found"),
            ("Mapping", "Untrusted, context only: the Contoso pack labels its kinds; nothing from it is part of a path until the pack is trusted on Mappings."),
            ("Coverage", "No coverage file. Its findings can open, but are never marked Fixed: a missing finding could be a host the collector didn't reach."),
            ("Source", "<b>FabrikamHound</b>, OpenGraph · 1 file: a.zip!fabrikam.json"),
            ("Read", "Read only partly (limit hit: edges)"),
            ("Mapping", "No mapping, context only: shown in Explore; never part of a path, finding or plan."),
            ("Coverage", "Coverage file bound, declared by a person: every enabled computer in FABRIKAM.LOCAL, 1 computer listed."),
        ] {
            assert!(has(k, v), "{k}: {v} in {:?}", row.facts);
        }
    assert_eq!(
            row.text,
            [
                "Relationship kinds no pack describes (context only): FB_Knows 3.",
                "Coverage files not used: stray.coverage.json.",
                "For retests: Findings that rest on ContosoHound can't be marked Fixed by a later run or retest: without coverage, their absence proves nothing. To declare what was scanned, analyze the files again from Analyze and fill in the coverage form under Detected sources.",
            ]
        );
    let panel = panel_html(&r, None, &applies, Remove::Hide, "n", None);
    assert!(
            panel.contains(r#"<details class="row env" open><summary><span class="title">Other sources</span><span class="aside warn">ContosoHound, &lt;b&gt;FabrikamHound&lt;/b&gt; · 2 untrusted mappings</span>"#),
            "{panel}"
        );
    assert!(!panel.contains("<b>FabrikamHound"));
    assert!(below_html(&r, None, &applies, Remove::Hide, None).contains(
        r#"<details class="rd-r warn" open><summary><span class="rd-t">Other sources</span>"#
    ));

    // Only unused coverage files: said, without the retest sentence.
    let only: pathwarden_core::ingest::OpenGraphStats =
        serde_json::from_value(serde_json::json!({ "unused_sidecars": ["stray.coverage.json"] }))
            .unwrap();
    r.other_sources = Some(Box::new(only));
    let all = rows(&r, None, &applies);
    assert_eq!(all[1].status, "Coverage files not used");
    assert_eq!(
        all[1].text,
        ["Coverage files not used: stray.coverage.json."]
    );
    assert_eq!(all[1].go, None);
}
