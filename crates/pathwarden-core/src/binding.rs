//! What ties each encrypted history file to its place: its path, its
//! run where it has one, and a sequence number, kept inside the encrypted
//! content and checked when the file is read.
//!
//! Without it, anyone who can write to the repository could put an older
//! encrypted copy of a file back (a rollback), or move one file into
//! another's place: age decrypts both without complaint.
//!
//! # Format
//!
//! The decrypted content of every file Pathwarden writes into an encrypted
//! history starts with one line, then the file as it would be in plain
//! text:
//!
//! ```text
//! pathwarden-binding/1 {"path":"history/20261018T170000.000Z.json","run":"20261018T170000.000Z","seq":3}
//! ```
//!
//! - `pathwarden-binding/<version>` ([`VERSION`]): a newer version is
//!   refused, in one sentence as every binding refusal: "... in the
//!   history needs a newer Pathwarden (binding version N)."
//! - `path`: the file's name in the history, without `.age`
//!   (`findings.json`, `history/<run>.json`, `runs/<run>/report.html.gz`).
//! - `run`: the run ID the path names (`history/`, `timings/`, `exposed/`,
//!   `runs/`), absent for the other files.
//! - `seq`: one more than the file had before, at that path. A file whose
//!   `seq` is lower than the highest this computer has seen at that path
//!   is refused.
//!
//! An encrypted history whose marker says format 1 was written before
//! this binding: its files are read without one (the upgrade path), and
//! the first write binds them all and sets format 2
//! ([`crate::crypt::FORMAT`]). From format 2 on, a file without a binding
//! is refused.
//!
//! # What each computer remembers
//!
//! The highest sequence seen at each path is kept on this computer, never
//! in the history: in the account's data beside the sticky "this history
//! is encrypted" records ([`crate::keystore::pins_dir`]), one record per
//! history folder and key. A new key (encryption turned on again, or the
//! passphrase changed) starts a new record. A computer with no record
//! accepts what it finds (trust on first use).
//!
//! In a git history a sequence is remembered only once the remote has the
//! file as it is on disk (see `store.rs`, `on_remote`), never for a write
//! of this computer's own that has not been pushed: another computer's
//! push wins a race, this computer's write is dropped, and the remote's
//! file, with the same or a lower sequence, must not look like a rollback.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// The binding line's version this Pathwarden writes and reads.
pub const VERSION: u32 = 1;

/// How the binding line starts.
const PREFIX: &[u8] = b"pathwarden-binding/";

/// The longest binding line read: paths are short.
const MAX_LINE: usize = 4096;

/// The binding of one file ([module docs](self)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binding {
    /// The file's name in the history, without `.age`.
    pub path: String,
    /// The run ID the path names, if it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// One more than the file had before at this path.
    pub seq: u64,
}

impl Binding {
    /// The binding of `rel` at sequence `seq`.
    pub fn new(rel: &str, seq: u64) -> Self {
        Binding {
            path: rel.to_string(),
            run: run_of(rel),
            seq,
        }
    }
}

/// The run ID a history path names: `history/<run>.json`,
/// `timings/<run>.json`, `exposed/<run>.json`, `runs/<run>/<name>`.
pub fn run_of(rel: &str) -> Option<String> {
    let (folder, rest) = rel.split_once('/')?;
    match folder {
        "history" | "timings" | crate::exposed::DIR => {
            rest.strip_suffix(".json").map(str::to_string)
        }
        "runs" => rest.split_once('/').map(|(id, _)| id.to_string()),
        _ => None,
    }
}

/// `body` with its binding line in front: what is encrypted.
pub fn wrap(binding: &Binding, body: &[u8]) -> Vec<u8> {
    let json = serde_json::to_string(binding).expect("a binding serializes");
    let mut out = Vec::with_capacity(PREFIX.len() + 8 + json.len() + body.len());
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(format!("{VERSION} {json}\n").as_bytes());
    out.extend_from_slice(body);
    out
}

/// What decrypted content holds: a binding, or none (written before it).
#[derive(Debug)]
pub enum Parsed {
    /// Written before the binding: the content is the file.
    Unbound(Vec<u8>),
    /// The binding, and the file after it.
    Bound(Binding, Vec<u8>),
}

/// Splits decrypted content ([`wrap`]) into its binding and the file.
/// Content that doesn't start with the binding line is [`Parsed::Unbound`];
/// a newer version, or a line that can't be read, is an error.
pub fn parse(mut plain: Vec<u8>) -> Result<Parsed, Problem> {
    if !plain.starts_with(PREFIX) {
        return Ok(Parsed::Unbound(plain));
    }
    let end = plain
        .iter()
        .take(MAX_LINE)
        .position(|&b| b == b'\n')
        .ok_or(Problem::Damaged)?;
    let line = std::str::from_utf8(&plain[PREFIX.len()..end]).map_err(|_| Problem::Damaged)?;
    let (version, json) = line.split_once(' ').ok_or(Problem::Damaged)?;
    let version: u32 = version.parse().map_err(|_| Problem::Damaged)?;
    if version > VERSION {
        return Err(Problem::Newer(version));
    }
    let binding: Binding = serde_json::from_str(json).map_err(|_| Problem::Damaged)?;
    plain.drain(..=end);
    Ok(Parsed::Bound(binding, plain))
}

/// Why a file of an encrypted history was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// Its binding names another path or run: it was moved or copied there.
    Moved,
    /// Its sequence is lower than this computer has seen, or it has no
    /// binding where every file has one: an older copy.
    Older,
    /// No binding, where the marker says every file has one: a copy from
    /// before the binding put back. Worded as [`Problem::Older`]; no
    /// record of this computer's accepts it.
    Unbound,
    /// The history's marker says format 1 again where this computer saw
    /// format 2.
    MarkerOlder,
    /// Bound by a newer Pathwarden (the binding's version).
    Newer(u32),
    /// The binding line can't be read.
    Damaged,
}

/// A file of an encrypted history refused by its binding. What it says
/// is for any page: one plain sentence, no commands. The command line
/// adds [`BindingError::hint`].
#[derive(Debug, Clone)]
pub struct BindingError {
    /// What was wrong.
    pub problem: Problem,
    /// The file, by its name in the history.
    pub rel: String,
    /// This computer's records that make it refuse the file (resetting
    /// them, [`crate::store::accept_history`], accepts the history as it
    /// is): none when no record is involved.
    pub records: Vec<PathBuf>,
    /// Whether the history is a git repository (else a folder).
    pub git: bool,
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rel = &self.rel;
        match self.problem {
            Problem::Moved => write!(
                f,
                "{rel} in the history was replaced with another file of the history."
            ),
            Problem::Older | Problem::Unbound => {
                write!(f, "{rel} in the history was replaced with an older copy.")
            }
            Problem::MarkerOlder => write!(
                f,
                "The history's encryption marker was replaced with an older one."
            ),
            Problem::Newer(v) => write!(
                f,
                "{rel} in the history needs a newer Pathwarden (binding version {v})."
            ),
            Problem::Damaged => write!(f, "{rel} in the history is damaged."),
        }
    }
}

impl std::error::Error for BindingError {}

impl BindingError {
    /// Whether accepting the history as it is
    /// ([`crate::store::accept_history`]) gets past this refusal: an older
    /// copy, or the marker set back, that this computer's records refuse.
    /// Never a file without a binding where every file has one, a newer
    /// binding, a damaged one or a moved file: accepting changes nothing
    /// there.
    pub fn acceptable(&self) -> bool {
        matches!(self.problem, Problem::Older | Problem::MarkerOlder) && !self.records.is_empty()
    }

    /// Why, in a few words, after the file's name in a list of files left
    /// out.
    pub fn short(&self) -> &'static str {
        match self.problem {
            Problem::Moved => "another file of the history was put in its place",
            Problem::Older | Problem::Unbound | Problem::MarkerOlder => {
                "an older copy was put back"
            }
            Problem::Newer(_) => "needs a newer Pathwarden",
            Problem::Damaged => "damaged",
        }
    }

    /// What to do, for the command line.
    pub fn hint(&self) -> Option<String> {
        let restore = if self.git {
            "Restore the file from the repository's earlier commits, or remove it there."
        } else {
            "Restore the file from a backup, or remove it from the folder."
        };
        let older = if self.git {
            "If nobody restored the history on purpose, someone who can write to the repository \
             put an older copy back: revert the commit that did."
        } else {
            "If nobody restored the history on purpose, someone who can write to the folder put \
             an older copy back: put the newer copy back from a backup."
        };
        let accept = if self.acceptable() {
            " If it was restored on purpose, run `pathwarden history storage accept` with the \
             same options to accept the history as it is now."
        } else {
            ""
        };
        Some(match self.problem {
            Problem::Newer(_) => "Upgrade Pathwarden on this computer to read it.".to_string(),
            Problem::Damaged | Problem::Moved => restore.to_string(),
            Problem::Unbound => older.to_string(),
            Problem::Older | Problem::MarkerOlder => format!("{older}{accept}"),
        })
    }
}

/// This computer's mark that it saw the history folder `history` (its
/// [`crate::keystore::history_key`]) with a format-2 marker, under any
/// key: a marker set back to format 1 is refused there from then on,
/// even with a key file put back too.
pub fn format2_mark_for(history: &str) -> Option<PathBuf> {
    let pins = crate::keystore::pins_dir().ok().flatten()?;
    let id = crate::crypt::digest_hex(format!("{history}\nformat 2").as_bytes());
    Some(pins.join("sequences").join(format!("{id}.format2")))
}

/// Leaves [`format2_mark_for`]'s mark. Best effort, as the records.
pub fn mark_format2(mark: &Path) {
    if mark.is_file() {
        return;
    }
    if let Some(parent) = mark.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        mark,
        "Pathwarden saw this history's encryption marker at format 2 on this computer; format 1 \
         is refused here from now on. Deleting this file accepts it.\n",
    );
}

/// What this computer has seen of one history under one key.
#[derive(Debug, Default)]
struct Seen {
    /// The highest sequence seen at each path.
    seqs: HashMap<String, u64>,
    /// The marker said format 2 (every file bound).
    bound: bool,
    /// The record's length when read, to notice another process's lines.
    len: u64,
}

/// One line of a record: a sequence seen, or the marker seen at format 2.
#[derive(Debug, Serialize, Deserialize)]
struct Line {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    bound: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

fn cache() -> std::sync::MutexGuard<'static, HashMap<PathBuf, Seen>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Seen>>> = OnceLock::new();
    CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// This computer's record for the history folder `history` (its
/// [`crate::keystore::history_key`]) under the key whose public half is
/// `public`: `None` where this account keeps no records (a debug build
/// without the test store, an account without a profile).
pub fn record_for(history: &str, public: &str) -> Option<PathBuf> {
    let pins = crate::keystore::pins_dir().ok().flatten()?;
    let id = crate::crypt::digest_hex(format!("{history}\n{public}").as_bytes());
    Some(pins.join("sequences").join(format!("{id}.jsonl")))
}

/// Reads `record` into the cache when it isn't there or another process
/// added to it, and runs `f` on what it holds.
fn with_seen<T>(record: &Path, f: impl FnOnce(&mut Seen) -> T) -> T {
    let mut c = cache();
    let len = std::fs::metadata(record).map(|m| m.len()).unwrap_or(0);
    let stale = c.get(record).is_none_or(|s| s.len != len);
    if stale {
        c.insert(record.to_path_buf(), load(record, len));
    }
    f(c.get_mut(record).expect("just cached"))
}

fn load(record: &Path, len: u64) -> Seen {
    let mut seen = Seen {
        len,
        ..Seen::default()
    };
    let Ok(text) = std::fs::read_to_string(record) else {
        return seen;
    };
    let mut lines = 0usize;
    for l in text.lines() {
        lines += 1;
        let Ok(line) = serde_json::from_str::<Line>(l) else {
            continue;
        };
        seen.bound |= line.bound;
        if let (Some(p), Some(s)) = (line.path, line.seq) {
            let e = seen.seqs.entry(p).or_default();
            *e = (*e).max(s);
        }
    }
    // Lines only ever added: written again, one per path, once mostly
    // superseded.
    if lines > 2 * seen.seqs.len() + 512 {
        let mut out = header();
        if seen.bound {
            out.push_str(&line(&Line {
                path: None,
                seq: None,
                bound: true,
                note: None,
            }));
        }
        let mut seqs: Vec<_> = seen.seqs.iter().collect();
        seqs.sort();
        for (p, s) in seqs {
            out.push_str(&line(&Line {
                path: Some(p.clone()),
                seq: Some(*s),
                bound: false,
                note: None,
            }));
        }
        let tmp = record.with_extension(format!("{}.tmp", std::process::id()));
        if std::fs::write(&tmp, &out).is_ok() && std::fs::rename(&tmp, record).is_ok() {
            seen.len = out.len() as u64;
        } else {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    seen
}

fn header() -> String {
    line(&Line {
        path: None,
        seq: None,
        bound: false,
        note: Some(
            "Pathwarden: the highest sequence seen at each path of one encrypted history on \
             this computer. A lower one is refused as an older copy. Deleting this file \
             accepts the history as it is."
                .into(),
        ),
    })
}

fn line(l: &Line) -> String {
    let mut s = serde_json::to_string(l).expect("a record line serializes");
    s.push('\n');
    s
}

/// Adds `text` to `record` (made with its header when new). Best effort:
/// a record that can't be written only remembers less.
fn append(record: &Path, seen: &mut Seen, text: &str) {
    if let Some(parent) = record.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let new = !record.exists();
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(record)
    else {
        return;
    };
    let text = if new {
        format!("{}{text}", header())
    } else {
        text.to_string()
    };
    if f.write_all(text.as_bytes()).is_ok() {
        seen.len = std::fs::metadata(record)
            .map(|m| m.len())
            .unwrap_or(seen.len + text.len() as u64);
    }
}

/// The highest sequence this computer has seen at `rel`.
pub fn last_seen(record: &Path, rel: &str) -> Option<u64> {
    with_seen(record, |s| s.seqs.get(rel).copied())
}

/// Whether this computer saw the history's marker at format 2.
pub fn seen_bound(record: &Path) -> bool {
    with_seen(record, |s| s.bound)
}

/// Remembers `seq` at `rel`, when higher than what was seen.
pub fn advance(record: &Path, rel: &str, seq: u64) {
    with_seen(record, |s| {
        if s.seqs.get(rel).is_some_and(|&had| had >= seq) {
            return;
        }
        s.seqs.insert(rel.to_string(), seq);
        append(
            record,
            s,
            &line(&Line {
                path: Some(rel.to_string()),
                seq: Some(seq),
                bound: false,
                note: None,
            }),
        );
    });
}

/// Deletes `record`, and what this process cached of it.
pub fn forget(record: &Path) {
    let mut c = cache();
    let _ = std::fs::remove_file(record);
    c.remove(record);
}

/// Refusals this process met that accepting the history would get past
/// ([`BindingError::acceptable`]), by history folder
/// ([`crate::keystore::history_key`]) and file, for the app's pages to
/// offer it where they show the history.
type Refusals = HashMap<String, std::collections::BTreeMap<String, BindingError>>;

fn refusals() -> std::sync::MutexGuard<'static, Refusals> {
    static REFUSED: OnceLock<Mutex<Refusals>> = OnceLock::new();
    REFUSED
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Keeps `e` for [`refused`] when it is [`BindingError::acceptable`];
/// otherwise forgets what was kept for its file (accepting wouldn't help
/// there any more).
pub fn note_refused(history: &str, e: &BindingError) {
    if e.acceptable() {
        refusals()
            .entry(history.to_string())
            .or_default()
            .insert(e.rel.clone(), e.clone());
    } else {
        clear_refused(history, Some(&e.rel));
    }
}

/// Forgets the refusal of `rel` (read since without one), or with `None`
/// every refusal of the history (accepted).
pub fn clear_refused(history: &str, rel: Option<&str>) {
    let mut r = refusals();
    match rel {
        Some(rel) => {
            if let Some(files) = r.get_mut(history) {
                files.remove(rel);
                if files.is_empty() {
                    r.remove(history);
                }
            }
        }
        None => {
            r.remove(history);
        }
    }
}

/// A refusal of the history folder `history` that accepting it would get
/// past, as this process last met it (the first file, by name).
pub fn refused(history: &str) -> Option<BindingError> {
    refusals().get(history)?.values().next().cloned()
}

/// Remembers that the marker said format 2.
pub fn mark_bound(record: &Path) {
    with_seen(record, |s| {
        if s.bound {
            return;
        }
        s.bound = true;
        append(
            record,
            s,
            &line(&Line {
                path: None,
                seq: None,
                bound: true,
                note: None,
            }),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binding_wraps_and_parses_back() {
        let b = Binding::new("history/20261018T170000.000Z.json", 3);
        assert_eq!(b.run.as_deref(), Some("20261018T170000.000Z"));
        let wrapped = wrap(&b, b"{\"a\": 1}\n");
        assert!(wrapped.starts_with(b"pathwarden-binding/1 {\"path\":\"history/"));
        match parse(wrapped).unwrap() {
            Parsed::Bound(got, body) => {
                assert_eq!(got, b);
                assert_eq!(body, b"{\"a\": 1}\n");
            }
            Parsed::Unbound(_) => panic!("bound"),
        }
        // Files from before the binding.
        assert!(matches!(
            parse(b"{\"version\": 3}".to_vec()).unwrap(),
            Parsed::Unbound(_)
        ));
        assert!(matches!(parse(Vec::new()).unwrap(), Parsed::Unbound(_)));
        // A newer version, a damaged line.
        assert_eq!(
            parse(b"pathwarden-binding/2 {}\nx".to_vec()).unwrap_err(),
            Problem::Newer(2)
        );
        assert_eq!(
            parse(b"pathwarden-binding/1 {\"path\":1}\nx".to_vec()).unwrap_err(),
            Problem::Damaged
        );
        assert_eq!(
            parse(b"pathwarden-binding/1 no end".to_vec()).unwrap_err(),
            Problem::Damaged
        );
    }

    #[test]
    fn runs_come_from_the_path() {
        assert_eq!(run_of("findings.json"), None);
        assert_eq!(run_of("settings/pathwarden.toml"), None);
        assert_eq!(run_of("timings/X.json").as_deref(), Some("X"));
        assert_eq!(run_of("exposed/X.json").as_deref(), Some("X"));
        assert_eq!(run_of("runs/X/report.html.gz").as_deref(), Some("X"));
        assert_eq!(Binding::new("last-run.json", 1).run, None);
    }

    #[test]
    fn words_on_pages_name_no_command() {
        for problem in [
            Problem::Moved,
            Problem::Older,
            Problem::Unbound,
            Problem::MarkerOlder,
            Problem::Newer(2),
            Problem::Damaged,
        ] {
            for git in [true, false] {
                let e = BindingError {
                    problem,
                    rel: "findings.json".into(),
                    records: vec![PathBuf::from("r.jsonl")],
                    git,
                };
                let text = e.to_string();
                // One sentence.
                assert!(text.ends_with('.'), "{text}");
                assert_eq!(text.matches(". ").count(), 0, "{text}");
                assert!(
                    !text.contains('`') && !text.contains("pathwarden "),
                    "{text}"
                );
                assert!(!text.contains("r.jsonl"), "{text}");
                // The command line's hint: git words for git only.
                let hint = e.hint().unwrap();
                if !matches!(problem, Problem::Newer(_)) {
                    assert_eq!(hint.contains("commit"), git, "{hint}");
                }
                let accepts = matches!(problem, Problem::Older | Problem::MarkerOlder);
                assert_eq!(e.acceptable(), accepts, "{problem:?}");
                assert_eq!(
                    hint.contains("pathwarden history storage accept"),
                    accepts,
                    "{hint}"
                );
                // Records are this computer's business: the command resets
                // them.
                assert!(!hint.contains("r.jsonl"), "{hint}");
                assert!(!hint.contains("  "), "{hint:?}");
                if accepts {
                    assert!(
                        hint.ends_with(
                            " If it was restored on purpose, run `pathwarden history storage \
                             accept` with the same options to accept the history as it is now."
                        ),
                        "{hint:?}"
                    );
                }
            }
        }
        // No record: nothing to accept, so the command isn't named.
        let e = BindingError {
            problem: Problem::Older,
            rel: "findings.json".into(),
            records: Vec::new(),
            git: true,
        };
        assert!(!e.acceptable());
        assert!(!e.hint().unwrap().contains("accept"));
    }

    #[test]
    fn a_record_keeps_the_highest_and_reads_back() {
        let dir =
            std::env::temp_dir().join(format!("pathwarden-binding-record-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let record = dir.join("r.jsonl");
        assert_eq!(last_seen(&record, "findings.json"), None);
        advance(&record, "findings.json", 3);
        advance(&record, "findings.json", 2);
        advance(&record, "last-run.json", 1);
        mark_bound(&record);
        assert_eq!(last_seen(&record, "findings.json"), Some(3));
        // Another process's view: read from the file.
        cache().remove(&record);
        assert_eq!(last_seen(&record, "findings.json"), Some(3));
        assert_eq!(last_seen(&record, "last-run.json"), Some(1));
        assert!(seen_bound(&record));
        // Lines added by another process are noticed.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&record)
            .unwrap();
        f.write_all(b"{\"path\":\"findings.json\",\"seq\":9}\n")
            .unwrap();
        drop(f);
        assert_eq!(last_seen(&record, "findings.json"), Some(9));
        // Superseded lines are written again once there are many.
        for s in 10..1200 {
            advance(&record, "findings.json", s);
        }
        cache().remove(&record);
        assert_eq!(last_seen(&record, "findings.json"), Some(1199));
        let lines = std::fs::read_to_string(&record).unwrap().lines().count();
        assert!(lines < 10, "{lines} lines");
        cache().remove(&record);
        assert_eq!(last_seen(&record, "findings.json"), Some(1199));
        assert!(seen_bound(&record));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
