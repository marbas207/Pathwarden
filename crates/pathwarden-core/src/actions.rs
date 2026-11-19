//! Finding actions: a program someone runs for one finding, when they ask
//! (`[[action]]` in pathwarden.toml, [`ActionConfig`]). Shared by
//! `pathwarden action` and the app, which call the same functions.
//!
//! The protocol (v1, only ever extended; docs/dev/formats.md):
//! - Pathwarden writes one JSON request (`pathwarden.action-request.v1`) to
//!   the program's stdin, and names its kind (`describe` or `run`) in
//!   `PATHWARDEN_ACTION_REQUEST`.
//! - The program writes one JSON answer to the file named in
//!   `PATHWARDEN_ACTION_RESULT`: for `describe` the actions it offers
//!   (`pathwarden.action-describe.v1`), for `run` what it did
//!   (`pathwarden.action-result.v1`).
//! - Each line it prints to stdout is a progress line, shown as it comes;
//!   stderr is kept for the details.
//!
//! Every answer is checked strictly ([`parse_describe`], [`parse_result`]):
//! text is cut to its cap and never read as HTML, links must be `https://`,
//! fields Pathwarden doesn't know are ignored. A missing or broken result
//! is a failed run, shown with the program's output.
//!
//! The program is found, checked and started as output plugins are
//! ([`crate::plugins`]): the same program rules, cleared environment plus
//! `*_env`, private folder and process-tree kill. Actions never run
//! unattended ([`crate::store::unattended`]).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::config::ActionConfig;
use crate::findings::{Category, Severity};
pub use crate::plugins::CancelHandle;
use crate::plugins::{self, PluginError};

pub const DESCRIBE_SCHEMA: &str = "pathwarden.action-describe.v1";
pub const REQUEST_SCHEMA: &str = "pathwarden.action-request.v1";
pub const RESULT_SCHEMA: &str = "pathwarden.action-result.v1";

/// Holds the request's kind: `describe` or `run`.
pub const REQUEST_ENV: &str = "PATHWARDEN_ACTION_REQUEST";
/// Holds the full path of the file the program writes its answer to.
pub const RESULT_ENV: &str = "PATHWARDEN_ACTION_RESULT";

/// Most actions one program may offer.
pub const MAX_ACTIONS: usize = 20;
/// Most inputs one action may ask for.
pub const MAX_INPUTS: usize = 20;
/// Longest action or input ID.
pub const MAX_ID: usize = 40;
/// Longest label (an action's button, an input's name).
pub const MAX_LABEL: usize = 80;
/// Longest action description.
pub const MAX_DESCRIPTION: usize = 300;
/// Longest "what it sends" line.
pub const MAX_SENDS: usize = 500;
/// Most choices a `choice` input may have, and the longest one.
pub const MAX_CHOICES: usize = 50;
pub const MAX_CHOICE: usize = 100;
/// A `text` input's default and largest `max`.
pub const TEXT_MAX: usize = 200;
pub const TEXT_MAX_LIMIT: usize = 1_000;
/// A `textarea` input's default and largest `max`.
pub const TEXTAREA_MAX: usize = 2_000;
pub const TEXTAREA_MAX_LIMIT: usize = 4_000;
/// Longest result message.
pub const MAX_MESSAGE: usize = 2_000;
/// Most fields on a record, and the longest field value.
pub const MAX_FIELDS: usize = 20;
pub const MAX_FIELD: usize = 200;
/// Longest field name, and longest record text (id, kind, label, number,
/// status).
pub const MAX_NAME: usize = 60;
pub const MAX_RECORD_TEXT: usize = 200;
/// Most records and links one result may hold.
pub const MAX_RECORDS: usize = 5;
pub const MAX_LINKS: usize = 5;
/// Longest link.
pub const MAX_URL: usize = 2_048;
/// Largest answer file read.
pub const MAX_ANSWER_BYTES: u64 = 1 << 20;
/// Most of stderr kept for the details.
pub const MAX_DETAILS: usize = 64 * 1024;
/// The longest `describe` may take (an action's own time limit is for
/// `run`, where sign-in can be slow).
pub const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(60);

// ------------------------------------------------------------ describe

/// What a program offers: its actions, in its order.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Describe {
    pub actions: Vec<ActionDef>,
}

/// One action a program offers.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ActionDef {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// What leaves the computer, in plain words.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sends: String,
    /// Which findings it is for, on top of the block's own filters.
    pub applies_to: Filters,
    pub inputs: Vec<InputDef>,
    /// Hidden while the finding has an open record from this action.
    pub once: bool,
    /// IDs of this program's `for: "record"` actions offered on the records
    /// this one returns.
    pub follow_ups: Vec<String>,
    /// Only offered as a follow-up on a record (`for: "record"`).
    #[serde(rename = "for", skip_serializing_if = "Option::is_none")]
    pub for_: Option<For>,
    /// Where the finding must stand for it to be offered (`when`: open,
    /// held, accepted, fixed), as the program gave it; `None` when it gave
    /// none ([`ActionDef::offered_when`] has the defaults).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<Vec<FindingStatus>>,
}

/// Where a finding stands for an action without `when`: open, held or
/// accepted. A fixed finding is offered only the actions that list
/// `fixed`, and the follow-ups on its records.
pub const DEFAULT_WHEN: [FindingStatus; 3] = [
    FindingStatus::Open,
    FindingStatus::Held,
    FindingStatus::Accepted,
];

impl ActionDef {
    /// Whether it may be offered on a finding that stands at `status`: one
    /// `when` lists, or without `when` open, held or accepted
    /// ([`DEFAULT_WHEN`]); a follow-up (`for: "record"`) without `when`, on
    /// a record of a finding however it stands.
    pub fn offered_when(&self, status: FindingStatus) -> bool {
        match &self.when {
            Some(w) => w.contains(&status),
            None => self.for_ == Some(For::Record) || DEFAULT_WHEN.contains(&status),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum For {
    Record,
}

/// Which findings an action is for: an `[[action]]` block's filters, or
/// a described action's `applies_to`. Empty matches every finding.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Filters {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<Category>,
}

impl Filters {
    /// The filters of an `[[action]]` block.
    pub fn of_config(a: &ActionConfig) -> Filters {
        Filters {
            min_severity: a.min_severity,
            rules: a.rules.clone(),
            categories: a.categories.clone(),
        }
    }

    /// Whether `f` passes. A filter on a severity or category the finding
    /// doesn't carry (a fixed or held finding's) doesn't pass.
    pub fn matches(&self, f: &FindingContext) -> bool {
        let severity = self
            .min_severity
            .is_none_or(|min| f.severity.is_some_and(|s| s >= min));
        let rule =
            self.rules.is_empty() || self.rules.iter().any(|r| r.eq_ignore_ascii_case(&f.rule));
        let category =
            self.categories.is_empty() || f.category.is_some_and(|c| self.categories.contains(&c));
        severity && rule && category
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InputType {
    Text,
    Textarea,
    Choice,
    Bool,
}

impl InputType {
    const NAMES: &'static str = "text, textarea, choice, bool";

    fn parse(s: &str) -> Option<InputType> {
        match s {
            "text" => Some(InputType::Text),
            "textarea" => Some(InputType::Textarea),
            "choice" => Some(InputType::Choice),
            "bool" => Some(InputType::Bool),
            _ => None,
        }
    }
}

/// One field an action asks for before it runs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InputDef {
    pub id: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: InputType,
    pub required: bool,
    /// `text` and `textarea`: the most characters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,
    /// `choice`: the choices, in order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<Value>,
}

impl InputDef {
    /// The most characters a `text` or `textarea` input takes.
    pub fn max_chars(&self) -> usize {
        self.max.unwrap_or(match self.kind {
            InputType::Textarea => TEXTAREA_MAX,
            _ => TEXT_MAX,
        })
    }
}

/// A described action's ID or an input's: lowercase letters, digits, `-`
/// and `_`, at most [`MAX_ID`].
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// `s` with control and bidi characters dropped (line breaks kept when
/// `lines`, as `\n`), trimmed, and cut to `max` characters. Whether it was
/// cut.
pub fn clean_text(s: &str, max: usize, lines: bool) -> (String, bool) {
    let s = s.replace("\r\n", "\n");
    let kept: String = s
        .chars()
        .map(|c| if c == '\t' { ' ' } else { c })
        .filter(|c| (lines && *c == '\n') || !c.is_control())
        .filter(|c| !crate::text::is_bidi_control(*c))
        .collect();
    let kept = kept.trim();
    if kept.chars().count() <= max {
        return (kept.to_string(), false);
    }
    let mut cut: String = kept.chars().take(max.saturating_sub(1)).collect();
    cut.push('…');
    (cut, true)
}

/// Problems found reading a document, as `path: what`.
struct Problems(Vec<String>);

impl Problems {
    fn add(&mut self, path: &str, what: impl std::fmt::Display) {
        self.0.push(format!("{path} {what}"));
    }
}

/// A JSON value's type in words.
fn type_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "true or false",
        Value::Number(_) => "a number",
        Value::String(_) => "text",
        Value::Array(_) => "a list",
        Value::Object(_) => "an object",
    }
}

/// Text field `key` of `o`, cleaned and cut to `max` (a cut is a problem).
/// `None` when it is missing (a problem when `required`) or not text.
fn text_field(
    o: &Map<String, Value>,
    key: &str,
    path: &str,
    max: usize,
    required: bool,
    p: &mut Problems,
) -> Option<String> {
    let at = format!("{path}.{key}");
    match o.get(key) {
        None | Some(Value::Null) => {
            if required {
                p.add(&at, "is missing");
            }
            None
        }
        Some(Value::String(s)) => {
            let (t, cut) = clean_text(s, max, false);
            if cut {
                p.add(&at, format!("is longer than {max} characters; it was cut"));
            }
            if t.is_empty() && required {
                p.add(&at, "is empty");
                return None;
            }
            Some(t)
        }
        Some(other) => {
            p.add(&at, format!("must be text, not {}", type_of(other)));
            None
        }
    }
}

/// Bool field `key` of `o`: false when missing.
fn bool_field(o: &Map<String, Value>, key: &str, path: &str, p: &mut Problems) -> Option<bool> {
    match o.get(key) {
        None | Some(Value::Null) => Some(false),
        Some(Value::Bool(b)) => Some(*b),
        Some(other) => {
            p.add(
                &format!("{path}.{key}"),
                format!("must be true or false, not {}", type_of(other)),
            );
            None
        }
    }
}

/// Reads filters (`min_severity`, `rules`, `categories`) from `o`.
fn filters_of(o: &Map<String, Value>, path: &str, p: &mut Problems) -> Option<Filters> {
    let before = p.0.len();
    let mut f = Filters::default();
    match o.get("min_severity") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) => match s.trim().parse::<Severity>() {
            Ok(s) => f.min_severity = Some(s),
            Err(_) => p.add(
                &format!("{path}.min_severity"),
                format!("'{s}' isn't one of critical, high, medium, low, info"),
            ),
        },
        Some(other) => p.add(
            &format!("{path}.min_severity"),
            format!("must be text, not {}", type_of(other)),
        ),
    }
    for key in ["rules", "categories"] {
        let at = format!("{path}.{key}");
        match o.get(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for (i, item) in items.iter().enumerate() {
                    let Some(s) = item.as_str() else {
                        p.add(&format!("{at}[{i}]"), "must be text");
                        continue;
                    };
                    if key == "rules" {
                        if s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                        {
                            p.add(
                                &format!("{at}[{i}]"),
                                format!("'{s}' is not a rule ID such as PW-001"),
                            );
                        } else {
                            f.rules.push(s.to_string());
                        }
                    } else {
                        match s.parse::<Category>() {
                            Ok(c) => f.categories.push(c),
                            Err(_) => p.add(
                                &format!("{at}[{i}]"),
                                format!("'{s}' isn't one of attack_path, hygiene"),
                            ),
                        }
                    }
                }
            }
            Some(other) => p.add(&at, format!("must be a list, not {}", type_of(other))),
        }
    }
    (p.0.len() == before).then_some(f)
}

/// Reads an action's `when`: one of open, held, accepted, fixed, or a
/// list of them (`"fixed"` is `["fixed"]`). `Some(None)` when absent;
/// `None` when it can't be used.
fn when_of(v: Option<&Value>, path: &str, p: &mut Problems) -> Option<Option<Vec<FindingStatus>>> {
    const NAMES: &str = "open, held, accepted, fixed";
    let at = format!("{path}.when");
    let items: Vec<&Value> = match v {
        None | Some(Value::Null) => return Some(None),
        Some(Value::Array(items)) => items.iter().collect(),
        Some(one) => vec![one],
    };
    if items.is_empty() {
        p.add(&at, format!("must list at least one of {NAMES}"));
        return None;
    }
    let before = p.0.len();
    let mut out = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let here = if matches!(v, Some(Value::Array(_))) {
            format!("{at}[{i}]")
        } else {
            at.clone()
        };
        let status = match item.as_str() {
            Some("open") => FindingStatus::Open,
            Some("held") => FindingStatus::Held,
            Some("accepted") => FindingStatus::Accepted,
            Some("fixed") => FindingStatus::Fixed,
            _ => {
                p.add(&here, format!("{item} isn't one of {NAMES}"));
                continue;
            }
        };
        if !out.contains(&status) {
            out.push(status);
        }
    }
    (p.0.len() == before).then_some(Some(out))
}

/// Reads input `i` of an action. `None` when it can't be used.
fn input_of(v: &Value, path: &str, p: &mut Problems) -> Option<InputDef> {
    let before = p.0.len();
    let Some(o) = v.as_object() else {
        p.add(path, format!("must be an object, not {}", type_of(v)));
        return None;
    };
    let id = text_field(o, "id", path, MAX_ID, true, p);
    if let Some(id) = &id {
        if !valid_id(id) {
            p.add(
                &format!("{path}.id"),
                format!("'{id}' must be lowercase letters, digits, - and _"),
            );
        }
    }
    let label = text_field(o, "label", path, MAX_LABEL, true, p);
    let kind = match o.get("type") {
        Some(Value::String(t)) => match InputType::parse(t) {
            Some(k) => Some(k),
            None => {
                p.add(
                    &format!("{path}.type"),
                    format!("'{t}' isn't one of {}", InputType::NAMES),
                );
                None
            }
        },
        None | Some(Value::Null) => {
            p.add(
                &format!("{path}.type"),
                format!("is missing: use one of {}", InputType::NAMES),
            );
            None
        }
        Some(other) => {
            p.add(
                &format!("{path}.type"),
                format!("must be text, not {}", type_of(other)),
            );
            None
        }
    };
    let required = bool_field(o, "required", path, p);
    let mut max = None;
    let mut choices = Vec::new();
    if let Some(kind) = kind {
        match o.get("max") {
            None | Some(Value::Null) => {}
            Some(m) if matches!(kind, InputType::Text | InputType::Textarea) => {
                let limit = if kind == InputType::Text {
                    TEXT_MAX_LIMIT
                } else {
                    TEXTAREA_MAX_LIMIT
                };
                match m.as_u64() {
                    Some(n) if n >= 1 && n as usize <= limit => max = Some(n as usize),
                    _ => p.add(
                        &format!("{path}.max"),
                        format!("must be a whole number from 1 to {limit}"),
                    ),
                }
            }
            Some(_) => p.add(
                &format!("{path}.max"),
                "is only for text and textarea inputs",
            ),
        }
        if kind == InputType::Choice {
            match o.get("choices") {
                Some(Value::Array(items)) if !items.is_empty() => {
                    if items.len() > MAX_CHOICES {
                        p.add(
                            &format!("{path}.choices"),
                            format!("has more than {MAX_CHOICES} choices"),
                        );
                    }
                    for (i, item) in items.iter().take(MAX_CHOICES).enumerate() {
                        match item.as_str().map(|s| clean_text(s, MAX_CHOICE, false)) {
                            Some((c, false)) if !c.is_empty() => {
                                if choices.contains(&c) {
                                    p.add(
                                        &format!("{path}.choices[{i}]"),
                                        format!("'{c}' is there twice"),
                                    );
                                } else {
                                    choices.push(c);
                                }
                            }
                            Some((_, true)) => p.add(
                                &format!("{path}.choices[{i}]"),
                                format!("is longer than {MAX_CHOICE} characters"),
                            ),
                            _ => p.add(
                                &format!("{path}.choices[{i}]"),
                                "must be text that isn't empty",
                            ),
                        }
                    }
                }
                _ => p.add(
                    &format!("{path}.choices"),
                    "must be a list of at least one choice",
                ),
            }
        }
    }
    let default = match (o.get("default"), kind) {
        (None | Some(Value::Null), _) | (_, None) => None,
        (Some(d), Some(kind)) => {
            let ok = match (kind, d) {
                (InputType::Bool, Value::Bool(_)) => true,
                (InputType::Choice, Value::String(s)) => choices.contains(s),
                (InputType::Text | InputType::Textarea, Value::String(s)) => {
                    let lines = kind == InputType::Textarea;
                    let limit = max.unwrap_or(if lines { TEXTAREA_MAX } else { TEXT_MAX });
                    let control = s.chars().any(|c| {
                        (c.is_control() && !(lines && matches!(c, '\n' | '\r' | '\t')))
                            || crate::text::is_bidi_control(c)
                    });
                    !control && s.chars().count() <= limit
                }
                _ => false,
            };
            if !ok {
                p.add(
                    &format!("{path}.default"),
                    match kind {
                        InputType::Bool => "must be true or false".to_string(),
                        InputType::Choice => "must be one of the choices".to_string(),
                        _ => "must be text no longer than max, without control characters"
                            .to_string(),
                    },
                );
            }
            Some(d.clone())
        }
    };
    if p.0.len() != before {
        return None;
    }
    Some(InputDef {
        id: id?,
        label: label?,
        kind: kind?,
        required: required?,
        max,
        choices,
        default,
    })
}

/// Reads action `i` of a describe answer. `None` when it can't be offered;
/// problems that only cut a text keep it.
fn action_of(v: &Value, path: &str, p: &mut Problems) -> Option<ActionDef> {
    let Some(o) = v.as_object() else {
        p.add(path, format!("must be an object, not {}", type_of(v)));
        return None;
    };
    let before = p.0.len();
    let mut blocking = false;
    let mut block = |p: &Problems, from: usize| blocking |= p.0.len() > from;
    let id = text_field(o, "id", path, MAX_ID, true, p);
    if let Some(id) = &id {
        if !valid_id(id) {
            p.add(
                &format!("{path}.id"),
                format!("'{id}' must be lowercase letters, digits, - and _"),
            );
        }
    }
    block(p, before);
    let at = p.0.len();
    let label = text_field(o, "label", path, MAX_LABEL, true, p);
    if label.is_none() {
        block(p, at);
    }
    let description = text_field(o, "description", path, MAX_DESCRIPTION, false, p);
    let sends = text_field(o, "sends", path, MAX_SENDS, false, p);
    if o.get("sends").is_none_or(Value::is_null) {
        p.add(
            &format!("{path}.sends"),
            "is missing: say in plain words what leaves the computer",
        );
    }
    let at = p.0.len();
    let applies_to = match o.get("applies_to") {
        None | Some(Value::Null) => Some(Filters::default()),
        Some(Value::Object(f)) => filters_of(f, &format!("{path}.applies_to"), p),
        Some(other) => {
            p.add(
                &format!("{path}.applies_to"),
                format!("must be an object, not {}", type_of(other)),
            );
            None
        }
    };
    let mut inputs = Vec::new();
    match o.get("inputs") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            if items.len() > MAX_INPUTS {
                p.add(
                    &format!("{path}.inputs"),
                    format!("has more than {MAX_INPUTS} inputs"),
                );
            }
            for (i, item) in items.iter().enumerate().take(MAX_INPUTS) {
                if let Some(input) = input_of(item, &format!("{path}.inputs[{i}]"), p) {
                    if inputs.iter().any(|x: &InputDef| x.id == input.id) {
                        p.add(
                            &format!("{path}.inputs[{i}].id"),
                            format!("'{}' is there twice", input.id),
                        );
                    } else {
                        inputs.push(input);
                    }
                }
            }
        }
        Some(other) => p.add(
            &format!("{path}.inputs"),
            format!("must be a list, not {}", type_of(other)),
        ),
    }
    let once = bool_field(o, "once", path, p);
    let for_ = match o.get("for") {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(s)) if s == "record" => Some(Some(For::Record)),
        Some(other) => {
            p.add(
                &format!("{path}.for"),
                format!("{other} isn't \"record\", the only value v1 knows"),
            );
            None
        }
    };
    let when = when_of(o.get("when"), path, p);
    block(p, at);
    let mut follow_ups = Vec::new();
    match o.get("follow_ups") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for (i, item) in items.iter().enumerate() {
                match item.as_str() {
                    Some(s) if valid_id(s) => {
                        if !follow_ups.iter().any(|f| f == s) {
                            follow_ups.push(s.to_string());
                        }
                    }
                    _ => p.add(
                        &format!("{path}.follow_ups[{i}]"),
                        "must be the ID of another action",
                    ),
                }
            }
        }
        Some(other) => p.add(
            &format!("{path}.follow_ups"),
            format!("must be a list, not {}", type_of(other)),
        ),
    }
    if blocking {
        return None;
    }
    Some(ActionDef {
        id: id?,
        label: label?,
        description: description.unwrap_or_default(),
        sends: sends.unwrap_or_default(),
        applies_to: applies_to?,
        inputs,
        once: once?,
        follow_ups,
        for_: for_?,
        when: when?,
    })
}

/// Reads a `describe` answer (`pathwarden.action-describe.v1`). `Err`
/// when it can't be used at all (not JSON, another schema, no `actions`
/// list), with every problem. Otherwise the actions that can be offered,
/// and the problems with the rest (an action with a problem in its ID,
/// filters, inputs, `for` or `when` is left out; a text that was too long
/// is cut). Fields Pathwarden doesn't know are ignored.
pub fn parse_describe(bytes: &[u8]) -> Result<(Describe, Vec<String>), Vec<String>> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|e| vec![format!("The list of actions isn't JSON: {e}")])?;
    let Some(o) = v.as_object() else {
        return Err(vec![format!(
            "The list of actions must be a JSON object, not {}",
            type_of(&v)
        )]);
    };
    let mut p = Problems(Vec::new());
    match o.get("schema") {
        Some(Value::String(s)) if s == DESCRIBE_SCHEMA => {}
        None | Some(Value::Null) => {
            p.add("schema", format!("is missing: use \"{DESCRIBE_SCHEMA}\""))
        }
        Some(other) => {
            return Err(vec![format!(
                "schema {other} isn't \"{DESCRIBE_SCHEMA}\", the version this Pathwarden reads"
            )])
        }
    }
    let Some(items) = o.get("actions").and_then(Value::as_array) else {
        p.add(
            "actions",
            "must be a list of the actions the program offers",
        );
        return Err(p.0);
    };
    if items.len() > MAX_ACTIONS {
        p.add(
            "actions",
            format!("has more than {MAX_ACTIONS} actions; the rest are left out"),
        );
    }
    let mut actions: Vec<ActionDef> = Vec::new();
    for (i, item) in items.iter().enumerate().take(MAX_ACTIONS) {
        if let Some(a) = action_of(item, &format!("actions[{i}]"), &mut p) {
            if actions.iter().any(|x| x.id == a.id) {
                p.add(
                    &format!("actions[{i}].id"),
                    format!("'{}' is there twice", a.id),
                );
            } else {
                actions.push(a);
            }
        }
    }
    // Follow-ups name this program's `for: "record"` actions.
    let record_ids: Vec<String> = actions
        .iter()
        .filter(|a| a.for_ == Some(For::Record))
        .map(|a| a.id.clone())
        .collect();
    for a in &mut actions {
        let id = a.id.clone();
        a.follow_ups.retain(|f| {
            let ok = record_ids.contains(f);
            if !ok {
                p.0.push(format!(
                    "Action '{id}': follow-up '{f}' isn't an action of this program with for: \"record\""
                ));
            }
            ok
        });
    }
    if actions.is_empty() && p.0.is_empty() {
        p.add("actions", "is empty: the program offers no action");
    }
    Ok((Describe { actions }, p.0))
}

// -------------------------------------------------------------- inputs

/// The inputs to send for `def`: `given` (by input ID) checked against
/// their types, and the defaults for the rest (text: empty; a choice: its
/// default, else the first; bool: its default, else false). Every problem,
/// in words naming the input's label, when any is wrong.
pub fn check_inputs(
    def: &ActionDef,
    given: &Map<String, Value>,
) -> Result<Map<String, Value>, Vec<String>> {
    let mut problems = Vec::new();
    for k in given.keys() {
        if !def.inputs.iter().any(|i| &i.id == k) {
            problems.push(if def.inputs.is_empty() {
                format!("{} takes no inputs, so '{k}' can't be given.", def.label)
            } else {
                format!(
                    "There is no input '{k}': {} takes {}.",
                    def.label,
                    def.inputs
                        .iter()
                        .map(|i| i.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
        }
    }
    let mut out = Map::new();
    for input in &def.inputs {
        let value = given.get(&input.id).filter(|v| !v.is_null());
        let label = &input.label;
        let checked = match input.kind {
            InputType::Text | InputType::Textarea => {
                let lines = input.kind == InputType::Textarea;
                let text = match value {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Number(n)) => Some(n.to_string()),
                    Some(other) => {
                        problems.push(format!("{label} must be text, not {}.", type_of(other)));
                        None
                    }
                    None => input
                        .default
                        .as_ref()
                        .and_then(Value::as_str)
                        .map(str::to_string),
                };
                text.and_then(|t| {
                    let t = t.replace("\r\n", "\n");
                    if t.chars().any(|c| {
                        (c.is_control() && !(lines && matches!(c, '\n' | '\t')))
                            || crate::text::is_bidi_control(c)
                    }) {
                        problems.push(format!(
                            "{label} holds a control character{}.",
                            if lines { "" } else { " or a line break" }
                        ));
                        return None;
                    }
                    let t = t.trim().to_string();
                    let n = t.chars().count();
                    if n > input.max_chars() {
                        problems.push(format!(
                            "{label} is {n} characters long; it takes at most {}.",
                            input.max_chars()
                        ));
                        return None;
                    }
                    Some(t)
                })
                .or_else(|| (value.is_none()).then(String::new))
                .map(|t| {
                    if t.is_empty() && input.required {
                        problems.push(format!("{label} is needed."));
                    }
                    Value::String(t)
                })
            }
            InputType::Choice => {
                let pick = match value {
                    Some(Value::String(s)) => {
                        match input
                            .choices
                            .iter()
                            .find(|c| c.eq_ignore_ascii_case(s.trim()))
                        {
                            Some(c) => Some(c.clone()),
                            None => {
                                problems.push(format!(
                                    "{label}: '{s}' isn't one of {}.",
                                    input.choices.join(", ")
                                ));
                                None
                            }
                        }
                    }
                    Some(other) => {
                        problems.push(format!(
                            "{label} must be one of the choices, not {}.",
                            type_of(other)
                        ));
                        None
                    }
                    None => input
                        .default
                        .as_ref()
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .or_else(|| input.choices.first().cloned()),
                };
                pick.map(Value::String)
            }
            InputType::Bool => {
                let b = match value {
                    Some(Value::Bool(b)) => Some(*b),
                    Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
                        "true" | "yes" | "on" | "1" => Some(true),
                        "false" | "no" | "off" | "0" => Some(false),
                        _ => {
                            problems.push(format!("{label} must be true or false, not '{s}'."));
                            None
                        }
                    },
                    Some(other) => {
                        problems.push(format!(
                            "{label} must be true or false, not {}.",
                            type_of(other)
                        ));
                        None
                    }
                    None => Some(
                        input
                            .default
                            .as_ref()
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    ),
                };
                b.map(Value::Bool)
            }
        };
        if let Some(v) = checked {
            out.insert(input.id.clone(), v);
        }
    }
    if problems.is_empty() {
        Ok(out)
    } else {
        Err(problems)
    }
}

/// Inputs a test run sends ([`check`]): each input's default, else a
/// short sample text, the first choice, or false.
pub fn sample_inputs(def: &ActionDef) -> Map<String, Value> {
    def.inputs
        .iter()
        .map(|i| {
            let v = i.default.clone().unwrap_or_else(|| match i.kind {
                InputType::Text | InputType::Textarea => Value::from("Test from Pathwarden"),
                InputType::Choice => Value::from(i.choices.first().cloned().unwrap_or_default()),
                InputType::Bool => Value::Bool(false),
            });
            (i.id.clone(), v)
        })
        .collect()
}

// -------------------------------------------------------------- result

/// What a run of an action did (`pathwarden.action-result.v1`), checked.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActionResult {
    pub ok: bool,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub links: Vec<Link>,
    #[serde(default)]
    pub records: Vec<Record>,
}

/// A link a result offers (always `https://`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Link {
    pub label: String,
    pub url: String,
}

/// Something an action created or looks after for the finding, such as a
/// ticket. A follow-up returns the same `id` to update it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    /// Always `https://`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Still open in the other system: drives `once` and "still Open".
    #[serde(default)]
    pub open: bool,
    /// Named values to show with it, by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    /// Fields a later release of v1 keeps on a record (in the history's
    /// `actions.json`), kept as they are. A program's result never sets
    /// them ([`parse_result`] reads only the fields above). On an
    /// [`ActionRecord`], its own unknown fields land here too, and are
    /// written back the same.
    #[serde(flatten)]
    pub other: BTreeMap<String, Value>,
}

/// A record kept on a finding: the result's record, which action made it
/// (its address, `<name>/<id>`), who first ran it, where and when, and
/// when it last changed. Kept in the history's `actions.json` (that issue
/// builds the file; [`offered`] and [`follow_ups`] read these).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRecord {
    pub action: String,
    #[serde(flatten)]
    pub record: Record,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<String>,
    #[serde(default)]
    pub at: String,
    #[serde(default)]
    pub updated_at: String,
}

/// `s` when it is an `https://` address with a host and no user name or
/// password, no spaces or control characters, at most [`MAX_URL`] long.
pub fn https_url(s: &str) -> Result<String, &'static str> {
    let s = s.trim();
    if s.len() > MAX_URL {
        return Err("is longer than 2,048 characters");
    }
    if s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || crate::text::is_bidi_control(c))
    {
        return Err("holds a space or a control character");
    }
    let Some(rest) = s
        .get(..8)
        .filter(|p| p.eq_ignore_ascii_case("https://"))
        .map(|_| &s[8..])
    else {
        return Err("must start with https://");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err("must not hold a user name or password");
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, port)| {
        if port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            authority
        }
    });
    if host.is_empty() || host.contains(['\\', '<', '>', '"']) {
        return Err("has no host");
    }
    Ok(s.to_string())
}

/// Reads one record of a result. `None` when it can't be kept.
fn record_of(v: &Value, path: &str, p: &mut Problems) -> Option<Record> {
    let Some(o) = v.as_object() else {
        p.add(path, format!("must be an object, not {}", type_of(v)));
        return None;
    };
    let before = p.0.len();
    let id = text_field(o, "id", path, MAX_RECORD_TEXT, true, p);
    if p.0.len() > before || id.is_none() {
        return None;
    }
    let mut r = Record {
        id: id?,
        kind: text_field(o, "kind", path, MAX_RECORD_TEXT, false, p),
        label: text_field(o, "label", path, MAX_RECORD_TEXT, false, p),
        number: text_field(o, "number", path, MAX_RECORD_TEXT, false, p),
        status: text_field(o, "status", path, MAX_RECORD_TEXT, false, p),
        open: bool_field(o, "open", path, p).unwrap_or(false),
        ..Record::default()
    };
    match o.get("url") {
        None | Some(Value::Null) => {}
        Some(Value::String(u)) => match https_url(u) {
            Ok(u) => r.url = Some(u),
            Err(why) => p.add(&format!("{path}.url"), format!("{why}; it was left out")),
        },
        Some(other) => p.add(
            &format!("{path}.url"),
            format!("must be text, not {}", type_of(other)),
        ),
    }
    match o.get("fields") {
        None | Some(Value::Null) => {}
        Some(Value::Object(f)) => {
            if f.len() > MAX_FIELDS {
                p.add(
                    &format!("{path}.fields"),
                    format!("has more than {MAX_FIELDS} fields; the rest were left out"),
                );
            }
            for (k, v) in f.iter().take(MAX_FIELDS) {
                let (name, cut) = clean_text(k, MAX_NAME, false);
                if cut || name.is_empty() {
                    p.add(&format!("{path}.fields"), format!("name '{name}' is empty or longer than {MAX_NAME} characters; it was left out"));
                    continue;
                }
                let text = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    other => {
                        p.add(
                            &format!("{path}.fields.{name}"),
                            format!("must be text, not {}; it was left out", type_of(other)),
                        );
                        continue;
                    }
                };
                if r.fields.contains_key(&name) {
                    p.add(
                        &format!("{path}.fields"),
                        format!(
                            "name '{name}' is there twice once cleaned; the second was left out"
                        ),
                    );
                    continue;
                }
                let (text, cut) = clean_text(&text, MAX_FIELD, false);
                if cut {
                    p.add(
                        &format!("{path}.fields.{name}"),
                        format!("is longer than {MAX_FIELD} characters; it was cut"),
                    );
                }
                r.fields.insert(name, text);
            }
        }
        Some(other) => p.add(
            &format!("{path}.fields"),
            format!("must be an object, not {}", type_of(other)),
        ),
    }
    Some(r)
}

/// Reads a `run` answer (`pathwarden.action-result.v1`). `Err` when it
/// can't be used at all (not JSON, another schema, no `ok`), with every
/// problem; the run then failed. Otherwise the result as checked and the
/// problems found: a text too long is cut, a link that isn't `https://`,
/// a record past [`MAX_RECORDS`] or a field past [`MAX_FIELDS`] is left
/// out. Fields Pathwarden doesn't know are ignored, and no text is ever
/// read as HTML.
pub fn parse_result(bytes: &[u8]) -> Result<(ActionResult, Vec<String>), Vec<String>> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let v: Value =
        serde_json::from_slice(bytes).map_err(|e| vec![format!("The result isn't JSON: {e}")])?;
    let Some(o) = v.as_object() else {
        return Err(vec![format!(
            "The result must be a JSON object, not {}",
            type_of(&v)
        )]);
    };
    let mut p = Problems(Vec::new());
    match o.get("schema") {
        Some(Value::String(s)) if s == RESULT_SCHEMA => {}
        None | Some(Value::Null) => p.add("schema", format!("is missing: use \"{RESULT_SCHEMA}\"")),
        Some(other) => {
            return Err(vec![format!(
                "schema {other} isn't \"{RESULT_SCHEMA}\", the version this Pathwarden reads"
            )])
        }
    }
    let ok = match o.get("ok") {
        Some(Value::Bool(b)) => *b,
        Some(other) => {
            p.add(
                "ok",
                format!("must be true or false, not {}", type_of(other)),
            );
            return Err(p.0);
        }
        None => {
            p.add("ok", "is missing: say whether the action worked");
            return Err(p.0);
        }
    };
    let message = match o.get("message") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => {
            let (m, cut) = clean_text(s, MAX_MESSAGE, true);
            if cut {
                p.add(
                    "message",
                    format!("is longer than {MAX_MESSAGE} characters; it was cut"),
                );
            }
            m
        }
        Some(other) => {
            p.add("message", format!("must be text, not {}", type_of(other)));
            String::new()
        }
    };
    let mut links = Vec::new();
    match o.get("links") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            if items.len() > MAX_LINKS {
                p.add(
                    "links",
                    format!("has more than {MAX_LINKS} links; the rest were left out"),
                );
            }
            for (i, item) in items.iter().enumerate().take(MAX_LINKS) {
                let at = format!("links[{i}]");
                let Some(l) = item.as_object() else {
                    p.add(&at, "must be an object with label and url");
                    continue;
                };
                let label = text_field(l, "label", &at, MAX_LABEL, true, &mut p);
                let url = match l.get("url").and_then(Value::as_str) {
                    Some(u) => match https_url(u) {
                        Ok(u) => Some(u),
                        Err(why) => {
                            p.add(
                                &format!("{at}.url"),
                                format!("{why}; the link was left out"),
                            );
                            None
                        }
                    },
                    None => {
                        p.add(&format!("{at}.url"), "is missing");
                        None
                    }
                };
                if let (Some(label), Some(url)) = (label, url) {
                    links.push(Link { label, url });
                }
            }
        }
        Some(other) => p.add("links", format!("must be a list, not {}", type_of(other))),
    }
    let mut records: Vec<Record> = Vec::new();
    match o.get("records") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            if items.len() > MAX_RECORDS {
                p.add(
                    "records",
                    format!("has more than {MAX_RECORDS} records; the rest were left out"),
                );
            }
            for (i, item) in items.iter().enumerate().take(MAX_RECORDS) {
                if let Some(r) = record_of(item, &format!("records[{i}]"), &mut p) {
                    if records.iter().any(|x| x.id == r.id) {
                        p.add(
                            &format!("records[{i}].id"),
                            format!("'{}' is there twice; the second was left out", r.id),
                        );
                    } else {
                        records.push(r);
                    }
                }
            }
        }
        Some(other) => p.add("records", format!("must be a list, not {}", type_of(other))),
    }
    Ok((
        ActionResult {
            ok,
            message,
            links,
            records,
        },
        p.0,
    ))
}

// ------------------------------------------------------------- finding

/// Where a finding stands in the run the request is built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Open,
    Fixed,
    Held,
    Accepted,
}

/// One finding of a run, as an action sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct FindingContext {
    pub fingerprint: String,
    pub rule: String,
    pub title: String,
    /// `None` for a held finding, whose event entry doesn't carry it.
    pub severity: Option<Severity>,
    /// `None` for a fixed or held finding.
    pub category: Option<Category>,
    pub status: FindingStatus,
    /// The request's `finding`: the event's finding object as it is, with
    /// `guide` (the rule's Markdown guide, or null) and `status` added.
    pub finding: Value,
    /// The request's `run`: `run_id`, `domains`, `pathwarden`.
    pub run: Value,
}

/// The finding `fingerprint` (any case) of event document `event`
/// (`pathwarden.event.v1`): one of its `findings` (open, or accepted when
/// a risk covers it), `resolved` (fixed) or `held`.
pub fn finding_in_event(event: &Value, fingerprint: &str) -> Option<FindingContext> {
    findings_in_event(event)
        .into_iter()
        .find(|f| f.fingerprint.eq_ignore_ascii_case(fingerprint.trim()))
}

/// Every finding of event document `event`: its `findings` in order, then
/// `resolved`, then `held`.
pub fn findings_in_event(event: &Value) -> Vec<FindingContext> {
    let run = json!({
        "run_id": event["run"]["run_id"],
        "domains": event["run"]["domains"],
        "pathwarden": event["run"]["pathwarden"],
    });
    let guide = |rule: &str| -> Value {
        event["guides"][rule]
            .as_str()
            .or_else(|| crate::guides::guide(rule))
            .map_or(Value::Null, Value::from)
    };
    let mut out = Vec::new();
    for (list, fixed) in [
        ("findings", None),
        ("resolved", Some(FindingStatus::Fixed)),
        ("held", Some(FindingStatus::Held)),
    ] {
        for f in event[list].as_array().into_iter().flatten() {
            let (Some(fp), Some(rule)) = (f["fingerprint"].as_str(), f["rule"].as_str()) else {
                continue;
            };
            let status = fixed.unwrap_or(if f["suppressed"].is_string() {
                FindingStatus::Accepted
            } else {
                FindingStatus::Open
            });
            let mut finding = f.clone();
            if let Some(o) = finding.as_object_mut() {
                o.insert("guide".into(), guide(rule));
                o.insert(
                    "status".into(),
                    serde_json::to_value(status).unwrap_or_default(),
                );
            }
            out.push(FindingContext {
                fingerprint: fp.to_string(),
                rule: rule.to_string(),
                title: f["title"]
                    .as_str()
                    .or_else(|| f["rule_title"].as_str())
                    .unwrap_or_default()
                    .to_string(),
                severity: f["severity"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| rule_severity(rule)),
                category: f["category"]
                    .as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| rule_category(rule)),
                status,
                finding,
                run: run.clone(),
            });
        }
    }
    out
}

/// The category of rule `rule`'s findings, from the rule catalog, for a
/// fixed or held finding whose event entry doesn't carry it: an attack
/// path when the rule's findings are rated by exposure, else hygiene.
pub fn rule_category(rule: &str) -> Option<Category> {
    crate::findings::default_levels(rule).map(|(exposure, _)| {
        if exposure {
            Category::AttackPath
        } else {
            Category::Hygiene
        }
    })
}

/// The severity of rule `rule`'s findings, from the rule catalog, for a
/// held finding whose event entry doesn't carry it: the highest level the
/// rule gives, so a held finding is offered what it was offered open.
pub fn rule_severity(rule: &str) -> Option<Severity> {
    crate::findings::default_levels(rule).and_then(|(_, levels)| levels.iter().max().copied())
}

/// A made-up finding for testing a program without a run ([`check`]).
pub fn sample_finding() -> FindingContext {
    let event = json!({
        "schema": crate::event::SCHEMA,
        "run": { "run_id": "20261118T140200.000Z", "domains": ["SCALE.LOCAL"], "pathwarden": env!("CARGO_PKG_VERSION") },
        "findings": [{
            "change": "new",
            "first_seen": 1_795_010_520,
            "times_seen": 1,
            "rule_title": "Account or group outside Tier Zero controls a Tier Zero object",
            "rule": "PW-001",
            "category": "attack_path",
            "severity": "critical",
            "rule_severity": "critical",
            "exposure": null,
            "fingerprint": "PW-001-0000000000000000",
            "title": "HELPDESK@SCALE.LOCAL can take over DOMAIN ADMINS@SCALE.LOCAL (sample)",
            "domain": "SCALE.LOCAL",
            "summary": "A sample finding, made up to test an action.",
            "remediation": "Nothing to do: this finding is a sample.",
            "affected": [],
            "path": null,
            "references": [],
            "suppressed": null,
            "rests_on": { "sessions": false, "local_groups": false }
        }]
    });
    findings_in_event(&event).remove(0)
}

/// A made-up record for testing a `for: "record"` action ([`check`]).
pub fn sample_record() -> Record {
    Record {
        id: "sample-1".into(),
        kind: Some("ticket".into()),
        number: Some("SAMPLE0001".into()),
        status: Some("Open".into()),
        open: true,
        ..Record::default()
    }
}

// --------------------------------------------------------- what applies

/// An `[[action]]` block and what its program said it offers.
#[derive(Debug, Clone, Copy)]
pub struct Program<'a> {
    pub config: &'a ActionConfig,
    pub describe: &'a Describe,
}

/// One action offered on a finding (or a record).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Offered {
    /// The block's name.
    pub name: String,
    /// The action's ID in its program.
    pub id: String,
    /// `<name>/<id>`.
    pub address: String,
    pub def: ActionDef,
}

fn offer(config: &ActionConfig, def: &ActionDef) -> Offered {
    Offered {
        name: config.name.clone(),
        id: def.id.clone(),
        address: format!("{}/{}", config.name, def.id),
        def: def.clone(),
    }
}

/// Whether `def` of `config` may be offered on `f` at all: the block's
/// filters, the action's `applies_to`, and `when`
/// ([`ActionDef::offered_when`]).
fn may_offer(config: &ActionConfig, def: &ActionDef, f: &FindingContext) -> bool {
    Filters::of_config(config).matches(f) && def.applies_to.matches(f) && def.offered_when(f.status)
}

/// The actions offered on finding `f`, in config order and then each
/// program's order: those whose block filters and `applies_to` match,
/// that aren't only for records (`for: "record"`), whose `when` lists
/// where `f` stands (without one: open, held or accepted, never fixed),
/// and, for `once`, while `f` has no open record from that action.
/// `records` are `f`'s records.
pub fn offered(programs: &[Program], f: &FindingContext, records: &[ActionRecord]) -> Vec<Offered> {
    let mut out = Vec::new();
    for p in programs {
        for def in &p.describe.actions {
            if def.for_ == Some(For::Record) || !may_offer(p.config, def, f) {
                continue;
            }
            let o = offer(p.config, def);
            if def.once
                && records
                    .iter()
                    .any(|r| r.record.open && r.action.eq_ignore_ascii_case(&o.address))
            {
                continue;
            }
            out.push(o);
        }
    }
    out
}

/// The follow-ups offered on `record` of finding `f`: those the action
/// that made it lists, of the same program, that may be offered on `f`
/// (the filters, and `when`: without one, a follow-up is offered however
/// `f` stands, fixed too), in the order it lists them.
pub fn follow_ups(programs: &[Program], f: &FindingContext, record: &ActionRecord) -> Vec<Offered> {
    let Some((name, id)) = record.action.split_once('/') else {
        return Vec::new();
    };
    let Some(p) = programs
        .iter()
        .find(|p| p.config.name.eq_ignore_ascii_case(name))
    else {
        return Vec::new();
    };
    let Some(parent) = p.describe.actions.iter().find(|a| a.id == id) else {
        return Vec::new();
    };
    parent
        .follow_ups
        .iter()
        .filter_map(|fu| p.describe.actions.iter().find(|a| &a.id == fu))
        .filter(|def| may_offer(p.config, def, f))
        .map(|def| offer(p.config, def))
        .collect()
}

/// The action `address` names among `offered` (`<name>/<id>`; or a
/// block's name when it offers one action here; or an ID only one block
/// offers). Without an address, the one action offered. The error says
/// why in words: none applies, several do, or the one named doesn't.
pub fn pick<'a>(offered: &'a [Offered], address: Option<&str>) -> Result<&'a Offered, String> {
    let all = || {
        offered
            .iter()
            .map(|o| o.address.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let Some(address) = address.map(str::trim).filter(|a| !a.is_empty()) else {
        return match offered {
            [] => Err("No action applies to this finding.".into()),
            [one] => Ok(one),
            _ => Err(format!(
                "Several actions apply to this finding: choose one of {}.",
                all()
            )),
        };
    };
    if let Some(o) = offered
        .iter()
        .find(|o| o.address.eq_ignore_ascii_case(address))
    {
        return Ok(o);
    }
    if !address.contains('/') {
        // A block's name or an action's ID: only when it means one action.
        let could: Vec<&Offered> = offered
            .iter()
            .filter(|o| o.name.eq_ignore_ascii_case(address) || o.id.eq_ignore_ascii_case(address))
            .collect();
        match could.as_slice() {
            [one] => return Ok(one),
            [] => {}
            _ => {
                let names = could
                    .iter()
                    .map(|o| o.address.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(format!(
                    "{address} could be {names}: give the action as name/id."
                ));
            }
        }
    }
    Err(if offered.is_empty() {
        format!("{address} doesn't apply to this finding, and no other action does.")
    } else {
        format!(
            "{address} doesn't apply to this finding. These do: {}.",
            all()
        )
    })
}

// ------------------------------------------------------------ requests

/// The `describe` request for a block: its settings.
pub fn describe_request(a: &ActionConfig) -> Value {
    json!({
        "schema": REQUEST_SCHEMA,
        "kind": "describe",
        "settings": a.settings,
    })
}

/// The `run` request for action `o` on finding `f`, as the program gets
/// it: `inputs` already checked ([`check_inputs`]), `record` for a
/// follow-up, and who asks (`requested_by`: `by`, `on`) from `who`.
pub fn run_request(
    a: &ActionConfig,
    o: &Offered,
    f: &FindingContext,
    inputs: &Map<String, Value>,
    dry_run: bool,
    record: Option<&Record>,
    who: &crate::identity::Actor,
) -> Value {
    json!({
        "schema": REQUEST_SCHEMA,
        "kind": "run",
        "action": o.id,
        "inputs": inputs,
        "dry_run": dry_run,
        "settings": a.settings,
        "run": f.run,
        "finding": f.finding,
        "record": record,
        "requested_by": { "by": who.user, "on": who.computer },
    })
}

/// A `run` request for finding `f` with no action, inputs or settings:
/// what `pathwarden action request` prints when no action is set up, for
/// someone writing one.
pub fn finding_request(f: &FindingContext, dry_run: bool, who: &crate::identity::Actor) -> Value {
    json!({
        "schema": REQUEST_SCHEMA,
        "kind": "run",
        "action": "",
        "inputs": {},
        "dry_run": dry_run,
        "settings": {},
        "run": f.run,
        "finding": f.finding,
        "record": null,
        "requested_by": { "by": who.user, "on": who.computer },
    })
}

/// A run, ready to start: the block, the action and the request, and for
/// a follow-up the record it runs on.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub config: ActionConfig,
    pub offered: Offered,
    pub request: Value,
    pub record: Option<ActionRecord>,
}

/// What someone asks to run ([`prepare`]): the action (see [`pick`]),
/// inputs by ID, whether it is a dry run, and for a follow-up the ID of
/// the finding's record it runs on.
#[derive(Debug, Clone, Default)]
pub struct Ask {
    pub action: Option<String>,
    pub inputs: Map<String, Value>,
    pub dry_run: bool,
    pub record: Option<String>,
}

/// The record `id` (any case) among a finding's `records`. The error says
/// why in words: there is none, or two actions made one with that ID.
pub fn find_record<'a>(records: &'a [ActionRecord], id: &str) -> Result<&'a ActionRecord, String> {
    let id = id.trim();
    // The ID as given first; another case only when it means one record.
    let exact: Vec<&ActionRecord> = records.iter().filter(|r| r.record.id == id).collect();
    let found: Vec<&ActionRecord> = if exact.is_empty() {
        records
            .iter()
            .filter(|r| r.record.id.eq_ignore_ascii_case(id))
            .collect()
    } else {
        exact
    };
    match found.as_slice() {
        [one] => Ok(one),
        [] if records.is_empty() => Err(format!("This finding has no records, so none is {id}.")),
        [] => Err(format!(
            "This finding has no record {id}. Its records: {}.",
            records
                .iter()
                .map(|r| r.record.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        many => {
            let mut actions: Vec<&str> = many.iter().map(|r| r.action.as_str()).collect();
            actions.dedup();
            Err(match actions.as_slice() {
                [one] => format!(
                    "This finding has {} records {id} from {one} (their IDs differ only in case), so it can't be told which: give its ID exactly.",
                    many.len()
                ),
                _ => format!(
                    "Several actions made a record {id} on this finding ({}), so it can't be told which.",
                    actions.join(", ")
                ),
            })
        }
    }
}

/// Picks the action `ask` names on finding `f` among the described
/// `programs`, checks the inputs and builds the request. `records` are
/// `f`'s records. With `ask.record`, the action is one of that record's
/// follow-ups ([`follow_ups`]); without, a `for: "record"` action is
/// refused: it runs as a follow-up on a record. The error says what is
/// wrong, in words.
pub fn prepare(
    programs: &[Program],
    f: &FindingContext,
    records: &[ActionRecord],
    ask: &Ask,
) -> Result<Prepared, String> {
    let record = match &ask.record {
        Some(id) => Some(find_record(records, id)?.clone()),
        None => None,
    };
    let offered = match &record {
        Some(r) => follow_ups(programs, f, r),
        None => offered(programs, f, records),
    };
    let o = match pick(&offered, ask.action.as_deref()) {
        Ok(o) => o.clone(),
        Err(_) if record.is_some() && offered.is_empty() => {
            return Err(format!(
                "No follow-up applies to record {} of this finding.",
                record
                    .as_ref()
                    .map(|r| r.record.id.as_str())
                    .unwrap_or_default()
            ))
        }
        Err(e) if record.is_some() => return Err(e.replace("this finding", "this record")),
        Err(e) => {
            // A follow-up named directly: say where it runs.
            let follow_up = ask
                .action
                .as_deref()
                .and_then(|a| a.split_once('/'))
                .and_then(|(n, id)| {
                    programs
                        .iter()
                        .find(|p| p.config.name.eq_ignore_ascii_case(n))
                        .and_then(|p| p.describe.actions.iter().find(|d| d.id == id))
                        .filter(|d| d.for_ == Some(For::Record))
                });
            return Err(match follow_up {
                Some(d) if records.is_empty() => format!(
                    "{} runs on a record of this finding, and it has none.",
                    d.label
                ),
                Some(d) => format!(
                    "{} runs on a record of this finding: name one of {}.",
                    d.label,
                    records
                        .iter()
                        .map(|r| r.record.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => e,
            });
        }
    };
    let config = programs
        .iter()
        .find(|p| p.config.name == o.name)
        .map(|p| p.config.clone())
        .expect("offered from these programs");
    let inputs = check_inputs(&o.def, &ask.inputs).map_err(|p| p.join(" "))?;
    let request = run_request(
        &config,
        &o,
        f,
        &inputs,
        ask.dry_run,
        record.as_ref().map(|r| &r.record),
        &crate::identity::Actor::current(),
    );
    Ok(Prepared {
        config,
        offered: o,
        request,
        record,
    })
}

// -------------------------------------------------------------- runner

#[derive(Debug, Clone, thiserror::Error)]
pub enum ActionError {
    /// A scheduled task or another unattended run asked.
    #[error("Actions run only when someone asks, never from a scheduled task.")]
    Unattended,
    /// The program can't be started (not found, refused, its folder).
    #[error("{name}: {detail}")]
    Program { name: String, detail: String },
    /// `describe` gave nothing that can be used.
    #[error("{name} didn't list its actions: {}", .problems.join("; "))]
    Describe {
        name: String,
        problems: Vec<String>,
        /// The program's stderr.
        details: String,
    },
}

/// How a run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ended {
    /// It exited by itself.
    Exited,
    /// It ran past its time limit and was stopped.
    TimedOut,
    /// Someone cancelled it.
    Cancelled,
}

/// What a run of an action did, checked: a failed run too (a missing or
/// broken result, a non-zero exit, a timeout, a cancel), with its output.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub ok: bool,
    /// The result's message, or what went wrong, in words.
    pub message: String,
    pub links: Vec<Link>,
    pub records: Vec<Record>,
    /// The latest stdout lines ([`plugins::MAX_PROGRESS_LINES`]).
    pub progress: Vec<String>,
    /// stderr, at most [`MAX_DETAILS`] bytes, for Show details.
    pub details: String,
    /// What was wrong with the result (cut, left out).
    pub problems: Vec<String>,
    pub ended: Ended,
    /// "exit code 0", or how it stopped.
    pub status: String,
    pub dry_run: bool,
}

/// What [`exec`] got from the program.
struct Exec {
    ended: Ended,
    status: Option<std::process::ExitStatus>,
    progress: Vec<String>,
    details: String,
    /// The answer file: `None` when it wasn't written.
    answer: Option<Result<Vec<u8>, String>>,
}

/// Removes the answer file when dropped, whatever happened.
struct AnswerFile(PathBuf);

impl Drop for AnswerFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A fresh answer file name in the private folder programs start in.
fn answer_path(dir: &Path) -> PathBuf {
    let mut rnd = [0u8; 12];
    let _ = getrandom::getrandom(&mut rnd);
    let hex: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    dir.join(format!("action-result-{hex}.json"))
}

/// The answer file, when the program wrote one: refused unless it is a
/// plain file (a pipe or device could block the read, a link point
/// elsewhere), at most [`MAX_ANSWER_BYTES`].
fn read_answer(path: &Path) -> Option<Result<Vec<u8>, String>> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Some(Err("The result file isn't a plain file.".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(format!("The result file couldn't be read: {e}"))),
    }
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        // Never wait on a pipe swapped in after the check above.
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let f = match open.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(format!("The result file couldn't be read: {e}"))),
    };
    match f.metadata() {
        Ok(m) if m.file_type().is_file() => {}
        _ => return Some(Err("The result file isn't a plain file.".into())),
    }
    let mut bytes = Vec::new();
    if let Err(e) = f.take(MAX_ANSWER_BYTES + 1).read_to_end(&mut bytes) {
        return Some(Err(format!("The result file couldn't be read: {e}")));
    }
    if bytes.len() as u64 > MAX_ANSWER_BYTES {
        return Some(Err("The result file is larger than 1 MiB.".into()));
    }
    Some(Ok(bytes))
}

/// stderr as details: control and bidi characters dropped but line
/// breaks, at most [`MAX_DETAILS`] bytes.
fn details_of(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut out: String = text
        .replace("\r\n", "\n")
        .chars()
        .filter(|c| {
            matches!(c, '\n' | '\t') || (!c.is_control() && !crate::text::is_bidi_control(*c))
        })
        .collect();
    if out.len() > MAX_DETAILS {
        let mut cut = MAX_DETAILS;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("\n[cut short]");
    }
    out.trim_end().to_string()
}

/// Runs the block's program with `request` (`kind`: describe or run).
fn exec(
    a: &ActionConfig,
    kind: &str,
    request: &Value,
    timeout: Duration,
    on_line: &mut dyn FnMut(&str),
    cancel: &CancelHandle,
) -> Result<Exec, ActionError> {
    if crate::store::unattended() {
        return Err(ActionError::Unattended);
    }
    let program_error = |e: PluginError| ActionError::Program {
        name: a.name.clone(),
        detail: e.to_string(),
    };
    let mut cmd = plugins::command_for_action(a).map_err(program_error)?;
    plugins::apply_env_in(&mut cmd, &a.settings);
    let dir = plugins::work_dir().map_err(program_error)?;
    let answer = AnswerFile(answer_path(&dir));
    let _ = std::fs::remove_file(&answer.0);
    cmd.current_dir(&dir)
        .env(REQUEST_ENV, kind)
        .env(RESULT_ENV, &answer.0);
    let mut progress: VecDeque<String> = VecDeque::new();
    let mut keep = |line: &str| {
        on_line(line);
        if progress.len() == plugins::MAX_PROGRESS_LINES {
            progress.pop_front();
        }
        progress.push_back(line.to_string());
    };
    let text = request.to_string();
    let ran = plugins::run_streaming(cmd, &a.name, &text, timeout, &mut keep, cancel)
        .map_err(program_error)?;
    let ended = match ran.stopped {
        None => Ended::Exited,
        Some(plugins::Stopped::TimedOut(_)) => Ended::TimedOut,
        Some(plugins::Stopped::Cancelled) => Ended::Cancelled,
    };
    let (status, details) = (ran.status, details_of(&ran.stderr));
    let answer = match ended {
        Ended::Exited => read_answer(&answer.0),
        _ => None,
    };
    Ok(Exec {
        ended,
        status,
        progress: progress.into(),
        details,
        answer,
    })
}

/// "exit code 0", or how the run stopped.
fn status_words(e: &Exec, timeout: Duration) -> String {
    match (e.ended, e.status) {
        (Ended::TimedOut, _) => format!("stopped after {} s", timeout.as_secs()),
        (Ended::Cancelled, _) => "cancelled".into(),
        (_, Some(s)) => match s.code() {
            Some(c) => format!("exit code {c}"),
            None => s.to_string(),
        },
        (_, None) => "ended".into(),
    }
}

/// What a program said it offers, checked ([`parse_describe`]).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Described {
    pub describe: Describe,
    /// What was wrong with it (actions left out, texts cut).
    pub problems: Vec<String>,
}

/// A describe kept in memory, by [`describe_key`], and when it was asked.
type KeptDescribe = (std::time::Instant, Result<Described, ActionError>);

/// Describes kept in memory, by [`describe_key`]: an answer until the
/// program or settings change, a failure for [`FAILED_DESCRIBE_KEPT`].
static DESCRIBED: Mutex<Option<HashMap<String, KeptDescribe>>> = Mutex::new(None);
/// How long a failed describe is kept, so a broken program isn't started
/// again for every finding shown.
pub const FAILED_DESCRIBE_KEPT: Duration = Duration::from_secs(30);
/// Most describes kept; past it the cache starts over.
const MAX_DESCRIBED: usize = 64;

/// What a block's describe depends on: its name, program, arguments and
/// settings, and the contents of the files it runs (the program and its
/// script), so a changed script is described again.
fn describe_key(a: &ActionConfig) -> String {
    let mut h = Sha256::new();
    h.update(a.name.as_bytes());
    h.update([0]);
    h.update(a.plugin.as_deref().unwrap_or_default().as_bytes());
    h.update([0]);
    h.update(serde_json::to_vec(&a.command).unwrap_or_default());
    h.update([0]);
    h.update(serde_json::to_vec(&a.settings).unwrap_or_default());
    for f in plugins::action_files(a) {
        h.update([0]);
        h.update(f.to_string_lossy().as_bytes());
        match std::fs::read(&f) {
            Ok(bytes) => h.update(Sha256::digest(&bytes)),
            Err(_) => h.update(b"unreadable"),
        }
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Asks the block's program what it offers, every time
/// ([`describe`] keeps the answer). Its progress lines go to `on_line`;
/// `cancel` stops it.
pub fn describe_fresh(
    a: &ActionConfig,
    on_line: &mut dyn FnMut(&str),
    cancel: &CancelHandle,
) -> Result<Described, ActionError> {
    let timeout = DESCRIBE_TIMEOUT.min(Duration::from_secs(a.timeout_seconds));
    let e = exec(
        a,
        "describe",
        &describe_request(a),
        timeout,
        on_line,
        cancel,
    )?;
    let fail = |problems: Vec<String>, e: &Exec| ActionError::Describe {
        name: a.name.clone(),
        problems,
        details: e.details.clone(),
    };
    match e.ended {
        Ended::TimedOut => {
            return Err(fail(
                vec![format!(
                    "it took longer than {} s and was stopped",
                    timeout.as_secs()
                )],
                &e,
            ))
        }
        Ended::Cancelled => return Err(fail(vec!["it was stopped".into()], &e)),
        Ended::Exited => {}
    }
    if let Some(s) = e.status.filter(|s| !s.success()) {
        return Err(fail(
            vec![format!(
                "it stopped with {}",
                match s.code() {
                    Some(c) => format!("exit code {c}"),
                    None => s.to_string(),
                }
            )],
            &e,
        ));
    }
    let bytes = match &e.answer {
        None => {
            return Err(fail(
                vec![format!(
                    "it wrote nothing to the file named in {RESULT_ENV}"
                )],
                &e,
            ))
        }
        Some(Err(why)) => return Err(fail(vec![why.clone()], &e)),
        Some(Ok(b)) => b,
    };
    match parse_describe(bytes) {
        Ok((describe, problems)) => Ok(Described { describe, problems }),
        Err(problems) => Err(fail(problems, &e)),
    }
}

/// [`describe_fresh`], kept in memory by the program file's contents and
/// the settings ([`describe_key`]), so a block is asked once until its
/// program, script or settings change. A failure is kept for
/// [`FAILED_DESCRIBE_KEPT`].
pub fn describe(a: &ActionConfig) -> Result<Described, ActionError> {
    let key = describe_key(a);
    if let Some((at, d)) = DESCRIBED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.get(&key))
    {
        if d.is_ok() || at.elapsed() < FAILED_DESCRIBE_KEPT {
            return d.clone();
        }
    }
    let d = describe_fresh(a, &mut |_| {}, &CancelHandle::new());
    // Unattended is never an answer of the program's.
    if !matches!(d, Err(ActionError::Unattended)) {
        let mut cache = DESCRIBED.lock().unwrap_or_else(|e| e.into_inner());
        let map = cache.get_or_insert_with(HashMap::new);
        if map.len() >= MAX_DESCRIBED {
            map.clear();
        }
        map.insert(key, (std::time::Instant::now(), d.clone()));
    }
    d
}

/// Every block described ([`describe`]), in config order, each with its
/// answer or why there is none.
pub fn describe_all(
    actions: &[ActionConfig],
) -> Vec<(&ActionConfig, Result<Described, ActionError>)> {
    actions.iter().map(|a| (a, describe(a))).collect()
}

/// Runs a prepared action ([`prepare`]): its program with `request` on
/// stdin, each progress line to `on_line` as it comes, until it ends, its
/// time limit passes or `cancel` stops it. A program that ran is always
/// an [`Outcome`], failed or not; `Err` when it couldn't start, or
/// unattended.
pub fn run(
    a: &ActionConfig,
    request: &Value,
    on_line: &mut dyn FnMut(&str),
    cancel: &CancelHandle,
) -> Result<Outcome, ActionError> {
    let timeout = Duration::from_secs(a.timeout_seconds.max(1));
    let e = exec(a, "run", request, timeout, on_line, cancel)?;
    let status = status_words(&e, timeout);
    let mut out = Outcome {
        ok: false,
        message: String::new(),
        links: Vec::new(),
        records: Vec::new(),
        progress: e.progress.clone(),
        details: e.details.clone(),
        problems: Vec::new(),
        ended: e.ended,
        status: status.clone(),
        dry_run: request["dry_run"].as_bool().unwrap_or(false),
    };
    match e.ended {
        Ended::TimedOut => {
            out.message = format!(
                "It took longer than {} seconds, its time limit, and was stopped.",
                timeout.as_secs()
            );
            return Ok(out);
        }
        Ended::Cancelled => {
            out.message = "Cancelled: it was stopped before it finished.".into();
            return Ok(out);
        }
        Ended::Exited => {}
    }
    let exited_ok = e.status.is_some_and(|s| s.success());
    match &e.answer {
        None => {
            out.message = format!("It ended without a result ({status}).");
        }
        Some(Err(why)) => {
            out.message = why.clone();
        }
        Some(Ok(bytes)) => match parse_result(bytes) {
            Err(problems) => {
                out.message = format!(
                    "Its result couldn't be read: {}.",
                    problems[0].trim_end_matches('.')
                );
                out.problems = problems;
            }
            Ok((r, problems)) => {
                out.ok = r.ok && exited_ok;
                out.message = r.message;
                out.links = r.links;
                out.records = r.records;
                out.problems = problems;
                if r.ok && !exited_ok {
                    out.problems
                        .push(format!("It said it worked, but ended with {status}."));
                }
                if out.message.is_empty() {
                    out.message = if out.ok {
                        "Done.".into()
                    } else {
                        format!("It didn't work ({status}).")
                    };
                }
            }
        },
    }
    Ok(out)
}

/// Checks a program as `pathwarden action check` does: its `describe`,
/// then a dry run of each action it offers on `f` (a `for: "record"`
/// action on [`sample_record`]), with [`sample_inputs`]. Every problem in
/// words, prefixed with the action it is about; empty when there are none.
/// Progress lines go to `on_line` with the action's address; `cancel`
/// stops the program running and the checks still to come.
pub fn check(
    a: &ActionConfig,
    f: &FindingContext,
    on_line: &mut dyn FnMut(&str, &str),
    cancel: &CancelHandle,
) -> Vec<String> {
    let described = match describe_fresh(
        a,
        &mut |l| on_line(&format!("{}:describe", a.name), l),
        cancel,
    ) {
        Ok(d) => d,
        Err(ActionError::Describe {
            problems, details, ..
        }) => {
            let mut out: Vec<String> = problems
                .into_iter()
                .map(|p| format!("describe: {p}"))
                .collect();
            if !details.is_empty() {
                out.push(format!(
                    "describe: its error output: {}",
                    details.lines().last().unwrap_or_default()
                ));
            }
            return out;
        }
        Err(e) => return vec![e.to_string()],
    };
    let mut out: Vec<String> = described
        .problems
        .iter()
        .map(|p| format!("describe: {p}"))
        .collect();
    let who = crate::identity::Actor::current();
    for def in &described.describe.actions {
        if cancel.is_cancelled() {
            out.push("Cancelled before every action was checked.".into());
            break;
        }
        let o = offer(a, def);
        let record = (def.for_ == Some(For::Record)).then(sample_record);
        let request = run_request(a, &o, f, &sample_inputs(def), true, record.as_ref(), &who);
        let address = o.address.clone();
        match run(a, &request, &mut |l| on_line(&address, l), cancel) {
            Ok(r) => {
                out.extend(
                    r.problems
                        .iter()
                        .map(|p| format!("{address}: dry run: {p}")),
                );
                if !r.ok {
                    out.push(format!("{address}: dry run failed: {}", r.message));
                }
            }
            Err(e) => out.push(format!("{address}: dry run: {e}")),
        }
    }
    out
}

#[cfg(test)]
#[path = "actions_tests.rs"]
mod tests;
