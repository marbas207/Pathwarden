//! The shared settings merged entry by entry ([`super::sync`]): each shared
//! section as entries (a Tier Zero object, an accepted risk, a Tier Zero
//! settings folder, a zone, a management plane, a mapping pack, a single
//! rule setting), compared with the last sync. Both sides' changes to
//! different entries are applied on both; the same entry changed to
//! different values on both sides, or changed on one and removed on the
//! other, is a clash, and waits for a choice while this computer keeps its
//! own value for it.
//!
//! Entries are written into `pathwarden.toml` and the repository's file
//! one by one ([`apply`]): every other entry, and the comments around it,
//! stay as they are.

use std::collections::{BTreeMap, BTreeSet};

use toml::Value;
use toml_edit::{ArrayOfTables, DocumentMut, Item, Table, TableLike};

/// One entry of a section, on one side.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Ent {
    /// What a person reads: "APP01$", "Stale Tier Zero account".
    pub label: String,
    /// As written; `None` for a rule setting left at its default.
    pub raw: Option<Value>,
    /// What is compared: the same for two ways of writing one value.
    pub eff: String,
    /// The key as written (a `[rules.severities]` key).
    pub name: String,
    /// Where it is in its list (0 for a key of a table): a section is
    /// recorded in the order its side writes it.
    pub pos: usize,
}

/// A section's entries, by ID.
pub(super) type Entries = BTreeMap<String, Ent>;

/// The rule settings with a field of their own, and their plain words.
pub(super) const RULE_KEYS: &[(&str, &str)] = &[
    ("stale_days", "Stale Tier Zero account"),
    ("password_age_days", "Old Tier Zero password"),
    ("krbtgt_age_days", "Old krbtgt password"),
    ("sso_key_age_days", "Old Seamless SSO key"),
    ("severity", "How attack paths are rated"),
];

/// A rule setting's value when `[rules]` doesn't set it.
fn rule_default(key: &str) -> Option<Value> {
    let d = crate::config::RulesConfig::default();
    Some(match key {
        "stale_days" => Value::Integer(d.stale_days),
        "password_age_days" => Value::Integer(d.password_age_days),
        "krbtgt_age_days" => Value::Integer(d.krbtgt_age_days),
        "sso_key_age_days" => Value::Integer(d.sso_key_age_days),
        "severity" => Value::String("exposure".into()),
        _ => return None,
    })
}

fn rule_eff(key: &str, v: &Value) -> String {
    match (key, v) {
        ("severity", Value::String(s)) => format!("s{}", s.trim().to_lowercase()),
        _ => super::digest(v),
    }
}

/// The ID of a string in a list: as each list compares its strings.
fn string_id(list: &str, s: &str) -> String {
    match list {
        "settings_folders" => crate::folder_origin::key(s),
        "disabled" => s.trim().to_uppercase(),
        _ => s.trim().to_lowercase(),
    }
}

/// The ID of an entry of `[[suppress]]`, `[[zone]]` or `[[mapping]]`.
fn table_id(key: &str, t: &toml::Table) -> Option<String> {
    let s = |k: &str| t.get(k).and_then(Value::as_str);
    match key {
        "suppress" => s("fingerprint")
            .or(s("rule"))
            .map(|x| x.trim().to_lowercase()),
        "zone" => s("name").map(crate::zones::name_key),
        "mapping" => s("path").map(crate::pack_origin::path_key),
        _ => None,
    }
}

fn table_label(key: &str, t: &toml::Table) -> String {
    let s = |k: &str| t.get(k).and_then(Value::as_str).unwrap_or_default().trim();
    match key {
        "suppress" if !s("fingerprint").is_empty() => format!("Accepted risk {}", s("fingerprint")),
        "suppress" => format!("Accepted risk for every {} finding", s("rule")),
        "zone" => format!("Zone {}", s("name")),
        _ => format!("Mapping pack {}", s("path")),
    }
}

fn severity_level(v: &Value) -> String {
    match v {
        Value::String(s) => format!("s{}", s.trim().to_lowercase()),
        Value::Table(t) => match t.get("severity") {
            Some(Value::String(s)) => format!("s{}", s.trim().to_lowercase()),
            _ => super::digest(v),
        },
        other => super::digest(other),
    }
}

/// Section `key` as entries, or `None` when it can't be taken apart (a form
/// this version doesn't read, two entries with one ID): it is then settled
/// whole, as one entry.
pub(super) fn entries(key: &str, v: Option<&Value>) -> Option<Entries> {
    let mut out = Entries::new();
    let strings = |out: &mut Entries,
                   list: &str,
                   prefix: &str,
                   v: Option<&Value>,
                   label: &dyn Fn(&str) -> String|
     -> Option<()> {
        let Some(v) = v else { return Some(()) };
        for (pos, x) in v.as_array()?.iter().enumerate() {
            let s = x.as_str()?;
            let id = format!("{prefix}{}", string_id(list, s));
            // Written twice: settled whole, so nothing is lost.
            if out.contains_key(&id) {
                return None;
            }
            out.insert(
                id,
                Ent {
                    label: label(s.trim()),
                    raw: Some(x.clone()),
                    eff: "1".into(),
                    name: s.to_string(),
                    pos,
                },
            );
        }
        Some(())
    };
    match key {
        "tier_zero" | "settings_folders" => {
            strings(&mut out, key, "", v, &|s| s.to_string())?;
        }
        "management_planes" => {
            let empty = toml::Table::new();
            let t = match v {
                None => &empty,
                Some(v) => v.as_table()?,
            };
            for (k, x) in t {
                if k == "not_tier_zero" && x.is_array() {
                    strings(&mut out, k, "not_tier_zero.", Some(x), &|s| s.to_string())?;
                } else {
                    out.insert(
                        k.clone(),
                        Ent {
                            label: format!("Management planes {k}"),
                            raw: Some(x.clone()),
                            eff: super::digest(x),
                            pos: 0,
                            name: k.clone(),
                        },
                    );
                }
            }
        }
        "rules" => {
            let empty = toml::Table::new();
            let t = match v {
                None => &empty,
                Some(v) => v.as_table()?,
            };
            for (k, label) in RULE_KEYS {
                if !t.contains_key(*k) {
                    let d = rule_default(k)?;
                    out.insert(
                        k.to_string(),
                        Ent {
                            label: label.to_string(),
                            raw: None,
                            eff: rule_eff(k, &d),
                            pos: 0,
                            name: k.to_string(),
                        },
                    );
                }
            }
            for (k, x) in t {
                match (k.as_str(), x) {
                    ("severities", Value::Table(set)) => {
                        for (rule, e) in set {
                            let id = format!("severities.{}", rule.trim().to_uppercase());
                            if out.contains_key(&id) {
                                return None;
                            }
                            out.insert(
                                id,
                                Ent {
                                    label: format!("Severity of {}", rule.trim().to_uppercase()),
                                    raw: Some(e.clone()),
                                    eff: severity_level(e),
                                    pos: 0,
                                    name: rule.clone(),
                                },
                            );
                        }
                    }
                    ("disabled", Value::Array(_)) => {
                        strings(&mut out, "disabled", "disabled.", Some(x), &|s| {
                            format!("{} turned off", s.to_uppercase())
                        })?;
                    }
                    _ => {
                        let label = RULE_KEYS
                            .iter()
                            .find(|(r, _)| r == k)
                            .map_or_else(|| format!("Rule setting {k}"), |(_, l)| l.to_string());
                        out.insert(
                            k.clone(),
                            Ent {
                                label,
                                raw: Some(x.clone()),
                                eff: rule_eff(k, x),
                                pos: 0,
                                name: k.clone(),
                            },
                        );
                    }
                }
            }
        }
        "suppress" | "zone" | "mapping" => {
            let Some(v) = v else { return Some(out) };
            for (pos, x) in v.as_array()?.iter().enumerate() {
                let t = x.as_table()?;
                let id = table_id(key, t)?;
                if out.contains_key(&id) {
                    return None;
                }
                out.insert(
                    id,
                    Ent {
                        label: table_label(key, t),
                        raw: Some(x.clone()),
                        eff: super::digest(x),
                        name: String::new(),
                        pos,
                    },
                );
            }
        }
        _ => return None,
    }
    Some(out)
}

/// Whether two values of section `key` hold the same entries.
pub(super) fn same(key: &str, a: Option<&Value>, b: Option<&Value>) -> bool {
    match (entries(key, a), entries(key, b)) {
        (Some(x), Some(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(id, e)| y.get(id).is_some_and(|f| f.eff == e.eff))
        }
        _ => a.map(super::digest) == b.map(super::digest),
    }
}

/// Section `key` from its entries, in the order given (`None` when it has
/// none): how the base records it.
pub(super) fn build(key: &str, e: &[(String, Ent)]) -> Option<Value> {
    let raws = || e.iter().filter_map(|(_, x)| x.raw.clone());
    let v = match key {
        "tier_zero" | "settings_folders" | "suppress" | "zone" | "mapping" => {
            Value::Array(raws().collect())
        }
        _ => {
            let mut t = toml::Table::new();
            let mut list: Vec<Value> = Vec::new();
            let mut severities = toml::Table::new();
            for (id, x) in e {
                let Some(raw) = x.raw.clone() else { continue };
                let id: &String = id;
                if id.starts_with("not_tier_zero.") || id.starts_with("disabled.") {
                    list.push(raw);
                } else if id.starts_with("severities.") {
                    severities.insert(x.name.clone(), raw);
                } else {
                    t.insert(id.clone(), raw);
                }
            }
            if !list.is_empty() {
                let k = if key == "rules" {
                    "disabled"
                } else {
                    "not_tier_zero"
                };
                t.insert(k.into(), Value::Array(list));
            }
            if !severities.is_empty() {
                t.insert("severities".into(), Value::Table(severities));
            }
            Value::Table(t)
        }
    };
    (!super::is_empty_value(&v)).then_some(v)
}

/// A choice for an entry with two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Pick {
    Here,
    Shared,
}

/// What a section's merge moves, by entry ID.
#[derive(Debug, Clone, Default)]
pub(super) struct Plan {
    /// Entries this computer takes from the shared settings.
    pub to_local: Vec<String>,
    /// Entries the shared settings take from this computer.
    pub to_repo: Vec<String>,
    /// Entries with two values, waiting for a choice: this computer keeps
    /// its own meanwhile.
    pub clashes: Vec<String>,
    /// Of [`Plan::to_local`] and [`Plan::to_repo`], the clashes `pick`
    /// settled.
    pub settled: Vec<String>,
}

/// One section, on each side and at the last sync.
#[derive(Debug, Clone)]
pub(super) struct Split {
    pub base: Entries,
    pub local: Entries,
    pub repo: Entries,
}

impl Split {
    fn ids(&self) -> BTreeSet<&String> {
        self.base
            .keys()
            .chain(self.local.keys())
            .chain(self.repo.keys())
            .collect()
    }

    /// The three-way merge: an entry changed on one side only goes to the
    /// other; changed on both to one value, nothing moves; changed on both
    /// to different values (or changed on one, removed on the other), a
    /// clash, unless `pick` chooses.
    pub fn plan(&self, pick: &dyn Fn(&str) -> Option<Pick>) -> Plan {
        fn eff<'a>(e: &'a Entries, id: &str) -> Option<&'a str> {
            e.get(id).map(|x| x.eff.as_str())
        }
        let mut p = Plan::default();
        for id in self.ids() {
            let (b, l, r) = (
                eff(&self.base, id),
                eff(&self.local, id),
                eff(&self.repo, id),
            );
            if l == r {
                continue;
            }
            if l == b {
                p.to_local.push(id.clone());
            } else if r == b {
                p.to_repo.push(id.clone());
            } else {
                match pick(id) {
                    Some(Pick::Shared) => p.to_local.push(id.clone()),
                    Some(Pick::Here) => p.to_repo.push(id.clone()),
                    None => {
                        p.clashes.push(id.clone());
                        continue;
                    }
                }
                p.settled.push(id.clone());
            }
        }
        // Each side takes entries in the order the other writes them.
        let pos = |e: &Entries, id: &str| e.get(id).map_or(usize::MAX, |x| x.pos);
        p.to_local.sort_by_key(|id| pos(&self.repo, id));
        p.to_repo.sort_by_key(|id| pos(&self.local, id));
        p
    }

    /// `picked` entries (from each ID's side) in the order the repository
    /// writes them: its own in its order, then the others in this
    /// computer's order (as [`apply`] adds them), then the base's.
    fn ordered(&self, picked: Vec<(String, Ent)>) -> Vec<(String, Ent)> {
        let mut v = picked;
        v.sort_by_key(
            |(id, _)| match (self.repo.get(id), self.local.get(id), self.base.get(id)) {
                (Some(e), _, _) => (0, e.pos),
                (None, Some(e), _) => (1, e.pos),
                (None, None, Some(e)) => (2, e.pos),
                _ => (3, 0),
            },
        );
        v
    }

    /// The section as the repository holds it once this computer's
    /// entries [`Plan::to_repo`] went there: a clash keeps its value.
    pub fn in_repo(&self, plan: &Plan) -> Vec<(String, Ent)> {
        let mut out = Vec::new();
        for id in self.ids() {
            let from = if plan.to_repo.contains(id) {
                &self.local
            } else {
                &self.repo
            };
            if let Some(e) = from.get(id) {
                out.push((id.clone(), e.clone()));
            }
        }
        self.ordered(out)
    }

    /// The section as the base records it after a sync with `plan`: each
    /// entry as the repository now holds it (with this computer's changes
    /// when `pushed`), clashes and `left_out` entries as they were.
    pub fn after(&self, plan: &Plan, pushed: bool, left_out: &[String]) -> Vec<(String, Ent)> {
        let mut out = Vec::new();
        for id in self.ids() {
            let from = if plan.clashes.contains(id) || left_out.contains(id) {
                &self.base
            } else if pushed && plan.to_repo.contains(id) {
                &self.local
            } else {
                &self.repo
            };
            if let Some(e) = from.get(id) {
                out.push((id.clone(), e.clone()));
            }
        }
        self.ordered(out)
    }
}

// ------------------------------------------------------------ the words

/// A value in plain words: "30 days", "by rule", "removed".
pub(super) fn words(key: &str, id: &str, e: Option<&Ent>) -> String {
    let Some(e) = e else {
        return "removed".into();
    };
    let raw = e.raw.clone().or_else(|| rule_default(id));
    let Some(raw) = raw else {
        return "not set".into();
    };
    match (key, id) {
        ("rules", "severity") => match raw.as_str().map(|s| s.trim().to_lowercase()) {
            Some(s) if s == "static" => "by rule".into(),
            Some(s) if s == "exposure" => "by exposure".into(),
            Some(s) => s,
            None => plain(&raw),
        },
        ("rules", k) if k.ends_with("_days") => match raw.as_integer() {
            Some(n) => crate::text::count(n.max(0) as usize, "day", "days"),
            None => plain(&raw),
        },
        ("rules", k) if k.starts_with("severities.") => {
            let level = match &raw {
                Value::Table(t) => t.get("severity").and_then(Value::as_str),
                other => other.as_str(),
            };
            level.map_or_else(|| plain(&raw), |l| l.trim().to_lowercase())
        }
        ("suppress" | "zone" | "mapping", _) => {
            let json = serde_json::to_value(Value::Array(vec![raw.clone()])).ok();
            super::section_lines(key, json.as_ref())
                .into_iter()
                .next()
                .unwrap_or_else(|| e.label.clone())
        }
        _ => plain(&raw),
    }
}

/// A value as text: a string as it is, anything else as written.
fn plain(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Datetime(d) => d.to_string(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// A value short enough for a button ("60"), when it has one.
pub(super) fn short(key: &str, id: &str, e: Option<&Ent>) -> Option<String> {
    let raw = e?.raw.clone().or_else(|| rule_default(id))?;
    (key == "rules" && id.ends_with("_days"))
        .then(|| raw.as_integer().map(|n| n.to_string()))
        .flatten()
}

/// What moved for entry `id` of section `key`, from `old` to `new`: "APP01$
/// added to Tier Zero", "Stale Tier Zero account: 60 days".
pub(super) fn change(key: &str, id: &str, old: Option<&Ent>, new: Option<&Ent>) -> String {
    let label = new.or(old).map(|e| e.label.clone()).unwrap_or_default();
    let verb = match (old, new) {
        (None, _) => "added",
        (_, None) => "removed",
        _ => "changed",
    };
    match key {
        "tier_zero" => match new {
            Some(_) => format!("{label} added to Tier Zero"),
            None => format!("{label} removed from Tier Zero"),
        },
        "settings_folders" => match new {
            Some(_) => format!("{label} added to the Tier Zero settings folders"),
            None => format!("{label} removed from the Tier Zero settings folders"),
        },
        "management_planes" if id.starts_with("not_tier_zero.") => match new {
            Some(_) => format!("{label} marked not Tier Zero"),
            None => format!("{label} no longer marked not Tier Zero"),
        },
        "rules" if id.starts_with("disabled.") => {
            let rule = id.trim_start_matches("disabled.");
            match new {
                Some(_) => format!("{rule} turned off"),
                None => format!("{rule} turned on"),
            }
        }
        "rules" if new.is_none() => format!("{label}: default"),
        "rules" => format!("{label}: {}", words(key, id, new)),
        _ => format!("{label} {verb}"),
    }
}

// ----------------------------------------------------------- the files

/// A parsed value of a document item, as the sides read it.
fn item_value(item: &Item) -> Option<Value> {
    let mut d = DocumentMut::new();
    d.insert("x", item.clone());
    d.to_string().parse::<toml::Table>().ok()?.remove("x")
}

/// Makes entries `ids` of section `key` in `doc` what they are in `from`:
/// replaced, added, or removed when `from` has none. Every other entry,
/// and the comments around it, stay. A section `from` doesn't hold in a
/// form this reads changes nothing.
pub(super) fn apply(
    doc: &mut DocumentMut,
    key: &str,
    ids: &[String],
    from: &DocumentMut,
) -> Result<(), String> {
    if ids.is_empty() {
        return Ok(());
    }
    let root = doc.as_table_mut();
    match key {
        "tier_zero" | "settings_folders" => {
            let wanted = strings_of(from.get(key));
            apply_strings(root, key, ids, &wanted);
        }
        "suppress" | "zone" | "mapping" => apply_tables(root, key, ids, from.get(key))?,
        "rules" | "management_planes" => {
            let src = from.get(key).and_then(Item::as_table_like);
            if !root.contains_key(key) {
                root.insert(key, Item::Table(Table::new()));
            }
            let t = root
                .get_mut(key)
                .and_then(Item::as_table_like_mut)
                .ok_or_else(|| format!("`{key}` in pathwarden.toml is not a table"))?;
            let list = if key == "rules" {
                "disabled"
            } else {
                "not_tier_zero"
            };
            let prefix = format!("{list}.");
            let in_list: Vec<String> = ids
                .iter()
                .filter_map(|i| i.strip_prefix(&prefix).map(str::to_string))
                .collect();
            if !in_list.is_empty() {
                let wanted = strings_of(src.and_then(|s| s.get(list)));
                apply_strings(t, list, &in_list, &wanted);
            }
            let sev: Vec<&str> = ids
                .iter()
                .filter_map(|i| i.strip_prefix("severities."))
                .collect();
            if key == "rules" && !sev.is_empty() {
                apply_severities(t, &sev, src.and_then(|s| s.get("severities")))?;
            }
            for id in ids {
                if id.starts_with(&prefix) || (key == "rules" && id.starts_with("severities.")) {
                    continue;
                }
                match src.and_then(|s| s.get(id)) {
                    Some(Item::Value(v)) => {
                        let mut v = v.clone();
                        match t.get_mut(id) {
                            Some(Item::Value(old)) => {
                                *v.decor_mut() = old.decor().clone();
                                *old = v;
                            }
                            _ => {
                                v.decor_mut().clear();
                                t.insert(id, Item::Value(v));
                            }
                        }
                    }
                    Some(other) => {
                        t.insert(id, other.clone());
                    }
                    None => {
                        t.remove(id);
                    }
                }
            }
            if t.is_empty() {
                root.remove(key);
            }
        }
        _ => {}
    }
    Ok(())
}

fn strings_of(item: Option<&Item>) -> Vec<String> {
    item.and_then(Item::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The list `name` of `t` with entries `ids` as in `wanted`.
fn apply_strings(t: &mut dyn TableLike, name: &str, ids: &[String], wanted: &[String]) {
    let id_of = |s: &str| string_id(name, s);
    let existed = t.contains_key(name);
    let current = strings_of(t.get(name));
    let mut out: Vec<String> = Vec::new();
    for s in &current {
        if ids.contains(&id_of(s)) {
            if let Some(w) = wanted.iter().find(|w| id_of(w) == id_of(s)) {
                if !out.iter().any(|o| id_of(o) == id_of(w)) {
                    out.push(w.clone());
                }
            }
        } else {
            out.push(s.clone());
        }
    }
    for id in ids {
        if out.iter().any(|o| &id_of(o) == id) {
            continue;
        }
        if let Some(w) = wanted.iter().find(|w| &id_of(w) == id) {
            out.push(w.clone());
        }
    }
    crate::config_edit::set_string_list(t, name, &out, existed);
}

fn apply_severities(
    t: &mut dyn TableLike,
    rules: &[&str],
    src: Option<&Item>,
) -> Result<(), String> {
    let src = src.and_then(Item::as_table_like);
    if !t.contains_key("severities") {
        let mut s = Table::new();
        s.set_implicit(false);
        t.insert("severities", Item::Table(s));
    }
    let set = t
        .get_mut("severities")
        .and_then(Item::as_table_like_mut)
        .ok_or("`severities` in [rules] is not a table; edit it by hand")?;
    for rule in rules {
        let find = |t: &dyn TableLike| {
            t.iter()
                .map(|(k, _)| k.to_string())
                .find(|k| k.trim().eq_ignore_ascii_case(rule))
        };
        if let Some(k) = find(set) {
            set.remove(&k);
        }
        if let Some((k, item)) =
            src.and_then(|s| find(s).and_then(|k| Some((k.clone(), s.get(&k)?.clone()))))
        {
            set.insert(&k, item);
        }
    }
    if set.is_empty() {
        t.remove("severities");
    }
    Ok(())
}

fn apply_tables(
    root: &mut Table,
    key: &str,
    ids: &[String],
    from: Option<&Item>,
) -> Result<(), String> {
    let id_of = |t: &Table| -> Option<String> {
        let v = item_value(&Item::Table(t.clone()))?;
        table_id(key, v.as_table()?)
    };
    let src: Vec<(String, Table)> = from
        .and_then(Item::as_array_of_tables)
        .into_iter()
        .flatten()
        .filter_map(|t| Some((id_of(t)?, t.clone())))
        .collect();
    if !root.contains_key(key) {
        root.insert(key, Item::ArrayOfTables(ArrayOfTables::new()));
    }
    let list = root
        .get_mut(key)
        .and_then(Item::as_array_of_tables_mut)
        .ok_or_else(|| {
            format!("`{key}` in pathwarden.toml is written in a form this can't edit")
        })?;
    for id in ids {
        let here = list.iter().position(|t| id_of(t).as_ref() == Some(id));
        let there = src.iter().find(|(i, _)| i == id).map(|(_, t)| t.clone());
        match (here, there) {
            (Some(i), Some(mut t)) => {
                if let Some(old) = list.get(i) {
                    t.decor_mut().clone_from(old.decor());
                }
                if let Some(slot) = list.get_mut(i) {
                    *slot = t;
                }
            }
            (None, Some(mut t)) => {
                t.decor_mut().set_prefix("\n");
                list.push(t);
            }
            (Some(i), None) => list.remove(i),
            (None, None) => {}
        }
    }
    if list.is_empty() {
        root.remove(key);
    }
    Ok(())
}
