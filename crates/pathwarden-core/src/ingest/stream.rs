//! Streaming collector files: each object in `data` is ingested as soon as it
//! is parsed, so memory holds one object at a time rather than a whole file
//! (a large forest's computers file runs to gigabytes).

use std::fmt;
use std::io::Read;

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use super::budget::{self, ObjectCost};
use super::raw::{RawMeta, RawObject};

/// How much of the start and end of a file is searched for the `meta` block.
pub(super) const PEEK: usize = 64 << 10;

/// The file's `meta` block. SharpHound and RustHound-CE write it after `data`,
/// so the end of the file is searched first, then the start.
pub(super) fn find_meta(head: &[u8], tail: &[u8]) -> Option<RawMeta> {
    [tail, head].into_iter().find_map(meta_in)
}

fn meta_in(buf: &[u8]) -> Option<RawMeta> {
    let text = String::from_utf8_lossy(buf);
    text.rmatch_indices("\"meta\"").find_map(|(at, key)| {
        let rest = text[at + key.len()..].trim_start().strip_prefix(':')?;
        let meta: RawMeta = serde_json::Deserializer::from_str(rest)
            .into_iter::<RawMeta>()
            .next()?
            .ok()?;
        (!meta.kind.is_empty()).then_some(meta)
    })
}

/// What the ends of a file say about it being an OpenGraph payload
/// (`{"metadata": {...}, "graph": {"nodes": [...], "edges": [...]}}`).
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct OgSniff {
    /// `metadata.source_kind`, when the block is within the ends read.
    pub source_kind: Option<String>,
}

/// Recognises an OpenGraph file from its first and last [`PEEK`] bytes: a
/// `"graph"` key holding an object, with `"nodes"` or `"edges"` in sight.
/// Only asked when there is no SharpHound `meta` block.
pub(super) fn find_opengraph(head: &[u8], tail: &[u8]) -> Option<OgSniff> {
    let head_text = String::from_utf8_lossy(head);
    let tail_text = String::from_utf8_lossy(tail);
    let texts = [head_text.as_ref(), tail_text.as_ref()];
    let graph = texts.iter().any(|t| {
        t.match_indices("\"graph\"").any(|(at, key)| {
            t[at + key.len()..]
                .trim_start()
                .strip_prefix(':')
                .is_some_and(|r| r.trim_start().starts_with('{'))
        })
    });
    let lists = texts
        .iter()
        .any(|t| t.contains("\"nodes\"") || t.contains("\"edges\""));
    if !graph || !lists {
        return None;
    }
    #[derive(serde::Deserialize)]
    struct Metadata {
        #[serde(default)]
        source_kind: Option<String>,
    }
    let source_kind = texts.iter().find_map(|t| {
        t.match_indices("\"metadata\"").find_map(|(at, key)| {
            let rest = t[at + key.len()..].trim_start().strip_prefix(':')?;
            let m: Metadata = serde_json::Deserializer::from_str(rest)
                .into_iter::<Metadata>()
                .next()?
                .ok()?;
            m.source_kind
        })
    });
    Some(OgSniff {
        source_kind: source_kind.filter(|s| !s.trim().is_empty() && s.len() <= 64),
    })
}

/// Parses a collector file from `de`, calling `each` for every object in its
/// `data` array with what it cost (see [`budget`]). An object over
/// `object_limit` bytes arrives with only its identifier, and
/// [`ObjectCost::oversized`] set. Everything else in the file is skipped.
pub(super) fn for_each_object<'de, R, F>(
    de: &mut serde_json::Deserializer<R>,
    object_limit: u64,
    mut each: F,
) -> serde_json::Result<()>
where
    R: serde_json::de::Read<'de>,
    F: FnMut(RawObject, ObjectCost),
{
    Top {
        each: &mut each,
        limit: object_limit,
    }
    .deserialize(&mut *de)?;
    de.end()
}

/// Reads a stream while keeping its first and last [`PEEK`] bytes, to find the
/// `meta` block without holding the whole file. Returns the byte count.
pub(super) fn head_and_tail<R: Read>(
    mut r: R,
    head: &mut Vec<u8>,
    tail: &mut Vec<u8>,
) -> std::io::Result<u64> {
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        total += n as u64;
        let chunk = &buf[..n];
        if head.len() < PEEK {
            let take = (PEEK - head.len()).min(n);
            head.extend_from_slice(&chunk[..take]);
        }
        tail.extend_from_slice(chunk);
        if tail.len() > 2 * PEEK {
            tail.drain(..tail.len() - PEEK);
        }
    }
}

struct Top<'a, F> {
    each: &'a mut F,
    limit: u64,
}

impl<'de, F: FnMut(RawObject, ObjectCost)> DeserializeSeed<'de> for Top<'_, F> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de, F: FnMut(RawObject, ObjectCost)> Visitor<'de> for Top<'_, F> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a BloodHound collector file (a JSON object)")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "data" {
                map.next_value_seed(Data {
                    each: &mut *self.each,
                    limit: self.limit,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct Data<'a, F> {
    each: &'a mut F,
    limit: u64,
}

impl<'de, F: FnMut(RawObject, ObjectCost)> DeserializeSeed<'de> for Data<'_, F> {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de, F: FnMut(RawObject, ObjectCost)> Visitor<'de> for Data<'_, F> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a list of objects")
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        loop {
            budget::begin(self.limit);
            let obj = seq.next_element::<RawObject>();
            let cost = budget::finish();
            let Some(obj) = obj? else {
                return Ok(());
            };
            if cost.oversized {
                // Only its identifier is kept, to report it.
                let object_identifier = obj.object_identifier;
                let stub = RawObject {
                    object_identifier,
                    ..RawObject::default()
                };
                (self.each)(stub, cost);
            } else {
                (self.each)(obj, cost);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_meta_after_data_and_before_it() {
        let after =
            br#"{"data":[{"ObjectIdentifier":"A"}],"meta":{"type":"users","count":1,"version":6}}"#;
        assert_eq!(find_meta(after, after).unwrap().kind, "users");
        let before = br#"{"meta": {"type": "computers"}, "data": []}"#;
        assert_eq!(find_meta(before, b"").unwrap().kind, "computers");
        // A property value that happens to say "meta" is not the block.
        let decoy =
            br#"{"data":[{"Properties":{"description":"\"meta\": x"}}],"meta":{"type":"groups"}}"#;
        assert_eq!(find_meta(decoy, decoy).unwrap().kind, "groups");
    }

    #[test]
    fn recognises_opengraph() {
        let og = br#"{"metadata":{"source_kind":"TaskHound"},"graph":{"nodes":[],"edges":[]}}"#;
        assert_eq!(
            find_opengraph(og, og).unwrap().source_kind.as_deref(),
            Some("TaskHound")
        );
        // Edges before nodes, metadata at the end, no metadata at all.
        let late = br#"{"graph": {"edges": [], "nodes": []}, "metadata": {"source_kind": "X"}}"#;
        assert_eq!(
            find_opengraph(late, late).unwrap().source_kind.as_deref(),
            Some("X")
        );
        let bare = br#"{"graph":{"nodes":[{"id":"A","kinds":["K"]}]}}"#;
        assert_eq!(find_opengraph(bare, bare).unwrap().source_kind, None);
        // A SharpHound file, or anything else, is not one.
        let sh = br#"{"data":[],"meta":{"type":"users"}}"#;
        assert!(find_opengraph(sh, sh).is_none());
        let decoy = br#"{"data":[{"Properties":{"description":"\"graph\": x"}}]}"#;
        assert!(find_opengraph(decoy, decoy).is_none());
    }

    #[test]
    fn streams_each_object_and_tolerates_null_data() {
        let text = r#"{"data":[{"ObjectIdentifier":"A"},{"ObjectIdentifier":"B"}],"meta":{"type":"users"}}"#;
        let mut seen = Vec::new();
        for_each_object(
            &mut serde_json::Deserializer::from_str(text),
            1 << 20,
            |o, _| seen.push(o.object_identifier),
        )
        .unwrap();
        assert_eq!(seen, ["A", "B"]);
        let mut n = 0;
        for_each_object(
            &mut serde_json::Deserializer::from_str(r#"{"data":null,"meta":{"type":"users"}}"#),
            1 << 20,
            |_, _| n += 1,
        )
        .unwrap();
        assert_eq!(n, 0);
    }

    /// An object whose lists outgrow the budget arrives as a stub, and the
    /// objects after it are read normally.
    #[test]
    fn oversized_objects_arrive_as_stubs() {
        let aces = "{},".repeat(50_000);
        let text = format!(
            r#"{{"data":[{{"ObjectIdentifier":"BIG","Aces":[{aces}{{}}],"Properties":{{"name":"BIG"}}}},{{"ObjectIdentifier":"OK","Aces":[{{"RightName":"Owns","PrincipalSID":"S-1"}}]}}],"meta":{{"type":"users"}}}}"#
        );
        let mut seen = Vec::new();
        for_each_object(
            &mut serde_json::Deserializer::from_str(&text),
            1 << 20,
            |o, cost| seen.push((o.object_identifier, o.aces.len(), cost.oversized)),
        )
        .unwrap();
        assert_eq!(
            seen,
            [("BIG".to_string(), 0, true), ("OK".to_string(), 1, false)]
        );
    }

    #[test]
    fn head_and_tail_keep_both_ends() {
        let data: Vec<u8> = (0..(3 * PEEK + 123)).map(|i| (i % 251) as u8).collect();
        let (mut head, mut tail) = (Vec::new(), Vec::new());
        let n = head_and_tail(&data[..], &mut head, &mut tail).unwrap();
        assert_eq!(n as usize, data.len());
        assert_eq!(head, data[..PEEK]);
        assert!(data.ends_with(&tail) && tail.len() >= PEEK);
    }
}
