//! The read on disk against reading into memory, on a fake directory
//! ([`FakePages`]): same entries, same order, same output. Then resuming a
//! read that stopped (slice 2): only what wasn't read is read again, and the
//! output is the same as a read that never stopped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};

use ldap3::SearchEntry;
use rusthound_ce::args::CollectionMethod;
use rusthound_ce::transport::ldap::LdapSearchEntry;

use super::tests::{entry, sid_bytes};
use super::*;

pub(super) const BASE: &str = "DC=contoso,DC=local";
pub(super) const CONFIG: &str = "CN=Configuration,DC=contoso,DC=local";
pub(super) const SCHEMA: &str = "CN=Schema,CN=Configuration,DC=contoso,DC=local";

type Pages = Box<dyn FnMut(&cache::Chunk, usize) -> Option<Vec<LdapSearchEntry>>>;
/// The naming contexts of a fake directory, which a test may change while
/// it is read.
type Dir = Arc<Mutex<Vec<(String, Vec<LdapSearchEntry>)>>>;

/// A directory without a DC: `pages(chunk, n)` is page `n` (from 0) of the
/// search for `chunk`. Fails at page `p` of the `k`th chunk it is asked for
/// (both from 1) when asked to, and calls `hook` with `k` as each starts.
pub(super) struct FakePages {
    pages: Pages,
    fail_at: Option<(usize, usize)>,
    /// The searches (by start) whose end says not all was returned.
    fail_end: Vec<usize>,
    hook: Option<Box<dyn FnMut(usize)>>,
    chunk: Option<cache::Chunk>,
    /// The rest chunk's Base searches: what they found, still to serve.
    queued: Option<std::collections::VecDeque<LdapSearchEntry>>,
    /// What they found gone.
    gone: Vec<String>,
    started: usize,
    page: usize,
    /// The chunks asked for, by id, in order.
    read: Vec<u32>,
    /// The objects read on their own by the rest chunk.
    objects: Vec<String>,
}

/// An entry's `uSNChanged` (0 when it has none).
pub(super) fn usn(e: &LdapSearchEntry) -> u64 {
    e.attrs
        .get("uSNChanged")
        .and_then(|v| v.first())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// `chunk`'s naming context whole, as [`returns`] understands it: what the
/// rest chunk's list searches.
pub(super) fn whole_of(chunk: &cache::Chunk) -> cache::Chunk {
    let mut whole = chunk.clone();
    whole.kind = cache::Kind::Whole;
    whole.usn_lo = None;
    whole.usn_hi = None;
    whole
}

/// The rest chunk's Base searches of `dns` in `entries` (a naming
/// context): the entries found, in order, and the DNs not there.
pub(super) fn base_reads(
    chunk: &cache::Chunk,
    entries: &[LdapSearchEntry],
    dns: &[String],
) -> (Vec<LdapSearchEntry>, Vec<String>) {
    let whole = whole_of(chunk);
    let (mut found, mut gone) = (Vec::new(), Vec::new());
    for dn in dns {
        match entries.iter().find(|e| returns(&whole, e) && e.dn == *dn) {
            Some(e) => found.push(e.clone()),
            None => gone.push(dn.clone()),
        }
    }
    (found, gone)
}

/// An object without a `uSNChanged` the account can read: no uSN range
/// returns it, a search of the whole naming context does.
pub(super) fn hide_usn(e: &mut LdapSearchEntry) {
    e.attrs.remove("uSNChanged");
}

/// Whether the search for `chunk` returns `e`, an entry of its naming
/// context: the head alone, or what is in its uSN window.
pub(super) fn returns(chunk: &cache::Chunk, e: &LdapSearchEntry) -> bool {
    // Deleted objects only with SHOW_DELETED: the delta.
    if cache::is_deleted(e) && !chunk.shows_deleted() {
        return false;
    }
    if chunk.base_only() {
        return e.dn.eq_ignore_ascii_case(&chunk.nc);
    }
    let u = usn(e);
    chunk.usn_lo.is_none_or(|lo| u >= lo) && chunk.usn_hi.is_none_or(|hi| u <= hi)
}

impl FakePages {
    fn new(pages: Pages) -> Self {
        Self {
            pages,
            fail_at: None,
            fail_end: Vec::new(),
            hook: None,
            chunk: None,
            queued: None,
            gone: Vec::new(),
            started: 0,
            page: 0,
            read: Vec::new(),
            objects: Vec::new(),
        }
    }

    /// Pages of `page_size` from fixed naming contexts.
    pub(super) fn of(ncs: Vec<(String, Vec<LdapSearchEntry>)>, page_size: usize) -> Self {
        Self::over(Arc::new(Mutex::new(ncs)), page_size)
    }

    /// Pages of `page_size` from `dir`, as it is when each page is asked for.
    fn over(dir: Dir, page_size: usize) -> Self {
        Self::new(Box::new(move |chunk, n| {
            let dir = dir.lock().unwrap();
            let (_, all) = dir.iter().find(|(nc, _)| *nc == chunk.nc)?;
            let page: Vec<_> = all
                .iter()
                .filter(|e| returns(chunk, e))
                .skip(n * page_size)
                .take(page_size)
                .cloned()
                .collect();
            (!page.is_empty()).then_some(page)
        }))
    }
}

impl PageSource for FakePages {
    async fn start(&mut self, chunk: &cache::Chunk, _filter: &str) -> Result<(), String> {
        self.started += 1;
        if let Some(hook) = self.hook.as_mut() {
            hook(self.started);
        }
        self.read.push(chunk.id);
        self.chunk = Some(chunk.clone());
        self.queued = None;
        self.page = 0;
        Ok(())
    }

    async fn start_rest(
        &mut self,
        chunk: &cache::Chunk,
        filter: &str,
        lookup: Lookup<'_>,
    ) -> Result<(), String> {
        match lookup {
            // The listing is the chunk's start; its Base searches aren't.
            Lookup::List => {
                self.start(chunk, filter).await?;
                self.chunk = Some(whole_of(chunk));
            }
            Lookup::Objects(dns) => {
                self.objects.extend(dns.iter().cloned());
                let whole = whole_of(chunk);
                let mut all = Vec::new();
                let mut n = 0;
                while let Some(page) = (self.pages)(&whole, n) {
                    all.extend(page);
                    n += 1;
                }
                let (found, gone) = base_reads(chunk, &all, dns);
                self.queued = Some(found.into());
                self.gone = gone;
                self.chunk = Some(whole);
                self.page = 0;
            }
        }
        Ok(())
    }

    fn take_gone(&mut self) -> Vec<String> {
        std::mem::take(&mut self.gone)
    }

    async fn next_page(&mut self) -> Result<Option<Page>, String> {
        self.page += 1;
        if self.fail_at == Some((self.started, self.page)) {
            return Err("LDAP search failed: connection reset".into());
        }
        let Some(chunk) = self.chunk.as_ref() else {
            return Ok(None);
        };
        if let Some(queued) = self.queued.as_mut() {
            let page: Vec<SearchEntry> = (0..5)
                .map_while(|_| queued.pop_front())
                .map(SearchEntry::from)
                .collect();
            return Ok((!page.is_empty()).then(|| Page::new(page)));
        }
        Ok((self.pages)(chunk, self.page - 1)
            .map(|p| Page::new(p.into_iter().map(SearchEntry::from).collect())))
    }

    async fn end(&mut self) -> Result<(), String> {
        if self.fail_end.contains(&self.started) {
            return Err("rc=4 (sizeLimitExceeded), dn: \"\", text: \"\"".into());
        }
        Ok(())
    }
}

/// A fresh scratch folder for one test.
pub(super) fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pw-cache-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A self-relative security descriptor: `owner`, and a DACL allowing each
/// (SID, mask).
pub(super) fn sd_bytes(owner: &[u32], aces: &[(&[u32], u32)]) -> Vec<u8> {
    let owner = sid_bytes(owner);
    let mut acl_body = Vec::new();
    for (sid, mask) in aces {
        let sid = sid_bytes(sid);
        let size = (8 + sid.len()) as u16;
        acl_body.extend_from_slice(&[0, 0]); // ACCESS_ALLOWED, no flags
        acl_body.extend_from_slice(&size.to_le_bytes());
        acl_body.extend_from_slice(&mask.to_le_bytes());
        acl_body.extend_from_slice(&sid);
    }
    let acl_size = (8 + acl_body.len()) as u16;
    let owner_at = 20u32;
    let dacl_at = owner_at + owner.len() as u32;
    let mut sd = vec![1u8, 0];
    sd.extend_from_slice(&0x8004u16.to_le_bytes()); // self-relative, DACL present
    sd.extend_from_slice(&owner_at.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes());
    sd.extend_from_slice(&dacl_at.to_le_bytes());
    sd.extend_from_slice(&owner);
    sd.extend_from_slice(&[2, 0]);
    sd.extend_from_slice(&acl_size.to_le_bytes());
    sd.extend_from_slice(&(aces.len() as u16).to_le_bytes());
    sd.extend_from_slice(&[0, 0]);
    sd.extend_from_slice(&acl_body);
    sd
}

fn with_sd(mut e: LdapSearchEntry, owner: &[u32]) -> LdapSearchEntry {
    let sd = sd_bytes(
        owner,
        &[(&[1, 2, 3, 512], 0x1000_0000), (&[1, 2, 3, 519], 0x20)],
    );
    e.bin_attrs.insert("nTSecurityDescriptor".into(), vec![sd]);
    e
}

/// Schema, domain (head first) and configuration naming contexts, as
/// RustHound-CE lists them.
pub(super) fn synthetic(users: usize) -> Vec<(String, Vec<LdapSearchEntry>)> {
    let mut schema = Vec::new();
    for (name, guid) in [("User", 1u8), ("Computer", 2), ("Group", 3)] {
        let mut e = entry(
            &format!("CN={name},{SCHEMA}"),
            &["top", "classSchema"],
            &[("name", name), ("lDAPDisplayName", &name.to_lowercase())],
            &[],
            &[9, 9, 9, guid as u32],
        );
        e.bin_attrs
            .insert("schemaIDGUID".into(), vec![vec![guid; 16]]);
        schema.push(e);
    }
    let mut domain = vec![with_sd(
        entry(
            BASE,
            &["top", "domain", "domainDNS"],
            &[("name", "contoso")],
            &[],
            &[1, 2, 3],
        ),
        &[1, 2, 3, 512],
    )];
    let mut members = Vec::new();
    for i in 0..users {
        let dn = format!("CN=User{i},CN=Users,{BASE}");
        let rid = 2000 + i as u32;
        domain.push(with_sd(
            entry(
                &dn,
                &["top", "person", "organizationalPerson", "user"],
                &[
                    ("name", &format!("User{i}")),
                    ("sAMAccountName", &format!("user{i}")),
                    ("userAccountControl", "512"),
                    ("primaryGroupID", "513"),
                ],
                &[],
                &[1, 2, 3, rid],
            ),
            &[1, 2, 3, 512],
        ));
        members.push(dn);
    }
    let members: Vec<&str> = members.iter().map(String::as_str).collect();
    domain.push(with_sd(
        entry(
            &format!("CN=Domain Admins,CN=Users,{BASE}"),
            &["top", "group"],
            &[
                ("name", "Domain Admins"),
                ("sAMAccountName", "Domain Admins"),
            ],
            &[("member", members)],
            &[1, 2, 3, 512],
        ),
        &[1, 2, 3, 512],
    ));
    domain.push(entry(
        &format!("CN=WS01,CN=Computers,{BASE}"),
        &["top", "person", "organizationalPerson", "user", "computer"],
        &[
            ("name", "WS01"),
            ("sAMAccountName", "WS01$"),
            ("dNSHostName", "ws01.contoso.local"),
            ("userAccountControl", "4096"),
            ("primaryGroupID", "515"),
        ],
        &[],
        &[1, 2, 3, 1105],
    ));
    domain.push(entry(
        &format!("OU=Servers,{BASE}"),
        &["top", "organizationalUnit"],
        &[("name", "Servers")],
        &[],
        &[1, 2, 3, 7000],
    ));
    let config = vec![entry(
        &format!("CN=Sites,{CONFIG}"),
        &["top", "container"],
        &[("name", "Sites")],
        &[],
        &[1, 2, 3, 7001],
    )];
    let mut ncs = vec![
        (SCHEMA.to_string(), schema),
        (BASE.to_string(), domain),
        (CONFIG.to_string(), config),
    ];
    // Each object's GUID, and its uSNChanged: the domain's from 1 in order
    // (the head first), the others' after them.
    let mut n = 0u64;
    for (nc, entries) in ncs.iter_mut() {
        for e in entries.iter_mut() {
            n += 1;
            e.bin_attrs.insert(
                "objectGUID".into(),
                vec![(n as u128 + 0x5000).to_le_bytes().to_vec()],
            );
            let u = if nc == BASE { n } else { n + 100_000 };
            e.attrs.insert("uSNChanged".into(), vec![u.to_string()]);
        }
    }
    let first = ncs[0].1.len() as u64;
    for e in ncs[1].1.iter_mut() {
        let u = usn(e) - first;
        e.attrs.insert("uSNChanged".into(), vec![u.to_string()]);
    }
    ncs
}

/// The domain's highest uSN in `ncs`.
pub(super) fn highest(ncs: &[(String, Vec<LdapSearchEntry>)]) -> u64 {
    ncs.iter()
        .filter(|(nc, _)| nc == BASE)
        .flat_map(|(_, v)| v.iter().map(usn))
        .max()
        .unwrap_or(0)
}

pub(super) fn contexts() -> Vec<String> {
    vec![SCHEMA.into(), BASE.into(), CONFIG.into()]
}

pub(super) fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// `read_directory` from `pages` into `sink`, each naming context whole.
pub(super) fn read(pages: &mut FakePages, sink: Sink) -> Result<ReadOut, String> {
    let (tx, _rx) = mpsc::channel::<Msg>();
    let mut timings = Timings::default();
    runtime().block_on(read_directory(
        pages,
        "(objectClass=*)",
        &cache::whole_plan(&contexts()),
        BASE,
        &tx,
        &mut timings,
        sink,
    ))
}

/// A folder for `contoso.local` in `root`, and a writer into it.
pub(super) fn disk(root: &Path) -> (cache::Folder, Sink) {
    let (folder, _) = cache::Folder::create(root, "contoso.local").unwrap();
    let writer = cache::Writer::start(&folder).unwrap();
    (folder, Sink::Disk(writer))
}

pub(super) fn same(a: &LdapSearchEntry, b: &LdapSearchEntry) -> bool {
    a.dn == b.dn && a.attrs == b.attrs && a.bin_attrs == b.bin_attrs
}

pub(super) fn dns(entries: &[LdapSearchEntry]) -> Vec<&str> {
    entries.iter().map(|e| e.dn.as_str()).collect()
}

pub(super) fn read_back(dir: &Path) -> Vec<LdapSearchEntry> {
    cache::Reader::open(dir)
        .unwrap()
        .map(|e| e.map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn a_segment_keeps_every_attribute() {
    let root = scratch("roundtrip");
    let mut e = entry(
        "CN=A,DC=x",
        &["top", "user"],
        &[("description", "é ü 中")],
        &[("member", vec!["CN=B", "CN=C"])],
        &[1, 2],
    );
    e.attrs.insert("empty".into(), vec![]);
    e.bin_attrs
        .insert("blob".into(), vec![vec![0, 255, 7], vec![]]);
    let input = vec![e, entry("CN=B,DC=x", &["top"], &[], &[], &[3])];
    let (folder, mut sink) = disk(&root);
    sink.begin(1, "DC=x").unwrap();
    sink.page(1, input.clone()).unwrap();
    sink.end(1, BTreeMap::from([("users".to_string(), 2)]))
        .unwrap();
    let Ok(ReadOut::Disk(w)) = sink.finish() else {
        panic!("written to disk")
    };
    assert_eq!((w.chunks, w.entries), (1, 2));
    assert!(w.bytes > 0);
    assert!(folder.path().join("chunk-0001.seg").is_file());
    assert!(!folder.path().join("chunk-0001.part").exists());
    let cp = cache::Checkpoint::load(folder.path()).unwrap();
    assert_eq!(cp.format, 3);
    assert_eq!(cp.key.domain, "contoso.local");
    assert_eq!(cp.chunks.len(), 1);
    assert_eq!(
        (cp.chunks[0].state, cp.chunks[0].entries, cp.chunks[0].bytes),
        (cache::State::Done, 2, w.bytes)
    );
    assert_eq!(cp.chunks[0].counts["users"], 2);
    assert_eq!((cp.totals.done, cp.totals.entries), (1, 2));
    let back = read_back(folder.path());
    assert_eq!(back.len(), 2);
    assert!(input.iter().zip(&back).all(|(a, b)| same(a, b)));
    // Dropping the folder of a stopped read keeps it, for resuming; once
    // the read is complete, it goes.
    let dir = folder.path().to_path_buf();
    let mut folder = folder;
    assert!(folder.resumable());
    folder.remove_on_drop();
    drop(folder);
    assert!(!dir.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// The files of a zip, by type (the time stamp in their names dropped),
/// with arrays sorted so that only content counts.
pub(super) fn normalized_zip(dir: &Path) -> BTreeMap<String, serde_json::Value> {
    fn norm(v: &mut serde_json::Value) {
        match v {
            serde_json::Value::Array(a) => {
                a.iter_mut().for_each(norm);
                a.sort_by_key(|x| x.to_string());
            }
            serde_json::Value::Object(o) => o.values_mut().for_each(norm),
            _ => {}
        }
    }
    let zips: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "zip"))
        .collect();
    assert_eq!(zips.len(), 1, "{zips:?}");
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&zips[0]).unwrap()).unwrap();
    let mut out = BTreeMap::new();
    for i in 0..zip.len() {
        let f = zip.by_index(i).unwrap();
        let name = f.name().unwrap().rsplit('_').next().unwrap().to_string();
        let mut v: serde_json::Value = serde_json::from_reader(f).unwrap();
        norm(&mut v);
        out.insert(name, v);
    }
    out
}

/// Same entries in the same order from disk as from memory, and the same
/// collection through RustHound-CE's parser and writer.
#[test]
fn from_disk_the_output_is_the_same_as_from_memory() {
    let root = scratch("same");
    let ncs = synthetic(40);
    // Pages of 7: several pages a naming context.
    let memory = match read(&mut FakePages::of(ncs.clone(), 7), Sink::memory()) {
        Ok(ReadOut::Memory(v)) => v,
        _ => panic!("in memory"),
    };
    let (folder, sink) = disk(&root.join("cache"));
    let Ok(ReadOut::Disk(written)) = read(&mut FakePages::of(ncs.clone(), 7), sink) else {
        panic!("on disk")
    };
    assert_eq!(written.chunks, 3);
    assert_eq!(written.entries, memory.len() as u64);
    let from_disk = read_back(folder.path());

    // The order RustHound-CE needs: Schema first, the domain head before
    // its objects, then the configuration.
    let expected: Vec<&str> = ncs
        .iter()
        .flat_map(|(_, v)| v.iter().map(|e| e.dn.as_str()))
        .collect();
    assert_eq!(dns(&memory), expected);
    assert_eq!(dns(&from_disk), expected);
    assert!(memory.iter().zip(&from_disk).all(|(a, b)| same(a, b)));
    assert_eq!(from_disk[3].dn, BASE, "the head right after the schema");

    // RustHound-CE's own in-memory source, against the cache through
    // Counting (as a collection parses it).
    let collect = |name: &str, from_cache: bool| {
        let out = root.join(name);
        std::fs::create_dir_all(&out).unwrap();
        let options = base_options(
            "contoso.local",
            &out,
            CollectionMethod::LdapOnly,
            "dc01.contoso.local".into(),
            true,
        );
        let rt = runtime();
        let results = if from_cache {
            let (tx, _rx) = mpsc::channel::<Msg>();
            let reader = cache::Reader::open(folder.path()).unwrap();
            let source = Counting::new(reader, written.entries, tx);
            rt.block_on(rusthound_ce::prepare_results_from_source(
                source, &options, None,
            ))
        } else {
            rt.block_on(rusthound_ce::prepare_results_from_source(
                memory.clone(),
                &options,
                None,
            ))
        }
        .map_err(|e| e.to_string())
        .unwrap();
        rusthound_ce::make_result(&options, results)
            .map_err(|e| e.to_string())
            .unwrap();
        normalized_zip(&out)
    };
    let a = collect("from-memory", false);
    let b = collect("from-disk", true);
    assert!(
        a.contains_key("users.json") && a.contains_key("domains.json"),
        "{:?}",
        a.keys()
    );
    assert_eq!(a, b);
    // The users got the domain's SID (the head came first), and the ACEs.
    let users = a["users.json"]["data"].as_array().unwrap();
    let user = users
        .iter()
        .find(|u| u["ObjectIdentifier"] == "S-1-5-21-1-2-3-2000")
        .expect("user");
    assert_eq!(user["Properties"]["domainsid"], "S-1-5-21-1-2-3");
    assert!(
        user["Aces"].as_array().is_some_and(|a| !a.is_empty()),
        "{user}"
    );
    drop(folder);
    let _ = std::fs::remove_dir_all(&root);
}

/// `--no-cache`: the parse from memory gives what the parse from disk does.
#[test]
fn reading_into_memory_still_works() {
    let root = scratch("nocache");
    let ncs = synthetic(5);
    let options = base_options(
        "contoso.local",
        &root,
        CollectionMethod::LdapOnly,
        "dc01.contoso.local".into(),
        true,
    );
    let (tx, rx) = mpsc::channel::<Msg>();
    let memory = read(&mut FakePages::of(ncs.clone(), 999), Sink::memory()).unwrap();
    assert!(matches!(memory, ReadOut::Memory(_)));
    let (a, _) = parse(&options, memory, &tx).unwrap();
    let (folder, sink) = disk(&root.join("cache"));
    let on_disk = read(&mut FakePages::of(ncs, 999), sink).unwrap();
    let (b, _) = parse(&options, on_disk, &tx).unwrap();
    assert_eq!(a.users.len(), b.users.len());
    assert_eq!(a.groups.len(), b.groups.len());
    assert_eq!(a.computers.len(), 1);
    assert_eq!(b.computers.len(), 1);
    assert_eq!(a.mappings.dn_sid, b.mappings.dn_sid);
    // The same progress, and a [cache] line for the read from disk.
    drop(tx);
    let logs: Vec<String> = rx
        .into_iter()
        .filter_map(|m| match m {
            Msg::Log(l) => Some(l),
            _ => None,
        })
        .collect();
    assert!(
        logs.iter()
            .any(|l| l.starts_with("[cache] 3 chunks, ") && l.contains(" on disk, written in ")),
        "{logs:?}"
    );
    assert!(shape(&b).starts_with("[memory] results: users "));
    drop(folder);
    let _ = std::fs::remove_dir_all(&root);
}

/// In memory too (`--no-cache`, a retest's read), a search the
/// domain controller ends with an error after some pages fails the read,
/// naming the naming context, instead of returning what it got.
#[test]
fn an_in_memory_search_cut_short_fails_the_read() {
    let ncs = synthetic(20);
    assert!(read(&mut FakePages::of(ncs.clone(), 5), Sink::memory()).is_ok());
    // The domain is the second search.
    let mut pages = FakePages::of(ncs, 5);
    pages.fail_end = vec![2];
    let e = read(&mut pages, Sink::memory())
        .err()
        .expect("the read fails");
    assert!(
        e.contains(&format!(
            "the domain controller did not return all of {BASE}"
        )),
        "{e}"
    );
    assert!(e.contains("sizeLimitExceeded"), "{e}");
}

/// A read that stops mid-chunk leaves a `.part`, which is never read; a
/// `.seg` cut short is refused rather than read short.
#[test]
fn a_torn_chunk_is_never_read() {
    let root = scratch("torn");
    let ncs = synthetic(20);
    let mut pages = FakePages::of(ncs.clone(), 5);
    // The domain is the second chunk: fail on its third page.
    pages.fail_at = Some((2, 3));
    let (folder, sink) = disk(&root);
    let e = read(&mut pages, sink).err().expect("the read fails");
    assert!(e.contains("connection reset"), "{e}");
    let dir = folder.path();
    assert!(dir.join("chunk-0001.seg").is_file());
    // The failed chunk's `.part` went with it (slice 3).
    assert!(!dir.join("chunk-0002.part").exists());
    assert!(!dir.join("chunk-0002.seg").exists());
    // One left by a crash is never read: the schema chunk's entries, as a
    // `.part` of the domain's.
    std::fs::copy(dir.join("chunk-0001.seg"), dir.join("chunk-0002.part")).unwrap();
    // Only the schema chunk is done.
    let back = read_back(dir);
    assert_eq!(dns(&back), dns(&ncs[0].1));

    // A checkpoint naming a chunk whose `.seg` isn't there: refused.
    let mut cp = cache::Checkpoint::load(dir).unwrap();
    let mut second = cp.chunks[0].clone();
    second.id = 2;
    cp.chunks.push(second);
    cp.save(dir).unwrap();
    let e = cache::Reader::open(dir).err().expect("refused");
    assert!(e.contains("chunk-0002.seg"), "{e}");

    // A `.seg` cut inside a length prefix ends "cleanly" for RustHound-CE's
    // reader: the count catches it.
    let cut = root.join("cut");
    let (cut_folder, mut sink) = disk(&cut);
    sink.begin(1, SCHEMA).unwrap();
    sink.page(1, ncs[0].1[..1].to_vec()).unwrap();
    sink.end(1, BTreeMap::new()).unwrap();
    // The size of a chunk of the first entry alone.
    let Ok(ReadOut::Disk(w)) = sink.finish() else {
        panic!("written")
    };
    let first = w.bytes;
    // Rewritten with every schema entry, then cut 2 bytes into the second.
    std::fs::copy(
        dir.join("chunk-0001.seg"),
        cut_folder.path().join("chunk-0001.seg"),
    )
    .unwrap();
    let mut cp = cache::Checkpoint::load(cut_folder.path()).unwrap();
    cp.chunks[0].entries = ncs[0].1.len() as u64;
    cp.save(cut_folder.path()).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(cut_folder.path().join("chunk-0001.seg"))
        .unwrap()
        .set_len(first + 2)
        .unwrap();
    let errors: Vec<String> = cache::Reader::open(cut_folder.path())
        .unwrap()
        .filter_map(|e| e.err().map(|e| e.to_string()))
        .collect();
    assert_eq!(
        errors,
        vec![format!(
            "chunk-0001.seg holds 1 entries, not {}",
            ncs[0].1.len()
        )]
    );
    drop(cut_folder);
    drop(folder);
    let _ = std::fs::remove_dir_all(&root);
}

/// The sweep removes our files only, in our folders only.
#[test]
fn the_sweep_leaves_what_is_not_ours() {
    let root = scratch("sweep");
    let touch = |p: PathBuf| std::fs::write(p, b"x").unwrap();
    // Ours, with a file of someone else's in it.
    let old = root.join("old.local");
    std::fs::create_dir(&old).unwrap();
    for f in [
        "checkpoint.json",
        "checkpoint.json.tmp",
        "checkpoint.json.lock",
        "chunk-0001.seg",
        "chunk-0002.part",
        "notes.txt",
        "chunk-0001.seg.bak",
    ] {
        touch(old.join(f));
    }
    // Ours, nothing else in it.
    let gone = root.join("gone.local");
    std::fs::create_dir(&gone).unwrap();
    touch(gone.join("checkpoint.json"));
    touch(gone.join("chunk-0001.seg"));
    // Not ours: no checkpoint.
    let other = root.join("other");
    std::fs::create_dir(&other).unwrap();
    touch(other.join("chunk-0001.seg"));
    touch(root.join("checkpoint.json"));

    assert_eq!(cache::sweep(&root), 2);
    let mut left: Vec<String> = std::fs::read_dir(&old)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["chunk-0001.seg.bak", "notes.txt"]);
    assert!(!gone.exists());
    assert!(other.join("chunk-0001.seg").is_file());
    assert!(root.join("checkpoint.json").is_file());

    // A read in progress (in another process, say) is left alone: it holds
    // its lock (File::try_lock, on every platform).
    {
        let (live, _) = cache::Folder::create(&root, "live.local").unwrap();
        assert_eq!(cache::sweep(&root), 0);
        assert!(live.path().join("checkpoint.json").is_file());
        let e = cache::Folder::create(&root, "live.local").err().unwrap();
        assert!(
            e.starts_with("another collection of live.local is reading")
                && e.ends_with("Wait for it to finish."),
            "{e}"
        );
        let dir = live.path().to_path_buf();
        drop(live);
        assert!(!dir.exists());
    }

    // A folder in the way of a new read, not ours, is not taken over.
    std::fs::create_dir(root.join("contoso.local")).unwrap();
    touch(root.join("contoso.local").join("mine.txt"));
    let e = cache::Folder::create(&root, "contoso.local").err().unwrap();
    assert!(e.contains("the folder is already there"), "{e}");
    assert!(root.join("contoso.local").join("mine.txt").is_file());
    let _ = std::fs::remove_dir_all(&root);
}

/// A new read replaces the last one's leftovers, sweeps other domains'
/// that can't be resumed, and starts with a format-2 checkpoint, in a
/// private folder.
#[test]
fn a_read_starts_clean_in_a_private_folder() {
    let root = scratch("fresh").join("collect-cache");
    let (first, swept) = cache::Folder::create(&root, "Contoso.Local").unwrap();
    assert_eq!(swept, 0);
    assert_eq!(first.path(), root.join("contoso.local"));
    first.crash();
    let (other, _) = cache::Folder::create(&root, "fabrikam.local").unwrap();
    other.crash();
    let (second, swept) = cache::Folder::create(&root, "contoso.local").unwrap();
    // Fabrikam's read had nothing in it: swept. Contoso's: replaced.
    assert_eq!(swept, 1);
    assert!(!root.join("fabrikam.local").exists());
    let cp = cache::Checkpoint::load(second.path()).unwrap();
    assert_eq!((cp.format, cp.chunks.len()), (3, 0));
    assert!(pathwarden_core::time::parse_rfc3339(&cp.started).is_some());
    assert!(pathwarden_core::perms::is_private_dir(&root));
    assert!(pathwarden_core::perms::is_private_dir(second.path()));
    drop(second);
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

#[test]
fn not_enough_space_stops_before_reading() {
    let root = scratch("space");
    // About 13 GB for 700,000 entries of 17,500 bytes; 6.5 GB free.
    fn six_and_a_half(_: &Path) -> Option<u64> {
        Some(13 << 29)
    }
    let c = crate::ReadCache {
        root: root.clone(),
        last_entries: Some(700_000),
        last_bytes: Some(700_000 * 17_500),
        ..crate::ReadCache::default()
    };
    let plan = read_plan(&c, six_and_a_half);
    let (tx, rx) = mpsc::channel::<Msg>();
    let e = prepare(&plan, &tx).err().expect("refused");
    assert!(
        e.ends_with(" for this read: about 13 GB needed, 6 GB free."),
        "{e}"
    );
    assert!(e.starts_with("Not enough free space on "), "{e}");
    drop(tx);
    let sent: Vec<crate::NoSpace> = rx
        .into_iter()
        .filter_map(|m| match m {
            Msg::NoSpace(n) => Some(*n),
            _ => None,
        })
        .collect();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to_string(), e);
    // Nothing left behind.
    assert!(!root.join("contoso.local").exists());

    // Enough: the folder stays for the read.
    fn plenty(_: &Path) -> Option<u64> {
        Some(1 << 40)
    }
    let plan = ReadPlan {
        free_space: plenty,
        ..plan
    };
    let (tx, _rx) = mpsc::channel::<Msg>();
    let d = prepare(&plan, &tx).unwrap().expect("on disk");
    assert!(d.known);
    assert!(d.folder.path().join("checkpoint.json").is_file());
    drop(d);
    // No cache asked for: into memory.
    let plan = ReadPlan {
        cache: None,
        ..plan
    };
    assert!(prepare(&plan, &tx).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&root);

    let words = crate::NoSpace {
        place: "C:".into(),
        needed: 13 << 30,
        free: (6 << 30) + 5,
    };
    assert_eq!(
        words.to_string(),
        "Not enough free space on C: for this read: about 13 GB needed, 6 GB free."
    );
    // Lab item 46: a small read, on a nearly full drive, in MB.
    let words = crate::NoSpace {
        place: "V:".into(),
        needed: cache::MIN_ROOM,
        free: 300 << 10,
    };
    assert_eq!(
        words.to_string(),
        "Not enough free space on V: for this read: about 64 MB needed, 0 MB free."
    );
    // 1 GiB is said in GB, not as 1024 MB.
    let words = crate::NoSpace {
        place: "V:".into(),
        needed: 1 << 30,
        free: 300 << 20,
    };
    assert_eq!(
        words.to_string(),
        "Not enough free space on V: for this read: about 1 GB needed, 0 GB free."
    );
}

/// A synthetic user of about 11 KB, as the probe reads them.
fn probe_user(i: usize) -> LdapSearchEntry {
    let dn = format!("CN=Probe User {i:06},OU=People,{BASE}");
    let description: String = format!("{i:06} ").repeat(300);
    let mut e = with_sd(
        entry(
            &dn,
            &["top", "person", "organizationalPerson", "user"],
            &[
                ("name", &format!("Probe User {i:06}")),
                ("sAMAccountName", &format!("probe{i:06}")),
                ("userAccountControl", "512"),
                ("primaryGroupID", "513"),
                ("description", &description),
                ("userPrincipalName", &format!("probe{i:06}@contoso.local")),
            ],
            &[],
            &[1, 2, 3, 10_000 + i as u32],
        ),
        &[1, 2, 3, 512],
    );
    let noise = |n: usize| {
        (0..n)
            .map(|k| ((k * 31 + i) % 251) as u8)
            .collect::<Vec<u8>>()
    };
    e.bin_attrs
        .insert("thumbnailPhoto".into(), vec![noise(6_000)]);
    e.bin_attrs
        .insert("userCertificate".into(), vec![noise(1_500), noise(1_000)]);
    e
}

/// Run by [`probe_peak_memory`] in a process of its own (`PW_PROBE` =
/// `memory` or `disk`): reads and parses `PW_PROBE_N` synthetic users and
/// prints the peak private bytes.
#[test]
#[ignore = "run by probe_peak_memory"]
fn probe_child() {
    let Ok(mode) = std::env::var("PW_PROBE") else {
        return;
    };
    let n: usize = std::env::var("PW_PROBE_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000);
    let root = scratch(&format!("probe-{mode}"));
    let head = synthetic(0);
    let mut pages = FakePages::new(Box::new(move |chunk, page| {
        let base = chunk.nc.as_str();
        let fixed = head
            .iter()
            .find(|(nc, _)| nc == base)
            .map(|(_, v)| v.clone());
        if base != BASE {
            return fixed.filter(|_| page == 0);
        }
        // The domain head, then the users, 999 a page.
        let mut out = if page == 0 {
            fixed.unwrap_or_default()
        } else {
            Vec::new()
        };
        let from = page * 999;
        out.extend((from..(from + 999).min(n)).map(probe_user));
        (!out.is_empty()).then_some(out)
    }));
    let folder;
    let sink = if mode == "disk" {
        let (f, s) = disk(&root.join("cache"));
        folder = Some(f);
        s
    } else {
        folder = None;
        Sink::memory()
    };
    let started = std::time::Instant::now();
    let out = read(&mut pages, sink).unwrap();
    let entries = out.entries();
    let read_took = started.elapsed();
    let options = base_options(
        "contoso.local",
        &root,
        CollectionMethod::LdapOnly,
        "dc01.contoso.local".into(),
        true,
    );
    let (tx, _rx) = mpsc::channel::<Msg>();
    let (results, _) = parse(&options, out, &tx).unwrap();
    let users = results.users.len();
    drop(results);
    drop(folder);
    let m = crate::memory::current().unwrap();
    println!(
        "probe mode={mode} entries={entries} users={users} peak_private={} peak_working_set={} read_ms={} total_ms={}",
        m.peak_private,
        m.peak_working_set,
        read_took.as_millis(),
        started.elapsed().as_millis()
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The measurement behind the on-disk read: the peak private bytes of a 200,000-entry read and
/// parse, from disk well below from memory. Each in its own process, since
/// a peak never comes down.
#[test]
#[ignore = "a probe: about 3 GB of memory and 2 GB of disk; run by hand"]
fn probe_peak_memory() {
    let exe = std::env::current_exe().unwrap();
    let run = |mode: &str| -> (u64, String) {
        let out = pathwarden_core::spawn::quiet(&exe)
            .args([
                "builtin::cache_tests::probe_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PW_PROBE", mode)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "{text}{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let line = text
            .lines()
            .find_map(|l| l.find("probe mode=").map(|i| &l[i..]))
            .unwrap_or_else(|| panic!("{text}"))
            .to_string();
        let peak = line
            .split(' ')
            .find_map(|w| w.strip_prefix("peak_private="))
            .and_then(|v| v.parse().ok())
            .unwrap();
        (peak, line)
    };
    let (memory, a) = run("memory");
    let (disk, b) = run("disk");
    eprintln!("{a}\n{b}");
    assert!(disk < 1_200 << 20, "from disk: {disk} bytes");
    assert!(
        disk * 10 < memory * 6,
        "from disk {disk}, from memory {memory}"
    );
}

/// Without an earlier read, the sizing count's estimate less what is on
/// disk already, against what is free now.
#[test]
fn the_check_after_the_count_counts_what_is_written() {
    let root = scratch("recheck");
    // 1,000,000 entries at 16 KB: about 18 GB. 9 GB free.
    fn nine(_: &Path) -> Option<u64> {
        Some(9 << 30)
    }
    let c = crate::ReadCache {
        root: root.clone(),
        ..crate::ReadCache::default()
    };
    let plan = read_plan(&c, nine);
    let (tx, _rx) = mpsc::channel::<Msg>();
    let mut d = prepare(&plan, &tx).unwrap().expect("on disk");
    assert!(!d.known);
    assert_eq!(d.need, cache::MIN_ROOM);
    let e = recheck_space(&mut d, 1_000_000, 0, nine, &tx).unwrap_err();
    assert!(e.ends_with("about 17 GB needed, 9 GB free."), "{e}");
    // 10 GB already written: about 7 GB to go.
    recheck_space(&mut d, 1_000_000, 10 << 30, nine, &tx).unwrap();
    assert_eq!(d.need, cache::needed(1_000_000, None));
    // A size known from an earlier read is not replaced.
    d.known = true;
    d.need = 5;
    recheck_space(&mut d, 1_000_000, 0, nine, &tx).unwrap();
    assert_eq!(d.need, 5);
    drop(d);
    let _ = std::fs::remove_dir_all(&root);
}

/// A writer that fails mid-read stops the read with its error; a full disk
/// becomes the typed refusal, with the space free when it filled.
#[test]
fn a_writer_failing_mid_read_stops_the_read() {
    let root = scratch("writefail");
    let ncs = synthetic(30);
    fn plenty(_: &Path) -> Option<u64> {
        Some(1 << 40)
    }
    fn nearly_none(_: &Path) -> Option<u64> {
        Some(1 << 20)
    }
    let c = crate::ReadCache {
        root: root.clone(),
        ..crate::ReadCache::default()
    };
    let plan = read_plan(&c, plenty);
    for kind in [
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::StorageFull,
    ] {
        let (tx, rx) = mpsc::channel::<Msg>();
        let d = prepare(&plan, &tx).unwrap().expect("on disk");
        // The third page: one chunk done, the domain's in progress.
        let writer = cache::Writer::failing(&d.folder, 3, kind).unwrap();
        let stats = writer.stats();
        let e = read(&mut FakePages::of(ncs.clone(), 5), Sink::Disk(writer))
            .err()
            .expect("the read fails");
        assert!(e.starts_with("cannot write the read to disk: "), "{e}");
        assert!(stats.written.load(Ordering::Relaxed) > 0);
        let full = kind == std::io::ErrorKind::StorageFull;
        assert_eq!(stats.full.load(Ordering::Relaxed), full);
        let message = disk_full(Some(&d), Some(&stats), e.clone(), nearly_none, &tx);
        drop(tx);
        let refused: Vec<crate::NoSpace> = rx
            .into_iter()
            .filter_map(|m| match m {
                Msg::NoSpace(n) => Some(*n),
                _ => None,
            })
            .collect();
        if full {
            assert!(
                message.starts_with("Not enough free space on ")
                    && message.ends_with("about 64 MB needed, 1 MB free."),
                "{message}"
            );
            assert_eq!(refused.len(), 1);
            assert_eq!(refused[0].free, 1 << 20);
        } else {
            assert_eq!(message, e);
            assert!(refused.is_empty());
        }
        // One chunk was done: kept, to resume once there is space.
        assert!(d.folder.resumable());
        let dir = d.folder.path().to_path_buf();
        drop(d);
        assert!(dir.join("chunk-0001.seg").is_file(), "kept to resume");
        assert_eq!(cache::remove_ours(&dir), cache::Removal::Removed);
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// A chunk another program holds open (an antivirus scan, an indexer) keeps
/// the checkpoint, so the folder stays ours and a later sweep finishes it.
#[cfg(windows)]
#[test]
fn a_chunk_held_open_is_swept_later() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = scratch("held");
    let (folder, _) = cache::Folder::create(&root, "contoso.local").unwrap();
    let dir = folder.path().to_path_buf();
    folder.crash();
    std::fs::write(dir.join("chunk-0001.seg"), b"raw").unwrap();
    std::fs::write(dir.join("chunk-0002.seg"), b"raw").unwrap();
    // Shared for reading and writing, not for deleting.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(dir.join("chunk-0001.seg"))
        .unwrap();
    assert_eq!(cache::sweep(&root), 0);
    assert!(dir.join("checkpoint.json").is_file());
    assert!(!dir.join("chunk-0002.seg").exists());
    assert_eq!(
        cache::remove_ours(&dir),
        cache::Removal::Kept("chunk-0001.seg".into())
    );
    let e = cache::Folder::create(&root, "contoso.local").err().unwrap();
    assert!(e.contains("another program has chunk-0001.seg open"), "{e}");
    drop(held);
    assert_eq!(cache::sweep(&root), 1);
    assert!(!dir.exists());
    let _ = std::fs::remove_dir_all(&root);
}

pub(super) fn plenty(_: &Path) -> Option<u64> {
    Some(1 << 40)
}

/// The account the fake domain controller names.
pub(super) const WHO: &str = "contoso\\svc";

/// A read of `contoso.local` into `c`, as `contoso\svc`, from dc01.
pub(super) fn read_plan(c: &crate::ReadCache, free_space: cache::FreeSpace) -> ReadPlan<'_> {
    ReadPlan {
        cache: Some(c),
        domain: "contoso.local",
        free_space,
        dc_host: "dc01.contoso.local",
        account: WHO.into(),
        sign_in: crate::sign_in_key(&crate::Auth::CurrentUser),
        attributes: attributes::PARSED,
        streams: 1,
        connector: None,
    }
}

/// [`prepare_cache`] with no uSN from the DC: each context whole.
fn prepare(plan: &ReadPlan<'_>, tx: &mpsc::Sender<Msg>) -> Result<Option<DiskPlan>, String> {
    let snap = DcSnapshot {
        highest_usn: None,
        ..snapshot(0)
    };
    prepare_cache(plan, &contexts(), BASE, "(objectClass=*)", &snap, tx)
}

/// The fake DC's database at uSN `highest`.
pub(super) fn snapshot(highest: u64) -> DcSnapshot {
    DcSnapshot {
        highest_usn: Some(highest),
        ds_service_name: "CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=contoso,DC=local".into(),
        invocation_id: "8f3c00a1b2c3d4e5f60718293a4b5c6d".into(),
    }
}

/// A read on disk in uSN windows, as a collection makes it.
struct Chunked {
    root: PathBuf,
    resume: bool,
    snap: DcSnapshot,
    account: String,
    filter: String,
    attributes: &'static [&'static str],
    /// The writer stops after renaming this chunk, as a crash would.
    crash_after: Option<u32>,
}

/// What [`Chunked::run`] did.
struct Ran {
    disk: DiskPlan,
    out: Result<ReadOut, String>,
    logs: Vec<String>,
}

impl Chunked {
    fn new(root: &Path, highest: u64) -> Self {
        Self {
            root: root.to_path_buf(),
            resume: false,
            snap: snapshot(highest),
            account: WHO.into(),
            filter: "(objectClass=*)".into(),
            attributes: attributes::PARSED,
            crash_after: None,
        }
    }

    fn resuming(mut self) -> Self {
        self.resume = true;
        self
    }

    fn run(&self, pages: &mut FakePages) -> Ran {
        let c = crate::ReadCache {
            root: self.root.clone(),
            resume: self.resume,
            ..crate::ReadCache::default()
        };
        let mut plan = read_plan(&c, plenty);
        plan.account = self.account.clone();
        plan.attributes = self.attributes;
        let (tx, rx) = mpsc::channel::<Msg>();
        let disk = prepare_cache(&plan, &contexts(), BASE, &self.filter, &self.snap, &tx)
            .unwrap()
            .expect("on disk");
        let writer = match self.crash_after {
            Some(id) => cache::Writer::crashing_after(&disk.folder, id),
            None => cache::Writer::start(&disk.folder),
        }
        .unwrap();
        let mut timings = Timings::default();
        let out = runtime().block_on(read_directory(
            pages,
            &self.filter,
            &disk.chunks,
            BASE,
            &tx,
            &mut timings,
            Sink::Disk(writer),
        ));
        drop(tx);
        let logs = rx
            .into_iter()
            .filter_map(|m| match m {
                Msg::Log(l) => Some(l),
                _ => None,
            })
            .collect();
        Ran { disk, out, logs }
    }
}

/// The normalized zip RustHound-CE writes from the read in `dir`.
pub(super) fn output_from(dir: &Path, out: &Path) -> BTreeMap<String, serde_json::Value> {
    std::fs::create_dir_all(out).unwrap();
    let options = base_options(
        "contoso.local",
        out,
        CollectionMethod::LdapOnly,
        "dc01.contoso.local".into(),
        true,
    );
    let (tx, _rx) = mpsc::channel::<Msg>();
    let reader = cache::Reader::open(dir).unwrap();
    let results = runtime()
        .block_on(rusthound_ce::prepare_results_from_source(
            Counting::new(reader, 0, tx),
            &options,
            None,
        ))
        .map_err(|e| e.to_string())
        .unwrap();
    rusthound_ce::make_result(&options, results)
        .map_err(|e| e.to_string())
        .unwrap();
    normalized_zip(out)
}

fn ids(from: u32, to: u32) -> Vec<u32> {
    (from..=to).collect()
}

/// A read that fails at chunk 23, page 4, then resumes: the chunks done
/// are not read again, the rest are, and the entries and the output are
/// those of a read that never stopped.
#[test]
fn a_stopped_read_resumes_where_it_stopped() {
    let root = scratch("resume");
    let ncs = synthetic(1280);
    let h = highest(&ncs);
    // Schema, head, 64 windows, Configuration, delta, rest.
    let all = 1 + 1 + 64 + 1 + 1 + 1;

    // A read that never stopped.
    let whole = Chunked::new(&root.join("whole"), h);
    let mut pages = FakePages::of(ncs.clone(), 5);
    let mut ran = whole.run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    assert_eq!(pages.read, ids(1, all));
    let expected = read_back(ran.disk.folder.path());
    let expected_out = output_from(ran.disk.folder.path(), &root.join("out-whole"));
    ran.disk.folder.remove_on_drop();
    drop(ran);

    // It stops at the 23rd chunk's 4th page.
    let first = Chunked::new(&root.join("cache"), h);
    let mut pages = FakePages::of(ncs.clone(), 5);
    pages.fail_at = Some((23, 4));
    let ran = first.run(&mut pages);
    let e = ran.out.err().expect("the read stops");
    assert!(e.contains("connection reset"), "{e}");
    assert!(ran.disk.folder.resumable());
    let dir = ran.disk.folder.path().to_path_buf();
    drop(ran.disk);
    // Kept: 22 chunks done; the 23rd's `.part` went when it failed.
    let cp = cache::Checkpoint::load(&dir).unwrap();
    let done: Vec<u32> = cp
        .chunks
        .iter()
        .filter(|c| c.is_done())
        .map(|c| c.id)
        .collect();
    assert_eq!(done, ids(1, 22));
    assert!(!dir.join("chunk-0023.part").exists());
    // One a crash left would go on resume.
    std::fs::write(dir.join("chunk-0023.part"), b"torn").unwrap();
    assert!(dir.join("checkpoint.json.lock").exists());
    let stopped = crate::stopped_read(
        &crate::ReadCache {
            root: root.join("cache"),
            ..crate::ReadCache::default()
        },
        "contoso.local",
        &crate::Auth::CurrentUser,
    )
    .expect("can be resumed");
    assert!(stopped.percent > 20 && stopped.percent < 40, "{stopped:?}");
    assert_eq!(stopped.ago(stopped.stopped + 7300), "2 h ago");

    // Resumed: only what wasn't done is read.
    let mut pages = FakePages::of(ncs.clone(), 5);
    let mut ran = first.resuming().run(&mut pages);
    assert!(
        ran.logs
            .iter()
            .any(|l| l.contains("resuming the read of contoso.local") && l.contains("21 of 69")),
        "{:?}",
        ran.logs
    );
    let Ok(ReadOut::Disk(w)) = &ran.out else {
        panic!("{:?}", ran.out.err())
    };
    // The head again (one Base search: as it is now), then what was left.
    let mut left = vec![2];
    left.extend(ids(23, all));
    assert_eq!(pages.read, left);
    assert!(w.resumed_from.is_some());
    assert_eq!(w.chunks, all as usize);
    assert!(!dir.join("chunk-0023.part").exists());
    let back = read_back(&dir);
    assert_eq!(dns(&back), dns(&expected));
    assert!(back.iter().zip(&expected).all(|(a, b)| same(a, b)));
    // Every entry of the directory once, the head right after the schema.
    assert_eq!(back.len(), ncs.iter().map(|(_, v)| v.len()).sum::<usize>());
    assert_eq!(back[3].dn, BASE);
    assert_eq!(output_from(&dir, &root.join("out-resumed")), expected_out);
    ran.disk.folder.remove_on_drop();
    drop(ran);
    assert!(!dir.exists());
    let _ = std::fs::remove_dir_all(&root);
}

/// A stopped read at `root`, with chunks 1 to 4 done.
fn stopped_at(root: &Path, ncs: &[(String, Vec<LdapSearchEntry>)]) -> PathBuf {
    let mut pages = FakePages::of(ncs.to_vec(), 5);
    pages.fail_at = Some((5, 1));
    let ran = Chunked::new(root, highest(ncs)).run(&mut pages);
    assert!(ran.out.is_err());
    let dir = ran.disk.folder.path().to_path_buf();
    drop(ran);
    assert!(dir.join("chunk-0004.seg").is_file());
    dir
}

fn edit_checkpoint(dir: &Path, f: impl FnOnce(&mut serde_json::Value)) {
    let path = dir.join("checkpoint.json");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
}

/// Each reason a read can't be resumed starts it over, with a log line:
/// another domain controller (invocationID), account, filter, format, or
/// more than 24 hours since it started. And not asking to resume.
#[test]
fn each_stale_cause_starts_over() {
    let root = scratch("stale");
    let ncs = synthetic(200);
    let h = highest(&ncs);
    type Change = Box<dyn Fn(&mut Chunked, &Path)>;
    let causes: Vec<(&str, Change)> = vec![
        (
            "it was read from another domain controller",
            Box::new(|c, _| c.snap.invocation_id = "00".repeat(16)),
        ),
        (
            "it was read with another account",
            Box::new(|c, _| c.account = "contoso\\someone-else".into()),
        ),
        (
            "it was read with another filter",
            Box::new(|c, _| c.filter = "(objectCategory=*)".into()),
        ),
        // A read stopped with the list, resumed with every attribute
        // (`--all-attributes`): the hash of what is asked for differs.
        (
            "it asked for other attributes",
            Box::new(|c, _| c.attributes = attributes::ALL),
        ),
        (
            "it was written by an older Pathwarden",
            Box::new(|_, dir| edit_checkpoint(dir, |v| v["format"] = 2.into())),
        ),
        (
            "it was written by a newer Pathwarden",
            Box::new(|_, dir| edit_checkpoint(dir, |v| v["format"] = 4.into())),
        ),
        (
            "it is more than 24 hours old",
            Box::new(|_, dir| {
                let then = pathwarden_core::time::format_rfc3339(cache::now() - 25 * 3600);
                edit_checkpoint(dir, |v| v["started"] = then.into())
            }),
        ),
        (
            "its checkpoint is damaged",
            Box::new(|_, dir| std::fs::write(dir.join("checkpoint.json"), b"{").unwrap()),
        ),
    ];
    for (why, change) in causes {
        let dir = stopped_at(&root, &ncs);
        let mut again = Chunked::new(&root, h).resuming();
        change(&mut again, &dir);
        let mut pages = FakePages::of(ncs.clone(), 999);
        let mut ran = again.run(&mut pages);
        assert!(ran.out.is_ok(), "{why}: {:?}", ran.out.err());
        assert_eq!(pages.read.first(), Some(&1), "{why}: started over");
        assert_eq!(pages.read.len(), 69, "{why}");
        assert!(
            ran.logs.iter().any(|l| l
                == &format!(
                    "[cache] the earlier read of contoso.local was not resumed: {why}. \
                     Starting over."
                )),
            "{why}: {:?}",
            ran.logs
        );
        ran.disk.folder.remove_on_drop();
    }
    // A read that could be resumed, without asking to: over too.
    stopped_at(&root, &ncs);
    let mut pages = FakePages::of(ncs.clone(), 999);
    let ran = Chunked::new(&root, h).run(&mut pages);
    assert_eq!(pages.read.first(), Some(&1));
    assert!(
        ran.logs
            .iter()
            .any(|l| l.ends_with("was not resumed: resuming it wasn't asked for. Starting over.")),
        "{:?}",
        ran.logs
    );
    // ... and the offer is only for the sign-in that read it, not in use.
    stopped_at(&root.join("offer"), &ncs);
    let c = crate::ReadCache {
        root: root.join("offer"),
        ..crate::ReadCache::default()
    };
    assert!(crate::stopped_read(&c, "contoso.local", &crate::Auth::CurrentUser).is_some());
    assert!(crate::stopped_read(&c, "fabrikam.local", &crate::Auth::CurrentUser).is_none());
    let password = crate::Auth::Password {
        user: "svc".into(),
        password: crate::Secret::new("x"),
    };
    assert!(crate::stopped_read(&c, "contoso.local", &password).is_none());
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// An object changed during the read leaves its window for the delta: it
/// is read back once, in its newest version, whether its window was read
/// before the change or after.
#[test]
fn an_object_changed_mid_read_appears_once_newest() {
    let root = scratch("changed");
    let ncs = synthetic(1280);
    let h = highest(&ncs);
    let dir: Dir = Arc::new(Mutex::new(ncs.clone()));
    let mut pages = FakePages::over(dir.clone(), 7);
    let early = format!("CN=User5,CN=Users,{BASE}");
    let late = format!("CN=User1279,CN=Users,{BASE}");
    {
        let (early, late) = (early.clone(), late.clone());
        pages.hook = Some(Box::new(move |k| {
            // At the 30th chunk: User5's window is read, User1279's isn't.
            if k != 30 {
                return;
            }
            let mut dir = dir.lock().unwrap();
            let (_, domain) = dir.iter_mut().find(|(nc, _)| nc == BASE).unwrap();
            for (dn, u) in [(&early, h + 3), (&late, h + 9)] {
                let e = domain.iter_mut().find(|e| e.dn == *dn).unwrap();
                e.attrs.insert("uSNChanged".into(), vec![u.to_string()]);
                e.attrs.insert("description".into(), vec!["changed".into()]);
            }
        }));
    }
    let mut ran = Chunked::new(&root, h).run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    let reader = cache::Reader::open(ran.disk.folder.path()).unwrap();
    let dropped = reader.dropped();
    let back: Vec<LdapSearchEntry> = reader.map(|e| e.unwrap()).collect();
    for dn in [&early, &late] {
        let found: Vec<_> = back.iter().filter(|e| e.dn == *dn).collect();
        assert_eq!(found.len(), 1, "{dn}");
        assert_eq!(found[0].attrs["description"], ["changed"], "{dn}");
    }
    assert_eq!(back.iter().filter(|e| e.dn == BASE).count(), 1);
    // User5's older version (the head read again with its window isn't counted).
    assert_eq!(dropped.load(Ordering::Relaxed), 1);
    assert_eq!(back.len(), ncs.iter().map(|(_, v)| v.len()).sum::<usize>());
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// The domain head is read back right after the schema even when it is
/// the last chunk read (here, resumed), and only once.
#[test]
fn the_head_comes_first_even_when_read_last() {
    let root = scratch("head");
    let ncs = synthetic(100);
    let h = highest(&ncs);
    let run = Chunked::new(&root, h);
    let ran = run.run(&mut FakePages::of(ncs.clone(), 999));
    assert!(ran.out.is_ok());
    let dir = ran.disk.folder.path().to_path_buf();
    drop(ran);
    // The head's chunk (2) not done: read again, last.
    edit_checkpoint(&dir, |v| v["chunks"][1]["state"] = "todo".into());
    let mut pages = FakePages::of(ncs.clone(), 999);
    let mut ran = run.resuming().run(&mut pages);
    assert!(ran.out.is_ok());
    assert_eq!(pages.read, [2]);
    let back = read_back(&dir);
    assert_eq!(back[ncs[0].1.len()].dn, BASE);
    assert_eq!(back.iter().filter(|e| e.dn == BASE).count(), 1);
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// A crash after a chunk's `.seg` is renamed but before the checkpoint
/// says it is done: the chunk is read again, and the output is complete.
#[test]
fn a_crash_between_rename_and_checkpoint_redoes_the_chunk() {
    let root = scratch("crash");
    let ncs = synthetic(300);
    let h = highest(&ncs);
    let mut run = Chunked::new(&root, h);
    run.crash_after = Some(10);
    let ran = run.run(&mut FakePages::of(ncs.clone(), 999));
    assert!(ran.out.is_err());
    let dir = ran.disk.folder.path().to_path_buf();
    drop(ran);
    assert!(dir.join("chunk-0010.seg").is_file());
    let cp = cache::Checkpoint::load(&dir).unwrap();
    assert!(!cp.chunks[9].is_done());
    run.crash_after = None;
    let mut pages = FakePages::of(ncs.clone(), 999);
    let mut ran = run.resuming().run(&mut pages);
    assert!(ran.out.is_ok());
    assert_eq!(pages.read[..2], [2, 10]);
    let back = read_back(&dir);
    assert_eq!(back.len(), ncs.iter().map(|(_, v)| v.len()).sum::<usize>());
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// Another domain's read that can still be resumed survives a new read's
/// sweep; a stale one doesn't, and a newer format's is left alone.
#[test]
fn the_sweep_keeps_what_can_be_resumed() {
    let root = scratch("keep");
    let ncs = synthetic(50);
    let fresh = stopped_at(&root, &ncs);
    let other = root.join("fabrikam.local");
    std::fs::rename(&fresh, &other).unwrap();
    let old = root.join("old.local");
    std::fs::create_dir(&old).unwrap();
    std::fs::copy(other.join("checkpoint.json"), old.join("checkpoint.json")).unwrap();
    let then = pathwarden_core::time::format_rfc3339(cache::now() - 25 * 3600);
    edit_checkpoint(&old, |v| v["started"] = then.into());
    let newer = root.join("newer.local");
    std::fs::create_dir(&newer).unwrap();
    std::fs::write(newer.join("checkpoint.json"), br#"{"format": 4}"#).unwrap();
    assert_eq!(cache::sweep(&root), 1);
    assert!(other.join("chunk-0001.seg").is_file());
    assert!(!old.exists());
    assert!(newer.join("checkpoint.json").is_file());
    let _ = std::fs::remove_dir_all(&root);
}

/// The normalized zip RustHound-CE writes from entries in memory.
pub(super) fn output_from_memory(
    entries: Vec<LdapSearchEntry>,
    out: &Path,
) -> BTreeMap<String, serde_json::Value> {
    std::fs::create_dir_all(out).unwrap();
    let options = base_options(
        "contoso.local",
        out,
        CollectionMethod::LdapOnly,
        "dc01.contoso.local".into(),
        true,
    );
    let results = runtime()
        .block_on(rusthound_ce::prepare_results_from_source(
            entries, &options, None,
        ))
        .map_err(|e| e.to_string())
        .unwrap();
    rusthound_ce::make_result(&options, results)
        .map_err(|e| e.to_string())
        .unwrap();
    normalized_zip(out)
}

/// The domain's entries with their uSNChanged shuffled: objects reach the
/// windows in an order that isn't the tree's (a group before its members,
/// an OU after what is in it).
fn shuffled(mut ncs: Vec<(String, Vec<LdapSearchEntry>)>) -> Vec<(String, Vec<LdapSearchEntry>)> {
    let domain = &mut ncs[1].1;
    let n = domain.len() as u64;
    for (i, e) in domain.iter_mut().enumerate() {
        // 7919 is prime, so this is a permutation of 1..=n.
        let u = (i as u64 * 7919) % n + 1;
        e.attrs.insert("uSNChanged".into(), vec![u.to_string()]);
    }
    ncs
}

/// N7: a read in uSN windows, with objects arriving out of tree order,
/// gives RustHound-CE's output exactly as the read into memory does.
#[test]
fn windows_in_any_order_give_the_in_memory_output() {
    let root = scratch("shuffled");
    let ncs = shuffled(synthetic(300));
    let h = highest(&ncs);
    let usns: Vec<u64> = ncs[1].1.iter().map(usn).collect();
    assert!(usns.windows(2).any(|w| w[0] > w[1]), "out of order");
    let memory = match read(&mut FakePages::of(ncs.clone(), 7), Sink::memory()) {
        Ok(ReadOut::Memory(v)) => v,
        _ => panic!("in memory"),
    };
    let expected = output_from_memory(memory, &root.join("out-memory"));
    let mut pages = FakePages::of(ncs.clone(), 7);
    let mut ran = Chunked::new(&root.join("cache"), h).run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    assert_eq!(pages.read.len(), 69);
    let back = read_back(ran.disk.folder.path());
    assert_eq!(back[3].dn, BASE);
    assert_eq!(back.len(), ncs.iter().map(|(_, v)| v.len()).sum::<usize>());
    assert_eq!(
        output_from(ran.disk.folder.path(), &root.join("out-windows")),
        expected
    );
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// S1: on resume the head is read again: the domain object as it is now
/// (a permission granted on it after the read stopped is not missed), once,
/// right after the schema.
#[test]
fn the_head_is_read_again_on_resume() {
    let root = scratch("headagain");
    let ncs = synthetic(200);
    let h = highest(&ncs);
    let dir = stopped_at(&root, &ncs);
    let cp = cache::Checkpoint::load(&dir).unwrap();
    assert!(cp.chunks[1].is_done(), "the head was read");
    // Changed after the read stopped: a newer uSN, so in the delta too.
    let mut changed = ncs.clone();
    let head = &mut changed[1].1[0];
    head.attrs
        .insert("description".into(), vec!["changed after the stop".into()]);
    head.attrs
        .insert("uSNChanged".into(), vec![(h + 5).to_string()]);
    let mut pages = FakePages::of(changed.clone(), 999);
    let mut ran = Chunked::new(&root, h).resuming().run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    assert_eq!(pages.read.first(), Some(&2));
    let back = read_back(&dir);
    let heads: Vec<_> = back.iter().filter(|e| e.dn == BASE).collect();
    assert_eq!(heads.len(), 1);
    assert_eq!(heads[0].attrs["description"], ["changed after the stop"]);
    assert_eq!(back[changed[0].1.len()].dn, BASE);
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// Marks `dn` in `ncs`'s domain deleted at uSN `u`, as AD does (it keeps
/// its GUID).
fn delete(domain: &mut [LdapSearchEntry], dn: &str, u: u64) {
    let e = domain.iter_mut().find(|e| e.dn == dn).unwrap();
    e.attrs.insert("isDeleted".into(), vec!["TRUE".into()]);
    e.attrs.insert("uSNChanged".into(), vec![u.to_string()]);
}

/// S2: an object deleted after its window was read is not in the output,
/// whether the read went on or stopped and resumed: the delta asks for
/// deleted objects and drops it from its window.
#[test]
fn an_object_deleted_mid_read_is_left_out() {
    let root = scratch("deleted");
    let ncs = synthetic(1280);
    let h = highest(&ncs);
    let early = format!("CN=User5,CN=Users,{BASE}");
    let late = format!("CN=User1279,CN=Users,{BASE}");
    // During one read.
    let dir: Dir = Arc::new(Mutex::new(ncs.clone()));
    let mut pages = FakePages::over(dir.clone(), 7);
    {
        let (early, late) = (early.clone(), late.clone());
        pages.hook = Some(Box::new(move |k| {
            if k == 30 {
                let mut dir = dir.lock().unwrap();
                let (_, domain) = dir.iter_mut().find(|(nc, _)| nc == BASE).unwrap();
                delete(domain, &early, h + 3);
                delete(domain, &late, h + 4);
            }
        }));
    }
    let mut ran = Chunked::new(&root.join("one"), h).run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    let back = read_back(ran.disk.folder.path());
    assert!(!back.iter().any(|e| e.dn == early || e.dn == late));
    assert!(!back.iter().any(cache::is_deleted));
    assert_eq!(
        back.len(),
        ncs.iter().map(|(_, v)| v.len()).sum::<usize>() - 2
    );
    ran.disk.folder.remove_on_drop();
    drop(ran);

    // Stopped, the object deleted, then resumed.
    let resumed = root.join("two");
    let dir = stopped_at(&resumed, &ncs);
    let mut gone = ncs.clone();
    delete(&mut gone[1].1, &early, h + 3);
    let mut ran = Chunked::new(&resumed, h)
        .resuming()
        .run(&mut FakePages::of(gone, 999));
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    let back = read_back(&dir);
    assert!(!back.iter().any(|e| e.dn == early));
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// S3: a read whose domain controller's database couldn't be identified
/// can't be resumed: not kept, and never offered.
#[test]
fn a_read_without_an_invocation_id_is_not_kept() {
    let root = scratch("noinvocation");
    let ncs = synthetic(50);
    let mut run = Chunked::new(&root, highest(&ncs));
    run.snap.invocation_id.clear();
    let mut pages = FakePages::of(ncs.clone(), 5);
    pages.fail_at = Some((5, 1));
    let ran = run.run(&mut pages);
    assert!(ran.out.is_err());
    assert!(!ran.disk.folder.resumable());
    let dir = ran.disk.folder.path().to_path_buf();
    drop(ran);
    assert!(!dir.exists());
    // A checkpoint left without one (a crash): no offer either.
    let dir = stopped_at(&root, &ncs);
    edit_checkpoint(&dir, |v| v["invocation_id"] = "".into());
    let c = crate::ReadCache {
        root: root.clone(),
        ..crate::ReadCache::default()
    };
    assert!(crate::stopped_read(&c, "contoso.local", &crate::Auth::CurrentUser).is_none());
    // ... and the sweep at start removes it.
    assert_eq!(crate::sweep_stopped_reads(&root), 1);
    assert!(!dir.exists());
    assert!(root.join("read-key").is_file(), "the cache's key stays");
    let _ = std::fs::remove_dir_all(&root);
}

/// N1: a chunk the DC didn't return completely stays to do: the read stops
/// (and can be resumed) instead of keeping a chunk with entries missing.
#[test]
fn an_incomplete_chunk_stays_to_do() {
    struct Short(FakePages);
    impl PageSource for Short {
        async fn start(&mut self, chunk: &cache::Chunk, filter: &str) -> Result<(), String> {
            self.0.start(chunk, filter).await
        }
        async fn start_rest(
            &mut self,
            chunk: &cache::Chunk,
            filter: &str,
            lookup: Lookup<'_>,
        ) -> Result<(), String> {
            self.0.start_rest(chunk, filter, lookup).await
        }
        fn take_gone(&mut self) -> Vec<String> {
            self.0.take_gone()
        }
        async fn next_page(&mut self) -> Result<Option<Page>, String> {
            self.0.next_page().await
        }
        async fn end(&mut self) -> Result<(), String> {
            if self.0.started == 4 {
                Err("sizeLimitExceeded".into())
            } else {
                Ok(())
            }
        }
    }
    let root = scratch("short");
    let ncs = synthetic(200);
    let run = Chunked::new(&root, highest(&ncs));
    let c = crate::ReadCache {
        root: root.clone(),
        ..crate::ReadCache::default()
    };
    let plan = read_plan(&c, plenty);
    let (tx, _rx) = mpsc::channel::<Msg>();
    let disk = prepare_cache(&plan, &contexts(), BASE, &run.filter, &run.snap, &tx)
        .unwrap()
        .unwrap();
    let writer = cache::Writer::start(&disk.folder).unwrap();
    let mut timings = Timings::default();
    let mut pages = Short(FakePages::of(ncs, 999));
    let e = runtime()
        .block_on(read_directory(
            &mut pages,
            &run.filter,
            &disk.chunks,
            BASE,
            &tx,
            &mut timings,
            Sink::Disk(writer),
        ))
        .err()
        .expect("stops");
    assert!(
        e.contains("did not return all of") && e.contains("sizeLimitExceeded"),
        "{e}"
    );
    let cp = cache::Checkpoint::load(disk.folder.path()).unwrap();
    assert!(cp.chunks[2].is_done() && !cp.chunks[3].is_done());
    let stopped = crate::ReadStopped {
        domain: "contoso.local".into(),
        dc: Some("dc01.contoso.local".into()),
        reason: e,
    };
    assert_eq!(
        stopped.to_string(),
        "The read stopped: dc01.contoso.local did not return everything. It can be resumed \
         for 24 hours."
    );
    drop(disk);
    let _ = std::fs::remove_dir_all(&root);
}

/// N5: the common causes in plain words; the rest as the collector said.
#[test]
fn why_a_read_stopped_in_plain_words() {
    let says = |reason: &str| {
        crate::ReadStopped {
            domain: "contoso.local".into(),
            dc: Some("dc01.contoso.local".into()),
            reason: reason.into(),
        }
        .to_string()
    };
    assert_eq!(
        says("LDAP search of DC=contoso,DC=local failed: An existing connection was forcibly closed by the remote host. (os error 10054)"),
        "The read stopped: the connection to dc01.contoso.local was lost. It can be resumed for 24 hours."
    );
    assert_eq!(
        says("LDAP search of DC=x: connection stalled: the domain controller sent nothing for 5 minutes"),
        "The read stopped: dc01.contoso.local stopped answering. It can be resumed for 24 hours."
    );
    assert_eq!(
        says("cannot write the read to disk: Access is denied. (os error 5)"),
        "The read stopped: it could not be written to disk. It can be resumed for 24 hours."
    );
    assert_eq!(
        says("something else."),
        "The read stopped: something else. It can be resumed for 24 hours."
    );
}

/// `ncs` with the `uSNChanged` of every `every`th object of the domain
/// (not the head) and of its group hidden, as a plain user sees the
/// BCKUPKEY secrets or some foreign security principals. Their DNs, sorted.
pub(super) fn hiding_usns(
    mut ncs: Vec<(String, Vec<LdapSearchEntry>)>,
    every: usize,
) -> (Vec<(String, Vec<LdapSearchEntry>)>, Vec<String>) {
    let mut hidden = Vec::new();
    for (i, e) in ncs[1].1.iter_mut().enumerate() {
        if i > 0 && (i % every == 1 || e.dn.starts_with("CN=Domain Admins,")) {
            hide_usn(e);
            hidden.push(e.dn.clone());
        }
    }
    hidden.sort();
    (ncs, hidden)
}

/// What the read into memory gives for `ncs`.
pub(super) fn memory_output(
    ncs: &[(String, Vec<LdapSearchEntry>)],
    out: &Path,
) -> BTreeMap<String, serde_json::Value> {
    let memory = match read(&mut FakePages::of(ncs.to_vec(), 7), Sink::memory()) {
        Ok(ReadOut::Memory(v)) => v,
        _ => panic!("in memory"),
    };
    output_from_memory(memory, out)
}

/// Lab item 42: objects whose `uSNChanged` the account can't read are in
/// no uSN range. The rest chunk lists the domain by DN and reads each one
/// it missed: the output is the read into memory's, read straight through
/// and across a resume that stopped in the rest chunk.
#[test]
fn objects_without_a_readable_usn_are_read_too() {
    let root = scratch("hidden-usn");
    let (ncs, hidden) = hiding_usns(synthetic(300), 7);
    assert!(hidden.len() > 40, "{}", hidden.len());
    let h = highest(&ncs);
    let expected = memory_output(&ncs, &root.join("out-memory"));
    let all = ncs.iter().map(|(_, v)| v.len()).sum::<usize>();

    // Straight through: each object read once, on its own.
    let mut pages = FakePages::of(ncs.clone(), 7);
    let mut ran = Chunked::new(&root.join("cache"), h).run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    assert_eq!(pages.read, ids(1, 69));
    let mut asked = pages.objects.clone();
    asked.sort();
    assert_eq!(asked, hidden);
    let said = format!(
        "[read] {} objects of {BASE} in no uSN range (this account can't read their \
         uSNChanged): reading each on its own",
        hidden.len()
    );
    assert!(ran.logs.contains(&said), "{:?}", ran.logs);
    let back = read_back(ran.disk.folder.path());
    assert_eq!(back.len(), all);
    assert_eq!(back[3].dn, BASE);
    assert_eq!(
        output_from(ran.disk.folder.path(), &root.join("out-cache")),
        expected
    );
    ran.disk.folder.remove_on_drop();
    drop(ran);

    // Every object has a readable uSNChanged: the list finds none missing.
    let plain = synthetic(300);
    let mut pages = FakePages::of(plain.clone(), 7);
    let mut ran = Chunked::new(&root.join("plain"), highest(&plain)).run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    assert!(pages.objects.is_empty());
    assert!(!ran.logs.iter().any(|l| l.contains("in no uSN range")));
    ran.disk.folder.remove_on_drop();
    drop(ran);

    // Stopped in the rest chunk's list (the 69th search), then resumed:
    // what the windows and the delta read before it stopped is seen from
    // their files, and only the hidden objects are read on their own.
    let first = Chunked::new(&root.join("stopped"), h);
    let mut pages = FakePages::of(ncs.clone(), 7);
    pages.fail_at = Some((69, 1));
    let ran = first.run(&mut pages);
    assert!(ran.out.is_err());
    assert!(ran.disk.folder.resumable());
    drop(ran);
    let mut pages = FakePages::of(ncs.clone(), 7);
    let mut ran = first.resuming().run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    // The head again, then the rest chunk alone.
    assert_eq!(pages.read, [2, 69]);
    let mut asked = pages.objects.clone();
    asked.sort();
    assert_eq!(asked, hidden);
    assert_eq!(read_back(ran.disk.folder.path()).len(), all);
    assert_eq!(
        output_from(ran.disk.folder.path(), &root.join("out-resumed")),
        expected
    );
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}

/// A resumed rest chunk takes what the windows saw from each done chunk's
/// keys (`chunk-NNNN.dns`), and from its `.seg` when they are missing or
/// cut short: the same output either way.
#[test]
fn a_resumed_rest_chunk_reads_the_keys_beside_the_chunks() {
    let root = scratch("hidden-keys");
    let (ncs, hidden) = hiding_usns(synthetic(300), 5);
    let h = highest(&ncs);
    let expected = memory_output(&ncs, &root.join("out-memory"));
    let first = Chunked::new(&root.join("cache"), h);
    let mut pages = FakePages::of(ncs.clone(), 7);
    pages.fail_at = Some((69, 1));
    let ran = first.run(&mut pages);
    assert!(ran.out.is_err());
    let dir = ran.disk.folder.path().to_path_buf();
    drop(ran);
    // The head, the windows and the delta have keys; the others don't.
    let cp = cache::Checkpoint::load(&dir).unwrap();
    for c in cp.chunks.iter().filter(|c| c.is_done()) {
        let keys = dir.join(format!("chunk-{:04}.dns", c.id));
        if cache::sees_dns(c.kind) {
            let len = std::fs::metadata(&keys).unwrap().len();
            assert_eq!(len, c.entries * 16, "chunk {}", c.id);
        } else {
            assert!(!keys.exists(), "chunk {}", c.id);
        }
    }
    // One window's keys gone, another's cut short: read from their `.seg`.
    std::fs::remove_file(dir.join("chunk-0010.dns")).unwrap();
    let cut = dir.join("chunk-0020.dns");
    let bytes = std::fs::read(&cut).unwrap();
    std::fs::write(&cut, &bytes[..bytes.len().saturating_sub(16)]).unwrap();
    let mut pages = FakePages::of(ncs.clone(), 7);
    let mut ran = first.resuming().run(&mut pages);
    assert!(ran.out.is_ok(), "{:?}", ran.out.err());
    let mut asked = pages.objects.clone();
    asked.sort();
    assert_eq!(asked, hidden);
    assert_eq!(output_from(&dir, &root.join("out-resumed")), expected);
    ran.disk.folder.remove_on_drop();
    drop(ran);
    let _ = std::fs::remove_dir_all(&root);
}
