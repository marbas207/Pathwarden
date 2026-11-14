//! Ranged retrieval: AD returns at most 1,500 values of an
//! attribute in one entry (`member;range=0-1499`), and the rest takes more
//! Base searches of that object. Read inline, those searches held up the
//! stream's next page; here a pool of workers, each on a connection of its
//! own, completes the entries while the streams read on. A page goes to
//! the writer only once all of its entries are complete
//! ([`super::LdapPages`]).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ldap3::{Scope as LdapScope, SearchEntry};
use tokio::sync::{mpsc, oneshot, Mutex};

use super::{or_stalled, STALL_TIMEOUT};

/// Workers in the pool.
pub(super) const WORKERS: usize = 4;

pub(super) type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A connection ranged searches go over.
pub(super) trait RangedConn: Send {
    /// `attr` (`member;range=1500-*`) of the object at `dn`, Base scope.
    fn base_search<'a>(
        &'a mut self,
        dn: &'a str,
        attr: &'a str,
    ) -> BoxFut<'a, Result<Option<SearchEntry>, String>>;
    /// Ends the connection.
    fn close(self: Box<Self>) -> BoxFut<'static, ()>;
}

impl RangedConn for ldap3::Ldap {
    fn base_search<'a>(
        &'a mut self,
        dn: &'a str,
        attr: &'a str,
    ) -> BoxFut<'a, Result<Option<SearchEntry>, String>> {
        Box::pin(async move {
            let search = async {
                self.search(dn, LdapScope::Base, "(objectClass=*)", vec![attr])
                    .await?
                    .success()
            };
            let what = format!("reading the members of {dn}");
            let (rs, _) = or_stalled(STALL_TIMEOUT, &what, search).await?;
            Ok(rs.into_iter().next().map(SearchEntry::construct))
        })
    }

    /// A handle on a connection someone else ends.
    fn close(self: Box<Self>) -> BoxFut<'static, ()> {
        Box::pin(async {})
    }
}

/// A connection of the pool's own: unbound and its driver stopped at the end.
pub(super) struct Owned {
    pub ldap: ldap3::Ldap,
    pub driver: super::Driver,
}

impl RangedConn for Owned {
    fn base_search<'a>(
        &'a mut self,
        dn: &'a str,
        attr: &'a str,
    ) -> BoxFut<'a, Result<Option<SearchEntry>, String>> {
        self.ldap.base_search(dn, attr)
    }

    fn close(self: Box<Self>) -> BoxFut<'static, ()> {
        let Owned { ldap, driver } = *self;
        Box::pin(super::close(ldap, driver))
    }
}

/// Opens a connection for a worker.
pub(super) type Opener =
    Arc<dyn Fn() -> BoxFut<'static, Result<Box<dyn RangedConn>, String>> + Send + Sync>;

/// Completes attributes cut short by AD's ranged retrieval
/// (`member;range=0-1499`) and files the values under the plain name. From
/// RustHound-CE's `transport::ldap` (MIT, see THIRD-PARTY-NOTICES.md),
/// where it is private. Returns how many extra searches it made.
pub(super) async fn complete(
    conn: &mut dyn RangedConn,
    entry: &mut SearchEntry,
) -> Result<u64, String> {
    let mut searches = 0;
    let ranged: Vec<(String, String)> = entry
        .attrs
        .keys()
        .filter_map(|k| {
            let (base, opt) = k.split_once(';')?;
            opt.to_ascii_lowercase()
                .starts_with("range=")
                .then(|| (k.to_string(), base.to_string()))
        })
        .collect();
    for (ranged_key, base_attr) in ranged {
        let mut values = entry.attrs.remove(&ranged_key).unwrap_or_default();
        let mut high = match range_bound(&ranged_key) {
            Some(Bound::Last) => {
                entry
                    .attrs
                    .entry(base_attr)
                    .or_default()
                    .append(&mut values);
                continue;
            }
            Some(Bound::Upto(high)) => high,
            None => {
                return Err(format!(
                    "reading the members of {}: the reply's range ({ranged_key}) can't be read",
                    entry.dn
                ))
            }
        };
        // Each reply must move on, and the last one ends in `-*`: anything
        // else fails the entry rather than keep part of the values or ask
        // for the same range again.
        loop {
            let want = format!("{base_attr};range={}-*", high + 1);
            searches += 1;
            let cut = |why: &str, got: usize| {
                format!(
                    "reading the members of {}: {why} after {got} values, so the list is \
                     incomplete",
                    entry.dn
                )
            };
            let Some(chunk) = conn.base_search(&entry.dn, &want).await? else {
                return Err(cut("the object wasn't returned", values.len()));
            };
            let found = chunk.attrs.keys().find_map(|k| {
                let (b, opt) = k.split_once(';')?;
                (b.eq_ignore_ascii_case(&base_attr)
                    && opt.to_ascii_lowercase().starts_with("range="))
                .then(|| k.clone())
            });
            let Some(key) = found else {
                return Err(cut("the reply has no range", values.len()));
            };
            if let Some(v) = chunk.attrs.get(&key) {
                values.extend(v.iter().cloned());
            }
            match range_bound(&key) {
                Some(Bound::Last) => break,
                Some(Bound::Upto(next)) if next > high => high = next,
                Some(Bound::Upto(_)) => {
                    return Err(cut("the reply's range didn't move on", values.len()))
                }
                None => return Err(cut("the reply's range can't be read", values.len())),
            }
        }
        entry
            .attrs
            .entry(base_attr)
            .or_default()
            .append(&mut values);
    }
    Ok(searches)
}

/// Whether `entry` has an attribute cut short by ranged retrieval.
pub(super) fn is_ranged(entry: &SearchEntry) -> bool {
    entry.attrs.keys().any(|k| {
        k.split_once(';')
            .is_some_and(|(_, opt)| opt.to_ascii_lowercase().starts_with("range="))
    })
}

/// Where a ranged reply ends.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Bound {
    /// `low-*`: the last values.
    Last,
    /// `low-high`: more after `high`.
    Upto(usize),
}

/// The end of `attr;range=low-high` or `attr;range=low-*`; `None` when it
/// can't be read.
pub(super) fn range_bound(key: &str) -> Option<Bound> {
    let opt = key.split(';').nth(1)?;
    let (name, spec) = opt.split_once('=')?;
    if !name.eq_ignore_ascii_case("range") {
        return None;
    }
    let (low, high) = spec.split_once('-')?;
    low.parse::<usize>().ok()?;
    if high == "*" {
        Some(Bound::Last)
    } else {
        high.parse().ok().map(Bound::Upto)
    }
}

/// The high bound of `attr;range=low-high`; `None` for `low-*`.
#[cfg(test)]
pub(super) fn range_high(key: &str) -> Option<usize> {
    match range_bound(key)? {
        Bound::Upto(high) => Some(high),
        Bound::Last => None,
    }
}

/// Why the pool didn't complete an entry.
#[derive(Debug)]
pub(super) enum Failed {
    /// The pool has no connection: the entry comes back, to be completed
    /// on the stream's own connection.
    NoConnection(SearchEntry),
    /// A search failed: the chunk fails.
    Search(String),
}

/// An entry completed: the entry, the searches it took and how long.
pub(super) type Done = Result<(SearchEntry, u64, Duration), Failed>;

struct Job {
    entry: SearchEntry,
    reply: oneshot::Sender<Done>,
}

/// Workers, each opening a connection the first time it has an entry to
/// complete (most domains have few groups over 1,500 members), and a new
/// one after a failure. When a connection can't be opened the pool stops
/// trying: from then on each entry comes back to its stream, which
/// completes it on its own connection, and the log says so once.
pub(super) struct Pool {
    tx: Option<mpsc::Sender<Job>>,
    workers: Vec<tokio::task::JoinHandle<()>>,
    #[cfg_attr(not(test), allow(dead_code))]
    down: Arc<AtomicBool>,
}

impl Pool {
    pub(super) fn start(
        workers: usize,
        open: Opener,
        log: Option<std::sync::mpsc::Sender<super::Msg>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<Job>(workers.max(1) * 4);
        let rx = Arc::new(Mutex::new(rx));
        let down = Arc::new(AtomicBool::new(false));
        let log = Arc::new(std::sync::Mutex::new(log));
        let workers = (0..workers.max(1))
            .map(|_| {
                let (rx, open, down, log) = (rx.clone(), open.clone(), down.clone(), log.clone());
                tokio::spawn(async move {
                    let mut conn: Option<Box<dyn RangedConn>> = None;
                    loop {
                        let job = { rx.lock().await.recv().await };
                        let Some(Job { mut entry, reply }) = job else {
                            break;
                        };
                        if down.load(Ordering::Relaxed) {
                            let _ = reply.send(Err(Failed::NoConnection(entry)));
                            continue;
                        }
                        let started = Instant::now();
                        if conn.is_none() {
                            match open().await {
                                Ok(c) => conn = Some(c),
                                Err(e) => {
                                    if !down.swap(true, Ordering::Relaxed) {
                                        // Said once, by the first to see it.
                                        if let Some(tx) = log.lock().ok().and_then(|mut l| l.take())
                                        {
                                            let _ = tx.send(super::Msg::Log(format!(
                                                "[read] the members of large groups are read on \
                                                 each stream's own connection: another \
                                                 connection could not be opened ({})",
                                                crate::one_line(&e)
                                            )));
                                        }
                                    }
                                    let _ = reply.send(Err(Failed::NoConnection(entry)));
                                    continue;
                                }
                            }
                        }
                        let Some(c) = conn.as_mut() else { continue };
                        match complete(c.as_mut(), &mut entry).await {
                            Ok(n) => {
                                let _ = reply.send(Ok((entry, n, started.elapsed())));
                            }
                            Err(e) => {
                                // A new connection for the next one.
                                if let Some(c) = conn.take() {
                                    c.close().await;
                                }
                                let _ = reply.send(Err(Failed::Search(e)));
                            }
                        }
                    }
                    if let Some(c) = conn {
                        c.close().await;
                    }
                })
            })
            .collect();
        Self {
            tx: Some(tx),
            workers,
            down,
        }
    }

    /// Whether it has stopped opening connections.
    #[cfg(test)]
    pub(super) fn is_down(&self) -> bool {
        self.down.load(Ordering::Relaxed)
    }

    /// Hands `entry` to a worker; the answer comes on the receiver.
    pub(super) async fn submit(&self, entry: SearchEntry) -> oneshot::Receiver<Done> {
        let (reply, rx) = oneshot::channel();
        let job = Job { entry, reply };
        match &self.tx {
            Some(tx) => {
                if let Err(mpsc::error::SendError(job)) = tx.send(job).await {
                    let _ = job.reply.send(Err(Failed::NoConnection(job.entry)));
                }
            }
            None => {
                let _ = job.reply.send(Err(Failed::NoConnection(job.entry)));
            }
        }
        rx
    }

    /// Lets the workers finish and end their connections.
    pub(super) async fn close(mut self) {
        drop(self.tx.take());
        for w in std::mem::take(&mut self.workers) {
            let _ = w.await;
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        for w in &self.workers {
            w.abort();
        }
    }
}
