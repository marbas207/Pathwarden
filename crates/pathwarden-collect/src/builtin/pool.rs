//! Worker pools for SYSVOL: the GPO folders and logon
//! scripts are read by several workers at once, each item once, in any
//! order; the results come back in the items' order, so what is made of
//! them is the same whatever the workers did.

use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Workers reading SYSVOL.
pub(crate) const SYSVOL_WORKERS: usize = 8;

/// What a pool read: each item's result in the items' order (`None`: not
/// read, its worker ran out of time or could not connect).
#[derive(Debug)]
pub(crate) struct Pooled<R> {
    pub results: Vec<Option<R>>,
    /// Items were left when the time was up.
    pub timed_out: bool,
}

impl<R> Pooled<R> {
    fn new(n: usize) -> Self {
        Self {
            results: (0..n).map(|_| None).collect(),
            timed_out: false,
        }
    }
}

/// `read` on each of `items`, by `workers` threads (blocking calls: Windows'
/// SMB client), none started once `stop` says so (the time is up). `done`
/// is called after each item, one call at a time, with how many are done:
/// it only goes up.
// Used by the Windows SYSVOL reads (and tests) only.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn blocking<T: Sync, R: Send>(
    items: &[T],
    workers: usize,
    stop: impl Fn() -> bool + Sync,
    read: impl Fn(&T) -> R + Sync,
    done: impl Fn(usize) + Sync,
) -> Pooled<R> {
    let next = AtomicUsize::new(0);
    let out = Mutex::new((Pooled::new(items.len()), 0usize));
    std::thread::scope(|s| {
        for _ in 0..workers.clamp(1, items.len().max(1)) {
            s.spawn(|| loop {
                if stop() {
                    if next.load(Ordering::SeqCst) < items.len() {
                        if let Ok(mut o) = out.lock() {
                            o.0.timed_out = true;
                        }
                    }
                    return;
                }
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(item) = items.get(i) else { return };
                let r = read(item);
                if let Ok(mut o) = out.lock() {
                    o.0.results[i] = Some(r);
                    o.1 += 1;
                    done(o.1);
                }
            });
        }
    });
    out.into_inner().unwrap_or_else(|e| e.into_inner()).0
}

/// `read` on each of `items`, by `workers` futures polled together in this
/// task, each with a connection of its own from `open` (worker 1 may be
/// given one, `first`), none started once `stop` says so (the time is up).
/// A worker that can't connect stops, and the others read its share. Also
/// returns the first error connecting.
pub(crate) async fn concurrent<T, R, C>(
    items: &[T],
    workers: usize,
    stop: impl Fn() -> bool + Sync,
    first: Option<C>,
    open: impl AsyncFn() -> Result<C, String>,
    read: impl AsyncFn(&mut C, &T) -> R,
    done: impl Fn(usize),
) -> (Pooled<R>, Option<String>) {
    let next = Cell::new(0usize);
    let finished = Cell::new(0usize);
    let out = RefCell::new(Pooled::new(items.len()));
    let failed: RefCell<Option<String>> = RefCell::new(None);
    let first = RefCell::new(first);
    let worker = |w: usize| {
        let (next, finished, out, failed, first) = (&next, &finished, &out, &failed, &first);
        let (open, read, done, stop) = (&open, &read, &done, &stop);
        async move {
            let mut conn = None;
            loop {
                if stop() {
                    if next.get() < items.len() {
                        out.borrow_mut().timed_out = true;
                    }
                    return;
                }
                if next.get() >= items.len() {
                    return;
                }
                if conn.is_none() {
                    let given = if w == 0 {
                        first.borrow_mut().take()
                    } else {
                        None
                    };
                    conn = match given {
                        Some(c) => Some(c),
                        None => match open().await {
                            Ok(c) => Some(c),
                            Err(e) => {
                                failed.borrow_mut().get_or_insert(e);
                                return;
                            }
                        },
                    };
                }
                let i = next.get();
                next.set(i + 1);
                let Some(item) = items.get(i) else { return };
                let Some(c) = conn.as_mut() else { return };
                let r = read(c, item).await;
                out.borrow_mut().results[i] = Some(r);
                finished.set(finished.get() + 1);
                done(finished.get());
            }
        }
    };
    let n = workers.clamp(1, items.len().max(1));
    let runs: Vec<super::streams::LocalFut<'_, ()>> = (0..n)
        .map(|w| Box::pin(worker(w)) as super::streams::LocalFut<'_, ()>)
        .collect();
    super::streams::join_all(runs).await;
    (out.into_inner(), failed.into_inner())
}
