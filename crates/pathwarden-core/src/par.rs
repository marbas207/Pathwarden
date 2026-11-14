//! A minimal parallel map over scoped threads, for the independent graph
//! searches (one per finding or plan step) that dominate large runs.

/// `items.iter().map(f).collect()`, spread over the available cores. Results
/// keep the order of `items`, so output does not depend on scheduling.
pub(crate) fn map<T, R, F>(items: &[T], f: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(items.len());
    if threads <= 1 {
        return items.iter().map(f).collect();
    }
    // Small chunks, handed out in order, balance uneven work (some searches
    // cover far more of the graph than others).
    let next = std::sync::atomic::AtomicUsize::new(0);
    let chunk = (items.len() / (threads * 8)).max(1);
    let mut parts: Vec<(usize, Vec<R>)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let start = next.fetch_add(chunk, std::sync::atomic::Ordering::Relaxed);
                        if start >= items.len() {
                            return done;
                        }
                        let end = (start + chunk).min(items.len());
                        done.push((start, items[start..end].iter().map(&f).collect()));
                    }
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("worker thread panicked"))
            .collect()
    });
    parts.sort_unstable_by_key(|(start, _)| *start);
    parts.into_iter().flat_map(|(_, rs)| rs).collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn keeps_order() {
        let items: Vec<u64> = (0..10_000).collect();
        let out = super::map(&items, |x| x * 2);
        assert_eq!(out, items.iter().map(|x| x * 2).collect::<Vec<_>>());
        assert!(super::map(&[] as &[u8], |x| *x).is_empty());
    }
}
