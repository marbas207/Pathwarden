use super::*;

fn pass(s: &str) -> SecretString {
    SecretString::from(s.to_string())
}

/// For each key file: how many scrypts are running on it, and the most
/// that ran at once. (Another test forgetting opened keys can make a
/// later reader open it again, but never at the same time.)
type Scrypts = HashMap<[u8; 32], (usize, usize)>;

fn scrypts() -> &'static Mutex<Scrypts> {
    static RUNS: OnceLock<Mutex<Scrypts>> = OnceLock::new();
    RUNS.get_or_init(Default::default)
}

pub(super) struct Running([u8; 32]);

impl Drop for Running {
    fn drop(&mut self) {
        scrypts().lock().unwrap().entry(self.0).or_default().0 -= 1;
    }
}

pub(super) fn scrypt_started(key_file: [u8; 32]) -> Running {
    let mut runs = scrypts().lock().unwrap();
    let (now, most) = runs.entry(key_file).or_default();
    *now += 1;
    *most = (*most).max(*now);
    Running(key_file)
}

#[test]
fn simultaneous_readers_open_the_key_once() {
    let dir = std::env::temp_dir().join(format!("pathwarden-key-once-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(MARKER), Marker::new().to_bytes()).unwrap();
    // Made here rather than with `new_key`, which keeps the key open.
    let p = pass("correct horse battery staple");
    let mut r = age::scrypt::Recipient::new(p.clone());
    r.set_work_factor(WORK_FACTOR);
    let id = Identity::generate();
    let bytes = age::encrypt(&r, id.to_string().expose_secret().as_bytes()).unwrap();
    std::fs::write(dir.join(KEY_FILE), &bytes).unwrap();
    give_passphrase(&dir, p);
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let dir = dir.clone();
            std::thread::spawn(move || key_for(&dir).unwrap())
        })
        .collect();
    for r in readers {
        assert_eq!(r.join().unwrap().to_public(), id.to_public());
    }
    assert_eq!(
        scrypts().lock().unwrap().get(&digest(&bytes)),
        Some(&(0, 1))
    );
    given()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&keystore::history_key(&dir));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_key_opens_with_its_passphrase_only() {
    let (id, bytes) = new_key(&pass("correct horse battery")).unwrap();
    // Cached on creation; opening again checks the passphrase anyway.
    let again = open_key(&bytes, &pass("correct horse battery"), Source::Given).unwrap();
    assert_eq!(id.to_public().to_string(), again.to_public().to_string());
    assert_eq!(
        open_key(&bytes, &pass("wrong horse battery"), Source::Env)
            .err()
            .unwrap(),
        CryptError::WrongPassphrase(Source::Env)
    );
    assert_eq!(
        CryptError::WrongPassphrase(Source::Env)
            .to_string()
            .split(" (")
            .next(),
        Some("That passphrase doesn't open this history")
    );
    let sealed = seal(&id, b"{\"a\": 1}").unwrap();
    assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
    assert_eq!(open(&again, &sealed, "x").unwrap(), b"{\"a\": 1}");
    // Another key can't open it.
    let (other, _) = new_key(&pass("correct horse battery")).unwrap();
    assert!(open(&other, &sealed, "x").is_err());
    // Not an age file at all.
    assert!(matches!(
        open_key(b"{}", &pass("correct horse battery"), Source::Given),
        Err(CryptError::Damaged(_))
    ));
}

/// A key file asking for more scrypt work than [`MAX_WORK_FACTOR`]
/// is refused before any of it is done (gap 22): a hostile one
/// must not cost gigabytes and tens of seconds. Its stanza says 2^25.
#[test]
fn a_key_file_asking_too_much_work_is_refused() {
    let p = pass("correct horse battery staple");
    let mut r = age::scrypt::Recipient::new(p.clone());
    r.set_work_factor(WORK_FACTOR);
    let bytes = age::encrypt(
        &r,
        Identity::generate().to_string().expose_secret().as_bytes(),
    )
    .unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let stanza = text.lines().find(|l| l.starts_with("-> scrypt ")).unwrap();
    assert!(stanza.ends_with(" 18"), "{stanza}");
    let hostile = format!("{} 25", stanza.strip_suffix(" 18").unwrap());
    let mut planted = bytes.clone();
    let at = text.find(stanza).unwrap();
    planted.splice(at..at + stanza.len(), hostile.bytes());
    let start = std::time::Instant::now();
    match open_key(&planted, &p, Source::Given) {
        Err(CryptError::Damaged(why)) => {
            assert!(
                why.contains("more work than Pathwarden allows (2^25)"),
                "{why}"
            )
        }
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("opened"),
    }
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    // The file as made opens.
    assert!(open_key(&bytes, &p, Source::Given).is_ok());
}

/// A key file with less scrypt work than Pathwarden writes is refused
/// before any scrypt runs: someone with the passphrase could otherwise
/// make offline guessing cheap for every reader of the history.
#[test]
fn a_key_file_asking_too_little_work_is_refused() {
    let p = pass("correct horse battery staple");
    let mut r = age::scrypt::Recipient::new(p.clone());
    r.set_work_factor(10);
    let bytes = age::encrypt(
        &r,
        Identity::generate().to_string().expose_secret().as_bytes(),
    )
    .unwrap();
    assert_eq!(scrypt_work_factor(&bytes), Some(10));
    match open_key(&bytes, &p, Source::Given) {
        Err(CryptError::Damaged(why)) => assert!(
            why.contains("less work than Pathwarden requires (2^10, at least 2^18)"),
            "{why}"
        ),
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("opened"),
    }
    assert!(!scrypts().lock().unwrap().contains_key(&digest(&bytes)));
    let (_, made) = new_key(&p).unwrap();
    assert_eq!(scrypt_work_factor(&made), Some(WORK_FACTOR));
}

/// A key file copied from history B into history A doesn't open A with
/// B's key, though this process opened B: only A's own passphrase
/// opens A. Another folder whose own passphrase is B's reuses the key
/// without another scrypt. A history pinned to its old key isn't
/// offered B's passphrase either.
#[test]
fn a_key_opened_for_one_history_never_opens_another() {
    let root = std::env::temp_dir().join(format!("pathwarden-key-bound-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (a, b, c) = (root.join("a"), root.join("b"), root.join("c"));
    let (pa, pb) = (pass("history a passphrase"), pass("history b passphrase"));
    let mut a_key = Vec::new();
    for (dir, p) in [(&a, &pa), (&b, &pb)] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(MARKER), Marker::new().to_bytes()).unwrap();
        let (_, bytes) = new_key(p).unwrap();
        std::fs::write(dir.join(KEY_FILE), &bytes).unwrap();
        if dir == &a {
            a_key = bytes;
        }
        give_passphrase(dir, p.clone());
    }
    let key_b = key_for(&b).unwrap();
    // B's key file in A: A's passphrase doesn't open it.
    let b_file = std::fs::read(b.join(KEY_FILE)).unwrap();
    std::fs::write(a.join(KEY_FILE), &b_file).unwrap();
    match key_for(&a) {
        Err(e) => assert!(
            matches!(
                e.downcast_ref::<CryptError>(),
                Some(CryptError::WrongPassphrase(Source::Given))
            ),
            "{e:#}"
        ),
        Ok(_) => panic!("history A opened with history B's key"),
    }
    // Nor without a passphrase of its own.
    given()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&keystore::history_key(&a));
    if keystore::lookup(&a).unwrap().is_none() {
        assert!(key_for(&a).is_err());
    }
    // A pinned to its old key: B's passphrase isn't offered for it.
    std::fs::create_dir_all(a.join(".git")).unwrap();
    std::fs::write(
        a.join(".git").join("pathwarden-encrypted"),
        format!("{}\n", digest_hex(&a_key)),
    )
    .unwrap();
    give_passphrase(&a, pa.clone());
    assert!(
        matches!(known_passphrase(&a).unwrap(), Known::Wrong(Source::Given)),
        "B's passphrase was offered for A"
    );
    // Another folder of history B, with B's passphrase: the same key,
    // no second scrypt.
    std::fs::create_dir_all(&c).unwrap();
    std::fs::write(c.join(MARKER), Marker::new().to_bytes()).unwrap();
    std::fs::write(c.join(KEY_FILE), &b_file).unwrap();
    give_passphrase(&c, pb.clone());
    let before = scrypts().lock().unwrap().get(&digest(&b_file)).copied();
    let key_c = key_for(&c).unwrap();
    assert_eq!(key_c.to_public(), key_b.to_public());
    assert_eq!(
        scrypts().lock().unwrap().get(&digest(&b_file)).copied(),
        before
    );
    for dir in [&a, &b, &c] {
        given()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&keystore::history_key(dir));
    }
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn short_passphrases_are_refused() {
    assert!(check_passphrase(&pass("short")).is_err());
    assert!(new_key(&pass("eleven char")).is_err());
    assert!(check_passphrase(&pass("twelve chars")).is_ok());
    assert!(check_passphrase(&pass(&"x".repeat(MAX_PASSPHRASE + 1))).is_err());
}

/// The work factor's cost, for docs/running.md: one scrypt to open the
/// key, then each file. Run with `--ignored --nocapture`.
#[test]
#[ignore]
fn measure_the_work_factor() {
    let p = pass("correct horse battery staple");
    let t = std::time::Instant::now();
    let (_, bytes) = new_key(&p).unwrap();
    let made = t.elapsed();
    let t = std::time::Instant::now();
    let id = open_key(&bytes, &p, Source::Given).unwrap();
    let unlocked = t.elapsed();
    let point = vec![b'x'; 4 * 1024];
    let t = std::time::Instant::now();
    for _ in 0..500 {
        let s = seal(&id, &point).unwrap();
        open(&id, &s, "x").unwrap();
    }
    let files = t.elapsed();
    for log_n in [16u8, 17, 18, 19, 20] {
        let mut r = age::scrypt::Recipient::new(p.clone());
        r.set_work_factor(log_n);
        let t = std::time::Instant::now();
        age::encrypt(&r, b"x").unwrap();
        eprintln!("scrypt 2^{log_n}: {:?}", t.elapsed());
    }
    eprintln!(
        "work factor 2^{WORK_FACTOR}: new key {made:?}, open {unlocked:?}; 500 files of 4 KiB \
             sealed and opened: {files:?}"
    );
}
