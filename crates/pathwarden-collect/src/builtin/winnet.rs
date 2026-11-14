//! Windows' own calls for [`super::winhosts::HostApi`]: NetAPI, Remote
//! Registry, LSA lookups and UNC file reads against a remote computer,
//! signed in as the current logon session (no password). Each call blocks;
//! the caller runs them on their own threads with a time limit.
//!
//! Every name passed here has been checked to be a plain DNS name
//! ([`super::winhosts::valid_host`]) from the directory's `dNSHostName`.

#![allow(unsafe_code)]

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{LocalFree, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NetApiBufferFree, NetLocalGroupGetMembers, NetUserModalsGet, NetWkstaUserEnum,
    LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH, USER_MODALS_INFO_2, WKSTA_USER_INFO_1,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{LookupAccountSidW, PSID, SID_NAME_USE};
use windows_sys::Win32::Storage::FileSystem::{NetSessionEnum, SESSION_INFO_10};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegConnectRegistryW, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW, HKEY,
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_WOW64_64KEY,
};

use dcerpc::rrp::RegValue;
use smb2_client::DirEntry;

use super::winhosts::{code_words, Code, HostApi, HostRegistry, HostShare, HKLM};

/// ERROR_INSUFFICIENT_BUFFER.
const INSUFFICIENT_BUFFER: u32 = 122;

/// Windows' calls, as the signed-in account.
pub(crate) struct WinNet;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `\\HOST`, as the NetAPI and registry calls take it.
fn unc(host: &str) -> Vec<u16> {
    wide(&format!("\\\\{host}"))
}

/// A NUL-terminated wide string (may be null).
///
/// # Safety
/// `p` is null or points to a NUL-terminated UTF-16 string.
unsafe fn from_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

/// A SID as `S-1-...`.
///
/// # Safety
/// `sid` is null or a valid SID.
unsafe fn sid_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut s: *mut u16 = std::ptr::null_mut();
    if ConvertSidToStringSidW(sid, &mut s) == 0 || s.is_null() {
        return None;
    }
    let out = from_wide(s);
    LocalFree(s as _);
    Some(out)
}

/// Calls a NetAPI enumeration until it has everything, giving each
/// returned buffer to `take` (entries read, buffer) before freeing it.
fn enumerate(
    call: impl FnMut(*mut *mut u8, *mut u32, *mut u32) -> u32,
    take: impl FnMut(u32, *const u8),
) -> Result<(), Code> {
    // SAFETY: a buffer the NetAPI allocated, freed once.
    enumerate_with(call, take, |buf| unsafe {
        NetApiBufferFree(buf as _);
    })
}

/// [`enumerate`], freeing each buffer with `free` (a fake's in tests).
/// Pages while the call says ERROR_MORE_DATA and returns entries; each
/// non-null buffer is freed exactly once, an error's too.
fn enumerate_with(
    mut call: impl FnMut(*mut *mut u8, *mut u32, *mut u32) -> u32,
    mut take: impl FnMut(u32, *const u8),
    mut free: impl FnMut(*mut u8),
) -> Result<(), Code> {
    loop {
        let mut buf: *mut u8 = std::ptr::null_mut();
        let (mut read, mut total) = (0u32, 0u32);
        let rc = call(&mut buf, &mut read, &mut total);
        if !buf.is_null() {
            if rc == 0 || rc == ERROR_MORE_DATA {
                take(read, buf);
            }
            free(buf);
        }
        match rc {
            0 => return Ok(()),
            // Nothing more came back: stop rather than loop.
            ERROR_MORE_DATA if read > 0 => continue,
            ERROR_MORE_DATA => return Ok(()),
            e => return Err(e),
        }
    }
}

impl HostApi for WinNet {
    fn reachable(&self, host: &str, timeout: Duration) -> bool {
        let started = Instant::now();
        let Ok(addrs) = (host, 445).to_socket_addrs() else {
            return false;
        };
        for a in addrs {
            let left = timeout.saturating_sub(started.elapsed());
            if left.is_zero() {
                return false;
            }
            if TcpStream::connect_timeout(&a, left).is_ok() {
                return true;
            }
        }
        false
    }

    fn net_sessions(&self, host: &str) -> Result<Vec<String>, Code> {
        let server = unc(host);
        let mut resume = 0u32;
        let mut out = Vec::new();
        enumerate(
            // SAFETY: `server` is NUL-terminated and outlives the call; the
            // out pointers are valid.
            |buf, read, total| unsafe {
                NetSessionEnum(
                    server.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    10,
                    buf,
                    MAX_PREFERRED_LENGTH,
                    read,
                    total,
                    &mut resume,
                )
            },
            |n, buf| {
                // SAFETY: level 10 returns `n` SESSION_INFO_10 entries.
                let items = unsafe {
                    std::slice::from_raw_parts(buf as *const SESSION_INFO_10, n as usize)
                };
                for i in items {
                    out.push(unsafe { from_wide(i.sesi10_username) });
                }
            },
        )?;
        Ok(out)
    }

    fn logged_on(&self, host: &str) -> Result<Vec<(String, String)>, Code> {
        let server = unc(host);
        let mut resume = 0u32;
        let mut out = Vec::new();
        enumerate(
            // SAFETY: as in `net_sessions`.
            |buf, read, total| unsafe {
                NetWkstaUserEnum(
                    server.as_ptr(),
                    1,
                    buf,
                    MAX_PREFERRED_LENGTH,
                    read,
                    total,
                    &mut resume,
                )
            },
            |n, buf| {
                // SAFETY: level 1 returns `n` WKSTA_USER_INFO_1 entries.
                let items = unsafe {
                    std::slice::from_raw_parts(buf as *const WKSTA_USER_INFO_1, n as usize)
                };
                for i in items {
                    out.push(unsafe {
                        (from_wide(i.wkui1_logon_domain), from_wide(i.wkui1_username))
                    });
                }
            },
        )?;
        Ok(out)
    }

    fn registry_users(&self, host: &str) -> Result<Vec<String>, Code> {
        let server = unc(host);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `server` is NUL-terminated; `key` receives a handle that
        // is closed below.
        let rc = unsafe { RegConnectRegistryW(server.as_ptr(), HKEY_USERS, &mut key) };
        if rc != 0 {
            return Err(rc);
        }
        let mut out = Vec::new();
        let mut name = vec![0u16; 512];
        let mut index = 0u32;
        let result = loop {
            let mut len = name.len() as u32;
            // SAFETY: `name` holds `len` characters; the other out
            // parameters are optional and null.
            let rc = unsafe {
                RegEnumKeyExW(
                    key,
                    index,
                    name.as_mut_ptr(),
                    &mut len,
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            match rc {
                0 => out.push(String::from_utf16_lossy(&name[..len as usize])),
                ERROR_NO_MORE_ITEMS => break Ok(out),
                // A longer name than a SID: not a user's key.
                ERROR_MORE_DATA => {}
                e => break Err(e),
            }
            index += 1;
        };
        // SAFETY: the handle RegConnectRegistryW opened.
        unsafe { RegCloseKey(key) };
        result
    }

    fn account_domain(&self, host: &str) -> Result<(String, String), Code> {
        let server = unc(host);
        let mut buf: *mut u8 = std::ptr::null_mut();
        // SAFETY: `server` is NUL-terminated; `buf` is freed below.
        let rc = unsafe { NetUserModalsGet(server.as_ptr(), 2, &mut buf) };
        if rc != 0 {
            if !buf.is_null() {
                unsafe { NetApiBufferFree(buf as _) };
            }
            return Err(rc);
        }
        if buf.is_null() {
            return Err(13); // ERROR_INVALID_DATA
        }
        // SAFETY: level 2 returns one USER_MODALS_INFO_2.
        let out = unsafe {
            let info = &*(buf as *const USER_MODALS_INFO_2);
            let name = from_wide(info.usrmod2_domain_name);
            let sid = sid_string(info.usrmod2_domain_id);
            NetApiBufferFree(buf as _);
            sid.map(|s| (name, s))
        };
        out.ok_or(13)
    }

    fn services(&self, host: &str) -> Result<Box<dyn HostRegistry>, Code> {
        let server = unc(host);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `server` is NUL-terminated; `key` receives a handle that
        // `WinRegistry` closes when dropped.
        let rc = unsafe { RegConnectRegistryW(server.as_ptr(), HKEY_LOCAL_MACHINE, &mut key) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Box::new(WinRegistry {
            keys: vec![Some(key)],
        }))
    }

    fn cifs_ticket(&self, host: &str) -> Result<(), String> {
        super::winkrb::cifs_ticket(host).map_err(|e| e.reason(host))
    }

    fn tasks(&self, host: &str) -> Result<Box<dyn HostShare>, Code> {
        Ok(Box::new(WinShare {
            root: format!(r"\\{host}\C$"),
        }))
    }

    fn alias_members(&self, host: &str, rid: u32) -> Result<Vec<String>, Code> {
        let name = alias_name(host, rid)?;
        let server = unc(host);
        let group = wide(&name);
        let mut resume = 0usize;
        let mut out = Vec::new();
        enumerate(
            // SAFETY: `server` and `group` are NUL-terminated and outlive
            // the call.
            |buf, read, total| unsafe {
                NetLocalGroupGetMembers(
                    server.as_ptr(),
                    group.as_ptr(),
                    // Level 0: SIDs only, all the module keeps; level 2
                    // would have the computer look up every member's name.
                    0,
                    buf,
                    MAX_PREFERRED_LENGTH,
                    read,
                    total,
                    &mut resume,
                )
            },
            |n, buf| {
                // SAFETY: level 0 returns `n` LOCALGROUP_MEMBERS_INFO_0
                // entries, each with a SID.
                let items = unsafe {
                    std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_0, n as usize)
                };
                for i in items {
                    if let Some(s) = unsafe { sid_string(i.lgrmi0_sid) } {
                        out.push(s);
                    }
                }
            },
        )?;
        Ok(out)
    }
}

/// Longest registry value read (a service's `ObjectName`, a task's `Id` or
/// `Hash`: a few hundred bytes at most). A larger one is not read.
const MAX_VALUE: u32 = 64 * 1024;
/// Longest key name the registry allows, plus its NUL.
const MAX_KEY_NAME: usize = 256;
/// FILE_ATTRIBUTE_DIRECTORY.
const ATTRIBUTE_DIRECTORY: u32 = 0x10;
/// FILE_FLAG_OPEN_REPARSE_POINT: a link is opened as itself, never
/// followed.
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// FILE_FLAG_BACKUP_SEMANTICS: needed to open a folder (no backup
/// privilege is used or asked for).
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// FILE_ATTRIBUTE_REPARSE_POINT.
const ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// A remote computer's HKLM (`RegConnectRegistryW`) and the keys opened
/// under it, by number ([`HKLM`] first). Every key is closed when it is
/// dropped.
struct WinRegistry {
    keys: Vec<Option<HKEY>>,
}

// SAFETY: registry handles may be used and closed from any thread; each is
// used by one thread at a time (the owner of this value).
unsafe impl Send for WinRegistry {}

impl WinRegistry {
    fn key(&self, n: usize) -> Result<HKEY, String> {
        self.keys
            .get(n)
            .copied()
            .flatten()
            .ok_or_else(|| "not an open key (rc=6)".to_string())
    }
}

impl HostRegistry for WinRegistry {
    fn open_key(&mut self, parent: usize, subkey: &str, access: u32) -> Result<usize, String> {
        let parent = self.key(parent)?;
        let name = wide(subkey);
        let mut key: HKEY = std::ptr::null_mut();
        // SAFETY: `parent` is open; `name` is NUL-terminated; `key` receives
        // a handle kept in `keys` and closed once. The 64-bit view: the
        // keys aren't redirected for a 64-bit process anyway.
        let rc =
            unsafe { RegOpenKeyExW(parent, name.as_ptr(), 0, access | KEY_WOW64_64KEY, &mut key) };
        if rc != 0 {
            return Err(format!("RegOpenKeyExW('{subkey}') failed (rc={rc})"));
        }
        self.keys.push(Some(key));
        Ok(self.keys.len() - 1)
    }

    fn enum_key(&mut self, key: usize, index: u32) -> Result<Option<String>, String> {
        let key = self.key(key)?;
        let mut name = vec![0u16; MAX_KEY_NAME];
        let mut len = name.len() as u32;
        // SAFETY: `name` holds `len` characters; the other out parameters
        // are optional and null.
        let rc = unsafe {
            RegEnumKeyExW(
                key,
                index,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        match rc {
            0 => Ok(Some(String::from_utf16_lossy(
                &name[..(len as usize).min(name.len())],
            ))),
            ERROR_NO_MORE_ITEMS => Ok(None),
            e => Err(format!("RegEnumKeyExW({index}) failed (rc={e})")),
        }
    }

    fn query(&mut self, key: usize, value: &str) -> Result<RegValue, String> {
        let key = self.key(key)?;
        let name = wide(value);
        let failed = |rc: u32| format!("RegQueryValueExW('{value}') failed (rc={rc})");
        let (mut ty, mut size) = (0u32, 0u32);
        // SAFETY: `name` is NUL-terminated; a null data pointer asks for the
        // type and size only.
        let rc = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null(),
                &mut ty,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if rc != 0 {
            return Err(failed(rc));
        }
        if size > MAX_VALUE {
            return Err(format!("{value} is larger than {MAX_VALUE} bytes"));
        }
        let mut data = vec![0u8; size as usize];
        let mut got = size;
        // SAFETY: `data` holds `got` bytes.
        let rc = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null(),
                &mut ty,
                data.as_mut_ptr(),
                &mut got,
            )
        };
        // ERROR_MORE_DATA: it grew in between; not read.
        if rc != 0 {
            return Err(failed(rc));
        }
        data.truncate((got as usize).min(data.len()));
        Ok(RegValue { ty, data })
    }

    fn close(&mut self, key: usize) {
        if key == HKLM {
            return;
        }
        if let Some(k) = self.keys.get_mut(key).and_then(Option::take) {
            // SAFETY: a handle RegOpenKeyExW opened, closed once.
            unsafe { RegCloseKey(k) };
        }
    }
}

impl Drop for WinRegistry {
    fn drop(&mut self) {
        for k in self.keys.iter_mut().filter_map(Option::take) {
            // SAFETY: handles this value opened, each closed once.
            unsafe { RegCloseKey(k) };
        }
    }
}

/// An I/O error in words, by its Win32 code where it has one.
fn io_words(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => code_words(code as u32),
        None => e.to_string().chars().take(200).collect(),
    }
}

/// A remote computer's `C$`, read by UNC path through Windows' SMB client.
struct WinShare {
    /// `\\HOST\C$`.
    root: String,
}

impl WinShare {
    fn path(&self, rel: &str) -> String {
        format!(r"{}\{rel}", self.root)
    }
}

impl HostShare for WinShare {
    fn list(&mut self, path: &str, max: usize) -> Result<(Vec<DirEntry>, bool), String> {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        // The folder itself, opened as what it is (a link is opened, not
        // followed): one swapped for a junction or symbolic link since it
        // was listed is refused.
        let folder = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
            .open(self.path(path))
            .map_err(|e| io_words(&e))?;
        let attributes = folder
            .metadata()
            .map_err(|e| io_words(&e))?
            .file_attributes();
        if attributes & ATTRIBUTE_REPARSE_POINT != 0 || attributes & ATTRIBUTE_DIRECTORY == 0 {
            return Err(format!(
                "{path} is a link or not a folder, so it isn't followed"
            ));
        }
        let entries = std::fs::read_dir(self.path(path)).map_err(|e| io_words(&e))?;
        let mut out = Vec::new();
        for e in entries {
            let e = e.map_err(|e| io_words(&e))?;
            if out.len() >= max {
                return Ok((out, true));
            }
            // From the listing itself: a link is not followed.
            let meta = e.metadata().map_err(|e| io_words(&e))?;
            let attributes = meta.file_attributes();
            out.push(DirEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir: attributes & ATTRIBUTE_DIRECTORY != 0,
                size: meta.len(),
                attributes,
            });
        }
        Ok((out, false))
    }

    fn read(&mut self, path: &str, max: usize) -> Result<(Vec<u8>, bool), String> {
        use std::io::Read;
        use std::os::windows::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(self.path(path))
            .map_err(|e| io_words(&e))?;
        let mut bytes = Vec::new();
        file.take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_words(&e))?;
        let more = bytes.len() > max;
        bytes.truncate(max);
        Ok((bytes, more))
    }
}

/// The name, on `host`, of the BUILTIN alias `S-1-5-32-<rid>` (localized,
/// so it is looked up from the SID there rather than assumed).
fn alias_name(host: &str, rid: u32) -> Result<String, Code> {
    let text = wide(&format!("S-1-5-32-{rid}"));
    let mut sid: PSID = std::ptr::null_mut();
    // SAFETY: `text` is NUL-terminated; `sid` is LocalFree'd below.
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32);
    }
    let system = wide(host);
    let mut name = vec![0u16; 256];
    let mut domain = vec![0u16; 256];
    let result = loop {
        let (mut n, mut d) = (name.len() as u32, domain.len() as u32);
        let mut usage: SID_NAME_USE = 0;
        // SAFETY: the buffers hold `n` and `d` characters; `sid` is valid.
        let ok = unsafe {
            LookupAccountSidW(
                system.as_ptr(),
                sid,
                name.as_mut_ptr(),
                &mut n,
                domain.as_mut_ptr(),
                &mut d,
                &mut usage,
            )
        };
        if ok != 0 {
            break Ok(String::from_utf16_lossy(&name[..n as usize]));
        }
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32;
        if e == INSUFFICIENT_BUFFER && (n as usize > name.len() || d as usize > domain.len()) {
            name.resize(n as usize, 0);
            domain.resize(d as usize, 0);
            continue;
        }
        break Err(e);
    };
    // SAFETY: the SID ConvertStringSidToSidW allocated.
    unsafe { LocalFree(sid as _) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// A paged enumeration through a fake: per call a return code and the
    /// entries (u32) of a buffer the fake owns until it is freed. Returns
    /// the result, the entries taken, the calls made and the buffers freed.
    fn run(script: &[(u32, Vec<u32>)]) -> (Result<(), Code>, Vec<u32>, usize, usize) {
        let live: RefCell<HashMap<usize, Box<[u32]>>> = RefCell::default();
        let freed = RefCell::new(0usize);
        let mut calls = 0usize;
        let mut got = Vec::new();
        let r = enumerate_with(
            |buf, read, total| {
                let (rc, items) = script[calls].clone();
                calls += 1;
                let n = items.len() as u32;
                if !items.is_empty() {
                    let mut b: Box<[u32]> = items.into_boxed_slice();
                    let p = b.as_mut_ptr() as *mut u8;
                    live.borrow_mut().insert(p as usize, b);
                    // SAFETY: the out pointers enumerate_with passes.
                    unsafe {
                        *buf = p;
                        *read = n;
                        *total = n;
                    }
                }
                rc
            },
            |n, buf| {
                // SAFETY: `n` u32 entries the fake wrote.
                let items = unsafe { std::slice::from_raw_parts(buf as *const u32, n as usize) };
                got.extend_from_slice(items);
            },
            |buf| {
                assert!(
                    live.borrow_mut().remove(&(buf as usize)).is_some(),
                    "freed twice"
                );
                *freed.borrow_mut() += 1;
            },
        );
        assert!(live.borrow().is_empty(), "a buffer wasn't freed");
        let freed = *freed.borrow();
        (r, got, calls, freed)
    }

    #[test]
    fn pages_are_read_until_the_last_and_each_freed_once() {
        // Three pages.
        assert_eq!(
            run(&[
                (ERROR_MORE_DATA, vec![1, 2]),
                (ERROR_MORE_DATA, vec![3]),
                (0, vec![4]),
            ]),
            (Ok(()), vec![1, 2, 3, 4], 3, 3)
        );
        // ERROR_MORE_DATA with nothing in it: stop rather than loop.
        assert_eq!(
            run(&[(ERROR_MORE_DATA, vec![7]), (ERROR_MORE_DATA, vec![])]),
            (Ok(()), vec![7], 2, 1)
        );
        // An error on a later page: the error, and its buffer freed unread.
        assert_eq!(
            run(&[(ERROR_MORE_DATA, vec![1]), (5, vec![9])]),
            (Err(5), vec![1], 2, 2)
        );
        // Nothing at all.
        assert_eq!(run(&[(0, vec![])]), (Ok(()), vec![], 1, 0));
    }
}
