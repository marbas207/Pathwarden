//! Keeping files private to the account that runs Pathwarden: the UI's
//! workspace and browser launcher file, evidence signing keys, and
//! collections (a full map of the directory).
//!
//! - Windows: a protected DACL, with inheritance from the parent removed.
//!   The workspace grants full control to the current user and SYSTEM;
//!   collection output also to Administrators. Files and folders created
//!   inside a private folder inherit its DACL.
//! - Unix: mode 700 on folders, 600 on files.
//!
//! [`others_with_access`] reports who else can read or change a folder, so
//! callers can warn about an existing folder they did not create.

use std::io;
use std::path::Path;

/// Creates `dir` (which must not exist yet) private to this account. Fails if
/// it already exists, so nobody can prepare it in advance.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(dir)
    }
    #[cfg(windows)]
    {
        win::create_dir(dir, win::Grant::Owner)
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::create_dir(dir)
    }
}

/// Creates `dir` (which must not exist yet) for collection output: this
/// account, Administrators and SYSTEM on Windows (nothing inherited from
/// the parent), mode 700 on Unix. Fails if it already exists.
pub fn create_output_dir(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        win::create_dir(dir, win::Grant::OwnerAndAdministrators)
    }
    #[cfg(not(windows))]
    {
        create_private_dir(dir)
    }
}

/// Gives a collection file its own permissions, so it does not inherit
/// from the folder it is in: this account, Administrators and SYSTEM on
/// Windows (a protected DACL), mode 600 on Unix.
pub fn make_output_file_private(file: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(windows)]
    {
        win::set_protected(file, win::Grant::FileForOwnerAndAdministrators)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = file;
        Ok(())
    }
}

/// Gives a file this account's own permissions, as
/// [`make_output_file_private`], with read (only) for one more account by
/// SID on Windows (a scheduled task's gMSA reading its DPAPI-NG passphrase
/// file). Mode 600 on Unix, where `reader` is ignored.
pub fn make_file_private_for(file: &Path, reader: Option<&str>) -> io::Result<()> {
    #[cfg(windows)]
    {
        match reader {
            Some(sid) => win::set_protected(file, win::Grant::FileReadBy(sid.to_string())),
            None => win::set_protected(file, win::Grant::FileForOwnerAndAdministrators),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = reader;
        make_output_file_private(file)
    }
}

/// Windows: gives a file Administrators as its owner and an access list
/// of Administrators and SYSTEM (full control) and read (only) for one
/// account, by SID: a file an administrator writes for another account (a
/// gMSA's DPAPI-NG passphrase file), so that nobody but Administrators and
/// SYSTEM can change it, the administrator who wrote it included. Needs an
/// elevated administrator (owner `S-1-5-32-544`); fails otherwise. Mode
/// 600 on Unix, where `reader` is ignored.
pub fn make_file_admin_owned_for(file: &Path, reader: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        win::set_owner_administrators(file)?;
        win::set_protected(file, win::Grant::FileAdminsReadBy(reader.to_string()))
    }
    #[cfg(not(windows))]
    {
        let _ = reader;
        make_output_file_private(file)
    }
}

/// Who besides `me`, Administrators and SYSTEM owns or may change a file
/// ([`FileSecurity`]): the owner and every writer that is not one of those
/// three. Empty when the file is theirs alone.
pub fn untrusted_holders(sec: &FileSecurity, me: &str) -> Vec<String> {
    const ADMINS_AND_SYSTEM: [&str; 2] = ["S-1-5-32-544", "S-1-5-18"];
    let trusted = |s: &str| s == me || ADMINS_AND_SYSTEM.contains(&s);
    let mut out: Vec<String> = Vec::new();
    for s in std::iter::once(&sec.owner).chain(&sec.writers) {
        if !trusted(s) && !out.contains(s) {
            out.push(s.clone());
        }
    }
    out
}

/// Restricts an existing folder (and, on Windows, everything inside that
/// inherits from it) to this account.
pub fn make_private(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(windows)]
    {
        win::set_protected(dir, win::Grant::Owner)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        Ok(())
    }
}

/// The command that makes `dir` private by hand (for a warning).
pub fn private_hint(dir: &Path) -> String {
    #[cfg(windows)]
    {
        let user = win::current_user_sid().unwrap_or_else(|_| "%USERNAME%".into());
        let user = if user.starts_with("S-") {
            format!("*{user}")
        } else {
            user
        };
        format!(
            "icacls \"{}\" /inheritance:r /grant:r \"{user}:(OI)(CI)F\" \"*S-1-5-18:(OI)(CI)F\"",
            dir.display()
        )
    }
    #[cfg(not(windows))]
    {
        format!("chmod 700 '{}'", dir.display())
    }
}

/// Someone besides this account who can read or change a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Access {
    /// An account name (`BUILTIN\Users`) or a description (`every user`).
    pub who: String,
    /// Can read it (on Windows: list a folder or read a file's data).
    pub read: bool,
    /// Can change it (create, delete or replace files, or its permissions).
    pub write: bool,
}

/// Who besides this account (and SYSTEM and Administrators on Windows, root
/// on Unix) can read or change `path`. Empty when it is private, or when
/// its permissions can't be read. On Windows this includes access that only
/// files created inside would inherit.
pub fn others_with_access(path: &Path) -> Vec<Access> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::metadata(path) else {
            return Vec::new();
        };
        let mode = meta.permissions().mode();
        [("its group", 0o040, 0o020), ("every user", 0o004, 0o002)]
            .into_iter()
            .filter(|(_, r, w)| mode & (r | w) != 0)
            .map(|(who, r, w)| Access {
                who: who.to_string(),
                read: mode & r != 0,
                write: mode & w != 0,
            })
            .collect()
    }
    #[cfg(windows)]
    {
        win::others_with_access(path).unwrap_or_default()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Vec::new()
    }
}

/// Whether `dir` is a folder (not a link) owned by this account that only
/// this account (and SYSTEM and Administrators on Windows) can open. On
/// Windows an elevated process's folders are owned by Administrators, which
/// counts as this account there. Unlike
/// [`others_with_access`], it fails closed: permissions that can't be read,
/// or an access entry it doesn't understand, mean no.
pub fn is_private_dir(dir: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if !meta.is_dir() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and can't fail.
        let me = unsafe { libc::geteuid() };
        meta.uid() == me && meta.permissions().mode() & 0o077 == 0
    }
    #[cfg(windows)]
    {
        win::is_private(dir)
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// The SID of the account this process runs as (`S-1-5-...`).
#[cfg(windows)]
pub fn current_user_sid() -> io::Result<String> {
    win::current_user_sid()
}

/// The SID of account `name` (`DOMAIN\name`, `name$` for a gMSA).
#[cfg(windows)]
pub fn account_sid(name: &str) -> io::Result<String> {
    win::account_sid(name)
}

/// Who owns an open file and who may change it, read from its handle (so
/// it is the file that was opened, not one put in its place since).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileSecurity {
    /// The owner (`S-1-5-...`).
    pub owner: String,
    /// Every SID an allow entry of its DACL lets write, append, change its
    /// permissions or owner, or delete it. An entry of a kind not read here
    /// that may allow any of these counts as `"?"`; no DACL at all as
    /// Everyone (`S-1-1-0`).
    pub writers: Vec<String>,
}

/// [`FileSecurity`] of an open file. `None` when it can't be read, and
/// always on other systems.
pub fn file_security(f: &std::fs::File) -> Option<FileSecurity> {
    #[cfg(windows)]
    {
        win::file_security(f)
    }
    #[cfg(not(windows))]
    {
        let _ = f;
        None
    }
}

/// Who besides this account (and SYSTEM and Administrators on Windows, root
/// on Unix) can read `dir`: account names, or a description. Empty when the
/// folder is private, or when its permissions can't be read.
pub fn readable_by_others(dir: &Path) -> Vec<String> {
    others_with_access(dir)
        .into_iter()
        .filter(|a| a.read)
        .map(|a| a.who)
        .collect()
}

#[cfg(windows)]
mod win {
    //! The Win32 calls behind [`super`]. Each function owns what it
    //! allocates and frees it on every path.

    use std::ffi::OsStr;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, LocalFree, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorDacl,
        GetTokenInformation, LookupAccountNameW, LookupAccountSidW, TokenElevation, TokenUser,
        ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::Access;

    /// `ACCESS_ALLOWED_ACE_TYPE` (winnt.h).
    const ACCESS_ALLOWED: u8 = 0;
    /// `ACCESS_DENIED_ACE_TYPE` (winnt.h).
    const ACCESS_DENIED: u8 = 1;
    /// `FILE_READ_DATA` / `FILE_LIST_DIRECTORY`.
    const READ_DATA: u32 = 0x1;
    /// `FILE_WRITE_DATA` / `FILE_ADD_FILE`, `FILE_APPEND_DATA` /
    /// `FILE_ADD_SUBDIRECTORY`, `FILE_WRITE_EA`, `FILE_DELETE_CHILD`,
    /// `FILE_WRITE_ATTRIBUTES`, `DELETE`, `WRITE_DAC` and `WRITE_OWNER`:
    /// anything that changes what the folder or file holds, lets it be
    /// removed (and so replaced), or changes who can open it.
    const WRITE_ANY: u32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x1_0000 | 0x4_0000 | 0x8_0000;

    /// Accounts that may always read: SYSTEM, Administrators, CREATOR OWNER
    /// and OWNER RIGHTS (the last two stand for the owner, who is this
    /// user), and TrustedInstaller, which owns the system's own folders
    /// (System32, Program Files) and changes them only for Windows updates.
    const TRUSTED: &[&str] = &[
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-3-0",
        "S-1-3-4",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    ];

    /// Who a private descriptor grants full control to.
    #[derive(Clone)]
    pub enum Grant {
        /// This user and SYSTEM, inherited by files and folders inside.
        Owner,
        /// This user, Administrators and SYSTEM, inherited by files and
        /// folders inside.
        OwnerAndAdministrators,
        /// This user, Administrators and SYSTEM, for a file.
        FileForOwnerAndAdministrators,
        /// [`Grant::FileForOwnerAndAdministrators`], and read (only) for
        /// one more account, by SID (`S-1-5-...`).
        FileReadBy(String),
        /// Administrators and SYSTEM, and read (only) for one more
        /// account, by SID: not this user (a file it writes for another
        /// account, [`super::make_file_admin_owned_for`]).
        FileAdminsReadBy(String),
    }

    /// Whether `s` is a SID string (`S-1-5-...`), the only thing that goes
    /// into an SDDL here.
    fn is_sid(s: &str) -> bool {
        s.strip_prefix("S-")
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_digit() || b == b'-'))
    }

    /// Makes Administrators (`S-1-5-32-544`) the owner of `path`. Works
    /// for an elevated administrator; anyone else gets
    /// `ERROR_INVALID_OWNER`.
    pub fn set_owner_administrators(path: &Path) -> io::Result<()> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        let admins = wide(OsStr::new("S-1-5-32-544"));
        let mut sid: PSID = null_mut();
        // SAFETY: `admins` is NUL-terminated; the SID is freed with
        // LocalFree on every path.
        unsafe {
            if ConvertStringSidToSidW(admins.as_ptr(), &mut sid) == 0 {
                return Err(io::Error::last_os_error());
            }
            let path = wide(path.as_os_str());
            let code = SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                sid,
                null_mut(),
                null(),
                null(),
            );
            LocalFree(sid as HLOCAL);
            match code {
                0 => Ok(()),
                code => Err(io::Error::from_raw_os_error(code as i32)),
            }
        }
    }

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    fn from_wide(p: *const u16) -> String {
        if p.is_null() {
            return String::new();
        }
        // SAFETY: `p` is a NUL-terminated string returned by the system.
        unsafe {
            let mut n = 0;
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    }

    /// `S-1-5-...` for a SID.
    fn sid_string(sid: PSID) -> Option<String> {
        let mut s: *mut u16 = null_mut();
        // SAFETY: `sid` is a valid SID; the string is freed with LocalFree.
        unsafe {
            if ConvertSidToStringSidW(sid, &mut s) == 0 {
                return None;
            }
            let out = from_wide(s);
            LocalFree(s as HLOCAL);
            Some(out)
        }
    }

    /// The owner and writers of an open file, from its handle.
    pub fn file_security(f: &std::fs::File) -> Option<super::FileSecurity> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
        /// `FILE_WRITE_DATA`, `FILE_APPEND_DATA`, `DELETE`, `WRITE_DAC`,
        /// `WRITE_OWNER`.
        const CHANGE: u32 = 0x2 | 0x4 | 0x1_0000 | 0x4_0000 | 0x8_0000;
        /// `INHERIT_ONLY_ACE`: not for the file itself.
        const INHERIT_ONLY: u8 = 0x08;
        /// Deny and audit entries; any other entry type may allow.
        const NOT_ALLOW: &[u8] = &[1, 2, 3, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17, 18, 19];
        // SAFETY: the handle is the open file's; the descriptor is freed
        // with LocalFree on every path, and the owner and DACL point into
        // it until then; ACEs are read within the ACL's bounds as reported
        // by the system.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let mut owner: PSID = null_mut();
            let mut dacl: *mut ACL = null_mut();
            let code = GetSecurityInfo(
                f.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            if code != 0 {
                return None;
            }
            let owner = if owner.is_null() {
                None
            } else {
                sid_string(owner)
            };
            let mut writers: Vec<String> = Vec::new();
            if dacl.is_null() {
                writers.push("S-1-1-0".into());
            } else {
                let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) == 0
                {
                    writers.push("?".into());
                } else {
                    for i in 0..info.AceCount {
                        let mut ace: *mut core::ffi::c_void = null_mut();
                        if GetAce(dacl, i, &mut ace) == 0 {
                            writers.push("?".into());
                            continue;
                        }
                        // The header first: every entry starts with one; only
                        // an ACCESS_ALLOWED entry is read as one.
                        let header = &*(ace as *const windows_sys::Win32::Security::ACE_HEADER);
                        let kind = header.AceType;
                        if NOT_ALLOW.contains(&kind) || header.AceFlags & INHERIT_ONLY != 0 {
                            continue;
                        }
                        if kind != ACCESS_ALLOWED {
                            // An object or callback entry: not read here.
                            writers.push("?".into());
                            continue;
                        }
                        let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                        let mask = allowed.Mask;
                        if mask & (CHANGE | GENERIC_WRITE | GENERIC_ALL) == 0 {
                            continue;
                        }
                        let sid = std::ptr::addr_of!(allowed.SidStart) as PSID;
                        writers.push(sid_string(sid).unwrap_or_else(|| "?".into()));
                    }
                }
            }
            LocalFree(sd as HLOCAL);
            writers.sort();
            writers.dedup();
            Some(super::FileSecurity {
                owner: owner?,
                writers,
            })
        }
    }

    /// `DOMAIN\name` for a SID, or the SID string.
    fn account_name(sid: PSID) -> String {
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let (mut n, mut d, mut kind) = (name.len() as u32, domain.len() as u32, 0i32);
        // SAFETY: buffers and their lengths are passed together.
        let ok = unsafe {
            LookupAccountSidW(
                null(),
                sid,
                name.as_mut_ptr(),
                &mut n,
                domain.as_mut_ptr(),
                &mut d,
                &mut kind,
            )
        };
        if ok == 0 {
            return sid_string(sid).unwrap_or_else(|| "an unknown account".into());
        }
        let name = from_wide(name.as_ptr());
        let domain = from_wide(domain.as_ptr());
        if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        }
    }

    /// The SID of the account this process runs as, as a string.
    pub fn current_user_sid() -> io::Result<String> {
        // SAFETY: the token handle is closed on every path; the buffer is
        // sized by the first call and holds a TOKEN_USER.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
            // u64 storage keeps the buffer aligned for TOKEN_USER.
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(
                token,
                TokenUser,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut len,
            );
            let err = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            sid_string(user.User.Sid).ok_or_else(io::Error::last_os_error)
        }
    }

    /// Whether this process runs elevated (an administrator's full token).
    /// False when it can't be told: the owner check then stays strict.
    pub fn is_elevated() -> bool {
        // SAFETY: the token handle is closed on every path; the buffer is a
        // TOKEN_ELEVATION of the size passed.
        unsafe {
            let mut token: HANDLE = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            CloseHandle(token);
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Administrators (`S-1-5-32-544`).
    const ADMINISTRATORS: &str = "S-1-5-32-544";

    /// Whether `owner` is the owner a folder this account creates gets: the
    /// account itself, or, for an elevated process, Administrators, which
    /// Windows makes the owner of what an elevated administrator creates.
    /// Anyone else, or Administrators for a process that isn't elevated,
    /// means no.
    pub fn is_own_owner(owner: &str, me: &str, elevated: bool) -> bool {
        owner == me || (elevated && owner == ADMINISTRATORS)
    }

    /// The SID of account `name`, as a string.
    pub fn account_sid(name: &str) -> io::Result<String> {
        let account = wide(OsStr::new(name));
        // u64 storage keeps the buffer aligned; 128 bytes hold the largest
        // SID (68).
        let mut sid = vec![0u64; 16];
        let mut domain = [0u16; 256];
        let (mut n, mut d, mut kind) = ((sid.len() * 8) as u32, domain.len() as u32, 0i32);
        // SAFETY: buffers and their lengths are passed together.
        unsafe {
            if LookupAccountNameW(
                null(),
                account.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut n,
                domain.as_mut_ptr(),
                &mut d,
                &mut kind,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            sid_string(sid.as_mut_ptr().cast()).ok_or_else(io::Error::last_os_error)
        }
    }

    /// A self-relative security descriptor with a protected DACL, freed on
    /// drop.
    struct PrivateSd(PSECURITY_DESCRIPTOR);

    impl PrivateSd {
        fn new(grant: Grant) -> io::Result<Self> {
            let user = current_user_sid()?;
            // Protected (P), auto-inherited (AI): full control (FA), for a
            // folder inherited by files (OI) and folders (CI) inside.
            let sddl = match grant {
                Grant::Owner => format!("D:PAI(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)"),
                Grant::OwnerAndAdministrators => {
                    format!("D:PAI(A;OICI;FA;;;{user})(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
                }
                Grant::FileForOwnerAndAdministrators => {
                    format!("D:PAI(A;;FA;;;{user})(A;;FA;;;BA)(A;;FA;;;SY)")
                }
                Grant::FileAdminsReadBy(reader) => {
                    if !is_sid(&reader) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{reader:?} is not a SID"),
                        ));
                    }
                    format!("D:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;{reader})")
                }
                Grant::FileReadBy(reader) => {
                    // Only a SID string goes into the SDDL.
                    if !is_sid(&reader) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("{reader:?} is not a SID"),
                        ));
                    }
                    let mut sddl = format!("D:PAI(A;;FA;;;{user})(A;;FA;;;BA)(A;;FA;;;SY)");
                    if reader != user {
                        sddl.push_str(&format!("(A;;FR;;;{reader})"));
                    }
                    sddl
                }
            };
            let sddl = wide(OsStr::new(&sddl));
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: `sddl` is NUL-terminated; `sd` is freed in Drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(sd))
        }

        fn dacl(&self) -> io::Result<*mut ACL> {
            let (mut present, mut defaulted) = (0, 0);
            let mut dacl: *mut ACL = null_mut();
            // SAFETY: `self.0` is a valid descriptor; the DACL points into it.
            let got = unsafe {
                GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted)
            };
            if got == 0 || present == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(dacl)
        }
    }

    impl Drop for PrivateSd {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptor... with
            // LocalAlloc.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    /// Creates the folder with the private descriptor already on it, so it
    /// is never briefly open to others.
    pub fn create_dir(dir: &Path, grant: Grant) -> io::Result<()> {
        let sd = PrivateSd::new(grant)?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let path = wide(dir.as_os_str());
        // SAFETY: `path` is NUL-terminated; `attrs` outlives the call.
        if unsafe { CreateDirectoryW(path.as_ptr(), &attrs) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Replaces the DACL of an existing file or folder with a protected,
    /// private one.
    pub fn set_protected(path: &Path, grant: Grant) -> io::Result<()> {
        let sd = PrivateSd::new(grant)?;
        let dacl = sd.dacl()?;
        let path = wide(path.as_os_str());
        // SAFETY: `path` is NUL-terminated; `dacl` lives as long as `sd`.
        // The change propagates to children that inherit.
        let code = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null(),
            )
        };
        match code {
            0 => Ok(()),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    /// Whether `path` is owned by this account (or by Administrators, when
    /// this process is elevated: [`is_own_owner`]) and only this account,
    /// SYSTEM and Administrators may read or change it. Fails closed: a
    /// descriptor that can't be read, a missing DACL, an ACE that can't be
    /// read, or any ACE type other than plain allow and deny (object,
    /// callback, ...) means not private.
    pub fn is_private(path: &Path) -> bool {
        let Ok(me) = current_user_sid() else {
            return false;
        };
        let path = wide(path.as_os_str());
        // SAFETY: the descriptor is freed with LocalFree on every path; the
        // owner and DACL point into it; ACEs are read within the ACL's
        // bounds as reported by the system.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let mut owner: PSID = null_mut();
            let mut dacl: *mut ACL = null_mut();
            let code = GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            if code != 0 {
                return false;
            }
            let private = (|| {
                if owner.is_null() {
                    return false;
                }
                match sid_string(owner) {
                    Some(o) if is_own_owner(&o, &me, is_elevated()) => {}
                    _ => return false,
                }
                if dacl.is_null() {
                    return false;
                }
                let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) == 0
                {
                    return false;
                }
                for i in 0..info.AceCount {
                    let mut ace: *mut core::ffi::c_void = null_mut();
                    if GetAce(dacl, i, &mut ace) == 0 {
                        return false;
                    }
                    let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                    match allowed.Header.AceType {
                        ACCESS_DENIED => continue,
                        ACCESS_ALLOWED => {}
                        _ => return false,
                    }
                    let sid = std::ptr::addr_of!(allowed.SidStart) as PSID;
                    match sid_string(sid) {
                        Some(s) if s == me || TRUSTED.contains(&s.as_str()) => {}
                        _ => return false,
                    }
                }
                true
            })();
            LocalFree(sd as HLOCAL);
            private
        }
    }

    pub fn others_with_access(path: &Path) -> io::Result<Vec<Access>> {
        let me = current_user_sid()?;
        let path = wide(path.as_os_str());
        // SAFETY: the descriptor is freed with LocalFree; ACEs are read
        // within the ACL's bounds as reported by the system.
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            let mut dacl: *mut ACL = null_mut();
            let code = GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            );
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            let mut who: Vec<Access> = Vec::new();
            if dacl.is_null() {
                // No DACL at all: everyone has full access.
                who.push(Access {
                    who: "Everyone".to_string(),
                    read: true,
                    write: true,
                });
            } else {
                let mut info: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(
                    dacl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) != 0
                {
                    for i in 0..info.AceCount {
                        let mut ace: *mut core::ffi::c_void = null_mut();
                        if GetAce(dacl, i, &mut ace) == 0 {
                            continue;
                        }
                        let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
                        if allowed.Header.AceType != ACCESS_ALLOWED {
                            continue;
                        }
                        let mask = allowed.Mask;
                        let read = mask & (READ_DATA | GENERIC_READ | GENERIC_ALL) != 0;
                        let write = mask & (WRITE_ANY | GENERIC_WRITE | GENERIC_ALL) != 0;
                        if !read && !write {
                            continue;
                        }
                        let sid = std::ptr::addr_of!(allowed.SidStart) as PSID;
                        let Some(s) = sid_string(sid) else { continue };
                        if s == me || TRUSTED.contains(&s.as_str()) {
                            continue;
                        }
                        let name = account_name(sid);
                        match who.iter_mut().find(|a| a.who == name) {
                            Some(a) => {
                                a.read |= read;
                                a.write |= write;
                            }
                            None => who.push(Access {
                                who: name,
                                read,
                                write,
                            }),
                        }
                    }
                }
            }
            LocalFree(sd as HLOCAL);
            Ok(who)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("pathwarden-perms-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// Only this account, Administrators and SYSTEM may own or change a
    /// file read as this account's own; an entry that can't be read
    /// (`?`) counts as someone else.
    #[test]
    fn untrusted_holders_are_named() {
        let me = "S-1-5-21-1-2-3-1001";
        let sec = |owner: &str, writers: &[&str]| FileSecurity {
            owner: owner.into(),
            writers: writers.iter().map(|s| s.to_string()).collect(),
        };
        assert!(untrusted_holders(&sec(me, &[me, "S-1-5-32-544", "S-1-5-18"]), me).is_empty());
        assert!(untrusted_holders(&sec("S-1-5-32-544", &["S-1-5-18"]), me).is_empty());
        assert_eq!(
            untrusted_holders(&sec("S-1-5-21-1-2-3-500", &["S-1-5-32-544"]), me),
            ["S-1-5-21-1-2-3-500"]
        );
        assert_eq!(
            untrusted_holders(&sec(me, &["S-1-5-32-545", "?", "S-1-5-32-545"]), me),
            ["S-1-5-32-545", "?"]
        );
    }

    /// The owner of a private folder is this account, or Administrators
    /// only when the process is elevated; nobody else, elevated or not.
    #[cfg(windows)]
    #[test]
    fn own_owner_is_this_account_or_elevated_administrators() {
        let me = "S-1-5-21-1-2-3-1001";
        for elevated in [false, true] {
            assert!(win::is_own_owner(me, me, elevated));
            assert!(!win::is_own_owner("S-1-5-21-1-2-3-1002", me, elevated));
            assert!(!win::is_own_owner("S-1-5-18", me, elevated));
            assert!(!win::is_own_owner("S-1-5-32-545", me, elevated));
            assert!(!win::is_own_owner("S-1-5-32-5440", me, elevated));
        }
        assert!(!win::is_own_owner("S-1-5-32-544", me, false));
        assert!(win::is_own_owner("S-1-5-32-544", me, true));
    }

    #[test]
    fn private_dirs_are_private() {
        let d = scratch("private");
        create_private_dir(&d).unwrap();
        // It must not exist already: nobody can prepare it in advance.
        assert!(create_private_dir(&d).is_err());
        assert_eq!(readable_by_others(&d), Vec::<String>::new());
        assert_eq!(others_with_access(&d), Vec::<Access>::new());
        // On Windows a file created inside inherits its ACL. On Unix the
        // file's mode comes from the umask, and the 0700 directory is what
        // keeps others out, so only the directory is checked there.
        std::fs::write(d.join("x"), "x").unwrap();
        #[cfg(windows)]
        assert_eq!(readable_by_others(&d.join("x")), Vec::<String>::new());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn private_dirs_are_told_apart() {
        let d = scratch("is-private");
        create_private_dir(&d).unwrap();
        assert!(is_private_dir(&d));
        let f = d.join("file");
        std::fs::write(&f, b"x").unwrap();
        assert!(!is_private_dir(&f), "a file is not a folder");
        assert!(!is_private_dir(&d.join("missing")), "nor is nothing");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn output_dirs_and_files_are_private() {
        let d = scratch("output");
        create_output_dir(&d).unwrap();
        assert!(create_output_dir(&d).is_err());
        assert_eq!(others_with_access(&d), Vec::<Access>::new());
        let f = d.join("x.zip");
        std::fs::write(&f, "x").unwrap();
        make_output_file_private(&f).unwrap();
        assert_eq!(others_with_access(&f), Vec::<Access>::new());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn others_who_can_read_are_named() {
        let d = scratch("open");
        std::fs::create_dir(&d).unwrap();
        #[cfg(windows)]
        {
            let icacls = |path: &Path, grant: &str| {
                let ok = crate::spawn::quiet("icacls")
                    .arg(path)
                    .args(["/grant", grant])
                    .stdout(std::process::Stdio::null())
                    .status()
                    .unwrap()
                    .success();
                assert!(ok);
            };
            // Whatever the temp folder passes down, plus BUILTIN\Users (by
            // SID, so the test does not depend on the system language).
            let before = readable_by_others(&d).len();
            icacls(&d, "*S-1-5-32-545:(OI)(CI)R");
            let who = readable_by_others(&d);
            assert_eq!(who.len(), before + 1, "{who:?}");
            // A file written inside inherits that, until it gets its own
            // protected DACL.
            let f = d.join("x.zip");
            std::fs::write(&f, "x").unwrap();
            assert!(!readable_by_others(&f).is_empty());
            make_output_file_private(&f).unwrap();
            assert_eq!(others_with_access(&f), Vec::<Access>::new());
            // Write access alone is reported too (S-1-5-4: INTERACTIVE,
            // which the temp folder does not grant).
            icacls(&d, "*S-1-5-4:(W)");
            assert!(
                others_with_access(&d).iter().any(|a| a.write && !a.read),
                "{:?}",
                others_with_access(&d)
            );
            make_private(&d).unwrap();
            assert_eq!(readable_by_others(&d), Vec::<String>::new());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert_eq!(readable_by_others(&d), vec!["its group", "every user"]);
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o703)).unwrap();
            assert_eq!(
                others_with_access(&d),
                vec![Access {
                    who: "every user".into(),
                    read: false,
                    write: true
                }]
            );
            make_private(&d).unwrap();
            assert!(readable_by_others(&d).is_empty());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }
}
