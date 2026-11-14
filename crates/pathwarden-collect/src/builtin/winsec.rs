//! File security descriptors over SMB through Windows itself:
//! `GetNamedSecurityInfoW` on a UNC path. The OS SMB client signs in as the
//! current user (Kerberos), so no password is needed; the `smb2-client`
//! RustHound-CE uses has no QUERY_INFO request, so the password path can't
//! read descriptors at all.

#![allow(unsafe_code)]

use windows_sys::Win32::Foundation::{LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

/// The owner and DACL of a file or folder, as a self-relative security
/// descriptor; `None` when it does not exist.
pub(crate) fn file_sd(path: &str) -> Result<Option<Vec<u8>>, String> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated and outlives the call; the out
    // pointers we don't want are null, which the API allows; `sd` receives
    // a LocalAlloc'd block that is freed below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    if rc != 0 {
        return Err(std::io::Error::from_raw_os_error(rc as i32).to_string());
    }
    if sd.is_null() {
        return Err("no security descriptor returned".into());
    }
    // SAFETY: `sd` is the valid descriptor the call returned; its length
    // covers the whole self-relative block, which is copied before freeing.
    let bytes = unsafe {
        let len = GetSecurityDescriptorLength(sd) as usize;
        let bytes = std::slice::from_raw_parts(sd as *const u8, len).to_vec();
        LocalFree(sd as _);
        bytes
    };
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_local_folder_and_misses_cleanly() {
        let dir = std::env::temp_dir();
        let sd = file_sd(&dir.to_string_lossy()).unwrap().unwrap();
        // Revision 1, self-relative.
        assert_eq!(sd[0], 1);
        assert_ne!(sd[3] & 0x80, 0);
        let missing = dir.join("pathwarden-no-such-file-1234");
        assert_eq!(file_sd(&missing.to_string_lossy()).unwrap(), None);
    }
}
