//! On Windows (MSVC), embeds the icon in pathwarden.exe, so Explorer, the
//! taskbar and the desktop window show it, and gives the main thread an
//! 8 MB stack.
//!
//! The icon is `assets/pathwarden.ico` (the Crown W, built by
//! `scripts/brand/build_repo.py`).
//! This writes it as a compiled resource file (`.res`) by hand and hands
//! that to the linker, which takes `.res` files as they are: no resource
//! compiler (rc.exe, windres) and no extra build dependency. Elsewhere it
//! does nothing.

use std::path::PathBuf;

const ICO: &str = "assets/pathwarden.ico";

/// Resource types (winuser.h).
const RT_ICON: u16 = 3;
const RT_GROUP_ICON: u16 = 14;

fn main() {
    println!("cargo:rerun-if-changed={ICO}");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return;
    }
    let ico = std::fs::read(ICO).expect("reading the icon");
    let res = res_file(&ico).expect("assets/pathwarden.ico is not a valid icon");
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("pathwarden.res");
    std::fs::write(&out, res).expect("writing the resource file");
    println!("cargo:rustc-link-arg-bins={}", out.display());
    // The main thread's stack: 8 MB as on Linux, not Windows' 1 MB, which
    // a debug build overflows while clap builds the command tree.
    println!("cargo:rustc-link-arg-bins=/STACK:8388608");
}

/// A `.res` file with the icon's images (RT_ICON 1..n) and the icon group
/// that lists them (RT_GROUP_ICON 1).
fn res_file(ico: &[u8]) -> Option<Vec<u8>> {
    let u16_at = |at: usize| Some(u16::from_le_bytes(ico.get(at..at + 2)?.try_into().ok()?));
    let u32_at = |at: usize| Some(u32::from_le_bytes(ico.get(at..at + 4)?.try_into().ok()?));
    if u16_at(0)? != 0 || u16_at(2)? != 1 {
        return None;
    }
    let count = u16_at(4)?;
    let mut res = Vec::new();
    // A .res file starts with an empty entry.
    entry(&mut res, 0, 0, 0, &[]);
    let mut group = Vec::new();
    group.extend_from_slice(&[0, 0, 1, 0]);
    group.extend_from_slice(&count.to_le_bytes());
    for i in 0..count {
        let at = 6 + 16 * usize::from(i);
        let dir = ico.get(at..at + 12)?;
        let size = u32_at(at + 8)? as usize;
        let offset = u32_at(at + 12)? as usize;
        let image = ico.get(offset..offset.checked_add(size)?)?;
        let id = i + 1;
        entry(&mut res, RT_ICON, id, 0x1010, image);
        // GRPICONDIRENTRY: the ICONDIRENTRY up to the size, then the ID.
        group.extend_from_slice(dir);
        group.extend_from_slice(&id.to_le_bytes());
    }
    entry(&mut res, RT_GROUP_ICON, 1, 0x1030, &group);
    Some(res)
}

/// One resource: the header (ordinal type and name, neutral language) and
/// the data, each padded to four bytes.
fn entry(res: &mut Vec<u8>, kind: u16, name: u16, flags: u16, data: &[u8]) {
    res.extend_from_slice(&(data.len() as u32).to_le_bytes());
    res.extend_from_slice(&32u32.to_le_bytes()); // header size
    res.extend_from_slice(&[0xff, 0xff]);
    res.extend_from_slice(&kind.to_le_bytes());
    res.extend_from_slice(&[0xff, 0xff]);
    res.extend_from_slice(&name.to_le_bytes());
    res.extend_from_slice(&0u32.to_le_bytes()); // data version
    res.extend_from_slice(&flags.to_le_bytes());
    res.extend_from_slice(&0u16.to_le_bytes()); // language: neutral
    res.extend_from_slice(&0u32.to_le_bytes()); // version
    res.extend_from_slice(&0u32.to_le_bytes()); // characteristics
    res.extend_from_slice(data);
    while !res.len().is_multiple_of(4) {
        res.push(0);
    }
}
