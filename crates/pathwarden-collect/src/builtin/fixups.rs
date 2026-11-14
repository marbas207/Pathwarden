//! Corrections to what RustHound-CE writes, found by scoring a real GOAD
//! collection against SharpHound's, plus the shared zip-rewriting used to add
//! data RustHound-CE doesn't collect. Applied by the built-in collector only;
//! Pathwarden's ingest copes with collections made before them (see
//! `pathwarden-core`'s ingest and the AD CS completeness report).
//!
//! ESC13 (templates' certificate policies and issuance policies' linked
//! groups), template publication by exact name, and foreign security
//! principals named by SID were corrected here until RustHound-CE fixed them
//! upstream (g0h4n/RustHound-CE#96 in 2.5.26, RustHound-CE#86 and
//! RustHound-CE#88 in 2.5.25);
//! `checker`'s tests keep the latter two fixed. [`patch_zip`] stays: the CA
//! registry flags (ESC6) are still added over it (see `careg`).

use serde_json::Value;
use std::io::{Read, Write};
use std::path::Path;

/// Rewrites the collection zip in place: each `.json` entry whose lowercase
/// name `wants` is parsed, handed to `patch`, and written back; every other
/// entry is copied unchanged. On an error the zip is left as it was.
pub(crate) fn patch_zip(
    zip_path: &Path,
    wants: impl Fn(&str) -> bool,
    mut patch: impl FnMut(&str, &mut Value),
) -> Result<(), String> {
    let tmp = zip_path.with_extension("zip.tmp");
    let result = rewrite(zip_path, &tmp, &wants, &mut patch);
    match result {
        Ok(()) => std::fs::rename(&tmp, zip_path).map_err(|e| e.to_string()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn rewrite(
    from: &Path,
    to: &Path,
    wants: &dyn Fn(&str) -> bool,
    patch: &mut dyn FnMut(&str, &mut Value),
) -> Result<(), String> {
    let err = |e: &dyn std::fmt::Display| e.to_string();
    let src = std::fs::File::open(from).map_err(|e| err(&e))?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(src)).map_err(|e| err(&e))?;
    let dst = std::fs::File::create(to).map_err(|e| err(&e))?;
    let mut zip = zip::ZipWriter::new(std::io::BufWriter::new(dst));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for i in 0..archive.len() {
        let name = archive
            .by_index_raw(i)
            .map_err(|e| err(&e))?
            .name()
            .map_err(|e| err(&e))?
            .into_owned();
        let lower = name.to_ascii_lowercase();
        if wants(&lower) {
            let mut text = String::new();
            archive
                .by_index(i)
                .map_err(|e| err(&e))?
                .read_to_string(&mut text)
                .map_err(|e| err(&e))?;
            let mut doc: Value = serde_json::from_str(&text).map_err(|e| err(&e))?;
            patch(&lower, &mut doc);
            zip.start_file(name, options).map_err(|e| err(&e))?;
            let bytes = serde_json::to_vec(&doc).map_err(|e| err(&e))?;
            zip.write_all(&bytes).map_err(|e| err(&e))?;
        } else {
            let file = archive.by_index_raw(i).map_err(|e| err(&e))?;
            zip.raw_copy_file(file).map_err(|e| err(&e))?;
        }
    }
    zip.finish().map_err(|e| err(&e))?;
    Ok(())
}
