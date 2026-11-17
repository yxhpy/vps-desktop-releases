//! `write_atomic` exactly as the app's desktop/core/src/owned.rs has it: the only part of that
//! module the manifest uses, to keep the highest sequence it has seen. The app's other file
//! handling is not part of this repository.

use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Writes a sibling temporary file and renames it over `path`. An existing file keeps its mode;
/// a new one is readable by its owner only.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::other("path has no parent"))?;
    fs::create_dir_all(dir)?;
    let name = path.file_name().ok_or_else(|| io::Error::other("path has no file name"))?.to_string_lossy();
    let temp = dir.join(format!(".{name}.vps-tmp-{}", std::process::id()));
    let _ = fs::remove_file(&temp);
    let result = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o600);
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
