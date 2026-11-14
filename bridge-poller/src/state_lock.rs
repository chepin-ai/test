//! OS-backed fail-fast exclusion for cooperating state writers.

use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

/// A sidecar lock remains on a stable inode when the state snapshot is atomically
/// renamed. It excludes cooperating processes using the same lexical state path;
/// it is not a distributed lock and does not constrain non-cooperating writers.
pub struct StateLock {
    _file: File,
    lock_path: PathBuf,
}

impl StateLock {
    pub fn acquire(state_path: &Path) -> io::Result<Self> {
        if let Some(parent) = state_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut lock_name = state_path.as_os_str().to_os_string();
        lock_name.push(".lock");
        let lock_path = PathBuf::from(lock_name);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(
                    error.kind(),
                    format!("state is already locked: {}", lock_path.display()),
                )
            } else {
                error
            }
        })?;
        Ok(Self {
            _file: file,
            lock_path,
        })
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sidecar_excludes_a_second_writer_and_releases_on_drop() {
        let state =
            std::env::temp_dir().join(format!("asfa-state-lock-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&state);
        let first = StateLock::acquire(&state).unwrap();
        let error = StateLock::acquire(&state).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            first.lock_path(),
            PathBuf::from(format!("{}.lock", state.display()))
        );
        drop(first);
        let second = StateLock::acquire(&state).unwrap();
        drop(second);
        let _ = std::fs::remove_file(format!("{}.lock", state.display()));
    }
}
