//! Fail-closed identity checks for paths used as distinct CLI outputs.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, Metadata};
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
enum FileIdentity {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows { volume: u32, index: u64 },
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(FileIdentity::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::windows::fs::MetadataExt;

    match (metadata.volume_serial_number(), metadata.file_index()) {
        (Some(volume), Some(index)) => Some(FileIdentity::Windows { volume, index }),
        _ => None,
    }
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_metadata: &Metadata) -> Option<FileIdentity> {
    None
}

/// A declared output with its filesystem-resolved destination and, when it already
/// exists, its platform file identity.
#[derive(Clone, Debug)]
pub struct OutputPath {
    label: &'static str,
    supplied: PathBuf,
    resolved: PathBuf,
    identity: Option<FileIdentity>,
}

impl OutputPath {
    pub fn new(label: &'static str, supplied: PathBuf) -> Result<Self, OutputPathError> {
        let resolved = resolve_path(&supplied).map_err(|source| OutputPathError::Resolve {
            label,
            path: supplied.display().to_string(),
            source,
        })?;
        let identity = match fs::metadata(&resolved) {
            Ok(metadata) => file_identity(&metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(OutputPathError::Inspect {
                    label,
                    path: supplied.display().to_string(),
                    source,
                });
            }
        };
        Ok(Self {
            label,
            supplied,
            resolved,
            identity,
        })
    }

    pub fn path(&self) -> &Path {
        &self.resolved
    }

    pub fn into_path(self) -> PathBuf {
        self.resolved
    }
}

#[derive(Debug)]
pub enum OutputPathError {
    Resolve {
        label: &'static str,
        path: String,
        source: io::Error,
    },
    Inspect {
        label: &'static str,
        path: String,
        source: io::Error,
    },
    Alias {
        first_label: &'static str,
        first_path: String,
        second_label: &'static str,
        second_path: String,
        reason: &'static str,
    },
}

impl fmt::Display for OutputPathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolve { label, path, source } => {
                write!(formatter, "cannot resolve {label} path {path}: {source}")
            }
            Self::Inspect { label, path, source } => {
                write!(formatter, "cannot inspect {label} path {path}: {source}")
            }
            Self::Alias {
                first_label,
                first_path,
                second_label,
                second_path,
                reason,
            } => write!(
                formatter,
                "output path alias ({reason}): {first_label}={first_path} and {second_label}={second_path}"
            ),
        }
    }
}

impl std::error::Error for OutputPathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resolve { source, .. } | Self::Inspect { source, .. } => Some(source),
            Self::Alias { .. } => None,
        }
    }
}

/// Reject path aliases and existing hard-link aliases between all declared outputs.
pub fn ensure_distinct(paths: &[&OutputPath]) -> Result<(), OutputPathError> {
    for (index, first) in paths.iter().enumerate() {
        for second in &paths[index + 1..] {
            let reason = if first.resolved == second.resolved {
                Some("resolved path")
            } else if first.identity.is_some() && first.identity == second.identity {
                Some("existing file identity")
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(OutputPathError::Alias {
                    first_label: first.label,
                    first_path: first.supplied.display().to_string(),
                    second_label: second.label,
                    second_path: second.supplied.display().to_string(),
                    reason,
                });
            }
        }
    }
    Ok(())
}

const MAX_SYMLINK_DEPTH: usize = 40;

fn dangling_symlink_redirect(path: &Path) -> io::Result<Option<PathBuf>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let target = fs::read_link(path)?;
            let redirected = if target.is_absolute() {
                target
            } else {
                path.parent().unwrap_or_else(|| Path::new("/")).join(target)
            };
            Ok(Some(redirected))
        }
        Ok(_) => Ok(None),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Resolve existing paths completely. For a not-yet-created output, resolve the
/// deepest existing ancestor and append the non-existing suffix. Dangling symbolic
/// links are followed at every missing level; ambiguous or cyclic redirection fails.
pub fn resolve_path(path: &Path) -> io::Result<PathBuf> {
    resolve_path_inner(path, 0)
}

fn resolve_path_inner(path: &Path, symlink_depth: usize) -> io::Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output path must not be empty",
        ));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    match fs::canonicalize(&absolute) {
        Ok(resolved) => Ok(resolved),
        Err(original_error) if original_error.kind() == io::ErrorKind::NotFound => {
            let mut ancestor = absolute.as_path();
            let mut suffix: Vec<OsString> = Vec::new();
            loop {
                if let Some(mut redirected) = dangling_symlink_redirect(ancestor)? {
                    if symlink_depth >= MAX_SYMLINK_DEPTH {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!("too many symbolic links while resolving {}", path.display()),
                        ));
                    }
                    for component in suffix.iter().rev() {
                        redirected.push(component);
                    }
                    return resolve_path_inner(&redirected, symlink_depth + 1);
                }
                let name = ancestor.file_name().ok_or_else(|| {
                    io::Error::new(
                        original_error.kind(),
                        format!(
                            "cannot unambiguously resolve non-existing path {}: {original_error}",
                            path.display()
                        ),
                    )
                })?;
                suffix.push(name.to_os_string());
                ancestor = ancestor.parent().ok_or_else(|| {
                    io::Error::new(
                        original_error.kind(),
                        format!("cannot resolve path {}: {original_error}", path.display()),
                    )
                })?;
                match fs::canonicalize(ancestor) {
                    Ok(mut resolved) => {
                        for component in suffix.iter().rev() {
                            resolved.push(component);
                        }
                        return Ok(resolved);
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                }
            }
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    fn test_directory(label: &str) -> PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "asfa-output-path-{}-{label}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn parent_and_dot_aliases_resolve_to_one_output() {
        let root = test_directory("parent");
        fs::create_dir(root.join("sub")).unwrap();
        let state = OutputPath::new("--state", root.join("state.json")).unwrap();
        let parent = OutputPath::new("--out", root.join("sub/../state.json")).unwrap();
        let dot = OutputPath::new("--out", root.join("./state.json")).unwrap();
        assert!(matches!(
            ensure_distinct(&[&state, &parent]),
            Err(OutputPathError::Alias {
                reason: "resolved path",
                ..
            })
        ));
        assert!(ensure_distinct(&[&state, &dot]).is_err());
        assert!(!root.join("state.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_alias_is_rejected_before_target_creation() {
        let root = test_directory("dangling");
        std::os::unix::fs::symlink(root.join("state.json"), root.join("report.json")).unwrap();
        let state = OutputPath::new("--state", root.join("state.json")).unwrap();
        let report = OutputPath::new("--out", root.join("report.json")).unwrap();
        assert!(ensure_distinct(&[&state, &report]).is_err());
        assert!(!root.join("state.json").exists());
        assert!(fs::symlink_metadata(root.join("report.json"))
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn existing_hardlinks_share_an_output_identity() {
        let root = test_directory("hardlink");
        fs::write(root.join("report.json"), "sentinel").unwrap();
        fs::hard_link(root.join("report.json"), root.join("plan.json")).unwrap();
        let report = OutputPath::new("--out", root.join("report.json")).unwrap();
        let plan = OutputPath::new("--wave-out", root.join("plan.json")).unwrap();
        assert!(matches!(
            ensure_distinct(&[&report, &plan]),
            Err(OutputPathError::Alias {
                reason: "existing file identity",
                ..
            })
        ));
        assert_eq!(
            fs::read_to_string(root.join("report.json")).unwrap(),
            "sentinel"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn distinct_nonexistent_nested_outputs_are_accepted() {
        let root = test_directory("distinct");
        let state = OutputPath::new("--state", root.join("new/state.json")).unwrap();
        let report = OutputPath::new("--out", root.join("other/report.json")).unwrap();
        ensure_distinct(&[&state, &report]).unwrap();
        assert_eq!(state.path(), root.join("new/state.json"));
        assert_eq!(report.path(), root.join("other/report.json"));
        fs::remove_dir_all(root).unwrap();
    }
}
