//! macOS sandboxing using Seatbelt (`sandbox_init`).
//!
//! Generates an SBPL (Seatbelt Profile Language) profile from a [`SandboxSpec`]
//! and provides a closure suitable for [`std::os::unix::process::CommandExt::pre_exec`].

use std::ffi::CString;
use std::io::Write;
use std::path::Path;
use std::ptr;

use crate::spec::SandboxSpec;

/// Deny-all baseline with minimal required permissions.
///
/// - `(deny default)` — deny everything not explicitly allowed
/// - `(allow mach*)` — required for basic IPC (dyld, libSystem)
/// - `(allow ipc*)` — required for IPC
/// - `(allow signal (target others))` — allow sending signals
/// - `(allow process-fork)` — allow fork (needed for subprocess spawn)
/// - `(allow sysctl*)` — allow sysctl queries
/// - `(allow system*)` — allow system info queries
/// - `(allow file-read-metadata)` — allow stat() on any path (needed for path resolution)
/// - `(system-network)` — allow DNS resolution and basic network config reads
const BASELINE_PROFILE: &[u8] = b"\
(version 1)
(import \"system.sb\")

(deny default)
(allow mach*)
(allow ipc*)
(allow signal (target others))
(allow process-fork)
(allow sysctl*)
(allow system*)
(allow file-read-metadata)
(system-network)
";

/// Build a Seatbelt profile string from a [`SandboxSpec`].
///
/// This can be called on the parent side (before fork), and the resulting
/// string passed into a `pre_exec` closure.
pub fn build_profile(spec: &SandboxSpec) -> Result<CString, SandboxError> {
    let profile = generate_profile(spec)?;
    CString::new(profile).map_err(|_| SandboxError::Activation("profile contains null byte".into()))
}

/// Apply a pre-built Seatbelt profile to the current process.
///
/// # Safety
///
/// Must be called in a single-threaded context (e.g., inside `pre_exec`
/// after fork, before exec).
pub unsafe fn apply_profile(profile: &CString) -> Result<(), SandboxError> {
    let mut error: *mut i8 = ptr::null_mut();

    // SAFETY: `sandbox_init` is a stable macOS C API. We pass a valid C string
    // and a pointer to receive error messages. The `0` flags argument means
    // the profile is a string (not a file path).
    let result = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error) };

    if result == 0 {
        Ok(())
    } else {
        let error_msg = if error.is_null() {
            "sandbox_init failed with unknown error".into()
        } else {
            // SAFETY: `error` is a valid C string allocated by sandbox_init.
            let msg = unsafe { std::ffi::CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            // SAFETY: `error` was allocated by sandbox_init and must be freed.
            unsafe { sandbox_free_error(error) };
            msg
        };
        Err(SandboxError::Activation(error_msg))
    }
}

/// Generate a Seatbelt profile from a sandbox spec.
fn generate_profile(spec: &SandboxSpec) -> Result<Vec<u8>, SandboxError> {
    let mut profile = BASELINE_PROFILE.to_vec();

    // Filesystem: allow-read
    for path in &spec.allow_read {
        write_path_rule(&mut profile, "allow", "file-read*", path)?;
    }

    // Filesystem: allow-write (implies read)
    for path in &spec.allow_write {
        write_path_rule(&mut profile, "allow", "file-read*", path)?;
        write_path_rule(&mut profile, "allow", "file-write*", path)?;
    }

    // Filesystem: allow-execute (implies read)
    for path in &spec.allow_execute {
        write_path_rule(&mut profile, "allow", "file-read*", path)?;
        write_path_rule(&mut profile, "allow", "process-exec", path)?;
    }

    // Filesystem: deny-read (overrides allow)
    for path in &spec.deny_read {
        write_path_rule(&mut profile, "deny", "file-read*", path)?;
    }

    // Filesystem: deny-write (overrides allow)
    for path in &spec.deny_write {
        write_path_rule(&mut profile, "deny", "file-write*", path)?;
    }

    // Filesystem: deny-execute (overrides allow)
    for path in &spec.deny_execute {
        write_path_rule(&mut profile, "deny", "process-exec", path)?;
    }

    // Network
    if spec.allow_net {
        profile.write_all(b"(allow network*)\n")?;
    }

    Ok(profile)
}

/// Write a single path rule to the profile buffer.
fn write_path_rule(
    buffer: &mut Vec<u8>,
    mode: &str,
    access_type: &str,
    path: &Path,
) -> Result<(), SandboxError> {
    let escaped = escape_path(path)?;
    writeln!(buffer, "({mode} {access_type} (subpath {escaped}))")?;
    Ok(())
}

/// Escape and quote a path for use in SBPL `subpath` expressions.
///
/// The path is canonicalized to resolve symlinks (Seatbelt operates on
/// real paths), then escaped for SBPL string syntax.
fn escape_path(path: &Path) -> Result<String, SandboxError> {
    // Try to canonicalize; fall back to the original if the path doesn't exist yet.
    let canonical = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    let path_str = canonical
        .as_os_str()
        .to_str()
        .ok_or_else(|| SandboxError::InvalidPath(path.to_path_buf()))?;

    // Strip trailing slashes (SBPL subpath requires no trailing slash).
    let trimmed = path_str.trim_end_matches('/');
    let trimmed = if trimmed.is_empty() { "/" } else { trimmed };

    // Escape special characters for SBPL string literals.
    let escaped = trimmed.replace('\\', r"\\").replace('"', r#"\""#);

    Ok(format!("\"{escaped}\""))
}

/// Errors from sandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("failed to activate sandbox: {0}")]
    Activation(String),

    #[error("invalid path for sandbox: {}", _0.display())]
    InvalidPath(std::path::PathBuf),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// FFI bindings to macOS sandbox API.
unsafe extern "C" {
    fn sandbox_init(profile: *const i8, flags: u64, errorbuf: *mut *mut i8) -> i32;
    fn sandbox_free_error(errorbuf: *mut i8);
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_escape_path_simple() {
        // /tmp always exists on macOS.
        let result = escape_path(Path::new("/tmp")).unwrap();
        // /tmp -> /private/tmp after canonicalization on macOS
        assert!(
            result == "\"/private/tmp\"" || result == "\"/tmp\"",
            "got: {result}"
        );
    }

    #[test]
    fn test_escape_path_trailing_slash() {
        let result = escape_path(Path::new("/tmp/")).unwrap();
        // Should not end with /
        assert!(!result.trim_matches('"').ends_with('/') || result == "\"/\"");
    }

    #[test]
    fn test_generate_profile_basic() {
        let spec = SandboxSpec {
            allow_read: vec![PathBuf::from("/tmp")],
            deny_read: vec![],
            allow_write: vec![],
            deny_write: vec![],
            allow_execute: vec![],
            deny_execute: vec![],
            allow_net: false,
            env: None,
        };

        let profile = generate_profile(&spec).unwrap();
        let profile_str = String::from_utf8(profile).unwrap();

        assert!(profile_str.contains("(deny default)"));
        assert!(profile_str.contains("(allow file-read*"));
        assert!(!profile_str.contains("(allow network*)"));
    }

    #[test]
    fn test_generate_profile_with_network() {
        let spec = SandboxSpec {
            allow_read: vec![],
            deny_read: vec![],
            allow_write: vec![],
            deny_write: vec![],
            allow_execute: vec![],
            deny_execute: vec![],
            allow_net: true,
            env: None,
        };

        let profile = generate_profile(&spec).unwrap();
        let profile_str = String::from_utf8(profile).unwrap();

        assert!(profile_str.contains("(allow network*)"));
    }

    #[test]
    fn test_generate_profile_deny_overrides() {
        let spec = SandboxSpec {
            allow_read: vec![PathBuf::from("/home/user")],
            deny_read: vec![PathBuf::from("/home/user/.ssh")],
            allow_write: vec![PathBuf::from("/home/user")],
            deny_write: vec![PathBuf::from("/home/user/.bashrc")],
            allow_execute: vec![],
            deny_execute: vec![],
            allow_net: false,
            env: None,
        };

        let profile = generate_profile(&spec).unwrap();
        let profile_str = String::from_utf8(profile).unwrap();

        // Allow rules should come before deny rules for the same parent.
        let allow_read_pos = profile_str.find("(allow file-read*").unwrap();
        let deny_read_pos = profile_str.find("(deny file-read*").unwrap();
        assert!(allow_read_pos < deny_read_pos);

        let allow_write_pos = profile_str.find("(allow file-write*").unwrap();
        let deny_write_pos = profile_str.find("(deny file-write*").unwrap();
        assert!(allow_write_pos < deny_write_pos);
    }
}
