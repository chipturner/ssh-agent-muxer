use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Validate that a backend socket is safe to connect to.
/// Must be owned by current user and not world-readable/writable.
pub fn validate_backend_socket(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{e}"))?;
    let uid = current_uid();

    if meta.uid() != uid {
        return Err(format!("owned by uid {}, expected {uid}", meta.uid()));
    }

    let mode = meta.mode();
    if mode & 0o002 != 0 {
        return Err("world-writable".into());
    }
    if mode & 0o004 != 0 {
        return Err("world-readable".into());
    }

    Ok(())
}

/// Get peer credentials from an accepted Unix socket connection.
/// Returns (pid, uid, gid) of the connecting process.
pub fn get_peer_cred(stream: &UnixStream) -> io::Result<(u32, u32, u32)> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &raw mut cred as *mut libc::c_void,
            &raw mut len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok((cred.pid as u32, cred.uid as u32, cred.gid as u32))
}

/// Check that connecting peer is the same user.
pub fn check_peer_uid(stream: &UnixStream) -> Result<(), String> {
    let (_, peer_uid, _) = get_peer_cred(stream).map_err(|e| format!("{e}"))?;
    let our_uid = current_uid();

    if peer_uid != our_uid {
        return Err(format!("peer uid {peer_uid} != our uid {our_uid}"));
    }

    Ok(())
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn test_peer_cred_returns_current_uid() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let client = UnixStream::connect(&sock_path).unwrap();
        let (server, _) = listener.accept().unwrap();

        let (pid, uid, _gid) = get_peer_cred(&server).unwrap();
        assert_eq!(uid, current_uid());
        assert_eq!(pid, std::process::id());

        let (pid, uid, _gid) = get_peer_cred(&client).unwrap();
        assert_eq!(uid, current_uid());
        // Listener side reports the listener's pid
        assert!(pid > 0);
    }

    #[test]
    fn test_check_peer_uid_accepts_same_user() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let _client = UnixStream::connect(&sock_path).unwrap();
        let (server, _) = listener.accept().unwrap();

        assert!(check_peer_uid(&server).is_ok());
    }

    fn chmod_socket(path: &std::path::Path, mode: u32) {
        let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        unsafe { libc::chmod(c_path.as_ptr(), mode) };
    }

    #[test]
    fn test_validate_own_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let _listener = UnixListener::bind(&sock_path).unwrap();
        chmod_socket(&sock_path, 0o600);

        assert!(validate_backend_socket(&sock_path).is_ok());
    }

    #[test]
    fn test_validate_rejects_world_writable() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let _listener = UnixListener::bind(&sock_path).unwrap();
        chmod_socket(&sock_path, 0o777);

        let err = validate_backend_socket(&sock_path).unwrap_err();
        assert!(err.contains("world-writable"), "got: {err}");
    }

    #[test]
    fn test_validate_rejects_world_readable() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let _listener = UnixListener::bind(&sock_path).unwrap();
        chmod_socket(&sock_path, 0o744);

        let err = validate_backend_socket(&sock_path).unwrap_err();
        assert!(err.contains("world-readable"), "got: {err}");
    }

    #[test]
    fn test_validate_rejects_nonexistent() {
        let result = validate_backend_socket(Path::new("/nonexistent/socket"));
        assert!(result.is_err());
    }
}
