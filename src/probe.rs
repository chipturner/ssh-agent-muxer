use base64::Engine;
use sha2::Digest;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;

#[derive(Debug, Clone)]
pub struct Identity {
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
}

#[derive(Debug)]
pub enum AgentStatus {
    Alive(Vec<Identity>),
    Dead(String),
    PermissionDenied,
}

/// Connect to a Unix socket with a timeout.
///
/// `UnixStream::connect` has no timeout parameter, so we create a non-blocking
/// socket, initiate the connect, then poll for completion.
fn connect_timeout(path: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    use std::os::unix::io::FromRawFd;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let ret = unsafe {
        libc::connect(
            fd,
            &make_sockaddr_un(path)? as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::WouldBlock
            && err.raw_os_error() != Some(libc::EINPROGRESS)
        {
            unsafe { libc::close(fd) };
            return Err(err);
        }

        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let poll_ret = unsafe { libc::poll(&mut pollfd as *mut _, 1, timeout_ms) };

        if poll_ret <= 0 {
            unsafe { libc::close(fd) };
            return if poll_ret == 0 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connect timed out",
                ))
            } else {
                Err(std::io::Error::last_os_error())
            };
        }

        let mut err_code: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err_code as *mut _ as *mut _,
                &mut len,
            );
        }
        if err_code != 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::from_raw_os_error(err_code));
        }
    }

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }

    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn make_sockaddr_un(path: &Path) -> std::io::Result<libc::sockaddr_un> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    addr.sun_path[..bytes.len()].copy_from_slice(unsafe {
        &*(bytes as *const [u8] as *const [i8])
    });
    Ok(addr)
}

/// Read a u32 big-endian from a byte slice, advancing the cursor.
fn read_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let end = *pos + 4;
    if end > buf.len() {
        return None;
    }
    let val = u32::from_be_bytes(buf[*pos..end].try_into().ok()?);
    *pos = end;
    Some(val)
}

/// Read a length-prefixed byte string from the wire format.
fn read_string<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = read_u32(buf, pos)? as usize;
    let end = *pos + len;
    if end > buf.len() {
        return None;
    }
    let val = &buf[*pos..end];
    *pos = end;
    Some(val)
}

fn fingerprint(key_blob: &[u8]) -> String {
    let hash = sha2::Sha256::digest(key_blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
    format!("SHA256:{b64}")
}

fn parse_identities(body: &[u8]) -> Option<Vec<Identity>> {
    let mut pos = 0;
    let nkeys = read_u32(body, &mut pos)?;
    let mut identities = Vec::with_capacity(nkeys as usize);

    for _ in 0..nkeys {
        let key_blob = read_string(body, &mut pos)?;

        // Key type is the first string inside the key blob
        let mut blob_pos = 0;
        let key_type_bytes = read_string(key_blob, &mut blob_pos)?;
        let key_type = String::from_utf8_lossy(key_type_bytes).into_owned();

        let comment_bytes = read_string(body, &mut pos)?;
        let comment = String::from_utf8_lossy(comment_bytes).into_owned();

        identities.push(Identity {
            key_type,
            fingerprint: fingerprint(key_blob),
            comment,
        });
    }

    Some(identities)
}

pub fn probe_agent(path: &Path, timeout: Duration) -> AgentStatus {
    let mut stream = match connect_timeout(path, timeout) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return AgentStatus::PermissionDenied;
        }
        Err(e) => return AgentStatus::Dead(e.to_string()),
    };

    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // Send SSH_AGENTC_REQUEST_IDENTITIES: length=1, type=11
    let request = [0u8, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];
    if let Err(e) = stream.write_all(&request) {
        return AgentStatus::Dead(e.to_string());
    }

    // Read response: 4-byte length + body
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        return AgentStatus::Dead(e.to_string());
    }
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    // Sanity cap: 10 MiB -- agents shouldn't send more than this
    if resp_len == 0 || resp_len > 10 * 1024 * 1024 {
        return AgentStatus::Dead(format!("bad response length: {resp_len}"));
    }

    let mut body = vec![0u8; resp_len];
    if let Err(e) = stream.read_exact(&mut body) {
        return AgentStatus::Dead(e.to_string());
    }

    // First byte is the message type
    if body[0] != SSH2_AGENT_IDENTITIES_ANSWER {
        return AgentStatus::Dead(format!("unexpected message type: {}", body[0]));
    }

    match parse_identities(&body[1..]) {
        Some(identities) => AgentStatus::Alive(identities),
        None => AgentStatus::Dead("malformed identities response".into()),
    }
}

pub fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}
