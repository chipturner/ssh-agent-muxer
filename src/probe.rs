use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;

#[derive(Debug)]
pub enum AgentStatus {
    Alive { num_identities: u32 },
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

    // Initiate non-blocking connect
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

        // Poll for connect completion
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

        // Check for connect error via SO_ERROR
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

    // Switch back to blocking mode
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }

    // SAFETY: fd is a valid, connected Unix stream socket
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

    // Read response header: 4-byte length + 1-byte type
    let mut header = [0u8; 5];
    if let Err(e) = stream.read_exact(&mut header) {
        return AgentStatus::Dead(e.to_string());
    }

    let msg_type = header[4];
    if msg_type != SSH2_AGENT_IDENTITIES_ANSWER {
        return AgentStatus::Dead(format!("unexpected message type: {msg_type}"));
    }

    // Read nkeys (u32 big-endian)
    let mut nkeys_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut nkeys_buf) {
        return AgentStatus::Dead(e.to_string());
    }

    AgentStatus::Alive {
        num_identities: u32::from_be_bytes(nkeys_buf),
    }
}

pub fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}
