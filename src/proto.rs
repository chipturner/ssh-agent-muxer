use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

const MAX_MESSAGE_LEN: usize = 10 * 1024 * 1024; // 10 MiB

/// Read a u32 big-endian from a byte slice, advancing the cursor.
pub fn read_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let end = *pos + 4;
    if end > buf.len() {
        return None;
    }
    let val = u32::from_be_bytes(buf[*pos..end].try_into().ok()?);
    *pos = end;
    Some(val)
}

/// Read a length-prefixed byte string from the wire format.
pub fn read_string<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = read_u32(buf, pos)? as usize;
    let end = *pos + len;
    if end > buf.len() {
        return None;
    }
    let val = &buf[*pos..end];
    *pos = end;
    Some(val)
}

/// Write a u32 big-endian to a byte vector.
pub fn put_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Write a length-prefixed byte string to a byte vector.
pub fn put_string(buf: &mut Vec<u8>, data: &[u8]) {
    put_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

/// Read a complete agent protocol message. Returns the body (including type byte).
pub fn read_message(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len == 0 || len > MAX_MESSAGE_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad message length: {len}"),
        ));
    }

    let mut body = vec![0u8; len];
    stream.read_exact(&mut body)?;
    Ok(body)
}

/// Write a complete agent protocol message (length prefix + body).
pub fn write_message(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let len = (body.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(body)?;
    stream.flush()
}

/// Connect to an agent socket with timeouts set.
pub fn agent_connect(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let stream = connect_timeout(path, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

/// Connect to a Unix socket with a timeout on the connect itself.
fn connect_timeout(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    use std::os::unix::io::FromRawFd;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe {
        libc::connect(
            fd,
            &make_sockaddr_un(path)? as *const libc::sockaddr_un as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::WouldBlock
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
                Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))
            } else {
                Err(io::Error::last_os_error())
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
            return Err(io::Error::from_raw_os_error(err_code));
        }
    }

    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK);
    }

    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

fn make_sockaddr_un(path: &Path) -> io::Result<libc::sockaddr_un> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_os_str().as_bytes();
    if bytes.len() >= 108 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "socket path too long",
        ));
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    addr.sun_path[..bytes.len()]
        .copy_from_slice(unsafe { &*(bytes as *const [u8] as *const [i8]) });
    Ok(addr)
}
