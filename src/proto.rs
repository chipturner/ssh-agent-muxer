use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENT_SUCCESS: u8 = 6;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH2_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;

/// Write operations -- forwarded to primary agent if configured.
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
pub const SSH_AGENTC_REMOVE_ALL_IDENTITIES: u8 = 19;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY: u8 = 20;
pub const SSH_AGENTC_REMOVE_SMARTCARD_KEY: u8 = 21;
pub const SSH_AGENTC_LOCK: u8 = 22;
pub const SSH_AGENTC_UNLOCK: u8 = 23;
pub const SSH_AGENTC_ADD_ID_CONSTRAINED: u8 = 25;
pub const SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
pub const SSH_AGENTC_EXTENSION: u8 = 27;
pub const SSH_AGENT_EXTENSION_FAILURE: u8 = 28;

pub fn msg_type_name(t: u8) -> &'static str {
    match t {
        SSH_AGENT_FAILURE => "FAILURE",
        SSH_AGENT_SUCCESS => "SUCCESS",
        SSH_AGENTC_REQUEST_IDENTITIES => "REQUEST_IDENTITIES",
        SSH2_AGENT_IDENTITIES_ANSWER => "IDENTITIES_ANSWER",
        SSH_AGENTC_SIGN_REQUEST => "SIGN_REQUEST",
        14 => "SIGN_RESPONSE",
        SSH_AGENTC_ADD_IDENTITY => "ADD_IDENTITY",
        SSH_AGENTC_REMOVE_IDENTITY => "REMOVE_IDENTITY",
        SSH_AGENTC_REMOVE_ALL_IDENTITIES => "REMOVE_ALL_IDENTITIES",
        SSH_AGENTC_ADD_SMARTCARD_KEY => "ADD_SMARTCARD_KEY",
        SSH_AGENTC_REMOVE_SMARTCARD_KEY => "REMOVE_SMARTCARD_KEY",
        SSH_AGENTC_LOCK => "LOCK",
        SSH_AGENTC_UNLOCK => "UNLOCK",
        SSH_AGENTC_ADD_ID_CONSTRAINED => "ADD_ID_CONSTRAINED",
        SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED => "ADD_SMARTCARD_KEY_CONSTRAINED",
        SSH_AGENTC_EXTENSION => "EXTENSION",
        SSH_AGENT_EXTENSION_FAILURE => "EXTENSION_FAILURE",
        _ => "UNKNOWN",
    }
}

/// Operations that require a primary agent (add key, smartcard ops).
pub fn is_add_operation(msg_type: u8) -> bool {
    matches!(
        msg_type,
        SSH_AGENTC_ADD_IDENTITY
            | SSH_AGENTC_ADD_ID_CONSTRAINED
            | SSH_AGENTC_ADD_SMARTCARD_KEY
            | SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED
            | SSH_AGENTC_REMOVE_SMARTCARD_KEY
    )
}

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
        if err.kind() != io::ErrorKind::WouldBlock && err.raw_os_error() != Some(libc::EINPROGRESS)
        {
            unsafe { libc::close(fd) };
            return Err(err);
        }

        let mut pollfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
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
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "socket path too long"));
    }

    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (i, &byte) in bytes.iter().enumerate() {
        addr.sun_path[i] = byte as libc::c_char;
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_u32() {
        let buf = [0x00, 0x00, 0x00, 0x2A]; // 42
        let mut pos = 0;
        assert_eq!(read_u32(&buf, &mut pos), Some(42));
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_read_u32_truncated() {
        let buf = [0x00, 0x00];
        let mut pos = 0;
        assert_eq!(read_u32(&buf, &mut pos), None);
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_read_u32_empty() {
        let mut pos = 0;
        assert_eq!(read_u32(&[], &mut pos), None);
    }

    #[test]
    fn test_read_u32_at_offset() {
        let buf = [0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01];
        let mut pos = 2;
        assert_eq!(read_u32(&buf, &mut pos), Some(1));
        assert_eq!(pos, 6);
    }

    #[test]
    fn test_read_string() {
        let mut buf = Vec::new();
        put_string(&mut buf, b"hello");
        let mut pos = 0;
        assert_eq!(read_string(&buf, &mut pos), Some(b"hello".as_slice()));
        assert_eq!(pos, buf.len());
    }

    #[test]
    fn test_read_string_truncated_length() {
        let buf = [0x00, 0x00]; // not enough for u32 length
        let mut pos = 0;
        assert_eq!(read_string(&buf, &mut pos), None);
    }

    #[test]
    fn test_read_string_truncated_data() {
        let buf = [0x00, 0x00, 0x00, 0x0A, 0x01, 0x02]; // claims 10 bytes, only 2
        let mut pos = 0;
        assert_eq!(read_string(&buf, &mut pos), None);
    }

    #[test]
    fn test_read_string_empty() {
        let mut buf = Vec::new();
        put_string(&mut buf, b"");
        let mut pos = 0;
        assert_eq!(read_string(&buf, &mut pos), Some(b"".as_slice()));
    }

    #[test]
    fn test_put_u32_roundtrip() {
        for val in [0u32, 1, 255, 65536, u32::MAX] {
            let mut buf = Vec::new();
            put_u32(&mut buf, val);
            let mut pos = 0;
            assert_eq!(read_u32(&buf, &mut pos), Some(val));
        }
    }

    #[test]
    fn test_put_string_roundtrip() {
        for data in [b"".as_slice(), b"x", b"hello world", &[0xFF; 256]] {
            let mut buf = Vec::new();
            put_string(&mut buf, data);
            let mut pos = 0;
            assert_eq!(read_string(&buf, &mut pos), Some(data));
        }
    }

    #[test]
    fn test_read_write_message_roundtrip() {
        let body = vec![11u8, 0, 0, 0, 1]; // REQUEST_IDENTITIES-like
        let mut wire = Vec::new();
        write_message(&mut wire, &body).unwrap();

        let mut cursor = Cursor::new(&wire);
        let got = read_message(&mut cursor).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn test_read_message_zero_length() {
        let wire = [0u8, 0, 0, 0]; // length = 0
        let mut cursor = Cursor::new(&wire);
        let err = read_message(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_read_message_excessive_length() {
        // length = 20 MiB (over 10 MiB cap)
        let wire = 20u32.wrapping_mul(1024 * 1024).to_be_bytes();
        let mut cursor = Cursor::new(&wire);
        let err = read_message(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_multiple_strings_sequential() {
        let mut buf = Vec::new();
        put_string(&mut buf, b"first");
        put_string(&mut buf, b"second");
        put_string(&mut buf, b"third");

        let mut pos = 0;
        assert_eq!(read_string(&buf, &mut pos), Some(b"first".as_slice()));
        assert_eq!(read_string(&buf, &mut pos), Some(b"second".as_slice()));
        assert_eq!(read_string(&buf, &mut pos), Some(b"third".as_slice()));
        assert_eq!(read_string(&buf, &mut pos), None); // exhausted
    }
}
