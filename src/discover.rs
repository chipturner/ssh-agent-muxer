use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub struct Discovery {
    /// socket path -> set of PIDs that reference it
    pub sockets: HashMap<PathBuf, HashSet<u32>>,
    /// agent PID (from SSH_AGENT_PID) -> set of PIDs that reference it
    pub agent_pids: HashMap<u32, HashSet<u32>>,
}

struct ProcEnv {
    pid: u32,
    ssh_auth_sock: Option<PathBuf>,
    ssh_agent_pid: Option<u32>,
}

fn read_proc_env(pid: u32) -> Option<ProcEnv> {
    let data = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    let mut ssh_auth_sock = None;
    let mut ssh_agent_pid = None;

    for chunk in data.split(|&b| b == 0) {
        if chunk.is_empty() {
            continue;
        }
        let s = String::from_utf8_lossy(chunk);
        if let Some(val) = s.strip_prefix("SSH_AUTH_SOCK=") {
            if !val.is_empty() {
                ssh_auth_sock = Some(PathBuf::from(val));
            }
        } else if let Some(val) = s.strip_prefix("SSH_AGENT_PID=") {
            ssh_agent_pid = val.parse().ok();
        }
    }

    Some(ProcEnv { pid, ssh_auth_sock, ssh_agent_pid })
}

pub fn discover() -> anyhow::Result<Discovery> {
    let mut sockets: HashMap<PathBuf, HashSet<u32>> = HashMap::new();
    let mut agent_pids: HashMap<u32, HashSet<u32>> = HashMap::new();

    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };

        let Some(env) = read_proc_env(pid) else {
            continue;
        };

        if let Some(sock) = env.ssh_auth_sock {
            sockets.entry(sock).or_default().insert(env.pid);
        }
        if let Some(agent_pid) = env.ssh_agent_pid {
            agent_pids.entry(agent_pid).or_default().insert(env.pid);
        }
    }

    Ok(Discovery { sockets, agent_pids })
}

/// Scan well-known filesystem locations for agent sockets that may not
/// appear in any process's environment (e.g. orphaned agents).
pub fn scan_socket_dirs() -> Vec<PathBuf> {
    let mut sockets = Vec::new();
    scan_ssh_dirs("/tmp", &mut sockets);

    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        scan_dir_for_agent_sockets(Path::new(&dir), &mut sockets);
    }

    sockets
}

fn scan_ssh_dirs(base: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(base) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str().is_some_and(|s| s.starts_with("ssh-")) {
            scan_dir_for_agent_sockets(&entry.path(), out);
        }
    }
}

fn scan_dir_for_agent_sockets(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_str().is_some_and(|s| s.starts_with("agent.")) && is_socket(&entry.path()) {
            out.push(entry.path());
        }
    }
}

fn is_socket(path: &Path) -> bool {
    use std::os::unix::fs::FileTypeExt;
    fs::symlink_metadata(path).map(|m| m.file_type().is_socket()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn test_scan_socket_dirs_finds_ssh_agent_sockets() {
        let dir_name = format!("ssh-test-scan-{}", std::process::id());
        let dir_path = PathBuf::from("/tmp").join(&dir_name);
        let _ = fs::remove_dir_all(&dir_path);
        fs::create_dir(&dir_path).unwrap();

        let sock_path = dir_path.join("agent.12345");
        let _listener = UnixListener::bind(&sock_path).unwrap();

        let found = scan_socket_dirs();
        let _ = fs::remove_dir_all(&dir_path);

        assert!(
            found.contains(&sock_path),
            "scan_socket_dirs should find {}, got: {found:?}",
            sock_path.display()
        );
    }

    #[test]
    fn test_scan_ignores_non_socket_files() {
        let dir_name = format!("ssh-test-nosock-{}", std::process::id());
        let dir_path = PathBuf::from("/tmp").join(&dir_name);
        let _ = fs::remove_dir_all(&dir_path);
        fs::create_dir(&dir_path).unwrap();

        // Regular file named like an agent socket
        fs::write(dir_path.join("agent.99999"), "not a socket").unwrap();

        let found = scan_socket_dirs();
        let _ = fs::remove_dir_all(&dir_path);

        assert!(!found.iter().any(|p| p.ends_with("agent.99999")), "should not find regular files");
    }
}
