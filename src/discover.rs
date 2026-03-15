use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

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

    Some(ProcEnv {
        pid,
        ssh_auth_sock,
        ssh_agent_pid,
    })
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

    Ok(Discovery {
        sockets,
        agent_pids,
    })
}
