use crate::mux::MuxState;
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[derive(Serialize, Deserialize)]
pub struct StatusResponse {
    pub pid: u32,
    pub uptime_secs: u64,
    pub locked: bool,
    pub total_keys: usize,
    pub backends: Vec<BackendInfo>,
}

#[derive(Serialize, Deserialize)]
pub struct BackendInfo {
    pub path: String,
    pub keys: usize,
}

/// Handle a control socket connection. Reads one command, writes response, returns.
pub fn handle_control_client(
    stream: UnixStream,
    state: &ArcSwap<MuxState>,
    reload: &AtomicBool,
    locked: &AtomicBool,
    start_time: Instant,
    discover_fn: Option<&dyn Fn()>,
) {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();

    if reader.read_line(&mut line).is_err() {
        return;
    }

    let cmd = line.trim();
    let response = match cmd {
        "STATUS" => {
            let status = build_status(state, locked, start_time);
            serde_json::to_string(&status).unwrap_or_else(|e| format!("ERR {e}")) + "\n"
        }
        "REFRESH" => {
            if let Some(f) = discover_fn {
                f();
            } else {
                reload.store(true, Ordering::Relaxed);
            }
            let snap = state.load();
            format!("OK {} keys\n", snap.key_map.len())
        }
        _ => format!("ERR unknown command: {cmd}\n"),
    };

    let mut writer = reader.into_inner();
    let _ = writer.write_all(response.as_bytes());
    let _ = writer.flush();
}

fn build_status(
    state: &ArcSwap<MuxState>,
    locked: &AtomicBool,
    start_time: Instant,
) -> StatusResponse {
    let snap = state.load();

    let mut backend_keys: HashMap<&std::path::Path, usize> = HashMap::new();
    for path in snap.key_map.values() {
        *backend_keys.entry(path.as_path()).or_default() += 1;
    }

    let mut backends: Vec<BackendInfo> = backend_keys
        .into_iter()
        .map(|(path, keys)| BackendInfo { path: path.display().to_string(), keys })
        .collect();
    backends.sort_by(|a, b| a.path.cmp(&b.path));

    StatusResponse {
        pid: std::process::id(),
        uptime_secs: start_time.elapsed().as_secs(),
        locked: locked.load(Ordering::Relaxed),
        total_keys: snap.key_map.len(),
        backends,
    }
}

/// Format a StatusResponse for human-readable CLI output.
pub fn format_status_human(json: &str) -> String {
    let Ok(status) = serde_json::from_str::<StatusResponse>(json) else {
        return json.to_string();
    };

    let uptime = format_uptime(status.uptime_secs);
    let lock_str = if status.locked { "yes" } else { "no" };

    let mut out = format!("ssh-agent-mux (pid {}, up {uptime})\n", status.pid);
    out.push_str(&format!("  locked: {lock_str}\n"));

    if status.backends.is_empty() {
        out.push_str("  backends: (none)\n");
    } else {
        out.push_str("  backends:\n");
        for b in &status.backends {
            let label = if b.keys == 1 { "key" } else { "keys" };
            out.push_str(&format!("    {}  {} {label}\n", b.path, b.keys));
        }
    }

    let label = if status.total_keys == 1 { "key" } else { "keys" };
    out.push_str(&format!("  total: {} {label}\n", status.total_keys));
    out
}

fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m}m")
    }
}
