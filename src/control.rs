use crate::mux::{LockState, MuxState};
use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

/// Handle a control socket connection. Reads one command, writes response, returns.
pub fn handle_control_client(
    stream: UnixStream,
    state: &ArcSwap<MuxState>,
    reload: &AtomicBool,
    lock: &LockState,
    start_time: Instant,
) {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();

    if reader.read_line(&mut line).is_err() {
        return;
    }

    let cmd = line.trim();
    let response = match cmd {
        "STATUS" => build_status(state, lock, start_time),
        "REFRESH" => {
            reload.store(true, Ordering::Relaxed);
            "OK\n".to_string()
        }
        _ => format!("ERR unknown command: {cmd}\n"),
    };

    let mut writer = reader.into_inner();
    let _ = writer.write_all(response.as_bytes());
    let _ = writer.flush();
}

fn build_status(state: &ArcSwap<MuxState>, lock: &LockState, start_time: Instant) -> String {
    let snap = state.load();
    let locked = lock.lock().unwrap().is_some();
    let uptime_secs = start_time.elapsed().as_secs();

    // Count keys per backend
    let mut backend_keys: HashMap<&std::path::Path, usize> = HashMap::new();
    for path in snap.key_map.values() {
        *backend_keys.entry(path.as_path()).or_default() += 1;
    }

    let mut backends = Vec::new();
    for (path, key_count) in &backend_keys {
        backends.push(format!(r#"    {{"path": "{}", "keys": {key_count}}}"#, path.display()));
    }

    let backends_json = backends.join(",\n");

    format!(
        r#"{{"pid": {}, "uptime_secs": {uptime_secs}, "locked": {locked}, "total_keys": {}, "backends": [
{backends_json}
]}}
"#,
        std::process::id(),
        snap.key_map.len(),
    )
}
