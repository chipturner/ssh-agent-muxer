use crate::proto;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct MuxState {
    /// Pre-serialized IDENTITIES_ANSWER message body (type byte + payload)
    pub identities_response: Vec<u8>,
    /// key_blob -> backend socket path
    pub key_map: HashMap<Vec<u8>, PathBuf>,
    pub timeout: Duration,
    /// Agent to forward add operations to. If None, adds return FAILURE.
    pub primary_agent: Option<PathBuf>,
}

/// Mux-level lock state. Lives outside MuxState so it persists across ArcSwap refreshes.
/// Some(sha256_hash) when locked, None when unlocked.
pub type LockState = Mutex<Option<[u8; 32]>>;

/// Build mux state, skipping backend sockets that fail security validation.
pub fn build_mux_state_validated(
    sockets: &[PathBuf],
    timeout: Duration,
) -> anyhow::Result<MuxState> {
    let valid: Vec<PathBuf> = sockets
        .iter()
        .filter(|p| match crate::security::validate_backend_socket(p) {
            Ok(()) => true,
            Err(reason) => {
                log::warn!("Skipping {}: {reason}", p.display());
                false
            }
        })
        .cloned()
        .collect();
    build_mux_state_from_sockets(&valid, timeout)
}

/// Build mux state from an explicit list of agent socket paths.
pub fn build_mux_state_from_sockets(
    sockets: &[PathBuf],
    timeout: Duration,
) -> anyhow::Result<MuxState> {
    let mut key_map: HashMap<Vec<u8>, PathBuf> = HashMap::new();
    let mut merged_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for path in sockets {
        let mut stream = match proto::agent_connect(path, timeout) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let request = [0u8, 0, 0, 1, proto::SSH_AGENTC_REQUEST_IDENTITIES];
        if stream.write_all(&request).is_err() {
            continue;
        }

        let body = match proto::read_message(&mut stream) {
            Ok(b) if !b.is_empty() && b[0] == proto::SSH2_AGENT_IDENTITIES_ANSWER => b,
            _ => continue,
        };

        let payload = &body[1..];
        let mut pos = 0;
        let Some(nkeys) = proto::read_u32(payload, &mut pos) else {
            continue;
        };

        for _ in 0..nkeys {
            let Some(key_blob) = proto::read_string(payload, &mut pos) else {
                break;
            };
            let Some(comment) = proto::read_string(payload, &mut pos) else {
                break;
            };

            if !key_map.contains_key(key_blob) {
                key_map.insert(key_blob.to_vec(), path.clone());
                merged_keys.push((key_blob.to_vec(), comment.to_vec()));
            }
        }
    }

    let mut resp = Vec::new();
    resp.push(proto::SSH2_AGENT_IDENTITIES_ANSWER);
    proto::put_u32(&mut resp, merged_keys.len() as u32);
    for (key_blob, comment) in &merged_keys {
        proto::put_string(&mut resp, key_blob);
        proto::put_string(&mut resp, comment);
    }

    Ok(MuxState { identities_response: resp, key_map, timeout, primary_agent: None })
}

// --- Empty identities response (used when locked) ---

fn empty_identities() -> Vec<u8> {
    let mut resp = Vec::new();
    resp.push(proto::SSH2_AGENT_IDENTITIES_ANSWER);
    proto::put_u32(&mut resp, 0);
    resp
}

// --- Client handling ---

/// Handle a single client connection.
pub fn handle_client(
    mut stream: UnixStream,
    state: &MuxState,
    reload: Option<&AtomicBool>,
    lock: Option<&LockState>,
) {
    loop {
        let msg = match proto::read_message(&mut stream) {
            Ok(m) => m,
            Err(_) => return,
        };

        if msg.is_empty() {
            let _ = proto::write_message(&mut stream, &[proto::SSH_AGENT_FAILURE]);
            continue;
        }

        let locked = lock.is_some_and(|l| l.lock().unwrap().is_some());

        let response = match msg[0] {
            // Unlock is always allowed
            proto::SSH_AGENTC_UNLOCK => handle_unlock(&msg, lock),

            // When locked, gate everything except unlock
            _ if locked => match msg[0] {
                proto::SSH_AGENTC_REQUEST_IDENTITIES => empty_identities(),
                proto::SSH_AGENTC_LOCK => vec![proto::SSH_AGENT_FAILURE], // already locked
                proto::SSH_AGENTC_EXTENSION => vec![proto::SSH_AGENT_EXTENSION_FAILURE],
                _ => vec![proto::SSH_AGENT_FAILURE],
            },

            // Normal (unlocked) dispatch
            proto::SSH_AGENTC_REQUEST_IDENTITIES => state.identities_response.clone(),
            proto::SSH_AGENTC_SIGN_REQUEST => handle_sign_request(&msg, state, reload),
            proto::SSH_AGENTC_EXTENSION => handle_extension(&msg, state, reload),
            proto::SSH_AGENTC_LOCK => handle_lock(&msg, lock),
            proto::SSH_AGENTC_REMOVE_IDENTITY => handle_remove_identity(&msg, state, reload),
            proto::SSH_AGENTC_REMOVE_ALL_IDENTITIES => handle_remove_all(&msg, state, reload),
            t if proto::is_add_operation(t) => handle_add(&msg, state, reload),
            _ => vec![proto::SSH_AGENT_FAILURE],
        };

        if proto::write_message(&mut stream, &response).is_err() {
            return;
        }
    }
}

// --- Lock/Unlock ---

fn handle_lock(msg: &[u8], lock: Option<&LockState>) -> Vec<u8> {
    let Some(lock) = lock else {
        return vec![proto::SSH_AGENT_FAILURE];
    };
    let mut pos = 1;
    let Some(passphrase) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    let hash = Sha256::digest(passphrase);
    let mut guard = lock.lock().unwrap();
    if guard.is_some() {
        return vec![proto::SSH_AGENT_FAILURE]; // already locked
    }
    *guard = Some(hash.into());
    vec![proto::SSH_AGENT_SUCCESS]
}

fn handle_unlock(msg: &[u8], lock: Option<&LockState>) -> Vec<u8> {
    let Some(lock) = lock else {
        return vec![proto::SSH_AGENT_FAILURE];
    };
    let mut pos = 1;
    let Some(passphrase) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    let hash: [u8; 32] = Sha256::digest(passphrase).into();
    let mut guard = lock.lock().unwrap();
    match *guard {
        Some(stored) if stored == hash => {
            *guard = None;
            vec![proto::SSH_AGENT_SUCCESS]
        }
        _ => vec![proto::SSH_AGENT_FAILURE],
    }
}

// --- Write operations ---

fn handle_add(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let Some(primary) = &state.primary_agent else {
        return vec![proto::SSH_AGENT_FAILURE];
    };
    let response = forward_to_backend(primary, msg, state.timeout, None);
    set_reload(reload);
    response
}

fn handle_remove_identity(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let mut pos = 1;
    let Some(key_blob) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };
    let Some(backend_path) = state.key_map.get(key_blob) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };
    let response = forward_to_backend(backend_path, msg, state.timeout, reload);
    set_reload(reload);
    response
}

fn handle_remove_all(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let backends: HashSet<&PathBuf> = state.key_map.values().collect();
    let mut any_success = false;

    for backend in backends {
        let resp = forward_to_backend(backend, msg, state.timeout, reload);
        if resp.first() == Some(&proto::SSH_AGENT_SUCCESS) {
            any_success = true;
        }
    }

    set_reload(reload);

    if any_success {
        vec![proto::SSH_AGENT_SUCCESS]
    } else if state.key_map.is_empty() {
        // No backends to remove from -- that's fine
        vec![proto::SSH_AGENT_SUCCESS]
    } else {
        vec![proto::SSH_AGENT_FAILURE]
    }
}

// --- Sign + Extension ---

fn handle_sign_request(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let mut pos = 1;
    let Some(key_blob) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };
    let Some(backend_path) = state.key_map.get(key_blob) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };
    forward_to_backend(backend_path, msg, state.timeout, reload)
}

fn handle_extension(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let mut pos = 1;
    let Some(ext_name) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_EXTENSION_FAILURE];
    };

    if ext_name == b"session-bind@openssh.com" {
        let Some(key_blob) = proto::read_string(msg, &mut pos) else {
            return vec![proto::SSH_AGENT_EXTENSION_FAILURE];
        };
        let Some(backend_path) = state.key_map.get(key_blob) else {
            return vec![proto::SSH_AGENT_EXTENSION_FAILURE];
        };
        return forward_to_backend(backend_path, msg, state.timeout, reload);
    }

    vec![proto::SSH_AGENT_EXTENSION_FAILURE]
}

// --- Backend forwarding ---

fn forward_to_backend(
    backend_path: &Path,
    msg: &[u8],
    timeout: Duration,
    reload: Option<&AtomicBool>,
) -> Vec<u8> {
    let mut backend = match proto::agent_connect(backend_path, timeout) {
        Ok(s) => s,
        Err(_) => {
            set_reload(reload);
            return vec![proto::SSH_AGENT_FAILURE];
        }
    };

    if proto::write_message(&mut backend, msg).is_err() {
        set_reload(reload);
        return vec![proto::SSH_AGENT_FAILURE];
    }

    match proto::read_message(&mut backend) {
        Ok(response) => response,
        Err(_) => {
            set_reload(reload);
            vec![proto::SSH_AGENT_FAILURE]
        }
    }
}

fn set_reload(reload: Option<&AtomicBool>) {
    if let Some(flag) = reload {
        flag.store(true, Ordering::Relaxed);
    }
}
