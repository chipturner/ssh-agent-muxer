use crate::proto;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct MuxState {
    /// Pre-serialized IDENTITIES_ANSWER message body (type byte + payload)
    pub identities_response: Vec<u8>,
    /// key_blob -> backend socket path
    pub key_map: HashMap<Vec<u8>, PathBuf>,
    pub timeout: Duration,
    /// Agent to forward write operations to (add/remove key, lock/unlock).
    /// If None, write operations return FAILURE.
    pub primary_agent: Option<PathBuf>,
}

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

/// Handle a single client connection.
/// `reload` is an optional flag set after write operations to trigger state refresh.
pub fn handle_client(mut stream: UnixStream, state: &MuxState, reload: Option<&AtomicBool>) {
    loop {
        let msg = match proto::read_message(&mut stream) {
            Ok(m) => m,
            Err(_) => return,
        };

        if msg.is_empty() {
            let _ = proto::write_message(&mut stream, &[proto::SSH_AGENT_FAILURE]);
            continue;
        }

        let response = match msg[0] {
            proto::SSH_AGENTC_REQUEST_IDENTITIES => state.identities_response.clone(),
            proto::SSH_AGENTC_SIGN_REQUEST => handle_sign_request(&msg, state, reload),
            proto::SSH_AGENTC_EXTENSION => handle_extension(&msg, state, reload),
            t if proto::is_write_operation(t) => handle_write_operation(&msg, state, reload),
            _ => vec![proto::SSH_AGENT_FAILURE],
        };

        if proto::write_message(&mut stream, &response).is_err() {
            return;
        }
    }
}

fn handle_write_operation(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let Some(primary) = &state.primary_agent else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    let response = forward_to_backend(primary, msg, state.timeout, None);

    // Always trigger refresh after write so new/removed keys are visible
    set_reload(reload);

    response
}

fn handle_sign_request(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let mut pos = 1; // skip type byte
    let Some(key_blob) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    let Some(backend_path) = state.key_map.get(key_blob) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    forward_to_backend(backend_path, msg, state.timeout, reload)
}

/// Forward a message to a specific backend agent and return the response.
/// Sets the reload flag on backend I/O failure so dead backends are pruned.
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

/// Handle SSH_AGENTC_EXTENSION (type 27).
/// Routes session-bind@openssh.com by key blob to the correct backend.
/// Returns EXTENSION_FAILURE (28) for unknown extensions.
fn handle_extension(msg: &[u8], state: &MuxState, reload: Option<&AtomicBool>) -> Vec<u8> {
    let mut pos = 1; // skip type byte
    let Some(ext_name) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_EXTENSION_FAILURE];
    };

    if ext_name == b"session-bind@openssh.com" {
        // Second field is the key blob -- route like a sign request
        let Some(key_blob) = proto::read_string(msg, &mut pos) else {
            return vec![proto::SSH_AGENT_EXTENSION_FAILURE];
        };
        let Some(backend_path) = state.key_map.get(key_blob) else {
            return vec![proto::SSH_AGENT_EXTENSION_FAILURE];
        };
        return forward_to_backend(backend_path, msg, state.timeout, reload);
    }

    // Unknown extension
    vec![proto::SSH_AGENT_EXTENSION_FAILURE]
}
