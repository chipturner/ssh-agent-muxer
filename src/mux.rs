use crate::proto;
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

pub struct MuxState {
    /// Pre-serialized IDENTITIES_ANSWER message body (type byte + payload)
    pub identities_response: Vec<u8>,
    /// key_blob -> backend socket path
    pub key_map: HashMap<Vec<u8>, PathBuf>,
    pub timeout: Duration,
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

    Ok(MuxState { identities_response: resp, key_map, timeout })
}

pub fn handle_client(mut stream: UnixStream, state: &MuxState) {
    loop {
        let msg = match proto::read_message(&mut stream) {
            Ok(m) => m,
            Err(_) => return,
        };

        if msg.is_empty() {
            let _ = proto::write_message(&mut stream, &[proto::SSH_AGENT_FAILURE]);
            continue;
        }

        match msg[0] {
            proto::SSH_AGENTC_REQUEST_IDENTITIES => {
                if proto::write_message(&mut stream, &state.identities_response).is_err() {
                    return;
                }
            }
            proto::SSH_AGENTC_SIGN_REQUEST => {
                let response = handle_sign_request(&msg, state);
                if proto::write_message(&mut stream, &response).is_err() {
                    return;
                }
            }
            _ => {
                if proto::write_message(&mut stream, &[proto::SSH_AGENT_FAILURE]).is_err() {
                    return;
                }
            }
        }
    }
}

fn handle_sign_request(msg: &[u8], state: &MuxState) -> Vec<u8> {
    let mut pos = 1; // skip type byte
    let Some(key_blob) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    let Some(backend_path) = state.key_map.get(key_blob) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    let mut backend = match proto::agent_connect(backend_path, state.timeout) {
        Ok(s) => s,
        Err(_) => return vec![proto::SSH_AGENT_FAILURE],
    };

    if proto::write_message(&mut backend, msg).is_err() {
        return vec![proto::SSH_AGENT_FAILURE];
    }

    match proto::read_message(&mut backend) {
        Ok(response) => response,
        Err(_) => vec![proto::SSH_AGENT_FAILURE],
    }
}
