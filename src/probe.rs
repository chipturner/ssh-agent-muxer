use crate::proto::{self, SSH_AGENTC_REQUEST_IDENTITIES, SSH2_AGENT_IDENTITIES_ANSWER};
use base64::Engine;
use sha2::Digest;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Identity {
    pub key_type: String,
    pub fingerprint: String,
    pub comment: String,
}

#[derive(Debug)]
pub enum AgentStatus {
    Alive(Vec<Identity>),
    Dead(String),
    PermissionDenied,
}

fn fingerprint(key_blob: &[u8]) -> String {
    let hash = sha2::Sha256::digest(key_blob);
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
    format!("SHA256:{b64}")
}

fn parse_identities(body: &[u8]) -> Option<Vec<Identity>> {
    let mut pos = 0;
    let nkeys = proto::read_u32(body, &mut pos)?;
    let mut identities = Vec::with_capacity(nkeys as usize);

    for _ in 0..nkeys {
        let key_blob = proto::read_string(body, &mut pos)?;

        let mut blob_pos = 0;
        let key_type_bytes = proto::read_string(key_blob, &mut blob_pos)?;
        let key_type = String::from_utf8_lossy(key_type_bytes).into_owned();

        let comment_bytes = proto::read_string(body, &mut pos)?;
        let comment = String::from_utf8_lossy(comment_bytes).into_owned();

        identities.push(Identity { key_type, fingerprint: fingerprint(key_blob), comment });
    }

    Some(identities)
}

pub fn probe_agent(path: &Path, timeout: Duration) -> AgentStatus {
    let mut stream = match proto::agent_connect(path, timeout) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return AgentStatus::PermissionDenied;
        }
        Err(e) => return AgentStatus::Dead(e.to_string()),
    };

    let request = [0u8, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];
    if let Err(e) = stream.write_all(&request) {
        return AgentStatus::Dead(e.to_string());
    }

    let body = match proto::read_message(&mut stream) {
        Ok(b) => b,
        Err(e) => return AgentStatus::Dead(e.to_string()),
    };

    if body.is_empty() || body[0] != SSH2_AGENT_IDENTITIES_ANSWER {
        return AgentStatus::Dead(format!(
            "unexpected message type: {}",
            body.first().unwrap_or(&0)
        ));
    }

    match parse_identities(&body[1..]) {
        Some(identities) => AgentStatus::Alive(identities),
        None => AgentStatus::Dead("malformed identities response".into()),
    }
}

pub fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}
