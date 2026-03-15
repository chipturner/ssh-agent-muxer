use anyhow::{bail, Context};
use clap::Parser;
use ssh_agent_fixer::discover;
use ssh_agent_fixer::proto::{self, SSH_AGENTC_REQUEST_IDENTITIES, SSH_AGENTC_SIGN_REQUEST};
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};

#[derive(Parser)]
#[command(name = "ssh-agent-mux", about = "Multiplex SSH agents into one")]
struct Cli {
    /// Socket timeout in seconds
    #[arg(short, long, default_value = "2")]
    timeout: u64,

    /// Socket path (default: /tmp/ssh-agent-mux-{PID}/agent.{PID})
    #[arg(short, long)]
    socket: Option<PathBuf>,
}

struct MuxState {
    /// Pre-serialized IDENTITIES_ANSWER message body (type byte + payload)
    identities_response: Vec<u8>,
    /// key_blob -> backend socket path
    key_map: HashMap<Vec<u8>, PathBuf>,
    timeout: Duration,
}

/// Discover live agents, collect their identities, build the merged state.
fn build_mux_state(timeout: Duration) -> anyhow::Result<MuxState> {
    let discovery = discover::discover()?;

    let mut key_map: HashMap<Vec<u8>, PathBuf> = HashMap::new();
    // Collect (key_blob, comment) pairs in insertion order for the response
    let mut merged_keys: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    let mut socket_paths: Vec<_> = discovery.sockets.keys().collect();
    socket_paths.sort();

    for path in socket_paths {
        let mut stream = match proto::agent_connect(path, timeout) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let request = [0u8, 0, 0, 1, SSH_AGENTC_REQUEST_IDENTITIES];
        if stream.write_all(&request).is_err() {
            continue;
        }

        let body = match proto::read_message(&mut stream) {
            Ok(b) if !b.is_empty() && b[0] == proto::SSH2_AGENT_IDENTITIES_ANSWER => b,
            _ => continue,
        };

        // Parse identities from the response body (skip type byte)
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

            // Deduplicate: first backend wins
            if !key_map.contains_key(key_blob) {
                key_map.insert(key_blob.to_vec(), path.clone());
                merged_keys.push((key_blob.to_vec(), comment.to_vec()));
            }
        }
    }

    // Build the pre-serialized IDENTITIES_ANSWER
    let mut resp = Vec::new();
    resp.push(proto::SSH2_AGENT_IDENTITIES_ANSWER);
    proto::put_u32(&mut resp, merged_keys.len() as u32);
    for (key_blob, comment) in &merged_keys {
        proto::put_string(&mut resp, key_blob);
        proto::put_string(&mut resp, comment);
    }

    eprintln!(
        "Discovered {} keys across {} backends",
        merged_keys.len(),
        key_map.values().collect::<std::collections::HashSet<_>>().len()
    );

    Ok(MuxState {
        identities_response: resp,
        key_map,
        timeout,
    })
}

fn handle_client(mut stream: std::os::unix::net::UnixStream, state: &MuxState) {
    loop {
        let msg = match proto::read_message(&mut stream) {
            Ok(m) => m,
            Err(_) => return, // client disconnected or error
        };

        if msg.is_empty() {
            let _ = proto::write_message(&mut stream, &[proto::SSH_AGENT_FAILURE]);
            continue;
        }

        match msg[0] {
            SSH_AGENTC_REQUEST_IDENTITIES => {
                if proto::write_message(&mut stream, &state.identities_response).is_err() {
                    return;
                }
            }
            SSH_AGENTC_SIGN_REQUEST => {
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
    // Parse key_blob from: [type=13][string key_blob][string data][uint32 flags]
    let mut pos = 1; // skip type byte
    let Some(key_blob) = proto::read_string(msg, &mut pos) else {
        return vec![proto::SSH_AGENT_FAILURE];
    };

    let Some(backend_path) = state.key_map.get(key_blob) else {
        eprintln!("No backend for key, rejecting sign request");
        return vec![proto::SSH_AGENT_FAILURE];
    };

    // Connect to backend, forward the entire message, relay response
    let mut backend = match proto::agent_connect(backend_path, state.timeout) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Backend connect failed: {e}");
            return vec![proto::SSH_AGENT_FAILURE];
        }
    };

    if proto::write_message(&mut backend, msg).is_err() {
        return vec![proto::SSH_AGENT_FAILURE];
    }

    match proto::read_message(&mut backend) {
        Ok(response) => response,
        Err(_) => vec![proto::SSH_AGENT_FAILURE],
    }
}

fn create_socket(path: Option<&Path>) -> anyhow::Result<(UnixListener, PathBuf, Option<PathBuf>)> {
    if let Some(p) = path {
        let listener = UnixListener::bind(p).context("binding socket")?;
        return Ok((listener, p.to_path_buf(), None));
    }

    let pid = std::process::id();
    let dir = PathBuf::from(format!("/tmp/ssh-agent-mux-{pid}"));
    fs::create_dir_all(&dir)?;
    let sock_path = dir.join(format!("agent.{pid}"));
    let listener = UnixListener::bind(&sock_path).context("binding socket")?;
    Ok((listener, sock_path, Some(dir)))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let timeout = Duration::from_secs(cli.timeout);

    let state = build_mux_state(timeout)?;
    if state.key_map.is_empty() {
        bail!("No live agents found");
    }

    let (listener, sock_path, temp_dir) = create_socket(cli.socket.as_deref())?;

    // Print the export line for the user
    println!(
        "SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;",
        sock_path.display()
    );
    eprintln!("Listening on {}", sock_path.display());

    // Clean up on Ctrl-C
    let cleanup_path = sock_path.clone();
    let cleanup_dir = temp_dir.clone();
    ctrlc::set_handler(move || {
        let _ = fs::remove_file(&cleanup_path);
        if let Some(d) = &cleanup_dir {
            let _ = fs::remove_dir(d);
        }
        std::process::exit(0);
    })?;

    let state = Arc::new(state);

    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || handle_client(stream, &state));
            }
            Err(e) => eprintln!("Accept error: {e}"),
        }
    }

    Ok(())
}
