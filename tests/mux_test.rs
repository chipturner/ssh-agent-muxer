mod common;

use arc_swap::ArcSwap;
use ssh_agent_fixer::mux;
use ssh_agent_fixer::proto;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);

/// Start a mux listener in a background thread, return the socket path.
fn start_mux_listener(state: Arc<mux::MuxState>) -> (PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    std::thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state);
                    std::thread::spawn(move || mux::handle_client(stream, &state));
                }
                Err(_) => break,
            }
        }
    });

    (sock_path, dir)
}

/// Connect to a mux socket and request identities. Returns (nkeys, raw key_blobs).
fn request_identities(sock_path: &std::path::Path) -> (u32, Vec<Vec<u8>>) {
    let mut stream = UnixStream::connect(sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();

    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    assert!(!resp.is_empty());
    assert_eq!(resp[0], proto::SSH2_AGENT_IDENTITIES_ANSWER);

    let payload = &resp[1..];
    let mut pos = 0;
    let nkeys = proto::read_u32(payload, &mut pos).unwrap();

    let mut key_blobs = Vec::new();
    for _ in 0..nkeys {
        let blob = proto::read_string(payload, &mut pos).unwrap();
        key_blobs.push(blob.to_vec());
        let _comment = proto::read_string(payload, &mut pos).unwrap();
    }

    (nkeys, key_blobs)
}

/// Build a SIGN_REQUEST message for a given key_blob and data.
fn build_sign_request(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(proto::SSH_AGENTC_SIGN_REQUEST);
    proto::put_string(&mut msg, key_blob);
    proto::put_string(&mut msg, data);
    proto::put_u32(&mut msg, 0); // flags
    msg
}

#[test]
fn test_mux_merges_identities() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();
    agent_a.add_key("key-from-a");
    agent_b.add_key("key-from-b");

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
    assert_eq!(state.key_map.len(), 2);

    let (sock_path, _dir) = start_mux_listener(state);
    let (nkeys, _blobs) = request_identities(&sock_path);
    assert_eq!(nkeys, 2);
}

#[test]
fn test_mux_routes_sign_request() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();
    agent_a.add_key("sign-key-a");
    agent_b.add_key("sign-key-b");

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());

    let (sock_path, _dir) = start_mux_listener(state);

    // Get the key blobs
    let (_nkeys, key_blobs) = request_identities(&sock_path);
    assert_eq!(key_blobs.len(), 2);

    // Sign with each key -- both should succeed
    for blob in &key_blobs {
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();

        let msg = build_sign_request(blob, b"test data to sign");
        proto::write_message(&mut stream, &msg).unwrap();
        let resp = proto::read_message(&mut stream).unwrap();

        assert!(!resp.is_empty(), "empty response for sign request");
        // Type 14 = SSH_AGENT_SIGN_RESPONSE, type 5 = FAILURE
        assert_eq!(resp[0], 14, "expected SIGN_RESPONSE (14), got {}", resp[0]);
    }
}

#[test]
fn test_mux_deduplicates_keys() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();

    // Generate key once, add the same private key to both agents
    let pubkey = agent_a.add_key("shared-key");
    let privkey = pubkey.with_extension(""); // remove .pub
    agent_b.add_key_file(&privkey);

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();

    // Should have 1 key, not 2
    assert_eq!(state.key_map.len(), 1);
}

#[test]
fn test_mux_unknown_message_returns_failure() {
    let agent = common::TestAgent::start();
    agent.add_key("dummy");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());

    let (sock_path, _dir) = start_mux_listener(state);

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();

    // Send a message with unknown type 99
    proto::write_message(&mut stream, &[99u8]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    assert_eq!(resp, vec![proto::SSH_AGENT_FAILURE]);
}

#[test]
fn test_mux_unknown_key_sign_returns_failure() {
    let agent = common::TestAgent::start();
    agent.add_key("real-key");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());

    let (sock_path, _dir) = start_mux_listener(state);

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();

    // Sign with a fabricated key blob that doesn't exist in any agent
    let msg = build_sign_request(b"totally-fake-key-blob", b"data");
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    assert_eq!(resp, vec![proto::SSH_AGENT_FAILURE]);
}

#[test]
fn test_mux_multiple_clients_concurrent() {
    let agent = common::TestAgent::start();
    agent.add_key("concurrent-key");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());

    let (sock_path, _dir) = start_mux_listener(state);

    // Spawn 5 clients in parallel, each requesting identities
    let handles: Vec<_> = (0..5)
        .map(|_| {
            let path = sock_path.clone();
            std::thread::spawn(move || {
                let (nkeys, _) = request_identities(&path);
                assert_eq!(nkeys, 1);
            })
        })
        .collect();

    for h in handles {
        h.join().expect("client thread panicked");
    }
}

// --- ArcSwap refresh tests ---

/// Start a mux listener backed by ArcSwap for testing state refresh.
fn start_mux_listener_swappable(
    state: Arc<ArcSwap<mux::MuxState>>,
) -> (PathBuf, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    std::thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let snapshot = state.load_full();
                    std::thread::spawn(move || mux::handle_client(stream, &snapshot));
                }
                Err(_) => break,
            }
        }
    });

    (sock_path, dir)
}

#[test]
fn test_mux_refresh_sees_new_keys() {
    let agent_a = common::TestAgent::start();
    agent_a.add_key("refresh-key-a");

    let sockets_a = vec![agent_a.sock_path().to_path_buf()];
    let initial = mux::build_mux_state_from_sockets(&sockets_a, TIMEOUT).unwrap();

    let state = Arc::new(ArcSwap::from_pointee(initial));
    let (sock_path, _dir) = start_mux_listener_swappable(Arc::clone(&state));

    // Initially 1 key
    let (nkeys, _) = request_identities(&sock_path);
    assert_eq!(nkeys, 1);

    // Add a second agent and swap in new state
    let agent_b = common::TestAgent::start();
    agent_b.add_key("refresh-key-b");

    let sockets_ab = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let refreshed = mux::build_mux_state_from_sockets(&sockets_ab, TIMEOUT).unwrap();
    state.store(Arc::new(refreshed));

    // New connection should see 2 keys
    let (nkeys, _) = request_identities(&sock_path);
    assert_eq!(nkeys, 2);
}

#[test]
fn test_mux_old_client_unaffected_by_refresh() {
    let agent_a = common::TestAgent::start();
    agent_a.add_key("stable-key-a");

    let sockets_a = vec![agent_a.sock_path().to_path_buf()];
    let initial = mux::build_mux_state_from_sockets(&sockets_a, TIMEOUT).unwrap();

    let state = Arc::new(ArcSwap::from_pointee(initial));
    let (sock_path, _dir) = start_mux_listener_swappable(Arc::clone(&state));

    // Open a persistent connection
    let mut client = UnixStream::connect(&sock_path).unwrap();
    client.set_read_timeout(Some(TIMEOUT)).unwrap();

    // Verify 1 key on this connection
    proto::write_message(&mut client, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut client).unwrap();
    let mut pos = 0;
    assert_eq!(proto::read_u32(&resp[1..], &mut pos), Some(1));

    // Swap in state with 2 keys
    let agent_b = common::TestAgent::start();
    agent_b.add_key("stable-key-b");
    let sockets_ab = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let refreshed = mux::build_mux_state_from_sockets(&sockets_ab, TIMEOUT).unwrap();
    state.store(Arc::new(refreshed));

    // Existing client still sees 1 key (its snapshot is frozen)
    proto::write_message(&mut client, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut client).unwrap();
    let mut pos = 0;
    assert_eq!(proto::read_u32(&resp[1..], &mut pos), Some(1));

    // New connection sees 2 keys
    let (nkeys, _) = request_identities(&sock_path);
    assert_eq!(nkeys, 2);
}
