mod common;

use arc_swap::ArcSwap;
use ssh_agent_fixer::mux;
use ssh_agent_fixer::proto;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
                    std::thread::spawn(move || mux::handle_client(stream, &state, None));
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
                    std::thread::spawn(move || mux::handle_client(stream, &snapshot, None));
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

// --- Empty state tests ---

#[test]
fn test_mux_empty_state_returns_zero_keys() {
    let state = mux::build_mux_state_from_sockets(&[], TIMEOUT).unwrap();
    assert_eq!(state.key_map.len(), 0);

    let state = Arc::new(state);
    let (sock_path, _dir) = start_mux_listener(state);
    let (nkeys, _) = request_identities(&sock_path);
    assert_eq!(nkeys, 0);
}

// --- Write operation forwarding tests ---

#[test]
fn test_mux_write_without_primary_rejects() {
    let agent = common::TestAgent::start();
    agent.add_key("write-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();

    let state = Arc::new(state);
    let (sock_path, _dir) = start_mux_listener(state);

    // Try to add a key (type 17) -- should get FAILURE since no primary agent
    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_ADD_IDENTITY, 0]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_FAILURE]);
}

#[test]
fn test_mux_write_with_primary_forwards() {
    let agent = common::TestAgent::start();
    agent.add_key("primary-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let mut state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();
    state.primary_agent = Some(agent.sock_path().to_path_buf());

    let reload = Arc::new(AtomicBool::new(false));

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let reload_clone = Arc::clone(&reload);
    std::thread::spawn(move || {
        let state = Arc::new(state);
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state);
                    let reload = Arc::clone(&reload_clone);
                    std::thread::spawn(move || mux::handle_client(stream, &state, Some(&reload)));
                }
                Err(_) => break,
            }
        }
    });

    // Lock the agent (type 22) -- should be forwarded to primary agent
    // Lock requires a passphrase (string), so send one
    let mut msg = vec![proto::SSH_AGENTC_LOCK];
    proto::put_string(&mut msg, b"test-passphrase");

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    // ssh-agent should accept the lock and return SUCCESS
    assert_eq!(resp, vec![proto::SSH_AGENT_SUCCESS]);

    // Write operation should have triggered a reload
    assert!(reload.load(Ordering::Relaxed), "reload flag should be set after write");

    // Unlock so the agent is usable for cleanup
    let mut msg = vec![proto::SSH_AGENTC_UNLOCK];
    proto::put_string(&mut msg, b"test-passphrase");
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_SUCCESS]);
}

// --- Sign-failure reload tests ---

/// Helper: start a mux listener with reload flag tracking.
fn start_mux_listener_with_reload(
    state: mux::MuxState,
) -> (PathBuf, tempfile::TempDir, Arc<AtomicBool>) {
    let reload = Arc::new(AtomicBool::new(false));
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let reload_clone = Arc::clone(&reload);
    std::thread::spawn(move || {
        let state = Arc::new(state);
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state);
                    let reload = Arc::clone(&reload_clone);
                    std::thread::spawn(move || mux::handle_client(stream, &state, Some(&reload)));
                }
                Err(_) => break,
            }
        }
    });

    (sock_path, dir, reload)
}

#[test]
fn test_mux_sign_failure_triggers_reload() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();
    agent_a.add_key("sign-reload-a");
    agent_b.add_key("sign-reload-b");

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();
    assert_eq!(state.key_map.len(), 2);

    // Grab agent_b's key blob before killing it
    let (_, key_blobs) = {
        let state_arc = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
        let (sock, _dir) = start_mux_listener(state_arc);
        request_identities(&sock)
    };

    let (sock_path, _dir, reload) = start_mux_listener_with_reload(state);

    // Kill agent_b so its backend is dead
    drop(agent_b);

    // Try to sign with agent_b's key -- should fail AND trigger reload
    let msg = build_sign_request(&key_blobs[1], b"test data");
    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    assert_eq!(resp, vec![proto::SSH_AGENT_FAILURE]);
    assert!(reload.load(Ordering::Relaxed), "reload should be set on sign failure");
}

// --- Extension routing tests ---

#[test]
fn test_extension_unknown_returns_extension_failure() {
    let agent = common::TestAgent::start();
    agent.add_key("ext-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();

    let state = Arc::new(state);
    let (sock_path, _dir) = start_mux_listener(state);

    // Send unknown extension
    let mut msg = vec![proto::SSH_AGENTC_EXTENSION];
    proto::put_string(&mut msg, b"unknown-extension@example.com");

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    // Should return EXTENSION_FAILURE (28), not generic FAILURE (5)
    assert_eq!(resp, vec![proto::SSH_AGENT_EXTENSION_FAILURE]);
}

#[test]
fn test_extension_session_bind_routes_by_key() {
    let agent = common::TestAgent::start();
    agent.add_key("session-bind-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();

    let state = Arc::new(state);
    let (sock_path, _dir) = start_mux_listener(Arc::clone(&state));

    // Get the key blob
    let (_, key_blobs) = request_identities(&sock_path);
    assert_eq!(key_blobs.len(), 1);

    // Build a session-bind extension message
    let mut msg = vec![proto::SSH_AGENTC_EXTENSION];
    proto::put_string(&mut msg, b"session-bind@openssh.com");
    proto::put_string(&mut msg, &key_blobs[0]); // key blob
    proto::put_string(&mut msg, b"fake-session-id"); // session identifier
    proto::put_string(&mut msg, b"fake-signature"); // signature
    msg.push(0); // is_forwarding = false

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    // The real agent will likely reject the fake signature, but it should
    // NOT return EXTENSION_FAILURE (28) -- that means we didn't route it.
    // It should return either SUCCESS (6) or generic FAILURE (5) from the agent.
    assert_ne!(
        resp,
        vec![proto::SSH_AGENT_EXTENSION_FAILURE],
        "should route to backend, not return extension failure"
    );
}
