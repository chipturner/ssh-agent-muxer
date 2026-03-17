mod common;

use arc_swap::ArcSwap;
use ssh_agent_mux::mux;
use ssh_agent_mux::proto;
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
        let state = Arc::new(ArcSwap::from(state));
        let reload = Arc::new(AtomicBool::new(false));
        let locked = Arc::new(AtomicBool::new(false));
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state);
                    let reload = Arc::clone(&reload);
                    let locked = Arc::clone(&locked);
                    std::thread::spawn(move || {
                        mux::handle_client(stream, &state, &reload, &locked)
                    });
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
    let (_nkeys, key_blobs) = request_identities(&sock_path);
    assert_eq!(key_blobs.len(), 2);

    for blob in &key_blobs {
        let mut stream = UnixStream::connect(&sock_path).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();

        let msg = build_sign_request(blob, b"test data to sign");
        proto::write_message(&mut stream, &msg).unwrap();
        let resp = proto::read_message(&mut stream).unwrap();

        assert!(!resp.is_empty(), "empty response for sign request");
        assert_eq!(resp[0], 14, "expected SIGN_RESPONSE (14), got {}", resp[0]);
    }
}

#[test]
fn test_mux_deduplicates_keys() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();

    let pubkey = agent_a.add_key("shared-key");
    let privkey = pubkey.with_extension("");
    agent_b.add_key_file(&privkey);

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();
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

#[test]
fn test_mux_refresh_sees_new_keys() {
    let agent_a = common::TestAgent::start();
    agent_a.add_key("refresh-key-a");

    let sockets_a = vec![agent_a.sock_path().to_path_buf()];
    let initial = mux::build_mux_state_from_sockets(&sockets_a, TIMEOUT).unwrap();

    let state = Arc::new(ArcSwap::from_pointee(initial));
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || {
        let reload = Arc::new(AtomicBool::new(false));
        let locked = Arc::new(AtomicBool::new(false));
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state_clone);
                    let reload = Arc::clone(&reload);
                    let locked = Arc::clone(&locked);
                    std::thread::spawn(move || {
                        mux::handle_client(stream, &state, &reload, &locked)
                    });
                }
                Err(_) => break,
            }
        }
    });

    let (nkeys, _) = request_identities(&sock_path);
    assert_eq!(nkeys, 1);

    let agent_b = common::TestAgent::start();
    agent_b.add_key("refresh-key-b");
    let sockets_ab = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let refreshed = mux::build_mux_state_from_sockets(&sockets_ab, TIMEOUT).unwrap();
    state.store(Arc::new(refreshed));

    let (nkeys, _) = request_identities(&sock_path);
    assert_eq!(nkeys, 2);
}

#[test]
fn test_mux_long_lived_client_sees_refresh() {
    // Per-message state load: existing connection sees updated keys after swap
    let agent_a = common::TestAgent::start();
    agent_a.add_key("stable-key-a");

    let sockets_a = vec![agent_a.sock_path().to_path_buf()];
    let initial = mux::build_mux_state_from_sockets(&sockets_a, TIMEOUT).unwrap();

    let state = Arc::new(ArcSwap::from_pointee(initial));
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let state_clone = Arc::clone(&state);
    std::thread::spawn(move || {
        let reload = Arc::new(AtomicBool::new(false));
        let locked = Arc::new(AtomicBool::new(false));
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state_clone);
                    let reload = Arc::clone(&reload);
                    let locked = Arc::clone(&locked);
                    std::thread::spawn(move || {
                        mux::handle_client(stream, &state, &reload, &locked)
                    });
                }
                Err(_) => break,
            }
        }
    });

    // Open a persistent connection
    let mut client = UnixStream::connect(&sock_path).unwrap();
    client.set_read_timeout(Some(TIMEOUT)).unwrap();

    // Verify 1 key
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

    // Existing client SHOULD see 2 keys now (per-message state load)
    proto::write_message(&mut client, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut client).unwrap();
    let mut pos = 0;
    assert_eq!(proto::read_u32(&resp[1..], &mut pos), Some(2));
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

// --- Write operation tests ---

#[test]
fn test_mux_write_without_primary_rejects() {
    let agent = common::TestAgent::start();
    agent.add_key("write-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();
    let state = Arc::new(state);
    let (sock_path, _dir) = start_mux_listener(state);

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_ADD_IDENTITY, 0]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_FAILURE]);
}

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
        let state = Arc::new(ArcSwap::from_pointee(state));
        let locked = Arc::new(AtomicBool::new(false));
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state);
                    let reload = Arc::clone(&reload_clone);
                    let locked = Arc::clone(&locked);
                    std::thread::spawn(move || {
                        mux::handle_client(stream, &state, &reload, &locked)
                    });
                }
                Err(_) => break,
            }
        }
    });

    (sock_path, dir, reload)
}

#[test]
fn test_mux_remove_all_triggers_reload() {
    let agent = common::TestAgent::start();
    agent.add_key("reload-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();

    let (sock_path, _dir, reload) = start_mux_listener_with_reload(state);

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REMOVE_ALL_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_SUCCESS]);

    assert!(reload.load(Ordering::Relaxed), "reload flag should be set after remove_all");
}

// --- Sign-failure reload tests ---

#[test]
fn test_mux_sign_failure_triggers_reload() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();
    agent_a.add_key("sign-reload-a");
    agent_b.add_key("sign-reload-b");

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();
    assert_eq!(state.key_map.len(), 2);

    let (_, key_blobs) = {
        let state_arc = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
        let (sock, _dir) = start_mux_listener(state_arc);
        request_identities(&sock)
    };

    let (sock_path, _dir, reload) = start_mux_listener_with_reload(state);

    drop(agent_b);

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
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
    let (sock_path, _dir) = start_mux_listener(state);

    let mut msg = vec![proto::SSH_AGENTC_EXTENSION];
    proto::put_string(&mut msg, b"unknown-extension@example.com");

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_EXTENSION_FAILURE]);
}

#[test]
fn test_extension_session_bind_routes_by_key() {
    let agent = common::TestAgent::start();
    agent.add_key("session-bind-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
    let (sock_path, _dir) = start_mux_listener(Arc::clone(&state));

    let (_, key_blobs) = request_identities(&sock_path);
    assert_eq!(key_blobs.len(), 1);

    let mut msg = vec![proto::SSH_AGENTC_EXTENSION];
    proto::put_string(&mut msg, b"session-bind@openssh.com");
    proto::put_string(&mut msg, &key_blobs[0]);
    proto::put_string(&mut msg, b"fake-session-id");
    proto::put_string(&mut msg, b"fake-signature");
    msg.push(0);

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    assert_ne!(
        resp,
        vec![proto::SSH_AGENT_EXTENSION_FAILURE],
        "should route to backend, not return extension failure"
    );
}

// --- Lock tests (broadcast to backends) ---

#[test]
fn test_lock_broadcast_blocks_identities() {
    let agent = common::TestAgent::start();
    agent.add_key("lock-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let state = Arc::new(ArcSwap::from_pointee(state));
    let locked = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));

    let state_clone = Arc::clone(&state);
    let locked_clone = Arc::clone(&locked);
    let reload_clone = Arc::clone(&reload);
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            match conn {
                Ok(stream) => {
                    let state = Arc::clone(&state_clone);
                    let reload = Arc::clone(&reload_clone);
                    let locked = Arc::clone(&locked_clone);
                    std::thread::spawn(move || {
                        mux::handle_client(stream, &state, &reload, &locked)
                    });
                }
                Err(_) => break,
            }
        }
    });

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();

    // 1 key before lock
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    let mut pos = 0;
    assert_eq!(proto::read_u32(&resp[1..], &mut pos), Some(1));

    // Lock
    let mut lock_msg = vec![proto::SSH_AGENTC_LOCK];
    proto::put_string(&mut lock_msg, b"my-passphrase");
    proto::write_message(&mut stream, &lock_msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_SUCCESS]);

    // Identities should be empty
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    let mut pos = 0;
    assert_eq!(proto::read_u32(&resp[1..], &mut pos), Some(0));

    // Wrong passphrase unlock fails
    let mut unlock_msg = vec![proto::SSH_AGENTC_UNLOCK];
    proto::put_string(&mut unlock_msg, b"wrong-passphrase");
    proto::write_message(&mut stream, &unlock_msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_FAILURE]);

    // Correct unlock
    let mut unlock_msg = vec![proto::SSH_AGENTC_UNLOCK];
    proto::put_string(&mut unlock_msg, b"my-passphrase");
    proto::write_message(&mut stream, &unlock_msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_SUCCESS]);

    // 1 key again
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    let mut pos = 0;
    assert_eq!(proto::read_u32(&resp[1..], &mut pos), Some(1));
}

// --- Smart write routing tests ---

#[test]
fn test_remove_identity_routes_by_key_blob() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();
    agent_a.add_key("remove-a");
    agent_b.add_key("remove-b");

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
    let (sock_path, _dir) = start_mux_listener(Arc::clone(&state));

    let (_, key_blobs) = request_identities(&sock_path);
    assert_eq!(key_blobs.len(), 2);

    let mut msg = vec![proto::SSH_AGENTC_REMOVE_IDENTITY];
    proto::put_string(&mut msg, &key_blobs[0]);

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &msg).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_SUCCESS]);
}

#[test]
fn test_remove_all_broadcasts_to_all_backends() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();
    agent_a.add_key("rmall-a");
    agent_b.add_key("rmall-b");

    let sockets = vec![agent_a.sock_path().to_path_buf(), agent_b.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
    let (sock_path, _dir) = start_mux_listener(Arc::clone(&state));

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REMOVE_ALL_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_SUCCESS]);

    let state_after = mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap();
    assert_eq!(state_after.key_map.len(), 0, "all keys should be removed from all backends");
}

#[test]
fn test_add_without_primary_fails() {
    let agent = common::TestAgent::start();
    agent.add_key("add-test");

    let sockets = vec![agent.sock_path().to_path_buf()];
    let state = Arc::new(mux::build_mux_state_from_sockets(&sockets, TIMEOUT).unwrap());
    let (sock_path, _dir) = start_mux_listener(state);

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    proto::write_message(&mut stream, &[proto::SSH_AGENTC_ADD_IDENTITY, 0]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();
    assert_eq!(resp, vec![proto::SSH_AGENT_FAILURE]);
}
