mod common;

use ssh_agent_fixer::probe::{self, AgentStatus};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn test_probe_alive_agent_with_key() {
    let agent = common::TestAgent::start();
    agent.add_key("test-key");

    match probe::probe_agent(agent.sock_path(), TIMEOUT) {
        AgentStatus::Alive(ids) => {
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0].comment, "test-key");
            assert_eq!(ids[0].key_type, "ssh-ed25519");
            assert!(ids[0].fingerprint.starts_with("SHA256:"));
        }
        other => panic!("expected Alive, got: {other:?}"),
    }
}

#[test]
fn test_probe_alive_agent_multiple_keys() {
    let agent = common::TestAgent::start();
    agent.add_key("key-alpha");
    agent.add_key("key-beta");
    agent.add_key("key-gamma");

    match probe::probe_agent(agent.sock_path(), TIMEOUT) {
        AgentStatus::Alive(ids) => {
            assert_eq!(ids.len(), 3);
            let comments: Vec<_> = ids.iter().map(|i| i.comment.as_str()).collect();
            assert!(comments.contains(&"key-alpha"));
            assert!(comments.contains(&"key-beta"));
            assert!(comments.contains(&"key-gamma"));
        }
        other => panic!("expected Alive, got: {other:?}"),
    }
}

#[test]
fn test_probe_empty_agent() {
    let agent = common::TestAgent::start();

    match probe::probe_agent(agent.sock_path(), TIMEOUT) {
        AgentStatus::Alive(ids) => assert_eq!(ids.len(), 0),
        other => panic!("expected Alive with 0 keys, got: {other:?}"),
    }
}

#[test]
fn test_probe_dead_socket() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("nonexistent.sock");

    match probe::probe_agent(&bogus, TIMEOUT) {
        AgentStatus::Dead(_) => {}
        other => panic!("expected Dead, got: {other:?}"),
    }
}

#[test]
fn test_pid_alive() {
    assert!(probe::pid_alive(std::process::id()));
    assert!(!probe::pid_alive(999_999_999));
}

#[test]
fn test_fingerprint_matches_ssh_keygen() {
    let agent = common::TestAgent::start();
    let pubkey_path = agent.add_key("fp-test");

    let expected_fp = common::ssh_keygen_fingerprint(&pubkey_path);

    match probe::probe_agent(agent.sock_path(), TIMEOUT) {
        AgentStatus::Alive(ids) => {
            assert_eq!(ids.len(), 1);
            assert_eq!(ids[0].fingerprint, expected_fp);
        }
        other => panic!("expected Alive, got: {other:?}"),
    }
}
