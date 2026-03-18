mod common;

use ssh_agent_mux::proto;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);

struct TestDaemon {
    child: Child,
    sock_path: std::path::PathBuf,
    pid_path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl TestDaemon {
    fn start(agent: &common::TestAgent) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("mux.sock");
        let pid_path = dir.path().join("mux.pid");
        let log_path = dir.path().join("mux.log");

        let binary = env!("CARGO_BIN_EXE_ssh-agent-mux");
        let child = Command::new(binary)
            .args([
                "start",
                "--foreground",
                "--socket",
                sock_path.to_str().unwrap(),
                "--pid-file",
                pid_path.to_str().unwrap(),
                "--log-file",
                log_path.to_str().unwrap(),
                "--agent",
                agent.sock_path().to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn ssh-agent-mux");

        // Wait for socket to appear
        for _ in 0..50 {
            if sock_path.exists() {
                return Self { child, sock_path, pid_path, _dir: dir };
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        panic!("mux socket never appeared at {}", sock_path.display());
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn test_foreground_mode_serves_keys() {
    let agent = common::TestAgent::start();
    agent.add_key("daemon-test-key");

    let daemon = TestDaemon::start(&agent);

    // Connect and request identities
    let mut stream = UnixStream::connect(&daemon.sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();

    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    assert!(!resp.is_empty());
    assert_eq!(resp[0], proto::SSH2_AGENT_IDENTITIES_ANSWER);

    let mut pos = 0;
    let nkeys = proto::read_u32(&resp[1..], &mut pos).unwrap();
    assert_eq!(nkeys, 1);
}

#[test]
fn test_foreground_mode_creates_pid_file() {
    let agent = common::TestAgent::start();
    agent.add_key("pid-test-key");

    let daemon = TestDaemon::start(&agent);

    assert!(daemon.pid_path.exists(), "PID file should exist");
    let contents = std::fs::read_to_string(&daemon.pid_path).unwrap();
    let pid: u32 = contents.trim().parse().unwrap();
    assert_eq!(pid, daemon.child.id());
}

#[test]
fn test_foreground_mode_clean_shutdown() {
    let agent = common::TestAgent::start();
    agent.add_key("shutdown-test-key");

    let mut daemon = TestDaemon::start(&agent);

    // Verify socket exists
    assert!(daemon.sock_path.exists());

    // Send SIGTERM
    unsafe { libc::kill(daemon.child.id() as i32, libc::SIGTERM) };

    // Wait for process to exit with timeout
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match daemon.child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success() || status.code() == Some(0));
                break;
            }
            None if std::time::Instant::now() > deadline => {
                panic!("daemon did not exit within 5 seconds after SIGTERM");
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    }

    // Socket and PID file should be cleaned up
    assert!(!daemon.sock_path.exists(), "socket should be removed after SIGTERM");
    assert!(!daemon.pid_path.exists(), "PID file should be removed after SIGTERM");
}

#[test]
fn test_start_is_idempotent() {
    let agent = common::TestAgent::start();
    agent.add_key("dup-test-key");

    let daemon = TestDaemon::start(&agent);

    // Second start with same PID file should succeed (idempotent) and print env
    let binary = env!("CARGO_BIN_EXE_ssh-agent-mux");
    let output = Command::new(binary)
        .args([
            "start",
            "--foreground",
            "--socket",
            daemon.sock_path.to_str().unwrap(),
            "--pid-file",
            daemon.pid_path.to_str().unwrap(),
            "--agent",
            agent.sock_path().to_str().unwrap(),
        ])
        .output()
        .expect("spawn second instance");

    assert!(output.status.success(), "second start should succeed (idempotent)");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SSH_AUTH_SOCK="), "should print export lines");
}

#[test]
fn test_multiple_agents_manual_mode() {
    let agent_a = common::TestAgent::start();
    let agent_b = common::TestAgent::start();
    agent_a.add_key("multi-key-a");
    agent_b.add_key("multi-key-b");

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("mux.sock");
    let pid_path = dir.path().join("mux.pid");
    let log_path = dir.path().join("mux.log");

    let binary = env!("CARGO_BIN_EXE_ssh-agent-mux");
    let mut child = Command::new(binary)
        .args([
            "start",
            "--foreground",
            "--socket",
            sock_path.to_str().unwrap(),
            "--pid-file",
            pid_path.to_str().unwrap(),
            "--log-file",
            log_path.to_str().unwrap(),
            "--agent",
            agent_a.sock_path().to_str().unwrap(),
            "--agent",
            agent_b.sock_path().to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    // Wait for socket
    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut stream = UnixStream::connect(&sock_path).unwrap();
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();

    proto::write_message(&mut stream, &[proto::SSH_AGENTC_REQUEST_IDENTITIES]).unwrap();
    let resp = proto::read_message(&mut stream).unwrap();

    let mut pos = 0;
    let nkeys = proto::read_u32(&resp[1..], &mut pos).unwrap();
    assert_eq!(nkeys, 2, "should see keys from both agents");

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn test_start_recovers_from_wedged_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let pid_path = dir.path().join("mux.pid");
    let sock_path = dir.path().join("agent.sock");
    let log_path = dir.path().join("mux.log");

    // Simulate a wedged daemon: a bash process that holds the flock on the PID file
    // and writes its own PID into it, but doesn't run a control socket.
    // bash -c 'echo $$ > file; flock file -c "sleep 3600"' won't work because
    // flock re-opens the file. Instead use: bash holds fd open via exec.
    let script = format!(
        r#"echo $BASHPID > {pid}; exec {{fd}}<{pid}; flock -x $fd; sleep 3600"#,
        pid = pid_path.display()
    );
    let mut wedged = Command::new("bash")
        .args(["-c", &script])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    // Wait for the wedged process to acquire the lock and write its PID
    let locked = (0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        pid_path.exists()
            && std::fs::read_to_string(&pid_path).is_ok_and(|s| {
                s.trim()
                    .parse::<u32>()
                    .is_ok_and(|pid| std::fs::metadata(format!("/proc/{pid}")).is_ok())
            })
    });
    assert!(locked, "wedged process should acquire lock");

    // Start the real daemon -- should detect wedged (no control socket) and recover
    let agent = common::TestAgent::start();
    agent.add_key("recovery-test");

    let binary = env!("CARGO_BIN_EXE_ssh-agent-mux");
    let mut daemon = Command::new(binary)
        .args([
            "start",
            "--foreground",
            "--socket",
            sock_path.to_str().unwrap(),
            "--pid-file",
            pid_path.to_str().unwrap(),
            "--log-file",
            log_path.to_str().unwrap(),
            "--agent",
            agent.sock_path().to_str().unwrap(),
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn daemon");

    // Wait for the daemon to start (socket appears = recovery succeeded)
    let started = (0..80).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        sock_path.exists()
    });

    // Clean up
    let _ = wedged.kill();
    let _ = wedged.wait();
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(started, "daemon should start after recovering from wedged process");
}
