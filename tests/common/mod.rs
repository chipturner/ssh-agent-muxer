#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// A real ssh-agent process for testing. Killed and cleaned up on drop.
pub struct TestAgent {
    child: Child,
    dir: tempfile::TempDir,
    sock_path: PathBuf,
}

impl TestAgent {
    /// Spawn a new ssh-agent listening on a socket in a temp directory.
    pub fn start() -> Self {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sock_path = dir.path().join("agent.sock");

        let child = Command::new("ssh-agent")
            .args(["-D", "-a"])
            .arg(&sock_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn ssh-agent");

        // Wait for the socket to appear
        for _ in 0..50 {
            if sock_path.exists() {
                return Self { child, dir, sock_path };
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("ssh-agent socket never appeared at {}", sock_path.display());
    }

    /// Generate an ed25519 key and add it to this agent. Returns the public key path.
    pub fn add_key(&self, comment: &str) -> PathBuf {
        let key_path = self.dir.path().join(format!("key_{comment}"));
        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
            .arg(&key_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run ssh-keygen");
        assert!(status.success(), "ssh-keygen failed");

        let status = Command::new("ssh-add")
            .arg(&key_path)
            .env("SSH_AUTH_SOCK", &self.sock_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run ssh-add");
        assert!(status.success(), "ssh-add failed");

        key_path.with_extension("pub")
    }

    /// Add an existing private key file to this agent.
    pub fn add_key_file(&self, key_path: &Path) {
        let status = Command::new("ssh-add")
            .arg(key_path)
            .env("SSH_AUTH_SOCK", &self.sock_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run ssh-add");
        assert!(status.success(), "ssh-add failed");
    }

    pub fn sock_path(&self) -> &Path {
        &self.sock_path
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // TempDir drops automatically and removes all files
    }
}

/// Get the SHA256 fingerprint of a public key file using ssh-keygen.
pub fn ssh_keygen_fingerprint(pubkey_path: &Path) -> String {
    let output = Command::new("ssh-keygen")
        .args(["-lf"])
        .arg(pubkey_path)
        .output()
        .expect("run ssh-keygen -lf");
    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    // Format: "256 SHA256:xxx comment (ED25519)"
    line.split_whitespace().nth(1).expect("fingerprint field").to_string()
}
