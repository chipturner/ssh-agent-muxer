use inotify::{Inotify, WatchMask};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{fs, io};

/// Watches filesystem directories for new SSH agent sockets.
/// Uses inotify for sub-second detection of new agents.
pub struct AgentWatcher {
    inotify: Inotify,
    watched_dirs: HashSet<PathBuf>,
    buf: Vec<u8>,
}

impl AgentWatcher {
    /// Create a new watcher. Watches `/tmp` for new `ssh-*` directories
    /// and any existing `ssh-*` directories for new socket files.
    /// Also watches the given extra directories (e.g. XDG_RUNTIME_DIR).
    pub fn new(extra_dirs: &[&Path]) -> io::Result<Self> {
        let inotify = Inotify::init()?;
        let mut watcher = Self { inotify, watched_dirs: HashSet::new(), buf: vec![0u8; 4096] };

        // Watch /tmp for new ssh-* directories
        let _ = watcher.inotify.watches().add("/tmp", WatchMask::CREATE | WatchMask::MOVED_TO);

        // Watch existing ssh-* directories under /tmp
        if let Ok(entries) = fs::read_dir("/tmp") {
            for entry in entries.flatten() {
                if is_ssh_dir(&entry.file_name()) {
                    watcher.watch_dir(&entry.path());
                }
            }
        }

        // Watch extra directories
        for dir in extra_dirs {
            if dir.is_dir() {
                watcher.watch_dir(dir);
            }
        }

        Ok(watcher)
    }

    /// Add a directory to watch for new socket files.
    pub fn watch_dir(&mut self, path: &Path) {
        if self.watched_dirs.contains(path) {
            return;
        }
        if self.inotify.watches().add(path, WatchMask::CREATE | WatchMask::MOVED_TO).is_ok() {
            self.watched_dirs.insert(path.to_path_buf());
        }
    }

    /// Poll for new potential agent sockets. Returns true if new sockets
    /// were detected and a state refresh should be triggered.
    /// Uses libc::poll with timeout_ms to avoid blocking.
    pub fn poll(&mut self, timeout_ms: i32) -> bool {
        use std::os::unix::io::AsRawFd;

        let fd = self.inotify.as_raw_fd();
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };

        let ret = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if ret <= 0 {
            return false;
        }

        let mut needs_refresh = false;
        let mut new_dirs = Vec::new();

        if let Ok(events) = self.inotify.read_events(&mut self.buf) {
            for event in events {
                let Some(name) = event.name else { continue };
                let name_str = name.to_string_lossy();

                if is_ssh_dir_name(&name_str) {
                    new_dirs.push(Path::new("/tmp").join(name));
                    needs_refresh = true;
                } else if name_str.starts_with("agent.") {
                    needs_refresh = true;
                }
            }
        }

        for dir in new_dirs {
            self.watch_dir(&dir);
        }

        needs_refresh
    }
}

fn is_ssh_dir(name: &std::ffi::OsStr) -> bool {
    name.to_str().is_some_and(is_ssh_dir_name)
}

fn is_ssh_dir_name(name: &str) -> bool {
    name.starts_with("ssh-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn test_watcher_detects_new_socket_in_watched_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut watcher = AgentWatcher::new(&[dir.path()]).unwrap();

        // Drain any initial events
        watcher.poll(100);

        // Create a socket in the watched directory
        let sock_path = dir.path().join("agent.12345");
        let _listener = UnixListener::bind(&sock_path).unwrap();

        // Should detect the new socket (retry a few times for slow systems)
        let detected = (0..5).any(|_| watcher.poll(500));
        assert!(detected, "watcher should detect new agent socket");
    }

    #[test]
    fn test_watcher_detects_new_ssh_dir() {
        // This test creates a directory under /tmp matching ssh-* pattern.
        // Only works if /tmp is watchable (which it should be).
        let dir_name = format!("ssh-test-watcher-{}", std::process::id());
        let dir_path = PathBuf::from("/tmp").join(&dir_name);

        // Clean up in case of previous failed run
        let _ = fs::remove_dir_all(&dir_path);

        let mut watcher = AgentWatcher::new(&[]).unwrap();

        // Create ssh-* directory
        fs::create_dir(&dir_path).unwrap();

        // Should detect the new directory
        let detected = watcher.poll(500);

        // Clean up
        let _ = fs::remove_dir_all(&dir_path);

        assert!(detected);
    }

    #[test]
    fn test_watcher_ignores_non_agent_files() {
        // Use a dedicated watcher that only watches a single temp dir
        // (not /tmp) to avoid noise from parallel tests.
        let inotify = Inotify::init().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut watcher =
            AgentWatcher { inotify, watched_dirs: HashSet::new(), buf: vec![0u8; 4096] };
        watcher.watch_dir(dir.path());

        // Create a regular file (not matching "agent.*")
        fs::write(dir.path().join("not-a-socket.txt"), "hello").unwrap();

        // Should not trigger refresh -- our filter only matches "agent.*"
        assert!(!watcher.poll(200));
    }
}
