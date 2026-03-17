use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use clap::Parser;
use log::{error, info, warn};
use ssh_agent_fixer::{discover, mux, proto, security, watch};
use std::io::Write;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{fs, io, thread};

#[derive(Parser)]
#[command(name = "ssh-agent-mux", about = "Multiplex SSH agents into one")]
struct Cli {
    /// Socket timeout in seconds
    #[arg(short, long, default_value = "2")]
    timeout: u64,

    /// Listener socket path
    #[arg(short, long)]
    socket: Option<PathBuf>,

    /// Explicit backend agent socket (repeatable, disables auto-discovery)
    #[arg(short, long = "agent", value_name = "PATH")]
    agents: Vec<PathBuf>,

    /// Run in foreground (default: daemonize)
    #[arg(short, long)]
    foreground: bool,

    /// /proc poll interval in seconds for agent discovery fallback (0 to disable)
    /// inotify handles fast detection; this is the slow safety net
    #[arg(long, default_value = "300")]
    refresh_interval: u64,

    /// PID file path
    #[arg(long)]
    pid_file: Option<PathBuf>,

    /// Log file path (default: $XDG_RUNTIME_DIR/ssh-agent-mux/mux.log in daemon mode)
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Primary agent for write operations (ssh-add, lock, etc.)
    #[arg(long, value_name = "PATH")]
    primary_agent: Option<PathBuf>,
}

// --- Path helpers ---

fn runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    let uid = current_uid();
    let run_user = PathBuf::from(format!("/run/user/{uid}"));
    if run_user.is_dir() {
        return run_user;
    }
    PathBuf::from(format!("/tmp/ssh-agent-mux-{uid}"))
}

fn default_socket_path() -> PathBuf {
    runtime_dir().join("ssh-agent-mux").join("agent.sock")
}

fn default_pid_path() -> PathBuf {
    runtime_dir().join("ssh-agent-mux.pid")
}

fn default_log_path() -> PathBuf {
    runtime_dir().join("ssh-agent-mux").join("mux.log")
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

// --- Discovery ---

fn discover_live_sockets(timeout: Duration, exclude: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let discovery = discover::discover()?;

    // Union /proc scan with filesystem scan, deduplicate
    let mut candidates: std::collections::BTreeSet<PathBuf> =
        discovery.sockets.into_keys().collect();
    for path in discover::scan_socket_dirs() {
        candidates.insert(path);
    }

    let sockets: Vec<PathBuf> = candidates
        .into_iter()
        .filter(|path| {
            if path == exclude {
                return false;
            }
            let mut stream = match proto::agent_connect(path, timeout) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let request = [0u8, 0, 0, 1, proto::SSH_AGENTC_REQUEST_IDENTITIES];
            if stream.write_all(&request).is_err() {
                return false;
            }
            matches!(
                proto::read_message(&mut stream),
                Ok(b) if !b.is_empty() && b[0] == proto::SSH2_AGENT_IDENTITIES_ANSWER
            )
        })
        .collect();
    Ok(sockets)
}

fn discover_and_build(
    timeout: Duration,
    exclude: &Path,
    primary_agent: Option<&Path>,
) -> anyhow::Result<mux::MuxState> {
    let sockets = discover_live_sockets(timeout, exclude)?;
    let mut state = mux::build_mux_state_validated(&sockets, timeout)?;
    state.primary_agent = primary_agent.map(PathBuf::from);
    Ok(state)
}

// --- Socket creation ---

fn create_socket(path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        chmod(parent, 0o700);
    }

    // Remove stale socket
    if path.exists() {
        fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path).context("binding socket")?;
    chmod(path, 0o600);
    Ok(listener)
}

fn chmod(path: &Path, mode: u32) {
    if let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        unsafe { libc::chmod(c_path.as_ptr(), mode) };
    }
}

// --- PID file ---

fn check_pid_file(path: &Path) -> anyhow::Result<()> {
    let contents = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context("reading pid file"),
    };

    if let Ok(pid) = contents.trim().parse::<u32>()
        && let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline"))
        && String::from_utf8_lossy(&cmd).contains("ssh-agent-mux")
    {
        bail!("Already running as PID {pid}");
    }

    // Stale PID file
    fs::remove_file(path)?;
    Ok(())
}

fn write_pid_file(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, format!("{}\n", std::process::id()))?;
    Ok(())
}

// --- Daemonization ---

fn daemonize() -> anyhow::Result<()> {
    // First fork
    match unsafe { libc::fork() } {
        -1 => bail!("fork failed: {}", io::Error::last_os_error()),
        0 => {}                     // child continues
        _ => std::process::exit(0), // parent exits
    }

    // New session
    if unsafe { libc::setsid() } < 0 {
        bail!("setsid failed: {}", io::Error::last_os_error());
    }

    // Second fork (prevent terminal acquisition)
    match unsafe { libc::fork() } {
        -1 => bail!("second fork failed: {}", io::Error::last_os_error()),
        0 => {}                     // grandchild continues
        _ => std::process::exit(0), // child exits
    }

    // Redirect stdin/stdout/stderr to /dev/null
    let devnull = fs::OpenOptions::new().read(true).write(true).open("/dev/null")?;
    use std::os::unix::io::AsRawFd;
    let fd = devnull.as_raw_fd();
    unsafe {
        libc::dup2(fd, 0);
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
    }

    Ok(())
}

// --- Logging ---

fn init_logging(foreground: bool, log_file: &Path) {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());

    if foreground {
        env_logger::Builder::new().parse_filters(&filter).init();
    } else {
        // File-based logger for daemon mode
        let file = match fs::OpenOptions::new().create(true).append(true).open(log_file) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to open log file {}: {e}", log_file.display());
                return;
            }
        };
        env_logger::Builder::new()
            .parse_filters(&filter)
            .target(env_logger::Target::Pipe(Box::new(file)))
            .init();
    }
}

// --- Refresh loop ---

fn refresh_loop(
    state: Arc<ArcSwap<mux::MuxState>>,
    proc_interval: Duration,
    timeout: Duration,
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
    own_socket: PathBuf,
    primary_agent: Option<PathBuf>,
) {
    // Set up inotify watcher for fast detection
    let runtime = runtime_dir();
    let extra_dirs: Vec<&Path> = vec![runtime.as_path()];
    let mut watcher = watch::AgentWatcher::new(&extra_dirs).ok();
    if watcher.is_none() {
        warn!("inotify unavailable, falling back to polling only");
    }

    let mut last_proc_poll = Instant::now();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        // Check for explicit reload request (SIGHUP or write operation)
        let force_reload = reload.swap(false, Ordering::Relaxed);

        // Check inotify for new sockets (1-second poll timeout)
        let inotify_triggered = watcher.as_mut().is_some_and(|w| w.poll(1000));

        // Periodic /proc fallback
        let proc_due = last_proc_poll.elapsed() >= proc_interval;

        if !force_reload && !inotify_triggered && !proc_due {
            if watcher.is_none() {
                // No inotify -- sleep briefly before next iteration
                thread::sleep(Duration::from_secs(1));
            }
            continue;
        }

        if proc_due {
            last_proc_poll = Instant::now();
        }

        match discover_and_build(timeout, &own_socket, primary_agent.as_deref()) {
            Ok(new_state) => {
                let old = state.load();
                let old_count = old.key_map.len();
                let new_count = new_state.key_map.len();
                state.store(Arc::new(new_state));
                if new_count != old_count {
                    info!("Refreshed: {old_count} -> {new_count} keys");
                }
            }
            Err(e) => warn!("Refresh failed: {e}"),
        }
    }
}

// --- Cleanup ---

fn cleanup(sock_path: &Path, pid_path: &Path) {
    let _ = fs::remove_file(sock_path);
    // Remove parent dir if it's our managed directory
    if let Some(parent) = sock_path.parent() {
        let _ = fs::remove_dir(parent);
    }
    let _ = fs::remove_file(pid_path);
}

// --- Main ---

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let timeout = Duration::from_secs(cli.timeout);
    let auto_discover = cli.agents.is_empty();

    // Determine paths
    let sock_path = cli.socket.unwrap_or_else(default_socket_path);
    let pid_path = cli.pid_file.unwrap_or_else(default_pid_path);
    let log_path = cli.log_file.unwrap_or_else(default_log_path);

    // Fail fast: check for existing instance
    check_pid_file(&pid_path)?;

    // Discover and build initial state
    let primary_agent = cli.primary_agent.as_deref();
    let state = if auto_discover {
        discover_and_build(timeout, &sock_path, primary_agent)?
    } else {
        let mut s = mux::build_mux_state_validated(&cli.agents, timeout)?;
        s.primary_agent = primary_agent.map(PathBuf::from);
        s
    };

    if state.key_map.is_empty() && !auto_discover {
        bail!("No live agents found");
    }

    info!(
        "Discovered {} keys across {} backends",
        state.key_map.len(),
        state.key_map.values().collect::<std::collections::HashSet<_>>().len()
    );

    // Fail fast: bind listener
    let listener = create_socket(&sock_path)?;

    // Print export line (visible before daemonizing)
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", sock_path.display());

    // Daemonize or stay in foreground
    if !cli.foreground {
        daemonize()?;
    }

    // Init logging (after fork so daemon logs to file, foreground logs to stderr)
    init_logging(cli.foreground, &log_path);
    info!("Listening on {}", sock_path.display());

    // Write PID file
    write_pid_file(&pid_path)?;

    // Signal handling
    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&reload))?;

    // Shared state via ArcSwap
    let state = Arc::new(ArcSwap::from_pointee(state));

    // Spawn refresh thread (auto-discover mode only)
    if auto_discover && cli.refresh_interval > 0 {
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        let reload = Arc::clone(&reload);
        let interval = Duration::from_secs(cli.refresh_interval);
        let own_socket = sock_path.clone();
        let primary = cli.primary_agent.clone();
        thread::spawn(move || {
            refresh_loop(state, interval, timeout, shutdown, reload, own_socket, primary)
        });
    }

    // Accept loop with poll-based timeout so shutdown flag is checked promptly.
    // signal-hook registers handlers with SA_RESTART, so accept() won't return
    // EINTR. Instead we use poll() with a 1-second timeout.
    use std::os::unix::io::AsRawFd;
    let listener_fd = listener.as_raw_fd();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Poll the listener fd with 1-second timeout
        let mut pfd = libc::pollfd { fd: listener_fd, events: libc::POLLIN, revents: 0 };
        let ret = unsafe { libc::poll(&raw mut pfd, 1, 1000) };

        if ret <= 0 {
            // Timeout or error -- just loop and check shutdown
            continue;
        }

        match listener.accept() {
            Ok((stream, _)) => {
                if let Err(reason) = security::check_peer_uid(&stream) {
                    warn!("Rejected connection: {reason}");
                    continue;
                }
                let snapshot = state.load_full();
                let reload = Arc::clone(&reload);
                thread::spawn(move || mux::handle_client(stream, &snapshot, Some(&reload)));
            }
            Err(e) => error!("Accept error: {e}"),
        }
    }

    cleanup(&sock_path, &pid_path);
    info!("Shutting down");

    Ok(())
}
