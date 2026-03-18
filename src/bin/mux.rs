use anyhow::{Context, bail};
use arc_swap::ArcSwap;
use clap::{Args, Parser, Subcommand};
use log::{info, warn};
use ssh_agent_mux::{control, discover, mux, proto, security, watch};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, io, thread};

#[derive(Parser)]
#[command(name = "ssh-agent-mux", about = "Multiplex SSH agents into one")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the mux daemon
    Start(StartArgs),
    /// Show daemon status (backends, keys, lock state)
    Status(CtlArgs),
    /// Trigger immediate agent rediscovery
    Refresh(CtlArgs),
    /// Stop the running daemon
    Stop(CtlArgs),
}

#[derive(Args)]
struct StartArgs {
    /// Discovery/probe timeout in seconds
    #[arg(short, long, default_value = "2")]
    timeout: u64,

    /// Sign request timeout in seconds (longer for hardware tokens)
    #[arg(long, default_value = "30")]
    sign_timeout: u64,

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
    #[arg(long, default_value = "300")]
    refresh_interval: u64,

    /// PID file path
    #[arg(long)]
    pid_file: Option<PathBuf>,

    /// Log file path (default: $XDG_RUNTIME_DIR/ssh-agent-mux/mux.log in daemon mode)
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Primary agent for add operations (ssh-add)
    #[arg(long, value_name = "PATH")]
    primary_agent: Option<PathBuf>,
}

#[derive(Args)]
struct CtlArgs {
    /// Socket directory (to find control.sock)
    #[arg(short, long)]
    socket_dir: Option<PathBuf>,

    /// Emit raw JSON (status only)
    #[arg(long)]
    json: bool,
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

fn default_socket_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SSH_AGENT_MUX_DIR") {
        return PathBuf::from(dir);
    }
    runtime_dir().join("ssh-agent-mux")
}

fn default_pid_path() -> PathBuf {
    runtime_dir().join("ssh-agent-mux.pid")
}

fn default_log_path() -> PathBuf {
    default_socket_dir().join("mux.log")
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

// --- Discovery ---

/// Compare files by (st_dev, st_ino) to detect symlinks to our own sockets.
fn same_inode(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(ma), Ok(mb)) = (fs::metadata(a), fs::metadata(b)) else {
        return false;
    };
    ma.dev() == mb.dev() && ma.ino() == mb.ino()
}

fn discover_live_sockets(timeout: Duration, exclude: &[PathBuf]) -> anyhow::Result<Vec<PathBuf>> {
    let discovery = discover::discover()?;

    let mut candidates: std::collections::BTreeSet<PathBuf> =
        discovery.sockets.into_keys().collect();
    for path in discover::scan_socket_dirs() {
        candidates.insert(path);
    }
    log::debug!("Discovery found {} candidate sockets", candidates.len());

    let sockets: Vec<PathBuf> = candidates
        .into_iter()
        .filter(|path| {
            if exclude.iter().any(|ex| path == ex || same_inode(path, ex)) {
                return false;
            }
            let start = std::time::Instant::now();
            log::debug!("Probing {}", path.display());
            let mut stream = match proto::agent_connect(path, timeout) {
                Ok(s) => s,
                Err(e) => {
                    log::debug!(
                        "Probe connect failed after {:?}: {}: {e}",
                        start.elapsed(),
                        path.display()
                    );
                    return false;
                }
            };
            let request = [0u8, 0, 0, 1, proto::SSH_AGENTC_REQUEST_IDENTITIES];
            if stream.write_all(&request).is_err() {
                log::debug!("Probe write failed after {:?}: {}", start.elapsed(), path.display());
                return false;
            }
            let alive = matches!(
                proto::read_message(&mut stream),
                Ok(b) if !b.is_empty() && b[0] == proto::SSH2_AGENT_IDENTITIES_ANSWER
            );
            let elapsed = start.elapsed();
            if elapsed.as_secs() >= 1 {
                log::warn!("Slow probe: {} took {:?} (alive={alive})", path.display(), elapsed);
            } else {
                log::debug!("Probe {} alive={alive} in {:?}", path.display(), elapsed);
            }
            alive
        })
        .collect();
    Ok(sockets)
}

fn discover_and_build(
    discover_timeout: Duration,
    sign_timeout: Duration,
    exclude: &[PathBuf],
    primary_agent: Option<&Path>,
) -> anyhow::Result<mux::MuxState> {
    let sockets = discover_live_sockets(discover_timeout, exclude)?;
    let mut state = mux::build_mux_state_validated(&sockets, discover_timeout, sign_timeout)?;
    state.primary_agent = primary_agent.map(PathBuf::from);
    Ok(state)
}

#[allow(clippy::too_many_arguments)]
fn do_refresh(
    state: &ArcSwap<mux::MuxState>,
    discover_timeout: Duration,
    sign_timeout: Duration,
    exclude: &[PathBuf],
    primary_agent: Option<&Path>,
    refresh_mutex: &Mutex<()>,
    locked: &AtomicBool,
    blocking: bool,
) -> anyhow::Result<usize> {
    // Skip refresh while locked -- backends return 0 keys when locked,
    // which would wipe the key_map and make unlock broadcast to nobody.
    if locked.load(Ordering::Relaxed) {
        log::debug!("Skipping refresh while locked");
        let snap = state.load();
        return Ok(snap.key_map.len());
    }

    let guard = if blocking {
        Some(refresh_mutex.lock().unwrap_or_else(|e| e.into_inner()))
    } else {
        match refresh_mutex.try_lock() {
            Ok(g) => Some(g),
            Err(std::sync::TryLockError::WouldBlock) => {
                log::debug!("Refresh already in progress, skipping");
                let snap = state.load();
                return Ok(snap.key_map.len());
            }
            Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
        }
    };

    let new_state = discover_and_build(discover_timeout, sign_timeout, exclude, primary_agent)?;
    let count = new_state.key_map.len();
    let old = state.load();
    let old_count = old.key_map.len();
    state.store(Arc::new(new_state));
    if count != old_count {
        info!("Refreshed: {old_count} -> {count} keys");
    }
    drop(guard);
    Ok(count)
}

// --- Socket creation ---

fn create_socket(path: &Path) -> anyhow::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        chmod(parent, 0o700);
    }

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

// --- PID file (atomic via flock) ---

struct PidFile {
    _file: fs::File,
    path: PathBuf,
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn acquire_pid_file(path: &Path) -> anyhow::Result<PidFile> {
    use std::os::unix::io::AsRawFd;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;

    let fd = file.as_raw_fd();
    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let contents = fs::read_to_string(path).unwrap_or_default();
        bail!("Already running (PID {}). Use `ssh-agent-mux stop` to terminate.", contents.trim());
    }

    // We hold the lock -- write our PID
    file.set_len(0)?;
    writeln!(&file, "{}", std::process::id())?;
    Ok(PidFile { _file: file, path: path.to_path_buf() })
}

// --- Daemonization ---

fn daemonize() -> anyhow::Result<()> {
    match unsafe { libc::fork() } {
        -1 => bail!("fork failed: {}", io::Error::last_os_error()),
        0 => {}
        _ => std::process::exit(0),
    }

    if unsafe { libc::setsid() } < 0 {
        bail!("setsid failed: {}", io::Error::last_os_error());
    }

    match unsafe { libc::fork() } {
        -1 => bail!("second fork failed: {}", io::Error::last_os_error()),
        0 => {}
        _ => std::process::exit(0),
    }

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
    use std::os::unix::fs::OpenOptionsExt;
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());

    if foreground {
        env_logger::Builder::new().parse_filters(&filter).init();
    } else {
        let file = match fs::OpenOptions::new().create(true).append(true).mode(0o600).open(log_file)
        {
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

#[allow(clippy::too_many_arguments)]
fn refresh_loop(
    state: Arc<ArcSwap<mux::MuxState>>,
    proc_interval: Duration,
    discover_timeout: Duration,
    sign_timeout: Duration,
    shutdown: Arc<AtomicBool>,
    reload: Arc<AtomicBool>,
    locked: Arc<AtomicBool>,
    exclude: Vec<PathBuf>,
    primary_agent: Option<PathBuf>,
    refresh_mutex: Arc<Mutex<()>>,
) {
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

        let force_reload = reload.swap(false, Ordering::Relaxed);
        let inotify_triggered = watcher.as_mut().is_some_and(|w| w.poll(1000));
        let proc_due = last_proc_poll.elapsed() >= proc_interval;

        if !force_reload && !inotify_triggered && !proc_due {
            if watcher.is_none() {
                thread::sleep(Duration::from_secs(1));
            }
            continue;
        }

        if proc_due {
            last_proc_poll = Instant::now();
        }

        if let Err(e) = do_refresh(
            &state,
            discover_timeout,
            sign_timeout,
            &exclude,
            primary_agent.as_deref(),
            &refresh_mutex,
            &locked,
            false, // non-blocking in refresh loop
        ) {
            warn!("Refresh failed: {e}");
        }
    }
}

// --- Cleanup ---

fn cleanup(sock_path: &Path, ctl_path: &Path) {
    let _ = fs::remove_file(sock_path);
    let _ = fs::remove_file(ctl_path);
    if let Some(parent) = sock_path.parent() {
        let _ = fs::remove_dir(parent);
    }
}

// --- Control socket client ---

fn ctl_socket_dir(args: &CtlArgs) -> PathBuf {
    args.socket_dir.clone().unwrap_or_else(default_socket_dir)
}

fn ctl_command(args: &CtlArgs, command: &str) -> anyhow::Result<String> {
    let dir = ctl_socket_dir(args);
    let ctl_path = dir.join("control.sock");

    let mut stream = UnixStream::connect(&ctl_path).with_context(|| {
        format!(
            "Cannot connect to daemon at {}. Is it running? Start with `ssh-agent-mux start`.",
            ctl_path.display()
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    writeln!(stream, "{command}")?;
    stream.flush()?;

    let mut response = String::new();
    BufReader::new(&stream).read_line(&mut response)?;
    Ok(response)
}

fn cmd_status(args: &CtlArgs) -> anyhow::Result<()> {
    let response = ctl_command(args, "STATUS")?;
    if args.json {
        print!("{response}");
    } else {
        print!("{}", control::format_status_human(&response));
    }
    Ok(())
}

fn cmd_refresh(args: &CtlArgs) -> anyhow::Result<()> {
    let response = ctl_command(args, "REFRESH")?;
    print!("{response}");
    Ok(())
}

fn cmd_stop(args: &CtlArgs) -> anyhow::Result<()> {
    // Try control socket first
    if let Ok(response) = ctl_command(args, "STOP") {
        print!("{response}");
        return Ok(());
    }

    // Fall back to PID file + SIGTERM
    let pid_path = default_pid_path();
    let contents = fs::read_to_string(&pid_path)
        .with_context(|| format!("reading {}. Is the daemon running?", pid_path.display()))?;
    let pid: i32 = contents.trim().parse().context("parsing PID")?;

    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).context("process not found")?;
    if !String::from_utf8_lossy(&cmdline).contains("ssh-agent-mux") {
        bail!("PID {pid} is not ssh-agent-mux");
    }

    unsafe { libc::kill(pid, libc::SIGTERM) };

    for _ in 0..50 {
        if fs::metadata(format!("/proc/{pid}")).is_err() {
            println!("Stopped (pid {pid})");
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }

    bail!("Daemon (pid {pid}) did not exit within 5 seconds");
}

// --- Main ---

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Status(args) => cmd_status(&args),
        Command::Refresh(args) => cmd_refresh(&args),
        Command::Stop(args) => cmd_stop(&args),
        Command::Start(args) => run_daemon(args),
    }
}

fn print_env(sock_path: &Path, sock_dir: &Path) {
    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", sock_path.display());
    println!("SSH_AGENT_MUX_DIR={}; export SSH_AGENT_MUX_DIR;", sock_dir.display());
}

/// Probe the control socket with a STATUS command to verify the daemon is responsive.
fn probe_control_socket(ctl_path: &Path) -> bool {
    let Ok(mut stream) = UnixStream::connect(ctl_path) else {
        return false;
    };
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
    if writeln!(stream, "STATUS").is_err() {
        return false;
    }
    let _ = stream.flush();
    let mut buf = String::new();
    BufReader::new(&stream).read_line(&mut buf).is_ok() && !buf.is_empty()
}

/// Kill a stale daemon by reading its PID file and sending SIGTERM.
fn kill_stale_daemon(pid_path: &Path) {
    let Ok(contents) = fs::read_to_string(pid_path) else {
        return;
    };
    let Ok(pid) = contents.trim().parse::<i32>() else {
        return;
    };
    unsafe { libc::kill(pid, libc::SIGTERM) };
    // Wait briefly for it to exit and release the flock
    for _ in 0..20 {
        if fs::metadata(format!("/proc/{pid}")).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    // Force kill if SIGTERM didn't work
    unsafe { libc::kill(pid, libc::SIGKILL) };
    thread::sleep(Duration::from_millis(100));
}

fn run_daemon(cli: StartArgs) -> anyhow::Result<()> {
    let discover_timeout = Duration::from_secs(cli.timeout);
    let sign_timeout = Duration::from_secs(cli.sign_timeout);
    let auto_discover = cli.agents.is_empty();

    let sock_dir = cli
        .socket
        .as_ref()
        .and_then(|p| p.parent().map(PathBuf::from))
        .unwrap_or_else(default_socket_dir);
    let sock_path = cli.socket.clone().unwrap_or_else(|| sock_dir.join("agent.sock"));
    let ctl_path = sock_dir.join("control.sock");
    let pid_path = cli.pid_file.unwrap_or_else(default_pid_path);
    let log_path = cli.log_file.unwrap_or_else(default_log_path);

    // Idempotent: if already running and healthy, just print env and exit.
    // If running but wedged, kill it and take over.
    let _pid_file = match acquire_pid_file(&pid_path) {
        Ok(pf) => pf,
        Err(_) => {
            if probe_control_socket(&ctl_path) {
                // Daemon is alive and responding
                print_env(&sock_path, &sock_dir);
                return Ok(());
            }
            // Daemon holds the lock but isn't responding -- kill and take over
            eprintln!("Daemon not responding, restarting...");
            kill_stale_daemon(&pid_path);
            // Retry the lock after killing
            acquire_pid_file(&pid_path)?
        }
    };

    let exclude_sockets = vec![sock_path.clone(), ctl_path.clone()];
    let primary_agent = cli.primary_agent.as_deref();
    let state = if auto_discover {
        discover_and_build(discover_timeout, sign_timeout, &exclude_sockets, primary_agent)?
    } else {
        let mut s = mux::build_mux_state_validated(&cli.agents, discover_timeout, sign_timeout)?;
        s.primary_agent = primary_agent.map(PathBuf::from);
        s
    };

    if state.key_map.is_empty() && !auto_discover {
        let paths: Vec<_> = cli.agents.iter().map(|p| p.display().to_string()).collect();
        bail!(
            "No live agents found. Tried: {}. Run `ssh-agent-probe` to diagnose.",
            paths.join(", ")
        );
    }

    info!(
        "Discovered {} keys across {} backends",
        state.key_map.len(),
        state.key_map.values().collect::<std::collections::HashSet<_>>().len()
    );

    let agent_listener = create_socket(&sock_path)?;
    let ctl_listener = create_socket(&ctl_path)?;

    print_env(&sock_path, &sock_dir);

    if !cli.foreground {
        daemonize()?;
    }

    init_logging(cli.foreground, &log_path);
    info!("Listening on {}", sock_path.display());

    let shutdown = Arc::new(AtomicBool::new(false));
    let reload = Arc::new(AtomicBool::new(false));
    let locked = Arc::new(AtomicBool::new(false));
    let refresh_mutex = Arc::new(Mutex::new(()));

    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGHUP, Arc::clone(&reload))?;

    let state = Arc::new(ArcSwap::from_pointee(state));
    let start_time = Instant::now();

    // Spawn refresh thread
    if auto_discover && cli.refresh_interval > 0 {
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        let reload = Arc::clone(&reload);
        let interval = Duration::from_secs(cli.refresh_interval);
        let primary = cli.primary_agent.clone();
        let rm = Arc::clone(&refresh_mutex);
        let locked = Arc::clone(&locked);
        let exclude = exclude_sockets.clone();
        thread::spawn(move || {
            refresh_loop(
                state,
                interval,
                discover_timeout,
                sign_timeout,
                shutdown,
                reload,
                locked,
                exclude,
                primary,
                rm,
            )
        });
    }

    // Build sync refresh closure for control socket
    let exclude_for_ctl = exclude_sockets;
    let primary_for_ctl = cli.primary_agent.clone();
    let state_for_ctl = Arc::clone(&state);
    let rm_for_ctl = Arc::clone(&refresh_mutex);
    let locked_for_ctl = Arc::clone(&locked);
    let sync_refresh = move || {
        let _ = do_refresh(
            &state_for_ctl,
            discover_timeout,
            sign_timeout,
            &exclude_for_ctl,
            primary_for_ctl.as_deref(),
            &rm_for_ctl,
            &locked_for_ctl,
            true, // blocking for control socket
        );
    };

    // Accept loop
    use std::os::unix::io::AsRawFd;
    let agent_fd = agent_listener.as_raw_fd();
    let ctl_fd = ctl_listener.as_raw_fd();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let mut pfds = [
            libc::pollfd { fd: agent_fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: ctl_fd, events: libc::POLLIN, revents: 0 },
        ];
        let ret = unsafe { libc::poll(pfds.as_mut_ptr(), 2, 1000) };

        if ret <= 0 {
            continue;
        }

        if pfds[0].revents & libc::POLLIN != 0
            && let Ok((stream, _)) = agent_listener.accept()
        {
            if let Err(reason) = security::check_peer_uid(&stream) {
                warn!("Rejected connection: {reason}");
            } else {
                log::debug!("Accepted agent connection");
                let state = Arc::clone(&state);
                let reload = Arc::clone(&reload);
                let locked = Arc::clone(&locked);
                thread::spawn(move || mux::handle_client(stream, &state, &reload, &locked));
            }
        }

        if pfds[1].revents & libc::POLLIN != 0
            && let Ok((stream, _)) = ctl_listener.accept()
        {
            if let Err(reason) = security::check_peer_uid(&stream) {
                warn!("Rejected control connection: {reason}");
            } else {
                control::handle_control_client(
                    stream,
                    &state,
                    &reload,
                    &locked,
                    &shutdown,
                    start_time,
                    Some(&sync_refresh),
                );
            }
        }
    }

    cleanup(&sock_path, &ctl_path);
    info!("Shutting down");

    Ok(())
}
