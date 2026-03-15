use anyhow::{Context, bail};
use clap::Parser;
use ssh_agent_fixer::{discover, mux, proto};
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

fn discover_live_sockets(timeout: Duration) -> anyhow::Result<Vec<PathBuf>> {
    let discovery = discover::discover()?;
    let mut sockets: Vec<PathBuf> = discovery
        .sockets
        .into_keys()
        .filter(|path| {
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
    sockets.sort();
    Ok(sockets)
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

    let sockets = discover_live_sockets(timeout)?;
    let state = mux::build_mux_state_from_sockets(&sockets, timeout)?;

    if state.key_map.is_empty() {
        bail!("No live agents found");
    }

    eprintln!(
        "Discovered {} keys across {} backends",
        state.key_map.len(),
        state.key_map.values().collect::<std::collections::HashSet<_>>().len()
    );

    let (listener, sock_path, temp_dir) = create_socket(cli.socket.as_deref())?;

    println!("SSH_AUTH_SOCK={}; export SSH_AUTH_SOCK;", sock_path.display());
    eprintln!("Listening on {}", sock_path.display());

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
                thread::spawn(move || mux::handle_client(stream, &state));
            }
            Err(e) => eprintln!("Accept error: {e}"),
        }
    }

    Ok(())
}
