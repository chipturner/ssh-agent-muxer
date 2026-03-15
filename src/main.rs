mod discover;
mod probe;

use clap::Parser;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "ssh-agent-probe", about = "Probe SSH agent liveness")]
struct Cli {
    /// Socket timeout in seconds
    #[arg(short, long, default_value = "2")]
    timeout: u64,

    /// Only show alive agents
    #[arg(long)]
    alive_only: bool,
}

fn format_pids(pids: &std::collections::HashSet<u32>) -> String {
    let mut sorted: Vec<_> = pids.iter().collect();
    sorted.sort();
    sorted
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let timeout = Duration::from_secs(cli.timeout);

    let discovery = discover::discover()?;

    let mut any_alive = false;

    // Probe each unique socket
    let mut socket_paths: Vec<_> = discovery.sockets.keys().collect();
    socket_paths.sort();

    for path in socket_paths {
        let pids = &discovery.sockets[path];
        let status = probe::probe_agent(path, timeout);

        match &status {
            probe::AgentStatus::Alive { num_identities } => {
                any_alive = true;
                let n = *num_identities;
                let label = if n == 1 { "identity" } else { "identities" };
                println!(
                    "ALIVE {}  ({n} {label}, referenced by PIDs: {})",
                    path.display(),
                    format_pids(pids),
                );
            }
            probe::AgentStatus::Dead(reason) => {
                if !cli.alive_only {
                    println!(
                        "DEAD  {}  ({reason}, referenced by PIDs: {})",
                        path.display(),
                        format_pids(pids),
                    );
                }
            }
            probe::AgentStatus::PermissionDenied => {
                if !cli.alive_only {
                    println!(
                        "DENY  {}  (permission denied, referenced by PIDs: {})",
                        path.display(),
                        format_pids(pids),
                    );
                }
            }
        }
    }

    // Check for stale SSH_AGENT_PIDs
    if !cli.alive_only {
        let mut agent_pids: Vec<_> = discovery.agent_pids.keys().collect();
        agent_pids.sort();

        for &agent_pid in &agent_pids {
            if !probe::pid_alive(*agent_pid) {
                let pids = &discovery.agent_pids[&agent_pid];
                println!(
                    "STALE SSH_AGENT_PID={agent_pid} (process not found, referenced by PIDs: {})",
                    format_pids(pids),
                );
            }
        }
    }

    std::process::exit(if any_alive { 0 } else { 1 });
}
