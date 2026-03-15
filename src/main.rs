mod discover;
mod probe;

use clap::Parser;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;
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

fn format_pids(pids: &HashSet<u32>) -> String {
    let mut sorted: Vec<_> = pids.iter().copied().collect();
    sorted.sort();
    sorted
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn section(title: &str) {
    let pad = 54usize.saturating_sub(title.len() + 1);
    println!("\n── {title} {}", "─".repeat(pad));
}

struct ProbeResult {
    path: PathBuf,
    pids: HashSet<u32>,
    status: probe::AgentStatus,
}

fn print_agents(results: &[ProbeResult], alive_only: bool) {
    section("Agents");

    for r in results {
        let pids = format_pids(&r.pids);
        match &r.status {
            probe::AgentStatus::Alive(ids) => {
                let n = ids.len();
                let label = if n == 1 { "key" } else { "keys" };
                println!("  \x1b[32m●\x1b[0m {}  \x1b[2m{n} {label}  PIDs: {pids}\x1b[0m", r.path.display());
            }
            probe::AgentStatus::Dead(reason) if !alive_only => {
                println!("  \x1b[31m●\x1b[0m {}  \x1b[2m{reason}  PIDs: {pids}\x1b[0m", r.path.display());
            }
            probe::AgentStatus::PermissionDenied if !alive_only => {
                println!("  \x1b[33m●\x1b[0m {}  \x1b[2mpermission denied  PIDs: {pids}\x1b[0m", r.path.display());
            }
            _ => {}
        }
    }
}

fn print_keys(results: &[ProbeResult]) {
    // fingerprint -> (key_type, comment, set of socket paths)
    let mut keys: BTreeMap<String, (String, String, BTreeSet<String>)> = BTreeMap::new();

    for r in results {
        if let probe::AgentStatus::Alive(ids) = &r.status {
            for id in ids {
                let entry = keys
                    .entry(id.fingerprint.clone())
                    .or_insert_with(|| (id.key_type.clone(), id.comment.clone(), BTreeSet::new()));
                entry.2.insert(r.path.display().to_string());
            }
        }
    }

    if keys.is_empty() {
        return;
    }

    section("Keys");

    for (fp, (key_type, comment, agents)) in &keys {
        let label = if comment.is_empty() {
            key_type.clone()
        } else {
            format!("{comment} ({key_type})")
        };
        println!("  {fp}  {label}");
        let agents: Vec<_> = agents.iter().collect();
        for (i, agent) in agents.iter().enumerate() {
            let connector = if i + 1 < agents.len() { "├" } else { "└" };
            println!("    {connector} {agent}");
        }
    }
}

fn print_stale_pids(discovery: &discover::Discovery) {
    let mut stale = Vec::new();
    for (&agent_pid, pids) in &discovery.agent_pids {
        if !probe::pid_alive(agent_pid) {
            stale.push((agent_pid, pids));
        }
    }

    if stale.is_empty() {
        return;
    }

    stale.sort_by_key(|(pid, _)| *pid);
    section("Stale Agent PIDs");

    for (agent_pid, pids) in stale {
        println!(
            "  \x1b[31m●\x1b[0m PID {agent_pid}  \x1b[2mprocess not found  PIDs: {}\x1b[0m",
            format_pids(pids),
        );
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let timeout = Duration::from_secs(cli.timeout);

    let discovery = discover::discover()?;

    let mut results: Vec<ProbeResult> = discovery
        .sockets
        .iter()
        .map(|(path, pids)| ProbeResult {
            path: path.clone(),
            pids: pids.clone(),
            status: probe::probe_agent(path, timeout),
        })
        .collect();
    results.sort_by(|a, b| a.path.cmp(&b.path));

    let any_alive = results
        .iter()
        .any(|r| matches!(r.status, probe::AgentStatus::Alive(_)));

    print_agents(&results, cli.alive_only);
    print_keys(&results);

    if !cli.alive_only {
        print_stale_pids(&discovery);
    }

    println!();
    std::process::exit(if any_alive { 0 } else { 1 });
}
