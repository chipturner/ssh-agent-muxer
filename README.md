# ssh-agent-mux

SSH agent multiplexer for Linux. Presents all live SSH agents on your system through a single stable socket.

Solves the stale `SSH_AUTH_SOCK` problem in tmux: when you reconnect from a different machine, your old socket is dead but tmux sessions still reference it. Instead of shell hacks or manual `export SSH_AUTH_SOCK=...`, point everything at the mux socket and it routes to whichever agent actually has the key.

## How it works

The mux daemon discovers all SSH agent sockets on the system (via `/proc`, filesystem scan, and inotify), probes them for liveness, and merges their key listings into one. When a client sends a sign request, the mux looks up which backend agent owns that key and forwards the request there.

New agents are detected within seconds via inotify. Dead agents are pruned automatically when sign requests fail.

## Install

```bash
cargo install --path .
```

Requires Rust 2024 edition (1.85+). Linux only -- uses `/proc`, inotify, and `SO_PEERCRED`.

## Quick start

```bash
# Start the daemon (daemonizes by default)
eval "$(ssh-agent-mux start)"

# Or run in foreground with debug logging
RUST_LOG=debug ssh-agent-mux start --foreground

# Or run via systemd
systemd-run --user --unit=ssh-agent-mux -- ssh-agent-mux start --foreground
```

That's it. `SSH_AUTH_SOCK` now points at the mux. All your SSH agents are merged behind it.

## Shell integration

Add to your `~/.bashrc` or `~/.zshrc`:

```bash
# Start mux if not running, set SSH_AUTH_SOCK
if ! ssh-agent-mux status --json >/dev/null 2>&1; then
    eval "$(ssh-agent-mux start)"
else
    export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/ssh-agent-mux/agent.sock"
    export SSH_AGENT_MUX_DIR="$XDG_RUNTIME_DIR/ssh-agent-mux"
fi
```

## Usage

### Daemon management

```bash
ssh-agent-mux start               # start daemon, print export lines
ssh-agent-mux start --foreground   # stay in foreground, log to stderr
ssh-agent-mux status               # show backends, keys, lock state
ssh-agent-mux status --json        # machine-readable status
ssh-agent-mux refresh              # trigger immediate agent rediscovery
ssh-agent-mux stop                 # stop the daemon
```

### Manual mode

If you don't want auto-discovery, specify agent sockets explicitly:

```bash
ssh-agent-mux start --agent /tmp/ssh-XXXXX/agent.1234 --agent /path/to/other.sock
```

### Adding keys through the mux

By default, `ssh-add` through the mux fails (there's no way to know which backend should receive the key). Designate a primary agent:

```bash
ssh-agent-mux start --primary-agent /tmp/ssh-XXXXX/agent.1234
```

Now `ssh-add` forwards to that agent. `ssh-add -D` (remove all) broadcasts to all backends.

### Diagnostic probe

```bash
ssh-agent-probe              # show all agents, keys, stale PIDs
ssh-agent-probe --alive-only # only show responsive agents
```

## Options

### `ssh-agent-mux start`

| Flag | Default | Description |
|------|---------|-------------|
| `--foreground` | off | Stay in foreground, log to stderr |
| `--socket PATH` | `$XDG_RUNTIME_DIR/ssh-agent-mux/agent.sock` | Listener socket path |
| `--agent PATH` | (auto-discover) | Explicit backend socket (repeatable) |
| `--primary-agent PATH` | (none) | Backend for `ssh-add` operations |
| `--timeout SECS` | 2 | Discovery/probe timeout |
| `--sign-timeout SECS` | 30 | Sign request timeout (for hardware tokens) |
| `--refresh-interval SECS` | 300 | `/proc` poll fallback interval (inotify handles fast detection) |
| `--log-file PATH` | `$XDG_RUNTIME_DIR/ssh-agent-mux/mux.log` | Log file in daemon mode |
| `--pid-file PATH` | `$XDG_RUNTIME_DIR/ssh-agent-mux.pid` | PID file path |

### `ssh-agent-mux status` / `refresh` / `stop`

| Flag | Description |
|------|-------------|
| `--socket-dir PATH` | Override control socket directory |
| `--json` | Raw JSON output (status only) |

### Environment variables

| Variable | Description |
|----------|-------------|
| `SSH_AGENT_MUX_DIR` | Socket directory for `status`/`refresh`/`stop` (printed by `start`) |
| `RUST_LOG` | Log level: `error`, `warn`, `info` (default), `debug`, `trace` |

## How routing works

The mux maintains a mapping of **key blob -> backend socket**. This works because the SSH agent protocol uses the same key blob in both `REQUEST_IDENTITIES` responses and `SIGN_REQUEST` messages -- it's a natural routing key.

| Operation | Routing |
|-----------|---------|
| List keys | Return merged list from all backends (cached, rebuilt on refresh) |
| Sign | Forward to the backend that owns the key |
| Add key | Forward to `--primary-agent` (fail if not set) |
| Remove key | Forward to the backend that owns the key |
| Remove all | Broadcast to all backends |
| Lock/Unlock | Broadcast to all backends |
| Extensions | `session-bind@openssh.com` routes by key blob; others return `EXTENSION_FAILURE` |

## Security

- Listener socket is chmod 0600 in a 0700 directory
- Client connections verified via `SO_PEERCRED` (same UID only)
- Backend sockets validated for ownership and permissions before every connection
- Parent directories checked for unsafe permissions (world-writable without sticky bit)
- The mux's own socket is excluded from discovery by inode comparison (prevents loops even through symlinks)
- Lock passphrases are never stored in mux memory -- forwarded directly to backend agents

## Building and testing

```bash
just check      # format check + clippy + full test suite
just test       # run all tests
just stress 10  # run full suite 10 times, report pass/fail
```

Tests spawn real `ssh-agent` processes with generated ed25519 keys. All processes are cleaned up on drop, even on panic.

## License

MIT
