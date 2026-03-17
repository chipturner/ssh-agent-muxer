# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## What is ssh-agent-mux

SSH agent multiplexer and diagnostic tool for Linux. Solves the stale `SSH_AUTH_SOCK` problem in tmux: when you reconnect from a different machine, your old socket is dead but tmux sessions still reference it. This tool discovers all live agents on the system and presents them through a single stable socket.

### Binaries

| Binary | Description |
|--------|-------------|
| `ssh-agent-probe` | Discover and probe all SSH agents on the system. Shows liveness, key counts, fingerprints. |
| `ssh-agent-mux` | Multiplexing daemon -- merges all live agents into one stable socket. Daemonizes by default, periodic auto-discovery, SIGHUP refresh. Routes sign requests to the correct backend by key blob. |

## Build & Test

Rust edition 2024. Uses `just` as the task runner. Tests via `cargo-nextest`.

```bash
just check                # clippy + full test suite (pre-push gate)
just fmt                  # format all source files
just test                 # all tests (pass args to filter: just test fingerprint)
just test-proto           # wire protocol unit tests only
just test-probe           # probe integration tests only
just test-mux             # mux e2e tests only
just stress 10            # run full suite N times, report pass/fail tally
```

```bash
just probe                # discover and show all agents
just probe --alive-only   # only show alive agents
just mux start                  # start mux daemon, prints SSH_AUTH_SOCK export line
just mux start --foreground     # mux in foreground (logs to stderr)
just mux start -s /tmp/my.sock  # mux with explicit listener socket path
just mux start --agent /path/to/sock  # manual mode (no auto-discovery)
just mux start --primary-agent /path/to/sock  # enable add ops (ssh-add) via this agent
just mux status                 # show daemon status (backends, keys, lock state)
just mux refresh                # trigger immediate agent rediscovery
just mux stop                   # stop the running daemon
```

## Architecture

Lib crate (`ssh_agent_mux`) with two thin binaries. Eight modules:

- **`proto`** -- SSH agent wire format. Length-prefixed messages (`[u32 BE length][body]`), `read_u32`/`read_string`/`put_u32`/`put_string` cursor-based parsing, `read_message`/`write_message` for framed I/O. `connect_timeout` using non-blocking socket + poll. No external SSH crate -- the protocol is implemented inline.
- **`discover`** -- Walk `/proc/*/environ`, extract `SSH_AUTH_SOCK` and `SSH_AGENT_PID`. Returns `Discovery { sockets: HashMap<PathBuf, HashSet<u32>>, agent_pids: HashMap<u32, HashSet<u32>> }`.
- **`probe`** -- `probe_agent()` connects to a socket, sends `REQUEST_IDENTITIES`, parses the response into `Vec<Identity>` with SHA-256 fingerprints. `AgentStatus` enum: `Alive(Vec<Identity>)`, `Dead(String)`, `PermissionDenied`.
- **`mux`** -- Core multiplexer logic. `MuxState` holds a pre-serialized `IDENTITIES_ANSWER` and a `key_map: HashMap<Vec<u8>, PathBuf>` (key blob -> backend socket). `handle_client()` dispatches per message type: `REQUEST_IDENTITIES` returns cached response, `SIGN_REQUEST` routes by key blob, `REMOVE_IDENTITY` routes by key blob, `REMOVE_ALL_IDENTITIES` broadcasts to all backends, `LOCK`/`UNLOCK` broadcast to all backends and track state via `AtomicBool`, add operations go to `primary_agent`. `build_mux_state_validated()` adds security filtering.
- **`control`** -- Control socket handler. Line-oriented protocol: `STATUS` returns JSON (backends, key counts, lock state, uptime), `REFRESH` triggers immediate rediscovery.
- **`security`** -- Socket security. `validate_backend_socket()` checks ownership/permissions and parent directory safety. `get_peer_cred()`/`check_peer_uid()` verify connecting clients via `SO_PEERCRED`.
- **`watch`** -- `AgentWatcher` uses inotify to monitor `/tmp` and runtime dirs for new `ssh-*` directories and `agent.*` socket files. Sub-second detection of new SSH agents.
- **`bin/probe.rs`** -- CLI for `ssh-agent-probe`. Pretty-prints agents, keys (grouped by fingerprint with tree connectors), stale PIDs.
- **`bin/mux.rs`** -- Daemon for `ssh-agent-mux`. Subcommands: `start` (daemon), `status`, `refresh`, `stop`. Daemonizes (double-fork), inotify-based agent detection with /proc poll fallback via `ArcSwap<MuxState>`, signal handling (SIGTERM/SIGINT shutdown, SIGHUP refresh), PID file, agent socket + control socket at `$XDG_RUNTIME_DIR/ssh-agent-mux/`. Lock/unlock broadcast to all backends, tracked via `AtomicBool`. Excludes own socket from discovery to prevent loops. `SSH_AGENT_MUX_SOCKET` env var for socket dir discovery.

### SSH Agent Wire Protocol

Messages: `[u32 BE length][u8 type][payload...]`. Key types used:

| Type | Const | Direction | Description |
|------|-------|-----------|-------------|
| 5 | `SSH_AGENT_FAILURE` | response | Generic failure |
| 11 | `SSH_AGENTC_REQUEST_IDENTITIES` | request | List keys (no payload) |
| 12 | `SSH2_AGENT_IDENTITIES_ANSWER` | response | `[u32 nkeys][per key: string key_blob, string comment]` |
| 13 | `SSH_AGENTC_SIGN_REQUEST` | request | `[string key_blob][string data][u32 flags]` |
| 14 | `SSH_AGENT_SIGN_RESPONSE` | response | `[string signature]` |

The mux routes sign requests by matching the `key_blob` field against `key_map`. Key blobs serve as the natural routing key since they appear in both identity listings and sign requests.

## Key Patterns

- **Cursor-based parsing**: `read_u32`/`read_string` take `(buf, &mut pos)` and advance the cursor. No allocations for reads.
- **Pre-serialized response**: The mux builds the merged `IDENTITIES_ANSWER` once and serves it as cached bytes. Rebuilt atomically on refresh.
- **First-wins deduplication**: When the same key appears in multiple agents, the first agent (sorted by path) wins the routing entry.
- **Connect timeout**: `UnixStream::connect` has no timeout, so `connect_timeout` uses `SOCK_NONBLOCK` + `poll()` + `SO_ERROR` check.
- **Thread-per-client**: Mux uses `thread::spawn` per accepted connection. State shared via `ArcSwap<MuxState>` -- each client loads a fresh snapshot per message, so long-lived connections (ControlMaster, mosh) see refreshed keys immediately.
- **Poll-based accept loop**: `libc::poll()` with 1-second timeout on the listener fd, since `signal-hook` uses `SA_RESTART` (accept() wouldn't return EINTR). Shutdown flag checked between polls.
- **inotify + /proc hybrid detection**: `AgentWatcher` uses inotify on `/tmp` and runtime dirs for sub-second detection of new agents. Slow /proc poll (5 min default) as safety net. inotify watches for `ssh-*` directories and `agent.*` socket files.
- **Socket security**: Listener socket chmod 0600, directory chmod 0700. Backend sockets validated for ownership, permissions, and parent directory safety. Re-validated on every connect (TOCTOU mitigation). Client connections checked via `SO_PEERCRED`.
- **Smart write routing**: `REMOVE_IDENTITY` routes by key blob to the correct backend. `REMOVE_ALL_IDENTITIES` broadcasts to all backends. `ADD_IDENTITY` and similar require `--primary-agent`. `LOCK`/`UNLOCK` broadcast to all backends.
- **Broadcast lock**: `LOCK` broadcasts to all backends (real agents handle crypto). Mux tracks locked state via `AtomicBool` -- no passphrase in mux memory. When locked: identities returns empty, sign/extension/write ops return FAILURE, only `UNLOCK` is allowed. Lock persists across ArcSwap state refreshes.
- **Control socket**: Second Unix socket (`control.sock`) for runtime introspection. `STATUS` returns JSON (via serde_json) with backends, key counts, lock state, uptime. `REFRESH` performs synchronous rediscovery and returns key count. CLI subcommands `status`/`refresh`/`stop` connect to control socket. Human-readable output by default, `--json` for raw.
- **Self-exclusion**: Discovery filters out the mux's own listener socket to prevent routing loops.
- **Process cleanup in tests**: `TestAgent` and `TestDaemon` structs wrap `Child` + `TempDir`. `Drop` kills processes and cleans up files. Even panicking tests clean up.

## Development Notes

### Testing
- **Unit tests**: `proto.rs` and `security.rs` have inline `#[cfg(test)]` tests.
- **Integration tests**: `tests/probe_test.rs` and `tests/mux_test.rs` spawn real `ssh-agent` processes with generated ed25519 keys. `tests/daemon_test.rs` tests the full daemon binary (foreground mode, PID file, shutdown, multi-agent).
- **Test harness**: `tests/common/mod.rs` provides `TestAgent::start()` and `TestAgent::add_key()`.
- **No process leaks**: All tests must clean up ssh-agent processes. `TestAgent` and `TestDaemon` have `Drop` impls.

### Workflow
- Run `just fmt` after making code changes.
- Run `just check` (clippy + full test suite) before finishing work.
