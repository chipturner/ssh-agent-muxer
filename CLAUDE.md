# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## What is ssh-agent-fixer

SSH agent multiplexer and diagnostic tool for Linux. Solves the stale `SSH_AUTH_SOCK` problem in tmux: when you reconnect from a different machine, your old socket is dead but tmux sessions still reference it. This tool discovers all live agents on the system and presents them through a single stable socket.

### Binaries

| Binary | Description |
|--------|-------------|
| `ssh-agent-probe` | Discover and probe all SSH agents on the system. Shows liveness, key counts, fingerprints. |
| `ssh-agent-mux` | Multiplexing proxy -- merges all live agents into one socket. Routes sign requests to the correct backend by key blob. |

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
just mux                  # start mux, prints SSH_AUTH_SOCK export line
just mux -s /tmp/my.sock  # mux with explicit socket path
```

## Architecture

Lib crate with two thin binaries. Five modules:

- **`proto`** -- SSH agent wire format. Length-prefixed messages (`[u32 BE length][body]`), `read_u32`/`read_string`/`put_u32`/`put_string` cursor-based parsing, `read_message`/`write_message` for framed I/O. `connect_timeout` using non-blocking socket + poll. No external SSH crate -- the protocol is implemented inline.
- **`discover`** -- Walk `/proc/*/environ`, extract `SSH_AUTH_SOCK` and `SSH_AGENT_PID`. Returns `Discovery { sockets: HashMap<PathBuf, HashSet<u32>>, agent_pids: HashMap<u32, HashSet<u32>> }`.
- **`probe`** -- `probe_agent()` connects to a socket, sends `REQUEST_IDENTITIES`, parses the response into `Vec<Identity>` with SHA-256 fingerprints. `AgentStatus` enum: `Alive(Vec<Identity>)`, `Dead(String)`, `PermissionDenied`.
- **`mux`** -- Core multiplexer logic. `MuxState` holds a pre-serialized `IDENTITIES_ANSWER` and a `key_map: HashMap<Vec<u8>, PathBuf>` (key blob -> backend socket). `handle_client()` dispatches: `REQUEST_IDENTITIES` returns cached response, `SIGN_REQUEST` routes by key blob lookup, others return `FAILURE`.
- **`bin/probe.rs`** -- CLI for `ssh-agent-probe`. Pretty-prints agents, keys (grouped by fingerprint with tree connectors), stale PIDs.
- **`bin/mux.rs`** -- CLI for `ssh-agent-mux`. Discovers live agents, builds mux state, binds listener, spawns thread per client.

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
- **Pre-serialized response**: The mux builds the merged `IDENTITIES_ANSWER` once at startup and serves it as cached bytes.
- **First-wins deduplication**: When the same key appears in multiple agents, the first agent (sorted by path) wins the routing entry.
- **Connect timeout**: `UnixStream::connect` has no timeout, so `connect_timeout` uses `SOCK_NONBLOCK` + `poll()` + `SO_ERROR` check.
- **Thread-per-client**: Mux uses `thread::spawn` per accepted connection. State shared via `Arc<MuxState>`.
- **Process cleanup in tests**: `TestAgent` struct wraps `Child` + `TempDir`. `Drop` kills the ssh-agent and the TempDir cleans up all files. Even panicking tests clean up.

## Development Notes

### Testing
- **Unit tests**: `proto.rs` has inline `#[cfg(test)]` tests for wire format parsing.
- **Integration tests**: `tests/probe_test.rs` and `tests/mux_test.rs` spawn real `ssh-agent` processes with generated ed25519 keys.
- **Test harness**: `tests/common/mod.rs` provides `TestAgent::start()` and `TestAgent::add_key()`.
- **No process leaks**: All tests must clean up ssh-agent processes. Verify with `pgrep ssh-agent` after test runs.

### Workflow
- Run `just fmt` after making code changes.
- Run `just check` (clippy + full test suite) before finishing work.
