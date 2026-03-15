set shell := ["zsh", "-uc"]

default:
    just --list

# Build the project
build:
    cargo build

# Clippy (strict) then full test suite -- the pre-push gate
check:
    cargo clippy -- -D warnings
    cargo nextest run

# Format all source files
fmt:
    cargo fmt

# Check formatting without modifying (CI-friendly)
fmt-check:
    cargo fmt -- --check

# Run tests (pass args to filter, e.g. `just test fingerprint`)
test *args:
    cargo nextest run {{ args }}

# Wire protocol unit tests only
test-proto:
    cargo nextest run -E 'test(proto::)'

# Probe integration tests only
test-probe:
    cargo nextest run --test probe_test

# Mux e2e tests only
test-mux:
    cargo nextest run --test mux_test

# Run full suite N times and report pass/fail tally
stress count="10":
    #!/usr/bin/env zsh
    pass=0 fail=0
    for i in $(seq 1 {{ count }}); do
        echo -n "Run $i/{{ count }}: "
        if ! cargo nextest run &>/dev/null; then
            echo "FAILED"
            ((fail++))
        else
            echo "PASSED"
            ((pass++))
        fi
    done
    echo "\n$pass passed, $fail failed out of {{ count }} runs"
    [[ $fail -eq 0 ]]

# Run the probe
probe *args:
    cargo run --bin ssh-agent-probe -- {{ args }}

# Run the mux (foreground)
mux *args:
    cargo run --bin ssh-agent-mux -- {{ args }}

# Clean all build artifacts
clean:
    cargo clean
