#!/bin/sh
set -eu

REPO="chipturner/ssh-agent-fixer"

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS-$ARCH" in
    Linux-x86_64)  TARGET=x86_64-unknown-linux-musl ;;
    Linux-aarch64) TARGET=aarch64-unknown-linux-musl ;;
    Darwin-*)
        echo "error: ssh-agent-mux is Linux-only (uses /proc, inotify, SO_PEERCRED)" >&2
        exit 1
        ;;
    *) echo "error: unsupported platform: $OS $ARCH" >&2; exit 1 ;;
esac

VERSION="${1:-latest}"
if [ "$VERSION" = "latest" ]; then
    BASE="https://github.com/$REPO/releases/latest/download"
else
    BASE="https://github.com/$REPO/releases/download/v$VERSION"
fi

TARBALL="ssh-agent-mux-$TARGET.tar.gz"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "downloading ssh-agent-mux ($TARGET)..."
curl -sSfL "$BASE/$TARBALL"   -o "$TMPDIR/$TARBALL"
curl -sSfL "$BASE/SHA256SUMS" -o "$TMPDIR/SHA256SUMS"

echo "verifying checksum..."
cd "$TMPDIR"
grep "$TARBALL" SHA256SUMS | sha256sum -c -

tar xzf "$TARBALL"

INSTALL_DIR="${SSH_AGENT_MUX_INSTALL_DIR:-$HOME/.local/bin}"
mkdir -p "$INSTALL_DIR"
mv ssh-agent-mux "$INSTALL_DIR/ssh-agent-mux"
mv ssh-agent-probe "$INSTALL_DIR/ssh-agent-probe"

echo "installed ssh-agent-mux and ssh-agent-probe to $INSTALL_DIR/"
case ":$PATH:" in
    *:"$INSTALL_DIR":*) ;;
    *) echo "note: add $INSTALL_DIR to your PATH" ;;
esac
