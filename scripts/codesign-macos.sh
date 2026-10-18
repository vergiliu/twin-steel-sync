#!/bin/sh
# Ad-hoc sign macOS binaries so the system lets them serve the local network.
#
# macOS completes a connection and then tears it down for programs it does not
# trust, which makes the server look broken (EINVAL from socket options, ENOTCONN
# from reads, "connection reset by peer" on the client). A signature is what the
# firewall checks. Ad-hoc signing needs no certificate, no account and no sudo:
#
#     codesign -s - -f --identifier dev.twin.cli target/debug/twin
#
# This script is a no-op everywhere except macOS, and skips files that are already
# signed, so a build can call it unconditionally.
#
# Usage: scripts/codesign-macos.sh <binary> [more binaries...]

set -eu

[ "$#" -gt 0 ] || { echo "usage: $0 <binary> [more binaries...]" >&2; exit 2; }

if [ "$(uname -s)" != "Darwin" ]; then
    exit 0
fi

if ! command -v codesign >/dev/null 2>&1; then
    echo "codesign-macos: no codesign on this machine; leaving the binaries unsigned" >&2
    exit 0
fi

for binary in "$@"; do
    if [ ! -f "$binary" ]; then
        echo "codesign-macos: $binary does not exist; nothing to sign" >&2
        continue
    fi

    if ! /usr/bin/codesign -dvvv "$binary" 2>&1 | grep -q "not signed at all"; then
        echo "codesign-macos: already signed, left alone: $binary"
        continue
    fi

    if ! /usr/bin/codesign -s - -f --identifier dev.twin.cli "$binary" >/dev/null 2>&1; then
        echo "codesign-macos: signing $binary failed; incoming local-network connections may be refused" >&2
        continue
    fi

    if /usr/bin/codesign -dvvv "$binary" 2>&1 | grep -q "not signed at all"; then
        echo "codesign-macos: $binary still reads as unsigned; sign it by hand if connections fail" >&2
    else
        echo "codesign-macos: signed $binary"
    fi
done
