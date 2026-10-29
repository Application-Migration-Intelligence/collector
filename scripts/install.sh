#!/bin/sh
# MigrateIntel collector: download, verify, run once, remove.
#
# The command on your project page looks like this:
#
#   curl -fsSL https://migrateintel.com/collect.sh | MIG_COLLECTOR_KEY=<key> sh -s -- /var/www/your-app
#
# It downloads the collector binary for this server's CPU from the public
# release, checks it against the release's published SHA-256 checksums (and its
# Sigstore signature when cosign is installed), runs `mig-collector upload`
# on the folder, and deletes the binary and its temporary folder whatever
# happens. Nothing stays installed. Pass `preview` as the first argument to
# see what would be sent without sending anything.
#
# Source: https://github.com/Application-Migration-Intelligence/collector (Apache-2.0)
set -eu

REPO="Application-Migration-Intelligence/collector"
VERSION="${MIG_COLLECTOR_VERSION:-latest}"

case "$(uname -s)" in
    Linux) os=linux ;;
    *) echo "mig-collector: this server runs $(uname -s); only Linux is supported for now" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "mig-collector: CPU $(uname -m) is not supported yet (amd64 and arm64 are)" >&2; exit 1 ;;
esac

command=upload
if [ "${1:-}" = "preview" ] || [ "${1:-}" = "collect" ]; then
    command=$1
    shift
fi

if [ "$VERSION" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
else
    base="https://github.com/$REPO/releases/download/$VERSION"
fi
binary="mig-collector-$os-$arch"

dir=$(mktemp -d "${TMPDIR:-/tmp}/mig-collector.XXXXXX")
cleanup() { rm -rf "$dir"; }
trap cleanup EXIT INT TERM HUP

fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q --https-only -O "$2" "$1"
    else
        echo "mig-collector: needs curl or wget" >&2
        exit 1
    fi
}

fetch "$base/$binary" "$dir/$binary"
fetch "$base/SHA256SUMS" "$dir/SHA256SUMS"

expected=$(awk -v f="$binary" '$2 == f || $2 == "*" f { print $1 }' "$dir/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$dir/$binary" | awk '{ print $1 }')
else
    actual=$(shasum -a 256 "$dir/$binary" | awk '{ print $1 }')
fi
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "mig-collector: the download does not match the published checksum; nothing was run" >&2
    exit 1
fi

if command -v cosign >/dev/null 2>&1; then
    fetch "$base/SHA256SUMS.sigstore.json" "$dir/SHA256SUMS.sigstore.json"
    cosign verify-blob \
        --bundle "$dir/SHA256SUMS.sigstore.json" \
        --certificate-identity-regexp "^https://github.com/$REPO/\.github/workflows/release\.yml@refs/tags/" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$dir/SHA256SUMS" >/dev/null 2>&1 || {
        echo "mig-collector: the release signature did not verify; nothing was run" >&2
        exit 1
    }
fi

chmod 700 "$dir/$binary"
"$dir/$binary" "$command" "$@"
