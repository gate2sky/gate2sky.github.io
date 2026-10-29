#!/bin/sh
# intergate tunnel, without installing anything: downloads the intergate
# client matching {{.Dashboard}}, checks it against the release's
# SHA256SUMS, runs it and deletes it when it ends.
#
#   curl -fsSL {{.URL}} | sh -s -- SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT] [-i KEY]
#
# --cache (first) keeps the client in ~/.cache/intergate/<version> to start
# faster next time. INTERGATE_DOWNLOAD_URL replaces GitHub with a directory
# holding intergate-<os>-<arch>.tar.gz and SHA256SUMS.
set -eu

REPO="jgermade/intergate"
VERSION='{{.Version}}'
SERVER='{{.Server}}'
HOST_KEY='{{.HostKey}}'

die() {
	printf 'intergate: %s\n' "$*" >&2
	exit 1
}
need() { command -v "$1" >/dev/null 2>&1; }

fetch() {
	if need curl; then
		curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
	elif need wget; then
		wget -q --tries=3 --timeout=20 -O "$2" "$1"
	else
		die "curl or wget is needed to download the client"
	fi
}

sha256() {
	if need sha256sum; then
		sha256sum "$1" | awk '{ print $1 }'
	elif need shasum; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	elif need openssl; then
		openssl dgst -sha256 "$1" | awk '{ print $NF }'
	else
		die "no sha256sum, shasum or openssl here to check the download with"
	fi
}

cache=0
if [ "${1:-}" = --cache ]; then
	cache=1
	shift
fi
[ $# -gt 0 ] || die "usage: sh -s -- SUBDOMAIN [--http PORT] [--tcp NAME=PORT] [--udp NAME=PORT]"

os=$(uname -s)
arch=$(uname -m)
case "$os" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "the intergate client is built for Linux and macOS, and this is $os" ;;
esac
case "$arch" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) die "there is no intergate build for $arch" ;;
esac
if [ "$os" = darwin ] && [ "$arch" = amd64 ] &&
	[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
	arch=arm64
fi
target="$os-$arch"
asset="intergate-$target.tar.gz"

# The server's own version, so the client speaks its language; a server
# built from source asks for the latest release.
VERSION=${INTERGATE_VERSION:-$VERSION}
if [ -n "${INTERGATE_DOWNLOAD_URL:-}" ]; then
	base=${INTERGATE_DOWNLOAD_URL%/}
elif [ -n "$VERSION" ]; then
	base="https://github.com/$REPO/releases/download/v${VERSION#v}"
else
	base="https://github.com/$REPO/releases/latest/download"
fi

dir=""
if [ "$cache" = 1 ] && [ -n "$VERSION" ]; then
	dir="${XDG_CACHE_HOME:-$HOME/.cache}/intergate/${VERSION#v}"
fi
bin="$dir/intergate-$target/intergate"
if [ -z "$dir" ] || [ ! -x "$bin" ]; then
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/intergate.XXXXXX")
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM
	fetch "$base/$asset" "$tmp/$asset" || die "could not download $base/$asset"
	fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $base/SHA256SUMS"
	want=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/SHA256SUMS")
	[ -n "$want" ] || die "SHA256SUMS does not list $asset"
	[ "$(sha256 "$tmp/$asset")" = "$want" ] || die "$asset does not match its checksum"
	if [ -n "$dir" ]; then
		mkdir -p "$dir"
		tar -xzf "$tmp/$asset" -C "$dir" || die "could not unpack $asset"
	else
		tar -xzf "$tmp/$asset" -C "$tmp" || die "could not unpack $asset"
		bin="$tmp/intergate-$target/intergate"
	fi
fi
[ -x "$bin" ] || die "$asset has no intergate binary in it"

"$bin" tunnel --server "$SERVER" --host-key "$HOST_KEY" "$@"
