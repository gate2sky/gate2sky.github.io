#!/usr/bin/env bash
# The installer, walked against builds of this tree: `pages/setup.sh`
# installs, finds it already there, updates to a newer release, reinstalls,
# refuses a download whose checksum is wrong, uninstalls keeping the
# configuration and data, and purges them. Releases are directories standing
# in for GitHub (`INTERGATE_DOWNLOAD_URL=file://…`), and the binary,
# configuration and data live in a temporary directory, so nothing on the
# machine running it is touched.
#
#   scripts/setup-check.sh
#
# The installer runs with `sh`, which is dash on Ubuntu and bash in POSIX mode
# on macOS — the two shells `curl … | sh` lands in.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
setup="$root/pages/setup.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
arm64 | aarch64) arch=arm64 ;;
*) echo "unsupported machine $(uname -m)" >&2; exit 1 ;;
esac
target="$os-$arch"
name="intergate-$target.tar.gz"
sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# release VERSION: a directory holding that version's archive and SHA256SUMS.
release() {
	dir="$work/release-$1"
	mkdir -p "$dir/intergate-$target"
	(cd "$root" && CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=$1" \
		-o "$dir/intergate-$target/intergate" ./cmd/intergate)
	tar -czf "$dir/$name" -C "$dir" "intergate-$target"
	rm -rf "${dir:?}/intergate-$target"
	(cd "$dir" && sum "$name" >SHA256SUMS)
}
release 0.0.1
release 0.0.2

bin="$work/bin/intergate"
config="$work/etc/intergate.yaml"
setup() {
	sh "$setup" "$@" --dir "$work/bin" --config "$config" --no-service
}
unset INTERGATE_INSTALL_DIR INTERGATE_VERSION

step() { printf '\n== %s\n' "$*"; }
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}
expect() { grep -q "$1" "$work/out" || fail "$2"; }

export INTERGATE_DOWNLOAD_URL="file://$work/release-0.0.1"

step "install"
# No command typed: with nobody to ask the script installs, which is what CI
# exercises; on a terminal it would show the menu, so ask it nothing here.
if (: </dev/tty) 2>/dev/null; then
	setup install </dev/null | tee "$work/out"
else
	setup </dev/null | tee "$work/out"
fi
expect '^Installed intergate 0.0.1' "install did not say it installed"
expect 'intergate config' "a first install did not point at the setup wizard"
[ "$("$bin" --version)" = "intergate 0.0.1" ] || fail "the installed binary is not 0.0.1"

step "install again, which has nothing to do"
setup install | tee "$work/out"
expect 'already installed' "a second install replaced the binary"

step "update to a newer release"
export INTERGATE_DOWNLOAD_URL="file://$work/release-0.0.2"
setup update | tee "$work/out"
expect '^Updated intergate from 0.0.1 to 0.0.2' "update did not replace 0.0.1"
[ "$("$bin" --version)" = "intergate 0.0.2" ] || fail "the update did not install 0.0.2"

step "reinstall"
setup reinstall | tee "$work/out"
expect '^Reinstalled intergate 0.0.2' "reinstall did not replace the binary"

step "a download that does not match its checksum"
cp "$work/release-0.0.2/SHA256SUMS" "$work/sums"
printf '%064d  %s\n' 0 "$name" >"$work/release-0.0.2/SHA256SUMS"
if setup reinstall >"$work/out" 2>&1; then fail "a download with the wrong checksum was installed"; fi
cat "$work/out"
expect 'does not match its checksum' "the checksum failure was not reported"
[ "$("$bin" --version)" = "intergate 0.0.2" ] || fail "a failed download touched the installed binary"
cp "$work/sums" "$work/release-0.0.2/SHA256SUMS"

step "uninstall keeps the configuration and data"
mkdir -p "$work/etc/state"
printf 'public_url: http://localhost:8080\ndata_dir: state # relative to this file\n' >"$config"
echo db >"$work/etc/state/intergate.db"
setup uninstall | tee "$work/out"
expect "^Removed $bin" "uninstall did not remove the binary"
expect 'Kept the configuration and data' "uninstall did not say what it kept"
[ ! -e "$bin" ] || fail "the binary is still there"
if [ ! -f "$config" ] || [ ! -f "$work/etc/state/intergate.db" ]; then fail "uninstall deleted the configuration or data"; fi

step "uninstall --purge without a terminal or --yes deletes nothing"
setup install >/dev/null
if setup uninstall --purge </dev/null >"$work/out" 2>&1 && ! (: </dev/tty) 2>/dev/null; then
	fail "--purge with nobody to ask did not refuse"
fi
[ -f "$config" ] || fail "--purge deleted without asking"

step "uninstall --purge --yes"
setup install >/dev/null
setup uninstall --purge --yes | tee "$work/out"
expect "Deleted $work/etc/state" "purge did not delete the data directory"
expect "Deleted $config" "purge did not delete the configuration"
if [ -e "$work/etc/state" ] || [ -e "$config" ]; then fail "purge left files behind"; fi

step "the --purge guard refuses dangerous data directories"
setup install >/dev/null
printf 'data_dir: /\n' >"$config"
if setup uninstall --purge --yes >"$work/out" 2>&1; then fail "--purge accepted data_dir: /"; fi
expect 'will not delete' "the dangerous data_dir was not reported"

printf '\nAll installer checks passed.\n'
