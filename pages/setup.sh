#!/bin/sh
# Install, update, configure or uninstall securegate on Linux and macOS.
#
#   curl -fsSL https://jgermade.github.io/securegate/setup.sh | sh
#   curl -fsSL https://jgermade.github.io/securegate/setup.sh | sh -s -- reinstall
#   curl -fsSL https://jgermade.github.io/securegate/setup.sh | sh -s -- uninstall
#
# With no command and a terminal to ask on, it asks what to do: install, and —
# when it finds securegate already there — update, reinstall, configure or
# uninstall. With nobody to ask it installs.
#
# One binary, from a GitHub release, into /usr/local/bin (or --dir). After a
# first install it offers `securegate config`, the setup wizard, and on Linux
# with systemd `securegate service --install`. An update restarts the service.
# `uninstall` keeps the configuration and data unless `--purge` says otherwise.
#
# Everything is a function and the last line calls `main`, so a download that
# was cut short runs nothing. POSIX sh, because `| sh` is dash on Debian.

set -eu

REPO="jgermade/securegate"
SETUP_URL="https://jgermade.github.io/securegate/setup.sh"
UNIT="/etc/systemd/system/securegate.service"
TMP=""

usage() {
	cat <<EOF
securegate setup: install, update, configure or uninstall securegate.

Usage:
  curl -fsSL $SETUP_URL | sh -s -- [command] [options]
  sh setup.sh [command] [options]

Commands:
  install      Install the latest release, or update to it. Does nothing when
               that version is already there.
  reinstall    Download and replace the binary, even if it is the same version.
  configure    Run the setup wizard (securegate config).
  uninstall    Stop and remove the service and the binary. The configuration
               and data are kept unless --purge.
  help         Show this text.

With no command, the script asks which of these to do, offering the last ones
only when it finds securegate installed. With no terminal to ask on it installs.

Options:
  --dir DIR        Where the binary goes. Default: /usr/local/bin
                   (or SECUREGATE_INSTALL_DIR)
  --version TAG    A release tag, such as v0.2.0. Default: the latest one.
                   (or SECUREGATE_VERSION)
  --config FILE    The configuration file. Default: /etc/securegate/securegate.yaml
  --no-service     Do not offer to install or restart the systemd service.
  --purge          With uninstall: also delete the configuration, the data
                   directory (subdomains, keys, users) and the service user.
  -y, --yes        Do not ask: install the service, and delete with --purge.
  -h, --help       Show this text.

Environment:
  SECUREGATE_DOWNLOAD_URL   A directory holding securegate-<os>-<arch>.tar.gz
                            and SHA256SUMS, used instead of GitHub: a mirror,
                            or file:// for a build of your own.
EOF
}

say() { printf '%s\n' "$*"; }
warn() { printf 'securegate setup: warning: %s\n' "$*" >&2; }
die() {
	printf 'securegate setup: error: %s\n' "$*" >&2
	exit 1
}
need() { command -v "$1" >/dev/null 2>&1; }

# fetch URL FILE: false on any failure, a 404 included.
fetch() {
	curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
}

has_tty() { (: </dev/tty) 2>/dev/null; }

# as_root CMD...: run as root, through sudo when this is not root already.
as_root() {
	if [ "$(id -u)" = 0 ]; then
		"$@"
	elif need sudo; then
		sudo "$@"
	else
		die "this step needs root and sudo is not installed: run the script as root"
	fi
}

# maybe_root DIR CMD...: as root only when DIR is not writable as this user.
maybe_root() {
	d=$1
	shift
	while [ ! -d "$d" ]; do d=$(dirname "$d"); done
	if [ -w "$d" ]; then "$@"; else as_root "$@"; fi
}

# The release target this machine runs: the suffix of the asset's name.
detect_target() {
	os=$(uname -s)
	arch=$(uname -m)
	case "$os" in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) die "securegate is built for Linux and macOS, and this is $os" ;;
	esac
	case "$arch" in
	x86_64 | amd64) arch=amd64 ;;
	arm64 | aarch64) arch=arm64 ;;
	*) die "there is no securegate build for $arch: build it from source (https://github.com/$REPO)" ;;
	esac
	# A shell under Rosetta says x86_64 on Apple Silicon, and the native build
	# is the one worth running there.
	if [ "$os" = darwin ] && [ "$arch" = amd64 ] &&
		[ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
		arch=arm64
	fi
	TARGET="$os-$arch"
}

# Sets TAG and BASE: which release, and where its files are. With
# SECUREGATE_DOWNLOAD_URL there is no tag to ask GitHub about, and the version
# is whatever the downloaded binary says it is.
resolve_release() {
	if [ -n "${SECUREGATE_DOWNLOAD_URL:-}" ]; then
		TAG=""
		BASE=${SECUREGATE_DOWNLOAD_URL%/}
		return
	fi
	if [ -n "$VERSION" ]; then
		case "$VERSION" in
		v*) TAG=$VERSION ;;
		*) TAG=v$VERSION ;;
		esac
	else
		# The redirect GitHub answers `latest` with names the tag, and costs
		# none of the API's rate limit.
		latest=$(curl -fsSLI --retry 3 --connect-timeout 20 -o /dev/null -w '%{url_effective}' \
			"https://github.com/$REPO/releases/latest") ||
			die "could not reach GitHub to find the latest release"
		TAG=${latest##*/}
		case "$TAG" in
		v[0-9]*) ;;
		*) die "GitHub has no release of securegate to install yet" ;;
		esac
	fi
	BASE="https://github.com/$REPO/releases/download/$TAG"
}

# "0.2.0" for a securegate binary, or nothing.
version_of() {
	"$1" --version </dev/null 2>/dev/null | awk '{ print $2; exit }'
}

sha256() {
	if need sha256sum; then
		sha256sum "$1" | awk '{ print $1 }'
	elif need shasum; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	elif need openssl; then
		openssl dgst -sha256 "$1" | awk '{ print $NF }'
	fi
}

# The sum the release publishes for an asset in its SHA256SUMS.
expected_sum() {
	fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" ||
		die "could not download $BASE/SHA256SUMS to check the download against"
	sum=$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")
	[ -n "$sum" ] || die "$BASE/SHA256SUMS does not list $1"
	printf '%s\n' "$sum"
}

service_installed() { [ -f "$UNIT" ]; }
service_active() { need systemctl && systemctl is-active --quiet securegate 2>/dev/null; }
has_systemd() { [ "$(uname -s)" = Linux ] && [ -d /run/systemd/system ] && need systemctl; }

# Yes or no from a person; with nobody to ask, the default given.
ask() {
	question=$1
	default=$2
	if [ "$YES" = 1 ]; then return 0; fi
	if ! has_tty; then [ "$default" = y ]; return; fi
	if [ "$default" = y ]; then hint="[Y/n]"; else hint="[y/N]"; fi
	printf '%s %s ' "$question" "$hint" >/dev/tty
	read -r answer </dev/tty || answer=""
	[ -n "$answer" ] || answer=$default
	case "$answer" in
	[yY] | [yY][eE][sS]) return 0 ;;
	*) return 1 ;;
	esac
}

# Yes, from --yes or from a person. Never from the pipe the script came in on:
# with nobody to ask, the answer is no.
confirm() {
	if [ "$YES" = 1 ]; then return 0; fi
	has_tty || die "there is no terminal to ask on, so nothing was deleted: pass --yes"
	ask "$1" n
}

run_wizard() {
	has_tty || {
		say "To configure it, run: sudo $BIN config --config $CONFIG"
		return 1
	}
	say ""
	# The wizard writes the configuration where only root (and the service
	# user) can read it: it holds secrets.
	maybe_root "$(dirname "$CONFIG")" "$BIN" config --config "$CONFIG" </dev/tty >/dev/tty
}

# What follows a fresh install: configuration, then the service.
first_run() {
	if [ ! -f "$CONFIG" ]; then
		if ask "Create the configuration now with the setup wizard?" y && has_tty; then
			run_wizard || return 0
		else
			say ""
			say "Next, create the configuration with the setup wizard:"
			say "  sudo securegate config"
			return 0
		fi
	fi
	[ -f "$CONFIG" ] || return 0
	if [ "$SERVICE" = 1 ] && has_systemd && ! service_installed; then
		if ask "Run securegate as a system service, started at boot?" y; then
			as_root "$BIN" service --install --config "$CONFIG"
			return 0
		fi
	fi
	if ! service_installed; then
		say ""
		say "Start it with:"
		say "  sudo securegate start --detached     (sudo securegate stop to stop it)"
	fi
}

# After an update: the running service keeps the old binary until restarted.
restart_running() {
	if [ "$SERVICE" = 1 ] && service_active; then
		say "Restarting the securegate service..."
		as_root systemctl restart securegate
		say "The service runs $1 now."
	elif "$BIN" status --config "$CONFIG" >/dev/null 2>&1; then
		say "securegate is running: restart it to use $1:"
		say "  sudo securegate stop && sudo securegate start --detached"
	fi
}

already_installed() {
	say "securegate $1 is already installed at $BIN."
	say "To download it again: curl -fsSL $SETUP_URL | sh -s -- reinstall"
}

install_securegate() {
	force=$1
	need curl || die "curl is needed to download securegate"
	need tar || die "tar is needed to unpack securegate"
	detect_target
	resolve_release

	current=""
	if [ -x "$BIN" ]; then current=$(version_of "$BIN"); fi
	if [ "$force" = 0 ] && [ -n "$current" ] && [ "v$current" = "$TAG" ]; then
		already_installed "$current"
		first_run
		return
	fi

	TMP=$(mktemp -d "${TMPDIR:-/tmp}/securegate-setup.XXXXXX")
	asset="securegate-$TARGET.tar.gz"
	say "Downloading securegate ${TAG:+$TAG }for $TARGET..."
	if ! fetch "$BASE/$asset" "$TMP/$asset"; then
		die "could not download $BASE/$asset.
${TAG:+Release $TAG may have no build for $TARGET: see https://github.com/$REPO/releases/tag/$TAG
}To build it from source instead:
  go install github.com/$REPO/cmd/securegate@latest"
	fi

	want=$(expected_sum "$asset")
	got=$(sha256 "$TMP/$asset")
	[ -n "$got" ] || die "no sha256sum, shasum or openssl here to check the download with"
	[ "$got" = "$want" ] || die "$asset does not match its checksum (expected $want, got $got)"

	tar -xzf "$TMP/$asset" -C "$TMP" || die "could not unpack $asset"
	new="$TMP/securegate-$TARGET/securegate"
	[ -f "$new" ] || die "$asset has no securegate binary in it"
	chmod 755 "$new"
	# Run before it replaces anything: a binary this system cannot run must
	# not take the place of one that works.
	if ! "$new" --version </dev/null >"$TMP/version" 2>"$TMP/error"; then
		die "the downloaded securegate does not run on this system:
$(cat "$TMP/error")"
	fi
	version=$(awk '{ print $2; exit }' "$TMP/version")
	if [ "$force" = 0 ] && [ -n "$current" ] && [ "$current" = "$version" ]; then
		already_installed "$current"
		first_run
		return
	fi

	maybe_root "$DIR" mkdir -p "$DIR" || die "could not create $DIR"
	# Copied beside the old one and renamed over it: nobody ever runs half a
	# binary, and a server already running keeps the file it started from.
	if ! maybe_root "$DIR" sh -c 'cp "$1" "$2/.securegate.$3" && mv -f "$2/.securegate.$3" "$2/securegate"' \
		sh "$new" "$DIR" "$$"; then
		maybe_root "$DIR" rm -f "$DIR/.securegate.$$"
		die "could not write $BIN"
	fi

	if [ -z "$current" ]; then
		say "Installed securegate $version at $BIN."
		case ":${PATH:-}:" in
		*":$DIR:"*) ;;
		*) warn "$DIR is not on your PATH" ;;
		esac
		first_run
	elif [ "$current" = "$version" ]; then
		say "Reinstalled securegate $version at $BIN."
		restart_running "$version"
	else
		say "Updated securegate from $current to $version at $BIN."
		restart_running "$version"
	fi
}

configure_securegate() {
	[ -x "$BIN" ] || die "securegate is not installed in $DIR: install it first"
	run_wizard || exit 1
	if [ "$SERVICE" = 1 ] && service_active; then
		if ask "Restart the service to apply the settings?" y; then
			as_root systemctl restart securegate
		fi
	elif [ "$SERVICE" = 1 ] && has_systemd && ! service_installed && [ -f "$CONFIG" ]; then
		if ask "Run securegate as a system service, started at boot?" y; then
			as_root "$BIN" service --install --config "$CONFIG"
		fi
	fi
}

# The data directory named in the configuration, resolved against its
# directory as securegate does. Nothing when it can't be told.
data_dir() {
	[ -f "$CONFIG" ] || return 0
	if [ -r "$CONFIG" ]; then
		d=$(sed -n 's/^data_dir:[[:space:]]*//p' "$CONFIG")
	else
		d=$(as_root sed -n 's/^data_dir:[[:space:]]*//p' "$CONFIG")
	fi
	d=$(printf '%s\n' "$d" | sed 's/[[:space:]]*#.*$//; s/^["'\'']//; s/["'\'']$//' | head -n 1)
	[ -n "$d" ] || d=data
	case "$d" in
	/*) ;;
	*) d="$(dirname "$CONFIG")/$d" ;;
	esac
	case "$d" in
	*[!/]*) printf '%s\n' "${d%/}" ;;
	*) printf '/\n' ;; # only slashes: the root, which --purge refuses
	esac
}

uninstall_securegate() {
	if service_installed; then
		if [ -x "$BIN" ]; then
			as_root "$BIN" service --uninstall
		else
			as_root systemctl disable --now securegate || true
			as_root rm -f "$UNIT"
			as_root systemctl daemon-reload || true
		fi
	elif [ -x "$BIN" ] && "$BIN" status --config "$CONFIG" >/dev/null 2>&1; then
		maybe_root "$(dirname "$CONFIG")" "$BIN" stop --config "$CONFIG" || true
	fi

	if [ -e "$BIN" ] || [ -L "$BIN" ]; then
		maybe_root "$DIR" rm -f "$BIN" || die "could not remove $BIN"
		say "Removed $BIN."
	else
		say "securegate is not installed in $DIR."
	fi

	data=$(data_dir)
	if [ "$PURGE" = 0 ]; then
		if [ -f "$CONFIG" ] || { [ -n "$data" ] && [ -d "$data" ]; }; then
			say "Kept the configuration and data (subdomains, SSH keys, users):"
			[ ! -f "$CONFIG" ] || say "  $CONFIG"
			[ -z "$data" ] || [ ! -d "$data" ] || say "  $data"
			say "To delete them as well: curl -fsSL $SETUP_URL | sh -s -- uninstall --purge"
		fi
		return
	fi

	case "$data" in
	"" | / | "${HOME%/}" | /etc | /var | /var/lib | /usr | /usr/local)
		[ -z "$data" ] || die "the data directory is $data, which --purge will not delete"
		;;
	esac
	say "--purge deletes securegate's configuration and data: subdomains, SSH keys, users, certificates."
	[ ! -f "$CONFIG" ] || say "  $CONFIG"
	[ -z "$data" ] || [ ! -d "$data" ] || say "  $data ($(as_root du -sh "$data" 2>/dev/null | awk '{ print $1 }'))"
	if id securegate >/dev/null 2>&1; then say "  the securegate system user"; fi
	if ! confirm "Delete them?"; then
		say "Nothing deleted."
		return
	fi
	if [ -n "$data" ] && [ -d "$data" ]; then
		as_root rm -rf "$data" || die "could not delete $data"
		say "Deleted $data."
	fi
	if [ -f "$CONFIG" ]; then
		base=${CONFIG%.*}
		as_root rm -f "$CONFIG" "$base.env"
		say "Deleted $CONFIG."
		dir=$(dirname "$CONFIG")
		if [ "$(basename "$dir")" = securegate ]; then
			as_root rmdir "$dir" 2>/dev/null || true
		fi
	fi
	if id securegate >/dev/null 2>&1 && need userdel; then
		as_root userdel securegate 2>/dev/null && say "Deleted the securegate user."
	fi
}

# No command was typed: ask what to do, offering the other options only when
# securegate is installed. The answer becomes COMMAND.
choose_command() {
	if ! has_tty; then
		say "There is no terminal to ask on, so: install. (--help for the commands.)"
		COMMAND=install
		return
	fi
	current=""
	if [ -x "$BIN" ]; then current=$(version_of "$BIN"); fi
	if [ -n "$current" ]; then
		state=""
		if service_active; then state=" — running as a service"; fi
		say "securegate $current is installed at $BIN$state."
		say ""
		say "  1) Update to the latest release"
		say "  2) Reinstall $current"
		say "  3) Configure: subdomains, SSH keys, users and settings"
		say "  4) Uninstall — keeps the configuration and data"
		say "  5) Quit"
	else
		say "securegate opens a gate from your machine to the web: an encrypted"
		say "SSH tunnel per subdomain, managed from a web dashboard."
		say ""
		say "  1) Install the latest release"
		say "  2) Quit"
	fi
	while :; do
		printf 'What should this do? [1] ' >/dev/tty
		read -r answer </dev/tty || answer=1
		[ -n "$answer" ] || answer=1
		case "$answer" in
		q | Q) answer=quit ;;
		esac
		if [ -n "$current" ]; then
			case "$answer" in
			1) COMMAND=install; return ;;
			2) COMMAND=reinstall; return ;;
			3) COMMAND=configure; return ;;
			4) COMMAND=uninstall; return ;;
			5 | quit)
				say "Nothing to do."
				exit 0
				;;
			esac
		else
			case "$answer" in
			1) COMMAND=install; return ;;
			2 | quit)
				say "Nothing to do."
				exit 0
				;;
			esac
		fi
		warn "not an option"
	done
}

main() {
	COMMAND=install
	EXPLICIT=0
	DIR=${SECUREGATE_INSTALL_DIR:-}
	VERSION=${SECUREGATE_VERSION:-}
	CONFIG=/etc/securegate/securegate.yaml
	SERVICE=1
	PURGE=0
	YES=0
	while [ $# -gt 0 ]; do
		case "$1" in
		install | reinstall | configure | uninstall)
			COMMAND=$1
			EXPLICIT=1
			;;
		update) # what install does when there is something newer
			COMMAND=install
			EXPLICIT=1
			;;
		help | -h | --help)
			usage
			return
			;;
		--dir)
			[ $# -ge 2 ] || die "--dir needs a directory"
			DIR=$2
			shift
			;;
		--dir=*) DIR=${1#*=} ;;
		--version)
			[ $# -ge 2 ] || die "--version needs a tag, such as v0.2.0"
			VERSION=$2
			shift
			;;
		--version=*) VERSION=${1#*=} ;;
		--config)
			[ $# -ge 2 ] || die "--config needs a file"
			CONFIG=$2
			shift
			;;
		--config=*) CONFIG=${1#*=} ;;
		--no-service) SERVICE=0 ;;
		--purge) PURGE=1 ;;
		-y | --yes) YES=1 ;;
		*) die "unknown argument: $1 (see --help)" ;;
		esac
		shift
	done

	if [ "$PURGE" = 1 ] && [ "$COMMAND" != uninstall ]; then
		die "--purge goes with uninstall"
	fi
	[ -n "$DIR" ] || DIR=/usr/local/bin
	# A `--dir=~/bin` reaches here unexpanded: the shell expands a tilde after
	# `=` only in an assignment.
	# shellcheck disable=SC2088
	case "$DIR" in
	"~") DIR=$HOME ;;
	"~/"*) DIR="$HOME/${DIR#"~/"}" ;;
	/*) ;;
	*) DIR="$(pwd)/$DIR" ;;
	esac
	DIR=${DIR%/}
	BIN="$DIR/securegate"
	case "$CONFIG" in
	/*) ;;
	*) CONFIG="$(pwd)/$CONFIG" ;;
	esac
	if [ "$EXPLICIT" = 0 ]; then choose_command; fi

	trap '[ -z "$TMP" ] || rm -rf "$TMP"' EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	case "$COMMAND" in
	install) install_securegate 0 ;;
	reinstall) install_securegate 1 ;;
	configure) configure_securegate ;;
	uninstall) uninstall_securegate ;;
	esac
}

main "$@"
