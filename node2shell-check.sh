#!/bin/sh
# node2shell-check.sh - read-only scanner for "Node2Shell" (CVE-2026-111497)
#
# CVE-2026-111497 is an out-of-bounds write in the Brotli decoder bundled
# with Node.js (and Bun, which bundles the same decoder). It affects
# Node.js 22.x, 24.x and 26.x, and the end-of-life 20.x/23.x/25.x lines.
# Fixed Node.js releases: 22.23.4, 24.22.1, 26.12.1 (2026-10-21).
# Fixed Bun release: 1.4.4.
#
# This script only reads. It never installs, upgrades, restarts or
# modifies anything. As root it executes "<bin> -v" / "--version" only on
# binaries that root owns and that no other user/group can write to;
# every other binary is inspected by reading its bytes, never executed.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/<you>/node2shell-check/main/node2shell-check.sh | sudo sh
#   wget -qO- https://raw.githubusercontent.com/<you>/node2shell-check/main/node2shell-check.sh | sudo sh -s -- --deep
#
# Exit codes: 0 = nothing vulnerable, 1 = vulnerable build or stale worker
# found, 2 = only undetermined builds found. Usage errors exit 64.

set -u

SELF_VERSION="1.0.0"

# Fixed releases per Node.js major line.
FIXED_22="22.23.4"
FIXED_24="24.22.1"
FIXED_26="26.12.1"
MIGRATE_TARGET="22.23.4, 24.22.1 or 26.12.1"

# Bun bundles the same Brotli decoder.
BUN_FIXED="1.4.4"
BUN_AFFECTED_FLOOR="1.0.21"

DEEP=0
SCAN_CONTAINERS=1
SCAN_BUN=1
USE_COLOR=1

N_VULN=0
N_OK=0
N_UNK=0
N_STALE=0

usage() {
	cat <<'EOF'
node2shell-check.sh - scan this host for Node2Shell (CVE-2026-111497)

Usage: node2shell-check.sh [options]

Options:
  --deep            Also search all local filesystems with find(1), not
                     just well-known install locations (slower).
  --no-containers   Skip scanning running Docker/Podman containers.
  --no-docker       Alias for --no-containers.
  --no-bun          Skip scanning for the Bun runtime (Bun bundles the
                     same vulnerable Brotli decoder).
  --no-color        Disable ANSI colors in the output.
  -h, --help        Show this help text and exit.
  -V, --version     Show the script version and exit.

Run as root for a complete scan (version-manager installs under other
users' home directories, process inspection, and container scanning all
need root to be reliable). The script never installs, upgrades, restarts
or modifies anything; it only reads.

Exit codes:
  0  nothing vulnerable was found
  1  a vulnerable build or a stale (upgraded-but-still-running) worker
     was found
  2  only undetermined builds were found
EOF
}

setup_colors() {
	if [ "$USE_COLOR" = 1 ] && [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		C_RED=$(printf '\033[31m')
		C_GRN=$(printf '\033[32m')
		C_YEL=$(printf '\033[33m')
		C_BLU=$(printf '\033[34m')
		C_BLD=$(printf '\033[1m')
		C_RST=$(printf '\033[0m')
	else
		C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""; C_RST=""
	fi
}

# ver_ge A B -> prints 1 if version A >= B (first three dot fields), else 0
ver_ge() {
	awk -v a="$1" -v b="$2" 'BEGIN {
		na = split(a, A, ".")
		nb = split(b, B, ".")
		for (i = 1; i <= 3; i++) {
			ai = (i <= na) ? A[i] + 0 : 0
			bi = (i <= nb) ? B[i] + 0 : 0
			if (ai > bi) { print 1; exit }
			if (ai < bi) { print 0; exit }
		}
		print 1
	}'
}

# fixed_for BRANCH -> prints the fixed release for a known Node major, or
# nothing if the branch is not one of the currently-maintained lines.
fixed_for() {
	case "$1" in
		22) printf '%s' "$FIXED_22" ;;
		24) printf '%s' "$FIXED_24" ;;
		26) printf '%s' "$FIXED_26" ;;
		*) printf '' ;;
	esac
}

# resolve PATH -> prints the canonical real path, following symlinks by
# hand so this works on systems without GNU readlink -f.
resolve() {
	_p="$1"
	_i=0
	while [ -L "$_p" ] && [ "$_i" -lt 20 ]; do
		_link=$(readlink "$_p" 2>/dev/null) || break
		case "$_link" in
			/*) _p="$_link" ;;
			*) _p="$(dirname "$_p")/$_link" ;;
		esac
		_i=$((_i + 1))
	done
	_dir=$(dirname "$_p")
	_base=$(basename "$_p")
	if _dir_abs=$(cd "$_dir" 2>/dev/null && pwd -P); then
		printf '%s/%s' "$_dir_abs" "$_base"
	else
		printf '%s' "$_p"
	fi
}

runtime_name() {
	case "$(basename "$1")" in
		node|nodejs) printf 'node' ;;
		bun) printf 'bun' ;;
		*) printf '' ;;
	esac
}

# add_cand KIND PATH -> dedupe by real path, skip shell wrappers, append
add_cand() {
	_kind="$1"; _path="$2"
	[ -f "$_path" ] || return 0
	_real=$(resolve "$_path")
	[ -f "$_real" ] || return 0
	grep -Fxq "$_real" "$TMP/seen" 2>/dev/null && return 0
	printf '%s\n' "$_real" >>"$TMP/seen"
	# skip shell-script wrappers (shims) - they are not the real binary
	if head -c 2 "$_real" 2>/dev/null | grep -q '^#!'; then
		return 0
	fi
	printf '%s\037%s\037%s\n' "$_kind" "$_real" "$_path" >>"$TMP/cands"
}

# list_homes -> prints unique candidate home directories to search for
# per-user version managers (nvm, volta, fnm, asdf, nodenv).
list_homes() {
	{
		[ -n "${HOME:-}" ] && printf '%s\n' "$HOME"
		printf '/root\n'
		[ -d /home ] && find /home -mindepth 1 -maxdepth 1 -type d 2>/dev/null
		[ -d /Users ] && find /Users -mindepth 1 -maxdepth 1 -type d 2>/dev/null
		if [ -r /etc/passwd ]; then
			awk -F: '{print $6}' /etc/passwd
		fi
	} | sort -u
}

collect_static() {
	_globs="
/usr/bin/node
/usr/bin/nodejs
/usr/local/bin/node
/usr/local/bin/nodejs
/opt/homebrew/bin/node
/snap/node/current/bin/node
/snap/bin/node
"
	for _g in $_globs; do
		[ -f "$_g" ] && add_cand node "$_g"
	done

	# command -v lookups (covers PATH entries the globs above miss)
	for _n in node nodejs; do
		_c=$(command -v "$_n" 2>/dev/null) && add_cand node "$_c"
	done

	# Homebrew Cellar (both Apple Silicon and Intel prefixes), incl.
	# versioned formulae such as node@18, node@20.
	for _prefix in /opt/homebrew/Cellar /usr/local/Cellar; do
		for _f in "$_prefix"/node*/*/bin/node; do
			[ -f "$_f" ] && add_cand node "$_f"
		done
	done

	# distro package managers may install under non-PATH locations too
	for _f in /usr/lib/node*/bin/node /opt/node*/bin/node /opt/node*/bin/nodejs; do
		[ -f "$_f" ] && add_cand node "$_f"
	done

	# n (tj/n) - stores every installed version under /usr/local/n
	for _f in /usr/local/n/versions/node/*/bin/node /usr/local/n/versions/node/*/bin/nodejs; do
		[ -f "$_f" ] && add_cand node "$_f"
	done

	# Per-user version managers: nvm, volta, fnm, asdf, nodenv
	list_homes | while IFS= read -r _h; do
		[ -n "$_h" ] && [ -d "$_h" ] || continue
		for _f in \
			"$_h"/.nvm/versions/node/*/bin/node \
			"$_h"/.volta/tools/image/node/*/bin/node \
			"$_h"/.fnm/node-versions/*/installation/bin/node \
			"$_h"/.local/share/fnm/node-versions/*/installation/bin/node \
			"$_h"/.asdf/installs/nodejs/*/bin/node \
			"$_h"/.nodenv/versions/*/bin/node \
			"$_h"/.nodenv/versions/*/bin/nodejs
		do
			[ -f "$_f" ] && add_cand node "$_f"
		done
	done

	if [ "$SCAN_BUN" = 1 ]; then
		for _f in /usr/local/bin/bun /opt/homebrew/bin/bun; do
			[ -f "$_f" ] && add_cand bun "$_f"
		done
		_c=$(command -v bun 2>/dev/null) && add_cand bun "$_c"
		for _prefix in /opt/homebrew/Cellar /usr/local/Cellar; do
			for _f in "$_prefix"/bun/*/bin/bun; do
				[ -f "$_f" ] && add_cand bun "$_f"
			done
		done
		list_homes | while IFS= read -r _h; do
			[ -n "$_h" ] && [ -d "$_h" ] || continue
			for _f in "$_h"/.bun/bin/bun; do
				[ -f "$_f" ] && add_cand bun "$_f"
			done
		done
	fi
}

# collect_processes - Linux only, via /proc/[pid]/exe
collect_processes() {
	[ -d /proc ] || return 0
	_self_ns=$(readlink /proc/self/ns/mnt 2>/dev/null)
	for _exe in /proc/[0-9]*/exe; do
		[ -e "$_exe" ] || continue
		_pid=$(printf '%s' "$_exe" | sed -n 's#/proc/\([0-9]*\)/exe#\1#p')
		# skip processes in a different mount namespace (containers);
		# scan_containers handles those via docker/podman exec instead.
		if [ -n "$_self_ns" ]; then
			_pns=$(readlink "/proc/$_pid/ns/mnt" 2>/dev/null)
			[ "$_pns" = "$_self_ns" ] || continue
		fi
		_target=$(readlink "$_exe" 2>/dev/null) || continue
		case "$_target" in
			*" (deleted)")
				_target=${_target% (deleted)}
				_kind=$(runtime_name "$_target")
				[ -n "$_kind" ] && printf '%s\037%s\n' "$_kind" "$_target" >>"$TMP/stale"
				continue
				;;
		esac
		_kind=$(runtime_name "$_target")
		[ -n "$_kind" ] || continue
		[ "$_kind" = "bun" ] && [ "$SCAN_BUN" != 1 ] && continue
		# record which user this binary is actually running as, keyed by
		# its real path, so check_install can report live usage, not just
		# file ownership (an unused install and the live service binary
		# are very different things to act on).
		_ruser=$(ps -o user= -p "$_pid" 2>/dev/null | tr -d ' ')
		if [ -n "$_ruser" ]; then
			_rreal=$(resolve "$_target")
			printf '%s\037%s\037%s\n' "$_rreal" "$_ruser" "$_pid" >>"$TMP/running"
		fi
		add_cand "$_kind" "$_target"
	done
}

collect_deep() {
	[ "$DEEP" = 1 ] || return 0
	find / \
		\( -path /proc -o -path /sys -o -path /dev -o -path /run \
		   -o -path '*/node_modules' -o -fstype nfs -o -fstype smbfs \) -prune -o \
		\( -type f -a \( -name node -o -name nodejs -o \( -name bun -a "$SCAN_BUN" = 1 \) \) \) \
		-print 2>/dev/null |
	while IFS= read -r _f; do
		_kind=$(runtime_name "$_f")
		[ -n "$_kind" ] && add_cand "$_kind" "$_f"
	done
}

# safe_to_exec FILE -> 0 if ok to execute, 1 otherwise.
# As non-root: always ok (you can only run what your own perms allow).
# As root: only run binaries root owns that nobody else can write to.
safe_to_exec() {
	_f="$1"
	[ "$IS_ROOT" = 1 ] || return 0
	_stat=$(stat -c '%U %a' "$_f" 2>/dev/null || stat -f '%Su %p' "$_f" 2>/dev/null) || return 1
	_owner=${_stat%% *}
	_mode=${_stat##* }
	_mode=${_mode#*0}
	[ "$_owner" = "root" ] || return 1
	_last3=${_mode#"${_mode%???}"}
	_grp=$(printf '%s' "$_last3" | cut -c2)
	_oth=$(printf '%s' "$_last3" | cut -c3)
	case "$_grp" in 2|3|6|7) return 1 ;; esac
	case "$_oth" in 2|3|6|7) return 1 ;; esac
	return 0
}

# owner_of FILE -> prints the Unix user that owns the file on disk
owner_of() {
	stat -c '%U' "$1" 2>/dev/null || stat -f '%Su' "$1" 2>/dev/null || printf 'unknown'
}

# file_version FILE KIND -> best-effort version string read from the raw
# bytes of a binary we chose not to execute. Node binaries embed the
# download URL used for process.release.sourceUrl, which is a reliable,
# low-noise string to grep for. Bun has no equally reliable marker known
# to this script, so it is left undetermined in that fallback path.
file_version() {
	_f="$1"; _kind="$2"
	if [ "$_kind" = "node" ]; then
		if grep -aoE 'nodejs\.org/download/release/v[0-9]+\.[0-9]+\.[0-9]+' "$_f" 2>/dev/null |
			head -n1 | sed -E 's#.*/v##'; then
			return 0
		fi
	fi
	printf ''
}

read_version() {
	_kind="$1"; _path="$2"
	V_FULL=""
	if safe_to_exec "$_path"; then
		case "$_kind" in
			node) _out=$("$_path" -v </dev/null 2>/dev/null) ;;
			bun) _out=$("$_path" --version </dev/null 2>/dev/null) ;;
			*) _out="" ;;
		esac
		_out=$(printf '%s' "$_out" | head -n1 | tr -d '\r')
		_v=${_out#v}
		case "$_v" in
			[0-9]*.[0-9]*.[0-9]*) V_FULL="$_v" ;;
		esac
	fi
	if [ -z "$V_FULL" ]; then
		_fv=$(file_version "$_path" "$_kind")
		[ -n "$_fv" ] && V_FULL="$_fv"
	fi
}

# pkg_owner PATH -> sets PKG_MGR, PKG_NAME, PKG_VER if the file belongs to
# a package manager's database.
pkg_owner() {
	PKG_MGR=""; PKG_NAME=""; PKG_VER=""
	_f="$1"
	case "$_f" in
		*/Cellar/*)
			PKG_MGR="brew"
			PKG_NAME=$(printf '%s' "$_f" | sed -E 's#.*/Cellar/([^/]+)/.*#\1#')
			PKG_VER=$(printf '%s' "$_f" | sed -E 's#.*/Cellar/[^/]+/([^/]+)/.*#\1#')
			return 0
			;;
	esac
	if command -v dpkg >/dev/null 2>&1; then
		_pkg=$(dpkg -S "$_f" 2>/dev/null | head -n1 | cut -d: -f1)
		if [ -n "$_pkg" ]; then
			PKG_MGR="dpkg"; PKG_NAME="$_pkg"
			PKG_VER=$(dpkg-query -W -f='${Version}' "$_pkg" 2>/dev/null)
			return 0
		fi
	fi
	if command -v rpm >/dev/null 2>&1; then
		_pkg=$(rpm -qf "$_f" 2>/dev/null | head -n1)
		case "$_pkg" in
			*"not owned"*|"") ;;
			*)
				PKG_MGR="rpm"
				PKG_NAME=$(rpm -q --qf '%{NAME}' -f "$_f" 2>/dev/null)
				PKG_VER=$(rpm -q --qf '%{VERSION}-%{RELEASE}' -f "$_f" 2>/dev/null)
				return 0
				;;
		esac
	fi
	if command -v apk >/dev/null 2>&1; then
		_pkg=$(apk info --who-owns "$_f" 2>/dev/null | sed -n 's/.*is owned by //p' | sed 's/-[0-9].*//')
		if [ -n "$_pkg" ]; then
			PKG_MGR="apk"; PKG_NAME="$_pkg"
			PKG_VER=$(apk info -e "$_pkg" 2>/dev/null)
			return 0
		fi
	fi
	case "$_f" in */snap/*) PKG_MGR="snap"; PKG_NAME=$(printf '%s' "$_f" | sed -E 's#.*/snap/([^/]+)/.*#\1#'); return 0 ;; esac
}

# assess KIND VERSION -> sets ST, BRANCH, TARGET, EOL, WHY
assess() {
	_kind="$1"; _v="$2"
	ST="UNKNOWN"; BRANCH=""; TARGET=""; EOL=0; WHY=""

	if [ -z "$_v" ]; then
		WHY="could not determine the installed version"
		return 0
	fi

	if [ "$_kind" = "bun" ]; then
		if [ "$(ver_ge "$_v" "$BUN_FIXED")" = 1 ]; then
			ST="PATCHED"
		elif [ "$(ver_ge "$_v" "$BUN_AFFECTED_FLOOR")" = 1 ]; then
			ST="VULNERABLE"; TARGET="$BUN_FIXED"
			WHY="Bun bundles the same vulnerable Brotli decoder as Node.js"
		else
			WHY="version predates the range this script evaluates; verify manually against Bun's advisory"
		fi
		return 0
	fi

	BRANCH=$(printf '%s' "$_v" | cut -d. -f1)
	case "$BRANCH" in
		''|*[!0-9]*) WHY="unrecognized version string"; return 0 ;;
	esac

	_fixed=$(fixed_for "$BRANCH")
	if [ -n "$_fixed" ]; then
		TARGET="$_fixed"
		if [ "$(ver_ge "$_v" "$_fixed")" = 1 ]; then
			ST="PATCHED"
		else
			ST="VULNERABLE"
			WHY="Node.js $BRANCH.x is affected below $_fixed"
		fi
		return 0
	fi

	if [ "$BRANCH" -gt 26 ]; then
		WHY="major $BRANCH is newer than any release this script knows about; verify manually"
		return 0
	fi

	ST="VULNERABLE"; EOL=1; TARGET="$MIGRATE_TARGET"
	WHY="Node.js $BRANCH.x is end-of-life and will not receive a fix; migrate to a maintained line"
}

# update_cmd MGR PATH PKG KIND TARGET OLD EOL -> prints the exact command
# to run. TARGET is always a single pinned version here, never "--lts" or
# "lts/*" - which version nvm/npm consider "latest LTS" changes over time
# (a newly-released major can flip to LTS within days of a security
# release), so a floating alias can silently jump you past the line your
# app was actually tested on.
update_cmd() {
	_mgr="$1"; _path="$2"; _pkg="$3"; _kind="$4"; _target="$5"; _old="$6"; _eol="$7"

	if [ "$_eol" = 1 ]; then
		case "$_mgr" in
			dpkg|rpm|apk|snap)
				printf 'the %s package for this end-of-life line will not get a fix upstream; move this install to nvm (or another version manager) and pick a maintained line' "$_mgr"
				return 0
				;;
		esac
		printf 'pick a maintained line for this app (22.23.4, 24.22.1 or 26.12.1), then run the matching install command for your version manager with that exact version - for nvm: nvm install <version> && nvm alias default <version>   # then: nvm uninstall %s' "${_old:-<old-version>}"
		return 0
	fi

	case "$_mgr" in
		dpkg) printf 'sudo apt-get update && sudo apt-get install --only-upgrade %s' "${_pkg:-nodejs}" ;;
		rpm) printf 'sudo dnf upgrade %s   # or: sudo yum update %s' "${_pkg:-nodejs}" "${_pkg:-nodejs}" ;;
		apk) printf 'sudo apk upgrade %s' "${_pkg:-nodejs}" ;;
		brew) printf 'brew upgrade %s' "${_pkg:-node}" ;;
		snap) printf 'sudo snap refresh %s' "${_pkg:-node}" ;;
		*)
			case "$_path" in
				*/.nvm/versions/node/*) printf 'nvm install %s && nvm alias default %s   # then: nvm uninstall %s' "$_target" "$_target" "${_old:-<old-version>}" ;;
				*/.volta/tools/image/node/*) printf 'volta install node@%s' "$_target" ;;
				*/.fnm/node-versions/*|*/fnm/node-versions/*) printf 'fnm install %s && fnm default %s' "$_target" "$_target" ;;
				*/.asdf/installs/nodejs/*) printf 'asdf install nodejs %s && asdf global nodejs %s' "$_target" "$_target" ;;
				*/.nodenv/versions/*) printf 'nodenv install %s && nodenv global %s' "$_target" "$_target" ;;
				*/n/versions/node/*) printf 'sudo n %s' "$_target" ;;
				*/.bun/bin/*) printf 'bun upgrade   # or: curl -fsSL https://bun.sh/install | bash' ;;
				*) printf 'reinstall/rebuild the %s binary from a release >= %s' "$_kind" "$_target" ;;
			esac
			;;
	esac
}

show() {
	_status="$1"; _label="$2"; shift 2
	case "$_status" in
		VULNERABLE) _c="$C_RED"; _tag="VULNERABLE" ;;
		PATCHED) _c="$C_GRN"; _tag="patched   " ;;
		UNKNOWN) _c="$C_YEL"; _tag="unknown   " ;;
		STALE) _c="$C_YEL"; _tag="RESTART   " ;;
		*) _c=""; _tag="$_status" ;;
	esac
	printf '  %s[%s]%s %s\n' "$_c" "$_tag" "$C_RST" "$_label"
	for _d in "$@"; do
		[ -n "$_d" ] && printf '          %s\n' "$_d"
	done
}

count() {
	case "$1" in
		VULNERABLE) N_VULN=$((N_VULN + 1)) ;;
		PATCHED) N_OK=$((N_OK + 1)) ;;
		UNKNOWN) N_UNK=$((N_UNK + 1)) ;;
	esac
}

record() {
	printf '%s\037%s\037%s\037%s\037%s\037%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >>"$TMP/results"
}

check_install() {
	_kind="$1"; _path="$2"; _orig="$3"
	read_version "$_kind" "$_path"
	_old_v="$V_FULL"
	assess "$_kind" "$V_FULL"
	pkg_owner "$_path"

	_detail=""
	if [ "$ST" = "VULNERABLE" ]; then
		if [ "$EOL" = 1 ]; then
			_fix="EOL - no patch available; migrate to $TARGET: $(update_cmd "$PKG_MGR" "$_path" "$PKG_NAME" "$_kind" "$TARGET" "$_old_v" 1)"
		else
			_fix="upgrade to $TARGET: $(update_cmd "$PKG_MGR" "$_path" "$PKG_NAME" "$_kind" "$TARGET" "$_old_v" 0)"
		fi
		_detail="$_fix"
	elif [ "$ST" = "UNKNOWN" ]; then
		_detail="$WHY"
	fi

	_file_owner=$(owner_of "$_path")
	_run_as=""
	if [ -s "$TMP/running" ]; then
		_run_as=$(awk -F'\037' -v p="$_path" '$1==p{print $2}' "$TMP/running" | sort -u | tr '\n' ',' | sed 's/,$//')
	fi
	if [ -n "$_run_as" ]; then
		_who="owner: $_file_owner, running as: $_run_as"
	elif [ -d /proc ]; then
		_who="owner: $_file_owner, not currently running"
	else
		_who="owner: $_file_owner, running state unknown - process scan needs /proc (Linux)"
	fi

	_label="$_kind ${V_FULL:-unknown} at $_path ($_who)"
	[ "$_path" != "$_orig" ] && _label="$_label (via $_orig)"

	count "$ST"
	record "$ST" "$_label" "$PKG_MGR" "$PKG_NAME" "$PKG_VER" "$_detail"
}

print_results() {
	[ -s "$TMP/results" ] || { printf '  (no Node.js or Bun installs found)\n'; return 0; }
	for _st in VULNERABLE UNKNOWN PATCHED; do
		while IFS=$(printf '\037') read -r _s _label _mgr _pkg _pkgver _note; do
			[ "$_s" = "$_st" ] || continue
			show "$_s" "$_label" "$_note"
		done <"$TMP/results"
	done
}

report_stale() {
	[ -s "$TMP/stale" ] || return 0
	printf '\n%sRunning processes using a deleted binary (upgraded on disk, not restarted):%s\n' "$C_BLD" "$C_RST"
	while IFS=$(printf '\037') read -r _kind _path; do
		show STALE "$_kind binary removed from disk: $_path" "restart the service/process using this interpreter"
		N_STALE=$((N_STALE + 1))
	done <"$TMP/stale"
}

scan_containers() {
	[ "$SCAN_CONTAINERS" = 1 ] || return 0
	for _eng in docker podman; do
		command -v "$_eng" >/dev/null 2>&1 || continue
		_ids=$("$_eng" ps -q 2>/dev/null) || continue
		[ -n "$_ids" ] || continue
		printf '\n%sContainers (%s):%s\n' "$C_BLD" "$_eng" "$C_RST"
		for _id in $_ids; do
			_name=$("$_eng" inspect --format '{{.Name}}' "$_id" 2>/dev/null | sed 's#^/##')
			for _kind in node bun; do
				[ "$_kind" = "bun" ] && [ "$SCAN_BUN" != 1 ] && continue
				_v=$("$_eng" exec "$_id" "$_kind" -v 2>/dev/null) || \
				_v=$("$_eng" exec "$_id" "$_kind" --version 2>/dev/null) || continue
				_v=$(printf '%s' "$_v" | head -n1 | tr -d '\r\n')
				_v=${_v#v}
				case "$_v" in [0-9]*.[0-9]*.[0-9]*) ;; *) continue ;; esac
				assess "$_kind" "$_v"
				_detail=""
				[ "$ST" = "VULNERABLE" ] && _detail="upgrade the container image to $_kind >= $TARGET"
				[ "$ST" = "UNKNOWN" ] && _detail="$WHY"
				show "$ST" "$_kind $_v in container ${_name:-$_id}" "$_detail"
				count "$ST"
			done
		done
	done
}

detect_os() {
	OS_NAME=$(uname -s 2>/dev/null)
	if [ -r /etc/os-release ]; then
		_pretty=$(sed -n 's/^PRETTY_NAME="\(.*\)"$/\1/p' /etc/os-release)
		[ -n "$_pretty" ] && OS_NAME="$_pretty"
	fi
}

main() {
	while [ $# -gt 0 ]; do
		case "$1" in
			--deep) DEEP=1 ;;
			--no-containers|--no-docker) SCAN_CONTAINERS=0 ;;
			--no-bun) SCAN_BUN=0 ;;
			--no-color) USE_COLOR=0 ;;
			-h|--help) usage; exit 0 ;;
			-V|--version) printf 'node2shell-check.sh %s\n' "$SELF_VERSION"; exit 0 ;;
			*)
				printf 'unknown option: %s\n\n' "$1" >&2
				usage >&2
				exit 64
				;;
		esac
		shift
	done

	setup_colors

	TMP=$(mktemp -d 2>/dev/null || mktemp -d -t node2shell) || {
		printf 'failed to create a temp directory\n' >&2
		exit 70
	}
	trap 'rm -rf "$TMP"' EXIT
	trap 'exit 130' INT TERM

	: >"$TMP/seen"
	: >"$TMP/cands"
	: >"$TMP/stale"
	: >"$TMP/results"
	: >"$TMP/running"

	if [ "$(id -u 2>/dev/null)" = "0" ]; then IS_ROOT=1; else IS_ROOT=0; fi
	detect_os

	printf '%sNode2Shell check (CVE-2026-111497)%s - host %s%s\n' "$C_BLD" "$C_RST" "$(uname -n 2>/dev/null)" "${OS_NAME:+ ($OS_NAME)}"
	[ "$IS_ROOT" = 1 ] || printf '%snote: not running as root - some installs or processes may be missed%s\n' "$C_YEL" "$C_RST"
	printf '\n'

	collect_static
	collect_processes
	collect_deep

	while IFS=$(printf '\037') read -r _kind _real _orig; do
		[ -n "$_kind" ] || continue
		check_install "$_kind" "$_real" "$_orig"
	done <"$TMP/cands"

	scan_containers
	print_results
	report_stale

	printf '\n%sSummary:%s %s%d vulnerable%s, %s%d patched%s, %s%d unknown%s, %s%d stale worker(s)%s\n' \
		"$C_BLD" "$C_RST" \
		"$C_RED" "$N_VULN" "$C_RST" \
		"$C_GRN" "$N_OK" "$C_RST" \
		"$C_YEL" "$N_UNK" "$C_RST" \
		"$C_YEL" "$N_STALE" "$C_RST"

	if [ "$N_VULN" -gt 0 ] || [ "$N_STALE" -gt 0 ]; then
		printf '\n%sFix:%s upgrade affected Node.js installs to %s (or the matching point\n' "$C_BLD" "$C_RST" "$MIGRATE_TARGET"
		printf 'release for your line), upgrade Bun to >= %s, and restart any\n' "$BUN_FIXED"
		printf 'process flagged as using a deleted/stale binary. EOL lines (20.x,\n'
		printf '23.x, 25.x and older) receive no fix - migrate them to a maintained\n'
		printf 'release line.\n'
	fi

	printf 'RESULT host=%s vulnerable=%d patched=%d unknown=%d stale=%d\n' \
		"$(uname -n 2>/dev/null)" "$N_VULN" "$N_OK" "$N_UNK" "$N_STALE"

	if [ "$N_VULN" -gt 0 ] || [ "$N_STALE" -gt 0 ]; then
		exit 1
	elif [ "$N_UNK" -gt 0 ]; then
		exit 2
	else
		exit 0
	fi
}

main "$@"
