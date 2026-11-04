# node2shell-check

A read-only, zero-dependency POSIX `sh` scanner that finds Node.js and Bun
installs affected by **"Node2Shell" (CVE-2026-111497)** — an out-of-bounds
write in the Brotli decoder bundled with Node.js (and with Bun, which
ships the same decoder) — and tells you what to upgrade and how.

| Line | Affected | Fixed in |
|---|---|---|
| Node.js 22.x | yes | 22.23.4 |
| Node.js 24.x | yes | 24.22.1 |
| Node.js 26.x | yes | 26.12.1 |
| Node.js 20.x, 23.x, 25.x | yes, **end-of-life — no fix** | migrate to a maintained line |
| Bun | yes (bundles the same Brotli decoder) | 1.4.4 |

The underlying Brotli library bug also affects other software that
bundles Brotli (Python, curl, Git for Windows, Envoy, …); this tool only
covers Node.js and Bun.

## Usage

Run it directly:

```sh
curl -fsSL https://raw.githubusercontent.com/aymenkmar/node2shell-check/master/node2shell-check.sh | sudo sh
```

```sh
wget -qO- https://raw.githubusercontent.com/aymenkmar/node2shell-check/master/node2shell-check.sh | sudo sh -s -- --deep
```

Prefer to review before running, or pin a specific commit:

```sh
curl -fsSL https://raw.githubusercontent.com/aymenkmar/node2shell-check/<commit>/node2shell-check.sh -o node2shell-check.sh
less node2shell-check.sh
sudo sh node2shell-check.sh
```

Run as root for a complete scan — per-user version managers (nvm, volta,
fnm, asdf, nodenv), full process inspection, and container scanning all
need root to be reliable. Without root the script still works, it just
may miss some installs.

### Options

```
--deep            Also search all local filesystems with find(1), not
                   just well-known install locations (slower).
--no-containers   Skip scanning running Docker/Podman containers.
--no-docker       Alias for --no-containers.
--no-bun          Skip scanning for the Bun runtime.
--no-color        Disable ANSI colors in the output.
-h, --help        Show help and exit.
-V, --version     Show the script version and exit.
```

### Scanning a fleet

Every run ends with a single machine-parseable line:

```
RESULT host=<hostname> vulnerable=<n> patched=<n> unknown=<n> stale=<n>
```

Loop over hosts over SSH and grep that line:

```sh
for h in $(cat hosts.txt); do
  printf '%s: ' "$h"
  ssh "$h" 'curl -fsSL https://raw.githubusercontent.com/aymenkmar/node2shell-check/master/node2shell-check.sh | sudo sh' | grep '^RESULT'
done
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing vulnerable found |
| 1 | a vulnerable build or a stale (upgraded-but-not-restarted) worker was found |
| 2 | only undetermined builds were found |
| 64 | usage error |
| 70 | could not create a temp directory |

## What it checks

- **Versions**: compares each found binary's version against the fixed
  releases above.
- **Locations**: distro packages (dpkg/rpm/apk), Homebrew (incl.
  versioned formulae like `node@20`), snap, `n`, and per-user installs
  under nvm, volta, fnm, asdf and nodenv across every discoverable home
  directory.
- **Running processes** (Linux): reads `/proc/[pid]/exe` to catch
  interpreters running from paths the static scan didn't enumerate.
- **Containers**: runs `node -v`/`bun --version` inside every running
  Docker/Podman container.
- **Stale workers**: on Linux, flags processes still running a binary an
  upgrade deleted from disk — these need a restart to actually be fixed.
- **Package-manager backing**: when a binary belongs to dpkg, rpm, apk,
  Homebrew or snap, the report names the package so you can use your
  normal update flow instead of a manual reinstall.

## Safety

This script only reads. It never installs, upgrades, restarts or
modifies anything on the host.

When run as root, it executes `<binary> -v` / `--version` only on files
that are owned by root and that no other user or group can write to.
Every other binary is inspected by reading its bytes (looking for the
embedded Node.js download-URL string used by `process.release.sourceUrl`)
rather than executed.

## Limits

- Process inspection via `/proc` is Linux-only; on macOS/BSD only the
  static install-path scan runs.
- Stopped containers, container images, and Kubernetes pods are not
  scanned — only running Docker/Podman containers.
- The file-based version fallback only works for Node.js binaries; a Bun
  binary that can't be safely executed is reported as unknown rather than
  guessed at.
- Node majors newer than 26 are reported as unknown rather than assumed
  patched, since this script has no fixed-release data for them yet.
- Windows is not supported.

## Interim mitigations

Upgrading is the only complete fix. Until you can, the public advisories
describe partial mitigations such as disabling Brotli
(`Content-Encoding: br`) decompression of untrusted input at your
application or reverse-proxy layer. Read the official advisories before
relying on a workaround instead of patching.

## License

MIT — see [LICENSE](LICENSE).
