# twin — Specification (v1, lean)

`twin` makes a directory on this machine match a directory elsewhere. The other side is either another local path (external drive, second disk) or a directory on another machine, served over mutual TLS.

One binary. No server to deploy, no daemon, no accounts, no config file, no chunk store. You run it, it converges the pair, it exits. Schedule it with cron / systemd timer / launchd when you want it periodic.

Prerequisites for a remote pair: `twin` installed on both machines, and a one-time exchange of certificate fingerprints (`twin id` there, `twin authorize <fingerprint>` here, `--pin <fingerprint>` on the first run). After that the client remembers the pin.

The superseded full-scope draft (hub, daemon, TUI, chunking, versioning, 126 requirements) is archived at `docs/archive/features-2026-09-13-full.md`; everything cut from v1 is listed with its re-entry trigger in §8.

## 1. Model

A **pair** is: local root, remote root (`host:/path` or `/abs/path`), mode, ignore rules. Three modes, one comparison model:

| Mode | Behavior |
|---|---|
| `sync` (default) | Two-way converge. Both sides end up equal; conflicts keep both versions |
| `push` | Local → remote, one-way. Add/update only unless `--delete` |
| `pull` | Remote → local, one-way. Same rules |

Two-way needs a record of what both sides last agreed on. That is the **archive**: one file per pair at `~/.local/share/twin/archive/<pair-id>.db` (SQLite, single table: path → kind, size, mtime, hash as of the last convergence). The archive plays the role of version vectors in a hub design — no vectors, no server-side causality, no merge points. If you would rather avoid SQLite, a JSONL file is acceptable below ~50k paths; the interface is `get/set/list`.

Comparison per path — current local vs archive vs current remote:

| Local vs archive | Remote vs archive | Action |
|---|---|---|
| equal | equal | nothing (metadata fast path) |
| changed | equal | propagate local → remote |
| equal | changed | propagate remote → local |
| changed | changed, equal to each other | update archive |
| changed | changed, differing | **conflict**: keep both, never overwrite |
| deleted | equal | delete remotely |
| equal | deleted | delete locally |
| deleted | changed | keep the change, report the resurrected path |
| deleted | deleted | drop from archive |

| ID | Requirement | Acceptance |
|---|---|---|
| F-001 | Pair identity | `twin sync ~/Docs mini:/srv/docs`; pair id = hash(local root, remote spec); archive created on first run |
| F-002 | First-run confirmation | A new pair prints the plan and does nothing unless `--auto` (or an interactive `yes`); a run that would touch > 100 paths never proceeds silently |
| F-003 | Idempotence | A second run immediately after a clean run performs zero transfers and zero writes, including archive writes |

## 2. Comparison

| ID | Requirement | Acceptance |
|---|---|---|
| F-010 | Metadata fast path | size + mtime (ns) + inode unchanged → file considered unchanged, never hashed, never transferred |
| F-011 | Hash verify | BLAKE3 whenever the fast path says changed, or sizes match with mtime differing inside a 2 s tolerance (coarse-mtime filesystems incl. FAT/exFAT) |
| F-012 | `--checksum` / `--fast` | `--checksum` hashes every tracked file on both sides; `--fast` trusts size+mtime and skips hashing entirely |
| F-013 | Streaming merge-walk | Both sides walked in sorted order and merged; plan memory is bounded per directory, not by tree size (500k files must not blow RSS) |
| F-014 | Hash memoization | Hashes live in the archive, so unchanged files are never rehashed across runs |
| F-015 | Plan output | `--dry-run` prints every action (create, update, delete, conflict, skip-with-reason) with sizes; exits 0, conflicts included — `twin verify` is the exception and keeps its own contract (0 in sync, 3 different) |
| F-016 | Plan/apply equivalence | The set of actions reported by `--dry-run` equals the set the real run performs — enforced by one test comparing plan output against an instrumented run |

## 3. Transfer

| ID | Requirement | Acceptance |
|---|---|---|
| F-020 | Whole-file transfer | Files move whole; no block-level delta, no chunk store |
| F-021 | Atomic placement | Write to `.twin-tmp-*` in the destination directory → fsync → `rename()`. No partial file ever exists under its real name (dir fsync on Linux, `F_FULLFSYNC` on macOS) |
| F-022 | Verified bytes | Hash the source while reading (torn reads caught) and re-verify the received file; mismatch → retry once, then fail the file and continue (counted, exit code 4) |
| F-023 | Resume with `--partial` | Interrupted transfers keep their temp file; the next run appends and verifies the finished hash — a bad prefix fails the hash and triggers a clean retransfer. The temp file is named after the destination, so the next run finds it; the wire protocol carries byte offsets (protocol version 2). Without the flag a transfer starts over and the temp file is removed |
| F-024 | Sequential, one connection | Files transfer one at a time over a single TLS connection per run; no muxing, no per-file connections |
| F-025 | Transport | TCP + **mutual TLS 1.3** (rustls, ring). Both ends hold a self-signed ECDSA P-256 key pair; each trusts the other by pinned certificate fingerprint — no CA, no accounts. `twin serve --root DIR --listen ADDR` serves; the protocol frames ride the TLS stream |
| F-026 | Local pairs | A path instead of `host:port` → plain filesystem copy path; identical semantics, no network involved |
| F-027 | Path confinement | The server refuses anything outside `--root`; the client refuses anything outside its local root: `..`, absolute paths, and symlinked ancestors rejected (the server half is done; the client half is still open) |
| F-028 | Protocol version handshake | First frame exchanges `twin` protocol versions; mismatch → actionable error, never silent misbehavior. A client whose fingerprint is not authorized is refused during the TLS handshake |
| F-029 | Disk-full / EIO | Per-file failure (ENOSPC, EACCES, I/O error) is reported with the path and errno, other files continue, exit code 4 — including a file that cannot be read while the plan is being built |

## 4. Deletions, conflicts, backup

| ID | Requirement | Acceptance |
|---|---|---|
| F-030 | Delete propagation | Two-way: deletes propagate only when the archive proves the other side is unchanged (§1 table). One-way: deletions happen only with `--delete` |
| F-031 | Mass-delete guard | A run that would delete more than max(100, 25 %) of tracked paths aborts before touching anything, listing what it would remove; `--force` overrides |
| F-032 | Conflict = keep both | Conflicting versions are preserved side by side as `<name>.conflict-<YYYYMMDD-HHMMSS>-<host>`; the local file keeps its name; both are reported and both converge afterwards |
| F-033 | Conflict exit status | Conflicts do not fail the run; exit code 3 means "converged, N conflicts kept" |
| F-034 | `--backup DIR` | Before overwriting or deleting anything, the old version is copied to `DIR` with a timestamped name, keeping the path under `DIR`. The backup lands on the client in both directions (the far side's version is fetched before it is overwritten); the backup directory is never synced, and a backup that cannot be written fails that file instead of being skipped |
| F-035 | Resurrections reported | A path deleted on one side but modified on the other is kept and explicitly listed, never silently re-created or silently dropped |

## 5. Ignore rules

| ID | Requirement | Acceptance |
|---|---|---|
| F-040 | `.twinignore` | gitignore syntax at the pair root, via the `ignore` crate; applies to both sides identically |
| F-041 | Built-in defaults | `.DS_Store`, `._*`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`, `lost+found`, `.twin/`, `.twin-tmp-*`, `*.swp`, `*~`; disable with `--no-default-ignores` |
| F-042 | Ignored ≠ deleted | A tracked path that becomes ignored leaves the archive without emitting a deletion; the run reports it once |

## 6. CLI

```
twin sync  <left> <right>     # two-way, default mode
twin push  <src>  <dst>       # one-way local → remote
twin pull  <src>  <dst>       # one-way remote → local
twin verify <left> <right>    # compare by hash, transfer nothing
twin id                       # this machine's fingerprint (creates its key)
twin authorize <fingerprint>  # let that client connect to this server
twin serve --root <dir>       # serve a directory over mutual TLS
```

| ID | Requirement | Acceptance |
|---|---|---|
| F-050 | Flags | `--dry-run --json --quiet -v --delete --force --checksum --fast --partial --backup DIR --exclude PAT --no-default-ignores --auto --pin HEX`. No config file; no state outside the data directory (`identity/`, `known_hosts`, `authorized_clients`, `archive/`) |
| F-051 | Exit codes | 0 converged · 1 error · 2 usage · 3 converged with conflicts · 4 partial (some files failed). A dry run exits 0 unless files failed |
| F-052 | `--json` events | One JSON object per line: plan entry, transfer start/finish, conflict, skip, error, summary; the last line is always the summary, and paths are relative to the synced root. Enough to build a UI on later |
| F-053 | Progress | TTY: current file, bytes, running total, ETA, drawn in place on standard error. Non-TTY: one line per completed file. The program prints no colour at all, so `NO_COLOR` has nothing to suppress |
| F-054 | Output restraint | Default output is a short summary; `-v` adds per-file lines; `--quiet` prints only errors |
| F-055 | Diagnostics | Failures name the operation and the path (`storing /srv/docs/a.txt: ...`), never a bare errno. Leveled diagnostics on stderr, off by default, raised by `-v`/`-vv` or `TWIN_LOG=error\|warn\|info\|debug` |
| F-056 | `twin doctor [PATH] [--remote ADDR --pin HEX]` | Probes the data dir, identity (key permissions, key↔cert usability), temp dir, archive integrity, free space, and the sync root's real abilities — create, atomic replace, mtime precision, fsync — plus whether this host's own network policy lets this program be reached on the local network (macOS firewall / local-network permission), naming the fixes that work — an ad-hoc signature (`codesign -s - -f --identifier dev.twin.cli <binary>`, no password needed), a firewall allowance, or granting Local Network access — and warning that a running server keeps the decision it started with. Then TCP/TLS/handshake/listing against a server. One line per check; exits 1 if anything failed |

## 7. Correctness and safety

| ID | Requirement | Acceptance |
|---|---|---|
| F-060 | Platform pairs | macOS ↔ Linux, macOS ↔ macOS, Linux ↔ Linux, machine ↔ external drive. Case-insensitive and normalization-insensitive detection where it matters |
| F-061 | Name representation | Names travel as raw bytes. If the destination cannot represent a name (non-UTF-8 created on Linux, NFD/NFC or case variant of an existing path on macOS), the file is skipped with a named reason — never overwritten, never silently dropped |
| F-062 | Interrupted runs | Kill the process at any point: no partial files under real names, archive remains consistent (per-file transactions), the next run converges |
| F-063 | Archive loss | Deleting the archive is recoverable: the next run falls back to `--checksum` classification and rebuilds it. (Two-way with an empty archive performs no destructive action without `--auto`) |
| F-066 | Host policy is named, not guessed | A connection torn down by the system before it can be used (macOS firewall / local-network permission) is reported as such, with the settings to change, instead of surfacing as EINVAL from socket options and ENOTCONN from reads |
| F-067 | Timestamp resilience | Setting an mtime is best-effort: a filesystem that refuses it (exFAT, NTFS-3g, several FUSE/SMB/virtiofs mounts answer EINVAL) warns and continues, because hashes decide what syncs. Nanosecond values are floored, never truncated, so pre-1970 timestamps cannot become an illegal `tv_nsec` |
| F-064 | Root sanity | Refuse to sync if either root is missing, unreadable, or contains the other (nesting); refuse if a root is `.` or `/` |
| F-065 | Clock skew | mtime is used only as a fast path; equality decisions rest on hashes, so differently-set clocks do not cause spurious transfers or wrong winners |

## 8. Parked (cut from v1, with re-entry triggers)

| Parked | Add when | Re-entry cost |
|---|---|---|
| Daemon + file watching (sync on save) | manual/timer runs become annoying | thin: `watch → run engine`; no new engine code |
| TUI | long runs need live progress | small: consumes `--json` events |
| Block-level delta (rsync algorithm) | WAN uploads of large files hurt | medium: one file's worth of rolling-checksum logic |
| Content-defined chunking, CAS, dedup | when delta alone is insufficient and history is wanted | large; this is where the archived draft's complexity lives |
| Version history + `restore` | `--backup` proves insufficient | large: hub or per-pair version store |
| Central hub, multi-device fan-out, shares, quotas | more than ~4 machines, or a replica that is always online | large: accounts, mTLS, manifests, GC — the archived draft |
| Config file, named pairs, completions, man pages | second user | small |
| Packaging: Homebrew tap, .deb/.rpm, Docker, installers | distributing to others | small, but needs ongoing CI |
| Prometheus metrics, fuzzing, simulation harness, perf budgets, 4-target release matrix | protocol growth or contributors | medium |
| Windows | a Windows machine to sync | medium: paths, ACLs, no POSIX rename semantics |

N machines with no hub = N(N−1)/2 pairs; fine for 2–4 devices, and each pair is independent. A server serves exactly one root, so two shared directories means two `twin serve` instances (different ports).

## 9. Tests (deliberately small)

| ID | Requirement | Acceptance |
|---|---|---|
| F-070 | Plan/classification tests | Table-driven over the §1 comparison matrix, including ignore interaction and name-collision cases |
| F-071 | Local integration | Real temp directories: create/update/delete/conflict/resume/backup, 10k-file tree |
| F-072 | Transport integration | A real `twin serve` on loopback, a real client: push, pull, two-way, conflicts, deletions, multi-chunk files, unauthorized client refused, wrong pin refused, pin remembered, first contact refused without a pin |
| F-073 | Crash test | SIGKILL mid-transfer; assert no partial files under real names, archive consistent, next run converges |
| F-074 | Two-platform CI | `cargo fmt`, `clippy -D warnings`, `cargo test` on macOS and Linux. Nothing else |

`.github/workflows/ci.yml` runs the three commands on both platforms. The 10k-file tree of F-071 is the one slow test — F-021 puts every file through an fsync, and on macOS that fsync is an `F_FULLFSYNC`, so ten thousand files cost minutes — so it is `#[ignore]`d in the default run and gets a job of its own (`cargo test --test scale -- --ignored`), where it can take as long as it needs. The crash test of F-073 runs a real `twin serve` on loopback, kills the client with SIGKILL while a 256 MiB transfer is in flight, and then asserts the three things that matter: no file under a real name is partial, the archive never records what was not verified, and the next run converges.

## 10. Build order (why this is finishable)

1. Compare + plan + `--dry-run` (pure functions over two directory walks) — testable with zero I/O risk. **Done**
2. Local pair transfer with archive, atomic placement, `--backup`. **Done**
3. Remote transport + `serve` + handshake + resume. **Done over mutual TLS (`twin serve`, `twin id`, `twin authorize`, pinning), with `--partial` (F-023) resuming an interrupted transfer**
4. Deletions, conflict copies, guards. **Done**
5. `--json`, progress, exit codes, docs. **Done: `--json` (F-052), progress (F-053), exit codes (F-051/F-015), diagnostics and `twin doctor` (F-054/F-055/F-056)**

On macOS a binary must be signed before the system lets it serve the local network, so the build signs what it produces: `make build` / `make release` run `scripts/codesign-macos.sh` (ad-hoc, no certificate and no sudo; a no-op on Linux, and it skips an already-signed file). `twin serve` warns at startup when the running binary is unsigned, and `twin doctor` reports `binary signature` next to `local network accepts connections`.


No daemon, no accounts, no CA, no protocol versioning beyond one handshake line. Dependencies: `clap`, `ignore`, `blake3`, `rusqlite`, `rustls`, `rcgen`, `rustls-pemfile`, `sha2`, `filetime`, `libc`. 49 requirements instead of 126.
