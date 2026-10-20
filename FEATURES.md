# twin — what it does today

**This file describes the program as it is built.** Every requirement below is implemented and covered by the test suite, unless its row says otherwise. Work that is **not** built lives in [PENDING.md](PENDING.md), not here.

`twin` copies a directory to another one. The other side is either another local path (external drive, second disk) or a directory on another machine, served over mutual TLS.

One binary. No server to deploy, no daemon, no accounts, no config file, no chunk store. You run it, it copies the pair, it exits. Schedule it with cron / systemd timer / launchd when you want it periodic.

Prerequisites for a remote pair: `twin` installed on both machines, and a one-time exchange of certificate fingerprints (every run of `twin` prints this machine's fingerprint, so run it on the client, then `twin authorize <fingerprint>` on the server, and pass `--pin <fingerprint>` on the first sync). After that the client remembers the pin.

> This document was corrected against the implementation. Two kinds of marks appear inline: **partly** — the requirement is not fully implemented, and the gap is in [PENDING.md](PENDING.md); **corrected** — the requirement text promised something the code never did, and it now describes what the program actually does. Every **partly** row has an entry in PENDING.md; the **corrected** ones have no open work behind them.

## 1. Model

A **pair** is: source, destination, ignore rules. One direction, one comparison model: the content always flows from the source to the destination.

| Role | Behavior |
|---|---|
| source (the first argument) | Read. Never written. |
| destination (the second argument) | Written. Never the authority. |

The source wins. A file that changed on the destination is put back to what the source holds, and a file the source no longer has is only removed from the destination when `--delete` says so.

The archive is what the pair last agreed on: one file per pair at `~/.local/share/twin/archive/<pair-id>.db` (SQLite, single table: path → kind, size, mtime of the source, mtime of the destination, hash as of the last convergence). The pair id is a hash of the source and the destination **in that order**, so the same two directories in the other direction are a different pair with a different archive. The archive is a cache, not a history: losing it costs a re-hash, nothing else.

Comparison per path — current source vs archive vs current destination:

| Source vs archive | Destination vs archive | Action |
|---|---|---|
| equal | equal | nothing (metadata fast path) |
| changed | equal | copy the source to the destination |
| equal | changed, same content | update the archive row |
| equal | changed, other content | copy the source to the destination |
| present | absent | copy the source to the destination |
| absent | present | delete it there — only with `--delete`; otherwise skip it and say why |
| absent | absent | drop the archive row |

| ID | Requirement | Acceptance |
|---|---|---|
| F-001 | Pair identity | `twin sync ~/Docs mini:/srv/docs`; pair id = hash(source, destination) in that order; archive created on first run |
| F-002 | First-run confirmation | A new pair prints the plan and does nothing unless `--auto` (or an interactive `yes`). A run that would delete more than the guard limit (F-031) aborts before touching anything |
| F-003 | Idempotence | A second run immediately after a clean run performs zero transfers and zero writes, including archive writes |

## 2. Comparison

| ID | Requirement | Acceptance |
|---|---|---|
| F-010 | Metadata fast path | size + mtime (ns) + kind unchanged → the file is considered unchanged: never hashed, never transferred. **partly**: the earlier text said "inode"; the archive has no inode column, and inode is not portable to the exFAT/NTFS targets this program names (PENDING.md) |
| F-011 | Hash verify | BLAKE3 whenever the fast path says changed. A file whose mtime moved but whose content did not is caught by the hash, and the archive row is refreshed, so the next run is quiet again. **corrected**: the earlier text promised a 2 s tolerance for coarse-mtime filesystems; there is no tolerance window — a coarse mtime costs one extra hash, never a wrong transfer |
| F-012 | `--checksum` / `--fast` | `--checksum` hashes every tracked file on both sides. `--fast` never hashes a file the archive already knows; a file it has never seen is hashed once, because there is nothing to compare it against |
| F-013 | Streaming merge-walk | Both sides are walked in sorted order and merged, so a path is decided once and the walk itself streams. **partly**: the earlier text claimed plan memory is bounded per directory; the plan holds one entry per changed path, so memory grows with the number of changes, not with the size of the tree (PENDING.md) |
| F-014 | Hash memoization | Hashes live in the archive, so unchanged files are never rehashed across runs. A path the two ends already agree on is written to the archive on first sight, so the memoization engages from the first run |
| F-015 | Plan output | `--dry-run` prints every action (create, update, delete, skip-with-reason) with sizes; exits 0 unless files failed |
| F-016 | Plan/apply equivalence | The plan a dry run prints is the plan the real run prints, path for path — enforced by one test. **partly**: the test compares two plans; it does not instrument the run to compare against what was actually done (PENDING.md) |

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
| F-027 | Path confinement | The server refuses anything outside `--root`. **partly**: the client half is still open — a remote-supplied path is joined onto the local root unchecked (PENDING.md) |
| F-028 | Protocol version handshake | First frame exchanges `twin` protocol versions; mismatch → actionable error, never silent misbehavior. A client whose fingerprint is not authorized is refused during the TLS handshake |
| F-029 | Disk-full / EIO | Per-file failure (ENOSPC, EACCES, I/O error) is reported with the path and errno, other files continue, exit code 4 — including a file that cannot be read while the plan is being built |

## 4. Deletions and backup

| ID | Requirement | Acceptance |
|---|---|---|
| F-030 | Delete propagation | The destination gives up a path only when the source does not have it, and only with `--delete`; without the flag the path is skipped and the reason is reported |
| F-031 | Mass-delete guard | A run that would delete more than max(100, 25 %) of tracked paths aborts before touching anything, listing what it would remove; `--force` overrides |
| F-034 | `--backup DIR` | Before overwriting or deleting anything, the old version is copied to `DIR` with a timestamped name, keeping the path under `DIR`. The backup lands on the client: when the destination is the far side, its version is fetched before it is overwritten. The backup directory is never synced, and a backup that cannot be written fails that file instead of being skipped |

## 5. Ignore rules

| ID | Requirement | Acceptance |
|---|---|---|
| F-040 | `.twinignore` | gitignore syntax at the root of the end that is on this machine, via the `ignore` crate; the same rules apply to both ends |
| F-041 | Built-in defaults | `.DS_Store`, `._*`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`, `lost+found`, `.twin/`, `.twin-tmp-*`, `*.swp`, `*~`; disable with `--no-default-ignores` |
| F-042 | Ignored ≠ deleted | A tracked path that becomes ignored is not a deletion: nothing is removed on either side. **corrected**: the earlier text said the path leaves the archive; the row stays, because the file is still on disk |

## 6. CLI

```
twin sync <source> <destination>  # copy the source to the destination
twin authorize <fingerprint>      # let that client connect to this server
twin authorize clear              # let nobody in
twin serve --root <dir>           # serve a directory over mutual TLS
```

There is no `id` command: every run prints this machine's fingerprint before it does anything else, so there is always a way to see it.

The order of the two arguments is the direction: the content flows from the first to the second, and only the second is written. One of the two must be a directory on this machine.

| ID | Requirement | Acceptance |
|---|---|---|
| F-050 | Flags | `--dry-run --json --quiet -v --delete --force --checksum --fast --partial --backup DIR --archive-dir DIR --exclude PAT --no-default-ignores --auto --pin HEX`. No config file; no state outside the data directory (`identity/`, `known_hosts`, `authorized_clients`, `archive/`) |
| F-051 | Exit codes | 0 done · 1 error · 2 usage · 4 partial (some files failed). A dry run exits 0 unless files failed |
| F-052 | `--json` events | One JSON object per line: plan entry, transfer start/finish, skip, error, summary; the last line is always the summary, names the source and the destination, and paths are relative to the synced root. Enough to build a UI on later |
| F-053 | Progress | TTY: current file, bytes, running total, ETA, drawn in place on standard error. Non-TTY: one line per completed file. The program prints no colour at all, so `NO_COLOR` has nothing to suppress |
| F-054 | Output restraint | Default output is a short summary; `-v` adds per-file lines; `--quiet` prints only errors |
| F-055 | Diagnostics | Failures name the operation and the path (`storing /srv/docs/a.txt: ...`), never a bare errno. Leveled diagnostics on stderr, off by default, raised by `-v`/`-vv` or `TWIN_LOG=error\|warn\|info\|debug` |
| F-056 | `twin doctor [PATH] [--remote ADDR --pin HEX]` | Probes the data dir, identity (key permissions, key↔cert usability), temp dir, archive integrity, free space, and the sync root's real abilities — create, atomic replace, mtime precision, fsync — plus whether this host's own network policy lets this program be reached on the local network (macOS firewall / local-network permission), naming the fixes that work — an ad-hoc signature (`codesign -s - -f --identifier dev.twin.cli <binary>`, no password needed), a firewall allowance, or granting Local Network access — and warning that a running server keeps the decision it started with. Then TCP/TLS/handshake/listing against a server. One line per check; exits 1 if anything failed |
| F-057 | Startup fingerprint | Every run prints this machine's fingerprint on standard error before it does anything else — `twin fingerprint: <64 hex>` — so the other side can be told about it without a separate command. `--help` prints it too. The report on standard output stays machine-readable |
| F-058 | `twin authorize clear` | Removes every authorized client at once and says how many there were. The list is read back before every connection, so a running server refuses every client from its next connection. `twin authorize` without an argument says what it wants |

## 7. Correctness and safety

| ID | Requirement | Acceptance |
|---|---|---|
| F-060 | Platform pairs | macOS ↔ Linux, macOS ↔ macOS, Linux ↔ Linux, machine ↔ external drive. The CI runs the whole suite on macOS and on Linux |
| F-061 | Name representation | Names travel as raw bytes, so a name created on Linux survives the trip. **partly**: a name the destination cannot represent (non-UTF-8, NFD/NFC or a case variant of an existing path) is not detected yet — it is written instead of being skipped with a named reason (PENDING.md) |
| F-062 | Interrupted runs | Kill the process at any point: no partial files under real names, archive remains consistent (per-file transactions), the next run converges |
| F-063 | Archive loss | Deleting the archive is recoverable: the next run classifies by hash and rebuilds it. A pair with an empty archive asks for consent before it writes anything |
| F-064 | Root sanity | Refuse to sync if either root is missing, unreadable, or contains the other (nesting); refuse the filesystem root `/`. **partly**: the earlier text also refused a root of `.`; only `/` is refused today (PENDING.md) |
| F-065 | Clock skew | mtime is used only as a fast path; equality decisions rest on hashes, so differently-set clocks do not cause spurious transfers or wrong winners |
| F-066 | Host policy is named, not guessed | A connection torn down by the system before it can be used (macOS firewall / local-network permission) is reported as such, with the settings to change, instead of surfacing as EINVAL from socket options and ENOTCONN from reads |
| F-067 | Timestamp resilience | Setting an mtime is best-effort: a filesystem that refuses it (exFAT, NTFS-3g, several FUSE/SMB/virtiofs mounts answer EINVAL) warns and continues, because hashes decide what syncs. Nanosecond values are floored, never truncated, so pre-1970 timestamps cannot become an illegal `tv_nsec` |

## 8. Tests

| ID | Requirement | Acceptance |
|---|---|---|
| F-070 | Plan/classification tests | Table-driven over the §1 comparison matrix, including ignore interaction and name-collision cases |
| F-071 | Local integration | Real temp directories: create/update/delete/resume/backup, 1k-file tree |
| F-072 | Transport integration | A real `twin serve` on loopback, a real client: both directions, deletions, multi-chunk files, unauthorized client refused, wrong pin refused, pin remembered, first contact refused without a pin |
| F-073 | Crash test | SIGKILL mid-transfer; assert no partial files under real names, archive consistent, next run converges |
| F-074 | Two-platform CI | `cargo fmt`, `clippy -D warnings`, `cargo test` on macOS and Linux. Nothing else |

`.github/workflows/ci.yml` runs the three commands on both platforms. The 1k-file tree of F-071 is the one slow test — F-021 puts every file through an fsync, and on macOS that fsync is an `F_FULLFSYNC`, so a thousand files cost about a minute — so it is `#[ignore]`d in the default run and gets a job of its own (`cargo test --test scale -- --ignored`), where it can take as long as it needs. The crash test of F-073 runs a real `twin serve` on loopback, kills the client with SIGKILL while a 256 MiB transfer is in flight, and then asserts the three things that matter: no file under a real name is partial, the archive never records what was not verified, and the next run converges.

## 9. How it got here

1. Compare + plan + `--dry-run` (pure functions over two directory walks) — testable with zero I/O risk. **Done**
2. Local pair transfer with archive, atomic placement, `--backup`. **Done**
3. Remote transport + `serve` + handshake + resume. **Done** over mutual TLS (`twin serve`, `twin authorize`, pinning), with `--partial` (F-023) resuming an interrupted transfer
4. Deletions and guards. **Done**
5. `--json`, progress, exit codes, docs. **Done**: `--json` (F-052), progress (F-053), exit codes (F-051/F-015), diagnostics and `twin doctor` (F-054/F-055/F-056)

On macOS a binary must be signed before the system lets it serve the local network, so the build signs what it produces: `make build` / `make release` run `scripts/codesign-macos.sh` (ad-hoc, no certificate and no sudo; a no-op on Linux, and it skips an already-signed file). `twin serve` warns at startup when the running binary is unsigned, and `twin doctor` reports `binary signature` next to `local network accepts connections`.

No daemon, no accounts, no CA, no protocol versioning beyond one handshake line. Dependencies: `clap`, `ignore`, `blake3`, `rusqlite`, `rustls`, `rcgen`, `rustls-pemfile`, `sha2`, `filetime`, `libc`. 48 requirements instead of 126, of which 6 are only partly implemented — the gap for each is in [PENDING.md](PENDING.md).
