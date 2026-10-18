# steelsync — Feature Specification

Working name: **`steelsync`** (single binary; hub runs as a mode of the same binary).

Status: draft v1 — establishes the complete v1.0 feature set plus explicitly deferred work.
Platforms: **macOS** (x86_64 + aarch64, 13 Ventura or newer) and **Linux** (x86_64 + aarch64, glibc ≥ 2.31 or musl, kernel ≥ 4.15). Hub runs on Linux (primary) and macOS (dev). MSRV policy: current stable minus 2 releases.

---

## 1. Product model

Locked decisions:

| Decision | Choice |
|---|---|
| Topology | **Central hub server** — one always-on node holds the authoritative replica + history; clients connect outbound |
| Interface | **CLI + per-user background daemon + TUI dashboard** |
| Conflict policy | **Keep both** — loser copied to a conflict filename, never silently discarded |
| Fidelity | **Content only** — bytes + mtimes; receiving side applies its own umask; no mode/owner/xattr/ACL/symlink preservation |

Consequences that shape everything:

1. **The hub is a full replica.** Every device can be offline for months and catch up. No device-to-device connectivity is ever required → no NAT traversal, no relay, no DHT, no hole punching.
2. **Ordering comes from the hub.** The hub assigns a per-folder monotonic sequence number to every accepted change; clients are pull-cursor based.
3. **Integrity by construction.** Every byte is addressed by BLAKE3 hash; chunk PUT/GET are idempotent, so retries and duplicates are free and crash-safe.
4. **Push before pull.** A client applies local changes immediately, commits to the hub, then pulls everything past its cursor. Hub outage degrades to queued local work, never to data loss.

v1.0 success definition: two machines (one macOS, one Linux) pointed at a hub stay converged on a ~500k-file tree including multi-GB files, across crashes, sleep/wake, hub downtime, and concurrent edits, with zero silent data loss.

---

## 2. Non-goals for v1.0

| Non-goal | Revisit when |
|---|---|
| Windows support | No windows support is ever needed |
| Mobile clients | Hub HTTP API already serves; add WebDAV/native later |
| Web UI | API is web-ready; only if TUI proves insufficient |
| CRDT / live co-editing | Conflicts are file-granular by design |
| Byte-range sync of actively-written files | Requires cooperation from the writing app |
| Permission/xattr/ACL/symlink preservation | Content-only chosen; `exec_bit` opt-in only (F-139) |
| Sparse-file hole preservation | Read/transmit materialized; documented cost |
| Hub HA / multi-node / sharding | SQLite + single node until capacity demands it (documented limits) |
| Plugin/extension system | No. Boring, closed core. |

---

## 3. Architecture

Crate layout (workspace; one `steelsync` binary + libraries):

- `steelsync-core` — engine: scanner, watcher, chunker, index, transfer planner, conflict resolver, apply pipeline. Filesystem access behind a `Vfs` trait so tests inject faults.
- `steelsync-proto` — wire types, manifest/version-vector logic, chunk framing, protocol version negotiation.
- `steelsync-client` — daemon: local RPC server, sync loop, queues, OS service integration.
- `steelsync-hub` — server: axum app, auth, storage, retention, GC, metrics.
- `steelsync-cli` — clap CLI + ratatui TUI. Thin; never touches index or files directly — everything through daemon RPC (in-process engine only for `--local` debug commands and tests).

### 3.1 Sync cycle (per folder)

1. **Detect** — watcher events (FSEvents/inotify) debounced into batches; periodic full rescan as safety net.
2. **Index** — compare (size, mtime_ns, inode) against the SQLite index; hash only what changed; recompute the FastCDC chunk list; bump the local device's version-vector component.
3. **Upload** — `POST /chunks/query` with the chunk hash list → hub replies which are missing → upload only those (idempotent, compressed).
4. **Commit** — `POST /manifests` with the entry + base vector; hub validates causality, assigns `seq`, accepts or rejects. Rejection = concurrent change elsewhere → conflict resolution locally (F-043), then retry.
5. **Pull** — `GET /changes?since=<cursor>` → fetch missing chunks, assemble, verify, atomic rename, advance cursor.
6. **Verify** — end-of-batch sanity checks; failures retried with backoff.

Correctness kernel: hub-side causality check in step 4 + version vectors + keep-both naming. Everything else is transport plumbing.

---

## 4. Feature catalog

Priority: **P0** = required for v1.0 · **P1** = v1.0 if it lands, else v1.1 · **P2** = post-1.0.

### 4.1 Sync engine core

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-001 | Folder registration | `steelsync folder add <path> --name <id>` writes a `.steelsync/` marker dir holding the folder UUID; refuses nested/overlapping roots; folder appears in `steelsync status` | P0 |
| F-002 | Unmount safety | Marker absent (drive unmounted, path deleted) → folder enters `unavailable`, **no deletions propagate**; auto-resumes when the marker returns | P0 |
| F-003 | Per-device folder modes | `bidirectional` (default), `send-only` (backup node), `receive-only` (mirror node); enforced locally before commit, so a send-only device never applies remote changes | P0 |
| F-004 | Plan/apply separation | Sync computation is side-effect free; `steelsync sync --dry-run --json` prints exactly what would change, byte counts included | P0 |
| F-008 | Bounded memory | No whole-file buffering; memory bounded by chunk size × concurrency. A 10 GB file must sync with < 200 MB RSS | P0 |
| F-009 | Clock-skew independence | Convergence holds with device clocks differing by hours; mtime never decides a conflict | P0 |
| F-012 | Local-only mode | Engine runs with no hub at all (`steelsync folder add --local`): supports engine development/testing and offline-only use | P0 |

### 4.2 Change detection and scanning

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-020 | Native watching | FSEvents on macOS; inotify on Linux (recursive watch management: add new dirs, drop removed ones); a single file write is detected < 1 s | P0 |
| F-021 | Debounce/coalescing | Configurable quiet window (default 2 s) and max delay (default 30 s) before batching; copying a 10k-file tree yields a handful of batches, not 10k | P0 |
| F-022 | Periodic safety rescan | Full rescan interval (default 12 h, per-folder) catches dropped/overflowed watcher events | P0 |
| F-023 | Warm scan performance | Metadata-only compare (size, mtime_ns, inode) for unchanged files; hash only on mismatch; ≥ 10k files/s warm on SSD | P0 |
| F-024 | Watcher degradation | inotify watch-limit exhaustion or FSEvents failure → loud log + automatic downgrade to periodic polling; watching never silently stops | P0 |
| F-025 | Ignore rules | `.steelsyncignore` (gitignore syntax, synced as a normal file so all devices agree) + built-in defaults (`.DS_Store`, `._*`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`, `lost+found`, `*.swp`, `*.swo`, `*~`, `4913`, `.steelsync/`); `steelsync ignore add\|list`; built-ins disengageable | P0 |
| F-026 | Hashing | BLAKE3, bounded multi-threaded, streaming; re-verify content hash immediately before upload | P0 |


### 4.3 Chunking, transfer, storage

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-030 | Content-defined chunking | FastCDC: min 64 KiB / avg 256 KiB / max 1 MiB; < 1 MiB treated as one chunk; inserting/deleting bytes mid-file re-uploads only the affected region (≪ full file) | P0 |
| F-031 | Hub chunk store | Per-user namespace (sharded `ab/cd/<hash>`), zstd level 3 when it shrinks the chunk; content-addressed → duplicate content (copies, repeated versions, hardlink steelsyncs) costs one copy | P0 |
| F-032 | Missing-chunk negotiation | Per-batch bulk hash query; client uploads only hashes the hub lacks | P0 |
| F-033 | Parallel transfers | Configurable in-flight chunk transfers (default 4, max 32), multiplexed over one HTTP/2 connection | P0 |
| F-034 | Resumable transfers | Chunk PUT idempotent by hash; interrupted download refetches only missing chunks; per-file progress persisted across restarts | P0 |
| F-035 | Atomic apply | Temp file in target dir → fsync (`F_FULLFSYNC` on macOS) → `rename()`; a partially written file is never visible under its real name | P0 |
| F-036 | Integrity verification | Chunk hash verified on receipt and on cache read; `steelsync verify [--folder <f>] [--remote]` walks everything and repairs from the hub | P0 |
| F-039 | Transfer fault tolerance | Drop, 5xx, hash mismatch → per-chunk retry, exponential backoff + jitter; bounded retry window; hub state never left inconsistent | P0 |

### 4.4 Conflict handling (keep-both)

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-040 | Version vectors | Every entry carries `{device_uuid: counter}`; a change is concurrent iff neither vector dominates the other | P0 |
| F-041 | Conflict copies | Loser of a concurrent modification written as `<stem>.sync-conflict-YYYYMMDD-HHMMSS-<dev8>.<ext>`; kept in the tree and synced to all devices like any file | P0 |
| F-042 | Deterministic winner | Total order: (1) vector dominance, (2) content hash, (3) mtime, (4) device UUID. Every device computes the same winner with no negotiation round trip | P0 |
| F-043 | Hub rejection → local resolution | Hub refuses a non-causal commit; client re-pulls, writes conflict copy, commits winner with merge point (`max(vv)+1` on local device), then commits the copy; both visible in `steelsync conflicts` | P0 |
| F-044 | Delete vs modify | Modification wins; file preserved, deletion dropped, resolved-conflict event recorded (nothing to preserve from the deleter, so no copy needed) | P0 |
| F-045 | Directory conflicts | Remote tombstone for a locally non-empty directory → directory kept, conflict recorded, user decides | P1 |
| F-046 | Conflict listing/resolution | `steelsync conflicts [--json]`, `steelsync conflicts resolve <id> --keep local\|remote\|both`; resolution never loses bytes | P1 |
| F-047 | Conflict observability | Conflicts counter in status + metrics; creation logged with both sides' device, mtime, hash | P1 |

### 4.5 Deletion, versioning, restore

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-050 | Tombstones | Deletes propagate as tombstone entries (path + seq + vector), never as a silent absence from a listing | P0 |
| F-051 | Hub version retention | Last N versions (default 10) and/or D days (default 30) per path, per folder; retained versions count against quota | P0 |
| F-054 | Hub GC | Mark-sweep over live manifests + retained versions + grace window (default 48 h); `steelsync server gc [--dry-run]` reports reclaimable bytes; never deletes anything reachable from a retained version | P0 |
| F-055 | Local trash (opt-in) | Per-folder: deleted/overwritten files moved to `<data>/trash/<ts>/` with retention instead of unlinked | P2 |
| F-056 | Hub snapshot | `steelsync server snapshot <dir>`: SQLite backup API + hardlinked CAS tree (same-FS hardlinks = cheap); documented hub backup/DR procedure | P1 |

### 4.6 Hub server

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-060 | Accounts & devices | Users own devices and folders; folders shared to users with a mode (F-003 semantics enforced hub-side); enrollment via one-time token (TTL 60 min, single use) | P0 |
| F-061 | Storage | SQLite (WAL, `busy_timeout`, serialized writes) for metadata + filesystem CAS for chunks; single-node limits documented | P0 |
| F-062 | Per-folder sequence | Monotonic commit order assigned inside the manifest transaction; clients resume from `since=<seq>` | P0 |
| F-065 | Disk-full behavior | Typed `storage_full` error; clients back off and retry; hub alerts via logs + metrics; no half-committed state | P0 |
| F-066 | Maintenance freeze | `steelsync server pause` stops accepting commits while serving reads; part of the pre-snapshot procedure | P1 |
| F-067 | Protocol compatibility | Hub advertises min/max client protocol; incompatible client gets an actionable error, not a broken sync | P1 |

### 4.7 Security and identity

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-070 | Device identity | ECDSA P-256 keypair generated on first run, private key `0600` in the data dir; device ID = public-key fingerprint; `steelsync device id` prints a short human-checkable fingerprint | P0 |
| F-071 | Enrollment | `steelsync login --server <url> --token <t>`; TLS client cert derived from the device key; hub pins the fingerprint at enrollment; `steelsync server device revoke` closes live connections immediately | P0 |
| F-072 | Transport security | TLS 1.3 only (rustls), mTLS, HTTP/2; server trust = system roots, or `--cert-fingerprint` pinning for self-signed hubs | P0 |
| F-073 | Authorization | Every request scoped to (device → folder, mode); no cross-user access to chunks/manifests/metadata; path ops confined to the folder root | P0 |
| F-074 | Path-traversal & symlink defense | Reject absolute paths, `..`, empty components, `\0`; apply refuses to write through a symlinked ancestor (lstat every component) | P0 |
| F-075 | Local IPC auth | UDS `0600` in the per-user runtime dir + same-UID peer check (`SO_PEERCRED` Linux, `LOCAL_PEERCRED` macOS); no TCP listener by default | P0 |
| F-076 | Token handling | 256-bit random tokens, SHA-256-hashed at rest on the hub, single use, expiring; secrets never logged | P0 |
| F-077 | Data at rest | Hub stores chunks in plaintext — documented explicitly with the physical-access implication; per-user CAS namespaces block cross-user hash probing | P0 |
| F-078 | Abuse resistance | Per-device request/byte caps, max request body, auth-failure backoff, request timeouts (`hyper` defaults cover slowloris) | P1 |
| F-079 | Supply chain | `cargo-deny` (licenses/advisories/bans) + `cargo-audit` in CI; pure-Rust TLS stack (no OpenSSL) | P0 |

### 4.8 Daemon and OS integration

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-081 | Single instance | flock on a lock file; second daemon exits with a clear message; stale socket recovered after crash | P0 |
| F-082 | Graceful lifecycle | SIGTERM/SIGINT → stop intake, flush index transaction, checkpoint, exit ≤ 2 s | P0 |
| F-083 | Sleep/wake & network transitions | Wake or interface change → reconnect with backoff + jitter, rescan affected folders, resume interrupted transfers; no reconnect spin while offline | P0 |
| F-084 | Offline operation | Scanning/hashing/queueing work offline; pending commits persisted; replay on reconnect is ordered and idempotent; queue survives daemon restart | P0 |
| F-085 | Crash consistency | Startup recovery: GC temp files, re-verify entries stuck in `applying`, rebuild index from full rescan if the SQLite integrity check fails — never lose data | P0 |
| F-086 | Config hot reload | SIGHUP re-reads ignores, limits, intervals, folder modes, folder add/remove — live; only listen addresses need restart | P1 |
| F-087 | Logging | `tracing`, human + JSON formats, per-level filter, daily rotation, 7-day retention; `steelsync logs --follow` streams via RPC | P0 |
| F-088 | Resource discipline | Configurable max concurrent scans/transfers and hash threads; Linux `ioprio` best-effort nice for hashing IO (P2); quiescent CPU < 1 % | P1 |

### 4.9 CLI

One binary, `clap`-based, grouped commands. Exit codes stable and documented.

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-090 | Command surface | `login`, `device id\|list`, `folder add\|rm\|list\|mode`, `pause`, `resume`, `sync` (`--dry-run`), `status`, `conflicts`, `restore`, `ls-versions`, `ignore`, `logs`, `tui`, `service`, `doctor`, `config validate\|show`, `version`, `completions`; `server` group for hub admin | P0 |
| F-091 | Exit codes | 0 ok · 1 usage/validation · 2 daemon unreachable · 3 partial failure · 4 auth/permission · 5 hub unavailable. Stable from v1.0 | P0 |
| F-092 | Machine-readable output | `--json` on all read commands, `--quiet`; JSON schema carries `"schema": 1` for forward compat | P0 |
| F-093 | Progress UX | TTY: `indicatif` progress; non-TTY: no spinner, line-oriented `--progress=plain`; auto-disable on CI/`NO_COLOR` | P0 |
| F-094 | Shell completions | bash/zsh/fish via `clap_complete`; man pages via `clap_mangen` | P1 |
| F-095 | `steelsync doctor` | Checks socket reachability + perms, inotify limits, folder markers, clock skew vs hub, disk space, cert/key validity, DB integrity, hub reachability; prints actionable fixes | P0 |

### 4.10 TUI

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-100 | Dashboard | Folders with state (idle/scanning/syncing/paused/error), progress %, up/down rates, hub connection state, last-sync time, pending queue depth | P0 |
| F-101 | Transfers view | Active transfers: file, direction, progress, rate, ETA; aggregates for the folder | P0 |
| F-102 | Conflicts view | List conflicts, show both sides (device, mtime, size), resolve keep-local/remote/both inline | P1 |
| F-103 | Events pane | Filterable live event log (level, folder, pattern), follow mode | P1 |
| F-104 | Controls | Pause/resume folder or all, retry failed, force rescan, copy path; all state changes go through the same RPC the CLI uses | P0 |
| F-105 | Accessibility | `?` help overlay listing keys, `NO_COLOR` respected, no color-only status encoding, degrades in 80×24 terminals | P1 |
| F-106 | Daemon-down behavior | Clear inline error with the exact command to start the daemon; no crash, no panic loop | P0 |

### 4.11 Observability

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-110 | Structured events | Every state transition logs folder, path, state, reason, and a batch/correlation id; JSON log mode is machine-parseable | P0 |
| F-111 | Hub metrics | `/metrics` Prometheus: bytes up/down, chunk counts, commits accepted/rejected, connected devices, queue depth, GC stats, errors by class | P1 |
| F-112 | Daemon counters | `steelsync status --json` exposes counters: files indexed, bytes pending, errors, conflicts, last error per file | P1 |
| F-113 | Debug bundle | `steelsync doctor --bundle <out.tar.gz>`: redacted config, logs, status snapshot, fingerprints; no file contents | P2 |

### 4.12 Configuration

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-120 | Configuration | `steelsync server ` or `steelsync client` as only required setup and config to start; if not specified `client` is the default | P0 |

### 4.13 Cross-platform behavior (macOS ↔ Linux)

| ID | Feature | Acceptance criteria | Prio |
|---|---|---|---|
| F-130 | Case-sensitivity detection | ALways assume case sensitive | P0 |
| F-137 | macOS specifics | TCC prompt for Desktop/Documents/Downloads (and Full Disk Access for other volumes) detected, explained, and surfaced by `doctor` — a launchd agent denied access must never look like an empty folder (F-011 backstop); `F_FULLFSYNC` for durability; `.DS_Store`/AppleDouble defaults (F-025); LaunchAgent quoting | P0 |
| F-138 | Linux specifics | inotify limits from `/proc/sys/fs/inotify/max_user_watches` checked by `doctor`, concrete sysctl fix printed; XDG dirs; musl static build; best-effort `ioprio` | P0 |

## 6. Interfaces

### 6.1 Hub HTTP API (`/api/v1`, JSON control plane, binary chunk plane)

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/chunks/query` | `{hashes[]}` → `{missing[]}` (F-032) |
| `PUT` | `/chunks/{hash}` | idempotent chunk upload, body zstd-optional, `Content-Encoding`-style header carries stored size/hash |
| `GET` | `/chunks/{hash}` | chunk download, verifiable by hash |
| `POST` | `/manifests` | commit entry batch with `base_seq` + `vv`; per-entry accept/reject with typed reasons (F-043) |
| `GET` | `/changes?since=&limit=` | ordered manifest deltas + `next_cursor`, `has_more` (F-062) |
| `GET` | `/versions?path=` | retained versions for a path (F-052) |
| `GET` | `/events?since=` | SSE stream of commit notifications for near-real-time pull |
| `GET` | `/server/info` | protocol min/max, quota, folder list + modes (F-067) |

Invariants: every mutation is idempotent or causally checked; `seq` assignment is inside the commit transaction; a rejected entry carries enough state for the client to resolve without another round trip.

### 6.2 CLI surface (representative)

```console
# Hub bootstrap (on the server)
steelsync server folder create docs 
steelsync server token issue --folder docs 

# Device onboarding
steelsync login --server https://hub.example.com --token <token>
steelsync folder add ~/Documents --name docs
steelsync status
steelsync tui

# Day-to-day
steelsync sync --dry-run --json
```


---

## 7. Milestones

| Milestone | Content | Exit criteria |
|---|---|---|
| **M0 — Local engine** | `steelsync-core` scanner, index, watcher, chunker, CAS, plan/apply; CLI `status`/`sync --dry-run`; local-only mode (F-012) | 500k-file scan within F-140/F-142 budgets; chunker round-trip property tests green; crash-injection (F-152) on local apply clean |
| **M1 — Hub + transport** | axum hub, mTLS enrollment, folders/shares, whole-file upload/download, cursor pull, service install; one-way folder modes | Mac ↔ Linux ↔ hub convergence E2E; revocation closes connections; protocol negotiation works |
| **M2 — Delta + conflicts + history** | FastCDC delta transfer, version vectors, keep-both conflict copies, tombstone deletes, retention + `restore`, mass-delete guard, hub GC | Full conflict matrix (F-151) green; restore round-trip proven; GC never removes reachable chunks (property-tested) |
| **M3 — Daemon + TUI + resilience** | autostart, TUI (F-100…F-106), offline queue, sleep/wake, `doctor`, hot reload, bandwidth limits | Kill -9 / network-fault / offline-catch-up suites green; TUI usable in 80×24; `doctor` catches every seeded misconfiguration |
| **M4 — Hardening + distribution** | packaging (F-160…F-164), fuzzing, benchmarks in CI, docs set, security pass | Release artifacts installable on all four target platforms; fuzzers clean for 24 h; docs cover every P0 feature |

Ordering rationale: M0 is testable with zero network; M1 proves the topology; M2 is the correctness kernel — it should not be deferred past M3 because everything else builds on its invariants.

---

## 8. Open decisions (need owner input before M1)

1. **Hub hosting shape** — personal single-user hub vs multi-user default. Spec builds multi-user but ships single-user config; confirm.
2. **Name** — `steelsync` is a placeholder; pick before publishing crates/binaries.
3. **Swap file behavior** — should files that look like VM/disk images (e.g. `*.qcow2`, `*.vmdk`) be excluded by default to avoid perpetual re-upload of huge changing files? (Recommend: warn-only at add time, no hidden exclusion.)
4. **Retention defaults** — 10 versions / 30 days is a guess; confirm storage appetite.
5. **E2E encryption** — explicitly out of v1; confirm that hub-readable content is acceptable (it is implied by "hub holds the authoritative copy").

---

## Appendix A — Candidate implementation blocks

Versions verified against crates.io on 2026-09-13. Non-binding: pin exact versions in `Cargo.toml` and keep `cargo-deny` happy.

| Concern | Crate | Latest |
|---|---|---|
| Async runtime | `tokio` | 1.53.1 |
| Hub HTTP/2 server | `axum` | 0.8.9 |
| TLS (pure Rust) + mTLS | `rustls` | (pair with `axum-server`/`tokio-rustls`) |
| Device cert generation | `rcgen` | 0.14.10 |
| Filesystem watching | `notify` (FSEvents + inotify backends) | 8.2.0 |
| Hashing | `blake3` | 1.8.7 |
| Content-defined chunking | `fastcdc` | 5.0.0 |
| Compression | `zstd` | 0.14.0 |
| Index DB | `rusqlite` (bundled SQLite, WAL) | 0.40.2 |
| Ignore matching | `ignore` | 0.4.33 |
| CLI | `clap` + `clap_complete` | 4.6.6 / 4.6.9 |
| TUI | `ratatui` | 0.30.2 |
| Progress | `indicatif` | 0.18.6 |
| Logging | `tracing` + `tracing-appender` | 0.1.44 / 0.2.5 |
| Paths/XDG | `directories` | 6.0.0 |
| Frame utilities | `tokio-util` | 0.7.19 |
| Tests | `cargo-nextest` | 0.9.144 |
| Simulation (F-154) | `turmoil` | 0.7.2 |

Serialization: `serde` + `serde_json` + `toml` (stable, unversioned here). Unix credentials: `libc`/`nix` for `SO_PEERCRED` and `LOCAL_PEERCRED`.

## Appendix B — External facts this spec depends on

- inotify is **not recursive** in the kernel; recursive watching is N syscalls and consumes N watch descriptors → F-024 degradation path is mandatory, and `doctor` must read `/proc/sys/fs/inotify/max_user_watches`.
- macOS FSEvents **coalesces** events and may be replayed after wake with a since-id; the engine must treat watcher input as hints, never as ground truth → F-022 is the correctness backstop.
- APFS/HFS+ commonly case-insensitive and normalization-insensitive; Linux ext4/xfs are case-sensitive byte-exact → F-130/F-131 exist because neither side can be assumed.
- Linux filenames are arbitrary bytes; macOS APIs require UTF-8 → F-132 is a one-way representability problem, not a conversion problem.
- Directory `fsync` is required on Linux for rename durability; macOS durability needs `F_FULLFSYNC` (plain `fsync` can be a lie on power loss) → F-035.

## Appendix C — Suggested next step

M0 scaffold: workspace with `steelsync-core` (Vfs trait + scanner + index + chunker), `steelsync-cli` with `status`/`sync --dry-run`, plus the F-150 property tests. That milestone needs no network, no auth, and no hub — and it validates the two performance budgets (F-140, F-142) that constrain every later decision.
