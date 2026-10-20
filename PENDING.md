# twin — remaining work

**This file lists what is not built.** Nothing in here is implemented: every entry says what is missing, why it matters, what it costs, and — where the call belongs to a human — what has to be decided first. What `twin` does today is in [FEATURES.md](FEATURES.md); the two files never overlap.

## 1. Requirements that are only partly implemented

| Requirement | What is missing | Cost |
|---|---|---|
| **F-027** — path confinement | The client half is open. `safe_join` (rejects absolute paths, `..` and symlinked ancestors) is used by the server only; the client joins remote-supplied paths onto its local root unchecked, in `LocalBackend::{hash,stat,put,get,remove}` and in the engine's transfer. `Path::join` with an absolute path replaces the base, so a peer holding the pinned certificate can make the client write — or delete — outside the local root. Route every remote-originated path through `safe_join` before it reaches the local backend, and add the regression test: a server that answers LIST with an absolute path and DELETE with `../../x` | small: the function and its unit tests exist |
| **F-061** — name representation | Names travel as raw bytes, but a name the destination cannot represent (non-UTF-8 created on Linux, an NFD/NFC or case variant of an existing path on macOS) is written anyway instead of being skipped with a named reason | small: one comparison per planned path, plus a skip reason |
| **F-013** — plan memory | The walk streams, but the plan accumulates every action in a `Vec`, so memory grows with the number of changes rather than staying bounded per directory | medium: the plan has to become a stream, or the actions have to be applied as they are produced |
| **F-064** — root sanity | A root of `.` is accepted; only `/` is refused | trivial |
| **F-016** — plan/apply equivalence | The test compares the plan a dry run prints with the plan a real run prints. The requirement asks for an instrumented run: one that records what it actually did | small |
| **F-010** — inode in the fast path | The fast path compares size + mtime + kind. The original requirement said inode; FEATURES.md now describes what the code does. Adding an inode column would make the fast path stricter, but inode is not portable to the exFAT/NTFS targets this program names, so the amended requirement is the honest fix unless someone decides otherwise | small, and probably not worth it |

## 2. Parked features (cut from v1, with re-entry triggers)

| Parked | Add when | Re-entry cost |
|---|---|---|
| Two-way convergence (a change on either side propagates to the other) | a machine is edited while it is away and must keep its own edits | medium: the archive becomes a shared history again, and the direction has to be chosen per path |
| Conflict copies (both versions kept side by side, `*.conflict-<stamp>-<host>`) and exit code 3 (converged with conflicts) | two machines edit the same file while both are offline | small on top of the two-way model |
| Resurrections (a path deleted on one side, changed on the other) | a deletion must never be able to swallow an edit | small, but only meaningful with the two-way model |
| Named verbs (`twin push`, `twin pull`) instead of the argument order | people keep typing the arguments the wrong way round | trivial: two aliases over the same call |
| `twin verify` (compare by hash, transfer nothing, exit 3 when they differ) | a script needs to know whether two trees agree without changing anything | small: a dry run plus an exit code of its own |
| Daemon + file watching (sync on save) | manual/timer runs become annoying | thin: `watch → run engine`; no new engine code |
| TUI | long runs need live progress | small: consumes `--json` events |
| Block-level delta (rsync algorithm) | WAN uploads of large files hurt | medium: one file's worth of rolling-checksum logic |
| Content-defined chunking, CAS, dedup | when delta alone is insufficient and history is wanted | large; this is where the archived draft's complexity lived |
| Version history + `restore` | `--backup` proves insufficient | large: a hub or a per-pair version store |
| Central hub, multi-device fan-out, shares, quotas | more than ~4 machines, or a replica that is always online | large: accounts, mTLS, manifests, GC — the archived draft's complexity |
| Config file, named pairs, completions, man pages | a second user | small |
| Packaging: Homebrew tap, .deb/.rpm, Docker, installers | distributing to others | small, but needs ongoing CI |
| Prometheus metrics, fuzzing, simulation harness, perf budgets, 4-target release matrix | protocol growth or contributors | medium |
| Windows | a Windows machine to sync | medium: paths, ACLs, no POSIX rename semantics |

N machines with no hub = N(N−1)/2 pairs; fine for 2–4 devices, and each pair is independent. A server serves exactly one root, so two shared directories means two `twin serve` instances (different ports).

## 3. Findings still open from the code review

- **The archive sweep asks the source about every tracked path.** One stat per path per run; over TLS that is one round trip per tracked file before the plan even exists. The destination is only asked when the source no longer has the path, so half the cost is already gone. A merge-walk of the archive against the source listing would remove the rest.
- **`Archive::get` re-prepares its SQL statement on every call** — one statement compile per path per run. Prepare it once.
- **No per-pair lock.** Two `twin sync` runs on the same pair interleave their plan and apply, and can write stale "last agreed" rows. The stated deployment is cron/systemd/launchd, where overlap happens. `libc` is already a dependency, so `flock` is free and auto-releases when the process dies.
- **macOS throughput.** F-021's per-file `F_FULLFSYNC` is correct but slow: a 400 MB / 400-file transfer took 64 s. Consider making it configurable.
- **Packaging hygiene.** `Cargo.toml` declares `license = "MIT OR Apache-2.0"` with no LICENSE file in the repo. `libsqlite3-sys` drags the `pkg-config` and `vcpkg` build dependencies into the build tree although SQLite is compiled from source (`bundled`) — check whether turning rusqlite's default features off trims them.

## 4. Open decisions (a human has to call these)

1. **Does the two-way model come back?** Everything in §2 that depends on it is blocked on this one answer.
2. **May a root be `.`?** The spec used to say no; the code says yes. `twin sync . /backup` is a legitimate thing to want.
3. **Inode in the fast path?** See F-010 above; the corrected requirement says no.
4. **Pairs or a hub beyond four machines?** The parked hub is the only answer the archived draft ever had.
