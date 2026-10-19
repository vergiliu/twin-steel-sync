───────────────────────────────────────────────────────────────────────────────

 Recommendation 1 — Confine remote-supplied paths on the client (F-027 is only half done)

 Problem. safe_join (src/side.rs:101-136) — which rejects absolute paths, .., and symlinked ancestors — is used only by the server (src/proto.rs:457,464,483,522,540). The client
 joins remote-supplied paths onto its local root unchecked: LocalBackend::hash/stat/put/get/remove all do self.root.join(path) (src/side.rs:65,69,77,81,85), and the engine
 forwards local_root.join(path) verbatim (src/engine.rs:773-774).

 Path::join with an absolute path replaces the base — confirmed on this machine:

 ```
Path::new("/home/me/sync").join("/etc/cron.d/x")   -> /etc/cron.d/x
Path::new("/home/me/sync").join("../../.ssh/authorized_keys") -> /home/me/sync/../../.ssh/authorized_keys
 ```

 Impact. A peer holding the pinned certificate can make the client write outside the local root (pull → src/remote.rs:283-311) or delete outside it (LocalBackend::remove →
 fs::remove_file(root.join(path)), src/side.rs:84-90). The conflict path has the same hole (src/engine.rs:737-738). F-027 explicitly requires "the client refuses anything outside
 its local root: .., absolute paths, and symlinked ancestors rejected".

 Do. Route every remote-originated path through safe_join(local_root, path) before it reaches LocalBackend — the function already exists and already has unit tests. Add a
 regression test with a server that answers LIST with an absolute path and DELETE with ../../x; assert nothing outside the root is written or removed. Small: a few hours, and it
 is the only finding with teeth.

 ────────────────────────────────────────────────────────────────────────────────

 Recommendation 2 — Write an archive row when two sides agree and there is none

 Problem. adoptable_row returns None whenever there is no base row (src/engine.rs:582-593, let mut row = base?.clone()). A path both sides already agree on, but that the archive
 has never seen, therefore yields Verdict::Adopt → no action and no row (src/engine.rs:474-485). The archive never learns the path exists.

 Verified on this machine (two dirs, one identical file):

 ```
$ twin sync a b --auto
created 0, updated 0, ... unchanged 1
$ sqlite3 archive/*.db "select count(*) from entries;"
0                     # after run 1, after run 2, still 0
 ```

 Impact.
 - F-014 (hash memoization) never engages for those paths: base is None, so resolve_side must hash both copies on every run (src/engine.rs:567).
 - F-063 (archive loss is recoverable) only half holds: the archive rebuilds for paths that had to be copied, never for paths that already agree — so it never reaches a complete
   state.
 - A/B timing on 200 × 256 KiB files: 0.166 s with no rows (re-hashing both sides every run) vs 0.034 s with rows — the gap grows with tree size.

 Do. When the verdict is Adopt and there is no base row, synthesize a BaseRow from the two entries (kind/size/mtime_local/mtime_remote/hash — the schema has per-side mtime
 columns precisely for this, src/model.rs:77-90) and store it. While you are in there, resolve the F-010 spec/code mismatch: the spec says the fast path is "size + mtime (ns) +
 inode", the code uses size + mtime + kind (src/model.rs:212-214) and there is no inode column (src/archive.rs:26-34). Either add it or amend the requirement — inode is not
 portable to the exFAT/NTFS targets the spec names, so amending the spec is the honest fix.

 ────────────────────────────────────────────────────────────────────────────────

 Recommendation 3 — Add the verification layer the spec already promises

 Problem. There is no CI at all (no .github/; Makefile:32-46 has only local targets), so F-074 ("macOS and Linux"), F-060 ("macOS ↔ Linux") and the Linux no-op branch of
 scripts/codesign-macos.sh have never been exercised automatically — the whole project has only ever been verified by hand on one Mac. Two test requirements from §9 do not exist:
 F-071's 10k-file tree and F-073's SIGKILL crash test (repo-wide grep finds only child.kill() inside test Drop impls). The largest tree in the suite is 200 files.

 Do.
 1. One GitHub Actions workflow, macos-latest + ubuntu-latest: cargo fmt --check, cargo clippy --all-targets -- -D warnings, cargo test (the macOS job needs the ad-hoc codesign
    step so it matches the local build).
 2. In that workflow, add the two missing tests: a 10k-file tree asserting wall time and peak RSS, and a SIGKILL-mid-transfer test asserting no partial files under real names, an
    intact archive, and convergence on the next run.

 This is also the cheapest way to find the scale defects below, rather than reasoning about them. Small in effort, large in what it catches.

 ────────────────────────────────────────────────────────────────────────────────

 Recommendation 4 — Close the four remaining v1 requirements

 These are exactly the items FEATURES.md §10 still marks open, and they are the difference between "nearly finished" and "finished". Suggested order:

 ┌──────────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │ Requirement      │ Why first                                                                                                                                                  │
 ├──────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ F-034 --backup   │ ~30 lines per the spec; the cheapest protection against an overwrite mistake, and the thing that decides whether the parked "version history" item ever    │
 │ DIR              │ has to come back.                                                                                                                                          │
 ├──────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ F-052 --json     │ One JSON object per line (plan entry, transfer start/finish, conflict, skip, error, summary). It is the prerequisite the parked TUI is explicitly waiting  │
 │                  │ on (§8), and it is what makes an unattended cron run auditable.                                                                                            │
 ├──────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ F-053 progress   │ TTY: current file, bytes, total, ETA; non-TTY: one line per completed file. Without it a long run is a silent terminal.                                    │
 ├──────────────────┼────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ F-023 --partial  │ The last transfer-reliability gap. Today an interrupted transfer restarts from zero and the temp file is deleted (src/remote.rs:318-320,                   │
 │                  │ src/proto.rs:641-643). Needs byte-range offsets in GET/PUSH plus retained partials.                                                                        │
 └──────────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 Fold in four small correctness fixes found in the same review — each is a spec line, not a preference:

 - twin authorize does not affect a running server. The allow-list is read once at startup (src/main.rs:342-348) and the TLS verifier holds a copy for the process lifetime
   (src/tls.rs:213-252), so a newly authorized client is refused until restart — and the error message tells the user to run twin authorize again, which changes nothing.
 - A plan-phase failure aborts the whole run with exit 1 instead of failing that one file with exit 4 (src/engine.rs:560 and the remote equivalent). F-029 says "other files
   continue".
 - F-022's "mismatch → retry once" does not exist (src/proto.rs:612-624, src/remote.rs:246-250).
 - F-015 says --dry-run "exits 0" — a dry run that finds a conflict exits 3 (verified: dry-run exit=3).

 ────────────────────────────────────────────────────────────────────────────────

 Smaller items worth folding into the same passes

 - F-013 is knowingly violated. The walk streams, but build_plan accumulates every action in a Vec (src/engine.rs:330) — plan memory is O(tree), not "bounded per directory" as
   the spec claims.
 - The archive's forgotten-path pass stats every archived path on both sides (src/engine.rs:373-384). On a remote pair that is one TLS round trip per tracked file before the plan
   even exists. Relatedly, Archive::get re-prepares its SQL statement on every call (src/archive.rs:56-58) — one statement compile per path per run.
 - No per-pair lock. Two twin sync runs on the same pair interleave their plan/apply and can write stale "last agreed" rows. The stated deployment is cron/systemd/launchd, where
   overlap happens. libc is already a dependency, so flock is free and auto-releases when the process dies.
 - macOS throughput. F-021's per-file F_FULLFSYNC (src/fsutil.rs:88-105) is correct but slow: a 400 MB / 400-file transfer took 64 s here. Consider making it configurable.
 - Packaging hygiene. Cargo.toml declares license = "MIT OR Apache-2.0" with no LICENSE files in the repo; there is no README, yet twin doctor itself tells users to cargo install
   --path .. Also, rusqlite is pulled with default features, which enables libsqlite3-sys's vcpkg + pkg-config build deps — dead weight on macOS/Linux (cargo tree -i vcpkg).

 Suggested order: 1 (security, cheap) → 2 (silent correctness bug, cheap) → 3 (protects everything after) → 4 (finish the spec). Items 1 and 2 together are under a day's work and
 close the only two findings that can lose data.
