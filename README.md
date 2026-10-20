# twin

Copy a directory to another one. The other side is either a second local path
(external drive, second disk) or a directory on another machine, served over
mutual TLS.

One binary. No server to deploy, no daemon, no accounts, no config file. You run
it, it converges the pair, it exits. Schedule it with cron / systemd timer /
launchd when you want it periodic.

```
twin sync <source> <destination>   # copy the source to the destination
twin authorize <fingerprint>       # let that client connect to this server
twin authorize clear               # let nobody in
twin serve --root <dir>            # serve a directory over mutual TLS
twin doctor [PATH]                 # check everything a sync depends on
```

Every run prints this machine's fingerprint before it does anything else, so
there is always a way to see it — no separate `id` command:

```
$ twin --help
twin fingerprint: 281c324175dbea089985b27e024de74fb90553116b62a274deb4d6e165181566
...
```

The fingerprint goes to standard error, so the report on standard output stays
machine-readable (`--json` is one JSON object per line, nothing else).

The order of the two arguments is the direction: the content flows from the
first to the second, and only the second is written. The source wins — a file
that changed on the destination is put back to what the source holds. Paths the
source no longer has are only removed from the destination when `--delete` says
so.

## What changed

### The fingerprint is printed on startup, and `twin id` is gone

`twin id` used to be the way to find out this machine's fingerprint, which is
the one thing you need on the other machine. Now every run prints it:

```
twin fingerprint: 281c324175dbea089985b27e024de74fb90553116b62a274deb4d6e165181566
```

It is printed before the program does anything, `--help` included, so
`twin --help` is enough to get it. The key pair is created on first use, as
before. The messages that used to say "run `twin id`" now say to run `twin`.

### `twin authorize clear`

`twin authorize <fingerprint>` lets one client in; `twin authorize clear` lets
nobody in — it empties the list and says how many clients it removed. A
running server reads the list before every connection, so the clients are
refused from its next connection, with no restart.


### `push`, `pull` and `verify` are gone

`sync` is the only way to move content, and it always moves it from the source
to the destination, in the order the two arguments are written:

| Before | Now |
|---|---|
| `twin push <local> <remote>` | `twin sync <local> <remote>` |
| `twin pull <remote> <local>` | `twin sync <remote> <local>` |
| `twin sync <local> <remote>` (two-way) | `twin sync <local> <remote>` (one-way, source wins) |
| `twin verify <a> <b>` | `twin sync <a> <b> --dry-run` |

What went with it: the two-way comparison, the conflict copies
(`*.conflict-<stamp>-<host>`), the resurrection rule, and the exit code 3 that
meant "converged with conflicts". The two-way model is parked in `PENDING.md`
with the trigger that would bring it back.

The archive (`~/.local/share/twin/archive/<pair-id>.db`) now remembers the
source's and the destination's mtime separately, and a pair is identified by
the source and the destination *in that order* — the same two directories in
the other direction are another pair, with another archive. Archives written
before this change are not read any more; the next run rebuilds them, so the
first run after the upgrade asks for `--auto` once.

## Build and test

```
make build     # debug binary, signed on macOS
make test      # the test suite
make lint      # clippy with warnings denied
make check     # fmt, lint, test, sign
```

## The documents

| File | What it is |
|---|---|
| `FEATURES.md` | What `twin` does today — every requirement implemented, with the few that are only partly implemented marked as such |
| `PENDING.md` | What is **not** built: the partly implemented requirements, the parked features with their re-entry triggers, the open findings, and the decisions that need a human |

The two never overlap: if a feature is in `FEATURES.md`, it is in the program;
if it is in `PENDING.md`, it is not.
