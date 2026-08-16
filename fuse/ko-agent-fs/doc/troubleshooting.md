# Troubleshooting `ko-agent-fs`

Where to look when the workspace FUSE filter — or something beneath it — misbehaves. Keyed by
symptom. Commands are given for podman machine (macOS/Windows); on native Linux drop
`podman machine ssh` and use the same paths under your own home.

## Where everything lives

All filter state sits in the daemon user's home, per project:

    ~/.local/share/ko-agent-sandbox/ko-agent-fs             the installed binary
    ~/.local/share/ko-agent-sandbox/mounts/<project>/
        workspace                                           the mountpoint the container binds
        daemon.log                                          the running daemon's log
        daemon.log.1                                        the previous daemon's log — the one
                                                            you want after a crash
        source-id                                           the source digest the daemon serves
        sessions/<container>                                one marker per live session
        lock                                                serializes a launch's reuse decision
                                                            against a reap's unmount

The log starts with a banner (`ko-agent-fs <version> source <id> t=<unix-secs> serving ...`), so an
empty file means the daemon never started, not that nothing happened. Denials are one line each:
`DENY t=<unix-secs> op=<op> target=<name> reason=<rule>` — attacker-chosen names arrive escaped,
and file contents are never logged. After 10,000 lines the log caps: further denials are counted,
with a running total every thousandth — refusal spam cannot fill the disk, and the magnitude
survives even when the detail does not.

The one-look health check:

    podman machine ssh 'pgrep -a ko-agent-fs; mount | grep ko-agent-fs;
                        tail .local/share/ko-agent-sandbox/mounts/*/daemon.log'

## "Operation not permitted" on something that should be allowed

The matching `DENY` line in `daemon.log` names the operation, the target and the rule:

- `reason=protected-git-control` on a file git needs for a normal command — most likely an
  operational path missing from the fail-closed allowlist (`git-metadata.md`, P2: a forgotten
  file breaks a git command, never opens a hole). Report it with the DENY line; the fix is one
  allowlist entry plus its tests.
- `reason=protected-git-entry` on a name that is not `.git` — the conservative name rule
  (`git-metadata.md`, "The name rule") swallowed a legitimate name. Report the exact bytes.
- `reason=protected-sandbox-config` — something tried to create or write `.ko-agent-sandbox`, the
  launcher's own configuration. Editing it is the host's job (`SECURITY.md`, "A project loosening
  its own confinement"); the same reason on a name that is merely *like* it is the fold rule
  over-reaching, and worth reporting with the exact bytes.
- `reason=nonportable-target-shape` on a `symlink` — a tool tried to create a link whose target is
  absolute or climbs above the workspace root, neither of which can be trusted to mean the same
  thing to the host (`SECURITY.md`, "A symlink is the sharpest case"; the rule and its limits are
  `fs.rs`, `target_has_portable_shape`). Give the tool a relative target landing inside the
  workspace, or let it cache inside the project. Tools that link into a store of their own generally
  fall back to copying: sbt 2 turns off linking for the session on the first refusal and copies out
  of its cache instead. The one that does not is `python3 -m venv`, whose `bin/python` is an absolute
  link to the interpreter — `--copies` builds the same environment, and a virtualenv under `~` is the
  better answer anyway, since one under `/workspace` names container paths in its `pyvenv.cfg` and
  shebangs and is unusable on the host regardless.

No DENY line for the failure? Then the `EPERM` did not come from the filter — check the backing
share's own permissions and SELinux label from inside the machine.

## "Too many levels of symbolic links" (ELOOP) on a path that has none

A handle held across a rename. The daemon reconstructs an inode's path from the names it was looked
up under, and something now stands at one of those names that is not what stood there before; the
resolver refuses to follow it rather than serve an object the path no longer describes (`fs.rs`,
`open_ino`). There is no `DENY` line, because no policy decision was reached. Reopen the path — a
fresh lookup builds a current chain.

## "Transport endpoint is not connected" (ENOTCONN)

The daemon died while the container held the mount. This is fail-closed by design — nothing is
served, not even a shell whose cwd is inside — and scoped to `/workspace` alone. Post-mortem:

    podman machine ssh 'tail -20 .local/share/ko-agent-sandbox/mounts/*/daemon.log*'
    podman machine ssh 'journalctl -k | grep -iE "oom|killed" | tail -5'

A panic lands in the log; an OOM kill lands in the kernel journal instead (an sbt-scale build in
the VM can eat it — see "The whole machine degrades"). Quit the session and relaunch: the mount
script finds the dead mount, lazily unmounts it, and starts a fresh daemon; the previous daemon's
log survives as `daemon.log.1`.

## The launch refuses to start

Every gate prints its reason; the message is the diagnosis.

- `the installed ko-agent-fs is not this launcher's build` — the binary and the jar disagree; run
  `--build`.
- `ko-agent-fs self-test failed` — the environment lost a premise. The self-test's own message
  names the usual two: no `fusermount3`, or `/etc/fuse.conf` lost `user_allow_other` (a recreated
  machine arrives without it; `--build` re-asks consent). Reproduce by hand:
  `podman machine ssh .local/share/ko-agent-sandbox/ko-agent-fs --self-test`.
- `refusing to serve ... hooks ... inside the workspace` — the startup guard (`guard.rs`): the
  repository's hook directory resolves inside the workspace, which the filter cannot protect. The
  remedy is in the message.
- `mountpoint ... is not empty; refusing` — something landed in the mountpoint directory while no
  filter was mounted. Inspect it in the machine before deleting; nothing legitimate writes there.

## `/workspace` is empty inside the container

The bind captured the bare mountpoint directory instead of a live mount — the daemon died in the
window between the launcher's mount check and the container start. By construction the directory
under the mount is empty, so nothing is exposed. Quit and relaunch. A *reap* cannot cause this:
`lock` above holds the mount check and the unmount apart. On a machine with no `flock` it can,
and then the marker's age is the only thing keeping the two apart.

## Everything works but slowly

Expected, quantified, and being worked: metadata through the filter costs ~5–12× the raw bind
(`TODO.md`, "Performance", has the table). If it is much worse than that, suspect the layer below —
see the next section.

## The whole machine degrades (every podman command slow or erroring)

The filter shares the VM with podman itself; when the *machine* is sick the filter is a casualty,
not the cause. In one observed incident an in-sandbox sbt cross-build exhausted the VM's memory
(container `/tmp` is tmpfs — RAM), the OOM killer took the podman service, and every API call
returned `EOF`. Check, in order:

    podman machine ssh 'free -h; df -h /'
    podman machine ssh 'journalctl -k | grep -iE "oom|out of memory" | tail -5'

Remedies: raise the machine's memory (`podman machine set --memory ...`, machine stopped, your
call); cap the container with `KO_AGENT_SANDBOX_MEMORY` so sbt dies before the VM does; keep
gigabyte-scale work under `~` in the container, not `/tmp`. After a hard stop, `--reset` sweeps the
stray proxy and networks; the filter needs nothing — mounts died with the VM and stale session
markers are pruned at a later reap.

## Stale state after crashes

Self-healing by design, so intervention is rarely needed: a leaked session marker is pruned by the
first reap that finds it older than the launch bound of ten minutes (its container no longer exists,
and by then no launch could still be on its way to creating one); a stale or version-skewed mount is
unmounted and
replaced at the next launch; `--reset` removes the project's whole `mounts/<project>` tree. The
one thing worth checking after repeated crashes is that `pgrep -a ko-agent-fs` matches the projects
that actually have sessions.
