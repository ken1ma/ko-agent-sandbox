# Limitations

## Permission prompts that remain

### `claude`

A prompt remains for an `rm` or `rmdir` that Claude Code resolves to a
[critical path](https://code.claude.com/docs/en/permission-modes#critical-paths), such as
`rm -rf *` in the workspace root (observed with Claude Code 2.1.276). No permission mode or
allow rule in the managed settings removes it.

1. Claude Code resolves a relative target against its working directory when it cannot follow a
   `cd`, as in `cd $_ && rm -rf *`, so the prompt can name a workspace path the command would not
   remove.
1. Read the whole command before approving: the `rm` can sit deep in a long script.
1. To make the prompt rarer and the prompted command short, the image's
   [AGENTS-SANDBOX.md](../container/ko-agent-sandbox/AGENTS-SANDBOX.md) tells agents how to write
   an `rm -rf`.

## `agy`'s terminal sandbox and Auto mode

`agy`'s terminal sandbox fails to start in a session, so in Auto mode commands run without it:
rely on the egress rules to limit where `agy` sends data. Measured with `agy` 1.4.5 on 2026-10-23
under podman's default seccomp profile, which `--nesting=user-namespace` keeps; the default
`--nesting=none` refuses the user namespace the sandbox creates first:

1. Each command `agy` runs in its sandbox fails with `connecting to sandbox server: ... connection
   reset by peer`. Its log names the step: `sbox: mount proc: permission denied`, and under
   `--nesting=same-uid`, which unmasks `/proc`, `sbox: sethostname: operation not permitted`.
1. `agy` offers Auto mode anyway. Google documents that `agy` withholds Auto where the sandbox is
   unavailable, naming hosts and containers that block unprivileged user namespaces; the measured
   session allowed them (https://antigravity.google/docs/cli/modes).
1. With Tool Permission `request-review`, the model reissues each failed command with
   `"BypassSandbox": true`, and `agy`'s safety check decides whether it runs without a prompt.
   - It ran a `readlink` without a prompt.
   - For `curl -sS -X POST --data-binary @README.md https://example.com/` it reached no verdict
     (`autorun: safety gate produced no verdict, asking the user`) and asked.
1. With the image's `always-proceed`, which the same page documents as taking precedence over Auto
   mode, that upload ran without a sandbox attempt or a prompt; the egress proxy refused its
   connection.
1. `agy -p --mode auto` stays in the default mode, warning `--mode auto is not available for this
   account`, while the interactive `agy` of the same account offers Auto. The log line
   `--mode auto is unavailable (rollout flag off)` comes before print mode signs in and loads its
   experiments.

## Pipes as small as 8 KiB

A program that reads a child's output only after the child exits can hang in a session: the child
blocks once it has written more than the pipe holds, which can be 8 KiB instead of Linux's 64 KiB.

1. In code, read a child's output while it runs, or send it to a file, as `KoReviewTest.runIn`
   does: that fixes the hang at any pipe size, while the steps below only enlarge the pipe.
1. Check in a session; this prints 8192 while the limit below is reached, 65536 otherwise:

       python3 -c "import os, fcntl; print(fcntl.fcntl(os.pipe()[1], fcntl.F_GETPIPE_SZ))"

1. Lift it until the podman machine restarts:
   `podman machine ssh -- sudo sysctl fs.pipe-user-pages-soft=0`, which removes the soft limit.
1. Or stop the containers that publish ports while a session needs full-size pipes.

The cause is outside the launcher:

- Linux counts pipe buffers per user across the machine, and once a user holds more than
  `fs.pipe-user-pages-soft` pages (16384, 64 MiB), each new pipe that user creates gets two pages
  (`fs/pipe.c`, `alloc_pipe_info`).
- A session's processes count as the podman machine's user, whom rootless podman maps the
  container's users to: a session holding 32 KiB of pipes got 8 KiB ones.
- Rootless podman's networking held the 64 MiB on one machine (2026-10-18): 32 pipes of 1 MiB in
  `pasta` and 30 in `rootlessport`, which runs for containers that publish ports. The launcher
  publishes none.

## No FIFO in the workspace

A session cannot make a FIFO (a named pipe, `mkfifo`) in the workspace, nor set the times of one
the host put there: both answer `EPERM`, on every platform.

1. Make the FIFO under `/tmp` or another directory of the container's own filesystem, where
   nothing refuses it; a session leaves `TMPDIR` unset, so a tool's temporary files go there
   without a setting.
1. A tool that insists on a FIFO beside its inputs fails at `mkfifo` with `EPERM`, visibly, rather
   than hanging the machine.

The reason is a libkrun defect on the macOS podman machine: a FIFO on the share whose times reach
the host's virtio-fs server blocks the share for every session on the machine, and a mere write
through the FIFO is enough, since the guest kernel flushes the FIFO's times itself
(`upstream-issues.md`, "Setting a FIFO's times blocks the macOS virtio-fs server"; `TODO.md`,
"A FIFO in the workspace hangs the podman machine", has the decision and what lifts it).

