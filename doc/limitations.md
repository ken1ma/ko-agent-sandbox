# Limitations

## Permission prompts that remain

### `claude`

Claude Code still prompts for an `rm` or `rmdir` that it resolves to a
[critical path](https://code.claude.com/docs/en/permission-modes#critical-paths), such as
`rm -rf *` in the workspace root (observed with Claude Code 2.1.276). No permission mode or
allow rule in the managed settings removes the prompt.

1. When Claude Code cannot follow a `cd`, as in `cd $_ && rm -rf *`, it resolves a relative target
   against its working directory. The prompt can then name a workspace path that the command would
   not remove.
1. Read the whole command before approving: the `rm` can sit deep in a long script.
1. The image's [AGENTS-SANDBOX.md](../container/ko-agent-sandbox/AGENTS-SANDBOX.md) tells agents
   how to write an `rm -rf`, so that the prompt comes less often and the prompted command stays
   short.

## `agy`'s terminal sandbox and Auto mode

`agy`'s terminal sandbox fails to start in a session, so in Auto mode commands run without it.
Rely on the egress rules to limit where `agy` sends data.

The items below were measured with `agy` 1.4.5 on 2026-10-23, under podman's default seccomp
profile, which `--nesting=user-namespace` keeps. The default `--nesting=none` refuses the user
namespace that `agy`'s sandbox creates first.

1. Each command `agy` runs in its sandbox fails with `connecting to sandbox server: ... connection
   reset by peer`. `agy`'s log names the failing step: `sbox: mount proc: permission denied`.
   Under `--nesting=same-uid`, which unmasks `/proc`, the log names
   `sbox: sethostname: operation not permitted`.
1. `agy` offers Auto mode anyway. Google documents that `agy` withholds Auto where the sandbox is
   unavailable, and names hosts and containers that block unprivileged user namespaces
   (https://antigravity.google/docs/cli/modes). The measured session allowed unprivileged user
   namespaces.
1. With Tool Permission `request-review`, the model reissues each failed command with
   `"BypassSandbox": true`. `agy`'s safety check then decides whether the command runs without a
   prompt.
   - A `readlink` ran without a prompt.
   - For `curl -sS -X POST --data-binary @README.md https://example.com/` the check reached no
     verdict (`autorun: safety gate produced no verdict, asking the user`) and asked.
1. With the image's `always-proceed`, that upload ran without a sandbox attempt or a prompt, and
   the egress proxy refused its connection. The same page documents that `always-proceed` takes
   precedence over Auto mode.
1. `agy -p --mode auto` stays in the default mode and warns `--mode auto is not available for this
   account`. The interactive `agy` of the same account offers Auto. The log line
   `--mode auto is unavailable (rollout flag off)` appears before print mode signs in and loads its
   experiments.

## Pipes as small as 8 KiB

A program that reads a child's output only after the child exits can hang in a session. The child
blocks once it has written more than the pipe holds, and a session's pipe can hold 8 KiB instead
of the kernel's default 64 KiB.

1. In code, read a child's output while the child runs, or send the output to a file, as
   `KoReviewTest.runIn` does. Either change fixes the hang at any pipe size, while the steps below
   only enlarge the pipe.
1. Check in a session with the command below, which prints 8192 while the limit below is reached
   and 65536 otherwise:

       python3 -c "import os, fcntl; print(fcntl.fcntl(os.pipe()[1], fcntl.F_GETPIPE_SZ))"

1. To remove the soft limit until the podman machine restarts, run
   `podman machine ssh -- sudo sysctl fs.pipe-user-pages-soft=0`.
1. Or stop the containers that publish ports while a session needs full-size pipes.

The cause is outside the launcher:

- Linux counts pipe buffers per user across the machine. Once a user holds more than
  `fs.pipe-user-pages-soft` pages (16384, 64 MiB), each new pipe that user creates gets two pages
  (`fs/pipe.c`, `alloc_pipe_info`).
- Rootless podman maps the container's users to the podman machine's user, so a session's
  processes count as that user. A session holding 32 KiB of pipes got 8 KiB pipes.
- On one machine, rootless podman's networking held the 64 MiB (2026-10-18): 32 pipes of 1 MiB in
  `pasta` and 30 in `rootlessport`. `rootlessport` runs for containers that publish ports, and the
  launcher publishes none.

## No FIFO in the workspace

On every platform, a session cannot make a FIFO (a named pipe, `mkfifo`) in the workspace, or set
the times of a FIFO the host put there. Under `--workspace=live,bpf`, a session cannot open a FIFO
the host put there either, in any mode. The refusals answer `EPERM`, with one exception: on the
macOS machine, the share refuses `mkfifo` under `live,bpf` with `EACCES`, before the policy runs.

1. Make the FIFO under `/tmp` or another directory of the container's own filesystem, where
   nothing refuses it. A session leaves `TMPDIR` unset, so a tool puts its temporary files under
   `/tmp` without a setting.
1. A tool that insists on a FIFO beside its inputs fails at `mkfifo`, visibly, rather than hanging
   the machine.

The reason is a libkrun defect on the macOS podman machine (`upstream-issues.md`, "Setting a FIFO's
times blocks the macOS virtio-fs server"):

- When a FIFO's times on the share reach the host's virtio-fs server, the server blocks the share
  for every session on the machine.
- A mere write through the FIFO is enough, since the guest kernel flushes the FIFO's times itself.

`TODO.md`, "A FIFO in the workspace hangs the podman machine", has the decision and what lifts it.

## No extended attributes or ACLs

`setfattr`, `setfacl` and other programs that make the same syscalls fail everywhere in a session,
`~` included. The xattr syscalls answer `Operation not supported`. `chattr` fails in the workspace,
where the share answers `Inappropriate ioctl for device`.

1. `cp -a`, `rsync -X` and `tar --xattrs` copy the files and drop the attributes, as on a
   filesystem without them.
1. A tool that needs to set an attribute fails at that call. Report the failure, since the rule is
   the launcher's. The workspace's protections need the rule (`SECURITY.md`, "No containers inside
   the sandbox by default", the profile's attribute rule, explains why).
