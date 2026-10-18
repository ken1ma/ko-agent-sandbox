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
