# Troubleshooting `ko-agent-fs-fuse`

The commands below use `podman machine ssh`, for macOS and Windows. On native Linux, run them
directly on the host, with the same paths under your own home.

## State and log locations

The FUSE backend keeps all its state in the daemon user's home, per workspace:

    ~/.local/share/ko-agent-sandbox/ko-agent-fs-fuse        the installed FUSE backend
    ~/.local/share/ko-agent-sandbox/ko-agent-fs             the installed policy's --resolve
    ~/.local/share/ko-agent-sandbox/mounts/<workspace-id>/
        workspace                                           the mountpoint the container binds
        daemon.log                                          the running daemon's log
        daemon.log.1                                        the previous daemon's log — the one
                                                            you want after a crash
        source-id                                           the source digest the daemon serves
        file-rules                                          the launcher's file rules the daemon
                                                            was started with
        file-rules.resolved                                 those rules and the guard's additions,
                                                            written by the daemon
        sessions/<container>                                one marker per live session
        lock                                                keeps a launch's reuse decision and a
                                                            reap's unmount from running at once

What the log holds:

- It starts with a banner (`ko-agent-fs-fuse <version> source <id> t=<unix-secs> serving ...`). An
  empty file therefore means the daemon never started, not that nothing happened.
- Each denial is one line: `DENY t=<unix-secs> op=<op> target=<name> reason=<rule>`.
  Attacker-chosen names arrive escaped. File contents are never logged.
- The log stops at 10,000 lines. After that, denials are only counted, with a running total every
  thousandth. After the cap notice, use the totals to find further refusals: single operations are
  no longer logged.

Check the daemon, the mount and the latest log:

    podman machine ssh "pgrep -a ko-agent-fs-fuse"
    podman machine ssh "mount | grep ko-agent-fs"
    podman machine ssh "tail .local/share/ko-agent-sandbox/mounts/*/daemon.log"

## "Operation not permitted" for an allowed mutation

Find the matching `DENY` line in `daemon.log`. It names the operation, the target and the rule:

- `reason=protected-git-control` on a file a normally allowed Git command needs — report the
  command and the DENY line. The workspace policy may lack an operational path in its allowlist
  (`../../policy/doc/git-metadata.md`, P2).
- `reason=pinned-git-component` — Git directories' `objects` and `objects/info` are only created by
  `mkdir`, never renamed or unlinked (`../../policy/doc/git-metadata.md`, "The immutable set"). If a
  normally allowed Git command needs otherwise, report the command and the DENY line.
- `reason=protected-git-entry` on a name that is not `.git` — the conservative name rule
  (`../../policy/doc/git-metadata.md`, "The name rule") refused a legitimate name. Report the exact
  bytes.
- `reason=protected-sandbox-config` — edit `.ko-agent-sandbox` on the host. If the refused name
  only looks like `.ko-agent-sandbox`, report its exact bytes.
- `reason=protected-file-rule`, `pinned-file-rule-component` or `file-rule-region` — the file rules
  refused it. `../../../doc/file-rules.md` says how to change a listed file on the host, or how to
  add a `writable` line.
- `reason=nonportable-target-syntax` on a `symlink` — use a relative target that stays inside the
  workspace, or put the program's cache inside the workspace.

  - The FUSE backend refuses absolute targets and targets that climb above the workspace root
    (`fs.rs`, `target_has_portable_syntax`).
  - After the first refusal, sbt 2 falls back to copying from its cache, where a build keeps its
    output in the workspace. "Everything works but slowly" says where the image puts that output.
  - For `python3 -m venv`, create the environment under `~`, or use `--copies` if it must be in
    the workspace. A virtualenv created in the container still names container paths in
    `pyvenv.cfg` and in shebangs. Copying does not make it usable on the host.

If no DENY line matches, first check whether the log has reached its cap. If it has not, check the
backing share's permissions and SELinux label from inside the machine.

## "Too many levels of symbolic links" (ELOOP) on a path that has none

Open the path again. A handle held across a rename can refer to names that no longer lead to the
original directories. The resolver refuses that stale path, and writes no DENY line (`fs.rs`,
`open_ino`).

## "Stale file handle" (ESTALE) in a directory that was renamed or replaced

Open the path again, or `cd` to it again. The names that a held handle or a working directory was
opened under now lead to another object. The resolver serves a handle only while it leads to the
object it was classified as (`fs.rs`, `open_ino`). There is no DENY line.

## "Transport endpoint is not connected" (ENOTCONN)

The daemon died. Only the workspace mount is unreachable, also for a shell whose current directory
is inside it. Read the logs on the host, then quit the session and launch again:

    podman machine ssh "tail -20 .local/share/ko-agent-sandbox/mounts/*/daemon.log*"
    podman machine ssh "journalctl -k | grep -iE 'oom|killed' | tail -5"

- A panic appears in the daemon log. An OOM kill appears in the kernel journal.
- After an OOM kill, follow "The whole machine degrades" below before you retry.
- A new launch starts a fresh daemon and keeps the previous log as `daemon.log.1`.

## The launch refuses to start

- `the installed ko-agent-fs-fuse is not this launcher's build`, or the same for `ko-agent-fs` —
  the binary and the jar disagree. Run `--build`.
- `ko-agent-fs-fuse self-test failed` — read the message that comes with it.
  - A setup failure can mean a missing `fusermount3`, or no `user_allow_other` in
    `/etc/fuse.conf`. In a recreated machine, `--build` asks to restore `user_allow_other`.
  - To reproduce: `podman machine ssh .local/share/ko-agent-sandbox/ko-agent-fs-fuse --self-test`.
  - If the setup succeeds but a check fails, report that failure. More mount privileges will not
    fix it.
- `refusing to serve ...` — follow the message's remedy on the host (`guard.rs`).
  - If it names a path `inside the workspace`, or says a symlink `leads into the workspace`: a
    protected Git path resolves through writable workspace files.
  - If it names a `bare repository`: the workspace root has a layout the workspace policy cannot
    protect.
- `refusing to serve ...` naming a path `outside the directories the podman machine shares` — a Git
  setting or a symlink below a listed entry leads where the machine cannot see the host's files. On
  Windows, that is another drive than the workspace's. Replace the link or the setting with a real
  file or directory inside the workspace or under a shared directory.
- `refusing to serve ...` saying something `resolves to the workspace root itself`, or to a
  directory that `holds the workspace` — a hook setting such as `core.hooksPath = .`, or a listed
  entry's symlink such as `.vscode -> ..`, points at the workspace root or above it. The workspace
  policy cannot hold that read-only. Point it at a directory of its own.
- `this workspace's concurrent sessions (...) run under other file rules` — someone edited
  `.ko-agent-sandbox/file/rule` while the named sessions run, and no start prompt asked to join them
  under their rules. Launch from a terminal, where the prompt appears, or after they end.
- `this workspace is mounted for sessions under other file rules` — the running mount's rules
  changed between the start prompt and the mount. Launch again.
- `mountpoint ... is not empty; refusing` — something created an entry in the mountpoint directory
  while no FUSE backend was mounted. Inspect it in the machine before you delete it: nothing
  legitimate writes there.

## The workspace mount is empty inside the container

Quit and launch again. The container may have started after the FUSE mount disappeared, and so
attached to the empty mountpoint. The workspace's files are still in the backing directory. The
races between mount and cleanup are described beside `KoAgentFs.koAgentFsReapScript`.

## Everything works but slowly

Compare your timings with `verification-log.md`, "The cost of a path walk":

- The measured metadata operations took about 6–18 times as long through the FUSE backend as
  through a plain bind mount on macOS, and 5–30 times as long on Windows.
- If your slowdown is much greater, check the machine as the next section describes.

`git status` is usually where it shows first:

- Claude Code runs one at startup, so a large tree appears as a long silence before its first
  word. `pulumi up` and `pulumi preview` run one each, to record whether the tree is dirty.
- git stats every tracked file by its full path, and each path component costs one round trip. So
  the cost is tracked files × depth.
- Measured: about 9 ms per file at depth 7, nearly as much again for the untracked walk, and 72 s
  for 4,200 files.

What shortens it, set on the host, since a session cannot write `.git/config`:

- `git config core.untrackedCache true` — drops the untracked walk, nearly half of the total.
- Ignore whole directories (`target/`, `node_modules/`), not file patterns (`*.class`). git skips
  an ignored directory without entering it, but walks every entry of a directory it must enter.
- Only fewer or shallower tracked files shorten the tracked-file pass itself. The rest is the
  FUSE backend's cost per operation, which `TODO.md`, "Performance", works on.

A build in the session that writes its output into the workspace pays that cost for each file it
writes, and a compiler writes deep:

- This repository's sbt compile takes 604 s into `target/out`, and 28 s into a directory outside
  the mount (`verification-log.md`, "an sbt build").
- The image moves what an sbt 2 build derives from `rootOutputDirectory` to `~/.cache/sbt-out`. By
  default, a jar that `sbt package` builds in a session is therefore there, not under `target/`,
  and is discarded with the session.
- A build that names an output path itself still writes the workspace. It can fail there with
  `NoSuchFileException` on links the host's sbt left (`container/ko-agent-sandbox/AGENTS-SANDBOX.md`
  has the cleanup).
- For another build program, point its output directory under `~/.cache` the same way, or run it
  on the host with `--run-on-host` (macOS).

For mill, the image sets nothing:

- mill takes its output directory from the environment variable `MILL_OUTPUT_DIR`: one value for
  every build that environment runs. sbt's setting, in contrast, is computed per build.
- Set in the image, the variable would give two mill builds in one session the same directory.
- Set it per command instead, keyed by the build:
  `MILL_OUTPUT_DIR=$HOME/.cache/mill-out/<the build's absolute path> ./mill …`.
- Use the same value on every command of that build. Another value starts from an empty directory,
  with a daemon of its own.
- What this saves for a mill build is not measured.
- `--run-on-host` does not forward the variable, so a mill build on the host keeps `out/`.

For gradle, the image sets nothing either. An init script can move every project's `build/`,
`buildSrc` and included builds too, keyed by the project's path:

    // ~/.gradle/init.d/out.init.gradle
    allprojects { project ->
        def key = project.projectDir.absolutePath.substring(1)
        project.layout.buildDirectory.set(
            new File(System.getProperty('user.home'), ".cache/gradle-out/${key}"))
    }

- The image does not ship it, because a gradle build, and the scripts around one, often name
  `build/` literally: `file("build/libs/…")`, a Containerfile's `COPY build/libs`. Those break when
  the directory moves. Check the workspace for such paths before you use it.
- It also saves less than sbt's setting. A generated 202-class build takes 75 s with `build/` in the
  mount, 44 s with it moved, and 4.5 s wholly outside the mount. So moving the persistent output
  out of the mount leaves most of the extra build time (`verification-log.md`, "a gradle build").
- `--project-cache-dir` for the project's `.gradle/` saves 3 s more.

For Maven, the image supplies nothing that moves `target/` from outside the project:

- `-Dproject.build.directory=…` is ignored. A core extension could do it, but none is written.
- `<build><directory>` in the project's own POM works. It takes the same generated build from 85 s
  to 47 s, against 1.9 s wholly outside the mount (`verification-log.md`, "a Maven build").
- Where the POM must not change, build a copy of the project under `~`, or run Maven on the host
  with `--run-on-host`.

## Tracing requests

To see which requests a program sends, and how long the daemon takes over each, start a daemon by
hand with `--trace` at a mountpoint of your own, and run the program there:

    ko-agent-fs-fuse --source <backing-dir> --mount <mountpoint> --trace 2>trace.log

The launcher never passes `--trace`, so a session's mount is not traced. Each request the FUSE
backend implements writes two lines:

    TRACE begin_us=5123 op=lookup parent=1:"." name="src"
    TRACE took_us=412 op=lookup parent=1:"." name="src"

- `begin_us` is the microseconds since the daemon was about to mount. The line is written before
  the request is served, so when the mount hangs, the log's last line names the request the daemon
  is in.
- `took_us` runs from after the first line is written until after the reply is sent. For
  `op=init`, it runs until just before the reply.
- The next `begin_us`, minus this request's `begin_us` and `took_us`, is time outside the measured
  interval. These timestamps cannot divide it among what it holds:
  - the kernel's and the caller's time;
  - the daemon's dispatch, and building and writing the two lines;
  - any request that writes no lines.
- A node is `<inode number>:<path from the backing root>`, or `<inode number>:?` when the daemon no
  longer knows the node. Names are escaped as in a `DENY` line. File contents are never logged.
- The lines do not hold the reply's error. A `DENY` line, written while the log is under its cap,
  falls between the two.
- Requests the FUSE backend leaves unimplemented (`fs.rs`, "Mutation coverage") write no lines.
- The trace has no cap: stop the daemon when the measurement is done.

## The whole machine degrades (every podman command slow or erroring)

Check the machine's free memory, disk space and OOM reports:

    podman machine ssh "free -h; df -h /"
    podman machine ssh "journalctl -k | grep -iE 'oom|out of memory' | tail -5"

An observed sbt cross-build used up the VM's memory, killed the podman service and left API calls
returning `EOF`. So memory pressure can look like a podman API failure.

If memory is short:

- Lower each session's `--memory` limit, or stop some sessions: their combined limits can exceed
  the VM's memory. [README.md](../../../README.md#reference) gives the default limit and the
  no-swap behavior.
- To give the machine more memory, stop it and run `podman machine set --memory ...`.
- Keep large builds under `~` in the container: `/tmp` uses RAM.
- The launch warns of low memory or disk space. Fix that shortage before another build.

After a hard stop, launch again to replace the FUSE mount. If stray containers or networks
remain, use `--reset`. It also ends this workspace's sessions and removes its saved state.

## Stale state after crashes

Launch again to replace a stale mount, or one built by a different jar. Cleanup removes session
markers whose containers are gone.

If the launcher died before its container started, allow ten minutes for the reaper to remove the
container. On Windows, or after the reaper failed to start, use `--reset` instead. Reset also
removes the workspace's FUSE backend state, ends its sessions and removes saved agent state; see the
[README.md](../../../README.md#reference).

After repeated crashes, compare `pgrep -a ko-agent-fs-fuse` with the workspaces that have live
sessions. Report daemons left over for workspaces with no sessions.
