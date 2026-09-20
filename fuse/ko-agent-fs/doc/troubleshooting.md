# Troubleshooting `ko-agent-fs`

Commands below use `podman machine ssh` on macOS/Windows. On native Linux, run the commands
directly on the host, using the same paths under your own home.

## State and log locations

All filter state is stored in the daemon user's home, per project:

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
with a running total every thousandth. After the cap notice, use the totals to identify further
refusals; individual operations are no longer logged.

Check the daemon, mount and latest log:

    podman machine ssh "pgrep -a ko-agent-fs"
    podman machine ssh "mount | grep ko-agent-fs"
    podman machine ssh "tail .local/share/ko-agent-sandbox/mounts/*/daemon.log"

## "Operation not permitted" for an allowed mutation

The matching `DENY` line in `daemon.log` names the operation, the target and the rule:

- `reason=protected-git-control` on a file needed by a normally allowed Git command — report the
  command and DENY line. The filter may be missing an operational path from its allowlist
  (`git-metadata.md`, P2).
- `reason=protected-git-entry` on a name that is not `.git` — the conservative name rule
  (`git-metadata.md`, "The name rule") refused a legitimate name. Report the exact bytes.
- `reason=protected-sandbox-config` — edit `.ko-agent-sandbox` on the host. If the refused name
  merely resembles `.ko-agent-sandbox`, report its exact bytes.
- `reason=nonportable-target-syntax` on a `symlink` — use a relative target that stays inside the
  workspace, or put the program's cache inside the project.

  - Absolute targets and targets that climb above the workspace root are refused (`fs.rs`,
    `target_has_portable_syntax`).
  - sbt 2 falls back to copying from its cache after the first refusal, where a build keeps
    its output in the project ("Everything works but slowly" has where the image puts it).
  - For `python3 -m venv`, create the environment under `~`, or use `--copies` if it must be in
    the project. A virtualenv created in the container still names container paths in
    `pyvenv.cfg` and shebangs; copying does not make it usable on the host.

If there is no matching DENY line, first check whether the log has reached its cap. If it has
not, check the backing share's permissions and SELinux label from inside the machine.

## "Too many levels of symbolic links" (ELOOP) on a path that has none

Reopen the path. A handle held across a rename can refer to names that no longer identify the
original directories. The resolver refuses that stale path without a DENY line (`fs.rs`,
`open_ino`).

## "Stale file handle" (ESTALE) in a directory that was renamed or replaced

Reopen the path, or `cd` to it again. The names a held handle or a working directory was opened
under now lead to another object, and the resolver serves a handle only the object it was
classified as (`fs.rs`, `open_ino`). There is no DENY line.

## "Transport endpoint is not connected" (ENOTCONN)

The daemon died; only the project mount is inaccessible, including to a shell whose current
directory is inside it. Read the logs on the host, then quit the session and relaunch:

    podman machine ssh "tail -20 .local/share/ko-agent-sandbox/mounts/*/daemon.log*"
    podman machine ssh "journalctl -k | grep -iE 'oom|killed' | tail -5"

A panic appears in the daemon log; an OOM kill appears in the kernel journal. For an OOM kill,
follow "The whole machine degrades" below before retrying. Relaunching starts a fresh daemon and
keeps the previous log as `daemon.log.1`.

## The launch refuses to start

- `the installed ko-agent-fs is not this launcher's build` — the binary and the jar disagree; run
  `--build`.
- `ko-agent-fs self-test failed` — read the accompanying message. A setup failure can mean
  missing `fusermount3` or `user_allow_other` in `/etc/fuse.conf`; `--build` asks to restore the
  latter in a recreated machine. To reproduce:
  `podman machine ssh .local/share/ko-agent-sandbox/ko-agent-fs --self-test`.
  If setup succeeds but a check fails, report that failure; more mount privileges will not fix it.
- `refusing to serve ...` naming a path `inside the workspace`, or a `bare repository` — follow
  the message's remedy on the host. A protected Git path resolves through writable project
  files, or the project root has a bare-repository layout that the filter cannot protect
  (`guard.rs`).
- `mountpoint ... is not empty; refusing` — an entry was created in the mountpoint directory while
  no filter was mounted. Inspect it in the machine before deleting; nothing legitimate writes there.

## The project mount is empty inside the container

Quit and relaunch. The container may have started after the filter mount disappeared, leaving
it attached to the empty mountpoint. The project files remain in the backing directory. Mount
and cleanup races are described beside `KoAgentFs.koAgentFsReapScript`.

## Everything works but slowly

Compare your timings with `verification-log.md`, "The cost of a path walk". The measured metadata
operations took about 6–18 times as long through the filter as through an unfiltered bind mount on
macOS, and 5–30 times on Windows. If your slowdown is much greater, check the machine as described
in the next section.

`git status` is where it usually shows first — Claude Code runs one at startup, so a large tree
appears as a long silence before its first word. git stats every tracked file by its full path and
each path component is a round trip, so the cost is tracked files × depth: ~9 ms per file at
depth 7 and nearly as much again for the untracked walk, 72 s for 4,200 files. What shortens it,
set on the host (a session cannot write `.git/config`):

- `git config core.untrackedCache true` — drops the untracked walk, nearly half of the total.
- Ignore whole directories (`target/`, `node_modules/`), not file patterns (`*.class`): git prunes
  an ignored directory without entering it, and walks every entry of one it must enter.
- The tracked-file pass itself shortens only with fewer or shallower tracked files; the rest is
  the filter's per-operation cost, and `TODO.md`, "Performance", is where that is being worked.

A build in the session that writes its output into the project pays that cost per file written,
and a compiler writes deep: this repository's sbt compile takes 604 s into `target/out` and 28 s
into a directory outside the mount (`verification-log.md`, "an sbt build"). The image moves what
an sbt 2 build derives from `rootOutputDirectory` to `~/.cache/sbt-out`, so by default a jar
`sbt package` builds in a session is there, not under `target/`, and is discarded with the
session; a build that names an output path itself still writes the project, and can fail there
with `NoSuchFileException` on links the host's sbt left
(`container/ko-agent-sandbox/AGENTS-SANDBOX.md` has the cleanup). For another build program, point
its output directory under `~/.cache` the same way, or run it on the host with `--run-on-host`
(macOS).

For mill the image sets nothing. mill takes its output directory from the environment variable
`MILL_OUTPUT_DIR`, one value for every build that environment runs, where sbt's setting is computed
per build; set in the image, it would give two mill builds in one session the same directory. Set
it per command instead, keyed by the build:
`MILL_OUTPUT_DIR=$HOME/.cache/mill-out/<the build's absolute path> ./mill …`. Use the same value
on every command of that build: another value starts from an empty directory with a daemon of its
own. What this saves for a mill build is not measured. `--run-on-host` does not forward the
variable, so a host mill build keeps `out/`.

For gradle the image sets nothing either. An init script can move every project's `build/`,
`buildSrc` and included builds too, keyed by the project's path:

    // ~/.gradle/init.d/out.init.gradle
    allprojects { project ->
        def key = project.projectDir.absolutePath.substring(1)
        project.layout.buildDirectory.set(
            new File(System.getProperty('user.home'), ".cache/gradle-out/${key}"))
    }

The image does not ship it because a gradle build, and the scripts around one, often name
`build/` literally — `file("build/libs/…")`, a Containerfile's `COPY build/libs` — and those
break with the directory moved. Check the project for such paths before using it. It also saves less
than sbt's setting: a generated 202-class build takes 75 s with `build/` in the mount, 44 s with
it moved, and 4.5 s wholly outside the mount, so most of the extra build time remains after
moving the persistent output outside the mount (`verification-log.md`, "a gradle build").
`--project-cache-dir` for the project's `.gradle/` takes off 3 s more.

For Maven the image supplies nothing that moves `target/` from outside the project:
`-Dproject.build.directory=…` is ignored, and a core extension could do it but none is written.
`<build><directory>` in the project's own POM works, and takes the same generated build from 85 s
to 47 s, against 1.9 s wholly outside the mount (`verification-log.md`, "a Maven build"). Where
the POM is not to change, build a copy of the project under `~`, or run Maven on the host with
`--run-on-host`.

## The whole machine degrades (every podman command slow or erroring)

Check the machine's available memory, disk space and OOM reports:

    podman machine ssh "free -h; df -h /"
    podman machine ssh "journalctl -k | grep -iE 'oom|out of memory' | tail -5"

An observed sbt cross-build exhausted the VM's memory, killed the podman service and left API
calls returning `EOF`. Memory pressure can therefore appear as a podman API failure.

If memory is short, lower each session's `KO_AGENT_SANDBOX_MEMORY` limit or stop some sessions;
their combined limits can exceed the VM's memory.
[README.md](../../../README.md#reference) gives the default limit and no-swap behavior.
To give the machine more memory, stop it and run `podman machine set --memory ...`.
Keep large builds under `~` in the container: `/tmp` uses RAM.
The launch warning reports low memory or disk space; resolve that shortage before another build.

After a hard stop, relaunch to replace the filter mount. If stray containers or networks remain,
use `--reset`; it also ends this project's sessions and removes its saved state.

## Stale state after crashes

Relaunch to replace a stale mount or one built by a different jar. Session markers whose
containers are gone are removed during cleanup.

If the launcher died before its container started, allow ten minutes for the reaper to remove
it. On Windows or after a failed reaper spawn, use `--reset` instead. Reset also removes the
project's filter state, ends its sessions and removes saved agent state; see the
[README.md](../../../README.md#reference).

After repeated crashes, compare `pgrep -a ko-agent-fs` with the projects that have live sessions.
Report daemons left over for projects with no sessions.
