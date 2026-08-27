# Plan: optional Coursier cache overlay

## Outcome

Add a repeatable opt-in `--cache-overlay` launch option whose kinds are a closed set.

Only `coursier` is defined in this increment. Each kind owns its host discovery, fixed container
destination, path validation and concurrency contract; this is not an arbitrary mount interface.
Without the option, Coursier and Scala tools use a new writable cache in the session's anonymous
home volume. Downloads disappear with the session. With it, the selected host Coursier `v1`
artifact cache is the readable lower layer at `~/.cache/coursier/v1`; sandbox writes go to a
Podman `:O` upper layer that disappears with the sandbox container. Extracted archives and JVMs
remain session-local because their cache entries can be host-OS-specific.

Keep the installed Coursier launchers in the image, outside `$HOME`.

This option expands the readable host boundary and is disabled by default. It never broadens
egress: a cache miss still succeeds only when the selected `--egress` profile admits the artifact
host. The image relocation and optional host overlay ship as one increment; implementation commits
may sequence them, but completion means the whole acceptance checklist passes.

## Evidence and target

The image has 1.1 GB and 3,259 files under `/home/nonroot`:

- 830 MB under `.cache/coursier`;
- 228 MB under `.local/share/coursier/bin`;
- the remaining agent-state seeds, shell files and other tool state.

A new volume mounted at `/home/nonroot` takes about 2.2 to 2.5 seconds to start because Podman
copies the image directory into it. The same image starts in about 0.2 seconds with `nocopy`.
Mounting the 25 GB macOS host Coursier cache root with `:O` takes 0.225 to 0.274 seconds and a
sandbox write is absent from the host after exit.

The target is to remove image-managed Coursier content from the copied home while retaining its
small seed files. Do not add `nocopy` to the home volume in this increment: that also hides the
`.claude`, `.codex`, `.gemini` and `.copilot` symlinks and can prevent a new persistent volume
from receiving its seed. A small ordinary copy-up preserves those contracts without material startup cost.

## Cold default

The launchers installed by `cs setup` are bootstraps. With no cache overlay, the first `sbt`,
`scala-cli`, `scalafmt` or other Scala-tool invocation in every session can download a substantial
part of the removed 830 MB again. A narrow egress profile can make that invocation fail when it
does not admit the required repositories. This cost is accepted: host artifacts remain unexposed
unless the user opts in, and all unshared downloads remain disposable.

Do not add a default cache image or retain an image-owned cache in this increment. Either would
preserve image size and add another cache lifecycle when the selected default deliberately permits
a cold session. If that decision is revisited, prefer first prototyping a root-owned cache under
the selected sandbox image and mounting its subpath with `type=image,rw=true`. That prototype must
prove ownership, the final nested-mount topology and each supported platform; it is not part of
this plan.

## Invariants

1. `sbt`, `scala-cli`, `cs`, `scalafmt`, and every other launcher produced by `cs setup` remain
   installed in the sandbox image.
2. No Coursier installation artifact or cache content is stored under image `/home/nonroot`; only
   the empty, nonroot-owned `.cache/coursier` parent remains as writable home structure.
3. The image contains no Coursier download cache in a hidden lower layer. Installation and cache
   removal happen in the same Containerfile `RUN` step.
4. The anonymous home remains writable and is removed with the sandbox. A launch without the flag
   neither reads nor writes any host Coursier path.
5. An overlay launch can read the selected host cache but cannot change its contents, ownership,
   mode, modification time, extended attributes or SELinux label. Access-time changes caused by
   reading the lower are outside this claim.
6. The overlay upper is private to one sandbox run. It is removed on normal exit, create/start
   failure, Ctrl-C and `--reset`; no new named volume or launcher state is introduced.
7. One project cannot name a cache path overlapping its workspace, launcher-owned state, Podman
   storage or an over-broad host directory and thereby create a second path around an existing
   boundary.
8. The option works with `KO_AGENT_SANDBOX_IMAGE`: it changes the mount, not the selected image.
9. Host-cache reuse does not imply offline operation. `.sbt`, Ivy and other non-Coursier caches
   remain session-local unless separately designed later.

## Command-line contract

Treat the option as launch authority because it exposes additional host files. It is repeatable so
future reviewed cache kinds do not require a comma-list grammar.

```text
--cache-overlay=coursier
--cache-overlay=coursier=/absolute/cache/v1
```

- No option: disabled.
- `coursier`: when `COURSIER_CACHE` is non-empty, use and validate its exact value without
  appending `v1` or mounting its parent; otherwise select the platform's conventional Coursier
  `v1` cache directory.
- `coursier=<directory>`: use that exact `v1` directory; do not append a platform-dependent
  component.
- Require the equals form for an explicit directory. A following word is the sandbox command under
  the launcher's existing first-non-option rule.
- Split the option value at its first `=` only. A Windows drive colon and commas in a path are data,
  not separators.
- Refuse an absent or unknown kind, an empty directory, a relative path and a duplicate kind.
  Different recognized kinds may repeat the option.
- Resolve symlinks and aliases to the canonical existing directory before boundary checks and
  before constructing the Podman argument. This follows a path the user explicitly supplied as
  launch authority, like project-directory canonicalization; it does not follow a
  repository-controlled symlink while discovering sandbox policy. Any overlap with the canonical
  project is refused below.
- Management verbs reject this launch-only option, as they reject launch authority they do not
  consume.
- Once the sandbox command starts, a token with the same spelling is passed to that command rather
  than parsed by the launcher.
- Do not accept `src:dst` or any caller-selected container destination. Podman's volume shorthand
  has Windows drive-colon ambiguity, and an arbitrary destination could shadow managed settings,
  `/workspace`, installed tools or persistent agent state.

Absent `COURSIER_CACHE`, bare `coursier` discovery uses:

| host | `v1` directory |
| --- | --- |
| Linux | `${XDG_CACHE_HOME:-$HOME/.cache}/coursier/v1` |
| macOS | `$HOME/Library/Caches/Coursier/v1` |
| Windows | `%LOCALAPPDATA%\Coursier\Cache\v1` |

Do not create a missing host cache. The user explicitly requested reuse, so a missing or unusable
directory is a launch error with the expected path and the `coursier=<directory>` override. Do not
silently fall back to the session cache.

## Cache-path boundary

Add one canonical resolver that returns either a validated `Path` or a user-facing error. Account
for each path relationship after canonicalization:

- refuse a filesystem root;
- refuse the configured user home, a well-known parent of user homes such as `/home` or `/Users`,
  or any ancestor of them;
- refuse any overlap with the project directory in either direction: a cache below the workspace
  is writable through `/workspace`, while a cache above it exposes unrelated host files;
- refuse any overlap with the launcher state root in either direction; it contains the inspection
  CA key and audit state;
- refuse any overlap with the launcher's install directory in either direction;
- refuse overlap with host-visible rootless storage configured in `storage.conf`, under
  `$XDG_DATA_HOME/containers`, or under `~/.local/share/containers`;
- on native Linux, ask Podman for its active graph root, run root and volume path before creating
  any resource and refuse overlap with each in either direction. Refuse the overlay if those roots
  cannot be determined. A Podman machine keeps its graph in the VM rather than the client path
  namespace; reject the client-side storage paths above, and do not compare unrelated path
  spellings from the two namespaces;
- on macOS, compare both data-volume spellings as `SandboxProject` already does;
- on Windows, reject UNC paths unless the existing Podman-volume path handling has an independently
  tested mapping; do not guess one;
- accept a narrower directory inside the user's home, including each default above, only after all
  protected-root checks pass;
- accept an explicit or `COURSIER_CACHE` directory outside the user's home, such as
  `/var/cache/coursier/v1`, under the same absolute, existence and protected-root checks.

The option is explicit permission to read every file under the accepted `v1` directory. Do not
attempt to recognize cache contents by filenames; a custom empty `v1` directory is valid. Do not
block credential-like path names: such a list is necessarily incomplete and would misstate this
explicit authority as a credential boundary.

## Image layout

Change `container/debian-coursier/Containerfile`, the canonical producer of the Scala toolchain:

1. Install the same launcher set as `cs setup` into `/opt/coursier/bin`.
2. Make the installed tree root-owned and non-writable by UID 65532.
3. Perform setup with a temporary `HOME`, then delete that home and every Coursier download cache
   in the same `RUN` instruction. A later `RUN rm` leaves the bytes in an earlier image layer and
   does not satisfy the invariant.
4. Set `PATH` in this order:

   ```text
   /home/nonroot/.local/share/coursier/bin:/opt/coursier/bin:<existing PATH>
   ```

   Runtime `cs install` therefore remains writable and overrides an image launcher of the same
   name. Do not set `COURSIER_BIN_DIR` globally: that would redirect runtime installation into the
   read-only `/opt` tree. Ordinary `cs update` manages only the session install directory and does
   not update image launchers. An update explicitly targeting `/opt/coursier/bin` fails; rebuilding
   the image updates the built-in launchers.
5. Detect the Temurin JDK in the parent image. Do not let setup install another JDK under its
   temporary home.
6. Create an empty `/home/nonroot/.cache/coursier` owned by UID/GID 65532. This gives Coursier a
   writable parent for session-local `arc` and `jvm` siblings after home copy-up. The final
   descendant-image guard below owns the content and ownership assertion.

`container/ko-agent-egress-proxy/Containerfile` also consumes `debian-coursier` and invokes `sbt`
during its build. Give that trusted build step explicit Buildah cache mounts for the Coursier and
sbt build caches if measurements show repeated proxy builds regress. Those are build caches, not
runtime image content; the final distroless proxy must still contain only its application output.
Update its comment that says the inherited `cs setup` cache lives under `/home/nonroot`: after the
relocation there is no inherited cache, and a nonroot build instead determines ownership of the
explicit build-cache mounts and session-created state.

Do not relocate or remove unrelated runtime caches in this increment. At the end of
`container/ko-agent-sandbox/Containerfile`, after every descendant-image producer has run, add the
binding population guard over image `/home/nonroot`. It enforces the directory contract in step 6,
requires `.local/share/coursier` to be absent, records the allowed top-level entries, and enforces
conservative apparent-size and inode ceilings. A later Scala smoke test or future tool that
repopulates image home must fail this guard instead of silently restoring copy-up latency.

## Launch topology

Keep the existing mounts and their order, adding the optional overlay after the home volume:

```text
type=volume,dst=/home/nonroot
<host-v1-directory>:/home/nonroot/.cache/coursier/v1:O  # only with the flag
type=volume,src=<persistent>,dst=/home/nonroot/persistent-volume
```

The exact ordering and nested-mount behavior must be proven with all three mounts together. The
small home copy-up includes `.cache/coursier`; Podman creates only the nested `v1` mountpoint. The
copy-up must also provide:

- `.claude -> persistent-volume/claude`;
- `.codex -> persistent-volume/codex`;
- `.gemini -> persistent-volume/antigravity`;
- `.copilot -> persistent-volume/copilot`;
- the seed files copied into a newly created persistent volume;
- a writable `.local`, `.cache`, `.sbt`, `.ivy2`, `.cargo` and other session-created paths.

Construct the overlay as exactly one `--volume` value ending in `:O`. Do not combine `O` with `U`,
`z`, `Z`, `ro` or another volume option; Podman documents `O` as conflicting with the other volume
options. Never chown or relabel the host cache to make the feature work.

Resolve and validate the cache path before creating networks, containers or reapers. Only an
enabled overlay adds a line before the existing Enter hold; the default adds no startup line:

```text
Cache overlay: coursier; host cache <path> is readable; sandbox writes are discarded
```

Do not create a capability-probe container before the hold. After Enter, `podman create` is the
canonical enforcement point. If Podman rejects `:O`, fail with its error and preserve the existing
cleanup path. Ctrl-C at the hold creates nothing; Ctrl-C after create remains covered by the
existing reaper or resident Windows cleanup.

## Platform contract

Podman implements `:O` in the Linux engine. Host-path availability is a separate machine-provider
contract.

- macOS/libkrun: require the exact `$HOME/Library/Caches/Coursier/v1` topology. The recorded
  parent-cache-root probe establishes `:O` support, but not the final nested target.
- Native Linux without enforcing SELinux: require the same read/write/discard and timing probes.
- SELinux-enforcing Linux: record labels, ownership, modes and timestamps before and after normal
  exit and forced cleanup. If Podman changes host metadata or requires disabling container labels,
  refuse the option on that host. Do not weaken SELinux separation for a cache optimization.
- Windows/WSL2: translate or pass the source through the same tested path mechanism as existing
  Podman bind mounts, then run the probe against `%LOCALAPPDATA%\Coursier\Cache\v1` on NTFS
  through `/mnt/<drive>`. Do not claim Windows support until it passes.
- Other remote Podman connections: the source is a server path, not necessarily a client path.
  Refuse automatic discovery unless the launcher can prove the discovered client directory is the
  directory Podman will mount. An explicit server-visible directory may be supported later under a
  separately stated contract.

## Security model

The lower cache is readable executable input shared across projects. The sandbox can inspect and
exfiltrate private artifacts, repository URLs, metadata and any accidentally stored file when its
egress profile permits a destination. State that at the option and in `SECURITY.md`.

The sandbox cannot poison the lower through the cache mount: all cache-path writes enter its
private upper. Preserve that claim with a host-observed integration test, not only an argument
test. The host can change the lower while a session runs; `:O` is not a snapshot, and Podman warns
against lower mutation. The accepted behavior is:

- redundant downloads and inconsistent cache misses are acceptable;
- a concurrent host mutation can make the current Coursier command fail and require a retry;
- no consistency or offline guarantee is made;
- a host change may or may not become visible to an untouched sandbox path;
- sandbox locks in the upper do not coordinate with host Coursier locks.

`PLAN-STAGED.md` rejects kernel OverlayFS over a mutable lower because staged workspace contents
must remain coherent and apply correctly. This cache overlay makes a narrower decision: its data
is disposable and reconstructible, so a transient miss, failed command and retry are accepted.
The workspace decision remains unchanged.

## Implementation sites

### `src/main/scala/AgentSandboxLauncher.scala`

- Keep platform discovery and path validation pure so every OS branch is unit-testable on one host.
- Update the file's canonical boundary diagram and home-volume statement.

If extracting the sandbox create-command builder is necessary to test the complete mount
population, do it once and make every launch use it. Do not leave a tested cache helper beside an
inline command that can omit or reorder it.

### Tests

`src/test/scala/AgentSandboxLauncherTest.scala`:

- parse disabled, auto-discovered and explicit-directory modes;
- prove repeatability through a parser helper supplied two fixture kinds;
- reject duplicate and unknown kinds, empty values, relative paths and separated-value spellings;
- prove first-non-option and `--` forwarding;
- prove every management verb rejects the launch-only option;
- test `COURSIER_CACHE` precedence and default `v1` discovery for Linux, macOS and Windows without
  depending on the test host;
- test canonical path overlap against project, launcher state and install directories, Podman
  storage, filesystem roots, home and macOS aliases;
- test that an explicit cache outside home is accepted when it overlaps no protected root;
- assert the complete create command has one anonymous home, one persistent volume, and exactly
  the selected cache overlays in registry-defined order;
- assert a custom sandbox image does not change the host mount semantics.

`src/test/scala/SessionBoundaryTest.scala`:

- default session: Coursier cache is writable session storage and no host cache mount exists;
- overlay session: the copied `.cache/coursier` parent retains UID/GID 65532, the `v1` target
  exists and is writable, and newly created sibling `arc` and `jvm` paths are writable session
  storage while unrelated host-home paths remain absent;
- update the complete mount allowlist deliberately rather than allowing every new host mount under
  `/home/nonroot` by prefix alone.

Add an opt-in integration suite using a temporary host `v1` directory, never the developer's real
cache:

1. Put a readable lower marker and an immutable fixture artifact in it.
2. Launch with the explicit option and prove both are visible.
3. Create, replace, rename and delete paths through the cache target.
4. Stop normally and prove every host file and claimed metadata value is unchanged.
5. Repeat with forced container removal and with the reaper-loss/reset lifecycle.
6. Launch two sessions over the same lower; prove their upper markers are mutually invisible and
   absent from the host.
7. Launch without the flag; prove the fixture is invisible and a session cache write disappears
   with the anonymous home.

Add image/toolchain checks:

- advertised Coursier-installed commands resolve from `/opt/coursier/bin` with a fresh home;
- a runtime `cs install` writes under `~/.local/share/coursier/bin` and wins `PATH` precedence;
- ordinary `cs update` does not modify `/opt/coursier/bin`, and explicitly selecting that directory
  fails without changing the image launchers;
- the default cold-cache path can launch the advertised Scala tools when egress admits their
  required hosts;
- the image-home allowlist, size and inode limits hold;
- the nonroot-owned `.cache/coursier` directory is empty, and no Coursier cache content or
  installed launcher remains under image home;
- a newly created persistent volume still receives all agent seeds and its three home links work.

Run the exact final mount topology on macOS, native Linux and Windows/WSL2. Record create, start and
total times separately for three warm-machine runs in each mode. Performance acceptance is based
on removing the copy-up regression, not a brittle CI wall-clock threshold:

- image `/home/nonroot` stays below the chosen size/inode ceilings;
- sandbox start no longer scales with the host cache's byte or inode count;
- overlay startup remains in the same order as the measured empty-volume baseline;
- `podman create` remains outside any timing attributed to an interactive command's lifetime.

### Documentation

Update each claim at its binding site:

| claim | canonical site | dependent site |
| --- | --- | --- |
| option syntax, defaults and exact `v1` meaning | README Reference/`--help` | parser tests |
| complete host-readable boundary | launcher diagram | README diagram, `SECURITY.md` |
| private artifacts and mutable-lower risk | `SECURITY.md` | README option warning |
| installed tools and session cache behavior | `SANDBOX.md` | Containerfile tests |
| mount and cleanup mechanism | launcher source | integration lifecycle tests |
| platform qualification | README option text | platform verification record |

The README's opening claim that the sandbox reaches no user files except the project must become a
default-mode claim with the opt-in cache exception named. Its diagram must show a one-way optional
host-cache lower and disposable per-run upper. Do not repeat the full threat analysis there; point
to `SECURITY.md`.

At the existing `cs install TOOL` instruction, `SANDBOX.md` should tell an acting agent that
session installs and ordinary `cs update` use `~/.local/share/coursier/bin`; image-managed
launchers under `/opt/coursier/bin` change only when the image is rebuilt. It should also say that
a missing Scala artifact is downloaded into disposable session state and that a narrow egress
profile can prevent the download. It does not need to teach Podman overlay mechanics.

## Acceptance checklist

- [ ] Default launch reads no host Coursier path and starts with a small home copy-up.
- [ ] Auto-discovered and explicit-directory Coursier modes mount exactly one `v1` directory.
- [ ] The copied `.cache/coursier` parent remains nonroot-owned and accepts session-local siblings.
- [ ] Help prices the cold default, including repeated downloads and egress-dependent failure.
- [ ] Installed Scala launchers remain available with an empty session cache.
- [ ] Overlay writes, including rename and deletion, leave the host cache and metadata unchanged.
- [ ] Normal exit, Ctrl-C, forced removal and reset leave no upper layer or new named volume.
- [ ] Concurrent sessions share only the readable lower and never one another's upper.
- [ ] Workspace, launcher state and Podman-storage overlap is refused before any resource is
      created; a safe explicit cache outside home is accepted.
- [ ] SELinux support either preserves host metadata without weakening labels or refuses clearly.
- [ ] macOS, native Linux and Windows claims match completed platform probes.
- [ ] The persistent volume is seeded correctly after reset and all three agent state paths work.
- [ ] Help, README, security model, sandbox instructions and launcher boundary diagram agree.
- [ ] Unit tests, full tests and opt-in container integration tests pass.
- [ ] Startup measurements demonstrate that image-home copy-up is no longer the dominant delay.

## Deliberate exclusions

- No automatic overlay: private host artifacts are not exposed without a launch flag.
- No persistent sandbox upper: cross-session executable cache state remains outside the sandbox's
  write authority.
- No host-cache mutation, synchronization, eviction or repair.
- No automatic sharing of `.sbt`, `.ivy2`, Maven, Gradle or other caches.
- No arbitrary host source/container destination mount syntax; every cache kind fixes its target
  and earns its own boundary analysis before entering the production registry.

## References

- [Podman volume semantics](https://docs.podman.io/en/latest/markdown/podman-create.1.html)
- [Podman Machine](https://docs.podman.io/en/latest/markdown/podman-machine-init.1.html)
- [Coursier cache locations and overrides](https://get-coursier.io/docs/cache)
- [Coursier setup options](https://get-coursier.io/docs/cli-setup)
- [Coursier install-directory behavior](https://get-coursier.io/docs/cli-install)
