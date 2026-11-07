# Plan: optional Coursier cache overlay

`--run-on-host` (`run-on-host.md`) meets part of this plan's goal: an agent's sbt and `mill` builds
run on the host against a per-workspace cache of their own, so they neither warm nor need the
container's cache. This plan covers what remains:

- the container's own Scala tooling, which runs `scala`, `scalafmt`, `cs install`, and sbt when the
  host channel is not in force;
- the relocation of image-home content, which removes the copy-up cost.

Both plans keep one property for the user's own Coursier cache: a sandboxed build never changes it.
The two plans reach that property in different ways:

- Here, a podman `:O` upper layer keeps the cache readable and unwritable.
- The host build sandbox has no mount namespace to overlay with, so it separates the caches by root
  instead (`run-on-host.md`, "The run-on-host cache").

## Outcome

Add an opt-in launch option, `--cache-overlay`, which may repeat and whose kinds are a closed set.

- This increment defines only the kind `coursier`.
- Each kind owns its host discovery, fixed container destination, path validation and concurrency
  contract. The option is not an arbitrary mount interface.
- Without the option, Coursier and Scala programs use a new writable cache in the session's
  anonymous home volume. Downloads disappear with the session.
- With the option, the selected host Coursier `v1` artifact cache is the readable lower layer at
  `~/.cache/coursier/v1`. Sandbox writes go to a podman `:O` upper layer, which disappears with the
  sandbox container.
- Extracted archives and JVMs stay session-local, because their cache entries can be specific to
  the host OS.
- The installed Coursier launchers stay in the image, outside `$HOME`.

The option widens what the sandbox can read on the host, so it is off by default. The option never
widens egress: a cache miss still succeeds only when the selected `--egress` profile allows the
artifact host.

The image relocation and the optional host overlay ship as one increment. Implementation commits
may come in sequence, but the increment is complete only when the whole acceptance checklist
passes.

## Evidence and target

The image holds 1.1 GB in 3,259 files under `/home/nonroot`:

- 830 MB under `.cache/coursier`;
- 228 MB under `.local/share/coursier/bin`;
- the remaining agent-state seeds, shell files and other program state.

Startup measurements:

- A new volume mounted at `/home/nonroot` takes about 2.2 to 2.5 seconds to start, because podman
  copies the image directory into it.
- The same image starts in about 0.2 seconds with `nocopy`.
- Mounting the 25 GB macOS host Coursier cache root with `:O` takes 0.225 to 0.274 seconds. A
  sandbox write is absent from the host after exit.

The target is to remove image-managed Coursier content from the copied home and keep its small seed
files.

- Do not add `nocopy` to the home volume in this increment: `nocopy` also hides the agents' symlinks
  into `persistent-volume`.
- Copying only the remaining home seed keeps those symlinks and costs no material startup time.

## Cold default

The launchers that `cs setup` installs are bootstraps. Without a cache overlay:

- the first `sbt`, `scala`, `scalafmt` or other Scala program in every session can download a
  substantial part of the removed 830 MB again;
- that first run can fail when a narrow egress profile does not allow the repositories it needs.

This cost is accepted: host artifacts stay unexposed unless the user opts in, and every download
that is not shared stays disposable.

Do not add a default cache image or keep an image-owned cache in this increment. Either would keep
the image size and add another cache lifecycle, while the chosen default deliberately allows a cold
session.

If that decision is revisited, first prototype a root-owned cache under the selected sandbox image,
and mount its subpath with `type=image,rw=true`. That prototype must prove ownership, the final
nested-mount topology and each supported platform. The prototype is not part of this plan.

## Guarantees

1. The sandbox image keeps the launchers that the `cs setup --apps` line in
   `container/debian-coursier/Containerfile` selects, and no others.
2. Image `/home/nonroot` stores no Coursier installation artifact or cache content. Only the empty,
   nonroot-owned `.cache/coursier` parent remains, as writable home structure.
3. No hidden lower layer of the image holds a Coursier download cache: one Containerfile `RUN` step
   both installs Coursier and removes the cache.
4. The anonymous home stays writable and is removed with the sandbox. A launch without the option
   neither reads nor writes any host Coursier path.
5. An overlay launch can read the selected host cache, but cannot change its contents, ownership,
   mode, modification time, extended attributes or SELinux label. This claim excludes access-time
   changes that reading the lower layer causes.
6. The overlay upper layer is private to one sandbox run. The upper layer is removed on normal exit,
   on a create or start failure, on Ctrl-C and on `--reset`. The option adds no named volume and no
   launcher state.
7. A launch cannot name a cache path that overlaps its workspace, launcher-owned state, podman
   storage or an over-broad host directory, and so cannot create a second path around an existing
   boundary.
8. The option works with `--image`: it changes the mount, not the selected image.
9. Reusing the host cache does not make the session work offline. `.sbt`, Ivy and other
   non-Coursier caches stay session-local unless a later design shares them.

## Command-line contract

The option is a session option, because it exposes more host files. The option repeats, so that
future reviewed cache kinds need no comma-list grammar.

```text
--cache-overlay=coursier
--cache-overlay=coursier=/absolute/cache/v1
```

- No option: the overlay is off.
- `coursier`: when `COURSIER_CACHE` is non-empty, the launcher uses and validates its exact value.
  The launcher neither appends `v1` nor mounts the parent. Otherwise the launcher selects the
  platform's conventional Coursier `v1` cache directory.
- `coursier=<directory>`: the launcher uses that exact `v1` directory and appends no
  platform-dependent component.
- An explicit directory requires the equals form. Under the launcher's existing first-non-option
  rule, a following word is the sandbox command.
- The launcher splits the option value at its first `=` only. A Windows drive colon and commas in a
  path are data, not separators.
- The launcher refuses an absent or unknown kind, an empty directory, a relative path and a
  duplicate kind. The option may repeat with different recognized kinds.
- The launcher resolves symlinks and aliases to the canonical existing directory before the
  boundary checks and before it builds the podman argument.
  - The launcher follows a path the user supplied at launch, as the workspace root's
    canonicalization does. The launcher does not follow a repository-controlled symlink while it
    discovers the boundary configuration.
  - "Cache-path boundary" refuses any overlap with the canonical workspace root.
- Management actions reject this launch-only option, as they reject the other session options they
  do not read.
- Once the sandbox command starts, a token with the same spelling goes to that command; the
  launcher does not parse it.
- The launcher accepts no `src:dst` form and no caller-selected container destination:
  - podman's volume shorthand is ambiguous with a Windows drive colon;
  - an arbitrary destination could shadow managed settings, the workspace mount, installed programs
    or persistent agent state.

Without `COURSIER_CACHE`, a bare `coursier` discovers this directory:

| host | `v1` directory |
| --- | --- |
| Linux | `${XDG_CACHE_HOME:-$HOME/.cache}/coursier/v1` |
| macOS | `$HOME/Library/Caches/Coursier/v1` |
| Windows | `%LOCALAPPDATA%\Coursier\Cache\v1` |

The launcher does not create a missing host cache. The user explicitly asked for reuse, so a
missing or unusable directory is a launch error. The error names the expected path and the
`coursier=<directory>` override. The launcher does not silently fall back to the session cache.

## Cache-path boundary

Add one canonical resolver that returns either a validated `Path` or an error for the user. The
resolver handles each path relationship after canonicalization:

- The resolver refuses a filesystem root.
- The resolver refuses the configured user home, a well-known parent of user homes such as `/home`
  or `/Users`, and any ancestor of them.
- The resolver refuses any overlap with the workspace, in either direction:
  - a cache below the workspace root is writable through the workspace mount;
  - a cache above the workspace root exposes unrelated host files.
- The resolver refuses any overlap with the launcher state root, in either direction. That root
  holds the inspection CA key and audit state.
- The resolver refuses any overlap with the launcher's install directory, in either direction.
- The resolver refuses overlap with host-visible rootless storage: the storage that `storage.conf`
  configures, and anything under `$XDG_DATA_HOME/containers` or `~/.local/share/containers`.
- On native Linux, the launcher asks podman for its active graph root, run root and volume path
  before it creates any resource. The resolver refuses overlap with each of them, in either
  direction.
  - The resolver refuses the overlay when those roots cannot be determined.
  - A podman machine keeps its graph in the VM, not in the client's path namespace. For a machine,
    the resolver rejects the client-side storage paths above and does not compare unrelated path
    spellings from the two namespaces.
- On macOS, the resolver compares both spellings of the data volume, as `SandboxWorkspace` does.
- On Windows, the resolver rejects UNC paths unless the existing podman-volume path handling has an
  independently tested mapping for them. Do not guess a mapping.
- The resolver accepts a narrower directory inside the user's home, including each default above,
  only after all protected-root checks pass.
- The resolver accepts an explicit or `COURSIER_CACHE` directory outside the user's home, such as
  `/var/cache/coursier/v1`, under the same checks: absolute, existing, and clear of every protected
  root.

The option is explicit permission to read every file under the accepted `v1` directory.

- The resolver does not try to recognize cache contents by file name; a custom empty `v1` directory
  is valid.
- The resolver does not block credential-like path names. Such a list is always incomplete, and it
  would misstate this explicit authority as a credential boundary.

## Image layout

Change `container/debian-coursier/Containerfile`, the Containerfile that installs the Scala
toolchain for the images built on it:

1. Install the launchers that the existing `cs setup --apps` line selects into `/opt/coursier/bin`.
2. Make the installed tree root-owned and not writable by UID 65532.
3. Run setup with a temporary `HOME`, then delete that home and every Coursier download cache in
   the same `RUN` instruction. A later `RUN rm` leaves the bytes in an earlier image layer, so it
   does not satisfy this step.
4. Set `PATH` in this order:

   ```text
   /home/nonroot/.local/share/coursier/bin:/opt/coursier/bin:<existing PATH>
   ```

   - A runtime `cs install` therefore stays writable, and its launcher overrides an image launcher
     of the same name.
   - Do not set `COURSIER_BIN_DIR` globally: it would redirect runtime installation into the
     read-only `/opt` tree.
   - An ordinary `cs update` manages only the session install directory and does not update image
     launchers.
   - An update that explicitly targets `/opt/coursier/bin` fails. Rebuilding the image updates the
     built-in launchers.
5. Detect the Temurin JDK in the parent image. Do not let setup install another JDK under its
   temporary home.
6. Create an empty `/home/nonroot/.cache/coursier` owned by UID/GID 65532.
   - After home copy-up, this directory gives Coursier a writable parent for the session-local
     `arc` and `jvm` siblings.
   - The check at the end of the final image build, below, asserts the directory's contents and
     owner.

`ko-agent-egress-proxy/Containerfile` also builds on `debian-coursier` and runs `sbt`
during its build.

- If measurements show that repeated proxy builds get slower, give that trusted build step explicit
  Buildah cache mounts for the Coursier and sbt build caches.
- Those mounts hold build caches, not runtime image content. The final distroless proxy image must
  still contain only its application output.
- Update the proxy Containerfile's comment that says the inherited `cs setup` cache is under
  `/home/nonroot`. After the relocation no cache is inherited; a nonroot build instead decides the
  ownership of the explicit build-cache mounts and of the state the session creates.

Do not relocate or remove unrelated runtime caches in this increment.

At the end of `container/ko-agent-sandbox/Containerfile`, after every step that builds on the
parent images, check every entry under image `/home/nonroot` and fail the build on a violation. The
check does the following:

- it enforces the directory contract of step 6;
- it requires `.local/share/coursier` to be absent;
- it records the allowed top-level entries;
- it enforces conservative limits on apparent size and inode count.

A later Scala smoke test or a future program that fills image home again must fail this check,
rather than silently bring back the copy-up latency.

## Launch topology

Keep the existing mounts and their order, and add the optional overlay after the home volume:

```text
type=volume,dst=/home/nonroot
<host-v1-directory>:/home/nonroot/.cache/coursier/v1:O  # only with the flag
type=volume,src=<persistent>,dst=/home/nonroot/persistent-volume
```

- The exact order and the nested-mount behavior must be proven with the full mount set.
- The small home copy-up includes `.cache/coursier`; podman creates only the nested `v1`
  mountpoint.
- The copy-up must also provide everything the image's home seed provides:
  - the agents' links into `persistent-volume` and their parents
    (`container/ko-agent-sandbox/Containerfile`);
  - the volume that `ko-sandbox-entrypoint` seeds;
  - a writable `.local`, `.cache`, `.sbt`, `.ivy2`, `.cargo` and other paths the session creates.

Build the overlay as exactly one `--volume` value ending in `:O`.

- Do not combine `O` with `U`, `z`, `Z`, `ro` or another volume option: podman documents `O` as
  conflicting with the other volume options.
- Never chown or relabel the host cache to make the feature work.

Resolve and validate the cache path before creating networks, containers or reapers. Only an
enabled overlay adds a line before the existing Enter hold; the default adds no startup line:

```text
Cache overlay: coursier; host cache <path> is readable; sandbox writes are discarded
```

- Do not create a container before the hold to probe what podman supports.
- After Enter, `podman create` is the one place that enforces the overlay. If podman rejects `:O`,
  the launch fails with podman's error and keeps the existing cleanup path.
- Ctrl-C at the hold creates nothing. Ctrl-C after create stays covered by the existing reaper or by
  the resident Windows cleanup.

## Platform contract

podman implements `:O` in the Linux engine. Whether a host path is available is a separate
contract, which the machine provider keeps.

- macOS/libkrun: require the exact `$HOME/Library/Caches/Coursier/v1` topology. The recorded probe
  of the parent cache root establishes `:O` support, but not the final nested target.
- Native Linux without enforcing SELinux: require the same read, write, discard and timing probes.
- SELinux-enforcing Linux: record labels, ownership, modes and timestamps before and after normal
  exit and forced cleanup.
  - If podman changes host metadata, or requires disabling container labels, refuse the option on
    that host.
  - Do not weaken SELinux separation for a cache optimization.
- Windows/WSL2: translate or pass the source through the same tested path mechanism as existing
  podman bind mounts. Then run the probe against `%LOCALAPPDATA%\Coursier\Cache\v1` on NTFS through
  `/mnt/<drive>`. Do not claim Windows support until the probe passes.
- Other remote podman connections: the source is a server path, not necessarily a client path.
  - Refuse automatic discovery unless the launcher can prove that the discovered client directory
    is the directory podman will mount.
  - A later version may support an explicit server-visible directory, under a separately stated
    contract.

## Security model

The lower cache is readable executable input, shared across workspaces. When the egress profile
permits a destination, the sandbox can inspect and exfiltrate private artifacts, repository URLs,
metadata and any file stored in the cache by accident. State this risk at the option and in
`SECURITY.md`.

The sandbox cannot poison the lower layer through the cache mount: every write to the cache path
enters the sandbox's private upper layer. Keep this claim with a host-observed suite under
`sbt testWithPodman`, not only with an argument test.

The host can change the lower layer while a session runs. `:O` is not a snapshot, and podman warns
against changing the lower layer. The accepted behavior:

- redundant downloads and inconsistent cache misses are acceptable;
- a concurrent host change can make the current Coursier command fail and need a retry;
- no consistency or offline guarantee is made;
- a host change may or may not become visible at a sandbox path the sandbox has not touched;
- sandbox locks in the upper layer do not coordinate with host Coursier locks.

`plan-staged.md` rejects kernel OverlayFS over a mutable lower tree, because staged workspace
contents must stay coherent and apply correctly. This cache overlay decides a narrower case: its
data is disposable and can be rebuilt, so a transient miss, a failed command and a retry are
acceptable. This plan does not change the workspace decision.

## Implementation sites

### `src/main/scala/AgentSandboxLauncher.scala`

- Keep platform discovery and path validation pure, so that unit tests on one host cover every OS
  branch.
- Update the file's boundary diagram, the authoritative one, and its statement about the home
  volume.

If testing the complete set of mounts requires extracting the builder of the sandbox create
command, extract it once and make every launch use it. Do not leave a tested cache helper beside an
inline command that can omit or reorder the overlay.

### Tests

`src/test/scala/AgentSandboxLauncherTest.scala`:

- parse the disabled, auto-discovered and explicit-directory modes;
- prove that the option repeats, through a parser helper given two fixture kinds;
- reject duplicate and unknown kinds, empty values, relative paths and separated-value spellings;
- prove first-non-option and `--` forwarding;
- prove that every management action rejects the launch-only option;
- test `COURSIER_CACHE` precedence and default `v1` discovery for Linux, macOS and Windows, without
  depending on the test host;
- test canonical path overlap against the workspace root, the launcher state and install
  directories, podman storage, filesystem roots, home and the macOS aliases;
- test that an explicit cache outside home is accepted when it overlaps no protected root;
- assert that the complete create command has one anonymous home, one persistent volume, and
  exactly the selected cache overlays in the order the registry defines;
- assert that a custom sandbox image does not change how the host mount behaves.

`src/test/scala/SessionBoundaryTest.scala`:

- default session: the Coursier cache is writable session storage, and no host cache mount exists;
- overlay session:
  - the copied `.cache/coursier` parent keeps UID/GID 65532;
  - the `v1` target exists and is writable;
  - newly created sibling `arc` and `jvm` paths are writable session storage;
  - unrelated host-home paths stay absent;
- update the complete mount allowlist deliberately, rather than allowing every new host mount under
  `/home/nonroot` by its prefix alone.

Add a container-launching suite under `sbt testWithPodman`. The suite uses a temporary host `v1`
directory, never the developer's real cache:

1. Put a readable lower marker and an immutable fixture artifact in the directory.
2. Launch with the explicit option and prove both are visible.
3. Create, replace, rename and delete paths through the cache target.
4. Stop normally and prove that every host file and claimed metadata value is unchanged.
5. Repeat with forced container removal and with the reaper-loss/reset lifecycle.
6. Launch two sessions over the same lower layer. Prove that each session's upper markers are
   invisible to the other session and absent from the host.
7. Launch without the option. Prove that the fixture is invisible and that a write to the session
   cache disappears with the anonymous home.

Add image and toolchain checks:

- the advertised Coursier-installed commands resolve from `/opt/coursier/bin` with a fresh home;
- a runtime `cs install` writes under `~/.local/share/coursier/bin` and wins `PATH` precedence;
- an ordinary `cs update` does not modify `/opt/coursier/bin`, and explicitly selecting that
  directory fails without changing the image launchers;
- on the default cold cache, the advertised Scala programs launch when egress allows the hosts they
  need;
- the allowlist, size limit and inode limit of image home hold;
- the nonroot-owned `.cache/coursier` directory is empty, and no Coursier cache content or
  installed launcher remains under image home;
- a newly created persistent volume still receives every agent seed, and each home link works.

Run the exact final mount topology on macOS, native Linux and Windows/WSL2. Record create, start
and total times separately, for three warm-machine runs in each mode. Performance acceptance rests
on removing the copy-up regression, not on a brittle CI wall-clock threshold:

- image `/home/nonroot` stays below the chosen size and inode limits;
- sandbox start time does not scale with the byte or inode count of the host cache;
- overlay startup stays in the same order of magnitude as the measured empty-volume baseline;
- no timing attributed to an interactive command's lifetime includes `podman create`.

### Documentation

Update each claim in the place that records it:

| claim | recorded in | depends on it |
| --- | --- | --- |
| option syntax, defaults and exact `v1` meaning | README Reference/`--help` | parser tests |
| complete host-readable boundary | launcher diagram | README diagram, `SECURITY.md` |
| private artifacts and mutable-lower risk | `SECURITY.md` | README option warning |
| installed programs and session cache behavior | `AGENTS-SANDBOX.md` | Containerfile tests |
| mount and cleanup mechanism | launcher source | `testWithPodman` lifecycle suites |
| platform qualification | README option text | platform verification record |

The README's opening list states its claims as defaults.

- The list's claim that the programs reach no host files outside the workspace must name the opt-in
  cache exception.
- The README diagram must show a one-way optional host-cache lower layer and a disposable per-run
  upper layer.
- Do not repeat the full threat analysis in the README; point to `SECURITY.md`.

At the existing `cs install PROGRAM` instruction, `AGENTS-SANDBOX.md` should tell an acting agent
these facts:

- session installs and an ordinary `cs update` use `~/.local/share/coursier/bin`;
- the image-managed launchers under `/opt/coursier/bin` change only when the image is rebuilt;
- a missing Scala artifact is downloaded into disposable session state, and a narrow egress profile
  can prevent the download.

`AGENTS-SANDBOX.md` does not need to teach how podman implements overlay mounts.

## Acceptance checklist

- [ ] A default launch reads no host Coursier path and starts with a small home copy-up.
- [ ] The auto-discovered and explicit-directory Coursier modes mount exactly one `v1` directory.
- [ ] The copied `.cache/coursier` parent stays nonroot-owned and accepts session-local siblings.
- [ ] Help says what the default without a cache overlay costs: repeated downloads, and failure
  when the egress rules block a repository.
- [ ] The installed Scala launchers stay available with an empty session cache.
- [ ] Overlay writes, including rename and deletion, leave the host cache and its metadata
  unchanged.
- [ ] Normal exit, Ctrl-C, forced removal and reset leave no upper layer and no new named volume.
- [ ] Concurrent sessions share only the readable lower layer, and never each other's upper layer.
- [ ] Overlap with the workspace, launcher state or podman storage is refused before any resource
  is created; a safe explicit cache outside home is accepted.
- [ ] On SELinux, the option either keeps host metadata without weakening labels or refuses
  clearly.
- [ ] The macOS, native Linux and Windows claims match completed platform probes.
- [ ] The persistent volume is seeded correctly after reset, and every agent state path works.
- [ ] Help, README, the security model, the sandbox instructions and the launcher boundary diagram
  agree.
- [ ] `sbt testFull` and `sbt testWithPodman` pass.
- [ ] Startup measurements show that image-home copy-up is not the dominant delay.

## Deliberate exclusions

- No automatic overlay: private host artifacts stay unexposed without a launch option.
- No persistent sandbox upper layer: the sandbox gets no write access to executable cache state
  that later sessions read.
- No host-cache mutation, synchronization, eviction or repair.
- No automatic sharing of `.sbt`, `.ivy2`, Maven, Gradle or other caches.
- No mount syntax for an arbitrary host source and container destination. Each cache kind fixes its
  target, and gets its own boundary analysis before it enters the production registry.

## References

- [podman volume semantics](https://docs.podman.io/en/latest/markdown/podman-create.1.html)
- [podman machine](https://docs.podman.io/en/latest/markdown/podman-machine-init.1.html)
- [Coursier cache locations and overrides](https://get-coursier.io/docs/cache)
- [Coursier setup options](https://get-coursier.io/docs/cli-setup)
- [Coursier install-directory behavior](https://get-coursier.io/docs/cli-install)
