# Native sbt / Mill Build Sandbox — Implementation Plan

**Target platforms:** macOS 26.4+, Linux, Windows  
**Build tools:** sbt, Mill  
**Primary goal:** Run Scala builds natively while granting only the filesystem and network access required for the build.

---

## 1. Scope

Implement a small native build-sandbox layer with a common policy and platform-specific enforcement:

| Platform | Filesystem / process mechanism | Network containment |
|---|---|---|
| macOS 26.4+ | Seatbelt via `sandbox-exec` | Seatbelt permits only the egress proxy |
| Linux | bubblewrap (`bwrap`) | isolated network namespace; proxy is the only egress path |
| Windows | AppContainer — prototype first | AppContainer/WFP or equivalent permits only the egress proxy |

The sandbox is intentionally narrower than a general AI-agent sandbox. It supports only sbt and Mill builds under documented prerequisites.

Out of scope initially:

- arbitrary build tools;
- arbitrary globally installed JVMs;
- Homebrew/SDKMAN/asdf JVMs;
- direct Internet access from the build;
- automatic expansion of permissions when a build fails;
- implicit access to `~/.m2`, `~/.ivy2`, user Git credentials, SSH credentials, or unrelated home-directory state.

---

## 2. Common security contract

The platform implementations should expose the same effective policy.

### 2.1 Filesystem

```text
PROJECT/**                         read-write

Coursier cache root/**             read-only
Coursier cache root/v1/**          read-write

~/.sbt/boot/**                     read-only          # sbt only

Coursier-installed sbt launcher    read/execute       # sbt only

session temporary directory        read-write         # fresh per session

everything else user-owned         inaccessible
```

Every backend is deny-by-default: nothing outside this table is visible to the build. A runtime path a toolchain requires — the loader, libc, the CA bundle — is added narrowly, read-only, and only where testing proves the read is stable. That is runtime authority, and it is never a way to reach a user path.

`$HOME` resolves to an empty read-only directory with the entries above mounted into it: a build cannot create `$HOME/.netrc`, a Coursier mirror file, or any other configuration a later step in the same session would read.

The temporary directory is the only unnamed writable space, and it is session-scoped: it starts empty, no session ever sees another's, and nothing may rely on it persisting. What holds is that no build reads temporary state left by another, which is not the same as an orderly exit always happening: a killed build can leave a directory on disk, and the next start reclaims it rather than reuses it (§4).

The Coursier-managed JVM is inside the Coursier cache hierarchy and is therefore covered by the read-only Coursier rule.

### 2.2 Network

```text
direct network                     denied
egress proxy                       allowed

egress proxy policy:
    explicitly allowed Maven repositories   allowed
    everything else                         denied
```

Initial repository allowlist:

```text
repo.maven.apache.org:443
```

Additional repositories must be explicitly configured. Do not infer or silently permit them.

### 2.3 Failure policy

Missing prerequisites or denied accesses should fail clearly rather than expanding authority automatically.

Examples:

```text
Coursier JVM missing               -> fail before entering sandbox
sbt not installed by cs            -> fail before entering sandbox
sbt bootstrap artifacts missing    -> build fails; report ~/.sbt/boot is read-only
Mill bootstrap absent              -> fail before entering sandbox
repository not allowlisted         -> proxy denial; report requested host
filesystem path not allowed        -> sandbox denial; report path when observable
```

---

## 3. Tool prerequisites

### 3.1 JVM

Only Coursier-managed JVMs are supported.

Validate the resolved JVM before entering the sandbox.

Expected managed JVM roots:

```text
macOS:   ~/Library/Caches/Coursier/jvm/
Linux:   ~/.cache/coursier/jvm/
Windows: %LOCALAPPDATA%\Coursier\Cache\jvm\
```

The wrapper should resolve symlinks/canonical paths and reject a JVM outside the configured Coursier JVM root.

Do not support:

```text
/Library/Java/JavaVirtualMachines/**
/opt/homebrew/**
SDKMAN JVMs
system-wide Windows JVM installations
other arbitrary JAVA_HOME locations
```

### 3.2 sbt

Require:

```text
cs install sbt
```

The wrapper must resolve the `sbt` launcher and verify that it belongs to the configured Coursier application-install directory.

Do not accept an arbitrary `sbt` from `PATH`.

`~/.sbt/boot` is read-only. The sandbox does not provision missing sbt/Scala bootstrap state.

Prefer disabling sbt server state outside the project:

```text
-Dsbt.server.autostart=false
```

If a global sbt base is needed, redirect it into the project:

```text
-Dsbt.global.base=<PROJECT>/.sandbox/sbt-global
```

Do not grant `~/.sbt/1.0`, `~/.sbt/2.0`, `~/.ivy2`, or `~/.m2` by default.

### 3.3 Mill

Require a project-local bootstrap script:

```text
<PROJECT>/mill
<PROJECT>/mill.bat
```

At least the platform-appropriate bootstrap script must exist. Repositories should normally commit both.

Do not support a globally installed Mill.

---

## 4. Common wrapper design

Implement one front-end command, for example:

```text
ko-agent-build-sandbox sbt [args...]
ko-agent-build-sandbox mill [args...]
```

or integrate the functionality into the existing `ko-agent-sandbox` CLI.

The wrapper performs these steps:

```text
 1. canonicalize project root
 2. detect requested build tool
 3. locate Coursier cache roots
 4. validate Coursier-managed JVM
 5. validate build-tool prerequisite
 6. create the session temporary directory, empty
 7. construct platform policy
 8. configure proxy environment / JVM proxy properties
 9. launch build under platform sandbox
10. remove the session temporary directory
11. preserve child exit code
12. provide actionable diagnostics for known denials
```

Step 6 creates a fresh, uniquely named directory under a wrapper-owned root and never adopts an existing one; step 10 removes it on every exit the wrapper survives to see, error and handled signal included. `SIGKILL`, a crashed wrapper and a lost machine defeat any handler, so a start also scavenges the root. Each session owns a directory there, holds its lock for the life of the build, and grants the build a writable child of it and nothing more:

```text
<wrapper root>/<session>/lock     wrapper-owned; named in no backend's policy
<wrapper root>/<session>/tmp      SESSION_TMP; the only part the build can write
```

The lock has to sit outside the build's authority. A lock inside `SESSION_TMP` is one the build can unlink and replace — deliberately, or by clearing its own temporary directory — leaving the wrapper holding a lock on an inode with no name; the next start would then lock the replacement, read a live session as stale, and delete a running build's working directory.

A session directory whose lock is free belongs to no live session and is removed whole. Liveness, not age — concurrent builds are ordinary, and a slow build must not have its temporary state collected out from under it.

That test is only sound if a directory reaches the scanned namespace already locked, so a session is published rather than built in place: the wrapper creates its directory in a staging area the scan does not visit, takes the lock there, and renames it into the root. A rename keeps the inode, and with it the lock, so no scanned entry is ever one whose session is still starting. Staging and root share a filesystem, which is what makes the rename atomic. On Windows the equivalents are a handle opened without `FILE_SHARE_DELETE` and a move within one volume.

A wrapper killed between creating its staging directory and renaming it leaves an entry there, so the scavenger clears staging too — and that is what a root lock is for: publication holds it from creating the staging directory through taking the lock to the rename, and staging cleanup holds it to remove what a kill left. A scavenger free to delete a directory whose creator has not locked it yet does not collect litter; it fails an ordinary start, whose rename then has nothing to move.

Nothing expensive runs inside that lock. A staging entry is a directory no build has written to, and the removal of published directories — where the bytes are — needs no root lock at all, since every published directory is locked by construction.

Where the platform already guarantees the property, both steps are no-ops: a Linux tmpfs is discarded with the mount namespace, whatever kills the process.

A JVM writes a preference store under `$HOME` on first use. Point that store and `java.io.tmpdir` at the session temporary directory (`-Djava.util.prefs.userRoot`, `-Djava.io.tmpdir`), so a read-only home costs no diagnostics.

All paths passed to the sandbox backend must be canonicalized before policy construction.

Reject paths that cannot be canonicalized.

---

## 5. Coursier cache policy

Coursier's normal artifact cache is `v1`.

Platform defaults:

```text
macOS:
  root = ~/Library/Caches/Coursier
  v1   = ~/Library/Caches/Coursier/v1

Linux:
  root = ~/.cache/coursier
  v1   = ~/.cache/coursier/v1

Windows:
  root = %LOCALAPPDATA%\Coursier\Cache
  v1   = %LOCALAPPDATA%\Coursier\Cache\v1
```

Permissions:

```text
root/**       RO
v1/**         RW
```

Rationale:

- managed JVMs and other provisioned Coursier state may be consumed;
- builds may download/update ordinary dependency artifacts in `v1`;
- builds may not modify managed JVMs or other Coursier state.

Do not grant broader write access unless a concrete supported build operation proves it necessary.

---

# 6. macOS implementation

## 6.1 Backend

Use:

```text
sandbox-exec
```

with one parameterized Seatbelt profile shared by sbt and Mill.

The wrapper supplies parameters such as:

```text
PROJECT
COURSIER_ROOT
COURSIER_V1
TOOL
SBT_BOOT
SESSION_TMP
PROXY endpoint
```

For Mill, `TOOL` points inside `PROJECT`.

For sbt, `TOOL` points to the Coursier-installed sbt launcher.

For Mill, the sbt-specific boot path can be omitted if separate conditional profile generation is easier than supplying a dummy path.

## 6.2 Filesystem policy

Each §2.1 row as the profile parameter that carries it:

```text
PROJECT                           RW
COURSIER_ROOT                     RO
COURSIER_V1                       RW
SBT_BOOT                          RO     # sbt
TOOL                              RX
SESSION_TMP                       RW
```

Seatbelt has no mount namespace to build a home out of, so the profile denies `$HOME` itself and permits only the paths above. `SESSION_TMP` is the writable child of the wrapper's per-session directory (§4), not the user's `TMPDIR`, and the session directory holding the lock is named in no rule.

Do not pre-authorize broad paths such as:

```text
/System/**
/usr/**
/opt/homebrew/**
```

unless testing proves a specific stable runtime read is required.

If a macOS/JVM runtime path is required, add the narrowest stable read-only rule justified by testing.

## 6.3 Network

Do not let the build make arbitrary outbound connections.

Seatbelt should permit connections only to the local/native egress-proxy ingress endpoint.

The JVM/Coursier configuration should also point at the proxy, but proxy settings are not the security boundary: Seatbelt must prevent bypass via direct sockets.

Configure JVM proxy properties as appropriate, e.g.:

```text
-Dhttps.proxyHost=...
-Dhttps.proxyPort=...
-Dhttp.proxyHost=...
-Dhttp.proxyPort=...
```

If the proxy is available through a local Unix socket rather than TCP, prefer that if it produces a cleaner Seatbelt rule and the bridge can be kept outside the sandbox.

## 6.4 macOS test gate

Before declaring the backend complete, verify at least:

```text
java -version
sbt --version
sbt compile
sbt test
./mill --version
./mill __.compile
./mill __.test
```

Negative tests:

```text
read ~/Documents/...                         denied
read ~/.ssh/...                              denied
write Coursier/jvm/...                       denied
write ~/.sbt/boot/...                        denied
write the Coursier-installed sbt launcher    denied
write Coursier/v1/...                        allowed
write PROJECT/...                            allowed
write session temporary directory            allowed
connect directly to arbitrary Internet host  denied
fetch allowed Maven artifact via proxy        allowed
fetch non-allowlisted host via proxy           denied
```

---

# 7. Linux implementation

## 7.1 Backend

Use `bubblewrap` rather than Landlock.

Filesystem mappings should use read-only/read-write bind mounts, built up from an empty tree rather than pared down from the host's: bubblewrap starts with nothing mounted, which is how §2.1 holds here by construction rather than by enumeration of what to hide.

`$HOME` gets an empty tmpfs of its own — sbt, Coursier and the JVM all resolve it — remounted read-only once the named paths are in place, so it holds those paths and nothing the build can add.

Mount ordering carries the authority: the `v1` writable bind sits over the read-only Coursier parent, and the Coursier tree, `~/.sbt/boot` and the project all sit over the `$HOME` tmpfs. `--remount-ro` comes last of all — bubblewrap creates a bind's mountpoint as it goes, and a read-only tmpfs has nowhere to create one; remounting the parent afterwards leaves the writable children writable.

## 7.2 Example mount concept

Conceptually:

```text
--unshare-all --die-with-parent
--proc /proc --dev /dev
--ro-bind /usr /usr                      # with the distro's /bin, /lib, /lib64 symlinks
--ro-bind /etc/ssl /etc/ssl              # the proxy's CA

--tmpfs   /tmp                           # the session temporary directory
--tmpfs   $HOME
--ro-bind COURSIER_ROOT COURSIER_ROOT
--bind    COURSIER_V1   COURSIER_V1
--ro-bind SBT_BOOT      SBT_BOOT
--bind    PROJECT       PROJECT
--remount-ro $HOME
```

The first block is runtime authority — a JVM does not start without the loader and libc — and distributions differ in it. The second is §2.1, path for path.

## 7.3 Network

`--unshare-all` above includes the network namespace, so the build has no direct host or Internet path.

Expose only the egress proxy through an explicit bridge.

Preferred architecture:

```text
sandbox network namespace
        |
        | Unix-domain socket mounted into sandbox
        v
host-side bridge / proxy ingress
        |
        v
ko-agent egress proxy
```

If a bridge such as `socat` is used, it runs outside the sandbox's isolated network namespace.

The build should have no route that permits it to bypass the proxy.

## 7.4 Linux test gate

Run the same positive and negative tests as macOS.

Additionally verify:

```text
raw TCP connection to public IP             impossible
DNS query outside proxy path                impossible/unnecessary
Unix socket to approved proxy bridge        works
```

Test on at least:

```text
Debian 13
```

Add other supported distros only after their required runtime mount differences are understood.

---

# 8. Windows implementation

## 8.1 Status

Treat AppContainer as a **feasibility-gated backend**, not yet as a committed final architecture.

The narrow sbt/Mill workload is a better fit for AppContainer than a general-purpose coding agent, but actual Java/sbt/Mill compatibility must be demonstrated.

## 8.2 Prototype

Create a per-user AppContainer profile, e.g.:

```text
KoAgentScalaBuild
```

Obtain/derive its AppContainer SID.

Grant inheritable ACL entries to that SID:

```text
PROJECT                            Modify / RX as required
Coursier root                      Read + Execute
Coursier\v1                        Modify
~\.sbt\boot                        Read + Execute
Coursier-installed sbt launcher    Read + Execute
session temporary directory        Modify
```

Do not recursively rewrite every child ACL if a directory-root inheritable ACE is sufficient.

Track exactly which ACL entries the tool adds so they can be removed deterministically.

## 8.3 AppContainer profile storage

Windows automatically gives an AppContainer its own profile storage and redirects `TEMP`/`TMP` into accessible AppContainer storage.

Neither that storage nor a project-local `PROJECT\.sandbox\tmp` can hold §4's lock, and for the same reason: the build writes both — the AppContainer storage is its own, and it holds Modify on all of `PROJECT`. A lock in either is a lock the build can replace.

So the session directory sits in the wrapper-owned per-user root, as on macOS, and `TEMP`/`TMP` are redirected to its writable child (§8.2's `session temporary directory` entry). Neither the AppContainer's own storage nor the project tree then carries temporary state a later session would have to reason about.

## 8.4 Network

Do not simply grant broad Internet capability and rely on Java proxy configuration.

The Windows backend needs an enforceable path where the AppContainer can reach the egress proxy but cannot reach arbitrary destinations directly.

Prototype candidates:

1. AppContainer capability + Windows Filtering Platform / firewall rule restricted to proxy endpoint.
2. Loopback/proxy endpoint with explicit AppContainer exemption plus WFP restriction.
3. A local IPC bridge to a host-side proxy endpoint if that provides stronger confinement.

Choose only after testing actual Windows AppContainer networking behavior.

## 8.5 Windows feasibility gate

The backend passes only if all of these work without granting broad user-data access:

```text
Coursier-managed java -version
cs-installed sbt --version
sbt compile
sbt test
project-local mill.bat --version
mill.bat __.compile
mill.bat __.test
dependency download through egress proxy
forked JVM/test process
```

And all negative tests pass:

```text
unrelated user files                   inaccessible
~\.ssh                                 inaccessible
Coursier JVM state                     not writable
sbt boot                               not writable
sbt launcher                           not writable
Coursier\v1                            writable
project                                writable
session temporary directory            writable
direct Internet connection             denied
non-allowlisted proxy destination      denied
```

### Decision point

If AppContainer requires broad capabilities or compatibility exceptions that materially weaken the common policy, stop and evaluate:

```text
restricted token + dedicated SID + ACLs + WFP
```

Do not silently broaden AppContainer privileges just to make the prototype pass.

---

# 9. Egress-proxy integration

Reuse the existing ko-agent egress proxy as the single destination-policy authority.

## 9.1 Build-specific allowlist

Start with:

```text
repo.maven.apache.org:443
```

Allow additional repositories only through explicit configuration.

Examples that may be needed by some projects, but are **not enabled by default**:

```text
repo.scala-sbt.org
repo1.maven.org
corporate Maven repository
GitHub release/download endpoints
JitPack
Sonatype snapshot repositories
```

## 9.2 Policy semantics

The proxy should log denied destination requests with enough information for the wrapper to produce:

```text
Build requested network access to:
  repo.example.org:443

This host is not permitted by the Scala build sandbox.
```

Do not automatically add it.

## 9.3 HTTPS

Prefer ordinary HTTP CONNECT tunneling where possible.

The proxy should enforce destination host/port at CONNECT time.

If the existing proxy performs TLS interception, keep trust-store handling explicit and separate from filesystem sandboxing.

The filesystem policy must not require granting access to arbitrary host certificate stores if the Coursier-managed JDK's configured trust store suffices.

---

# 10. Diagnostics

Good denial diagnostics are part of the product.

Define stable error categories:

```text
PREREQ_JVM_NOT_COURSIER
PREREQ_SBT_NOT_COURSIER
PREREQ_MILL_BOOTSTRAP_MISSING
PREREQ_SBT_BOOT_MISSING

FS_READ_DENIED
FS_WRITE_DENIED

NET_DIRECT_DENIED
NET_PROXY_HOST_DENIED

BACKEND_UNAVAILABLE
BACKEND_SETUP_FAILED
```

Where the underlying platform exposes sufficient information, include the denied path/endpoint.

Do not turn a denial into an automatic retry with broader permissions.

---

# 11. Configuration

Use one platform-independent logical configuration.

Example:

```toml
[build-sandbox]
enabled = true

[build-sandbox.repositories]
allowed = [
  "repo.maven.apache.org:443"
]
```

Avoid exposing platform-specific filesystem paths unless an override is genuinely necessary.

Derived platform defaults should come from Coursier conventions and environment APIs.

Possible advanced overrides:

```toml
[build-sandbox.coursier]
cache-root = "..."
jvm-root = "..."
install-root = "..."
```

Do not add these until needed.

---

# 12. Implementation phases

## Phase 1 — Common policy and prerequisite validator

Implement:

- project canonicalization;
- Coursier root discovery;
- Coursier-managed JVM validation;
- sbt launcher validation;
- Mill bootstrap validation;
- common policy model;
- structured diagnostics.

No sandbox backend yet.

**Exit criterion:** unit tests prove that supported and unsupported layouts are classified correctly.

---

## Phase 2 — macOS backend

Implement Seatbelt profile generation / parameterization and proxy-only network rules.

Test on macOS 26.4+.

**Exit criterion:** complete positive/negative filesystem and network matrix passes.

This should be the first production backend because the macOS design is already well understood.

---

## Phase 3 — Linux backend

Implement bubblewrap filesystem mapping and isolated-network proxy bridge.

Target Debian 13 first.

**Exit criterion:** same common test matrix passes without platform-specific weakening of the policy.

---

## Phase 4 — Windows AppContainer prototype

Implement:

- profile creation/lookup;
- SID derivation;
- ACL setup/removal;
- AppContainer process launch;
- child-process tests;
- proxy-only network experiment.

**Exit criterion:** feasibility report plus automated test results.

Do not call Windows production-ready at the end of this phase.

---

## Phase 5 — Windows backend decision

If AppContainer passes cleanly:

```text
promote AppContainer backend
```

Otherwise:

```text
prototype restricted-token + SID/ACL + WFP backend
```

Compare only against the same common security contract.

---

## Phase 6 — Hardening

Add:

- denial telemetry;
- cleanup/recovery after interrupted Windows ACL setup;
- symlink/junction/reparse-point tests;
- path race tests;
- proxy bypass tests;
- forked-process tests;
- snapshot dependency tests;
- malicious `build.sbt` / `build.mill` fixtures;
- CI coverage for each backend.

---

# 13. Security-focused test suite

Maintain a deliberately hostile sample Scala project.

Its build definition should attempt:

### Filesystem reads

```text
$HOME/.ssh/*
$HOME/.aws/*
$HOME/.gitconfig
arbitrary sibling repository
```

Expected: denied.

### Filesystem writes

```text
Coursier/jvm/*
~/.sbt/boot/*
Coursier-installed sbt launcher
arbitrary $HOME path
```

Expected: denied.

### Allowed writes

```text
PROJECT/*
Coursier/v1/*
session temporary directory/*
```

Expected: allowed.

### Process inheritance

Have sbt/Mill launch:

```text
forked JVM
shell command
test process
```

Verify children retain containment.

### Network bypass

Attempt:

```text
raw TCP to public IP
HTTPS request ignoring proxy variables
DNS/direct socket access
allowed Maven request through proxy
denied host through proxy
```

Expected:

```text
direct paths                denied
allowed proxy request       succeeds
denied proxy request        proxy-denied
```

---

# 14. Symlink / path-escape requirements

Do not rely only on textual path prefixes.

Before passing important roots to a backend:

- canonicalize the project root;
- canonicalize Coursier roots;
- canonicalize tool/JVM locations;
- reject unexpected ancestor relationships.

Tests must cover symlinks from inside the project to:

```text
$HOME
/
Coursier read-only state
another repository
```

The expected behavior is that a symlink must not provide authority beyond the sandbox's underlying filesystem policy.

On Windows, add equivalent junction/reparse-point tests.

---

# 15. Definition of done

A platform backend is complete only when:

1. sbt and Mill compile/test normal Scala projects.
2. Missing dependencies can be downloaded into Coursier `v1`.
3. The build cannot modify Coursier-managed JVMs.
4. The build cannot modify `~/.sbt/boot`.
5. The build cannot access unrelated user data.
6. Child processes inherit containment.
7. Direct network access is impossible.
8. The only egress path is the ko-agent egress proxy.
9. The proxy can restrict Maven destination hosts.
10. Denials fail closed and produce useful diagnostics.
11. No backend broadens permissions automatically after failure.
12. The common security contract is identical across platforms except for documented platform necessities.

---

# 16. Open questions to resolve during implementation

### macOS

- Exact minimum non-user-data Seatbelt runtime allowances required by the selected Coursier JVM on macOS 26.4+.
- Best local proxy transport: TCP loopback vs Unix socket/bridge.

### Linux

- Exact minimal `/proc`, `/dev`, and other runtime mounts needed for JVM/sbt/Mill under bubblewrap.
- Preferred Unix-socket proxy bridge implementation.

### Windows

- Whether current Coursier JVM + sbt + Mill operate cleanly in a normal AppContainer.
- Exact AppContainer network/WFP configuration required to make the proxy the sole egress path.
- Whether inheritable root ACL entries are sufficient for all supported project/cache layouts without recursive ACL churn.

These are implementation experiments, not reasons to broaden the common policy in advance.

---

# 17. Source references

These references support the implementation assumptions used above:

- Coursier managed JVMs and platform JVM-cache locations:  
  https://get-coursier.io/docs/cli-java
- Coursier artifact cache and platform `v1` locations:  
  https://get-coursier.io/upcoming/features-cache/
- Coursier installation/application directory behavior:  
  https://get-coursier.io/docs/cli-installation
- Mill project-local bootstrap scripts (`mill` / `mill.bat`) and recommendation:  
  https://mill-build.org/mill/cli/installation-ide.html
- bubblewrap bind mounts and `--ro-bind`:  
  https://manpages.debian.org/unstable/bubblewrap/bwrap.1.en.html
- Microsoft AppContainer launch/profile model:  
  https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer
- Microsoft `CreateAppContainerProfile`:  
  https://learn.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-createappcontainerprofile

---

## Recommended implementation order

```text
common validator/model
        ↓
macOS Seatbelt
        ↓
Linux bubblewrap
        ↓
Windows AppContainer feasibility prototype
        ↓
Windows backend decision
        ↓
cross-platform hardening
```

The principal design constraint is **fail closed rather than generalize**: support only the paths, repositories, JVM installation method, and build-tool installation method explicitly included in this contract.
