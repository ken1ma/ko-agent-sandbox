# Plan: a launch announces itself, so nothing waits ten minutes to know it is gone

## The window

A launch writes files before its containers exist: this run's TLS mount copies under
`tls/<project>/run-<suffix>/`, the workspace filter's session marker, and the sandbox container
itself, created and then started only once the proxy is up. Inside that window nothing that
sweeps leftovers can tell a launch in progress from a launch that died, because every sweep asks
podman whether a container names the run, and the container is not there yet. So every sweep
adds an age test, and the age is ten minutes, chosen once and repeated four times:

- `AgentSandboxLauncher.olderThanLaunchBound`, gating `tlsRunDirsToPrune`;
- the reaper's loop in `SandboxLifecycle`, which removes a created-but-never-started container
  after six hundred one-second waits;
- the filter's marker prune in `KoAgentFs`, `find -mmin +10`;
- the launcher's own comments naming "the launch bound" at each of those sites.

The costs: a launch that dies leaves its files for ten minutes, a sweep that meets a launch
older than ten minutes and still in progress — a slow image pull inside the JDK trust-store
preparation, a machine under memory pressure — deletes a live launch's files out from under
its `podman start`, and four places carry one number.

## The replacement

A launch holds a lease from before its first write until its containers exist: an exclusive
file lock (`HostCommands.withFileLock`'s mechanism, held open rather than released) on a file in
the run directory, and for the filter's marker a lock on the marker itself. A lock dies with its
process, so a launcher killed at any point releases it without a cleanup path, and a sweep's
liveness question becomes two: does a container name the run, and failing that, is the run's
lock held. Held means in progress, whatever the age; not held and no container means gone.

`flock` in the mount script's shell and `FileChannel.tryLock` in the launcher take the same
lock, so the marker prune and the launcher's sweep agree on one run. The reaper's loop is the one
site the lock does not reach — it runs after the containers exist — and its wait stays, since it
bounds a different thing: a container created and never started because the launcher died
between the two podman calls.

## Inventory

Every reader of the ten-minute bound, each to be the lock or deliberately kept:

- `olderThanLaunchBound` and `tlsRunDirsToPrune`: the lock;
- the marker prune's `find -mmin +10`: the lock;
- the reaper's six hundred waits: kept, with the reason above written beside it;
- `tlsRunDirsToPrune`'s tests and `KoAgentFsTest`'s marker tests: a held lock keeps a run's
  files at any age; a released one lets them go at once.

## Deliberate exclusions

- A pid file: a pid is reused, and a stale pid file needs the age test this plan removes.
- Shortening the bound instead: the two costs above scale with it in opposite directions.
