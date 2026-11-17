# Plan: overlap the launch's steps with the start prompt

A launch runs its independent steps beside each other:

- the image inspects and the backends' checks beside `podman info` (`BesideInfo`);
- the BPF backend's reconcile beside the networks, the run's files and the proxy;
- the two network creates beside each other and the run's files (`ResourceSteps`);
- the listing of live sessions beside the launch script (`createUnderLaunchLock`).

The steps left on either side of the start prompt could also overlap the reader's time at the
prompt. This plan sets out the two ways to do that, A and B, against taking neither.
- The user decides after `plan-coursier.md` is implemented, from launches measured with it
  ("Recommendation").
- Both ways change recorded behavior, so each section below lists what the way gains and costs.

## Baseline

Two Windows launches under `bpf`, with the image's caches warm, measured these times
(`launch.log`): one with its steps in sequence (2026-11-16), one with the overlaps above
(2026-11-17).

| part | in sequence, ms | overlapped, ms |
| --- | ---: | ---: |
| before the prompt | 8,758 | 5,083 |
| the reader's time at the prompt | 14,310 | 4,054 |
| after the prompt | 12,590 | 8,460 |
| of which the wait for `podman init` | 9,972 | 5,978 |

- With the overlaps, this path is left before the prompt: the settings, `podman info`, the rules,
  the run's files and the proxy.
- Most of `podman init` is podman copying the image's home into the session's volume, 3.0 to 9.6s
  on Windows. `plan-coursier.md` removes that copy, and is deferred.
- Either decision below gains only while the reader stays at the prompt. A reader who presses Enter
  at once gains nothing; the two launches' readers took 14s and 4s.
- Under `--session-start=immediate`, nobody waits at a prompt, and neither decision gains anything.

## Decision A: show the prompt before the proxy is ready

The launch would print its launch lines and the start prompt once the rules and the backend's probe
are settled. The reconcile, the networks, the run's files and the proxy would continue in the
background, and the launch would join them after Enter, before the create.

What it gains:

- The prompt would appear about 2.8s sooner: the overlapped launch's time from the Git layout to
  the proxy's ready line.
- A reader who stays at least that long at the prompt would start the agent that much sooner.

What makes it possible:

- `printLaunchLines` needs the rules, the Git layout and the mount, not the proxy, so the launch
  lines can still come before the prompt.
- The prompt is not consent for the proxy or the networks: they exist before the prompt today.

What it costs:

- A refusal from the run's files, the networks or the proxy would come after Enter. The reader
  agreed to start a launch that then refuses, and launches again after the fix.
- A note that comes after Enter, such as the reconcile's or the container listing's, is cleared by
  the agent's TUI. The README says that `pause` holds a launch's startup lines on screen. The launch
  would print the notes that are ready before the prompt, and write the rest to `launch.log`.
- `prepareRunFiles` would run in the background. Its refusals would become values that the launch
  reports after Enter, since `inBackground` forbids `fail` in a step.
- A Ctrl-C at the prompt would interrupt the proxy's create or start. The proxy's steps would join
  the set that the cleanup waits for (`ResourceSteps`).

## Decision B: create the container while the prompt waits

The launch would run the launch script, the listing, `podman create`, `podman init` and the
placement check in the background before the prompt. After Enter, it would spawn the reaper, start
the relays, mount the FUSE backend, spawn the runner and start the container.

What it gains:

- Up to the 8.5 to 12.6s after the prompt, as far as the reader's time at the prompt covers it.
- After `plan-coursier.md`, the time after the prompt would shrink to about 3s, and so would this
  gain.

What it costs:

- It reverses the order that `launch()` records: "The hold comes before the container exists."
  The reasons recorded there change:
  - A Ctrl-C at the prompt would remove the container and the backend's session too. The cleanup
    already removes a created container and runs the backend's teardown, but it would also have to
    wait for a launch script in flight.
  - A launcher killed outright at the prompt would leave a created container, its attach cgroup
    and its pins. On Windows, which runs no reaper, they would stay until `--reset`, because the
    reconcile keeps a session that a container names.
- The reaper could not come right after the create, as it does today. Its first wait is bounded, so
  it would remove the container under a reader who stays at the prompt longer than that bound. The
  reaper would come after Enter, and until then only the launcher would remove the container.
- Answering `n` would remove the container. With today's image, that `podman rm -v` takes 3.7 to
  4.7s on Windows, so a decline would take that much longer.
- The create's environment carries the AWS credentials, which the launch checks after the hold
  today because the hold may outlast them. With the create before the hold, credentials that
  expired at the prompt would refuse after Enter, and the reader would launch again.
- A container waiting at a prompt is a live session to every other launch's comparison
  (`KoAgentBpf.refusalBeside`). A launch with a conflicting backend or socket setting would be
  refused while the prompt waits, as it is today while the session runs.
- The BPF policy would be attached, and the session's records written, before the reader agrees.
  Nothing runs under the policy until the start, so no boundary changes.

## Comparison

| | A | B | neither |
| --- | --- | --- | --- |
| largest gain now | about 2.8s | 8.5 to 12.6s | none |
| largest gain after `plan-coursier.md` | about 2.8s | about 3s | none |
| refusals that move after Enter | run files, networks, proxy | expired AWS credentials | none |
| left by a launcher killed at the prompt | nothing new | container, cgroup and pins | nothing new |
| recorded order changed | no | the hold before the container | no |
| code that changes | `prepareRunFiles` | the create path, the reaper, the decline | none |

## Recommendation

1. Implement `plan-coursier.md` first. It shortens `podman init` on every launch, including those
   under `immediate` and those whose reader presses Enter at once. Without the home copy, `init`
   takes 0.36s on Windows ("Evidence and target" there).
2. Measure two warm launches with it, and replace "Baseline" with them.
3. Choose between A and neither. After `plan-coursier.md`, B gains about as much as A, and changes
   far more.
   - The strongest objection to A: it gains at most 2.8s, and a refusal can come after the reader
     agreed. Neither is the choice when that trade is not worth it.
