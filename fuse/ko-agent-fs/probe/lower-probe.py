#!/usr/bin/env python3
"""The platform-verification probe for what a stage's lower can represent (doc/TODO.md, "What the
staged lower can do, per share"): hardlink identity, atomic rename flags, symlink creation, case
folding between two names, and how far an open-file hold reaches. Each decides a stage
representation choice, and only the backing filesystem and the share answer any of them.

Every row is two-party — the host acts and the session observes, or the reverse — so this half runs
INSIDE a sandbox session and `lower-probe-host.py` runs on the HOST, in the same project directory.
The two rendezvous through files under lower-probe-work/.

Run in a SCRATCH project; it creates and deletes files:

    cp .../lower-probe.py .../lower-probe-host.py <scratch-project>/
    java -jar ko-agent-sandbox.jar bash          # add KO_AGENT_SANDBOX_WORKSPACE_GUARD=none to compare
    python3 lower-probe.py             # here, in the session

    python3 lower-probe-host.py        # in a HOST terminal, same directory

The unfiltered run is the control, and it is what separates this filter's own answer from the
share's: an inode number the filter minted per name looks exactly like a share that invented one.

Results are printed here, the host's observations folded in; the host half needs python3 and nothing
else. The rendezvous travels through the share, so a hang is a coherency failure before it is
anything else, and `coherency-probe.py` is what settles that.
"""

import contextlib
import ctypes
import json
import os
import platform
import shutil
import sys
import tempfile
import time

WORK = "lower-probe-work"
WAIT = 120

AT_FDCWD = -100
RENAME_NOREPLACE = 1 << 0
RENAME_EXCHANGE = 1 << 1

# Findings accumulate here rather than printing as they happen: a two-party probe interleaves its
# two sides, and a reader wants the rows, not the conversation.
rows: list[tuple[str, list[str]]] = []


def record(name: str, *observations: str) -> None:
    """One row, one observation per line under it. A row that says two things — one per direction,
    or one per side — is two lines, because that is how it gets read and copied into the log."""
    rows.append((name, list(observations)))


def stack() -> str:
    """Filtered or not, by the property that separates the filter from the launcher's mount pin:
    `.git` is refused at any depth. `coherency-probe.py`'s copy of this carries the full reasoning;
    each probe is copied into a scratch project on its own, so they do not share a module."""
    probe = tempfile.mkdtemp(prefix=".lower-probe-stack-", dir=".")
    try:
        os.mkdir(os.path.join(probe, ".git"))
    except PermissionError:
        return "filtered"
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    return "raw bind (unfiltered)"


def ask(step: str, **payload) -> dict:
    """One round trip to the host half: publish a request, wait for its answer. The closing step is
    a round trip like the rest, and has to be: this side removes the directory once it returns, and
    a request nobody acknowledged is one the host half would still be waiting for.

    The request is staged and renamed into place, because the host reads it through the share and a
    half-written file there is a parse error rather than a wait."""
    request = os.path.join(WORK, f"req-{step}.json")
    answer = os.path.join(WORK, f"res-{step}.json")
    with open(request + ".partial", "w") as handle:
        json.dump(payload, handle)
    os.replace(request + ".partial", request)
    deadline = time.monotonic() + WAIT
    while time.monotonic() < deadline:
        if os.path.exists(answer):
            with open(answer) as handle:
                return json.load(handle)
        time.sleep(0.05)
    print(f"\nabort: the host half never answered '{step}' within {WAIT}s.")
    print("Is lower-probe-host.py running in a HOST terminal in this same directory?")
    print(f"{WORK}/ is left in place; its request and answer files are what says which side stalled.")
    sys.exit(2)


def renameat2(old: str, new: str, flags: int) -> str:
    """`ok`, or the errno name. Python has no wrapper; glibc grew the symbol in 2.28, and the raw
    syscall covers a libc that has not."""
    libc = ctypes.CDLL(None, use_errno=True)
    old_bytes, new_bytes = old.encode(), new.encode()
    ctypes.set_errno(0)
    if hasattr(libc, "renameat2"):
        result = libc.renameat2(AT_FDCWD, old_bytes, AT_FDCWD, new_bytes, flags)
    else:
        numbers = {"x86_64": 316, "aarch64": 276}
        number = numbers.get(platform.machine())
        if number is None:
            return f"no renameat2 wrapper and no syscall number for {platform.machine()}"
        result = libc.syscall(number, AT_FDCWD, old_bytes, AT_FDCWD, new_bytes, flags)
    if result == 0:
        return "ok"
    return os.strerror(ctypes.get_errno())


def seed(name: str, content: bytes) -> str:
    path = os.path.join(WORK, name)
    with open(path, "wb") as handle:
        handle.write(content)
    return path


# --- the five rows -----------------------------------------------------------------------------


def hardlink_identity() -> None:
    """Both directions: a pair the host made, seen here, and a pair made here, seen there. An
    invented inode per path shows up as two different st_ino for one file."""
    host = ask("hardlink-create")
    if host["created"] != "ok":
        record("hardlink identity", f"host could not create the pair: {host['created']}")
        return
    here = [os.stat(os.path.join(WORK, name)) for name in ("hl-host-a", "hl-host-b")]
    host_to_session = (
        "same inode, nlink 2" if here[0].st_ino == here[1].st_ino and here[0].st_nlink == 2
        else f"st_ino {here[0].st_ino} vs {here[1].st_ino}, nlink {here[0].st_nlink}"
    )

    seed("hl-guest-a", b"guest-side pair\n")
    try:
        os.link(os.path.join(WORK, "hl-guest-a"), os.path.join(WORK, "hl-guest-b"))
    except OSError as ex:
        record(
            "hardlink identity",
            f"host -> session: {host_to_session}",
            f"session -> host: cannot link at all: {ex}",
        )
        return
    there = ask("hardlink-observe")
    session_to_host = (
        "same inode, nlink 2" if there["same_inode"] and there["nlink"] == 2
        else f"st_ino {there['ino_a']} vs {there['ino_b']}, nlink {there['nlink']}"
    )
    record(
        "hardlink identity",
        f"host -> session: {host_to_session}",
        f"session -> host: {session_to_host}",
    )


def rename_flags() -> None:
    """Through the mount, and on the host path apply would replace. The flags are Linux's; a host
    that has no equivalent primitive answers so, which is itself the finding."""
    seed("rn-x", b"x\n")
    seed("rn-y", b"y\n")
    exchange = renameat2(os.path.join(WORK, "rn-x"), os.path.join(WORK, "rn-y"), RENAME_EXCHANGE)
    noreplace_onto_existing = renameat2(
        os.path.join(WORK, "rn-x"), os.path.join(WORK, "rn-y"), RENAME_NOREPLACE
    )
    seed("rn-z", b"z\n")
    noreplace_onto_free = renameat2(
        os.path.join(WORK, "rn-z"), os.path.join(WORK, "rn-free"), RENAME_NOREPLACE
    )
    host = ask("rename-flags")
    record(
        "rename flags",
        f"mount: exchange {exchange}; noreplace onto a taken name {noreplace_onto_existing} "
        f"(a refusal is the pass), onto a free one {noreplace_onto_free}",
        f"host:  exchange {host['exchange']}; noreplace onto a taken name "
        f"{host['noreplace_onto_existing']}",
    )


def symlinks() -> None:
    """Created here and resolved there, and the reverse. Windows makes host creation privileged, so
    a refusal there is a constraint to plan around rather than a failure."""
    seed("sl-target", b"target\n")
    try:
        os.symlink("sl-target", os.path.join(WORK, "sl-guest"))
        created_here = "ok"
    except OSError as ex:
        created_here = str(ex)
    host = ask("symlink", created_here=created_here)

    host_link = os.path.join(WORK, "sl-host")
    if host["created"] != "ok":
        seen_here = f"host could not create one: {host['created']}"
    elif not os.path.islink(host_link):
        seen_here = "sees it, but not as a link"
    else:
        seen_here = f"sees a link to {os.readlink(host_link)!r}"
    record(
        "symlinks",
        f"session creates: {created_here}; the host then sees {host['sees_guest_link']}",
        f"host creates: {host['created']}; the session then {seen_here}",
    )


def case_folding() -> None:
    """Whether two names differing only by case are two entries or one. On a folding lower an upper
    entry and a lower entry cannot differ by case alone, which constrains how whiteouts are named."""
    host = ask("case-create")
    if host["created"] != "ok":
        record("case folding", f"host could not create the probe name: {host['created']}")
        return
    folded = os.path.join(WORK, "case-probe")
    found_by_other_case = os.path.exists(folded)
    try:
        with open(folded, "xb") as handle:
            handle.write(b"lowercase\n")
        coexist = "both names exist independently"
    except FileExistsError:
        coexist = "the second name collides with the first"
    except OSError as ex:
        coexist = f"refused: {ex}"
    record(
        "case folding",
        f"mount: lookup of the other case {'finds' if found_by_other_case else 'misses'} it, "
        f"{coexist}",
        f"host:  {host['verdict']}",
    )


def open_file_hold() -> None:
    """How far a descriptor held here reaches the host's ability to write, rename and unlink that
    path — and whether releasing it restores what was refused. Apply write-back stands on this.

    Each attempt gets its own file, and the released phase gets a third set. A shared target would
    have the unlink attempt destroy what the next phase is about to hold, which is a probe measuring
    its own footprints."""
    outcomes = {}
    for label, flags in (("read", "rb"), ("write", "r+b"), ("released", None)):
        prefix = f"hold-{label}"
        for kind in ("write", "rename", "unlink"):
            seed(f"{prefix}-{kind}", b"held\n")
        with contextlib.ExitStack() as held:
            if flags is not None:
                for kind in ("write", "rename", "unlink"):
                    held.enter_context(open(os.path.join(WORK, f"{prefix}-{kind}"), flags))
            outcomes[label] = ask(prefix, prefix=prefix)
    record(
        "open-file hold",
        *(
            f"{label:<8} host write {result['write']}, rename {result['rename']}, "
            f"unlink {result['unlink']}"
            for label, result in outcomes.items()
        ),
    )


def main() -> int:
    if not os.path.isdir("/workspace"):
        print("abort: no /workspace — run this inside the sandbox, not on the host")
        return 2
    os.chdir("/workspace")
    shutil.rmtree(WORK, ignore_errors=True)
    os.mkdir(WORK)

    print(f"stack under test: {stack()}")
    print(f"session: {platform.system()} {platform.release()} {platform.machine()}")
    print()
    print("READY. In a HOST terminal, in this project directory, run:")
    print("    python3 lower-probe-host.py")
    print(f"waiting up to {WAIT}s per step ...")
    sys.stdout.flush()

    host = ask("hello")
    print(f"host:    {host['system']} {host['release']} {host['machine']}")

    broken = False
    for step in (hardlink_identity, rename_flags, symlinks, case_folding, open_file_hold):
        try:
            step()
        except Exception as ex:  # noqa: BLE001 - one broken row must not cost the other four
            record(step.__name__.replace("_", " "), f"the probe itself failed here: {ex!r}")
            broken = True
    ask("done")

    print()
    width = max(len(name) for name, _ in rows)
    for name, observations in rows:
        for index, observation in enumerate(observations):
            print(f"{name if index == 0 else '':<{width}}  {observation}")
    print()
    print("Every line above is a measurement, not a pass or a fail: record them in")
    print("doc/verification-log.md with this venue, and tick the rows in doc/TODO.md.")
    if broken:
        print()
        print("A row above says the probe itself failed: that one is unmeasured, not a finding.")
        print(f"{WORK}/ is left in place — the request and answer files, and what the host left")
        print("behind, are how a failed row is told apart from a row that measured a refusal.")
        return 1
    # A clean run leaves nothing: the scratch project is the user's, and a stale directory is what
    # makes a later run stall on a request the host half answered for an earlier one.
    shutil.rmtree(WORK, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
