#!/usr/bin/env python3
"""Does the FUSE backend's `ENOSYS` on extended attributes cost anything real (doc/TODO.md,
"Non-TODOs")? `setxattr`/`removexattr`/`getxattr` are unimplemented. That fails closed and opens no
way to execute code. But the plain bind mount underneath *does* support `user.*` xattrs, so
the question is not whether ENOSYS is safe. It is whether programs notice ENOSYS as a cost.

Answer it by measurement, not by reasoning: run this in a FUSE backend session and again in a
plain run, and compare. The plain run is the control, as the plain bind mount column is in the
performance table:

    cp .../xattr-probe.py <scratch-workspace>/
    java -jar ko-agent-sandbox.jar --workspace=live,fuse python3 xattr-probe.py
    .../bench/plain-bind.sh python3 xattr-probe.py      # the control

Rows that differ between the two runs show what implementing xattrs would enable. Rows that fail
in both runs come from the environment, not the FUSE backend. Record the result in
doc/verification-log.md with the OS and podman versions, as the name-rule probe does.

It writes only under a temporary directory, which it removes, and leaves nothing in the workspace.
"""

import errno
import os
import shutil
import subprocess
import sys
import tempfile

MARKER = "user.ko-agent-fs-probe"


def stack() -> str:
    """Which stack, decided by two properties a bind mount does not have: the FUSE backend refuses a
    `.git` directory at *any* depth, and the BPF backend, which allows the directory
    (doc/bpf-lsm-cgroup.md, "Directories"), refuses a hook file inside it. Probing inside a fresh
    subdirectory rather than at the root is what makes that work in a workspace that already has a
    `.git`."""
    probe = tempfile.mkdtemp(prefix=".ko-agent-fs-stack-", dir=".")
    try:
        try:
            os.mkdir(os.path.join(probe, ".git"))
        except PermissionError:
            return "FUSE backend"
        try:
            os.mkdir(os.path.join(probe, ".git", "hooks"))
            with open(os.path.join(probe, ".git", "hooks", "pre-commit"), "wb"):
                pass
        except PermissionError:
            return "BPF backend"
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    return "plain bind mount"


def row(label: str, outcome: str) -> None:
    print(f"  {label:<34} {outcome}")


def errno_of(ex: OSError) -> str:
    return errno.errorcode.get(ex.errno, str(ex.errno))


def direct_ops(work: str) -> None:
    """The four calls the FUSE layer either implements or leaves at ENOSYS."""
    path = os.path.join(work, "target")
    with open(path, "wb") as handle:
        handle.write(b"payload\n")

    try:
        os.setxattr(path, MARKER, b"value")
        row("setxattr", "OK")
    except OSError as ex:
        row("setxattr", errno_of(ex))
        # The other rows mean something only once an attribute is set.
        for name in ("getxattr", "removexattr"):
            row(name, "not reached (nothing was set)")
        try:
            os.listxattr(path)
            row("listxattr", "OK")
        except OSError as list_ex:
            row("listxattr", errno_of(list_ex))
        return

    for name, call in (
        ("getxattr", lambda: os.getxattr(path, MARKER)),
        ("listxattr", lambda: os.listxattr(path)),
        ("removexattr", lambda: os.removexattr(path, MARKER)),
    ):
        try:
            call()
            row(name, "OK")
        except OSError as ex:
            row(name, errno_of(ex))


def carrying_programs(work: str) -> None:
    """What a program that *preserves* xattrs does when the destination refuses them. The source is
    outside the mount, because inside it there may be no way to attach an xattr in the first
    place — which is exactly what extracting an archive or copying a tree into
    the workspace does."""
    source = tempfile.mkdtemp(prefix="ko-agent-fs-xattr-src-")
    try:
        origin = os.path.join(source, "file")
        with open(origin, "wb") as handle:
            handle.write(b"payload\n")
        try:
            os.setxattr(origin, MARKER, b"carried")
        except OSError as ex:
            row("cp -a", f"skipped: {os.path.dirname(source)} refuses xattrs ({errno_of(ex)})")
            return

        done = subprocess.run(
            ["cp", "-a", origin, os.path.join(work, "viacp")],
            capture_output=True,
            text=True,
        )
        arrived = False
        try:
            arrived = MARKER in os.listxattr(os.path.join(work, "viacp"))
        except OSError:
            pass
        complaint = (done.stderr or done.stdout).strip().splitlines()
        row(
            "cp -a",
            f"exit {done.returncode}; xattr {'arrived' if arrived else 'dropped'}"
            + (f"; said {complaint[0]!r}" if complaint else ""),
        )
    finally:
        shutil.rmtree(source, ignore_errors=True)


def main() -> int:
    # podman puts this marker in every container it runs.
    if not os.path.exists("/run/.containerenv"):
        print("abort: not in a container — run this inside the sandbox, not on the host")
        return 2
    print(f"stack under test: {stack()}")
    print()

    work = tempfile.mkdtemp(prefix=".ko-agent-fs-xattr-", dir=os.getcwd())
    try:
        direct_ops(work)
        carrying_programs(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    print("Run this again in the other stack and diff the rows; the difference is the cost.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
