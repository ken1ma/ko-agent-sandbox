#!/usr/bin/env python3
"""Does the filter's `ENOSYS` on extended attributes cost anything real (doc/TODO.md,
"Correctness")? `setxattr`/`removexattr`/`getxattr` are unimplemented, which is fail-closed and not
an execution vector — but the raw bind mount underneath *does* support `user.*` xattrs, so the
question is not whether ENOSYS is safe. It is whether ENOSYS is a regression the tools notice.

Answer it by measurement, not by reasoning: run this in a filtered session and again in an
unfiltered one, and compare. The unfiltered run is the control, exactly as the perf table's raw-bind
column is:

    cp .../xattr-probe.py <scratch-project>/
    java -jar ko-agent-sandbox.jar bash          # then again with KO_AGENT_SANDBOX_WORKSPACE_GUARD=none
    python3 xattr-probe.py

Rows that differ between the two runs are what implementing xattrs would buy. Rows that fail in both
are the environment's, not the filter's. Record the result in doc/TODO.md with the OS and podman
versions, the way the name-rule and coherency probes do.

Writes only under a temporary directory it removes; leaves nothing in the project.
"""

import errno
import os
import shutil
import subprocess
import sys
import tempfile

MARKER = "user.ko-agent-fs-probe"


def stack() -> str:
    """Filtered or not, decided by the one property that separates the filter from the launcher's
    mount pin: `.git` is refused at *any* depth, not only at the workspace root. Probing inside a
    fresh subdirectory rather than at the root is what makes that work in a project that already
    has a `.git` — including the empty one an unfiltered launch leaves behind in a project that had
    none (`SECURITY.md`, "Silent changes to what you own"), which is every scratch project that has
    been launched once."""
    probe = tempfile.mkdtemp(prefix=".ko-agent-fs-stack-", dir=".")
    try:
        os.mkdir(os.path.join(probe, ".git"))
    except PermissionError:
        return "filtered"
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    return "raw bind (unfiltered)"


def row(label: str, outcome: str) -> None:
    print(f"  {label:<34} {outcome}")


def errno_of(caught: OSError) -> str:
    return errno.errorcode.get(caught.errno, str(caught.errno))


def direct_ops(work: str) -> None:
    """The four calls the FUSE layer either implements or leaves at ENOSYS."""
    path = os.path.join(work, "target")
    with open(path, "wb") as handle:
        handle.write(b"payload\n")

    try:
        os.setxattr(path, MARKER, b"value")
        row("setxattr", "OK")
    except OSError as caught:
        row("setxattr", errno_of(caught))
        # The rest only mean anything once one is set.
        for name in ("getxattr", "removexattr"):
            row(name, "not reached (nothing was set)")
        try:
            os.listxattr(path)
            row("listxattr", "OK")
        except OSError as also:
            row("listxattr", errno_of(also))
        return

    for name, call in (
        ("getxattr", lambda: os.getxattr(path, MARKER)),
        ("listxattr", lambda: os.listxattr(path)),
        ("removexattr", lambda: os.removexattr(path, MARKER)),
    ):
        try:
            call()
            row(name, "OK")
        except OSError as caught:
            row(name, errno_of(caught))


def carrying_tools(work: str) -> None:
    """What a tool that *preserves* xattrs does when the destination refuses them. The source is
    outside the mount, because inside it there may be no way to attach an xattr in the first
    place — which is exactly the shape of extracting an archive or copying a tree into
    /workspace."""
    source = tempfile.mkdtemp(prefix="ko-agent-fs-xattr-src-")
    try:
        origin = os.path.join(source, "file")
        with open(origin, "wb") as handle:
            handle.write(b"payload\n")
        try:
            os.setxattr(origin, MARKER, b"carried")
        except OSError as caught:
            row("cp -a", f"skipped: {os.path.dirname(source)} refuses xattrs ({errno_of(caught)})")
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
    if not os.path.isdir("/workspace"):
        print("abort: no /workspace — run this inside the sandbox, not on the host")
        return 2
    os.chdir("/workspace")
    print(f"stack under test: {stack()}")
    print()

    work = tempfile.mkdtemp(prefix=".ko-agent-fs-xattr-", dir="/workspace")
    try:
        direct_ops(work)
        carrying_tools(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    print("Run this again in the other stack and diff the rows; the difference is the cost.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
