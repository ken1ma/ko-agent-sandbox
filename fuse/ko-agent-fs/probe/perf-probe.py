#!/usr/bin/env python3
"""The metadata cost of the filter, as a command rather than a reconstruction (doc/TODO.md,
"Performance"). It builds its own corpus, so two runs are comparable even on different machines,
and reports microseconds per entry for the five operation shapes the table there is built from.

Run it INSIDE a sandbox session, twice, and compare the columns — the second run is the control:

    cp .../perf-probe.py <scratch-project>/
    java -jar ko-agent-sandbox.jar bash                          # filtered
    python3 perf-probe.py
    KO_AGENT_SANDBOX_WORKSPACE_GUARD=none java -jar ko-agent-sandbox.jar bash
    python3 perf-probe.py

The control matters more than the absolute numbers: the raw bind is fast because the VM kernel
caches virtiofs metadata across processes, which is exactly the caching the coherency invariant
forbids the filter (doc/architecture.md). What the ratio prices is that invariant, not the backing.

Everything is written under a temporary directory in /workspace — which is the point, /tmp is not
the filesystem under test — and removed afterwards. FILES=n varies the corpus size.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

FILES = int(os.environ.get("FILES", "1800"))


def stack() -> str:
    """Filtered or not, decided by the one property that separates the filter from the launcher's
    mount pin: `.git` is refused at any depth, not only at the workspace root."""
    probe = tempfile.mkdtemp(prefix=".perf-probe-stack-", dir="/workspace")
    try:
        os.mkdir(os.path.join(probe, ".git"))
    except PermissionError:
        return "filtered"
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    return "raw bind (unfiltered)"


def build(root: str) -> int:
    """A shape a build tool actually produces: a few hundred directories, a handful of small files
    in each. 4 KB of content, so the run measures metadata rather than bandwidth."""
    payload = b"x" * 4096
    for index in range(FILES):
        directory = os.path.join(root, "tree", str(index // 6))
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, "file-%d" % index), "wb") as handle:
            handle.write(payload)
    return sum(len(files) + len(dirs) for _, dirs, files in os.walk(os.path.join(root, "tree"))) + 1


def timed(label: str, entries: int, *command: str) -> None:
    """A failed command aborts the probe rather than being timed: its wall time measures nothing,
    and a number that can come from a failure is not evidence."""
    start = time.monotonic()
    done = subprocess.run(command, capture_output=True)
    if done.returncode != 0:
        sys.exit(
            "abort: %s failed: %s"
            % (" ".join(command), done.stderr.decode(errors="replace").strip())
        )
    print("  %-32s %8d us/entry" % (label, (time.monotonic() - start) * 1e6 / entries))


def main() -> int:
    if not os.path.isdir("/workspace"):
        print("abort: no /workspace — run this inside the sandbox, not on the host")
        return 2
    os.chdir("/workspace")

    under_test = stack()
    work = tempfile.mkdtemp(prefix=".perf-probe-", dir="/workspace")
    try:
        print("building a %d-entry corpus ..." % FILES)
        entries = build(work)
        tree = os.path.join(work, "tree")

        print("\nstack under test: %s   (%d entries)\n" % (under_test, entries))
        timed("find (readdir only)", entries, "find", tree)
        timed("find -printf (readdir+stat)", entries, "find", tree, "-printf", "%s %p\n")
        timed("ls -lR (stat + xattr)", entries, "ls", "-lR", tree)
        timed("cp -r (create + write)", entries, "cp", "-r", tree, os.path.join(work, "copy"))
        timed("rm -rf", entries, "rm", "-rf", os.path.join(work, "copy"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\nRun this again in the other stack; the ratio between the two columns is what the")
    print('coherency invariant costs (doc/TODO.md, "Performance").')
    return 0


if __name__ == "__main__":
    sys.exit(main())
