#!/usr/bin/env python3
"""The platform-verification probe for end-to-end coherency (docs/TODO.md, "End-to-end coherency
through the real host share"): does a host-side write become visible inside the sandbox promptly —
through read(), and through an already-established mmap (the AUTO_INVAL_DATA path, which nothing
else exercises)? The rig's coherency tests use a local backing; this one crosses the real stack:
host filesystem -> virtiofs -> (filter, when enabled) -> container.

Run INSIDE a sandbox session, in a scratch project, with a host terminal beside it:

    cp .../coherency-probe.py <scratch-project>/
    java -jar ko-agent-sandbox.jar bash          # add KO_AGENT_SANDBOX_NO_FUSE_FILTER=1 to compare
    python3 coherency-probe.py

then follow the printed instruction in the HOST terminal. The probe reports the polling delay at
which the change became visible, separately for read() and for the mapped page. Delete
coherency-probe-data afterwards (the probe prints a reminder).
"""

import mmap
import os
import sys
import time

DATA = "coherency-probe-data"
OLD = b"AAAA"
NEW = b"BBBB"  # same length: the mapped page is compared in place, no size change involved


def stack() -> str:
    try:
        os.mkdir(".git")
    except PermissionError:
        return "filtered"
    os.rmdir(".git")
    return "raw bind (unfiltered)"


def main() -> int:
    if not os.path.isdir("/workspace"):
        print("abort: no /workspace — run this inside the sandbox, not on the host")
        return 2
    os.chdir("/workspace")

    print(f"stack under test: {stack()}")
    with open(DATA, "wb") as handle:
        handle.write(OLD)

    with open(DATA, "rb") as mapped_handle:
        mapped = mmap.mmap(mapped_handle.fileno(), len(OLD), prot=mmap.PROT_READ)
        assert bytes(mapped) == OLD

        print()
        print("READY. In a HOST terminal, in this project directory, run:")
        print(f"    printf {NEW.decode()} > {DATA}")
        print("waiting up to 120s ...")
        sys.stdout.flush()

        deadline = time.monotonic() + 120
        read_seen = None
        while time.monotonic() < deadline:
            with open(DATA, "rb") as reader:
                if reader.read() == NEW:
                    read_seen = time.monotonic()
                    break
            time.sleep(0.01)
        if read_seen is None:
            print("FAIL: the host write never became visible to read()")
            return 1
        # The host write happened at an unknown moment before this; poll from here to see how far
        # the mapped view lags the read() view — that lag is the AUTO_INVAL_DATA measurement.
        start = read_seen
        mmap_seen = None
        while time.monotonic() < deadline:
            if bytes(mapped) == NEW:
                mmap_seen = time.monotonic()
                break
            time.sleep(0.01)

        print()
        print("read():  the host write is visible (polled at 10 ms until it appeared)")
        if mmap_seen is None:
            print("FAIL: the mapped page still shows the old bytes 120s after read() saw the new")
            print("      — AUTO_INVAL_DATA is not invalidating; mmap coherency is broken")
            return 1
        lag = mmap_seen - start
        print(f"mmap():  the mapped page shows the new bytes, {lag * 1000:.0f} ms after read() did")
        if lag > 2.0:
            print("MARGINAL: over 2 s of mmap lag — record it; git mmaps .git/index and packfiles")
        print()
        print(f"RESULT: pass. Clean up with: rm {DATA}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
