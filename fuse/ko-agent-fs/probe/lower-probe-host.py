#!/usr/bin/env python3
"""The HOST half of the staged-lower probe (doc/TODO.md, "What the staged lower can do, per share").
`lower-probe.py`, running inside a sandbox session, has the procedure and prints the results; this
side acts on the real backing filesystem when asked and reports what it observed.

    python3 lower-probe-host.py        # in the project directory, beside a running lower-probe.py

Stdlib only, and it exits when the session half says it is done. The rename flags are the one place
the platforms genuinely differ: Linux has `renameat2`, macOS `renamex_np`, and Windows neither — a
host with no exchange primitive is a finding, not a defect in this script.
"""

import ctypes
import json
import os
import platform
import sys
import time

WORK = "lower-probe-work"
IDLE = 120

AT_FDCWD = -100
LINUX_NOREPLACE = 1 << 0
LINUX_EXCHANGE = 1 << 1
DARWIN_SWAP = 0x0002
DARWIN_EXCL = 0x0004


def libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def attempt(action) -> str:
    """`ok`, or the platform's own words for the refusal — a Windows sharing violation names itself
    and is the reason this returns text rather than a boolean."""
    try:
        action()
        return "ok"
    except OSError as ex:
        return str(ex)


def exchange(first: str, second: str) -> str:
    if sys.platform == "linux":
        return _linux_renameat2(first, second, LINUX_EXCHANGE)
    if sys.platform == "darwin":
        return _darwin_renamex(first, second, DARWIN_SWAP)
    return "no exchange primitive on this host"


def noreplace(old: str, new: str) -> str:
    if sys.platform == "linux":
        return _linux_renameat2(old, new, LINUX_NOREPLACE)
    if sys.platform == "darwin":
        return _darwin_renamex(old, new, DARWIN_EXCL)
    # Windows: os.rename already refuses an existing target, which is the semantics, not a fallback.
    return attempt(lambda: os.rename(old, new))


def _linux_renameat2(old: str, new: str, flags: int) -> str:
    functions = libc()
    ctypes.set_errno(0)
    if hasattr(functions, "renameat2"):
        result = functions.renameat2(AT_FDCWD, old.encode(), AT_FDCWD, new.encode(), flags)
    else:
        numbers = {"x86_64": 316, "aarch64": 276}
        number = numbers.get(platform.machine())
        if number is None:
            return f"no renameat2 wrapper and no syscall number for {platform.machine()}"
        result = functions.syscall(number, AT_FDCWD, old.encode(), AT_FDCWD, new.encode(), flags)
    return "ok" if result == 0 else os.strerror(ctypes.get_errno())


def _darwin_renamex(old: str, new: str, flags: int) -> str:
    functions = libc()
    if not hasattr(functions, "renamex_np"):
        return "no renamex_np in libSystem"
    ctypes.set_errno(0)
    result = functions.renamex_np(old.encode(), new.encode(), ctypes.c_uint(flags))
    return "ok" if result == 0 else os.strerror(ctypes.get_errno())


def work(name: str) -> str:
    return os.path.join(WORK, name)


# --- handlers, one per step the session half asks for -------------------------------------------


def hello(_request: dict) -> dict:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    }


def hardlink_create(_request: dict) -> dict:
    def make() -> None:
        with open(work("hl-host-a"), "wb") as handle:
            handle.write(b"host-side pair\n")
        os.link(work("hl-host-a"), work("hl-host-b"))

    return {"created": attempt(make)}


def hardlink_observe(_request: dict) -> dict:
    first, second = os.stat(work("hl-guest-a")), os.stat(work("hl-guest-b"))
    return {
        "ino_a": first.st_ino,
        "ino_b": second.st_ino,
        "same_inode": first.st_ino == second.st_ino,
        "nlink": first.st_nlink,
    }


def rename_flags(_request: dict) -> dict:
    with open(work("rh-x"), "wb") as handle:
        handle.write(b"x\n")
    with open(work("rh-y"), "wb") as handle:
        handle.write(b"y\n")
    # The session composes the prose; this side reports only what it observed.
    return {
        "exchange": exchange(work("rh-x"), work("rh-y")),
        "noreplace_onto_existing": noreplace(work("rh-x"), work("rh-y")),
    }


def symlink(request: dict) -> dict:
    guest = work("sl-guest")
    if request.get("created_here") != "ok":
        sees = "not created by the session"
    elif not os.path.islink(guest):
        sees = "present but not a symlink here"
    else:
        sees = f"a link to {os.readlink(guest)!r}"
    return {
        "sees_guest_link": sees,
        "created": attempt(lambda: os.symlink("sl-target", work("sl-host"))),
    }


def case_create(_request: dict) -> dict:
    def make() -> None:
        with open(work("Case-Probe"), "wb") as handle:
            handle.write(b"capitalized\n")

    created = attempt(make)
    if created != "ok":
        return {"created": created, "verdict": "not created"}
    other = work("case-probe")
    found = os.path.exists(other)
    try:
        with open(other, "xb") as handle:
            handle.write(b"lowercase\n")
        coexist = "both names exist independently"
        os.remove(other)
    except FileExistsError:
        coexist = "the second name collides with the first"
    except OSError as ex:
        coexist = f"refused: {ex}"
    return {
        "created": created,
        "verdict": f"lookup of the other case {'finds' if found else 'misses'} it, {coexist}",
    }


def hold(request: dict) -> dict:
    """Write, rename and unlink against three paths the session is holding open — one each, so
    nothing here is undone and nothing a later phase needs is destroyed."""
    prefix = request["prefix"]

    def write() -> None:
        with open(work(f"{prefix}-write"), "r+b") as handle:
            handle.write(b"host")

    def rename() -> None:
        os.rename(work(f"{prefix}-rename"), work(f"{prefix}-rename.moved"))

    def unlink() -> None:
        os.remove(work(f"{prefix}-unlink"))

    return {"write": attempt(write), "rename": attempt(rename), "unlink": attempt(unlink)}


HANDLERS = {
    "hello": hello,
    "hardlink-create": hardlink_create,
    "hardlink-observe": hardlink_observe,
    "rename-flags": rename_flags,
    "symlink": symlink,
    "case-create": case_create,
    "hold-read": hold,
    "hold-write": hold,
    "hold-released": hold,
}


def answer(step: str, payload: dict) -> None:
    """Written aside and renamed into place: the session reads this through the share, and a
    half-written file there is a parse error rather than a wait."""
    final = os.path.join(WORK, f"res-{step}.json")
    staging = final + ".partial"
    with open(staging, "w") as handle:
        json.dump(payload, handle)
    os.replace(staging, final)


def main() -> int:
    print(f"host: {platform.system()} {platform.release()} {platform.machine()}")
    print(f"waiting for {WORK}/ and the session half ...")
    deadline = time.monotonic() + IDLE
    greeted = False
    while True:
        if time.monotonic() > deadline:
            print(f"abort: nothing asked for {IDLE}s; is lower-probe.py running in a session?")
            return 2
        if not os.path.isdir(WORK):
            time.sleep(0.05)
            continue
        for entry in sorted(os.listdir(WORK)):
            if not entry.startswith("req-") or not entry.endswith(".json"):
                continue
            step = entry[len("req-"):-len(".json")]
            if os.path.exists(os.path.join(WORK, f"res-{step}.json")):
                continue
            if step == "done":
                if not greeted:
                    # A directory an earlier run left behind. The session clears it at startup, so
                    # exiting on this one would end this half before the real run had begun.
                    continue
                # Answered before exiting: the session removes the directory once this lands, and
                # would otherwise remove it while this half was still watching for the request.
                answer(step, {})
                print("done.")
                return 0
            try:
                with open(os.path.join(WORK, entry)) as handle:
                    request = json.load(handle)
            except (FileNotFoundError, json.JSONDecodeError):
                continue  # the session is clearing an earlier run's directory under this walk
            handler = HANDLERS.get(step)
            if handler is None:
                answer(step, {"error": f"no handler for {step}"})
                print(f"{step}: no handler — the two halves have drifted")
                return 2
            answer(step, handler(request))
            greeted = greeted or step == "hello"
            print(f"{step}: answered")
            deadline = time.monotonic() + IDLE
        time.sleep(0.05)


if __name__ == "__main__":
    sys.exit(main())
