#!/usr/bin/env python3
"""The platform-verification probe for the .git and .ko-agent-sandbox name rules (doc/TODO.md,
"P1 — Platform verification"): creates each candidate spelling through the mounted filter and
reports which were denied, with which errno. The corpus in doc/TODO.md carries rows this script
does not — the Windows 8.3 short names — because they mean nothing off NTFS; run those by hand
there.
Run INSIDE a filtered sandbox session, from the root of a scratch project:

    cp .../apfs-name-rule-probe.py <scratch-project>/
    java -jar ko-agent-sandbox.jar bash          # filtered unless you opt out
    python3 apfs-name-rule-probe.py

Then, on the HOST, the checks this script cannot do — the property itself, on the real filesystem:

    ls .git                  # must fail: No such file or directory
    git status               # must say: not a git repository
    ls .ko-agent-sandbox     # must fail: No such file or directory

Record the result with `sw_vers` and the volume's File System Personality. Afterwards:

    python3 apfs-name-rule-probe.py clean

Refuses to run outside the filter: without it the canary .git would be created — it is removed
again and the run aborts, testing nothing.
"""

import errno
import os
import sys

DENIED = [
    ".GIT", ".Git", ".gIt", ".giT",           # ASCII case variants
    ".g\u0131t", ".g\u0130t",                 # Turkish i-family: dotless i, dotted capital I
    ".gi\u200ct", ".g\u200bit",               # zero width non-joiner / zero width space
    "\ufeff.git", ".git\u00ad",               # BOM prefix, soft hyphen
    ".git.", ".git ", ".git. ",               # trailing punctuation Win32 ignores
]
# The launcher's configuration name has two letters .git has not: APFS resolves U+212A KELVIN
# SIGN to k — by normalization alone, its canonical decomposition being K — and U+017F LONG S to s.
DENIED_CONFIG = [
    ".ko-agent-sandbox", ".KO-AGENT-SANDBOX", ".Ko-Agent-Sandbox",
    ".\u212ao-agent-sandbox", ".ko-agent-\u017fandbox",
    ".ko-agent\u00ad-sandbox", ".ko-agent-sandbox.",
]
ALLOWED = [
    ".gitignore", ".gitattributes", ".gitmodules", ".github",
    ".g\u00edt", ".gi\u0301t",                # i-acute in NFC and NFD: the normalization control
    ".ko-agent-sandbox-notes",
]


def clean() -> None:
    removed = []
    for name in ALLOWED:
        try:
            os.remove(name)
            removed.append(name)
        except FileNotFoundError:
            pass
    print(f"removed {len(removed)} probe files")


def main() -> int:
    for guarded in (".git", ".ko-agent-sandbox"):
        if os.path.lexists(guarded):
            print(f"abort: this directory already has {guarded} — use a scratch project's root")
            return 2

    # The canary doubles as the base case: behind the filter this is EPERM; anywhere else it
    # would succeed, which means the run is testing nothing — undo and abort.
    try:
        os.mkdir(".git")
        os.rmdir(".git")
        print("abort: created .git — this is NOT a filtered session;")
        print("       run it through the launcher, under --write=live")
        return 2
    except PermissionError:
        print("ok denied  '.git' (the canary: this session is filtered)")

    failures = 0
    for name in DENIED + DENIED_CONFIG:
        try:
            os.mkdir(name)
            print(f"FAIL created {name!r} — the name rule missed a spelling")
            failures += 1
        except OSError as caught:
            if caught.errno == errno.EPERM:
                print(f"ok denied  {name!r}")
            else:
                print(f"FAIL wrong errno for {name!r}: {caught}")
                failures += 1

    for name in ALLOWED:
        try:
            with open(name, "w"):
                pass
            print(f"ok allowed {name!r}")
        except OSError as caught:
            print(f"FAIL refused {name!r}: {caught} — the superset over-reached")
            failures += 1

    if failures:
        print(f"RESULT: FAIL ({failures} rows) — fix policy::folds_to, not the test")
        return 1
    print("RESULT: all rows pass. Now run the host-side checks (see the header), then `clean`.")
    return 0


if __name__ == "__main__":
    sys.exit(clean() if len(sys.argv) > 1 and sys.argv[1] == "clean" else main())
