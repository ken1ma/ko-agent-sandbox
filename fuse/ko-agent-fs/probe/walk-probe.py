#!/usr/bin/env python3
"""The cost of a path walk through the filter, as a command (doc/verification-log.md, "The cost of
a path walk"): `lstat` by depth, one deep file three ways, every tracked file by path and through
directory fds, and `find` and `git status` over the tree.

Run it INSIDE a filtered session, at the root of a project that is a git repository; it reads and
writes nothing but stat calls:

    java -jar ko-agent-sandbox.jar python3 fuse/ko-agent-fs/probe/walk-probe.py

Depth counts components under the mount. Every figure is warm: each path is visited once before
it is timed, and the two commands run once before their timed run.
"""

import os
import statistics
import subprocess
import sys
import time

if not os.path.exists("/run/.containerenv"):
    sys.exit("abort: not in a container — run this inside the sandbox, not on the host")

root = os.getcwd()
listing = subprocess.run(["git", "ls-files", "-z"], capture_output=True)
tracked = [p for p in listing.stdout.decode().split("\0")[:-1] if os.path.lexists(p)]
if listing.returncode != 0 or not tracked:
    sys.exit(
        "abort: git lists no tracked files in %s — run this at the root of a project that is a git "
        "repository%s" % (root, (": " + listing.stderr.decode().strip()) if listing.stderr else "")
    )
depths = [p.count("/")+1 for p in tracked]
entries = sum(len(d)+len(f) for _,d,f in os.walk("."))
print("tracked", len(tracked), "mean depth %.1f" % statistics.mean(depths), "entries", entries)

# lstat by depth: one file per depth, absolute path, warm, 200 iterations
by_depth = {}
for p in tracked:
    by_depth.setdefault(p.count("/")+1, p)
for depth in sorted(by_depth):
    path = os.path.join(root, by_depth[depth])
    os.lstat(path)
    start = time.perf_counter()
    for _ in range(200): os.lstat(path)
    print("depth %d  %.2f ms  %s" % (depth, (time.perf_counter()-start)*1000/200, by_depth[depth]))

# deepest file three ways
deep = max(tracked, key=lambda p: p.count("/"))
absolute = os.path.join(root, deep); directory, name = os.path.split(absolute)
def per(fn):
    fn(); start = time.perf_counter()
    for _ in range(200): fn()
    return (time.perf_counter()-start)*1000/200
print("deepest depth", deep.count("/")+1)
print("  absolute %.2f ms" % per(lambda: os.lstat(absolute)))
os.chdir(directory); print("  relative after chdir %.2f ms" % per(lambda: os.lstat(name))); os.chdir(root)
fd = os.open(directory, os.O_RDONLY|os.O_DIRECTORY)
print("  through directory fd %.2f ms" % per(lambda: os.lstat(name, dir_fd=fd))); os.close(fd)

# every tracked file: by path, then through a directory fd
for p in tracked: os.lstat(p)
start = time.perf_counter()
for p in tracked: os.lstat(os.path.join(root, p))
total = time.perf_counter()-start
print("lstat each tracked by path: %.1f s, %.2f ms/file" % (total, total*1000/len(tracked)))
groups = {}
for p in tracked:
    d, n = os.path.split(p); groups.setdefault(d or ".", []).append(n)
# Only the lstat calls are timed: opening a directory by its path pays that directory's depth,
# which is the term this row exists to exclude.
held = 0.0
opening = 0.0
for d, names in groups.items():
    start = time.perf_counter()
    fd = os.open(d, os.O_RDONLY|os.O_DIRECTORY)
    opening += time.perf_counter() - start
    start = time.perf_counter()
    for n in names: os.lstat(n, dir_fd=fd)
    held += time.perf_counter() - start
    os.close(fd)
print("same through directory fds: %.1f s, %.2f ms/file (opening the %d directories by path: %.1f s)"
      % (held, held*1000/len(tracked), len(groups), opening))

for label, command in [("find . -type f", ["find",".","-type","f"]),
                       ("git status", ["git","status","--porcelain"]),
                       ("git status --untracked-files=no", ["git","status","--porcelain","--untracked-files=no"])]:
    # Warm-up, then the timed run. A failed command aborts the probe rather than being timed: its
    # wall time measures nothing, and a number that can come from a failure is not evidence.
    for timed in (False, True):
        start = time.perf_counter()
        done = subprocess.run(command, capture_output=True)
        elapsed = time.perf_counter() - start
        if done.returncode != 0:
            sys.exit("abort: %s failed: %s" % (label, done.stderr.decode(errors="replace").strip()))
    print("%s: %.1f s" % (label, elapsed))
