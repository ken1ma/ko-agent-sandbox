#!/bin/sh
# Re-check the git-layout premises that doc/git-metadata.md records under "Premises". This drives a
# real git through a series of ordinary operations and classifies every path it writes under .git
# with the actual policy (through the classify_paths example).
#
# Run this after a git upgrade. Update the classifier, tests/git_corpus.rs and those premises if:
#
# - the CONTROL set gains a path that is not config, hooks, description, commondir, gitdir,
#   config.worktree or branches; or
# - an operational file moves.
#
# Needs: git, and a built classify_paths example (cargo build -p ko-agent-fs --example
# classify_paths).
set -eu

workspace=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
program="$workspace/target/debug/examples/classify_paths"
[ -x "$program" ] && "$program" </dev/null >/dev/null 2>&1 || \
    ( cd "$workspace" && cargo build -q -p ko-agent-fs --example classify_paths )

export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@e GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@e
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

git init -q donor
( cd donor; echo a >a; git add a; git commit -qm a; echo b >b; git add b; git commit -qm b )

git init -q main
cd main
echo hi >f; git add f; git commit -qm first
git branch feature
echo more >>f; git add f; git commit -qm second

mark="$work/mark"; touch "$mark"; sleep 1.2   # writes after here are the normal-operation set
branch=$(git symbolic-ref --short HEAD)

# No failure in the series is suppressed: under `set -eu`, a failing git command aborts the run. A
# command that silently did nothing would leave its writes out of the classification, and the
# output would read as if the premises held. Only stdout is silenced.
git switch -qc feature2; echo x >g; git add g; git commit -qm feat
git switch -q "$branch"; git merge -q --no-edit feature2 >/dev/null
git tag v1
echo y >>f; git add f; git commit -qm third
git switch -q feature; git rebase -q "$branch" >/dev/null
git switch -q "$branch"
echo z >>f; git stash -q; git stash pop -q >/dev/null
git remote add donor ../donor
git -c protocol.file.allow=always fetch -q donor
git gc -q
git worktree add -q ../wt >/dev/null
git -c protocol.file.allow=always submodule add -q ../donor sub
git commit -qm "add sub"

echo "git $(git --version | awk '{print $3}')"
echo
# Where the submodule gitdirs actually are. A maxdepth-1 listing would not do: a submodule's name
# defaults to its path, so `modules/libs/foo` is one gitdir, not two levels of one. A `HEAD` file
# marks a gitdir root; the filter's FUSE layer asks the tree the same question.
module_roots=$(find .git/modules -mindepth 1 -name HEAD -type f 2>/dev/null | sed 's|/HEAD$||' | sort)

echo "# nested gitdir roots git created"
{ printf '%s\n' "$module_roots"
  find .git/worktrees -maxdepth 1 -mindepth 1 -type d 2>/dev/null; } | grep . | sort | sed 's/^/  /'
echo
echo "# CONTROL-classified writes during normal ops (premise: all in the frozen set)"
# $module_roots is unquoted on purpose: each root is a separate argument to the classifier.
find .git \( -type f -o -type l \) -newer "$mark" | sort \
    | "$program" $module_roots | grep '^CONTROL' | sed 's/^/  /'
echo
echo "# OPERATIONAL writes at the main gitdir root (premise: all must stay writable)"
find .git -maxdepth 1 \( -type f -o -type l \) -newer "$mark" | sort | "$program" | grep '^OPERATIONAL' | sed 's/^/  /'
