// The BPF backend's corpus fixture as both of its runners lay it out: the policy suite
// (ko-agent-fs/bpf/test/podman/policy/Policy.scala) and --self-test (BpfSelfTest.scala). Each case of
// the corpus (exercise.c) expects the answer of the policy that these rules and guarded objects make.
// The file is self-contained, with no dependency on the launcher, so that the suite's Scala CLI script
// can pull it in as it pulls in SourceDigest.scala.

package agentsandbox.launcher

object BpfCorpus:

  /** The trees that `exercise make-tree TREE` lays out: TREE, and TREE-ptr beside it. */
  val Tree = "tree"
  val PointerTree = "tree-ptr"

  /**
   * The rule files, from the launcher's default lines, each spelled `word name`. A holds, in order:
   * - the defaults;
   * - a workspace line freeing one file;
   * - filler lines up to the map's capacity;
   * - the guard's anchored lines: first a relocated hook directory, ahead of every floating line, so that
   *   an alias context computed with the wrong indices names the wrong lines, which the alias cases
   *   catch; last, the traversed component and the end of the `.claude` symlink, with its alias context.
   *
   * B, which the suite's second session takes, has a workspace line in place of the last filler, as a
   * later rule file would, and also has 128 lines.
   */
  def ruleFiles(defaults: Seq[String]): (Seq[String], Seq[String]) =
    val freed = defaults :+ "writable .vscode/settings.json"
    val filled = freed ++ (freed.length until 124).map(i => s"read-only zz-filler-$i")
    val first = Seq("read-only githooks anchored")
    val anchored = Seq("pinned-path shared anchored", "pinned-path shared/claude anchored alias=.claude")
    (
      first ++ filled ++ Seq("read-only zz-filler-last") ++ anchored,
      first ++ filled ++ Seq("read-only README.md") ++ anchored,
    )

  /**
   * The roots the policy records for the two trees, as (kind, path relative to the trees' parent), in the
   * kinds of `fixture records --guarded`. The `.git` directories and pointer files are guarded objects,
   * so the gitdir cases run under a recorded `.git` directory, with the workspace's rules and depth kept
   * above it.
   */
  val Roots: Seq[(String, String)] = Seq(
    "workspace" -> Tree,
    "workspace" -> PointerTree,
    "gitdir" -> s"$Tree/.git/modules/sub",
    "guarded-git" -> s"$PointerTree/.git",
    "guarded-git" -> s"$Tree/submod/.git",
    "guarded-git" -> s"$Tree/.git",
    "guarded-sandbox" -> s"$PointerTree/.ko-agent-sandbox",
    "guarded-sandbox" -> s"$Tree/.ko-agent-sandbox",
  )

  /**
   * The hard links that the host makes after `exercise make-tree`, as (link, target) relative to the trees'
   * parent: the `ptr` group's second names. A process in the machine cannot make them, since the
   * corpus's cases are second names that the host, outside every policy, made.
   * - The pointer tree's guarded files at the names NTFS would give them as short names. NTFS itself
   *   serves `GIT~1` as the pointer file's short name, so the link at that name may be refused there; the
   *   name NTFS serves then stands in, and the runner goes on.
   * - The submodule worktree's pointer file, in another directory. This link must exist.
   */
  val ShortNameLinks: Seq[(String, String)] = Seq(
    s"$PointerTree/GIT~1" -> s"$PointerTree/.git",
    s"$PointerTree/KO-AGE~1" -> s"$PointerTree/.ko-agent-sandbox",
  )
  val RequiredLinks: Seq[(String, String)] = Seq(s"$Tree/apps/submod-pointer" -> s"$Tree/submod/.git")
