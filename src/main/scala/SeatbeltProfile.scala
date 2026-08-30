// The Seatbelt profile a host build runs under: PLAN-SBT-ON-HOST.md §7.2 as text. Pure — a
// BuildPolicy in, SBPL out — so what the profile says is a unit test rather than something only a
// Mac can check.
//
// Two properties of SBPL shape everything here, both measured by probe/seatbelt-semantics.sh:
//
//   - It canonicalizes the path being *accessed* but matches the rule *as written*. A rule naming a
//     non-canonical path therefore matches nothing, which grants rather than denies. Every path
//     that reaches `render` is refused unless it is absolute and normalized, and BuildSandboxPolicy
//     resolves symlinks before it gets here.
//   - Rules are last-match-wins, so the guard denies are emitted after every allow. A generator
//     that appended a grant later would silently reopen the guard, which is why nothing here takes
//     extra rules from a caller.


package agentsandbox.launcher

import java.nio.file.Path

import BuildSandboxPolicy.{BuildPolicy, Tool}

object SeatbeltProfile:

  /**
   * `.git` and `.ko-agent-sandbox` at any depth. A pattern by intent, and the only regex in the
   * profile: everything else is a wrapper-supplied path, which a regex would mangle — the Coursier
   * JDK home alone carries a percent-encoded `+`, a literal `+` and dots.
   *
   * The trailing `(/|$)` is what stops `.gitignore` and `.github` matching. Case is not folded
   * here and does not need to be: SBPL canonicalizes the accessed path, and on a case-insensitive
   * volume that returns the on-disk spelling, so `.GIT` arrives as `.git`. A profile written to
   * rely on pattern folding instead would not fold.
   */
  val GuardedNames: Seq[String] = Seq(".git", ".ko-agent-sandbox")

  /**
   * The character devices a JVM opens before it runs anything. Named literally rather than left to
   * the measured runtime set: `/dev` also holds the disks, and a subpath grant there would be a
   * read of every volume on the machine.
   */
  /**
   * The root directory entry. `(subpath "/")` is not the union of `(subpath "/child")` over every
   * child — resolving `/bin/sh` authorizes `/` first, and no grant on a child covers it. Measured
   * rather than reasoned: metadata alone is *not* sufficient, `file-read*` is, and without it a
   * process dies inside the loader before it has a stderr to report on.
   *
   * It names the directory entry, not its contents, so it reveals nothing about what is on the
   * disk. A profile that reached for `(subpath "/")` instead — the obvious fix when only that
   * appears to work — would grant the whole filesystem.
   */
  val RootComponent: String = """(allow file-read* file-test-existence (literal "/"))"""

  /**
   * Every directory between `/` and a granted path, as a literal read plus `file-test-existence`.
   *
   * Resolving a path authorizes each component, and a `(subpath …)` grant covers what is *under*
   * it, never the directories above. Measured: with only the deep grants, `java -version` dies in
   * the loader; with the chain present it runs, and the chain is what a coarse `/Users` grant was
   * standing in for. A literal names the directory entry, not its contents, so the chain reveals
   * nothing but the existence of directories whose names the profile already contains.
   *
   * Apple spells the same rule with a built-in, `(apply path-ancestors …)` paired with
   * `file-test-existence` (`/System/Library/Sandbox/Profiles/dyld-support.sb`), and gives the
   * reason for the root entry: the loader opens `/` to use as an `openat(2)` root. Adopting the
   * built-in would replace this enumeration with one rule per path, and is worth doing once it is
   * shown to work under `(version 1)`.
   */
  def ancestorLiterals(paths: Seq[Path]): Seq[Path] =
    paths
      .flatMap(path => Iterator.iterate(path.getParent)(p => if p == null then null else p.getParent)
        .takeWhile(_ != null).toSeq)
      .distinct
      .filterNot(_.toString == "/")
      .sortBy(_.toString)

  val DevicePaths: Seq[Path] =
    Seq("/dev/null", "/dev/random", "/dev/urandom", "/dev/tty").map(Path.of(_))

  val Devices: String =
    DevicePaths.map(path => literal(path)).mkString("(allow file-read* file-write-data ", " ", ")")

  /** What the build may reach, beyond the policy's own paths, to start a JVM at all. Discovered by
    * running a real build under this profile and reading the denials, never guessed: §2.1 admits a
    * runtime path only where testing proves the read is stable. */
  case class RuntimeAuthority(reads: Seq[Path], executes: Seq[Path])

  case class ProfileInputs(
    policy: BuildPolicy,
    sessionTmp: Path,
    sbtDistribution: Option[Path],
    proxyPort: Int,
    runtime: RuntimeAuthority,
  )

  /**
   * The profile, or the first reason it cannot be built. A refusal rather than a best effort: a
   * profile with one unusable rule is a profile with one silent grant.
   */
  def render(inputs: ProfileInputs): Either[String, String] =
    val policy = inputs.policy
    val readOnly = Seq(policy.jdkHome) ++ policy.sbtBoot ++ inputs.sbtDistribution ++ Seq(policy.launcher)
    val readWrite = Seq(policy.project, policy.coursierV1, inputs.sessionTmp)
    val everyPath = readOnly ++ readWrite ++ inputs.runtime.reads ++ inputs.runtime.executes

    everyPath.find(path => !usable(path)) match
      case Some(bad) => Left(nonCanonicalReason(bad))
      case None if inputs.proxyPort < 1 || inputs.proxyPort > 65535 =>
        Left(s"the proxy port ${inputs.proxyPort} is not a port")
      case None =>
        val lines = Seq.newBuilder[String]
        lines += "(version 1)"
        lines += ";; Generated by SeatbeltProfile.render. Rules are last-match-wins: the guard"
        lines += ";; denies are last, and nothing may be appended after them."
        lines += "(deny default)"
        lines += ""
        lines += ";; Path resolution authorizes every component, and the root has no parent to be"
        lines += ";; covered by a subpath grant: without this, nothing starts and nothing says why."
        lines += RootComponent
        // DevicePaths included: /dev needs its own literal like any other ancestor, and without it
        // the JVM cannot open /dev/urandom — SecureRandom then fails with "NativePRNG not
        // available", which names the algorithm rather than the path.
        (ancestorLiterals(
          readOnly ++ readWrite ++ inputs.runtime.reads ++ inputs.runtime.executes ++ DevicePaths,
        ))
          .foreach(path => lines += s"(allow file-read* file-test-existence ${literal(path)})")
        lines += ""
        lines += ";; A process at all: not filesystem authority, and none of it reaches user data."
        lines += "(allow process-fork sysctl-read mach-lookup)"
        lines += Devices
        lines += ""
        lines += ";; Runtime authority: measured by probe/build-profile-iterate.sh, never guessed."
        inputs.runtime.reads.foreach(path => lines += s"(allow file-read* ${subpath(path)})")
        inputs.runtime.executes.foreach: path =>
          lines += s"(allow process-exec* file-read* ${subpath(path)})"
        lines += ""
        lines += ";; The build's own tools, never writable by it."
        readOnly.foreach(path => lines += s"(allow process-exec* file-read* ${subpath(path)})")
        lines += ""
        lines += ";; What the build may change."
        readWrite.foreach(path => lines += s"(allow file-read* file-write* ${subpath(path)})")
        lines += ""
        lines += ";; The build's own proxy, and no other destination."
        lines += s"""(allow network-outbound (remote tcp "localhost:${inputs.proxyPort}"))"""
        lines += ""
        lines += ";; The guard, last. §2.1: repository state a later host git command would execute,"
        lines += ";; and the boundary configuration a later launch would read."
        GuardedNames.foreach: name =>
          lines += s"(deny file-write* file-read* file-link ${anyDepth(name)})"
        Right(lines.result().mkString("\n") + "\n")

  /** The tool this profile is for, which decides whether the sbt-only paths are present. */
  def toolOf(policy: BuildPolicy): Tool = policy.tool

  /**
   * The second half of the sbt launcher: what the `cs`-installed wrapper execs, which is an
   * unpacked distribution inside the Coursier archive cache. Its path encodes the download URL of
   * whichever sbt Coursier installed, so it is read out of the wrapper rather than derived — and
   * read rather than obtained by running it, for §3.3's reason.
   *
   * The longest cache path the wrapper names, because a shorter one is a prefix of the real answer
   * and a grant on a prefix is wider than it should be. Refused if it escapes the cache root.
   */
  def sbtDistribution(wrapperText: String, coursierCacheRoot: Path): Option[Path] =
    val prefix = coursierCacheRoot.toString
    val candidates =
      for
        line <- wrapperText.linesIterator
        start <- indexesOf(line, prefix)
        raw = line.drop(start).takeWhile(ch => ch != '"' && ch != '\'' && ch != ';' && ch != '\n')
        trimmed = raw.trim
        if trimmed.length > prefix.length
      yield trimmed
    candidates.toSeq.sortBy(-_.length).headOption
      .map(text => Path.of(text).normalize())
      .filter(_.startsWith(coursierCacheRoot))

  /**
   * The distribution root to grant, from the path the wrapper execs. The inner launcher resolves
   * `sbt_home` as the parent of its own `bin` directory and reads `sbt-launch.jar`, `conf/` and the
   * `sbtn` binaries from there, so a grant on the executable alone starts a build that cannot find
   * its own launcher jar.
   */
  def distributionHome(executable: Path): Path =
    val parent = executable.getParent
    if parent != null && parent.getFileName != null && parent.getFileName.toString == "bin" then
      Option(parent.getParent).getOrElse(parent)
    else if parent != null then parent
    else executable

  private def indexesOf(line: String, needle: String): Seq[Int] =
    Iterator
      .unfold(0): from =>
        line.indexOf(needle, from) match
          case -1    => None
          case index => Some((index, index + 1))
      .toSeq

  /** Absolute and already normalized. Symlink resolution happens before this, in BuildSandboxPolicy:
    * it needs the filesystem, and this stays pure. */
  private def usable(path: Path): Boolean =
    path.isAbsolute && path.normalize() == path

  private def nonCanonicalReason(path: Path): String =
    s"$path is not a canonical absolute path; SBPL matches rules as written, so a rule naming it " +
      "would match nothing and grant rather than deny"

  /** An SBPL string literal. Paths here carry spaces, `+` and percent signs; only a quote or a
    * backslash needs escaping, and neither occurs in a path this wrapper accepts. */
  private def sbpl(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

  private def subpath(path: Path): String = s"(subpath ${sbpl(path.toString)})"

  private def literal(path: Path): String = s"(literal ${sbpl(path.toString)})"

  /** The name at any depth, anchored so `.gitignore` and `.github` do not match. */
  private def anyDepth(name: String): String =
    s"""(regex #"/${name.replace(".", "\\.")}(/|$$)")"""
