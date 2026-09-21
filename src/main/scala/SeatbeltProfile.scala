// The Seatbelt profiles a host command and the host proxy run under (run-on-host.md "The Seatbelt
// profile", "The command's egress proxy"). Pure — paths in, SBPL out — so unit tests check the
// generated SBPL without requiring macOS.
//
// Two properties of SBPL decide how paths are written and how rules are ordered here, both measured by
// src/probe/seatbelt-semantics.sh:
//
//   - It canonicalizes the path being *accessed* but matches the rule *as written*. A rule naming a
//     non-canonical path can leave a deny unmatched and a broader allow in force. Every path
//     that reaches `render` is refused unless it is absolute and normalized, and RunOnHostPrereqs
//     resolves symlinks before it gets here.
//   - Rules are last-match-wins, so the guard denies are emitted after every allow. A generator
//     that appended a grant later would silently reopen the guard, which is why nothing here takes
//     extra rules from a caller.


package agentsandbox.launcher

import java.nio.file.Path

import RunOnHostPrereqs.{CommandPrereqs, Program}

object SeatbeltProfile:

  /**
   * `.git` and `.ko-agent-sandbox` at any depth under the project. A pattern by intent, and the
   * only regex in the profile: everything else is a wrapper-supplied path, which a regex would
   * mangle — the Coursier JDK home alone contains a percent-encoded `+`, a literal `+` and dots.
   * The project itself is kept out of the pattern the same way: `(require-all (subpath …) (regex …))`
   * conjoins a literal filter with the name pattern.
   *
   * The trailing `(/|$)` is what stops `.gitignore` and `.github` matching. The pattern is
   * lowercase alone: on a case-insensitive volume it matches the other spellings measured
   * (run-on-host.md, "The host command's filesystem rules").
   */
  val GuardedNames: Seq[String] = Seq(".git", ".ko-agent-sandbox")

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
   * Every directory between `/` and a granted path, as a literal `file-read-metadata` plus
   * `file-test-existence`.
   *
   * Resolving a path authorizes each component, and a `(subpath …)` grant covers what is *under*
   * it, never the directories above. Measured: with only the deep grants, `java -version` dies in
   * the loader; with the chain present it runs, and the chain is what a coarse `/Users` grant was
   * standing in for. Metadata and not `file-read*`, because on a directory `file-read*` is its
   * listing: src/probe/run-on-host-acceptance-test.sh showed a chain granted that way listing all of
   * `~/Library/Caches`. Only the root entry needs the wider read.
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

  /**
   * The character devices a JVM opens before it runs anything. No `/dev/tty`: closing the child's
   * stdin does not detach its controlling terminal, and a command that can open the terminal can
   * read what the user types. The random devices are read-only.
   */
  val DevicePaths: Seq[Path] = Seq("/dev/null", "/dev/random", "/dev/urandom").map(Path.of(_))

  val Devices: String =
    """(allow file-read* file-write-data (literal "/dev/null"))""" + "\n" +
      """(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))"""

  /**
   * The Mach services both profiles may look up, by name: an unfiltered `mach-lookup` reaches
   * every service of the host, and a service may act for its caller outside the profile.
   * Measured by src/probe/run-on-host-profile-iterate.sh `mach-proxy` and `mach`: without this
   * name the serving proxy dies of a segmentation fault, where `java -version` and `sbt about`
   * run with no name at all. A command gets it unmeasured (run-on-host.md, "The Seatbelt
   * profile", has the reason).
   */
  val MachServices: Seq[String] = Seq("com.apple.system.opendirectoryd.libinfo")

  private val MachLookup: String =
    s"(allow mach-lookup ${MachServices.map(name => s"(global-name ${sbpl(name)})").mkString(" ")})"

  /** What the command may reach, beyond the prerequisites' paths, to start a JVM at all. Discovered by
    * running a real build under this profile and reading the denials, never guessed: a system path is
    * granted only where testing proves the read is stable. */
  case class SystemPaths(reads: Seq[Path], executes: Seq[Path])

  /** The network authority beyond the proxy and the session's own UNIX sockets, typed so that
    * the dispatch shows which program gets which: nothing more for an sbt server and Maven; for
    * an sbt client, the sockets under the broker's `tmp/`, where its server listens; for the
    * mill daemon, listeners on any port, since it binds port 0 and no rule confines a bind to
    * one, and at any address of this host, since the "localhost" class admits a wildcard bind —
    * a grant everything the daemon forks inherits, so a build under mill can bind a listener a
    * LAN peer reaches, where one under sbt or Maven gets EPERM (SECURITY.md "Run on host");
    * for a mill client, outbound to the daemon's one port (RunOnHostSandbox.BrokerRuntimes,
    * RunOnHostMillDaemons); for Gradle, the mill daemon's grant plus outbound to any port of this host:
    * its daemon, workers and file-lock socket bind port 0 and connect to each other's, and the
    * client starts the daemon itself, so one profile serves both. Measured:
    * src/probe/run-on-host-broker-session.sh L1–L4, G1, G7–G10. */
  enum Network:
    case ProxyOnly
    case SbtClient(serverTmp: Path)
    case MillDaemon
    case MillClient(daemonPort: Int)
    case Gradle

  case class ProfileInputs(
    prereqs: CommandPrereqs,
    sessionTmp: Path,
    distribution: Option[Path],
    sbtGlobal: Option[Path],
    ivyHome: Option[Path],
    gradleUserHome: Option[Path],
    m2Repository: Option[Path],
    proxyPort: Int,
    systemPaths: SystemPaths,
    network: Network,
  )

  /**
   * The profile, or the first reason it cannot be built. A deny naming the wrong path could
   * leave a broader allow in force.
   */
  def render(inputs: ProfileInputs): Either[String, String] =
    val prereqs = inputs.prereqs
    val readOnly = Seq(prereqs.jdkHome) ++ inputs.distribution ++ Seq(prereqs.executable)
    // Tests write and run stubs in the project and the command's temporary directory. Children
    // inherit the profile. Caches need no process-exec grant: the JVM loads their code by reading it.
    val readWriteExec = Seq(prereqs.project, inputs.sessionTmp)
    val readWrite =
      Seq(prereqs.coursierV1) ++ inputs.sbtGlobal ++ inputs.ivyHome ++ inputs.gradleUserHome ++ inputs.m2Repository
    val serverTmp = inputs.network match
      case Network.SbtClient(tmp) => Some(tmp)
      case _                      => None
    val networkProgram = inputs.network match
      case Network.ProxyOnly                          => None
      case Network.SbtClient(_)                       => Some(Program.Sbt)
      case Network.MillDaemon | Network.MillClient(_) => Some(Program.Mill)
      case Network.Gradle                             => Some(Program.Gradle)
    val daemonPort = inputs.network match
      case Network.MillClient(port) => Some(port)
      case _                        => None
    val everyPath =
      readOnly ++ readWriteExec ++ readWrite ++ inputs.systemPaths.reads ++ inputs.systemPaths.executes ++ serverTmp

    val program = prereqs.program
    everyPath.find(path => !isAbsoluteNormalized(path)) match
      case _ if program == Program.Sbt && inputs.distribution.isEmpty =>
        Left(
          "an sbt profile needs the distribution the sbt script execs; without it the command cannot find" +
            " sbt-launch.jar",
        )
      case _ if program == Program.Gradle && inputs.distribution.isEmpty =>
        Left("a gradle profile needs the distribution its gradle runs from; without it the command cannot find lib/")
      case _ if program == Program.Gradle && inputs.gradleUserHome.isEmpty =>
        Left("a gradle profile needs the user home it grants; without it every cache is a denial")
      case _ if program == Program.Mvn && inputs.distribution.isEmpty =>
        Left("an mvn profile needs the distribution its mvn runs from; without it the command cannot find lib/")
      case _ if program == Program.Sbt && inputs.sbtGlobal.isEmpty =>
        Left("an sbt profile needs the global base it grants; without it the server's own state is a denial")
      case _ if program == Program.Sbt && inputs.ivyHome.isEmpty =>
        Left("an sbt profile needs the Ivy home it grants; without it the local resolver is a denial")
      case _ if program == Program.Mvn && inputs.m2Repository.isEmpty =>
        Left("an mvn profile needs the local repository it grants; without it every resolution is a denial")
      case _ if program == Program.Mill && inputs.distribution.isDefined =>
        Left("a mill profile has no distribution to grant")
      case _ if networkProgram.exists(_ != program) =>
        Left(s"a ${program.name} profile has no ${networkProgram.get.name} server or daemon to reach")
      case _ if daemonPort.exists(port => port < 1 || port > 65535) =>
        Left(s"the daemon port ${daemonPort.get} is not a port")
      case _ if program != Program.Sbt && inputs.sbtGlobal.isDefined =>
        Left(s"a ${program.name} profile has no sbt global base to grant")
      case _ if program != Program.Sbt && inputs.ivyHome.isDefined =>
        Left(s"a ${program.name} profile has no Ivy home to grant")
      case _ if program != Program.Gradle && inputs.gradleUserHome.isDefined =>
        Left(s"a ${program.name} profile has no Gradle user home to grant")
      case _ if program != Program.Mvn && inputs.m2Repository.isDefined =>
        Left(s"a ${program.name} profile has no Maven local repository to grant")
      case Some(bad) => Left(invalidPathReason(bad))
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
          readOnly ++ readWriteExec ++ readWrite ++ inputs.systemPaths.reads ++ inputs.systemPaths.executes
            ++ DevicePaths ++ serverTmp,
        ))
          .foreach(path => lines += s"(allow file-read-metadata file-test-existence ${literal(path)})")
        lines += ""
        lines += ";; A process at all: not filesystem authority, and none of it reaches user data."
        lines += "(allow process-fork sysctl-read)"
        lines += MachLookup
        lines += Devices
        lines += ""
        lines += ";; System paths: measured by src/probe/run-on-host-profile-iterate.sh, never guessed."
        inputs.systemPaths.reads.foreach(path => lines += s"(allow file-read* ${subpath(path)})")
        inputs.systemPaths.executes.foreach: path =>
          lines += s"(allow process-exec* file-read* ${subpath(path)})"
        lines += ""
        lines += ";; The command's own programs, never writable by it."
        readOnly.foreach(path => lines += s"(allow process-exec* file-read* ${subpath(path)})")
        lines += ""
        lines += ";; What the command may change, and run: a child inherits this profile."
        readWriteExec.foreach(path => lines += s"(allow file-read* file-write* process-exec* ${subpath(path)})")
        lines += ";; Caches: reads and writes, but no direct process execution; the JVM can load their code."
        readWrite.foreach(path => lines += s"(allow file-read* file-write* ${subpath(path)})")
        lines += ""
        lines += ";; The command's own proxy, and no other destination."
        // Bazel's loopback spelling (DarwinSandboxedSpawnRunner, bazel#14828). "localhost" is the
        // only host the filter compiler accepts besides *, and it covers native 127.0.0.1 and ::1 —
        // not a dual-stack JVM's v4-mapped connect, which is why the command's environment sets
        // preferIPv4Stack (src/probe/jvm-proxy-rule.sh measured all of this).
        lines += s"""(allow network-outbound (remote ip "localhost:${inputs.proxyPort}"))"""
        // Seatbelt treats a UNIX-domain socket as network: without this, sbt's server gets EPERM
        // from bind() on its boot socket and the client waits for it forever. Confined to the
        // command's temporary directory, where the command's environment points XDG_RUNTIME_DIR and
        // SBT_GLOBAL_SERVER_DIR; measured that a socket outside the subpath stays denied.
        lines += ";; sbt's boot and server sockets, inside the command's temporary directory."
        lines += "(allow network-bind network-inbound network-outbound " +
          s"(local unix-socket ${subpath(inputs.sessionTmp)}) (remote unix-socket ${subpath(inputs.sessionTmp)}))"
        // The client attaches to the server socket the broker's server bound under the broker's
        // tmp/, `<SBT_GLOBAL_SERVER_DIR>/<hash>/sock`; the connect resolves the socket's own
        // directory, hence the metadata grant, and nothing there is read.
        serverTmp.foreach: tmp =>
          lines += ";; The broker's sbt server: its socket under the broker's temporary directory."
          lines += s"(allow file-read-metadata file-test-existence ${subpath(tmp)})"
          lines += s"(allow network-outbound (remote unix-socket ${subpath(tmp)}))"
        inputs.network match
          case Network.MillDaemon =>
            // "localhost:*", since the daemon binds port 0 and the filter names no range. No
            // outbound: the daemon and every JVM the build forks inherit this profile, and the
            // only spelling that would admit a connect to the daemon's port — chosen by the
            // kernel during the starter's own run, so no rule can name it — is
            // (remote ip "localhost:*"), which reaches every service of this host (Gradle's
            // grant; run-on-host.md "Network" records the cost). So the starter's own connect
            // is denied, which is what leaves the daemon behind, and the broker ends the starter
            // once the daemon listens rather than widen the grant (RunOnHostMillDaemons.endStarter).
            lines += ";; The mill daemon: listeners, any port, any address of this host; inherited by what the build" +
              " forks."
            lines += """(allow network-bind network-inbound (local ip "localhost:*"))"""
          case Network.MillClient(port) =>
            lines += ";; The broker's mill daemon, on the one port it was proved listening on."
            lines += s"""(allow network-outbound (remote ip "localhost:$port"))"""
          case Network.Gradle =>
            // Gradle's daemon, workers and file-lock socket bind port 0 and connect to each
            // other's, TCP and UDP; the client starts the daemon, so the grant is one profile's.
            lines += ";; Gradle: listeners, any port, any address of this host, and outbound to any port of this" +
              " host; inherited by what the build forks."
            lines += """(allow network-bind network-inbound (local ip "localhost:*"))"""
            lines += """(allow network-outbound (remote ip "localhost:*"))"""
          case Network.ProxyOnly | Network.SbtClient(_) => ()
        lines += ""
        lines += ";; The guard, last: repository state a later host git command would execute,"
        lines += ";; and the boundary configuration a later launch would read. Scoped to the project:"
        lines += ";; a .git a test builds in the command's temporary directory is removed with it, and no"
        lines += ";; host git ever runs there."
        GuardedNames.foreach: name =>
          lines +=
            s"(deny file-write* file-read* file-link (require-all ${subpath(prereqs.project)} ${anyDepth(name)}))"
        Right(lines.result().mkString("\n") + "\n")

  /**
   * The host proxy's inputs (run-on-host.md "The command's egress proxy"): what it runs from —
   * the native image, or the JDK of the jar form — what it loads, the class-path entries of the
   * jar form, and the system paths the command profile grants (RunOnHostSandbox.proxyInputs).
   */
  case class ProxyInputs(executables: Seq[Path], reads: Seq[Path], systemPaths: SystemPaths)

  /**
   * The profile every host proxy runs under, or the first reason it cannot be built. Nothing of
   * the user's is granted: no project, no cache, no write anywhere — its log is its inherited
   * stderr — and no working directory: the proxy runs from `/`, which the root component grants
   * (RunOnHostSandbox.startProxy).
   */
  def renderProxy(inputs: ProxyInputs): Either[String, String] =
    val everyPath = inputs.executables ++ inputs.reads ++ inputs.systemPaths.reads ++ inputs.systemPaths.executes
    everyPath.find(path => !isAbsoluteNormalized(path)) match
      case Some(bad) => Left(invalidPathReason(bad))
      case None if inputs.executables.isEmpty => Left("a proxy profile needs the executable the proxy runs from")
      case None =>
        val lines = Seq.newBuilder[String]
        lines += "(version 1)"
        lines += ";; Generated by SeatbeltProfile.renderProxy: the host proxy's own profile."
        lines += "(deny default)"
        lines += ""
        lines += ";; Path resolution authorizes every component (render's ancestor chain)."
        lines += RootComponent
        ancestorLiterals(everyPath ++ DevicePaths :+ ResolverSocket)
          .foreach(path => lines += s"(allow file-read-metadata file-test-existence ${literal(path)})")
        // The resolver's client spells its socket /var/run/mDNSResponder, and the root link is
        // not in the canonical chain above: without it every lookup fails with "nodename nor
        // servname provided" (measured: the acceptance test's proxy fetch rows, /var alone suffices).
        lines += ";; The root link the resolver's socket path goes through."
        lines += s"(allow file-read-metadata file-test-existence ${literal(ResolverSocketLink)})"
        lines += ""
        // Measured (src/probe/run-on-host-profile-iterate.sh ops on the JDK, then the proxy
        // itself with each family added in turn): sysctl-read for the JVM, and mach-lookup
        // (MachServices). No process-fork: the proxy forks nothing.
        lines += ";; A process at all."
        lines += "(allow sysctl-read)"
        lines += MachLookup
        lines += Devices
        lines += ""
        lines += ";; The system paths as reads alone: the proxy executes nothing but itself."
        (inputs.systemPaths.reads ++ inputs.systemPaths.executes).foreach: path =>
          lines += s"(allow file-read* ${subpath(path)})"
        lines += ""
        lines += ";; The proxy's own executable, and what it loads."
        inputs.executables.foreach(path => lines += s"(allow process-exec* file-read* ${subpath(path)})")
        inputs.reads.foreach(path => lines += s"(allow file-read* ${subpath(path)})")
        lines += ""
        // Which hosts a client may reach is the proxy's own decision, by name; SBPL filters by
        // address, so it decides nothing here.
        lines += ";; Every remote: host filtering is the proxy's job."
        lines += """(allow network-outbound (remote ip "*:*"))"""
        lines += ";; The resolver, which InetAddress.getAllByName reaches over this socket."
        lines += s"(allow network-outbound (remote unix-socket ${literal(ResolverSocket)}))"
        // The listener is the proxy's EGRESS_BIND, 127.0.0.1 port 0; "localhost:*" is the narrowest
        // class the filter compiles for a port it does not know (render's mill daemon rule).
        lines += ";; Its listener."
        lines += """(allow network-bind network-inbound (local ip "localhost:*"))"""
        Right(lines.result().mkString("\n") + "\n")

  /** Where macOS's resolver listens; `/var/run` is a link to it, and the filter matches the resolved path. */
  val ResolverSocket: Path = Path.of("/private/var/run/mDNSResponder")

  /** The root link the resolver's client goes through to reach ResolverSocket. */
  val ResolverSocketLink: Path = Path.of("/var")

  /**
   * The second half of the cs-installed `sbt`: the script execs an unpacked distribution inside the
   * Coursier archive cache. Its path encodes the download URL of whichever sbt Coursier installed,
   * so it is read out of the script rather than derived — and read rather than obtained by running
   * it: running the script is executing on the host, unconfined.
   *
   * The longest cache path the script names, because a shorter one is a prefix of the real answer
   * and a grant on a prefix is wider than it should be. Refused if it escapes the cache root.
   */
  def sbtDistribution(scriptText: String, coursierCacheRoot: Path): Option[Path] =
    val prefix = coursierCacheRoot.toString
    val candidates =
      for
        line <- scriptText.linesIterator
        start <- indexesOf(line, prefix)
        raw = line.drop(start).takeWhile(ch => ch != '"' && ch != '\'' && ch != ';' && ch != '\n')
        trimmed = raw.trim
        if trimmed.length > prefix.length
      yield trimmed
    candidates.toSeq.sortBy(-_.length).headOption
      .map(text => Path.of(text).normalize())
      .filter(_.startsWith(coursierCacheRoot))

  private def indexesOf(line: String, needle: String): Seq[Int] =
    Iterator
      .unfold(0): from =>
        line.indexOf(needle, from) match
          case -1    => None
          case index => Some((index, index + 1))
      .toSeq

  /** Absolute and already normalized. Symlink resolution happens before this, in RunOnHostPrereqs:
    * it needs the filesystem, and this stays pure. */
  private def isAbsoluteNormalized(path: Path): Boolean =
    path.isAbsolute && path.normalize() == path

  private def invalidPathReason(path: Path): String =
    s"$path is not absolute and normalized; supply an absolute path with no . or .. components " +
      "and resolve symlinks before rendering the profile"

  /** An SBPL string literal. Paths here contain spaces, `+` and percent signs; only a quote or a
    * backslash needs escaping, and neither occurs in a path this wrapper accepts. */
  private def sbpl(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

  private def subpath(path: Path): String = s"(subpath ${sbpl(path.toString)})"

  private def literal(path: Path): String = s"(literal ${sbpl(path.toString)})"

  /** The name at any depth, anchored so `.gitignore` and `.github` do not match. */
  private def anyDepth(name: String): String =
    s"""(regex #"/${name.replace(".", "\\.")}(/|$$)")"""
