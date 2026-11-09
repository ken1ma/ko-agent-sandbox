// The Seatbelt profiles that a host command and the host proxy run under (seatbelt.md; run-on-host-internals.md,
// "The command's egress proxy"). The code is pure, paths in and SBPL out, so unit tests check the generated SBPL
// without requiring macOS.
//
// Two properties of SBPL decide how paths are written and how rules are ordered here. src/probe/seatbelt-semantics.sh
// measured both:
//
//   - SBPL canonicalizes the path being *accessed*, but matches the rule *as written*. A rule naming a non-canonical
//     path can leave a deny unmatched and a broader allow in force. `render` therefore refuses every path that is not
//     absolute and normalized, and RunOnHostPrereqs resolves symlinks before a path gets here.
//   - Rules are last-match-wins, so the guard denies are emitted after every allow. A generator that appended a grant
//     later would silently reopen the guard, which is why nothing here takes extra rules from a caller.


package agentsandbox.launcher

import java.nio.file.Path

import RunOnHostPrereqs.{CommandPrereqs, Program}

object SeatbeltProfile:

  /**
   * The root directory entry.
   *
   *   - `(subpath "/")` is not the union of `(subpath "/child")` over every child. Resolving `/bin/sh` authorizes `/`
   *     first, and no grant on a child covers it.
   *   - Measured rather than reasoned: metadata alone is *not* sufficient, and `file-read*` is. Without `file-read*`, a
   *     process dies inside the loader before it has a stderr to report on.
   *   - The rule names the directory entry, not its contents, so it reveals nothing about what is on the disk.
   *   - A profile that reached for `(subpath "/")` instead would grant the whole filesystem. Such a grant is the
   *     obvious fix when only `(subpath "/")` appears to work.
   */
  val RootComponent: String = """(allow file-read* file-test-existence (literal "/"))"""

  /**
   * Every directory between `/` and a granted path, as a literal `file-read-metadata` plus `file-test-existence`.
   *
   *   - Resolving a path authorizes each component, and a `(subpath …)` grant covers what is *under* it, never the
   *     directories above.
   *   - Measured: with only the deep grants, `java -version` dies in the loader. With the chain present,
   *     `java -version` runs. A coarse `/Users` grant would stand in for the chain.
   *   - The chain grants metadata and not `file-read*`, because on a directory `file-read*` is its listing.
   *     A chain granted that way listed all of `~/Library/Caches` (SeatbeltCheck's row "list an ancestor of a granted
   *     path").
   *     Only the root entry needs the wider read.
   *
   * Apple spells the same rule with a built-in, `(apply path-ancestors …)` paired with `file-test-existence`
   * (`/System/Library/Sandbox/Profiles/dyld-support.sb`).
   *
   *   - Apple gives the reason for the root entry: the loader opens `/` to use as an `openat(2)` root.
   *   - Adopting the built-in would replace this enumeration with one rule per path. The built-in is worth adopting
   *     once it is shown to work under `(version 1)`.
   */
  def ancestorLiterals(paths: Seq[Path]): Seq[Path] =
    paths
      .flatMap(path => Iterator.iterate(path.getParent)(p => if p == null then null else p.getParent)
        .takeWhile(_ != null).toSeq)
      .distinct
      .filterNot(_.toString == "/")
      .sortBy(_.toString)

  /**
   * The character devices a JVM opens before it runs anything.
   *
   *   - `/dev/tty` is left out. Closing the child's stdin does not detach its controlling terminal, and a command that
   *     can open the terminal can read what the user types.
   *   - The random devices are read-only.
   */
  val DevicePaths: Seq[Path] = Seq("/dev/null", "/dev/random", "/dev/urandom").map(Path.of(_))

  val Devices: String =
    """(allow file-read* file-write-data (literal "/dev/null"))""" + "\n" +
      """(allow file-read* (literal "/dev/random") (literal "/dev/urandom"))"""

  /**
   * The Mach services that both profiles may look up, by name.
   *
   *   - An unfiltered `mach-lookup` reaches every service of the host, and a service may act for its caller outside
   *     the profile.
   *   - src/probe/run-on-host-profile-iterate.sh `mach-proxy` and `mach` measured the list. Without this name, the
   *     serving proxy dies of a segmentation fault, while `java -version` and `sbt about` run with no name at all.
   *   - A command gets the name unmeasured (seatbelt.md, "Mach services", has the reason).
   */
  val MachServices: Seq[String] = Seq("com.apple.system.opendirectoryd.libinfo")

  /**
   * Keeps a command from reading another process's arguments and environment through `sysctl(KERN_PROCARGS2)`.
   *
   *   - That call is the one behind `ps -E`, and the kernel answers it for any process of the same user.
   *   - The rule is agent-safehouse's (`profiles/10-system-runtime.sb`).
   *   - pidinfo stays allowed inside the inherited sandbox, where a build inspects its own children.
   *   - `ProcessHandle.of` still finds a process outside the sandbox, and its `info()` throws (seatbelt.md,
   *     "Processes").
   */
  val ProcessReadRule: Seq[String] = Seq(
    """(deny sysctl-read (sysctl-name-regex #"procargs"))""",
    "(deny process-info-pidinfo)",
    "(allow process-info-pidinfo (target same-sandbox))",
  )

  private val MachLookup: String =
    s"(allow mach-lookup ${MachServices.map(name => s"(global-name ${sbpl(name)})").mkString(" ")})"

  /** What the command may reach, beyond the prerequisites' paths, to start a JVM at all. The paths were discovered by
    * running a real build under this profile and reading the denials, never guessed. A system path is granted only
    * where testing proves the read is stable. */
  case class SystemPaths(reads: Seq[Path], executes: Seq[Path])

  /** The network authority beyond the proxy and the session's own UNIX sockets. The type shows in the dispatch which
    * program gets which authority. src/probe/run-on-host-runner-session.sh L1–L4, G1 and G7–G10 measured the cases.
    *
    *   - An sbt server and Maven get nothing more.
    *   - An sbt client gets the sockets under the runner's `tmp/`, where its server listens.
    *   - The mill daemon gets listeners on any port, at any address of this host:
    *     - Any port, since the daemon binds port 0 and no rule confines a bind to one port.
    *     - Any address, since the "localhost" class admits a wildcard bind.
    *     - Everything the daemon forks inherits the grant. A build under mill can therefore bind a listener that a LAN
    *       peer reaches, where a build under sbt or Maven gets EPERM (SECURITY.md, "Run on host").
    *   - A mill command that runs its build without a daemon (RunOnHostPrereqs.millRunsWithoutDaemon) gets the same,
    *     so that the build binds what it would under a daemon.
    *   - A mill client gets outbound to the daemon's one port (RunnerRuntimes, RunOnHostMillDaemons). The client also
    *     gets the daemon's arguments, which Mill's client reads to check that the daemon is the one that took its lock.
    *   - Gradle gets the mill daemon's grant plus outbound to any port of this host. Gradle's daemon, workers and
    *     file-lock socket bind port 0 and connect to each other's ports. The client starts the daemon itself, so one
    *     profile serves both. */
  enum Network:
    case ProxyOnly
    case SbtClient(serverTmp: Path)
    case MillDaemon
    case MillClient(daemonPort: Int, daemonPid: Long)
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
    // The directory of the proxy's CA certificate. The profile grants the two files in it that the command's
    // environment names (RunOnHostInspection).
    trust: Path,
    systemPaths: SystemPaths,
    network: Network,
    // The file rules and the workspace policy's guard paths (FileRules.Resolved): the workspace files that a host
    // program executes on an event, which the command must not write either.
    fileRules: FileRules.Resolved,
  )

  /**
   * The profile, or the first reason it cannot be built. A deny naming the wrong path could leave a broader allow in
   * force.
   */
  def render(inputs: ProfileInputs): Either[String, String] =
    val prereqs = inputs.prereqs
    // Distinct, because a mill build's java-home file may record the JDK that JAVA_HOME names.
    val readOnly = (Seq(prereqs.jdkHome) ++ inputs.distribution ++ Seq(prereqs.executable)).distinct
    // Tests write and run stubs in the workspace and the command's temporary directory. Children inherit the profile.
    // Caches need no process-exec grant, because the JVM loads their code by reading it.
    val readWriteExec = Seq(prereqs.workspaceRoot, inputs.sessionTmp)
    val readWrite =
      Seq(prereqs.coursierV1) ++ inputs.sbtGlobal ++ inputs.ivyHome ++ inputs.gradleUserHome ++ inputs.m2Repository
    val serverTmp = inputs.network match
      case Network.SbtClient(tmp) => Some(tmp)
      case _                      => None
    val networkProgram = inputs.network match
      case Network.ProxyOnly                             => None
      case Network.SbtClient(_)                          => Some(Program.Sbt)
      case Network.MillDaemon | Network.MillClient(_, _) => Some(Program.Mill)
      case Network.Gradle                                => Some(Program.Gradle)
    val (daemonPort, daemonPid) = inputs.network match
      case Network.MillClient(port, pid) => (Some(port), Some(pid))
      case _                             => (None, None)
    val trustFiles = Seq(RunOnHostInspection.caBundle(inputs.trust), RunOnHostInspection.trustStore(inputs.trust))
    val everyPath =
      readOnly ++ readWriteExec ++ readWrite ++ inputs.systemPaths.reads ++ inputs.systemPaths.executes ++ serverTmp
        :+ inputs.trust

    val program = prereqs.program
    val fileRuleFilters = SeatbeltProfile.fileRuleFilters(prereqs.workspaceRoot, inputs.fileRules)
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
      case _ if networkProgram.exists(_ != program) =>
        Left(s"a ${program.name} profile has no ${networkProgram.get.name} server or daemon to reach")
      case _ if daemonPort.exists(port => port < 1 || port > 65535) =>
        Left(s"the daemon port ${daemonPort.get} is not a port")
      case _ if daemonPid.exists(_ < 1) =>
        Left(s"the daemon pid ${daemonPid.get} is not a pid")
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
      case None if fileRuleFilters.isLeft => Left(fileRuleFilters.swap.getOrElse(""))
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
        // DevicePaths included: /dev needs its own literal like any other ancestor. Without it, the JVM cannot open
        // /dev/urandom, and SecureRandom then fails with "NativePRNG not available", which names the algorithm rather
        // than the path.
        (ancestorLiterals(
          readOnly ++ readWriteExec ++ readWrite ++ inputs.systemPaths.reads ++ inputs.systemPaths.executes
            ++ DevicePaths ++ serverTmp ++ trustFiles,
        ))
          .foreach(path => lines += s"(allow file-read-metadata file-test-existence ${literal(path)})")
        lines += ""
        lines += ";; A process at all: not filesystem authority, and none of it reaches user data."
        lines += "(allow process-fork sysctl-read)"
        lines += ";; No other process's arguments and environment: the read succeeds while either"
        lines += ";; the name or pidinfo is allowed, and (deny default) does not cover process-info*."
        lines ++= ProcessReadRule
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
        lines += ";; The CA of the command's proxy: outside tmp/, so no command replaces what the next one trusts."
        trustFiles.foreach(path => lines += s"(allow file-read* ${literal(path)})")
        lines += ""
        lines += ";; The command's own proxy, and no other destination."
        // Bazel's loopback spelling (DarwinSandboxedSpawnRunner, bazel#14828). "localhost" is the only host that the
        // filter compiler accepts besides *. It covers native 127.0.0.1 and ::1, but not a dual-stack JVM's v4-mapped
        // connect, which is why the command's environment sets preferIPv4Stack (src/probe/jvm-proxy-rule.sh measured
        // all of this).
        lines += s"""(allow network-outbound (remote ip "localhost:${inputs.proxyPort}"))"""
        // Seatbelt treats a UNIX-domain socket as network. Without this rule, sbt's server gets EPERM from bind() on
        // its boot socket, and the client waits for it forever. The rule is confined to the process's own `tmp/`,
        // where XDG_RUNTIME_DIR and SBT_GLOBAL_SERVER_DIR point for every profile but the sbt client's. The client's
        // point at the runner's `tmp/`, which Network.SbtClient grants. A socket outside the subpaths stays denied
        // (measured).
        lines += ";; sbt's boot and server sockets, inside the process's own tmp/."
        lines += "(allow network-bind network-inbound network-outbound " +
          s"(local unix-socket ${subpath(inputs.sessionTmp)}) (remote unix-socket ${subpath(inputs.sessionTmp)}))"
        // The client attaches to the server socket that the runner's server bound under the runner's tmp/,
        // `<SBT_GLOBAL_SERVER_DIR>/<hash>/sock`. The connect resolves the socket's own directory, hence the metadata
        // grant, and nothing there is read.
        serverTmp.foreach: tmp =>
          lines += ";; The runner's sbt server: its socket under the runner's temporary directory."
          lines += s"(allow file-read-metadata file-test-existence ${subpath(tmp)})"
          lines += s"(allow network-outbound (remote unix-socket ${subpath(tmp)}))"
        inputs.network match
          case Network.MillDaemon =>
            // "localhost:*", since the daemon binds port 0 and the filter names no range.
            //
            // No outbound connection is granted:
            //
            // - The daemon and every JVM the build forks inherit this profile.
            // - The kernel chooses the daemon's port during the starter's own run, so no rule can name it.
            // - The only spelling that would admit a connect to that port is (remote ip "localhost:*"), which reaches
            //   every service of this host. That spelling is Gradle's grant, and run-on-host-internals.md, "Network",
            //   records the cost.
            // - The starter's own connect is therefore denied, which is what leaves the daemon behind. The runner ends
            //   the starter once the daemon listens, rather than widening the grant (RunOnHostMillDaemons.endStarter).
            lines += ";; The mill daemon: listeners, any port, any address of this host; inherited by what the build" +
              " forks."
            lines += """(allow network-bind network-inbound (local ip "localhost:*"))"""
          case Network.MillClient(port, pid) =>
            lines += ";; The runner's mill daemon, on the one port it was observed listening on."
            lines += s"""(allow network-outbound (remote ip "localhost:$port"))"""
            // Mill's client checks the daemon that holds its lock with ProcessHandle.info(), which reads the daemon's
            // arguments (PidLock.isLockValid). The call throws under ProcessReadRule, because the daemon runs under a
            // sandbox-exec of its own. An allow of the one sysctl name `kern.procargs2.<pid>`, after the rule, opens
            // that read for the daemon alone (seatbelt.md, "Processes").
            lines += ";; The daemon's arguments, which Mill's client reads to check the daemon holds its lock; the" +
              " runner gave the daemon the client's own environment."
            lines += s"""(allow sysctl-read (sysctl-name "kern.procargs2.$pid"))"""
          case Network.Gradle =>
            // Gradle's daemon, workers and file-lock socket bind port 0 and connect to each other's ports, TCP and UDP.
            // The client starts the daemon, so one profile holds the grant.
            lines += ";; Gradle: listeners, any port, any address of this host, and outbound to any port of this" +
              " host; inherited by what the build forks."
            lines += """(allow network-bind network-inbound (local ip "localhost:*"))"""
            lines += """(allow network-outbound (remote ip "localhost:*"))"""
          case Network.ProxyOnly | Network.SbtClient(_) => ()
        lines += ""
        lines += ";; Workspace files a host program executes on an event, and the components their names"
        lines += ";; pass through: the file rules in order, then the workspace policy's guard paths and the"
        lines += ";; rules' rests below where symlinks lead. Reads stay allowed."
        for (protection, filter) <- fileRuleFilters.getOrElse(Vector.empty) do
          protection match
            case Protection.Writable => lines += s"(allow file-write* $filter)"
            case Protection.ReadOnly => lines += s"(deny file-write* file-link $filter)"
            case Protection.Pinned   => lines += s"(deny file-write-create file-write-unlink file-link $filter)"
        lines += ""
        lines += ";; The guard, last: repository state a later host git command would execute,"
        lines += ";; and the boundary configuration a later launch would read. Scoped to the workspace:"
        lines += ";; a .git a test builds in the command's temporary directory is removed with it, and no"
        lines += ";; host git ever runs there."
        FileRules.GuardedComponents.foreach: name =>
          lines +=
            s"(deny file-write* file-read* file-link (require-all ${subpath(prereqs.workspaceRoot)} ${anyDepth(name)}))"
        Right(lines.result().mkString("\n") + "\n")

  /**
   * The host proxy's inputs (run-on-host-internals.md, "The command's egress proxy"; RunOnHostProxy.proxyInputs):
   *
   *   - what the proxy runs from: the native image, or the JDK of the jar form;
   *   - what the proxy loads: the class-path entries of the jar form;
   *   - the system paths that the command profile grants.
   */
  case class ProxyInputs(executables: Seq[Path], reads: Seq[Path], systemPaths: SystemPaths)

  /**
   * The profile that every host proxy runs under, or the first reason it cannot be built. Nothing of the user's is
   * granted:
   *
   *   - no workspace and no cache;
   *   - no write anywhere, since the proxy's log is its inherited stderr;
   *   - no working directory, since the proxy runs from `/`, which the root component grants
   *     (RunOnHostProxy.startProxy).
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
        // The resolver's client spells its socket /var/run/mDNSResponder, and the root link is not in the canonical
        // chain above. Without this rule, every lookup fails with "nodename nor servname provided". The run-on-host
        // checks' proxy fetch rows measured this, and /var alone suffices.
        lines += ";; The root link the resolver's socket path goes through."
        lines += s"(allow file-read-metadata file-test-existence ${literal(ResolverSocketLink)})"
        lines += ""
        // The JVM needs sysctl-read, and mach-lookup (MachServices). src/probe/run-on-host-profile-iterate.sh measured
        // this with ops on the JDK, then with the proxy itself and each family added in turn. No process-fork, because
        // the proxy forks nothing.
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
        // The proxy itself decides by name which hosts a client may reach. SBPL filters by address, so SBPL decides
        // nothing here.
        lines += ";; Every remote: host filtering is the proxy's job."
        lines += """(allow network-outbound (remote ip "*:*"))"""
        lines += ";; The resolver, which InetAddress.getAllByName reaches over this socket."
        lines += s"(allow network-outbound (remote unix-socket ${literal(ResolverSocket)}))"
        // The listener is the proxy's EGRESS_BIND, 127.0.0.1 port 0. "localhost:*" is the narrowest class that the
        // filter compiles for a port it does not know (render's mill daemon rule).
        lines += ";; Its listener."
        lines += """(allow network-bind network-inbound (local ip "localhost:*"))"""
        Right(lines.result().mkString("\n") + "\n")

  /** Where macOS's resolver listens. Clients spell the socket `/var/run/mDNSResponder`, through the `/var` link
    * (ResolverSocketLink), and the filter matches the resolved path. */
  val ResolverSocket: Path = Path.of("/private/var/run/mDNSResponder")

  /** The root link the resolver's client goes through to reach ResolverSocket. */
  val ResolverSocketLink: Path = Path.of("/var")

  /** Absolute and already normalized. Symlink resolution happens before this check, in RunOnHostPrereqs, because
    * resolution needs the filesystem and this file stays pure. */
  private def isAbsoluteNormalized(path: Path): Boolean =
    path.isAbsolute && path.normalize() == path

  private def invalidPathReason(path: Path): String =
    s"$path is not absolute and normalized; supply an absolute path with no . or .. components " +
      "and resolve symlinks before rendering the profile"

  /** An SBPL string literal. Paths here contain spaces, `+` and percent signs. Only a quote or a backslash needs
    * escaping, and neither occurs in a path that this supervisor accepts. */
  private def sbpl(value: String): String =
    "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

  private def subpath(path: Path): String = s"(subpath ${sbpl(path.toString)})"

  private def literal(path: Path): String = s"(literal ${sbpl(path.toString)})"

  /**
   * What a file-rule filter does to writes:
   *
   *   - ReadOnly denies writes to the entry and everything below it;
   *   - Pinned denies creating and removing the entry alone;
   *   - Writable allows writes again to the entry and everything below it.
   */
  enum Protection:
    case ReadOnly, Pinned, Writable

  /**
   * The file rules as SBPL filters in the order they render, each with what it does, or the reason they cannot be
   * written. SBPL's last matching filter decides, as the workspace policy's last matching line does.
   *
   *   - Each line becomes a regex anchored after the workspace root's own path, with `*` as any run within one
   *     component. A `read-only` line becomes a deny, and a `writable` line an allow. The anchor keeps a directory
   *     above the workspace root that bears a listed name, such as a checkout named `mise`, from matching.
   *   - Before the line, each interior component of the line becomes a deny on the entry alone. A later line that
   *     matches the entry or an ancestor overrides that deny, as the workspace policy's pruning does.
   *     - The deny covers `file-write-create`, `file-write-unlink` and `file-link`. Seatbelt checks a rename's two
   *       sides, and both sides of a `RENAME_SWAP` exchange, as `file-write-create` and `file-write-unlink`
   *       (`src/probe/seatbelt-semantics.sh` E13, E14, E17).
   *     - The deny therefore also covers the component's `mkdir` and `rmdir`, which the workspace policy allows.
   *     - The deny leaves the entry's contents, mode and attributes to the other rules.
   *   - After every line come the guard's `read-only-path` entries by `subpath`, and its `pinned-path` entries and the
   *     interior components of both by `literal`.
   *   - Last comes each `read-only-under` rest, as a regex anchored at its directory, with its interior components
   *     pinned. A `writable` line that lifts part of a rest under the symlink's name stays unlifted here, although
   *     the workspace policy lifts it (doc/run-on-host-internals.md).
   *
   * An allow grants `file-write*` alone, the workspace's own grant, so it never widens the profile. A hard link to a
   * file that a `writable` line lifts inside a read-only directory stays denied.
   */
  def fileRuleFilters(workspaceRoot: Path, resolved: FileRules.Resolved): Either[String, Vector[(Protection, String)]] =
    val root = workspaceRoot.toString
    if root.contains('"') then Left(s"$workspaceRoot holds a double quote, which no SBPL regex can spell")
    else
      val prefix = "^" + escapeRegex(root) + "/(.*/)?"
      val lineFilters = resolved.lines.flatMap: line =>
        val components = line.name.split("/").toVector.map(globToRegex)
        val interiors = (1 until components.size).map: count =>
          Protection.Pinned -> s"""(regex #"$prefix${components.take(count).mkString("/")}$$")"""
        // After its interiors, so that the line decides an entry that it names whole at one alignment and as an
        // interior at another, such as `ax/ab` under `a*/a*`, as in the workspace policy.
        val protection = line.word match
          case FileRules.Word.ReadOnly => Protection.ReadOnly
          case FileRules.Word.Writable => Protection.Writable
        interiors :+ (protection -> s"""(regex #"$prefix${components.mkString("/")}(/|$$)")""")
      // An anchored path's interior components are pinned, as the workspace policy pins an anchored line's components.
      val interiors = (resolved.readOnlyPaths ++ resolved.pinnedPaths).flatMap: path =>
        val components = path.split("/").toVector
        (1 until components.size).map(count => components.take(count).mkString("/"))
      val paths =
        resolved.readOnlyPaths.map(Protection.ReadOnly -> _) ++
          (interiors ++ resolved.pinnedPaths).map(Protection.Pinned -> _)
      val underDirectories = resolved.readOnlyUnder.map(_(0))
      (paths.map(_(1)) ++ underDirectories)
        .map(relative => (relative, workspaceRoot.resolve(relative)))
        .find((relative, path) =>
          relative.isEmpty || !isAbsoluteNormalized(path) || !path.startsWith(workspaceRoot),
        ) match
        case Some((relative, _)) =>
          Left(s"the workspace policy's guard named '$relative', which is no path below $workspaceRoot")
        case None =>
          underDirectories.find(_.contains('"')) match
            case Some(relative) =>
              Left(
                s"the workspace policy's guard named '$relative', whose double quote no SBPL regex can spell; " +
                  "rename it on the host, then relaunch",
              )
            case None =>
              val pathFilters = paths.map: (protection, relative) =>
                protection match
                  case Protection.ReadOnly => protection -> subpath(workspaceRoot.resolve(relative))
                  case _                   => protection -> literal(workspaceRoot.resolve(relative))
              val underFilters = resolved.readOnlyUnder.flatMap: (relative, rest) =>
                val under = "^" + escapeRegex(workspaceRoot.resolve(relative).toString) + "/"
                val components = rest.split("/").toVector.map(globToRegex)
                val restInteriors = (1 until components.size).map: count =>
                  Protection.Pinned -> s"""(regex #"$under${components.take(count).mkString("/")}$$")"""
                restInteriors :+ (Protection.ReadOnly -> s"""(regex #"$under${components.mkString("/")}(/|$$)")""")
              // Of two equal filters, the later one is kept, because dropping an earlier copy changes no last match.
              Right((lineFilters ++ pathFilters ++ underFilters).reverse.distinct.reverse)

  private def escapeRegex(text: String): String =
    text.flatMap(ch => if "\\^$.|?*+()[]{}".contains(ch) then s"\\$ch" else ch.toString)

  /** A rule component, whose characters are a-z, 0-9, `.`, `_`, `-` and `*` (FileRules.parse). */
  private def globToRegex(component: String): String =
    component.flatMap:
      case '*' => "[^/]*"
      case '.' => "\\."
      case ch  => ch.toString

  /**
   * A guarded name (FileRules.GuardedComponents) at any depth under the workspace root.
   *
   *   - The rule is a pattern by intent, and the only regex besides the file rules' (fileRuleFilters). Everything else
   *     is a supervisor-supplied path, which a regex would mangle. The Coursier JDK home alone contains a
   *     percent-encoded `+`, a literal `+` and dots.
   *   - The workspace root itself is kept out of the pattern the same way. `(require-all (subpath …) (regex …))`
   *     conjoins a literal filter with the name pattern.
   *   - The trailing `(/|$)` is what stops `.gitignore` and `.github` from matching.
   *   - The pattern is lowercase alone. On a case-insensitive volume, it matches the other spellings measured
   *     (seatbelt.md, "Paths").
   */
  private def anyDepth(name: String): String =
    s"""(regex #"/${name.replace(".", "\\.")}(/|$$)")"""
