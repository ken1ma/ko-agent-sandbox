#!/usr/bin/env -S scala shebang
//> using scala 3.10.1
//> using file ../test/scala/HostDriver.scala
//> using file ../test/scala/RunOnHostIdle.scala
//> using file ../test/scala/RunOnHostChecks.scala

/*
  Discovers the profile's system paths (seatbelt.md, "System paths") the only way that the profile allows: by running
  a real build and reading what the build needs, never by listing what the host happens to have. Run the probe when a
  command stops under the profile and nothing names the missing grant.

  `(debug deny)` makes denials visible; Bazel's darwin-sandbox puts it at the top of every generated profile. The
  other instruments fail:
  - `(trace)` is restricted on macOS 26 and writes nothing;
  - unified-log denials have their paths redacted unless private-data logging is enabled system-wide.

  The searches below rely on none of these instruments. Whether the command works is always reliable, so the searches
  start from a set that runs and remove grants cumulatively, keeping only grants whose absence breaks the command.

  Run the probe on the macOS HOST, from the repository root, with no sandbox session of this workspace running with
  --run-on-host:

      src/probe/RunOnHostProfileIterate.scala checks         # which check fails? run this first
      src/probe/RunOnHostProfileIterate.scala ops "<command>"    # which operations does it need?
      src/probe/RunOnHostProfileIterate.scala paths          # what does /bin/sh need?
      src/probe/RunOnHostProfileIterate.scala paths "$JAVA_HOME/bin/java -version"   # ... or the JDK
      src/probe/RunOnHostProfileIterate.scala narrow         # drop every grant that is not needed
      src/probe/RunOnHostProfileIterate.scala mach-route     # does `open` start a program outside the profile?
      src/probe/RunOnHostProfileIterate.scala mach ["<sbt command>"]   # which Mach services does sbt fail without?
      src/probe/RunOnHostProfileIterate.scala mach-proxy [native-image]   # ... and the host proxy, in either form?
      src/probe/RunOnHostProfileIterate.scala procargs   # can a command read another process's environment?

  Whether the current grant set builds is the question of the run-on-host checks (src/test/run-on-host/), not of this
  probe.

  System paths accumulate in src/main/resources/agentsandbox/SeatbeltProfile.SystemPaths.txt, which you edit by hand.
  A line added because a command failed once is a grant that outlives every later command, so a path belongs there
  only if it is a stable runtime read and not a path into user data.
*/

import agentsandbox.launcher.HostDriver
import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.*
import agentsandbox.launcher.RunOnHostIdle

import java.nio.file.{Files, Path, StandardCopyOption}

import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.Using

@main def iterate(args: String*): Unit = RunOnHostProfileIterate.run(args)

object RunOnHostProfileIterate:
  val usage =
    "usage: src/probe/RunOnHostProfileIterate.scala [checks|ops|paths|narrow|mach-route|mach|mach-proxy|procargs] " +
      "[command|native-image]"

  def run(args: Seq[String]): Unit =
    orExit(Either.cond(sys.props("os.name") == "Mac OS X", (), "Run this on macOS."))
    val root = orExit(repositoryRoot(SystemPathsFile))
    val uid = com.sun.security.auth.module.UnixSystem().getUid.toInt
    RunOnHostIdle.requireIdle(RunOnHostIdle.supervisorRoot(uid), Seq(root.toRealPath())).left.foreach: refusal =>
      System.err.println(refusal)
      sys.exit(1)
    val probe = Probe(root, args.lift(1))
    args.headOption.getOrElse("checks") match
      case "ops"        => probe.ops()
      case "paths"      => probe.paths()
      case "checks"     => probe.checks()
      case "narrow"     => probe.narrow()
      case "mach-route" => probe.machRoute()
      case "mach"       => probe.mach()
      case "mach-proxy" => probe.machProxy()
      case "procargs"   => probe.procargs()
      case _            => fail(usage, 2)

  /** What `emit` wrote: the log, whose lines name the run-on-host cache and the executable, and the command's
    * temporary directory, which the profile grants. */
  case class Emitted(log: String, sessionTmp: Path):
    def value(prefix: String): Option[String] =
      log.linesIterator.collectFirst { case line if line.startsWith(prefix) => line.stripPrefix(prefix) }
    def coursierV1: String = value("run-on-host cache: ").getOrElse(fail("emit printed no run-on-host cache"))

  /** Only these SBPL families take a path filter. An unfiltered family, such as sysctl-read, inside an
    * (allow ... (subpath ...)) makes the whole profile invalid. */
  def pathFamily(family: String): Boolean =
    Seq("file-read", "file-write", "process-exec").exists(family.startsWith)
      || family == "file-map-executable" || family == "file-ioctl"

  def fail(message: String, status: Int = 1): Nothing =
    System.err.println(message)
    sys.exit(status)

  class Probe(root: Path, argument: Option[String]):
    val work: Path = Path.of(sys.env.getOrElse("TMPDIR", "/tmp")) / "ko-agent-run-on-host-profile"
    val systemPaths: Path = root / SystemPathsFile
    val operationsFile: Path = root / "src" / "probe" / "seatbelt-runtime-operations.txt"
    val commandProfile: Path = work / "command.sb"
    val sbtCommand: String = argument.getOrElse("about")
    Files.createDirectories(work)
    if !Files.exists(systemPaths) then
      Files.writeString(systemPaths,
        "# One absolute path per line. Prefix with \"x \" if it must also be executable.\n")

    def javaHome: String = sys.env.get("JAVA_HOME").filter(_.nonEmpty)
      .getOrElse(fail("set JAVA_HOME to the JDK the profile grants"))

    // --- Running under a profile ------------------------------------------------------------------------------

    /** Renders the sbt command profile for this checkout from the system-paths file given, or says why it failed. */
    def emit(paths: Path): Option[Emitted] =
      Files.deleteIfExists(work / "command.env")
      val output = HostDriver.run(Seq("sbt", "-batch",
        s"Test/runMain agentsandbox.launcher.EmitRunOnHostProfile \"$commandProfile\" \"$paths\""))
      Files.writeString(work / "emit.log", output.text)
      if !output.ok then
        println("emit failed:")
        println(output.text.linesIterator.toSeq.takeRight(20).mkString("\n"))
        None
      else
        Files.move(work / "command.sb.env", work / "command.env", StandardCopyOption.REPLACE_EXISTING)
        Files.readAllLines(work / "command.env").asScala
          .collectFirst { case line if line.startsWith("SESSION_TMP=") => line.stripPrefix("SESSION_TMP=") }
          .map(tmp => Emitted(output.text, Path.of(tmp)))

    def emitOrExit(): Emitted = emit(systemPaths).getOrElse(sys.exit(1))

    def endSbtServer(): Unit = HostDriver.run(Seq("sbt", "--jvm-client", "-batch", "shutdown"))

    /**
     * Runs an sbt command under the profile, writing both streams to the log.
     *
     *   - It passes -java-home because the sbt script declares `java_cmd=java` and would otherwise resolve
     *     /usr/bin/java from PATH, which the profile does not grant.
     *   - It passes no -Dsbt.server.autostart=false, which sbt 2 cannot honour: sbt 2's own --no-server means "run
     *     sbtn, and fail if it cannot connect to a server", and sets that same flag. sbt 2 is client/server by
     *     construction, so the server starts inside the sandbox, and the server's state goes to the command's
     *     temporary directory with everything else.
     *   - The environment takes from the supervisor's closed set (RunOnHostSandbox): COURSIER_CACHE routes to the
     *     run-on-host cache; _JAVA_OPTIONS reaches the server that the client forks, where -D flags do not; the two
     *     socket directories keep sbt inside the command's temporary directory.
     *   - `boundSeconds` ends the client, which waits without end for a server that a denied lookup ended.
     */
    def runCommand(emitted: Emitted, log: Path, profile: Path = commandProfile, command: String = sbtCommand,
        cwd: Path = root, boundSeconds: Option[Int] = None): Boolean =
      val tmp = emitted.sessionTmp
      val output = HostDriver.run(
        Seq("/usr/bin/sandbox-exec", "-f", profile.toString, "sbt", s"-Dsbt.global.base=$tmp/sbt-global",
          "--jvm-client", "-batch", "-java-home", javaHome, command),
        cwd = cwd, timeoutSeconds = boundSeconds,
        environment = Map(
          "PATH" -> s"$javaHome/bin:${sys.env.getOrElse("PATH", "")}",
          "COURSIER_CACHE" -> emitted.coursierV1,
          "XDG_RUNTIME_DIR" -> tmp.toString,
          "SBT_GLOBAL_SERVER_DIR" -> tmp.toString,
          "_JAVA_OPTIONS" -> (s"-Djava.io.tmpdir=$tmp -Djava.util.prefs.userRoot=$tmp " +
            s"-Dsbt.global.base=$tmp/sbt-global -Dsbt.ivy.home=$tmp/ivy-home"),
          "SBT_LOCAL_CACHE" -> s"$tmp/sbt-global/cache",
        ))
      Files.writeString(log, output.text)
      output.ok

    def dumpProfile(profile: Path): Unit =
      println("--- profile ---")
      Files.readAllLines(profile).asScala.foreach(line => println(s"   $line"))
      println("---------------")

    /** Whether the shell command runs under the profile. A profile that sandbox-exec cannot compile fails exactly as
      * a missing grant does: the child dies either way. The difference shows in sandbox-exec's own message, so the
      * probe reports a profile that will not compile as such rather than as a denial. */
    def attemptProfile(profile: Path, shellCommand: String): Boolean =
      val output = HostDriver.run(Seq("/usr/bin/sandbox-exec", "-f", profile.toString, "/bin/sh", "-c", shellCommand))
      val compileError = "(?i).*sandbox-exec:.*(compil|syntax|unable|invalid).*".r
      if output.ok then true
      else
        output.text.linesIterator.filter(compileError.matches).toSeq match
          case Seq() => false
          case errors =>
            println()
            println("!! the profile does not compile — this is not a missing grant:")
            errors.foreach(line => println(s"   $line"))
            dumpProfile(profile)
            sys.exit(1)

    // --- ops ---------------------------------------------------------------------------------------------------

    /** Finds which SBPL operation families a command needs, by the same cumulative removal that `paths` uses. Paths
      * stay wide open at (subpath "/"), so that only the operation varies. Run this mode first when `paths` reports
      * that granting every root entry still fails: that is what "not only a path" looks like, and a search that holds
      * operations fixed cannot see it. */
    def ops(): Unit =
      val probeCommand = argument.getOrElse("/bin/sh -c 'echo ok'")
      val opsProfile = work / "ops.sb"
      // A family under test must be truly absent when dropped. An unconditional
      // (allow file-read* file-map-executable process-exec* (subpath "/")) would re-grant three of the families being
      // measured and make their removal untestable. Path-filtered families take (subpath "/"). The other families
      // take no filter, because a filter is a syntax error for them.
      def tryOps(families: Seq[String]): Boolean =
        val rules = families.map(family =>
          if pathFamily(family) then s"""(allow $family (subpath "/"))""" else s"(allow $family)")
        Files.write(opsProfile, (Seq("(version 1)", "(debug deny)", "(deny default)") ++ rules).asJava)
        attemptProfile(opsProfile, probeCommand)
      var keep = Vector("file-read*", "file-write*", "file-map-executable", "process-exec*", "process-fork",
        "process-info*", "sysctl-read", "sysctl-write", "mach-lookup", "mach-register", "ipc-posix-shm",
        "ipc-posix-sem", "signal", "network*", "system-socket", "iokit-open", "pseudo-tty", "file-ioctl")

      println(s"measuring: $probeCommand")
      if !tryOps(keep) then
        System.err.println("every family granted and it still fails — the command is broken, not the profile.")
        dumpProfile(opsProfile)
        sys.exit(1)
      println("all families: PASS. Removing cumulatively:")
      for family <- keep do
        val candidate = keep.filterNot(_ == family)
        if tryOps(candidate) then
          println(s"  drop    $family")
          keep = candidate
        else println(s"  KEEP    $family")
      // Greedy removal finds *a* minimal set, not *the* minimal one. Where two families are interchangeable, the
      // removal keeps whichever it happened to test last, which is how sysctl-write can survive while sysctl-read
      // drops. Try the weaker spelling of each family before believing the result.
      println()
      println("downgrades — is a weaker family enough?")
      for (strong, weak) <- Seq("sysctl-write" -> "sysctl-read", "file-write*" -> "file-read*",
          "mach-register" -> "mach-lookup") if keep.contains(strong)
      do
        val candidate = keep.filterNot(_ == strong) :+ weak
        if tryOps(candidate) then
          println(s"  $weak suffices in place of $strong")
          keep = candidate
        else println(s"  $strong is genuinely needed; $weak is not enough")

      println()
      dumpProfile(opsProfile)
      println(s"the operations it needs: ${keep.mkString(" ")}")
      Files.writeString(operationsFile, keep.mkString(" ") + "\n")
      println(s"written to ${root.relativize(operationsFile)}, which 'paths' uses as its base")

    // --- paths -------------------------------------------------------------------------------------------------

    /**
     * Finds the minimal set of trees that the command needs, /bin/sh by default, by cumulative removal.
     *
     * Testing each denial independently cannot work here. A loader can reach what it needs by more than one route, so
     * the command survives every single removal, and the "individually required" set comes out empty while the union
     * of those removals fails. Cumulative removal drops a tree only if the remaining set still works. `narrow` uses
     * the same algorithm, and the algorithm converges.
     */
    def paths(): Unit =
      // Grant the families that `ops` measured, so that a missing operation does not defeat the path search. Without
      // these families, the JDK reports "not a path" when the truth is "not only a path".
      val families =
        if Files.isRegularFile(operationsFile) then Files.readString(operationsFile).split("\\s+").filter(_.nonEmpty)
          .toSeq
        else Seq("file-read*", "process-exec*")
      // The search measures the JDK rather than assuming its paths. Seeding the *bundle* rather than JAVA_HOME only
      // widens the starting point. The descent pass then reports whether Contents/Home would have sufficed, so "a
      // macOS JDK needs libjli.dylib from Contents/MacOS" is a result rather than a premise.
      val jdkSeed = sys.env.get("JAVA_HOME").filter(_.nonEmpty).map: home =>
        if home.endsWith("/Contents/Home") then home.stripSuffix("/Home") else home
      var keep: Vector[String] =
        ((entries(Path.of("/"), dotFiles = true) ++ entries(Path.of("/private"), dotFiles = false)).map(_.toString)
          .sorted ++ jdkSeed).filter(entry => Files.exists(Path.of(entry)))
      val pathsProfile = work / "paths.sb"
      // `granted` holds what is already granted, so that the measurement answers "what *else*" rather than
      // rediscovering the prerequisites' paths.
      val granted = Files.readAllLines(systemPaths).asScala.filterNot(line => line.isEmpty || line.startsWith("#"))
        .map(line => s""" (subpath "${line.stripPrefix("x ")}")""").mkString
      var base = "(deny default)"
      def profileFrom(trees: Seq[String]): Unit =
        val (filtered, unfiltered) = families.partition(pathFamily)
        val grants = trees.map: tree =>
          if tree.startsWith("L ") then s""" (literal "${tree.stripPrefix("L ")}")""" else s""" (subpath "$tree")"""
        val lines = Seq("(version 1)", "(debug deny)", base) ++ unfiltered.map(family => s"(allow $family)") :+
          s"(allow${filtered.map(" " + _).mkString}$granted${grants.mkString})"
        Files.write(pathsProfile, lines.asJava)
      val probeCommand = argument.getOrElse("/bin/sh -c 'echo ok'")
      def passes(trees: Seq[String]): Boolean =
        profileFrom(trees)
        attemptProfile(pathsProfile, probeCommand)
      def removeCumulatively(report: Boolean): Unit =
        for tree <- keep do
          val candidate = keep.filterNot(_ == tree)
          if passes(candidate) then
            if report then println(s"  drop    $tree")
            keep = candidate
          else if report then println(s"  KEEP    $tree")

      println(s"measuring: $probeCommand")
      // (subpath "/") passes while the union of every (subpath "/child") fails, so the missing grant is the root
      // component itself: resolving /bin/sh authorizes "/" before "/bin". The cost depends on which grant on "/"
      // suffices: a literal names the directory entry alone and reveals nothing about the directory's contents.
      val rootGrant = Seq(
        """(allow file-read-metadata (literal "/"))""",
        """(allow file-read* (literal "/"))""",
        """(allow file-read* file-map-executable process-exec* (literal "/"))""",
      ).find: candidate =>
        base = s"(deny default)$candidate"
        passes(keep)
      rootGrant match
        case Some(candidate) => println(s"root component: $candidate is enough")
        case None =>
          base = "(deny default)"
          System.err.println("no grant on \"/\" alone rescues the union — the gap is not a path.")
          dumpProfile(pathsProfile)
          sys.exit(1)
      println("all root entries: PASS. Removing cumulatively:")
      removeCumulatively(report = true)
      println()
      // A kept root entry is rarely the answer: /System is required, but a command has no business reading all of
      // it. The pass tries to replace each entry with its children and keeps the descent only while the command still
      // works, so the result is as deep as the evidence allows.
      println()
      println("descending into each kept tree:")
      var changed = true
      while changed do
        changed = false
        val descended = keep.iterator.filterNot(_.startsWith("L ")).flatMap: tree =>
          val children = entries(Path.of(tree), dotFiles = false).map(_.toString).sorted
          // The entry itself stays as a literal: resolving a child authorizes the child's parent as a path component,
          // and a grant on the children does not cover the parent. Without the literal, a tree can never be
          // descended, and the result reads as "the whole tree is required".
          val candidate = keep.filterNot(_ == tree) ++ (s"L $tree" +: children)
          Option.when(children.nonEmpty && passes(candidate))((tree, children.size, candidate))
        .nextOption()
        descended.foreach: (tree, count, candidate) =>
          println(s"  descend $tree -> $count children")
          keep = candidate
          changed = true
          removeCumulatively(report = false)

      println()
      println("the minimal set it needs:")
      keep.foreach(tree => println(s"  $tree"))
      // Regenerate the profile, because the last profile written was a failed attempt, not the answer.
      profileFrom(keep)
      dumpProfile(pathsProfile)
      println()

    // --- checks ------------------------------------------------------------------------------------------------

    /** A process that dies before writing anything says nothing about which grant is missing. This mode runs checks
      * in order, from the smallest possible program to a real build, and stops at the first check that fails, so the
      * missing grant is one that this check already needs. The output goes to the terminal: the reason usually goes
      * there, and capturing it would lose it. */
    def checks(): Unit =
      emitOrExit()
      def check(label: String, command: String*): Unit =
        println()
        println(s"--- $label")
        val status = ProcessBuilder(("/usr/bin/sandbox-exec" +: "-f" +: commandProfile.toString +: command)*)
          .inheritIO().start().waitFor()
        if status == 0 then println("    ok")
        else
          println(s"    FAILED (exit $status) — this check is the first to require the missing grant")
          sys.exit(1)
      // The checks run only binaries that the profile grants: a check that fails because it reached for an ungranted
      // binary says nothing about the program it claims to test.
      check("the loader, through a granted shell", "/bin/sh", "-c", "echo hello")
      check("the sbt script's interpreter: /usr/bin/env sh", "/usr/bin/env", "sh", "-c", "echo hello")
      check("bash, which the inner sbt script needs", "/bin/bash", "-c", "echo hello")
      check("the coreutils that script calls", "/bin/bash", "-c", "uname -s; dirname /a/b; basename /a/b")
      check("the JDK", s"$javaHome/bin/java", "-version")
      check("the sbt script, no build", "sbt", "-java-home", javaHome, "--script-version")
      println()
      println("every check passed; the run-on-host checks are next: SeatbeltCheck.scala, then BuildsCheck.scala")
      println(s"  in $ChecksPath/")

    // --- narrow ------------------------------------------------------------------------------------------------

    def narrow(): Unit =
      val emitted = emitOrExit()
      if !runCommand(emitted, work / "base.log") then
        fail("the current grant set does not run the command; fix that with the run-on-host checks first.")
      println("the baseline runs the command. Removing one grant at a time.")
      val grants = Files.readAllLines(systemPaths).asScala.toVector.filterNot(_.matches("\\s*(#.*)?"))
      val without = work / "without.txt"
      val kept = grants.filter: line =>
        Files.write(without, grants.filterNot(_ == line).asJava)
        val needed = !emit(without).exists(runCommand(_, work / "try.log"))
        println(s"  ${if needed then "KEEP" else "drop"}    $line")
        needed
      val keptFile = work / "kept.txt"
      Files.write(keptFile, kept.asJava)
      println()
      println(s"the grants that earned their place: $keptFile")
      println(s"review it, then replace the body of ${root.relativize(systemPaths)} with it.")

    // --- mach-route --------------------------------------------------------------------------------------------

    /** Measures whether a command, with /usr/bin executable, starts a program outside the profile through
      * LaunchServices. The confined rows run under the rendered profile with mach-lookup unfiltered, so that a row
      * that starts nothing shows a barrier other than the profile's one Mach service. Each confined row has a
      * control, the same `open` unconfined. A control that starts nothing, because of an approval prompt or a changed
      * default application, leaves its row undecided. */
    def machRoute(): Unit =
      emitOrExit()
      val route = root / "target" / "mach-route"
      removeTree(route)
      Files.createDirectories(route)
      val unfiltered = work / "mach-route.sb"
      machProfile(commandProfile, None, unfiltered)
      def confined(shell: String): Output =
        HostDriver.run(Seq("/usr/bin/sandbox-exec", "-f", unfiltered.toString, "/bin/sh", "-c", shell))
      def row(label: String, value: String): Unit = println(f"$label%-64s $value")
      val confinedLabel = "  under the profile, mach-lookup unfiltered"
      def firstLine(output: Output): String = output.text.linesIterator.nextOption().getOrElse("")

      // R1: an application that the system ships.
      def calculatorRuns: Boolean = HostDriver.run(Seq("/usr/bin/pgrep", "-x", "Calculator")).ok
      def quitCalculator(): Unit =
        HostDriver.run(Seq("/usr/bin/pkill", "-x", "Calculator"))
        within(10, 500)(!calculatorRuns)
      if calculatorRuns then fail("Quit Calculator first: R1 tells a start by whether it runs.", 2)
      println("R1 open -a Calculator")
      HostDriver.run(Seq("/usr/bin/open", "-g", "-a", "Calculator"))
      val r1Control = within(10, 500)(calculatorRuns)
      row("  control, unconfined", if r1Control then "STARTED" else "not started: R1 decides nothing")
      quitCalculator()
      if r1Control then
        val opened = confined("/usr/bin/open -g -a Calculator")
        if within(10, 500)(calculatorRuns) then
          row(confinedLabel, "STARTED: LaunchServices is reachable")
        else row(confinedLabel, s"not started (open exited ${opened.status}: ${firstLine(opened)})")
        quitCalculator()

      // R2: a program that the command wrote, run by Terminal, which no profile confines. The marker lies where the
      // profile denies a write, so the marker's existence shows that the program ran outside the profile.
      println("R2 open WORKSPACE/target/mach-route/<script>.command (it opens Terminal windows; close them after)")
      def scriptText(marker: Path): String = s"#!/bin/sh\n: > ${shellQuoted(marker)}\n"
      val controlMarker = work / "mach-route-marker-control"
      val confinedMarker = work / "mach-route-marker-confined"
      Seq(controlMarker, confinedMarker).foreach(Files.deleteIfExists)
      val controlScript = route / "control.command"
      Files.writeString(controlScript, scriptText(controlMarker))
      controlScript.toFile.setExecutable(true)
      HostDriver.run(Seq("/usr/bin/open", "-g", controlScript.toString))
      if !within(20, 500)(Files.exists(controlMarker)) then
        row("  control, unconfined", "did not run: R2 decides nothing")
      else
        row("  control, unconfined", "RAN")
        if confined(s": > ${shellQuoted(confinedMarker)}").ok || Files.exists(confinedMarker) then
          row(confinedLabel, "the marker is writable under the profile: R2 decides nothing")
        else
          val script = route / "confined.command"
          Files.writeString(route / "text", scriptText(confinedMarker))
          val opened = confined(s"cp ${shellQuoted(route / "text")} ${shellQuoted(script)} && " +
            s"chmod +x ${shellQuoted(script)} && /usr/bin/open -g ${shellQuoted(script)}")
          if within(20, 500)(Files.exists(confinedMarker)) then
            row(confinedLabel, "RAN: a program the command wrote ran outside the profile")
          else row(confinedLabel, s"did not run (open exited ${opened.status}: ${firstLine(opened)})")
          row("  extended attributes of the script the command wrote",
            HostDriver.run(Seq("/usr/bin/xattr", script.toString)).text.linesIterator.mkString(" "))
      removeTree(route)
      Seq(controlMarker, confinedMarker).foreach(Files.deleteIfExists)

    // --- mach-lookup -------------------------------------------------------------------------------------------

    /** Writes a rendered profile with its mach-lookup rule (SeatbeltProfile.MachServices) replaced in place, so that
      * the guard denies stay last. The replacement is one global-name rule per name. With no names, the replacement
      * is the unfiltered grant: the baseline, because a JDK or a build may need a service that the rendered rule does
      * not name, and finding such services is what the search is for. */
    def machProfile(rendered: Path, names: Option[Seq[String]], out: Path): Unit =
      val rules =
        names.fold(Seq("(allow mach-lookup)"))(_.map(name => s"""(allow mach-lookup (global-name "$name"))"""))
      val lines = Files.readAllLines(rendered).asScala.toSeq
      val machRule = """\(allow mach-lookup \(global-name .*\)""".r
      if !lines.exists(machRule.matches) then
        fail(s"$rendered has no mach-lookup rule to replace; this mode measures nothing there.")
      Files.write(out, lines.flatMap:
        case "(version 1)" => Seq("(version 1)", "(debug deny)")
        case line if machRule.matches(line) => rules
        case line => Seq(line)
      .asJava)

    /**
     * The names that a launchd job definition registers: the MachServices keys of the launchd plists under
     * /System/Library, /Library and ~/Library, and the names in mach-extra.txt.
     *
     *   - A key of a nested dictionary (ResetAtClose, HideUntilCheckIn) comes along as a name that no service has; the
     *     search drops that name like any other.
     *   - Names that a process registers at run time are not in the plists. `machSearch` says so when the full list
     *     does not run the command, and mach-extra.txt takes those names.
     */
    def machCandidates(): Vector[String] =
      val userAgents = Path.of(sys.env.getOrElse("HOME", "")) / "Library" / "LaunchAgents"
      val directories = Seq("/System/Library/LaunchDaemons", "/System/Library/LaunchAgents", "/Library/LaunchDaemons",
        "/Library/LaunchAgents").map(Path.of(_)) :+ userAgents
      val key = ".*<key>(.*)</key>.*".r
      val found = for
        directory <- directories if Files.isDirectory(directory)
        plist <- entries(directory, dotFiles = false).filter(_.toString.endsWith(".plist")).sorted
        if Files.isRegularFile(plist)
        output = HostDriver.run(Seq("/usr/bin/plutil", "-extract", "MachServices", "xml1", "-o", "-", plist.toString))
        if output.ok
        case key(name) <- output.text.linesIterator
      yield name
      if !Files.exists(machExtra) then Files.writeString(machExtra, "")
      (found ++ Files.readAllLines(machExtra).asScala)
        .filterNot(name => name.isEmpty || name.exists("\"\\&".contains(_))).distinct.sorted.toVector

    def machExtra: Path = work / "mach-extra.txt"

    /** Drops `chunk` from `keep` if `passes` still succeeds without it, and otherwise halves the chunk, down to single
      * names. This is cumulative removal as `paths` does it, by halves because the candidates are thousands and the
      * needed names few. Like `ops`, the removal is greedy: of two interchangeable names, it keeps the one that it
      * tested last. */
    def machReduce(passes: Seq[String] => Boolean, keep: Seq[String], chunk: Seq[String]): Seq[String] =
      var kept = keep
      val queue = mutable.Queue(chunk)
      while queue.nonEmpty do
        val part = queue.dequeue()
        val without = kept.filterNot(part.toSet)
        if part.isEmpty then ()
        else if passes(without) then
          println(s"  drop    ${if part.size == 1 then part.head else s"${part.size} names"}")
          kept = without
        else if part.size == 1 then println(s"  KEEP    ${part.head}")
        else
          val (first, second) = part.splitAt((part.size + 1) / 2)
          queue.prependAll(Seq(first, second))
      kept

    /** Finds the names that the quick command needs first. The quick command is `java -version`, because a JVM start
      * takes seconds, and `slow` is a build or a served fetch. The search then tries the slow command with those names
      * alone, and halves the rest only if that attempt fails. */
    def machSearch(quickLabel: String, quick: Seq[String] => Boolean, slow: Seq[String] => Boolean,
        baseline: () => Boolean, attemptLog: Path): Unit =
      def tail(): Unit =
        if Files.exists(attemptLog) then
          System.err.println(Files.readAllLines(attemptLog).asScala.takeRight(20).mkString("\n"))
      if !baseline() then
        System.err.println(
          "with mach-lookup unfiltered the profile still does not run the measured command, so no lookup is the cause:")
        tail()
        sys.exit(1)
      println("the rendered profile with mach-lookup unfiltered: PASS")
      println("collecting candidate names from the launchd plists")
      val all = machCandidates()
      val extras = Files.readAllLines(machExtra).asScala.count(_.nonEmpty)
      println(s"${all.size} candidates, $extras of them from $machExtra")
      if !slow(all) then
        System.err.println(
          s"""every candidate granted and it still fails: a name it looks up is in no launchd plist.
             |Read the denied names while rerunning this mode, and add them to $machExtra, one per line:
             |  log stream --style compact --predicate 'sender == "Sandbox" AND eventMessage CONTAINS "mach-lookup"'
             |The attempt's own output:""".stripMargin)
        tail()
        sys.exit(1)
      println("all candidates: PASS")
      val needed =
        if slow(Seq.empty) then
          println("no name at all: PASS — the measured command fails on no denied lookup.")
          Seq.empty
        else
          println(s"$quickLabel, removing by halves:")
          val quickNeeds = machReduce(quick, all, all)
          if slow(quickNeeds) then
            println("the measured command runs with those names alone.")
            quickNeeds
          else
            println("the measured command needs more than those names. Removing the rest by halves:")
            val rest = machReduce(slow, all, all.filterNot(quickNeeds.toSet))
            println("the first names again, with the rest settled:")
            machReduce(slow, rest, quickNeeds)
      val neededFile = work / "mach-needed.txt"
      Files.write(neededFile, needed.asJava)
      println()
      println(s"the names it needs ($neededFile):")
      needed.foreach(name => println(s"  $name"))
      println()
      println("A name is listed because the measured command fails without it. A lookup whose denial the")
      println("command survives is not listed, so the run-on-host checks decide whether a build under these names")
      println("behaves.")

    def mach(): Unit =
      val emitted = emitOrExit()
      // End emit's own sbt server, which holds this project's portfile; the run-on-host checks end it for the same
      // reason.
      endSbtServer()
      val bound = sys.env.get("MACH_BOUND").flatMap(_.toIntOption).getOrElse(600)
      // The probe builds a project of its own inside the workspace that the profile grants. This checkout's target/
      // links into the store of the unconfined sbt that emit ran, and the profile denies that store
      // (run-on-host-internals.md, "sbt", the paragraph on the server's state). Sweeping those links is the runner's
      // job, not this probe's.
      val fixture = root / "target" / "mach-fixture"
      removeTree(fixture)
      Files.createDirectories(fixture / "project")
      Files.copy(root / "project" / "build.properties", fixture / "project" / "build.properties")
      Files.writeString(fixture / "build.sbt", "")
      val openProfile = work / "mach-open.sb"
      val attemptProfilePath = work / "mach.sb"
      val activeServer = fixture / "project" / "target" / "active.json"
      val tryLog = work / "mach-try.log"
      def fixtureCommand(log: Path, profile: Path, command: String = sbtCommand): Boolean =
        runCommand(emitted, log, profile, command, cwd = fixture, boundSeconds = Option.when(bound > 0)(bound))
      machProfile(commandProfile, None, openProfile)
      def endServer(): Unit =
        if Files.exists(activeServer) then fixtureCommand(work / "mach-shutdown.log", openProfile, "shutdown")
      def quickPasses(names: Seq[String]): Boolean =
        machProfile(commandProfile, Some(names), attemptProfilePath)
        attemptProfile(attemptProfilePath, s"${shellQuoted(s"$javaHome/bin/java")} -version")
      // The server that a passing attempt leaves would serve the next attempt's client under the earlier attempt's
      // names. So the probe ends the server under the unfiltered profile, which the baseline proved to work.
      def buildPasses(names: Seq[String]): Boolean =
        machProfile(commandProfile, Some(names), attemptProfilePath)
        val result = fixtureCommand(tryLog, attemptProfilePath)
        endServer()
        if Files.exists(activeServer) then
          fail(s"an sbt server outlived its shutdown ($activeServer, ${work / "mach-shutdown.log"}); " +
            "end it, then rerun.")
        result
      def buildBaseline(): Boolean =
        val result = fixtureCommand(tryLog, openProfile)
        endServer()
        result
      println(s"measuring: sbt $sbtCommand in $fixture, each attempt bounded at ${bound}s (MACH_BOUND)")
      machSearch("java -version", quickPasses, buildPasses, buildBaseline, tryLog)
      removeTree(fixture)

    def machProxy(): Unit =
      val image = argument.filter(_.nonEmpty).map: named =>
        val path = Path.of(named)
        if !Files.isRegularFile(path) || !Files.isExecutable(path) then fail(s"$named is not an executable file", 2)
        // Absolute, because the proxy starts from /.
        path.toRealPath()
      val proxyProfile = work / "proxy.sb"
      def emitProxy(form: String*): Unit =
        val output = HostDriver.run(Seq("sbt", "-batch", (Seq("Test/runMain agentsandbox.launcher.EmitRunOnHostProfile",
          s"\"$proxyProfile\"", s"\"$systemPaths\"") ++ form).mkString(" ")))
        Files.writeString(work / "emit-proxy.log", output.text)
        if !output.ok then
          fail(s"emit failed for the proxy:\n${output.text.linesIterator.toSeq.takeRight(20).mkString("\n")}")
      val classpath = image match
        case Some(binary) =>
          emitProxy("proxy-image", s"\"$binary\"")
          None
        case None =>
          val cp = emitOrExit().value("classpath: ").getOrElse(fail("emit printed no classpath"))
          emitProxy("proxy", s"\"$javaHome\"", s"\"$cp\"")
          Some(cp)
      endSbtServer()
      val proxyLog = work / "mach-proxy.log"
      val attemptProfilePath = work / "mach.sb"
      val listening = """.*ko-agent-egress-proxy listening on :(\d+).*""".r
      def port: Option[String] =
        if !Files.exists(proxyLog) then None
        else Files.readAllLines(proxyLog).asScala.collectFirst { case listening(found) => found }
      // Starts the proxy as RunOnHostProxy.startProxy starts it, then sends one fetch through the proxy, which makes
      // the proxy resolve a name and connect.
      def serveUnder(profile: Path): Boolean =
        val proxyCommand = image match
          case Some(binary) => Seq(binary.toString, "-Djava.net.preferIPv4Stack=true", "--serve-proxy-on-host")
          case None => Seq(s"$javaHome/bin/java", "-Djava.net.preferIPv4Stack=true", "-cp", classpath.get,
            "agentsandbox.launcher.AgentSandboxLauncher", "--serve-proxy-on-host")
        val builder = ProcessBuilder(("/usr/bin/sandbox-exec" +: "-f" +: profile.toString +: proxyCommand)*)
          .directory(Path.of("/").toFile).redirectOutput(ProcessBuilder.Redirect.DISCARD)
          .redirectError(proxyLog.toFile)
        builder.environment.clear()
        Seq("HTTPS_PROXY", "https_proxy").foreach(name => sys.env.get(name).foreach(builder.environment.put(name, _)))
        builder.environment.put("EGRESS_PROFILE", "deny-unless-allowed")
        builder.environment.put("EGRESS_RULE", "deny defaults\nallow https://repo1.maven.org/ read")
        builder.environment.put("EGRESS_BIND", "127.0.0.1:0")
        val proxy = builder.start()
        try
          within(30, 500)(!proxy.isAlive || port.isDefined)
          port.exists: found =>
            val fetch = HostDriver.run(Seq("curl", "-fsS", "-o", "/dev/null", "--max-time", "30", "--proxy",
              s"http://127.0.0.1:$found", "https://repo1.maven.org/maven2/"))
            Files.writeString(work / "mach-curl.err", fetch.text)
            fetch.ok
        finally
          proxy.descendants.forEach(_.destroy())
          proxy.destroy()
          proxy.waitFor()
      def servePasses(names: Seq[String]): Boolean =
        machProfile(proxyProfile, Some(names), attemptProfilePath)
        serveUnder(attemptProfilePath)
      def serveBaseline(): Boolean =
        val openProfile = work / "mach-open.sb"
        machProfile(proxyProfile, None, openProfile)
        serveUnder(openProfile)
      // The quick check runs java itself from /, because the proxy's profile grants no shell and no other working
      // directory. A native image has no quicker start than serving, so serving is its quick check too.
      def quickPasses(names: Seq[String]): Boolean =
        if image.isDefined then servePasses(names)
        else
          machProfile(proxyProfile, Some(names), attemptProfilePath)
          HostDriver.run(Seq("/usr/bin/sandbox-exec", "-f", attemptProfilePath.toString, s"$javaHome/bin/java",
            "-version"), cwd = Path.of("/")).ok
      println(s"measuring: the host proxy${image.fold("")(binary => s" ($binary)")} serving one fetch of " +
        "https://repo1.maven.org/maven2/")
      machSearch(if image.isDefined then "the image serving" else "java -version", quickPasses, servePasses,
        serveBaseline, proxyLog)

    // --- procargs ----------------------------------------------------------------------------------------------

    /**
     * Measures whether a confined command reads the environment of another process of the same user through
     * sysctl(KERN_PROCARGS2), the call behind `ps -E`. Also measures whether the rule that denies the call leaves the
     * JDK running (seatbelt.md, "Processes", records the answers). ProcArgs.java makes the call: `ps` is setuid,
     * which no profile lets a command execute, and a build can make the call itself.
     *
     * Two targets lie outside the sandbox, because the kernel omits the environment of a cs_restricted process unless
     * the caller is the target (xnu bsd/kern/kern_sysctl.c, sysctl_procargsx). Apple's own binaries are cs_restricted.
     *   - A JDK started here with a marker variable stands in for the runner and a supervisor, which are JDKs that
     *     hold the launch's environment.
     *   - /bin/sleep, started here, is Apple's.
     *
     * Two more targets cover what `same-sandbox` spans:
     *   - a child that the reader starts, which inherits the reader's sandbox;
     *   - a JDK under a sandbox-exec of its own with the same profile, as the runner starts an sbt server and a Mill
     *     daemon apart from their clients.
     * Each line ends with whether `ProcessHandle.of` finds the target and whether `info()` reads it. Mill's client asks
     * the same of its daemon (PidLock.isLockValid).
     *
     * The call succeeds while either sysctl-read of its name, kern.procargs2.<pid>, or process-info-pidinfo is
     * allowed, and `(deny default)` does not cover process-info*. So the rule denies both and allows pidinfo again
     * inside the sandbox, where a build inspects its own children
     * (https://github.com/eugene1g/agent-safehouse profiles/10-system-runtime.sb). The two rows before the row "both"
     * deny one family each.
     *
     * The first four profiles are `(allow default)` plus the rule under test, isolated as seatbelt-semantics.sh
     * isolates its rules. Then come the rendered command profile without the rule, with it, and with it and a mill
     * client's one-name exception. No build runs here: the JDK starting under the rendered profile is the row itself,
     * and whether every program starts under that profile is the run-on-host checks' question. Run this mode on each
     * new macOS release.
     */
    def procargs(): Unit =
      val java = s"$javaHome/bin/java"
      val probeSource = (root / "src" / "probe" / "ProcArgs.java").toString
      def started(command: Seq[String]): Process =
        val builder = ProcessBuilder(command*).redirectOutput(ProcessBuilder.Redirect.DISCARD)
          .redirectError(ProcessBuilder.Redirect.DISCARD)
        builder.environment.put("KO_AGENT_PROCARGS_PROBE", "1")
        builder.start()
      val targets = mutable.Buffer.empty[Process]
      Runtime.getRuntime.addShutdownHook(Thread(() => targets.foreach(_.destroy())))
      val held = started(Seq(java, probeSource, "--hold"))
      val apple = started(Seq("/bin/sleep", "86400"))
      targets ++= Seq(held, apple)
      Thread.sleep(2000)
      val byName = """(deny sysctl-read (sysctl-name-regex #"procargs"))"""
      val byPidinfo = "(deny process-info-pidinfo) (allow process-info-pidinfo (target same-sandbox))"
      val ruleProfile = work / "procargs-rule.sb"
      def profileWith(rules: String*): Path =
        Files.write(ruleProfile, (Seq("(version 1)", "(allow default)") ++ rules).asJava)
      def readUnder(label: String, profile: Path, tmp: Option[Path] = None): Unit =
        println()
        println(s"--- $label")
        val tmpOption = tmp.map(dir => s"-Djava.io.tmpdir=$dir").toSeq
        val apart = started(Seq("/usr/bin/sandbox-exec", "-f", profile.toString, java) ++ tmpOption ++
          Seq(probeSource, "--hold"))
        targets += apart
        Thread.sleep(2000)
        val reader = ProcessBuilder((Seq("/usr/bin/sandbox-exec", "-f", profile.toString, java,
          "--enable-native-access=ALL-UNNAMED") ++ tmpOption ++ Seq(probeSource, s"the held JDK=${held.pid}",
          s"an Apple binary, /bin/sleep=${apple.pid}", s"a JDK in a sandbox of its own=${apart.pid}",
          s"--child=$probeSource"))*)
          .redirectOutput((work / "procargs.out").toFile).redirectError((work / "procargs.err").toFile)
        val status = reader.start().waitFor()
        if status == 0 then Files.readAllLines(work / "procargs.out").asScala.foreach(line => println(s"    $line"))
        else
          println(s"    the JVM did not run (exit $status):")
          Files.readAllLines(work / "procargs.err").asScala.takeRight(5).foreach(line => println(s"    $line"))
        apart.destroy()
        targets -= apart

      readUnder("no rule: what the kernel allows a same-user process", profileWith())
      readUnder(s"the name alone: $byName", profileWith(byName))
      readUnder(s"pidinfo alone: $byPidinfo", profileWith(byPidinfo))
      readUnder("both", profileWith(byName, byPidinfo))

      val emitted = emitOrExit()
      val commandLines = Files.readAllLines(commandProfile).asScala.toSeq
      // Take SeatbeltProfile.ProcessReadRule's lines out of the rendered profile for the contrast.
      def ruleLine(line: String): Boolean =
        line == """(deny sysctl-read (sysctl-name-regex #"procargs"))""" || line.contains("process-info-pidinfo")
      if commandLines.count(ruleLine) != 3 then
        fail("the rendered profile does not hold SeatbeltProfile.ProcessReadRule's three lines")
      val noRule = work / "command-norule.sb"
      Files.write(noRule, commandLines.filterNot(ruleLine).asJava)
      readUnder("the rendered command profile without the rule", noRule, Some(emitted.sessionTmp))
      readUnder("the rendered command profile", commandProfile, Some(emitted.sessionTmp))
      // The exception that a mill client's profile takes for its daemon (SeatbeltProfile.Network.MillClient): the
      // sysctl name of the held JDK's arguments alone, allowed after the rule. Expected: the held JDK is read, with
      // info read; every other target is denied, with info throwing.
      val oneName = s"""(allow sysctl-read (sysctl-name "kern.procargs2.${held.pid}"))"""
      val sameSandbox = "(allow process-info-pidinfo (target same-sandbox))"
      if !commandLines.contains(sameSandbox) then
        fail("the rendered profile has no same-sandbox pidinfo line to put the name after")
      val withOneName = work / "command-one-name.sb"
      val oneNameLines = commandLines.flatMap(line => if line == sameSandbox then Seq(line, oneName) else Seq(line))
      Files.write(withOneName, oneNameLines.asJava)
      readUnder(s"the rendered command profile and $oneName", withOneName, Some(emitted.sessionTmp))
      println()
      println("ENVIRONMENT READ of the held JDK without the rule is what a host command would reach")
      println("(SECURITY.md, \"Run on host\"). DENIED (EPERM) under the rendered profile, with the JDK running and")
      println("listing its processes, is SeatbeltProfile.ProcessReadRule; SeatbeltCheck runs every program.")

  /** The entries of a directory, without the dot entries unless asked, or none when it cannot be listed. */
  private def entries(dir: Path, dotFiles: Boolean): Vector[Path] =
    try
      Using.resource(Files.list(dir))(_.iterator.asScala.toVector)
        .filter(entry => dotFiles || !entry.getFileName.toString.startsWith("."))
    catch case _: java.io.IOException => Vector.empty
