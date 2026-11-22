#!/usr/bin/env -S scala shebang
//> using scala 3.10.1
//> using file ../test/scala/HostDriver.scala
//> using file ../test/scala/RunOnHostIdle.scala
//> using file ../test/scala/RunOnHostChecks.scala

/*
  Measures what the runner's session rests on (doc/run-on-host-internals.md, "Network", "sbt" and "mill") before the
  runner encodes any of it. A changed rule or command line calls for a rerun. The rows fall into four groups:

    L1-L5  SBPL: a loopback listener on port 0 under (local ip "localhost:*"), its control, an exact-port outbound
           rule that reaches its port and not the neighbor's, and whether the checked descriptor scan can be complete
    G1-G12 SBPL for Gradle (SECURITY.md, "Run on host", the per-program table) and for the reach of "localhost":
           - a UDP socket and a TCP listener bound to the wildcard address on port 0, reached at the loopback address;
           - what happens at this host's LAN address, inbound and outbound, TCP and UDP, under the Gradle candidate
             and under the mill daemon's rule;
           - the wildcard bind's control;
           - an exact-port rule at the LAN address;
           - a remote destination under the candidate
    S1-S6  sbt 1.13.1 and 2.1.0, one scratch project each:
           - a server started by the owner's command line publishes its portfile before a deadline;
           - a client with its own tmp attaches and forks nothing;
           - the client's unix-socket rule;
           - a TERMed client cancels its exec, and what the forked JVM does;
           - where sbt 2 writes its proc entry;
           - the wrong-directory control, then a protocol shutdown at the socket recorded before it
    M1-M8  Mill 1.1.10, one scratch project. The runner starts a daemon only before Mill 1.2
           (run-on-host-internals.md, "Mill 1.2 and later: no daemon"), so the rows measure the last Mill before it:
           - the stock ./mill under the daemon profile leaves a daemon behind its denied connect;
           - the port from lsof;
           - a client confined to that port, and to the neighbor;
           - the command's environment reaching the build;
           - a TERMed client mid-command;
           - MILL_SERVER_TIMEOUT_MILLIS;
           - a foreign daemon whose fingerprint differs;
           - the starter's group topology, and the starter TERMed once its daemon listens

  Run the probe on the macOS HOST from the repository root, with the sbt that cs installed and python3 on PATH, and
  JAVA_HOME (or `cs java-home`) naming a JDK:

      src/probe/RunOnHostRunnerSession.scala          # every row, about ten minutes on a warm cache
      src/probe/RunOnHostRunnerSession.scala sbpl     # the L and G rows alone, about a minute

  - The probe downloads what the two sbt versions and Mill need, unconfined, into your own caches. That is the
    provisioning that the supervisor requires of you. Only the rows run confined.
  - The run's logs, tables and records go to log/run-on-host-runner-session/.
  - On any FAIL, the probe keeps the scratch tree under /private/tmp and names it.
  - INFO rows are measurements with no expected answer.

  Every process that the probe starts runs in a group whose leader stays alive and whose start time is recorded, as
  the supervisor registers its own processes (RunOnHostSession.registeredSpawn):
  - the leader runs the child in the given environment, publishes the child's exit status beside its record, and
    stays;
  - every wait has a deadline, and a passed deadline is a FAIL that ends the group;
  - cleanup signals only groups whose leader is still alive.
  A denial row passes only on the operating system's own refusal in the process's output, or on the behavior that sbt
  documents for the denial, never on a bare failure.

  The confined rows use (allow default) profiles that deny network* and then allow one rule, so each row measures the
  network rule alone. Measuring the filesystem rules is SeatbeltCheck's job, and a deny-default profile here would
  chase grants that the question is not about.
*/

import agentsandbox.launcher.HostDriver
import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.removeTree
import agentsandbox.launcher.RunOnHostIdle

import java.io.{File, IOException}
import java.lang.ProcessBuilder.Redirect
import java.nio.charset.StandardCharsets.UTF_8
import java.nio.file.{FileVisitResult, Files, Path, SimpleFileVisitor, StandardOpenOption}
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.atomic.AtomicBoolean

import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import scala.util.matching.Regex

@main def measureRunnerSession(args: String*): Unit = RunOnHostRunnerSession.run(args)

object RunOnHostRunnerSession:
  val SbtVersions: Seq[String] = Seq("1.13.1", "2.1.0")
  val MillVersion = "1.1.10"
  val ScalaVersion = "3.10.1"
  val Denied = "Operation not permitted"
  /** The deadline of the probe's own lsof and ps calls. A full lsof scan takes about a second. */
  val HelperSeconds = 120
  /** The bootstrap's overrides, which the supervisor drops from a mill command's environment
    * (RunOnHostSandbox.MillOverrides, which this script does not compile against). Dropped from the unconfined runs
    * too, so that they provision and run the Mill that the confined rows use. */
  val MillOverrides = Set("MILL_VERSION", "DEFAULT_MILL_VERSION", "MILL_OUTPUT_DIR", "MILL_BSP_OUTPUT_DIR")
  val usage =
    "usage: src/probe/RunOnHostRunnerSession.scala [all|sbpl]   (sbpl: the L and G rows alone, about a minute)"

  def run(args: Seq[String]): Unit =
    val os = sys.props("os.name")
    orExit(Either.cond(os == "Mac OS X", (), s"This probe measures a macOS host; this is $os. Run it on macOS."))
    val inSession = sys.env.get("KO_AGENT_SANDBOX_EGRESS_RULESET").exists(_.nonEmpty)
      || Files.isDirectory(Path.of("/etc/ko-agent-sandbox"))
    orExit(Either.cond(!inSession, (), "This looks like a sandbox session. Run the probe on the host instead."))
    val root = orExit(repositoryRoot("src/test/run-on-host/fixtures/mill/mill"))
    val sbplOnly = args match
      case Seq() | Seq("all") => false
      case Seq("sbpl")        => true
      case _                  => orExit(Left(usage))
    val javaHome = orExit(sys.env.get("JAVA_HOME").filter(_.nonEmpty).orElse(csJavaHome).map(Path.of(_))
      .filter(home => Files.isExecutable(home / "bin" / "java"))
      .toRight("JAVA_HOME does not name a JDK and cs java-home gave none"))
    val sbtScript = orExit(onPath("sbt").map(_.toAbsolutePath).toRight("no sbt on PATH; cs install sbt"))
    val session = Session(root, javaHome, sbtScript, scratchDirectory())
    runMeasured(session.transcript, session)(session.measure(sbplOnly))

  private def csJavaHome: Option[String] =
    try Some(HostDriver.run(Seq("cs", "java-home"), discardStderr = true)).filter(_.ok).map(_.text.trim)
    catch case _: IOException => None

  /** A short path, for the budget of sbt's boot socket path: Files.createTempDirectory's random part is up to 19
    * digits long. The directory is the owner's alone, as Files.createTempDirectory's would be: other users could
    * otherwise read the scans of this user's processes, and a group-writable umask would let them change the scratch
    * builds that the probe runs unconfined. */
  private def scratchDirectory(): Path =
    import java.nio.file.attribute.PosixFilePermissions.{asFileAttribute, fromString}
    val random = java.security.SecureRandom()
    val alphabet = ('a' to 'z') ++ ('A' to 'Z') ++ ('0' to '9')
    def suffix = Seq.fill(6)(alphabet(random.nextInt(alphabet.size))).mkString
    Iterator.continually(Path.of(s"/private/tmp/ko-probe.$suffix"))
      .flatMap: candidate =>
        try Some(Files.createDirectory(candidate, asFileAttribute(fromString("rwx------"))))
        catch case _: java.nio.file.FileAlreadyExistsException => None
      .next()

  /** The environment a group's leader passes to the child: the probe's own plus `variables`, or `variables` alone. */
  case class Environment(variables: Map[String, String], inherit: Boolean)
  val Inherited: Environment = Environment(Map.empty, inherit = true)

  /** One row of the checked scan: one descriptor of one process. */
  case class Row(pid: String, command: String, fd: String, device: String, name: String, kind: String):
    def line: String = Seq(pid, command, fd, device, name, kind).mkString("\t")

  /** The checked scan: complete only when `reason` is None. */
  case class Scan(rows: Vector[Row], seen: Int, missed: Vector[Long], errors: Vector[Row], reason: Option[String])

  /** How a connect from `/bin/bash`'s /dev/tcp ended. */
  enum Connect:
    case Connected
    case Denied(line: String)
    case Failed(line: String)

  class Session(root: Path, javaHome: Path, sbtScript: Path, val work: Path) extends AutoCloseable:
    val transcript: Transcript = Transcript(work / "report.log")
    private val account = sys.props("user.name")
    // The JVM's user.home comes from the account database, not from HOME, which the supervisor passes on.
    private val home = sys.env.get("HOME").filter(_.nonEmpty).getOrElse(sys.props("user.home"))
    private val uid = com.sun.security.auth.module.UnixSystem().getUid
    private val systemPath = s"$javaHome/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    private val logs = root / "log" / "run-on-host-runner-session"
    private val closed = AtomicBoolean(false)

    // --- Rows -----------------------------------------------------------------------------------------------------

    private def described(label: String, detail: String): String =
      if detail.isEmpty then label else f"$label%-58s  $detail"
    def pass(label: String, detail: String): Unit = transcript.pass(described(label, detail))
    def fail(label: String, detail: String): Unit = transcript.fail(described(label, detail))
    def info(label: String, detail: String): Unit = transcript.info(described(label, detail))
    def skip(label: String, detail: String): Unit = transcript.skip(described(label, detail))
    def heading(text: String): Unit =
      transcript.log("")
      transcript.log(text)
    def showTable(lines: Iterable[String]): Unit = lines.foreach(line => transcript.log("        " + line))

    // --- Groups ---------------------------------------------------------------------------------------------------

    /** The group's leader. Perl, because a JVM cannot call setpgrp between its fork and the child's exec. */
    private val LeaderScript =
      """setpgrp(0, 0) or exit 71;
        |my ($record, @command) = @ARGV;
        |my $pid = fork;
        |exit 71 unless defined $pid;
        |if ($pid == 0) { exec { $command[0] } @command or exit 71; }
        |waitpid($pid, 0);
        |my $status = ($? & 127) ? 128 + ($? & 127) : $? >> 8;
        |open(my $out, ">", "$record.exit.pending") or exit 71;
        |print $out "$status\n";
        |close($out) or exit 71;
        |rename("$record.exit.pending", "$record.exit") or exit 71;
        |sleep 3600 while 1;""".stripMargin

    /** One `pid -> start` entry per live leader, as the supervisor records them. */
    private val leaders = mutable.LinkedHashMap[Long, String]()

    private def sibling(record: Path, suffix: String): Path = Path.of(record.toString + suffix)

    /** Starts the command in `dir` as the child of a new group's leader, with stdin from /dev/null. The leader
      * publishes the child's exit status to RECORD.exit and then stays. Gives the leader's pid. Stderr goes to
      * `stdout` unless `stderr` names a file of its own. */
    def groupStart(record: Path, dir: Path, command: Seq[String], environment: Environment, stdout: Path,
        stderr: Option[Path] = None): Long =
      Files.deleteIfExists(sibling(record, ".exit"))
      Files.deleteIfExists(sibling(record, ".timeout"))
      val builder = ProcessBuilder((Seq("/usr/bin/perl", "-e", LeaderScript, record.toString) ++ command)*)
        .directory(dir.toFile).redirectInput(Redirect.from(File("/dev/null"))).redirectOutput(stdout.toFile)
      stderr match
        case Some(file) => builder.redirectError(file.toFile)
        case None       => builder.redirectErrorStream(true)
      if !environment.inherit then builder.environment.clear()
      environment.variables.foreach(builder.environment.put(_, _))
      // close() sets `closed` and copies the leaders under this lock, so no group starts unseen behind its copy.
      leaders.synchronized:
        if closed.get then throw IllegalStateException("the probe is closing: no group starts")
        val leader = builder.start().pid
        leaders(leader) = RunOnHostIdle.startOf(leader).getOrElse("")
        leader

    def exited(record: Path): Boolean =
      Files.exists(sibling(record, ".exit")) || Files.exists(sibling(record, ".timeout"))

    /** The child's exit status, 124 when the child's deadline passed, or None when neither was recorded. */
    def statusOf(record: Path): Option[Int] =
      if Files.exists(sibling(record, ".timeout")) then Some(124) else text(sibling(record, ".exit")).trim.toIntOption

    /** Waits for the child to exit, and records a passed deadline as RECORD.timeout. */
    def awaitExit(record: Path, seconds: Int): Unit =
      if !within(seconds, 100)(exited(record)) then Files.writeString(sibling(record, ".timeout"), "")

    /** Ends a group only through its recorded leader, and retires the record. The leader must be alive and have the
      * start time recorded when the group was made, as the supervisor checks a group's leader before signalling it. A
      * pgid whose leader died may belong to someone else by now. */
    def endGroup(leader: Long): Unit =
      val recorded = leaders.synchronized(leaders.remove(leader))
      if recorded.exists(start => start.nonEmpty && RunOnHostIdle.startOf(leader).contains(start)) then
        signal("TERM", s"-$leader")
        if !within(5, 100)(helperLines(strict = false, "/bin/ps", "-o", "pid=", "-g", leader.toString)
            .forall(_.isBlank)) then
          signal("KILL", s"-$leader")

    /** Runs the command with a deadline and ends its group afterwards. The status is 124 when the deadline passed, or
      * 71 when the leader could not start the command. */
    def bounded(seconds: Int, record: Path, dir: Path, command: Seq[String], environment: Environment, stdout: Path,
        stderr: Option[Path] = None): Option[Int] =
      val leader = groupStart(record, dir, command, environment, stdout, stderr)
      awaitExit(record, seconds)
      endGroup(leader)
      statusOf(record)

    /** The wording of a failed bounded run, for a FAIL detail. */
    def failed(record: Path, log: Path): String = statusOf(record) match
      case Some(124) => "deadline passed; group ended"
      case Some(71)  => "the leader could not start it"
      case status    => s"exit ${status.fold("none")(_.toString)}: ${firstLine(log)}${cause(log)}"

    // --- Files and processes --------------------------------------------------------------------------------------

    /** The file's text, or empty when it does not exist. Malformed UTF-8 is replaced rather than refused. */
    def text(file: Path): String =
      try String(Files.readAllBytes(file), UTF_8)
      catch case _: IOException => ""

    def size(file: Path): Long = if Files.exists(file) then Files.size(file) else 0

    /** The first line of a log that is neither empty nor a JVM's `Picked up` notice, cut to 70 characters. */
    def firstLine(file: Path): String =
      text(file).linesIterator.filter(_.nonEmpty).filterNot(_.contains("Picked up")).nextOption().getOrElse("").take(70)

    def lineAt(file: Path, index: Int): String = text(file).linesIterator.drop(index).nextOption().getOrElse("")

    def lastLine(file: Path): String = text(file).linesIterator.toSeq.lastOption.getOrElse("")

    def cause(log: Path): String =
      text(log).linesIterator.find(_.contains("Caused by")).fold("")(line => ("; " + line).take(90))

    /** The first line of the file that the pattern matches, cut to 70 characters. */
    def matchingLine(pattern: String, file: Path): Option[String] =
      val regex = pattern.r
      text(file).linesIterator.find(regex.findFirstIn(_).isDefined).map(_.take(70))

    def hasLine(pattern: String, file: Path): Boolean = matchingLine(pattern, file).isDefined

    /** The command's output lines. The command has a deadline, because the cleanup calls this too and the JVM exits
      * only after the cleanup returns. Past the deadline, a row gets an IOException, so that no row measures cut
      * output; the cleanup (`strict = false`) gets what the command printed. */
    def helperLines(strict: Boolean, command: String*): Vector[String] =
      val output = HostDriver.run(command, timeoutSeconds = Some(HelperSeconds), discardStderr = true)
      // HostDriver.run answers -1 only for a command that it killed at the deadline.
      if strict && output.status == -1 then
        throw IOException(s"${command.head} did not finish within ${HelperSeconds}s")
      output.text.linesIterator.toVector

    def lines(command: String*): Vector[String] = helperLines(strict = true, command*)

    def gone(pid: Long): Boolean = !ProcessHandle.of(pid).map(_.isAlive).orElse(false)

    def sameProcess(pid: Long, start: Option[String]): Boolean =
      start.exists(_.nonEmpty) && RunOnHostIdle.startOf(pid) == start

    def signal(name: String, target: String): Unit = HostDriver.run(Seq("/bin/kill", s"-$name", "--", target))

    def pgrep(pattern: String): Vector[Long] =
      lines("/usr/bin/pgrep", "-f", "--", pattern).flatMap(_.trim.toLongOption)

    /** Whether the path is a socket, as `test -S` answers: the file type bits of its mode are S_IFSOCK. */
    def isSocket(path: Path): Boolean =
      try (Files.getAttribute(path, "unix:mode").asInstanceOf[Int] & 0xf000) == 0xc000
      catch case _: IOException => false

    /** The regular files under the directory, skipping entries that vanish or cannot be read during the walk. */
    def filesUnder(dir: Path): Vector[Path] =
      val found = Vector.newBuilder[Path]
      if Files.isDirectory(dir) then
        Files.walkFileTree(dir, new SimpleFileVisitor[Path]:
          override def visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult =
            if attributes.isRegularFile then found += file
            FileVisitResult.CONTINUE
          override def visitFileFailed(file: Path, ex: IOException): FileVisitResult = FileVisitResult.CONTINUE
        )
      found.result()

    /** The processes whose command line matches the pattern and whose cwd is the directory or lies under it. This is
      * the run-on-host checks' own test (CheckRun.withCwd), with one lsof for every process rather than one per
      * candidate. */
    def withCwd(pattern: Regex, dir: Path, strict: Boolean = true): Vector[Long] =
      var pid = ""
      val inside = Vector.newBuilder[Long]
      for line <- helperLines(strict, "/usr/sbin/lsof", "-d", "cwd", "-Fpn") do
        if line.startsWith("p") then pid = line.drop(1)
        else if line.startsWith("n") then
          val path = line.drop(1)
          if path == dir.toString || path.startsWith(s"$dir/") then pid.toLongOption.foreach(inside += _)
      inside.result().distinct.filter: candidate =>
        helperLines(strict, "/bin/ps", "-o", "command=", "-p", candidate.toString).headOption
          .exists(pattern.findFirstIn(_).isDefined)

    /** The rows of `ps -eo pid=,pgid=,command=` whose group is the leader's and whose command line holds the text. */
    def groupMember(leader: Long, text: String): Option[Long] =
      lines("/bin/ps", "-eo", "pid=,pgid=,command=").map(_.trim.split("\\s+", 3)).collectFirst:
        case Array(pid, pgid, command) if pgid == leader.toString && command.contains(text) => pid.toLong

    def secondsSince(startNanos: Long): Long = (System.nanoTime - startNanos) / 1_000_000_000L

    // --- The checked scan -----------------------------------------------------------------------------------------
    //
    // The checked scan lists every descriptor of every process of this user, one row each. The scan is one listing,
    // so that a server's rows and its peers' rows come from the same moment. Apple's lsof hides failures in three
    // ways:
    // - it skips a process whose proc_pidinfo fails with EPERM or ESRCH, without a word;
    // - it reports a process whose descriptors it cannot enumerate as an entry whose fd is `err` (dproc.c);
    // - it reports one descriptor that it cannot read under the descriptor's number as `<kind>: <reason>`, with the
    //   kind from the kernel's descriptor listing. So `socket: Operation not permitted` may hide a client.
    //   `vnode: FD unavailable` cannot hide one: it marks a file closed between listing and reading, as Spotlight's
    //   indexer does during a scan (dproc.c, dfile.c err2nm, dsock.c).
    // With `-u`, every file of the user's processes inherits the selection (proc.c alloc_lfile), so those entries are
    // in this listing, where a `-a -p <pid> -U` table would drop them.
    //
    // The scan is complete only when all of these hold; otherwise its reason says why, and the scan is unknown, never
    // idle:
    // - lsof exits 0 with nothing on stderr. lsof exits 1 for a scan that it could not complete, a partial table
    //   included;
    // - every process of this user that is alive before and after the scan has a row;
    // - no row is an error that can hide a socket: an `err` entry, a `socket:` entry or an `unknown file type`.
    // No name that lsof writes for a readable socket has those forms: paths start with `/`, peers with `->`, and
    // addresses with a digit or `[`.
    //
    // "This user's processes" means by effective uid on both sides, which is lsof's notion. `ps -u` selects by real
    // uid, which a setuid `login` from the terminal keeps while it runs as root; such a process is unreadable to lsof
    // and is no client of anything.

    /** Live processes: this user's by effective uid, and not zombies, which hold no descriptor for lsof to list. */
    def livePids(): Set[Long] =
      lines("/bin/ps", "-eo", "pid=,uid=,stat=").map(_.trim.split("\\s+")).collect:
        case Array(pid, owner, stat) if owner == uid.toString && !stat.startsWith("Z") => pid.toLong
      .toSet

    /** Takes the checked scan, and writes its rows to `out` and its reason, if any, to OUT.reason. */
    def scan(out: Path): Scan =
      val before = livePids()
      val raw = sibling(out, ".raw")
      val err = sibling(out, ".err")
      val process = ProcessBuilder("/usr/sbin/lsof", "-u", account, "-nP", "-Fpcftdn")
        .redirectInput(Redirect.from(File("/dev/null"))).redirectOutput(raw.toFile).redirectError(err.toFile)
        .start()
      val finished = process.waitFor(HelperSeconds, java.util.concurrent.TimeUnit.SECONDS)
      if !finished then process.destroyForcibly().waitFor()
      val status = if finished then process.exitValue else -1
      val after = livePids()
      var pid = ""
      var command = ""
      var fd = ""
      var device = ""
      var kind = ""
      val rows = Vector.newBuilder[Row]
      val seen = mutable.Set[Long]()
      for line <- text(raw).linesIterator if line.nonEmpty do
        val value = line.drop(1)
        line.head match
          case 'p' =>
            pid = value
            value.toLongOption.foreach(seen += _)
          case 'c' => command = value
          case 'f' =>
            fd = value
            device = ""
            kind = ""
          case 't' => kind = value
          case 'd' => device = value
          case 'n' => rows += Row(pid, command, fd, device, value, kind)
          case _   => ()
      val table = rows.result()
      Files.write(out, table.map(_.line).asJava)
      val missed = (before intersect after).diff(seen).toVector.sorted
      // Every missed pid, since a row prints at most five and lsof's raw output cannot show which ones it skipped.
      Files.write(sibling(out, ".missed"), missed.map(_.toString).asJava)
      val errors = table.filter: row =>
        row.fd.trim == "err" || row.name.startsWith("socket: ") || row.name.startsWith("unknown file type: ")
      val reason =
        if !finished then Some(s"lsof did not finish within ${HelperSeconds}s")
        else if status != 0 then Some(s"lsof exit $status")
        else if size(err) > 0 then Some(s"lsof stderr: ${firstLine(err)}")
        else if missed.nonEmpty then Some(s"${missed.size} live processes missed")
        else if errors.nonEmpty then Some(s"${errors.size} descriptor errors")
        else None
      val reasonFile = sibling(out, ".reason")
      reason match
        case Some(why) => Files.writeString(reasonFile, why + "\n")
        case None      => Files.deleteIfExists(reasonFile)
      Scan(table, seen.size, missed, errors, reason)

    // A pid's UNIX sockets in a scan. Apple's lsof (dialects/darwin/libproc/dsock.c) names a socket by its bound path
    // when it has one, and by `->0x<peer pcb>` only when it has none. XNU's unp_connect copies the bound path from the
    // listener onto each accepted socket. The DEVICE field is the socket's own pcb. So:
    // - a server's clients are its rows named by the socket path beyond the listener;
    // - a row named `->` is a socket that the server opened;
    // - a client's socket names the server-side pcb that the client is connected to.
    // A live sbt server always holds its listening socket, so an empty table is a failed observation, never an idle
    // server.

    /** The pid's UNIX-socket rows, written to `file`, or None when there are none. */
    def socketTable(scanned: Scan, pid: Long, file: Path): Option[Vector[Row]] =
      val table = scanned.rows.filter(row => row.pid == pid.toString && row.kind == "unix")
      Files.write(file, table.map(_.line).asJava)
      Option.when(table.nonEmpty)(table)

    /** The listener and the accepted sockets: the table's rows named by the socket path. */
    def named(table: Vector[Row], path: String): Int = table.count(_.name == path)

    /** `pid command` of every socket in the same scan whose name is `->` followed by the pcb of one of the table's
      * path-named sockets: the live clients of the server. */
    def peers(scanned: Scan, table: Vector[Row], path: String): Vector[String] =
      val pcbs = table.filter(_.name == path).map("->" + _.device).toSet
      scanned.rows.filter(row => pcbs(row.name)).map(row => s"${row.pid} ${row.command}")

    /** The TCP ports the process listens on. */
    def listenPorts(pid: Long): Vector[String] =
      val port = "^n.*:([0-9]*)$".r
      lines("/usr/sbin/lsof", "-a", "-p", pid.toString, "-iTCP", "-sTCP:LISTEN", "-nP", "-Fn")
        .collect { case port(number) => number }.distinct.sorted

    /** The process's established TCP connections on the port. */
    def established(pid: Long, port: String): Int =
      lines("/usr/sbin/lsof", "-a", "-p", pid.toString, "-iTCP", "-sTCP:ESTABLISHED", "-nP")
        .count(_.contains(s":$port"))

    // --- Profiles, environments and commands ----------------------------------------------------------------------

    /** An allow-default profile that denies network* and allows the rules. */
    def profile(file: Path, rules: String*): Path =
      Files.write(file, (Seq("(version 1)", "(allow default)", "(deny network*)") ++ rules).asJava)

    def sandboxed(profile: Path, command: Seq[String]): Seq[String] =
      Seq("/usr/bin/sandbox-exec", "-f", profile.toString) ++ command

    /** The supervisor's closed environment, without the proxy, also written to `file` for the logs. */
    def closedEnvironment(file: Path, tmp: Path, runtimeDir: Path, extraJavaOptions: String,
        extra: (String, String)*): Environment =
      val variables = Seq(
        "PATH" -> systemPath,
        "JAVA_HOME" -> javaHome.toString,
        "HOME" -> home,
        "USER" -> account,
        "LOGNAME" -> account,
        "TMPDIR" -> tmp.toString,
        "XDG_RUNTIME_DIR" -> runtimeDir.toString,
        "_JAVA_OPTIONS" -> s"-Djava.io.tmpdir=$tmp -Djava.net.preferIPv4Stack=true $extraJavaOptions".trim,
      ) ++ extra
      Files.write(file, variables.map((name, value) => s"$name=$value").asJava)
      Environment(variables.toMap, inherit = false)

    def python(script: String): Seq[String] = Seq("python3", (work / script).toString)

    /** Runs the command to its end, bounded, with both streams in the log, and gives its status: -1 when killed at
      * the bound. */
    def logged(command: Seq[String], log: Path, timeoutSeconds: Int = 60): Int =
      val output = HostDriver.run(command, cwd = work, timeoutSeconds = Some(timeoutSeconds))
      Files.writeString(log, output.text)
      output.status

    /** A connect through bash's /dev/tcp, under the profile or unconfined, with its stderr in the log. */
    def connect(profile: Option[Path], host: String, port: String, log: Path): Connect =
      val command = Seq("/bin/bash", "-c", s"exec 3<>/dev/tcp/$host/$port")
      if logged(profile.fold(command)(sandboxed(_, command)), log, 30) == 0 then Connect.Connected
      else matchingLine(Denied, log).fold(Connect.Failed(firstLine(log)))(Connect.Denied(_))

    /** An unconfined listener from tcp-listen.py, in a group: its leader and port, or an empty port. */
    def startListener(record: Path, bind: Option[String] = None): (Long, String) =
      val out = sibling(record, ".out")
      val leader =
        groupStart(record, work, python("tcp-listen.py") ++ bind, Inherited, out, Some(sibling(record, ".log")))
      within(5, 100)(size(out) > 0)
      (leader, lineAt(out, 0))

    // --- The run --------------------------------------------------------------------------------------------------

    def measure(sbplOnly: Boolean): Int =
      val javaVersion = HostDriver.run(Seq((javaHome / "bin" / "java").toString, "-version")).text.linesIterator
        .nextOption().getOrElse("")
      transcript.log(s"machine: macOS ${lines("/usr/bin/sw_vers", "-productVersion").mkString}, " +
        s"${lines("/usr/bin/uname", "-m").mkString}; $javaVersion")
      transcript.log(s"sbt script: $sbtScript")
      transcript.log(s"scratch: $work")
      loopbackRows()
      gradleRows()
      if !sbplOnly then
        writeShutdownScript()
        SbtVersions.foreach(sbtRows)
        millRows()
      transcript.log("")
      transcript.log(s"PASS ${transcript.passed}  FAIL ${transcript.failed}")
      if transcript.failed == 0 then 0 else 1

    /** Held for the whole cleanup, so that the shutdown hook waits for a cleanup the measurement thread began: the JVM
      * exits once its hooks return. */
    private val cleanup = Object()

    def close(): Unit = cleanup.synchronized:
      val running = leaders.synchronized(Option.when(closed.compareAndSet(false, true))(leaders.keys.toVector))
      running.foreach: groups =>
        groups.foreach(endGroup)
        // Kill whatever an ended group re-parented away, found by a cwd under the scratch tree.
        withCwd(".".r, work, strict = false).foreach(pid => signal("KILL", pid.toString))
        saveLogs()
        if transcript.failed == 0 then removeTree(work) else println(s"kept for inspection: $work")

    /** Copies the run's logs, tables and records under the workspace, where the sandbox can read them. The scratch
      * tree itself keeps a short path for sbt's socket paths, and the copy leaves out the scratch tree's build
      * trees. */
    private def saveLogs(): Unit =
      removeTree(logs)
      Files.createDirectories(logs)
      val suffixes = Seq(".log", ".exit", ".timeout", ".sb", ".out")
      val prefixes = Seq("sockets-", "env", "timeline", "l5", "settle")
      for file <- filesUnder(work) do
        val relative = "./" + work.relativize(file)
        val name = file.getFileName.toString
        val kept = suffixes.exists(name.endsWith) || prefixes.exists(name.startsWith) || name.contains(".scan")
        val buildTree = Seq("/out/", "/target/", "/global/", "/ivy/").exists(relative.contains)
          || relative.startsWith("./mill/tmp/")
        if kept && !buildTree then
          val target = logs / work.relativize(file)
          Files.createDirectories(target.getParent)
          Files.copy(file, target)
      println("logs: log/run-on-host-runner-session/")

    // --- L: the SBPL rules ----------------------------------------------------------------------------------------

    def loopbackRows(): Unit =
      heading("L: SBPL loopback rules")
      Files.writeString(work / "listener.py",
        """# Bind port 0 on loopback, print the port, accept one connection or time out; exit 0 on accept.
          |import socket, sys
          |s = socket.socket()
          |s.bind(("127.0.0.1", 0))
          |s.listen(1)
          |print(s.getsockname()[1], flush=True)
          |s.settimeout(15)
          |try:
          |    s.accept()
          |except socket.timeout:
          |    sys.exit(3)
          |""".stripMargin)
      def listenerRow(label: String, rules: Path, expectBind: Boolean): Unit =
        val record = work / "listener"
        val portFile = work / "l-port"
        val err = work / "l.err"
        val leader = groupStart(record, work, sandboxed(rules, python("listener.py")), Inherited, portFile, Some(err))
        if within(5, 100)(size(portFile) > 0) then
          val port = lineAt(portFile, 0)
          connect(None, "127.0.0.1", port, work / "l-connect.log")
          awaitExit(record, 20)
          if expectBind && statusOf(record).contains(0) then pass(label, s"bound port $port, accepted a connection")
          else if expectBind then fail(label, s"bound port $port; ${failed(record, err)}")
          else fail(label, s"bound port $port without a rule")
        else
          awaitExit(record, 20)
          matchingLine(Denied, err).filter(_ => !expectBind && !statusOf(record).contains(124)) match
            case Some(denial) => pass(label, s"bind denied: $denial")
            case None         => fail(label, s"no port; ${failed(record, err)}")
        endGroup(leader)
      listenerRow("L1 bind port 0 + accept under (local ip localhost:*)",
        profile(work / "l1.sb", """(allow network-bind network-inbound (local ip "localhost:*"))"""), expectBind = true)
      listenerRow("L2 control: no rule denies the bind", profile(work / "l2.sb"), expectBind = false)

      Files.writeString(work / "two.py",
        """import socket, time
          |a, b = socket.socket(), socket.socket()
          |for s in (a, b):
          |    s.bind(("127.0.0.1", 0)); s.listen(1)
          |print(a.getsockname()[1], b.getsockname()[1], flush=True)
          |time.sleep(60)
          |""".stripMargin)
      val two = work / "l-two"
      val twoLeader = groupStart(work / "two", work, python("two.py"), Inherited, two, Some(work / "two.err"))
      within(5, 100)(size(two) > 0)
      val (portOk, portOther) = lineAt(two, 0).split(" ") match
        case Array(first, second) => (first, second)
        case _                    => ("", "")
      val exactPort = profile(work / "l3.sb", s"""(allow network-outbound (remote ip "localhost:$portOk"))""")
      connect(Some(exactPort), "127.0.0.1", portOk, work / "l3.err") match
        case Connect.Connected => pass("L3 exact-port outbound reaches its port", s"localhost:$portOk")
        case Connect.Denied(line) => fail("L3 exact-port outbound reaches its port", line)
        case Connect.Failed(line) => fail("L3 exact-port outbound reaches its port", line)
      connect(Some(exactPort), "127.0.0.1", portOther, work / "l4.err") match
        case Connect.Connected => fail("L4 exact-port outbound denies the neighbor", s"connected to $portOther")
        case Connect.Denied(line) => pass("L4 exact-port outbound denies the neighbor", s"denied: $line")
        case Connect.Failed(line) => fail("L4 exact-port outbound denies the neighbor", s"failed otherwise: $line")
      endGroup(twoLeader)

      // L5: whether the checked scan can be complete on this host at all. The probe takes the scan once here, idle.
      val idle = scan(work / "l5")
      idle.reason match
        case None => pass("L5 the checked scan is complete", s"${idle.seen} processes")
        case Some(reason) =>
          fail("L5 the checked scan is complete", reason)
          showTable(idle.missed.take(5).flatMap(pid => lines("/bin/ps", "-o", "pid=,user=,comm=", "-p", pid.toString)))
          showTable(idle.errors.take(5).map(_.line))

    // --- G: the SBPL rules a Gradle profile needs -----------------------------------------------------------------

    // What Gradle binds:
    // - Gradle's TCP listeners bind the loopback address on port 0 (TcpIncomingConnector, InetAddressFactory), which
    //   L1 covers;
    // - Gradle's file-lock socket binds the wildcard address on port 0 (DefaultFileLockCommunicator);
    // - a build's own tests bind where they like.
    // The candidate profile grants any bind and names "localhost" for what arrives and leaves. These rows measure,
    // under the candidate and under the mill daemon's rule, whether that class stops at loopback or covers every
    // address of this host. The mill daemon's rule admits the same binds (seatbelt.md, "Network", records the answer).
    // The LAN rows send to this host's own LAN address: the packet's addresses are the LAN's even when the route is
    // local, and the unconfined controls show that the receiver hears the packet that way.
    //
    // Each probe gives one outcome word and its detail. The outcomes that a rule can produce:
    // - `answered`: the sender got the answer too;
    // - `heard`;
    // - `accepted`;
    // - `nothing`: the socket's own deadline passed with nothing arriving;
    // - `refused`: the receive, accept or send died on the operating system's denial;
    // - `no bind`: the bind died on the denial.
    // Anything else is `failed`: the deadline of the process itself, a launch that failed, or an error that is not the
    // denial. A row that expects a denial fails on `failed`, because an observation that did not happen approves
    // nothing.

    /** A probe of the G rows: the profile, or None for none, the destination host and an optional bind address. */
    type Probe = (Option[Path], String, Option[String]) => String

    /** Runs the command under the profile in a group and awaits its first output line: its leader and that line, or
      * an empty line. */
    def confined(record: Path, rules: Option[Path], command: Seq[String]): (Long, String) =
      val out = sibling(record, ".out")
      val leader = groupStart(record, work, rules.fold(command)(sandboxed(_, command)), Inherited, out,
        Some(sibling(record, ".log")))
      (leader, if within(5, 100)(size(out) > 0) then lineAt(out, 0) else "")

    /** The socket's own outcome once the process has ended: HEARD-WORD when the process's output matches the pattern,
      * and otherwise by the exit status. Status 3 is the socket's deadline, and status 4 is the socket's failure,
      * which is `refused` only on the denial. */
    def socketOutcome(record: Path, port: String, heardPattern: String, heardWord: String): String =
      awaitExit(record, 20)
      val out = sibling(record, ".out")
      val second = lineAt(out, 1)
      if hasLine(heardPattern, out) then s"$heardWord port $port; $second"
      else if statusOf(record).contains(3) then s"nothing arrived at port $port"
      else if statusOf(record).contains(4) && hasLine(Denied, out) then s"refused: $second"
      else s"failed: ${failed(record, sibling(record, ".log"))}$second"

    /** The outcome of a process that printed no port. */
    def bindOutcome(record: Path): String =
      awaitExit(record, 20)
      val log = sibling(record, ".log")
      matchingLine(Denied, log).filter(_ => !statusOf(record).contains(124)) match
        case Some(denial) => s"no bind: $denial"
        case None         => s"failed: ${failed(record, log)}"

    /** Sends one datagram from an unconfined sender to the host, at a wildcard UDP socket under the profile. */
    val udpProbe: Probe = (rules, host, bind) =>
      val record = work / "g-recv"
      val (leader, port) = confined(record, rules, python("udp-recv.py") ++ bind)
      val seen =
        if port.isEmpty then bindOutcome(record)
        else
          val sendLog = work / "g-send.log"
          val sent = logged(python("udp-send.py") ++ Seq(host, port), sendLog)
          val outcome = socketOutcome(record, port, "^received", "heard")
          // The receiver's silence counts only when the sender sent and waited out its answer.
          if outcome.startsWith("heard") && sent == 0 then "answered " + outcome.stripPrefix("heard ")
          else if outcome.startsWith("nothing") && sent != 3 then s"failed: sender exit $sent: ${firstLine(sendLog)}"
          else outcome
      endGroup(leader)
      seen

    /** Makes one unconfined connect to the host, at a wildcard TCP listener under the profile. */
    val tcpProbe: Probe = (rules, host, bind) =>
      val record = work / "g-listen"
      val (leader, port) = confined(record, rules, python("tcp-listen.py") ++ bind)
      val seen =
        if port.isEmpty then bindOutcome(record)
        else
          val connectLog = work / "g-connect.log"
          connect(None, host, port, connectLog)
          val outcome = socketOutcome(record, port, "^accepted", "accepted")
          if outcome.startsWith("nothing") then s"$outcome; connect: ${firstLine(connectLog)}" else outcome
      endGroup(leader)
      seen

    /** Sends one datagram from a sender under the profile to the host, at an unconfined wildcard UDP socket. The
      * outcome is `answered`, `heard` (the sender got no answer), `nothing` when the socket's deadline passed with the
      * sender denied, or `failed`. */
    val udpSendProbe: Probe = (rules, host, _) =>
      val record = work / "g-uncon"
      val (leader, port) = confined(record, None, python("udp-recv.py"))
      val seen =
        if port.isEmpty then bindOutcome(record)
        else
          val sendLog = work / "g-csend.log"
          val send = python("udp-send.py") ++ Seq(host, port)
          val sent = logged(rules.fold(send)(sandboxed(_, send)), sendLog)
          val outcome = socketOutcome(record, port, "^received", "heard")
          if outcome.startsWith("heard") && sent == 0 then "answered " + outcome.stripPrefix("heard ")
          else if !outcome.startsWith("nothing") then outcome
          else if hasLine(s"send failed: .*$Denied", sendLog) then s"$outcome; send denied"
          else if sent == 3 then s"$outcome; the datagram left and never arrived"
          else s"failed: sender exit $sent: ${firstLine(sendLog)}"
      endGroup(leader)
      seen

    def gradleRows(): Unit =
      heading("G: SBPL rules for Gradle")
      Files.writeString(work / "udp-recv.py",
        """# Bind port 0 on the wildcard address, or the one given, print the port, wait for one datagram,
          |# answer it: exit 0 on receipt, 3 on the deadline, 4 when the receive itself fails.
          |import socket, sys
          |s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          |s.bind((sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0", 0))
          |print(s.getsockname()[1], flush=True)
          |s.settimeout(15)
          |try:
          |    data, peer = s.recvfrom(64)
          |except socket.timeout:
          |    sys.exit(3)
          |except OSError as ex:
          |    print("receive failed: %s" % ex, flush=True)
          |    sys.exit(4)
          |print("received from %s:%d" % peer, flush=True)
          |try:
          |    s.sendto(b"ack", peer)
          |except OSError as ex:
          |    print("answer failed: %s" % ex, flush=True)
          |""".stripMargin)
      Files.writeString(work / "udp-send.py",
        """# One datagram to HOST PORT, then its answer: exit 0 on an answer, 3 on none, 4 when the send
          |# itself fails, 5 when the receive does.
          |import socket, sys
          |s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          |s.settimeout(5)
          |try:
          |    s.sendto(b"ping", (sys.argv[1], int(sys.argv[2])))
          |except OSError as ex:
          |    print("send failed: %s" % ex, flush=True)
          |    sys.exit(4)
          |try:
          |    s.recvfrom(64)
          |except socket.timeout:
          |    sys.exit(3)
          |except OSError as ex:
          |    print("receive failed: %s" % ex, flush=True)
          |    sys.exit(5)
          |""".stripMargin)
      Files.writeString(work / "tcp-listen.py",
        """# Bind port 0 on the wildcard address, or the one given, print the port, accept one connection:
          |# exit 0 on accept, 3 on the deadline, 4 when the accept itself fails.
          |import socket, sys
          |s = socket.socket()
          |s.bind((sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0", 0))
          |s.listen(1)
          |print(s.getsockname()[1], flush=True)
          |s.settimeout(15)
          |try:
          |    conn, peer = s.accept()
          |except socket.timeout:
          |    sys.exit(3)
          |except OSError as ex:
          |    print("accept failed: %s" % ex, flush=True)
          |    sys.exit(4)
          |print("accepted from %s:%d" % peer, flush=True)
          |""".stripMargin)
      val interface = lines("/sbin/route", "-n", "get", "default").map(_.trim)
        .collectFirst { case line if line.startsWith("interface:") => line.stripPrefix("interface:").trim }
      val lanIp = interface.flatMap(name => lines("/usr/sbin/ipconfig", "getifaddr", name).headOption.map(_.trim))
        .filter(_.nonEmpty)
      transcript.log(lanIp.fold("no LAN address: the LAN rows are not measured")(ip => s"LAN address: $ip"))
      val millRule = work / "l1.sb"
      val noRule = work / "l2.sb"
      val candidate = profile(work / "g.sb",
        """(allow network-bind (local ip "*:*"))""",
        """(allow network-inbound (local ip "localhost:*"))""",
        """(allow network-outbound (remote ip "localhost:*"))""")

      // A row with no expected outcome still fails when the helper produced no measurement.
      def observe(label: String, outcome: String): Unit =
        if outcome.startsWith("failed") then fail(label, outcome) else info(label, outcome)
      // Runs the unconfined control first, because the LAN address must be heard or the row measures nothing. Then
      // runs the probe under the profile at this host's LAN address and reports the probe as the measurement it is. A
      // failed observation is still a FAIL.
      def lanRow(label: String, probe: Probe, rules: Path, bindToLan: Boolean = false): Unit = lanIp match
        case None => skip(label, "no LAN address")
        case Some(lan) =>
          val bind = Option.when(bindToLan)(lan)
          val control = probe(None, lan, bind)
          if !Seq("heard", "answered", "accepted").exists(control.startsWith) then
            fail(label, s"control: unconfined, the LAN address is not heard: $control")
          else
            observe(label, probe(Some(rules), lan, bind))
      def expect(label: String, outcome: String, word: String): Unit =
        if outcome.startsWith(word) then pass(label, outcome) else fail(label, outcome)

      // G1: whether the Mill rule already admits a wildcard UDP bind decides whether the bind grant must widen to
      // "*:*" at all.
      observe("G1 wildcard UDP bind under (local ip localhost:*)", udpProbe(Some(millRule), "127.0.0.1", None))
      expect("G2 control: no rule denies the wildcard UDP bind", udpProbe(Some(noRule), "127.0.0.1", None), "no bind")
      expect("G3 wildcard UDP socket answers at the loopback address", udpProbe(Some(candidate), "127.0.0.1", None),
        "answered")
      lanRow("G4 wildcard UDP socket at the LAN address", udpProbe, candidate)
      expect("G5 wildcard TCP listener accepts at the loopback address", tcpProbe(Some(candidate), "127.0.0.1", None),
        "accepted")
      lanRow("G6 wildcard TCP listener at the LAN address", tcpProbe, candidate)

      // G7, G8: the outbound side, against an unconfined wildcard socket, at any loopback port and at the LAN address.
      // TCP is measured by a connect, and UDP by a datagram from a confined sender.
      val (g7Leader, g7Port) = startListener(work / "g7")
      connect(Some(candidate), "127.0.0.1", g7Port, work / "g7-loop.log") match
        case Connect.Connected => pass("G7 outbound reaches any loopback port", s"127.0.0.1:$g7Port")
        case Connect.Denied(line) => fail("G7 outbound reaches any loopback port", line)
        case Connect.Failed(line) => fail("G7 outbound reaches any loopback port", line)
      endGroup(g7Leader)
      // By this row, G6's unconfined control has shown that the LAN address is reachable.
      // The profile comes from the listener's port.
      def lanConnectRow(label: String, record: Path, rules: String => Path, bindToLan: Boolean): Unit = lanIp match
        case None => skip(label, "no LAN address")
        case Some(lan) =>
          val (leader, port) = startListener(record, Option.when(bindToLan)(lan))
          connect(Some(rules(port)), lan, port, sibling(record, "-lan.log")) match
            case Connect.Connected => info(label, s"connected to $lan:$port")
            case Connect.Denied(line) => info(label, s"denied: $line")
            case Connect.Failed(line) => fail(label, s"failed otherwise: $line")
          endGroup(leader)
      lanConnectRow("G7 outbound at the LAN address", work / "g7b", _ => candidate, bindToLan = false)
      expect("G8 outbound UDP reaches any loopback port", udpSendProbe(Some(candidate), "127.0.0.1", None), "answered")
      lanRow("G8 outbound UDP at the LAN address", udpSendProbe, candidate)
      // G9, G10: the same under the mill daemon's rule, (local ip "localhost:*") for bind and inbound, which every
      // process that the daemon forks inherits. G9 is a wildcard bind reached at the LAN address, and G10 is a bind to
      // the LAN address itself.
      lanRow("G9 mill rule: wildcard TCP listener at the LAN address", tcpProbe, millRule)
      lanRow("G9 mill rule: wildcard UDP socket at the LAN address", udpProbe, millRule)
      lanRow("G10 mill rule: TCP listener bound to the LAN address", tcpProbe, millRule, bindToLan = true)
      lanRow("G10 mill rule: UDP socket bound to the LAN address", udpProbe, millRule, bindToLan = true)
      // G11: the exact-port rule that every client and the proxy rule use, (remote ip "localhost:<port>"), against a
      // listener bound to the LAN address on that port. The row measures whether the port grant covers one address or
      // every address of this host. An unconfined listener binds the LAN address, the rule then names the listener's
      // port, and the connect runs under the rule.
      lanConnectRow("G11 exact-port outbound at the LAN address", work / "g11",
        port => profile(work / "g11.sb", s"""(allow network-outbound (remote ip "localhost:$port"))"""),
        bindToLan = true)
      // G12: a remote destination under the candidate's (remote ip "localhost:*"). An IP literal keeps DNS out, and the
      // connect or send must die on the denial, never on a slow timeout.
      connect(Some(candidate), "1.1.1.1", "443", work / "g12-tcp.log") match
        case Connect.Connected => fail("G12 candidate denies a remote TCP destination", "connected to 1.1.1.1:443")
        case Connect.Denied(line) => pass("G12 candidate denies a remote TCP destination", s"denied: $line")
        case Connect.Failed(line) => fail("G12 candidate denies a remote TCP destination", s"failed otherwise: $line")
      // The send itself must meet the denial, because the helper's receive can be denied on its own.
      val udpLog = work / "g12-udp.log"
      if logged(sandboxed(candidate, python("udp-send.py") ++ Seq("1.1.1.1", "53")), udpLog) == 0 then
        fail("G12 candidate denies a remote UDP destination", "1.1.1.1:53 answered")
      else matchingLine(s"send failed: .*$Denied", udpLog) match
        case Some(denial) => pass("G12 candidate denies a remote UDP destination", s"denied: $denial")
        case None         =>
          fail("G12 candidate denies a remote UDP destination", s"failed otherwise: ${firstLine(udpLog)}")

    // --- S: sbt, per version --------------------------------------------------------------------------------------

    def writeShutdownScript(): Unit = Files.writeString(work / "shutdown.py",
      """# sbt's local-socket shutdown at a given socket path (RunOnHostSbtServerShutdown, session-recovery.sh M4).
        |import socket, sys, time, uuid
        |deadline = time.monotonic() + 120
        |s = socket.socket(socket.AF_UNIX)
        |s.settimeout(120)
        |s.connect(sys.argv[1])
        |def send(msg):
        |    body = msg.encode()
        |    s.sendall(f"Content-Length: {len(body) + 2}\r\n\r\n".encode() + body + b"\r\n")
        |opts = '{"skipAnalysis":true,"canWork":true,"subscribeToAll":false}'
        |send('{ "jsonrpc": "2.0", "id": "%s", "method": "initialize",'
        |     ' "params": { "initializationOptions": %s } }' % (uuid.uuid4(), opts))
        |try:
        |    s.recv(4096)
        |except OSError:
        |    pass
        |send('{ "jsonrpc": "2.0", "id": "%s", "method": "sbt/exec",'
        |     ' "params": { "commandLine": "shutdown" } }' % uuid.uuid4())
        |try:
        |    while s.recv(4096) and time.monotonic() < deadline:
        |        pass
        |except OSError:
        |    pass
        |""".stripMargin)

    def sbtRows(version: String): Unit =
      val d = work / s"s${version.takeWhile(_ != '.')}"
      val (proj, srv, cmd, global, ivy) = (d / "proj", d / "srv", d / "cmd", d / "global", d / "ivy")
      Seq(proj / "project", proj / "src" / "main" / "scala", srv, cmd, global, ivy).foreach(Files.createDirectories(_))
      Files.writeString(proj / "project" / "build.properties", s"sbt.version=$version\n")
      Files.writeString(proj / "build.sbt", "fork := true\n")
      Files.writeString(proj / "src" / "main" / "scala" / "Main.scala",
        """object Main {
          |  def main(args: Array[String]): Unit = {
          |    println("probe-main")
          |    Thread.sleep(120000)
          |  }
          |}
          |""".stripMargin)
      val portfile = proj / "project" / "target" / "active.json"
      val sbt = sbtScript.toString
      // The server JVM: an executable named java whose arguments carry -Dsbt.script. The script that execs the JVM
      // and the group's leader carry the same option, but run as bash and perl. ps prints the executable apart from
      // the arguments, so a JAVA_HOME with a space still matches.
      def servers(): Vector[Long] = withCwd("-Dsbt\\.script=".r, proj).filter: pid =>
        lines("/bin/ps", "-o", "comm=", "-p", pid.toString).headOption.map(_.trim)
          .exists(name => name == "java" || name.endsWith("/java"))
      // srv is the owner's directory and holds the socket budget; tmp is the process's own. `-Dsbt.global.base` puts
      // the sbt 2 proc registry under the global base (CommandExchange.notifyOtherServers).
      def sbtOptions(tmp: Path) = s"-Djava.util.prefs.userRoot=$tmp -Dsbt.global.base=$global -Dsbt.ivy.home=$ivy"
      val serverEnvironment =
        closedEnvironment(d / "env-srv", srv, srv, sbtOptions(srv), "SBT_GLOBAL_SERVER_DIR" -> srv.toString)
      val clientEnvironment =
        closedEnvironment(d / "env-cmd", cmd, srv, sbtOptions(cmd), "SBT_GLOBAL_SERVER_DIR" -> srv.toString)
      val clientArgs = Seq("--jvm-client", "-batch", "-java-home", javaHome.toString)
      // A client with its own tmp, which attaches to the portfile, with a deadline.
      def client(name: String, log: String, command: Seq[String]): Boolean =
        bounded(300, d / name, proj, command, clientEnvironment, d / log).contains(0)

      heading(s"S: sbt $version")
      // S1: the owner's command line in a group of its own, with stdio as the runner gives its server. The command
      // line is NetworkClient.serverCommand's, to which the client passes -Dsbt.script and not -batch.
      val serverRecord = d / "server"
      val serverLeader = groupStart(serverRecord, proj, Seq(sbt, s"-Dsbt.script=$sbt", "--detach-stdio", "--server"),
        serverEnvironment, d / "server-out.log", Some(d / "server-err.log"))
      val started = System.nanoTime
      within(420, 100)(Files.exists(portfile) || exited(serverRecord))
      if !Files.exists(portfile) then
        fail("S1 owner-started server publishes the portfile", failed(serverRecord, d / "server-err.log"))
        endGroup(serverLeader)
        return
      pass("S1 owner-started server publishes the portfile", s"${secondsSince(started)}s; ${text(portfile).trim}")
      val server = servers().headOption match
        case Some(pid) => pid
        case None =>
          fail("S1 server process found by cwd", "none")
          endGroup(serverLeader)
          return
      val serverStart = RunOnHostIdle.startOf(server)
      def sameServer: Boolean = sameProcess(server, serverStart)
      if text(portfile).contains(s"local://$srv/") then pass("S1 socket under the owner's directory", srv.toString)
      else fail("S1 socket under the owner's directory", text(portfile).trim)
      val socket = "\"uri\" *: *\"local://([^\"]*)\"".r.findFirstMatchIn(text(portfile)).fold("")(_.group(1))

      // S2: a client with its own tmp attaches; the server stays the same process, and there is one server.
      if client("about", "client-about.log", Seq(sbt) ++ clientArgs :+ "about") && sameServer && servers().size == 1
      then
        pass("S2 client attaches; same server, no fork", s"pid $server")
        val idle = scan(d / "scan-idle")
        idle.reason.fold(socketTable(idle, server, d / "sockets-idle"))(_ => None) match
          case Some(table) =>
            info("S2 idle server's UNIX sockets",
              s"${named(table, socket)} named by the socket path; ${table.count(_.line.contains("->"))} ->")
          case None => fail("S2 idle server's UNIX sockets", idle.reason.getOrElse(s"no sockets for pid $server"))
      else
        fail("S2 client attaches; same server, no fork",
          s"servers: ${servers().mkString(" ")}; ${failed(d / "about", d / "client-about.log")}")

      // S3: the client's unix-socket rule, the right directory.
      val clientProfile =
        profile(d / "client.sb", s"""(allow network-outbound (remote unix-socket (subpath "$srv")))""")
      if client("about-sb", "client-sb.log", sandboxed(clientProfile, Seq(sbt) ++ clientArgs :+ "about")) then
        pass("S3 client under (remote unix-socket (subpath owner-tmp))", "attached")
      else
        fail("S3 client under (remote unix-socket (subpath owner-tmp))", failed(d / "about-sb", d / "client-sb.log"))

      // S4: a TERMed client mid-run cancels the exec; the row records what the forked JVM does.
      val runLeader = groupStart(d / "run", proj, Seq(sbt) ++ clientArgs :+ "run", clientEnvironment,
        d / "client-run.log")
      def forked(): Option[Long] = pgrep(s"$proj/target").headOption
      if within(300, 100)(hasLine("probe-main", d / "client-run.log")) && forked().nonEmpty then
        val forkedPid = forked().get
        // The idle detector for a confined sbt server counts the clients of the server's path-named sockets, as
        // `peers` finds them.
        // - No runner path reads this measurement: the runner shuts the user's server down by protocol after its
        //   exec, and attaches to or takes over another launch's server (doc/run-on-host-internals.md, "The channel
        //   and the command").
        // - The detector looks at the server JVM, never its group leader, and has no baseline, as a runner that takes
        //   over has none.
        // - The rows measure the detector first on the already-busy server, then after the client is gone, and then
        //   with an unrelated UNIX connection that the server itself opened beside a connected client. The tables
        //   follow each row.
        def detector(label: String, table: Path, expectedPeers: Int): Unit =
          val scanned = scan(sibling(table, ".scan"))
          scanned.reason match
            case Some(reason) => fail(label, s"unknown: $reason")
            case None => socketTable(scanned, server, table) match
              case None => fail(label, s"no sockets for pid $server")
              case Some(rows) =>
                val found = peers(scanned, rows, socket)
                val detail = s"${named(rows, socket)} named by the socket path; live peers: " +
                  (if found.isEmpty then "none" else found.mkString(","))
                if found.size == expectedPeers then pass(label, detail) else fail(label, detail)
                showTable(rows.map(_.line))
        detector("S4 detector: busy server, no baseline", d / "sockets-busy", 1)
        endGroup(runLeader)
        within(20, 100):
          val settled = scan(d / "settle.scan")
          settled.reason.isEmpty
            && socketTable(settled, server, d / "settle").exists(peers(settled, _, socket).isEmpty)
        detector("S4 detector: none after the client is gone", d / "sockets-after", 0)
        if within(20, 100)(gone(forkedPid)) then
          info("S4 forked JVM after the client's TERM", "ended within 20s: the cancel reached it")
        else
          info("S4 forked JVM after the client's TERM", "alive after 20s; killed")
          signal("TERM", forkedPid.toString)
        if sameServer && client("after", "client-after.log", Seq(sbt) ++ clientArgs :+ "about") then
          pass("S4 server answers after a cancelled command", s"pid $server")
        else fail("S4 server answers after a cancelled command", failed(d / "after", d / "client-after.log"))
        // The third case: while a client is connected, the server holds a UNIX connection that is no client of its
        // own, because the server's build opened it to an unrelated listener. The candidate counts both; the kept
        // table shows what tells them apart, if anything does.
        val unrelatedSocket = d / "unrelated.sock"
        val unrelatedLeader = groupStart(d / "unrelated", d, Seq("python3", "-c",
          """import socket, sys, time
            |s = socket.socket(socket.AF_UNIX); s.bind(sys.argv[1]); s.listen(1); print("bound", flush=True)
            |time.sleep(60)""".stripMargin, unrelatedSocket.toString), Inherited, d / "unrelated.log")
        // The fixture confirms its own setup by its own markers, never by the detector under test. The listener says
        // `bound`, and the eval says `probe-connected` once connected. Only then does the probe capture the table,
        // whatever the detector counts in it.
        if !within(5, 100)(hasLine("bound", d / "unrelated.log")) then
          fail("S4 unrelated listener bound", firstLine(d / "unrelated.log"))
        else
          val evaluate = "eval { val c = java.nio.channels.SocketChannel.open(java.net.StandardProtocolFamily.UNIX); " +
            s"""c.connect(java.net.UnixDomainSocketAddress.of("$unrelatedSocket")); println("probe-connected"); """ +
            "Thread.sleep(20000); c.close(); 0 }"
          val evalLeader = groupStart(d / "eval", proj, Seq(sbt) ++ clientArgs :+ evaluate, clientEnvironment,
            d / "client-eval.log")
          if !within(120, 100)(hasLine("probe-connected", d / "client-eval.log")) then
            fail("S4 the server opened the unrelated connection",
              s"no probe-connected within 120s: ${firstLine(d / "client-eval.log")}")
          else detector("S4 detector: one client beside an unrelated connection", d / "sockets-unrelated", 1)
          endGroup(evalLeader)
        endGroup(unrelatedLeader)
      else
        fail("S4 run reaches its forked JVM", failed(d / "run", d / "client-run.log"))
        endGroup(runLeader)

      // S5: sbt 2's proc registry lies under the global base, and nowhere under the user's caches.
      val ours = filesUnder(global).map(_.toString).filter(_.matches(".*/proc/.*\\.json")).take(3).mkString(" ")
      val theirs = Seq(Path.of(home, ".cache", "sbt"), Path.of(home, "Library", "Caches", "sbt")).flatMap(filesUnder)
        .map(_.toString).filter(_.endsWith(s"/proc/$server.json")).mkString(" ")
      def orNone(text: String) = if text.isEmpty then "none" else text
      if version.startsWith("2.") then
        if ours.nonEmpty && theirs.isEmpty then pass("S5 proc entry under the global base only", ours)
        else fail("S5 proc entry under the global base only", s"ours: ${orNone(ours)}; user caches: ${orNone(theirs)}")
      else info("S5 proc entries (sbt 1 has no registry)", s"ours: ${orNone(ours)}; user caches: ${orNone(theirs)}")

      // S6: the wrong-directory control runs last. A client whose connect is denied treats the server as dead: the
      // client deletes the portfile and starts a server of its own, which the profile denies too. So:
      // - the row has its own deadline;
      // - the probe reads the denial from the client's output or from the portfile that the client replaced;
      // - the probe measures what the client left of the owner's server before the shutdown.
      val wrongProfile = profile(d / "wrong.sb", s"""(allow network-outbound (remote unix-socket (subpath "$cmd")))""")
      val before = text(portfile)
      val wrongRecord = d / "wrong"
      val wrongLeader = groupStart(wrongRecord, proj, sandboxed(wrongProfile, Seq(sbt) ++ clientArgs :+ "about"),
        clientEnvironment, d / "client-wrong.log")
      // Records a timeline while the client runs, one line per change, of the owner's server, the portfile, the socket
      // file and the servers that the client spawns. The probe copies the spawned servers' stderr file while the file
      // exists, because the client deletes the file at exit. The order says what ended the owner's server, if anything
      // did.
      val timeline = d / "timeline"
      val timelineStart = System.nanoTime
      var last = ""
      val socketPath = Path.of(socket)
      def recordTimeline(): Boolean =
        val state = s"server=${if gone(server) then "gone" else "alive"} " +
          s"portfile=${if Files.exists(portfile) then "present" else "absent"} " +
          s"socket=${if isSocket(socketPath) then "present" else "absent"} " +
          s"servers=${servers().filterNot(_ == server).map(pid => s"$pid,").mkString}"
        if state != last then
          Files.writeString(timeline, s"${secondsSince(timelineStart)}s $state\n", StandardOpenOption.CREATE,
            StandardOpenOption.APPEND)
          last = state
        listedNames(cmd).filter(name => name.startsWith("sbt-server-err") && name.endsWith(".log")).foreach: name =>
          try Files.copy(cmd / name, d / "second-server-err.log", java.nio.file.StandardCopyOption.REPLACE_EXISTING)
          catch case _: IOException => ()
        exited(wrongRecord)
      if !within(120, 100)(recordTimeline()) then Files.writeString(sibling(wrongRecord, ".timeout"), "")
      endGroup(wrongLeader)
      val wrong = failed(wrongRecord, d / "client-wrong.log")
      val portfileNow = text(portfile)
      if statusOf(wrongRecord).contains(0) then fail("S6 control: wrong directory is denied", "the client attached")
      else if hasLine(Denied, d / "client-wrong.log") then
        val denial = text(d / "client-wrong.log").linesIterator.find(_.contains(Denied)).getOrElse("").take(60)
        pass("S6 control: wrong directory is denied", s"$wrong; $denial")
      else if portfileNow != before then
        pass("S6 control: wrong directory is denied", s"$wrong; the client replaced the portfile")
      else fail("S6 control: wrong directory is denied", s"failed otherwise: $wrong")
      if portfileNow == before then info("S6 portfile after the denied client", "kept")
      else
        info("S6 portfile after the denied client",
          s"changed: ${if Files.exists(portfile) then portfileNow.trim else "deleted"}")
      info("S6 socket file after the denied client", if isSocket(socketPath) then "kept" else "gone")
      if sameServer then info("S6 server after the denied client", s"alive, pid $server")
      else
        info("S6 server after the denied client", s"gone, exit ${statusOf(serverRecord).fold("none")(_.toString)}; " +
          s"servers now: ${servers().mkString(" ")}; the timeline follows")
        showTable(text(timeline).linesIterator.toSeq)
        for log <- Seq(d / "server-out.log", d / "server-err.log", d / "second-server-err.log") if Files.exists(log) do
          showTable(s"==> $log <==" +: text(log).linesIterator.toSeq.takeRight(5))

      if !isSocket(socketPath) then
        info("S6 protocol shutdown at the recorded socket", "skipped: the socket file is gone")
      else if !sameServer then info("S6 protocol shutdown at the recorded socket", "skipped: the server is gone")
      else
        val shutdown = bounded(150, d / "shutdown", proj, python("shutdown.py") :+ socket, Inherited,
          d / "shutdown.log")
        if shutdown.contains(0) && within(60, 100)(servers().isEmpty) then
          pass("S6 protocol shutdown at the recorded socket ends the server", "")
        else
          fail("S6 protocol shutdown at the recorded socket ends the server",
            s"${servers().mkString(" ")} still here; ${failed(d / "shutdown", d / "shutdown.log")}")
      endGroup(serverLeader)

    // --- M: Mill --------------------------------------------------------------------------------------------------

    def millRows(): Unit =
      heading(s"M: Mill $MillVersion")
      val mp = work / "mill"
      Files.createDirectories(mp / "app" / "src")
      Files.createDirectories(mp / "tmp")
      Files.copy(root / "src" / "test" / "run-on-host" / "fixtures" / "mill" / "mill", mp / "mill")
      (mp / "mill").toFile.setExecutable(true)
      Files.writeString(mp / "build.mill",
        s"""//| mill-version: $MillVersion
           |//| mill-jvm-version: system
           |package build
           |import mill.*, scalalib.*
           |
           |object app extends ScalaModule {
           |  def scalaVersion = "$ScalaVersion"
           |}
           |
           |def probeEnv() = Task.Command {
           |  println("PROBE_ENV=" + Task.env.getOrElse("PROBE_ENV", "unset"))
           |}
           |""".stripMargin)
      Files.writeString(mp / "app" / "src" / "App.scala",
        """object App {
          |  def main(args: Array[String]): Unit = {
          |    println("probe-main")
          |    Thread.sleep(120000)
          |  }
          |}
          |""".stripMargin)
      def daemons(): Vector[Long] = withCwd("mill\\.daemon\\.MillDaemonMain".r, mp / "out" / "mill-daemon")
      def endDaemons(): Unit =
        daemons().foreach(pid => signal("TERM", pid.toString))
        within(20, 100)(daemons().isEmpty)
      // The download folder as the bootstrap derives it (RunOnHostPrereqs.millDownloadDir). The probe resolves the
      // folder once here and gives it to every row the way the supervisor gives it, so that provisioning and the rows
      // agree on it whatever MILL_FINAL_DOWNLOAD_FOLDER or XDG_CACHE_HOME the host has set.
      def set(name: String) = sys.env.get(name).filter(_.nonEmpty)
      val downloads = "MILL_FINAL_DOWNLOAD_FOLDER" -> set("MILL_FINAL_DOWNLOAD_FOLDER")
        .getOrElse(s"${set("XDG_CACHE_HOME").getOrElse(s"$home/.cache")}/mill/download")
      val unconfined = Environment(sys.env -- MillOverrides + downloads, inherit = false)
      def millEnvironment(name: String, extra: (String, String)*) =
        closedEnvironment(mp / name, mp / "tmp", mp / "tmp", "", (downloads +: extra)*)
      val baseEnvironment = millEnvironment("env")
      val daemonProfile = profile(mp / "daemon.sb", """(allow network-bind network-inbound (local ip "localhost:*"))""")
      // M2's client, which is ./mill until M2 chooses one.
      var millClient = Seq("./mill")
      def clientName = millClient.mkString(" ")
      // A confined client in the closed environment, bounded.
      def runClient(name: String, command: Seq[String], environment: Environment = baseEnvironment): Option[Int] =
        bounded(300, mp / name, mp, command, environment, mp / s"$name.log")
      // Starts the starter under the daemon profile, in a group of its own, with the given environment. Gives the
      // starter's leader and the MillDaemonMain in that group.
      def startDaemon(environment: Environment): (Long, Option[Long]) =
        val record = mp / "starter"
        val leader = groupStart(record, mp, sandboxed(daemonProfile, millClient :+ "version"), environment,
          mp / "starter.log")
        if !within(120, 100)(exited(record)) then
          Files.writeString(sibling(record, ".timeout"), "")
          fail("starter ./mill version under the daemon profile", failed(record, mp / "starter.log"))
          endGroup(leader)
        (leader, groupMember(leader, "MillDaemonMain"))

      // Provisioning runs unconfined, but in a group of its own that ends with it, daemon included. Provisioning
      // fetches the executable, Mill's `mill-daemon-classpath` file and the compiler.
      transcript.log(s"provisioning mill $MillVersion and its compiler, unconfined (can take a few minutes)")
      if !bounded(900, mp / "provision", mp, Seq("./mill", "app.compile"), unconfined, mp / "provision.log").contains(0)
      then
        fail("M0 unconfined ./mill app.compile",
          s"${failed(mp / "provision", mp / "provision.log")}; the log's tail follows")
        showTable(text(mp / "provision.log").linesIterator.toSeq.takeRight(8))
        endDaemons()
        return
      endDaemons()
      // Provisioning also fetches the JVM launcher for the M2 candidate that needs it: `-jvm` makes the bootstrap
      // fetch mill-dist's executable assembly, which the PATH's java runs.
      val jvmLauncher = Seq("/usr/bin/env", s"MILL_VERSION=$MillVersion-jvm", "./mill")
      if !bounded(600, mp / "provision-jvm", mp, jvmLauncher :+ "version", unconfined, mp / "provision-jvm.log")
        .contains(0)
      then info("M0 unconfined JVM launcher", failed(mp / "provision-jvm", mp / "provision-jvm.log"))
      endDaemons()

      // M1: the profile denies the starter's connect; the daemon stays in the starter's group.
      val starter = mp / "starter"
      val (starterLeader, daemon) = startDaemon(baseEnvironment)
      val deniedInLog = hasLine(Denied, mp / "starter.log")
      daemon.filter(pid => !gone(pid) && deniedInLog) match
        case Some(pid) =>
          pass("M1 daemon survives the starter's denied connect",
            s"starter exit ${statusOf(starter).fold("none")(_.toString)}; daemon pid $pid in group $starterLeader")
        case None =>
          fail("M1 daemon survives the starter's denied connect",
            s"daemon: ${daemon.fold("none")(_.toString)}; denial in log: ${if deniedInLog then "yes" else "no"}; " +
              failed(starter, mp / "starter.log"))
      val daemonPorts = daemon.fold(Vector.empty[String])(listenPorts)
      val port = daemonPorts.headOption
      val filed = text(mp / "out" / "mill-daemon" / "socketPort").trim
      port.filter(_ => daemonPorts.size == 1) match
        case Some(number) =>
          val says = if filed.isEmpty then "nothing" else filed
          pass("M1 one listening port from lsof", s"port $number; socketPort file says $says")
        case None => fail("M1 one listening port from lsof", s"ports: ${daemonPorts.mkString(" ")}")
      val idle = (daemon, port) match
        case (Some(pid), Some(number)) => established(pid, number)
        case _                         => 0
      if port.nonEmpty && idle == 0 then pass("M1 an idle daemon has no established connection", s"port ${port.get}")
      else fail("M1 an idle daemon has no established connection", s"$idle on port ${port.getOrElse("none")}")

      (daemon, port) match
        case (Some(daemonPid), Some(number)) =>
          val clientProfile = profile(mp / "client.sb", s"""(allow network-outbound (remote ip "localhost:$number"))""")
          val neighborProfile =
            profile(mp / "neighbor.sb", s"""(allow network-outbound (remote ip "localhost:${number.toInt + 1}"))""")
          // M2: a client confined to the daemon's port. The native launcher is a GraalVM image and takes no
          // _JAVA_OPTIONS. So the environment's preferIPv4Stack never reaches the launcher, and the launcher's connect
          // is dual-stack and v4-mapped, which the "localhost" class denies (seatbelt.md, "Network"). The row tries
          // three candidates in order, and the first that runs is the client of the rows after:
          // - the native launcher as is;
          // - the native launcher with the property on its command line, for the image's runtime to consume;
          // - the JVM launcher, which takes the environment's options.
          val candidates = Seq(Seq("./mill"), Seq("./mill", "-Djava.net.preferIPv4Stack=true"), jvmLauncher)
          val chosen = candidates.zipWithIndex.find: (candidate, index) =>
            val name = s"m2-${index + 1}"
            val label = s"M2 exact-port client: ${candidate.mkString(" ")}"
            if runClient(name, sandboxed(clientProfile, candidate :+ "version")).contains(0) && !gone(daemonPid) then
              pass(label, lastLine(mp / s"$name.log").take(40))
              true
            else
              info(label, failed(mp / name, mp / s"$name.log"))
              false
          chosen match
            case Some((candidate, _)) => millClient = candidate
            case None => fail("M2 a client under the exact-port rule runs a command", "no candidate did")
          // M3: the OS denies the neighbor's port, the launcher's retry bounds the row, and the daemon stays untouched.
          val neighbor = runClient("m3", sandboxed(neighborProfile, millClient :+ "version"))
          if neighbor.contains(0) then fail("M3 client under the neighbor's port is denied", "the command ran")
          else if neighbor.contains(124) || !hasLine(Denied, mp / "m3.log") then
            fail("M3 client under the neighbor's port is denied",
              s"failed otherwise: ${failed(mp / "m3", mp / "m3.log")}")
          else if !gone(daemonPid) then
            pass("M3 client under the neighbor's port is denied", s"$Denied; daemon $daemonPid still alive")
          else fail("M3 client under the neighbor's port is denied", "denied, but the daemon is gone")
          // M4: each command's environment reaches the build (Task.env).
          val first = runClient("m4a", sandboxed(clientProfile, millClient :+ "probeEnv"),
            millEnvironment("env-first", "PROBE_ENV" -> "first"))
          val second = runClient("m4b", sandboxed(clientProfile, millClient :+ "probeEnv"),
            millEnvironment("env-second", "PROBE_ENV" -> "second"))
          if first.contains(0) && second.contains(0) && hasLine("PROBE_ENV=first", mp / "m4a.log")
            && hasLine("PROBE_ENV=second", mp / "m4b.log")
          then pass("M4 each command's environment reaches the build", "Task.env")
          else
            val found = Seq(mp / "m4a.log", mp / "m4b.log").flatMap(log => text(log).linesIterator)
              .filter(_.contains("PROBE_ENV")).take(2).map(_ + " ").mkString
            fail("M4 each command's environment reaches the build",
              s"${found}a: ${failed(mp / "m4a", mp / "m4a.log")}; b: ${failed(mp / "m4b", mp / "m4b.log")}")
          // M5: a client TERMed mid-command. Server.scala says that the daemon then shuts itself down.
          val runLeader = groupStart(mp / "m5", mp, sandboxed(clientProfile, millClient :+ "app.run"), baseEnvironment,
            mp / "m5.log")
          if within(180, 100)(hasLine("probe-main", mp / "m5.log")) then
            // The runner's foreign-daemon rule rests on this idle observation (RunOnHostMillDaemons.endForeign): a
            // running command is an established connection on the daemon's port, and no connection remains once the
            // command ends.
            val busy = established(daemonPid, number)
            if busy > 0 then pass("M5 a running command is an established connection", s"$busy on port $number")
            else fail("M5 a running command is an established connection", s"none on port $number")
            endGroup(runLeader)
            if within(30, 100)(gone(daemonPid)) then
              info("M5 daemon after a client TERMed mid-command", "gone within 30s, as Server.scala says")
            else info("M5 daemon after a client TERMed mid-command", "still alive after 30s")
            pgrep(s"$mp/out/app").headOption match
              case Some(pid) =>
                info("M5 forked run JVM after the TERM", s"alive ($pid); killed")
                signal("TERM", pid.toString)
              case None => info("M5 forked run JVM after the TERM", "gone")
          else
            fail("M5 app.run reaches its forked JVM", failed(mp / "m5", mp / "m5.log"))
            endGroup(runLeader)
          endDaemons()
        case _ => ()
      endGroup(starterLeader)

      // M6: the accept timeout, set through the starter's environment. Mill starts its idle clock at a client's
      // disconnect (Server.ConnectionTracker), never at the daemon's start, so one exact-port client runs first. A
      // daemon that nobody connected to would never expire.
      val (timeoutLeader, timeoutDaemon) =
        startDaemon(millEnvironment("env-timeout", "MILL_SERVER_TIMEOUT_MILLIS" -> "5000"))
      timeoutDaemon.filterNot(gone) match
        case Some(pid) =>
          pass(s"M6 daemon survives the denied connect of $clientName", s"daemon pid $pid")
          val port6 = listenPorts(pid).headOption.getOrElse("0")
          val timeoutProfile =
            profile(mp / "client6.sb", s"""(allow network-outbound (remote ip "localhost:$port6"))""")
          if !runClient("m6", sandboxed(timeoutProfile, millClient :+ "version")).contains(0) then
            fail("M6 a client connects before the timeout is measured", failed(mp / "m6", mp / "m6.log"))
          val connected = System.nanoTime
          if within(40, 100)(gone(pid)) then
            pass("M6 daemon exits after MILL_SERVER_TIMEOUT_MILLIS idle",
              s"${secondsSince(connected)}s after the starter, $clientName")
          else
            fail("M6 daemon exits after MILL_SERVER_TIMEOUT_MILLIS idle", "alive after 40s; killed")
            signal("TERM", pid.toString)
        case None =>
          fail("M6 daemon started for the timeout row", s"daemon: none; ${failed(starter, mp / "starter.log")}")
      endDaemons()
      endGroup(timeoutLeader)

      // M7: a foreign daemon whose fingerprint differs (a JAVA_OPTS that the closed environment lacks) stays alive in
      // its own group, and then the starter runs. On the mismatch, ServerLauncher removes the foreign processId before
      // it probes the lock. RunOnHostMillDaemons.start closes that window by ending the foreign daemon and running the
      // starter once more.
      val foreignRecord = mp / "foreign"
      val foreignLeader = groupStart(foreignRecord, mp, Seq("./mill", "version"),
        Environment(unconfined.variables + ("JAVA_OPTS" -> "-Dprobe.foreign=1"), inherit = false),
        mp / "m7-foreign.log")
      if !within(300, 100)(exited(foreignRecord)) then
        Files.writeString(sibling(foreignRecord, ".timeout"), "")
        fail("M7 unconfined ./mill leaves a daemon", failed(foreignRecord, mp / "m7-foreign.log"))
      else
        daemons().headOption match
          case Some(foreign) =>
            val (leader, ours) = startDaemon(baseEnvironment)
            val oursText = ours.fold("none")(_.toString)
            if gone(foreign) then
              info("M7 foreign daemon after the starter's fingerprint mismatch",
                s"ended by the starter (ServerLauncher); ours: $oursText")
            else
              info("M7 foreign daemon after the starter's fingerprint mismatch",
                s"alive; starter exit ${statusOf(starter).fold("none")(_.toString)}; ours: $oursText")
            endGroup(leader)
          case None => fail("M7 unconfined ./mill leaves a daemon", failed(foreignRecord, mp / "m7-foreign.log"))
      endGroup(foreignLeader)
      endDaemons()

      // M8: the runner ends a starter early (RunOnHostMillDaemons.endStarter). Once the daemon in the starter's group
      // listens on the port that socketPort names, the runner sends TERM to the launcher alone. The launcher is the
      // daemon's parent, a member of the group other than the leader. The daemon stays, listens and serves a client.
      // The group's rows before and after show the topology: which pid is the launcher, and whether a shell sits
      // between the leader and the launcher.
      val m8Record = mp / "m8-starter"
      val m8Leader = groupStart(m8Record, mp, sandboxed(daemonProfile, millClient :+ "version"), baseEnvironment,
        mp / "m8-starter.log")
      var m8Daemon = Option.empty[Long]
      var m8Port = ""
      def m8Listening(): Boolean =
        m8Daemon = groupMember(m8Leader, "MillDaemonMain")
        m8Port = text(mp / "out" / "mill-daemon" / "socketPort").trim
        m8Daemon.exists(pid => m8Port.nonEmpty && listenPorts(pid).contains(m8Port))
      def groupTable(fields: String): Seq[String] =
        lines("/bin/ps", "-o", fields, "-g", m8Leader.toString).map(_.take(110))
      within(120, 100)(exited(m8Record) || m8Listening())
      if exited(m8Record) || !m8Listening() then
        fail("M8 the daemon listens on socketPort's port before its starter exits",
          s"daemon ${m8Daemon.fold("none")(_.toString)}, port ${if m8Port.isEmpty then "none" else m8Port}; " +
            failed(m8Record, mp / "m8-starter.log"))
      else
        val daemonPid = m8Daemon.get
        info("M8 the starter's group while the daemon listens", s"pid ppid pgid command; leader $m8Leader")
        showTable(groupTable("pid=,ppid=,pgid=,command="))
        val launcher = lines("/bin/ps", "-o", "ppid=", "-p", daemonPid.toString).headOption.map(_.trim).getOrElse("")
        val launcherGroup = if launcher.isEmpty then ""
          else lines("/bin/ps", "-o", "pgid=", "-p", launcher).headOption.map(_.trim).getOrElse("")
        if launcher == m8Leader.toString || launcherGroup != m8Leader.toString then
          fail("M8 the daemon's parent is a member of the group other than the leader",
            s"parent ${if launcher.isEmpty then "none" else launcher}, leader $m8Leader; nothing signalled")
        else
          signal("TERM", launcher)
          if within(5, 100)(exited(m8Record)) && statusOf(m8Record).contains(143) && !gone(daemonPid)
            && listenPorts(daemonPid).contains(m8Port)
          then
            pass("M8 the starter ends on TERM behind its listening daemon",
              s"launcher $launcher exit 143; daemon $daemonPid listens on $m8Port")
          else
            fail("M8 the starter ends on TERM behind its listening daemon",
              s"starter status ${statusOf(m8Record).fold("none")(_.toString)}; daemon $daemonPid " +
                s"${if gone(daemonPid) then "gone" else "alive"}, " +
                s"listening on: ${listenPorts(daemonPid).mkString(" ")}")
          info("M8 the starter's group after the TERM", s"pid ppid command; leader $m8Leader")
          showTable(groupTable("pid=,ppid=,command="))
          val listenerProfile =
            profile(mp / "client8.sb", s"""(allow network-outbound (remote ip "localhost:$m8Port"))""")
          if runClient("m8-client", sandboxed(listenerProfile, millClient :+ "version")).contains(0) && !gone(daemonPid)
          then
            pass("M8 the daemon serves a client after its launcher's TERM", lastLine(mp / "m8-client.log").take(40))
          else
            fail("M8 the daemon serves a client after its launcher's TERM",
              s"${failed(mp / "m8-client", mp / "m8-client.log")}; " +
                s"daemon ${if gone(daemonPid) then "gone" else "alive"}")
      endDaemons()
      endGroup(m8Leader)
