#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../scala/HostDriver.scala
//> using file ../scala/RunOnHostIdle.scala
//> using file ../scala/RunOnHostChecks.scala

/*
  The run-on-host Seatbelt check: whether each generated Seatbelt profile denies and grants what the contract claims
  (SECURITY.md, "Run on host"). It runs no build, so a rerun after a profile change takes minutes.

  Run it on the macOS HOST, from the repository root, with no sandbox session of this workspace running with
  --run-on-host:

      src/test/run-on-host/SeatbeltCheck.scala [--program sbt|mill|gradle|mvn|all] [--jobs N]

  - The profiles' rows run in parallel. The console shows every row as it runs, prefixed with its profile. The files
    go to src/test/run-on-host/out-macos/seatbelt/, which each run empties first: transcript.log holds the machine,
    the setup, the proxy's rows and the totals, and <profile>.log each profile's rows with its commands' output.
  - Before the first run, provision each fixture once on the host. The setup names every missing host run at once:
    in fixtures/mill, `MILL_VERSION=<v>-jvm ./mill --no-daemon version` for the bootstrap's DEFAULT_MILL_VERSION and
    for 1.1.10; in fixtures/gradle, `./gradlew --version`; in fixtures/mvn, `./mvnw --version`. A mill daemon left in
    a fixture makes the check refuse to start, so both mill runs take `--no-daemon`.

  The rows run under each selected target's profile: the sbt profile for this repository, and the mill, gradle and
  mvn profiles for their fixtures, the mill and gradle ones also for the copies on older releases. Per profile:

  - the JVM starts;
  - reads and writes that the profile must deny, and the writes it must allow;
  - the Mach services: no application starts, and a JVM that asks the system's resolver survives;
  - processes: another process's arguments are refused, and a child of the command is in the same sandbox;
  - the network: no connection but the proxy's port, no DNS of its own, and an unrelated service of this host only
    for Gradle.

  Then the proxy's own profile: its JVM starts, and it can neither read ~ nor write a file.

  The negative rows never write anything real:
  - a "write" is `: >> file`, which opens for append and writes nothing;
  - every created marker lies in a scratch tree that the check makes and removes, or is a file named after this run
    that the cleanup removes.
  A denied row reports the denial from stderr. The `open` row, if wrongly permitted, starts Calculator, which the row
  ends unless Calculator was running before.
*/

import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.*

import java.net.{InetAddress, InetSocketAddress, ServerSocket}
import java.nio.file.{Files, Path, StandardCopyOption}

import scala.jdk.CollectionConverters.*

@main def check(args: String*): Unit = SeatbeltCheck.run(args)

object SeatbeltCheck:
  val usage = "usage: src/test/run-on-host/SeatbeltCheck.scala [--program sbt|mill|gradle|mvn|all] [--jobs N]"

  def run(args: Seq[String]): Unit =
    val root = orExit(repositoryRoot(ChecksPath))
    val options = orExit(parseOptions(args, usage))
    val programs = options.programs
    val hostPaths = orExit(HostPaths.of(sys.env.get))
    orExit(Either.cond(scala.util.Properties.isMac, (), "Run this on macOS."))
    val checkout = Checkout(root)
    val out = checkOut(root, "seatbelt")
    val transcript = Transcript(out / "transcript.log", timestamps = true)
    val checkRun = CheckRun(transcript, checkout, out, programs, hostPaths)
    runMeasured(transcript, checkRun.cleanup):
      val targets = targetsOf(checkout, programs)
      val measured =
        for
          _ <- checkRun.preflight(Seq(root) ++ targets.map(_.workspace))
          _ <- checkRun.makeOlderCopies()
          folding = checkRun.machine()
          emitted <- checkRun.setup(targets)
        yield SeatbeltRows(checkRun, folding, options.jobs).measure(targets.flatMap(target => emitted.get(target.id)))
      measured.fold(identity, identity)

object SeatbeltRows:
  /** The lock of the row that starts Calculator. */
  val calculator = Object()

/** The rows, under each emitted profile and then under the proxy's own. */
class SeatbeltRows(run: CheckRun, folding: Boolean, jobs: Option[Int] = None):
  private val transcript = run.transcript
  private val root = run.checkout.root
  private val hostPaths = run.host
  private val out = run.out
  private val marker = s"run-on-host-marker.${ProcessHandle.current.pid}"

  def measure(profiles: Vector[Emitted]): Int =
    val sibling = siblingRepository()
    val listener = unrelatedListener()
    val held = heldJdk()
    run.cleanup.add("remove the markers"):
      val markerDirs =
        profiles.flatMap(emitted => Seq(emitted.coursierV1, emitted.sessionTmp, emitted.gradleUserHome)) ++ Seq(
          root / ".git", hostPaths.home / ".sbt" / "boot", hostPaths.userV1, hostPaths.millDownloads,
          hostPaths.home / ".gradle", hostPaths.home / ".m2" / "repository", hostPaths.javaHome,
          hostPaths.coursier / "jvm",
        )
      markerDirs.foreach(dir => Files.deleteIfExists(dir / marker))
    // The profiles' rows run in parallel, since each profile's rows touch only its own profile, run-on-host cache,
    // temporary directory and scratch tree. Each profile reports to a transcript of its own, `<id>.log`.
    run.inParallel(
      profiles.map(emitted =>
        emitted.target.id -> ((part: CheckRun) => SeatbeltRows(part, folding, jobs).rows(emitted, sibling, listener,
          held))),
      jobs.getOrElse(profiles.size),
    )
    proxyRows()
    if transcript.failed == 0 then 0 else 1

  /** An unrelated repository outside the workspace, the target of the symlink-escape rows. */
  def siblingRepository(): Path =
    val sibling = Files.createTempDirectory("run-on-host-sibling")
    run.cleanup.add("remove the sibling repository")(removeTree(sibling))
    Files.createDirectories(sibling / ".git")
    Files.writeString(sibling / ".git" / "config", "fixture\n")
    sibling

  /** The unrelated service that the network rows connect to, on a port of the kernel's choosing on the loopback
    * address. It accepts and closes each connection. */
  def unrelatedListener(): ServerSocket =
    val socket = ServerSocket()
    socket.bind(InetSocketAddress(InetAddress.getLoopbackAddress, 0))
    run.cleanup.add("close the unrelated listener")(socket.close())
    val acceptor = Thread(() =>
      try while true do socket.accept().close()
      catch case _: java.io.IOException => ())
    acceptor.setDaemon(true)
    acceptor.start()
    socket

  /** The process-read rows' target: a JDK outside every profile that holds a variable, as the launcher, the runner and
    * a supervisor are JDKs that hold the launch's environment. Apple's own binaries would not do, because the kernel
    * withholds their environment (seatbelt.md, "Processes"). */
  def heldJdk(): Started =
    val held = run.start("procargs-held", Seq((hostPaths.javaHome / "bin" / "java").toString,
      (root / "src" / "probe" / "ProcArgs.java").toString, "--hold"),
      environment = Map("KO_AGENT_PROCARGS_PROBE" -> "1"))
    run.cleanup.add("end the held JDK")(held.process.destroyForcibly())
    held

  /** A scratch tree inside the profile's workspace stands in for a workspace with nested repositories. The check makes
    * it on the host, outside the profile, so that the rows test the guard and not the ability to build the fixture. */
  def scratchTree(workspace: Path, sibling: Path): Path =
    val scratch = Files.createTempDirectory(workspace, "run-on-host-scratch")
    run.cleanup.add(s"remove $scratch")(removeTree(scratch))
    Files.createDirectories(scratch / "sub" / "nested" / ".git" / "hooks")
    Files.createDirectories(scratch / ".ko-agent-sandbox" / "egress")
    Files.writeString(scratch / "sub" / "nested" / ".git" / "config", "fixture\n")
    Files.writeString(scratch / ".ko-agent-sandbox" / "egress" / "rule", "fixture\n")
    Files.createSymbolicLink(scratch / "link", Path.of("sub/nested/.git"))
    // A symlink must add no authority over its target.
    Files.createSymbolicLink(scratch / "esc-home", hostPaths.home)
    Files.createSymbolicLink(scratch / "esc-root", Path.of("/"))
    Files.createSymbolicLink(scratch / "esc-user-v1", hostPaths.userV1)
    Files.createSymbolicLink(scratch / "esc-repo", sibling)
    scratch

  def rows(emitted: Emitted, sibling: Path, listener: ServerSocket, held: Started): Unit =
    val id = emitted.target.id
    val workspace = emitted.target.workspace
    val profile = emitted.profile
    val tmp = emitted.sessionTmp
    val java = (hostPaths.javaHome / "bin" / "java").toString
    val scratch = scratchTree(workspace, sibling)
    def q(path: Path): String = shellQuoted(path)
    def denied(label: String, shell: String): Unit = run.expectDenied(profile, label, shell, workspace)
    def allowed(label: String, shell: String): Unit = run.expectAllowed(profile, label, shell, workspace)
    def presentThenDenied(label: String, path: Path, shell: String): Unit =
      if run.presentOrSkip(label, path) then denied(label, shell)

    transcript.step(s"the $id profile")
    // Run from the profile's own workspace: the JVM reads its working directory at start, and the profile grants its
    // program's workspace.
    val version = run.sandboxed(emitted, Seq(java, "-version"), workspace, timeoutSeconds = 120)
    run.check("java -version", version.ok,
      version.text.linesIterator.find(_.contains("version")).getOrElse(version.text))

    transcript.step(s"reads, under the $id profile")
    presentThenDenied("read ~/Documents", hostPaths.home / "Documents", s"ls ${q(hostPaths.home / "Documents")}")
    presentThenDenied("read ~/.ssh", hostPaths.home / ".ssh", s"ls ${q(hostPaths.home / ".ssh")}")
    presentThenDenied("read the launcher state root", hostPaths.stateRoot, s"ls ${q(hostPaths.stateRoot)}")
    // Another workspace's cache, beside this one's under the run-on-host tree.
    val caches = emitted.runOnHostCache.getParent
    val otherCache = scala.util.Using.resource(Files.list(caches))(_.iterator.asScala.toVector)
      .filter(dir => dir != emitted.runOnHostCache && Files.isDirectory(dir)).sorted.headOption
    otherCache match
      case Some(other) => denied("read another workspace's run-on-host cache", s"ls ${q(other)}")
      case None => run.skip("read another workspace's run-on-host cache", "no other workspace has a run-on-host cache")
    denied("read the user's Coursier v1", s"ls ${q(hostPaths.userV1)}/")
    denied("read the user's other Coursier arc entries", s"ls ${q(hostPaths.userArc)}")
    // The profile grants a granted path's ancestors file-read-metadata alone, because a listing would reveal sibling
    // names.
    denied("list an ancestor of a granted path", s"ls ${q(hostPaths.home / "Library" / "Caches")}")
    denied("read WORKSPACE/.git", s"cat ${q(root / ".git" / "HEAD")}")
    denied("read a nested .git", s"cat ${q(scratch / "sub" / "nested" / ".git" / "config")}")
    denied("read via WORKSPACE/link -> WORKSPACE/.git", s"cat ${q(scratch / "link" / "config")}")
    // The trailing slash on each listed symlink forces resolution into the target. ls on a link whose target cannot
    // even be stat'ed prints the link's own name and succeeds, exactly like a broken link, so a denial so complete
    // that it covers the stat would otherwise read as a grant.
    denied("read ~ via a workspace symlink", s"ls ${q(scratch / "esc-home")}/")
    denied("read /Users via a workspace symlink to /", s"ls ${q(scratch / "esc-root" / "Users")}")
    denied("read the user's Coursier v1 via a workspace symlink", s"ls ${q(scratch / "esc-user-v1")}/")
    denied("read another repository via a workspace symlink", s"cat ${q(scratch / "esc-repo" / ".git" / "config")}")
    denied("write another repository via a workspace symlink", s": >> ${q(scratch / "esc-repo" / ".git" / "config")}")

    transcript.step(s"writes, under the $id profile")
    val jvmDir = hostPaths.coursier / "jvm"
    if Files.exists(jvmDir) then denied("write Coursier/jvm", s": > ${q(jvmDir / marker)}")
    else denied("write the Coursier JDK home (no jvm/; the home is in arc/)", s": > ${q(hostPaths.javaHome / marker)}")
    denied("write ~/.sbt/boot", s": > ${q(hostPaths.home / ".sbt" / "boot" / marker)}")
    presentThenDenied("write ~/.ivy2", hostPaths.home / ".ivy2", s": > ${q(hostPaths.home / ".ivy2" / marker)}")
    presentThenDenied("write ~/.gradle", hostPaths.home / ".gradle", s": > ${q(hostPaths.home / ".gradle" / marker)}")
    presentThenDenied("write ~/.m2/repository", hostPaths.home / ".m2" / "repository",
      s": > ${q(hostPaths.home / ".m2" / "repository" / marker)}")
    denied("write the Coursier-installed sbt script", s": >> ${q(hostPaths.sbtExecutable)}")
    denied("write WORKSPACE/.git/config", s": >> ${q(root / ".git" / "config")}")
    denied("create under WORKSPACE/.git", s": > ${q(root / ".git" / marker)}")
    denied("write WORKSPACE/sub/nested/.git/hooks/x", s": > ${q(scratch / "sub" / "nested" / ".git" / "hooks" / "x")}")
    denied("write existing .git/config through .GIT", s": >> ${q(scratch / "sub" / "nested" / ".GIT" / "config")}")
    denied("create WORKSPACE/.git during the command", s"mkdir ${q(scratch / ".git")}")
    // These rows create a spelling that the volume folds to a guarded name, where no entry exists for the access to
    // resolve to. Host git and the launcher would open such an entry as the guarded name (seatbelt-semantics.sh
    // E9-E12). U+212A KELVIN SIGN and U+017F LONG S fold to k and s, and .git has no such letter.
    Files.createDirectories(scratch / "fresh")
    for spelling <- Seq(".GIT", ".KO-AGENT-SANDBOX", ".Ko-agent-sandbox", ".ko-agent-ſandbox") do
      val label = s"create WORKSPACE/$spelling where no such entry exists"
      if folding then denied(label, s"mkdir ${q(scratch / "fresh" / spelling)}")
      else run.skip(label, "the workspace volume folds no case")
    denied("link WORKSPACE/x -> WORKSPACE/.git/config",
      s"ln ${q(scratch / "sub" / "nested" / ".git" / "config")} ${q(scratch / "x")}")
    denied("write via WORKSPACE/link -> WORKSPACE/.git", s": >> ${q(scratch / "link" / "config")}")
    denied("write WORKSPACE/.ko-agent-sandbox/...", s": >> ${q(scratch / ".ko-agent-sandbox" / "egress" / "rule")}")
    // The check lays out the file rules' defaults (doc/file-rules.md) on the host. The rename rows measure which
    // operations SBPL checks for a rename.
    val rules = scratch / "rules"
    Seq(rules / ".vscode", rules / ".claude", rules / "sub", rules / "node_modules" / "p").foreach(
      Files.createDirectories(_))
    Files.writeString(rules / ".vscode" / "tasks.json", "{}\n")
    Files.writeString(rules / ".claude" / "settings.json", "{}\n")
    denied("write a listed file", s": >> ${q(rules / ".vscode" / "tasks.json")}")
    denied("create a listed name deeper", s"mkdir ${q(rules / "sub" / ".vscode")}")
    denied("rename a directory a listed name passes through", s"mv ${q(rules / ".claude")} ${q(rules / "saved")}")
    denied("rename a staged directory onto a name a listed name passes through",
      s"mkdir -p ${q(rules / "staged")} && mv ${q(rules / "staged")} ${q(rules / "sub" / ".claude")}")
    allowed("create a listed name inside node_modules, which a later writable line lifts",
      s"mkdir ${q(rules / "node_modules" / "p" / ".vscode")}")
    allowed("write beside a listed file", s": > ${q(rules / ".claude" / "notes.md")}")
    denied("write the user's Coursier v1", s": > ${q(hostPaths.userV1 / marker)}")
    presentThenDenied("write the user's mill download folder", hostPaths.millDownloads,
      s": > ${q(hostPaths.millDownloads / marker)}")
    emitted.target.program match
      case Program.Mvn | Program.Gradle =>
        // The one provisioned distribution runs; its neighbours under wrapper/dists are unreadable.
        val name = if emitted.target.program == Program.Mvn then "Maven" else "Gradle"
        val distribution = emitted.executable.getParent.getParent
        val versionArgs = if emitted.target.program == Program.Mvn then Seq("--batch-mode", "--version")
          else Seq("--version")
        val ran = run.sandboxed(emitted, emitted.executable.toString +: versionArgs, workspace)
        run.check(s"read and execute the $name distribution", ran.ok, if ran.ok then "" else ran.text.trim)
        denied("list the wrapper's dists folder", s"ls ${q(distribution.getParent.getParent)}")
        denied(s"write the $name distribution", s": >> ${q(emitted.executable)}")
      case Program.Mill =>
        // The launcher's neighbours in the download folder are unreadable. BuildsCheck runs the launcher itself,
        // which resolves Mill's daemon into the run-on-host cache that its builds fill.
        denied("list the mill download folder", s"ls ${q(hostPaths.millDownloads)}")
      case Program.Sbt => ()

    transcript.step(s"Mach services, under the $id profile")
    // One profile at a time: the row reads and ends a process that every profile shares.
    SeatbeltRows.calculator.synchronized:
      val calculatorBefore = run.command("/usr/bin/pgrep", "-x", "Calculator").trim.nonEmpty
      denied("start an application through open", "/usr/bin/open -g -a Calculator")
      if !calculatorBefore then run.command("/usr/bin/pkill", "-x", "Calculator")
    // The proxy's JVM dies of a segmentation fault without the service that SeatbeltProfile.MachServices names; a
    // command's JVM that asks the system's resolver must not die. Whether the name resolves is not this row's question.
    Files.writeString(tmp / "Resolve.java",
      """class Resolve {
        |    public static void main(String[] arguments) {
        |        try { System.out.println(java.net.InetAddress.getByName(arguments[0])); }
        |        catch (java.net.UnknownHostException ex) { System.out.println(ex); }
        |    }
        |}
        |""".stripMargin)
    allowed("a JVM resolving a name survives it", s"${q(Path.of(java))} ${q(tmp / "Resolve.java")} localhost")

    transcript.step(s"processes, under the $id profile")
    // These rows measure SeatbeltProfile.ProcessReadRule. A row passes only on ProcArgs's own report, so a JVM that did
    // not run fails the row. Mill's client also asks info() of its daemon, which Network.MillClient's exception
    // covers, so these rows do not check info(). The reader is copied out of this repository, which only the sbt
    // profile grants.
    Files.copy(root / "src" / "probe" / "ProcArgs.java", tmp / "ProcArgs.java",
      StandardCopyOption.REPLACE_EXISTING)
    val reader = s"${q(Path.of(java))} --enable-native-access=ALL-UNNAMED ${q(tmp / "ProcArgs.java")}"
    val report = q(tmp / "procargs.out")
    allowed("reading another process's arguments and environment is refused",
      s"$reader target=${held.pid} > $report && " +
        s"grep -q '^target (pid ${held.pid}): DENIED errno=1 .*; ProcessHandle.of present; info ' $report")
    allowed("read a child the command starts: the same sandbox",
      s"$reader --child=${q(tmp / "ProcArgs.java")} > $report && " +
        s"grep -q '^a child of the reader (pid [0-9]*): ENVIRONMENT READ ' $report")

    transcript.step(s"allowed writes, under the $id profile")
    allowed("write run-on-host cache coursier/v1/...", s": > ${q(emitted.coursierV1 / marker)}")
    allowed("write WORKSPACE/...", s": > ${q(scratch / "ok")}")
    allowed("write command's temporary directory", s": > ${q(tmp / marker)}")
    if emitted.target.program == Program.Gradle then
      allowed("write the Gradle user home", s": > ${q(emitted.gradleUserHome / marker)}")
    // The guard is scoped to the workspace: a build's tests may make throwaway repositories in the command's temporary
    // directory, and this project's own do.
    allowed("create .git in the command's temporary directory",
      s"mkdir -p ${q(tmp / "fixture" / ".git")} && : > ${q(tmp / "fixture" / ".git" / "config")}")

    transcript.step(s"network, under the $id profile")
    // /bin/bash's /dev/tcp is a connect(2) with no program to grant; an IP literal keeps DNS out.
    denied("connect directly to arbitrary Internet host", "/bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'")
    // No proxy variable is set here, so curl stands for a command that ignores them. Either the resolution or the
    // connect must die on the profile, never on a slow timeout.
    denied("HTTPS around the proxy (curl, direct)", "/usr/bin/curl --max-time 5 -sS https://repo1.maven.org/maven2/")
    denied("DNS resolution (direct socket)", "/usr/bin/nslookup -timeout=3 example.com")
    // The system's resolver, through the Mach service that the profile grants (SECURITY.md, "DNS"). The row passes only
    // on Resolve's own report of an unresolved name, so a JVM that crashed or resolved the name fails the row.
    allowed("DNS resolution (the system's resolver) fails",
      s"${q(Path.of(java))} ${q(tmp / "Resolve.java")} example.com > ${q(tmp / "resolve.out")} && " +
        s"grep -q '^java.net.UnknownHostException' ${q(tmp / "resolve.out")}")
    // An unrelated service of this host: a Gradle process may reach it, and no other program's process may
    // (SECURITY.md, "Run on host", the table). Gradle's daemon, workers and file-lock socket connect to each other's
    // ports of the kernel's choosing.
    val connect = s"/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/${listener.getLocalPort}'"
    if emitted.target.program == Program.Gradle then allowed("connect to an unrelated service of this host", connect)
    else denied("connect to an unrelated service of this host", connect)

  /**
   * The proxy's own profile. BuildsCheck runs every fetch through a proxy under this profile, so it proves that
   * the confined proxy works, the resolver rule included. These rows prove that the profile denies, with the granted
   * java as the probe, since the profile execs nothing else.
   *
   *   - A JVM that reads `@dir` reports "Failed to read" on a directory that it may open and "could not open" on one
   *     that it may not, so the control's word separates the denial from the directory.
   *   - `-Xlog` to a file is a write. The write's control creates the file, and the JVM reports its denial as the open
   *     that it could not make.
   *   - The proxy runs from /, as the supervisor runs it, because the JVM asks for its working directory at start. The
   *     rows read both streams, because the JVM reports a log file that it cannot open on stdout.
   */
  def proxyRows(): Unit =
    transcript.step("the proxy's own profile")
    val java = (hostPaths.javaHome / "bin" / "java").toString
    def confined(arguments: String*): Output =
      host(transcript, Seq("/usr/bin/sandbox-exec", "-f", run.proxyProfile.toString, java) ++ arguments,
        cwd = Path.of("/"), timeoutSeconds = Some(120))
    def plain(arguments: String*): Output = host(transcript, java +: arguments, timeoutSeconds = Some(120))
    def first(output: Output): String = output.text.linesIterator.nextOption().getOrElse("")

    val started = confined("-version")
    run.check("the proxy's java starts under its profile", started.ok, first(started))

    val readControl = plain(s"@${hostPaths.home}", "-version")
    if readControl.ok || !readControl.has("Failed to read") then
      run.fail("the proxy cannot read ~", s"control: ${first(readControl)}")
    else
      val read = confined(s"@${hostPaths.home}", "-version")
      if read.ok then run.fail("the proxy cannot read ~", "allowed")
      else run.check("the proxy cannot read ~", read.has("could not open"), s"denied: ${first(read)}")

    val probe = out / "proxy-write.log"
    val writeControl = plain(s"-Xlog:gc:file=$probe", "-version")
    if !writeControl.ok || !Files.exists(probe) then
      run.fail("the proxy cannot write a file", s"control: ${first(writeControl)}")
    else
      Files.delete(probe)
      val write = confined(s"-Xlog:gc:file=$probe", "-version")
      if write.ok || Files.exists(probe) then run.fail("the proxy cannot write a file", "allowed")
      else run.check("the proxy cannot write a file", write.has("Error opening log file"), s"denied: ${first(write)}")
