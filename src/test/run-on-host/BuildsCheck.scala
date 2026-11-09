#!/usr/bin/env -S scala shebang
//> using scala 3.10.0
//> using file ../scala/HostDriver.scala
//> using file ../scala/RunOnHostIdle.scala
//> using file ../scala/RunOnHostChecks.scala

/*
  The run-on-host builds check: whether real builds of each program run through the supervisor under the generated
  profile, resolve through the command's proxy, and leave no server, daemon or proxy behind (SECURITY.md, "Run on
  host").

  Run it on the macOS HOST, from the repository root, with no sandbox session of this workspace running with
  --run-on-host:

      src/test/run-on-host/BuildsCheck.scala [--program sbt|mill|gradle|mvn|all] [--jobs N]

  - The groups below run in parallel, each building directories of its own. --jobs N runs at most N at once, for a
    machine short of memory: each group holds a JVM or two for its builds.
  - The console shows every row as it runs, prefixed with its group. The files go to
    src/test/run-on-host/out-macos/builds/, which each run empties first: transcript.log holds the machine, the setup
    and the totals, <group>.log each group's rows, and each build's output has a log of its own.
  - Before the first run, provision each fixture once on the host, as SeatbeltCheck.scala says; the setup names every
    missing host run at once.
  - A cold run-on-host cache resolves through the command's proxy inside the profile, and that is the measurement.

  The groups:

  - sbt: this repository's compile; sbt's own clients under the emitted profile, the server's JDK, and the processes
    that the command forks; then the command's proxy: a re-fetch, a refused PUT, and which CA variables curl and git
    read.
  - sbt-fixtures: a test run in fixtures/sbt, since this repository's own tests bind TCP listeners, which the profile
    refuses; packageBin across a dependsOn edge in fixtures/ivy, on sbt 1; and an unlisted host in fixtures/deny.
  - mill, and mill on the last Mill with a daemon: compile and test; the JDK that a pinned or unset mill-jvm-version
    runs on; and the launcher itself under the emitted profile.
  - gradle, on the fixture's Gradle and then on the last Gradle 8 release, in one group: a gradle daemon's records are
    the launch's, so two groups at once could not tell whose daemon survived.
  - mvn: --version and test.

  Last, after every group: no proxy, sbt server, mill daemon, gradle daemon or command directory survives.
*/

import agentsandbox.launcher.HostDriver.*
import agentsandbox.launcher.RunOnHostChecks.*

import java.nio.file.{Files, Path}

import scala.jdk.CollectionConverters.*

@main def check(args: String*): Unit = BuildsCheck.run(args)

object BuildsCheck:
  val usage = "usage: src/test/run-on-host/BuildsCheck.scala [--program sbt|mill|gradle|mvn|all] [--jobs N]"

  def run(args: Seq[String]): Unit =
    val root = orExit(repositoryRoot(ChecksPath))
    val options = orExit(parseOptions(args, usage))
    val hostPaths = orExit(HostPaths.of(sys.env.get))
    orExit(Either.cond(scala.util.Properties.isMac, (), "Run this on macOS."))
    val checkout = Checkout(root)
    val out = checkOut(root, "builds")
    val transcript = Transcript(out / "transcript.log", timestamps = true)
    val checkRun = CheckRun(transcript, checkout, out, options.programs, hostPaths)
    runMeasured(transcript, checkRun.cleanup):
      val targets = targetsOf(checkout, options.programs)
      val workspaces = Seq(root, checkout.sbtFixture, checkout.denyFixture, checkout.ivyFixture) ++
        targets.map(_.workspace)
      val measured =
        for
          _ <- checkRun.preflight(workspaces)
          _ <- checkRun.makeOlderCopies()
          _ = checkRun.machine()
          emitted <- checkRun.setup(targets)
        yield BuildsRows(checkRun, emitted).measure(options.jobs)
      measured.fold(identity, identity)

/** The groups of rows, each on a thread of its own and reporting to a transcript of its own. */
class BuildsRows(run: CheckRun, emitted: Map[String, Emitted]):
  private val checkout = run.checkout
  private val root = checkout.root
  private val hostPaths = run.host

  def measure(jobs: Option[Int]): Int =
    run.cleanup.add("end what the rows started")(run.endUnclaimed(run.leftovers(sbtDirectories, millWorkspaces)
      .flatMap(_._2)))
    val groups = Vector(
      Option.when(run.want(Program.Sbt))("sbt" -> ((part: CheckRun) => sbtRows(part))),
      Option.when(run.want(Program.Sbt))("sbt-fixtures" -> ((part: CheckRun) => sbtFixtureRows(part))),
      Option.when(run.want(Program.Mill))("mill" -> ((part: CheckRun) => millRows(part, "mill"))),
      Option.when(run.want(Program.Mill))(s"mill-$DaemonMill" -> ((part: CheckRun) =>
        millRows(part, s"mill-$DaemonMill"))),
      Option.when(run.want(Program.Gradle))("gradle" -> ((part: CheckRun) =>
        Seq("gradle", s"gradle-$OlderGradle").foreach(id => gradleRows(part, id)))),
      Option.when(run.want(Program.Mvn))("mvn" -> ((part: CheckRun) => mvnRows(part))),
    ).flatten
    run.inParallel(groups, jobs.getOrElse(groups.size))
    run.transcript.step("after every group")
    run.checkNothingSurvives(sbtDirectories, millWorkspaces)
    if run.transcript.failed == 0 then 0 else 1

  private val sbtDirectories = Seq(root, checkout.sbtFixture, checkout.denyFixture, checkout.ivyFixture)
  private val millWorkspaces = Seq(checkout.millFixture, checkout.millCopy, checkout.pinnedMill("mill"),
    checkout.pinnedMill(s"mill-$DaemonMill"))

  /** The first line that matches, or else the output's last line, cut for the row. */
  private def excerpt(output: Output, pattern: String): String =
    val lines = output.text.linesIterator.toVector
    val matching = s"(?:$pattern)".r
    lines.find(matching.findFirstIn(_).isDefined).orElse(lines.filterNot(_.isBlank).lastOption).getOrElse("").take(90)

  // --- sbt ------------------------------------------------------------------------------------------------------

  def sbtRows(run: CheckRun): Unit =
    val transcript = run.transcript
    val profile = emitted("sbt")
    transcript.step("sbt builds through the supervisor")
    val compile = run.supervisor("sbt-compile", Program.Sbt, root, Seq("compile"))
    run.check("sbt compile (supervisor)", compile.ok, excerpt(compile, if compile.ok then "^\\[success\\]"
      else "^\\[error\\]|^refused|Exception"))

    transcript.step("sbt's own clients under the emitted profile")
    // These rows use the same profile with no proxy behind it; the supervisor rows above warmed the run-on-host cache
    // through the proxy. The executable is the one that the supervisor runs; the profile's PATH holds no sbt.
    def sbt(client: Option[String], arguments: String*): Output =
      run.sandboxed(profile, Seq(hostPaths.sbtExecutable.toString, s"-Dsbt.global.base=${profile.sbtGlobal}") ++
        client.toSeq ++ Seq("-batch", "-java-home", hostPaths.javaHome.toString) ++ arguments, root)
    // Both clients run, so that the need for --jvm-client stays measured.
    for client <- Seq(Some("--jvm-client"), None) do
      val version = sbt(client, "--version")
      run.check(s"sbt --version (${client.getOrElse("sbtn")})", version.ok, excerpt(version, "version:"))
    val dependent = Seq("server runs the granted JDK", "a process forked by the command cannot read ~",
      "a process forked by the command cannot write WORKSPACE/.git", "sbtn compile")
    // The supervisor sweeps host-cache links before it warms the granted cache. If its compile failed, these direct
    // clients cannot establish that prerequisite themselves; the compile row holds the failure.
    if !compile.ok then dependent.foreach(run.skip(_, s"the supervisor's sbt compile failed; see ${run.out}"))
    else
      // The client forks the server, so nothing about the client's own JVM proves which JVM the command runs in.
      val jdk = sbt(Some("--jvm-client"), """eval System.getProperty("java.home")""")
      run.check("server runs the granted JDK", jdk.ok && jdk.has(hostPaths.javaHome.toString), excerpt(jdk, "ans:"))
      // Processes that the command itself starts keep the containment. The server is already the client's forked JVM,
      // so each eval measures a child of a child. The rows run under the sbt profile alone: inheritance across fork and
      // exec is the kernel's, not the profile's.
      def forked(label: String, expression: String): Unit =
        val result = sbt(Some("--jvm-client"), expression)
        val exit = "forked-exit=(\\d+)".r.findFirstMatchIn(result.text).map(_.group(1))
        exit match
          case Some("0") => run.fail(label, "the forked process succeeded")
          case Some(code) => run.pass(label, s"forked-exit=$code")
          case None => run.fail(label, excerpt(result, "^\\[error\\]"))
      forked("a process forked by the command cannot read ~",
        """eval { val code = scala.sys.process.Process(Seq("/bin/ls", sys.env("HOME"))).!; "forked-exit=" + code }""")
      forked("a process forked by the command cannot write WORKSPACE/.git",
        s"""eval { val code = scala.sys.process.Process(Seq("/usr/bin/touch", "${root / ".git" / "run-on-host-marker"
          }")).!; "forked-exit=" + code }""")
      sbt(Some("--jvm-client"), "shutdown")
      run.cleanup.add("remove the forked row's marker")(Files.deleteIfExists(root / ".git" / "run-on-host-marker"))
      // sbtn returns with nothing built, and this row keeps asking whether that changes. A build's success is the
      // measure: sbtn's --version passes and proves nothing.
      val sbtn = sbt(None, "compile")
      if sbtn.ok && sbtn.text.linesIterator.exists(_.startsWith("[success]")) then
        run.info("sbtn compile", "passes: the --jvm-client requirement can be reconsidered")
      else run.info("sbtn compile", s"no build: ${excerpt(sbtn, "$^")}")
      sbt(Some("--jvm-client"), "shutdown")

    transcript.step("the command's proxy")
    // The row makes the cache cold on purpose: with the artifact gone from the run-on-host cache, a successful compile
    // can only have fetched it. The Seatbelt check shows that the profile's only route is the proxy.
    removeTree(profile.coursierV1 / "https" / "repo1.maven.org" / "maven2" / "org" / "scalameta")
    val refetch = run.supervisor("sbt-refetch", Program.Sbt, root, Seq("Test/compile"))
    run.check("fetch allowed Maven artifact via proxy", refetch.ok,
      if refetch.ok then "munit re-fetched, Test/compile ok" else excerpt(refetch, "^\\[error\\]|^refused|Exception"))
    // `read` is enforced: the proxy answers a PUT to the host that it allows with 403 inside the tunnel, and the
    // supervisor names the request after the command.
    // - The expression has no `;`, because sbt's command splitter would cut there.
    // - The client is the JDK's, which takes the proxy and the trust store from _JAVA_OPTIONS.
    val putUrl = "https://repo1.maven.org/maven2/ko-agent-sandbox-run-on-host-put"
    val put = run.supervisor("sbt-put", Program.Sbt, root, Seq(
      s"""eval java.net.http.HttpClient.newHttpClient().send(java.net.http.HttpRequest.newBuilder(""" +
        s"""java.net.URI.create("$putUrl")).PUT(java.net.http.HttpRequest.BodyPublishers.noBody()).build(), """ +
        "java.net.http.HttpResponse.BodyHandlers.discarding()).statusCode"))
    run.check("a PUT to an allowed host is refused, and the supervisor names it",
      put.has("Int = 403") && put.has("Command sent requests the host command sandbox refuses") &&
        put.has(s"PUT $putUrl"),
      if put.has("Int = 403") then s"403; PUT $putUrl" else excerpt(put, "Int = |^\\[error\\]|^refused|Exception"))
    caProbe(run)

  /** The rows in sbt fixtures, each a build directory of its own. */
  def sbtFixtureRows(run: CheckRun): Unit =
    run.transcript.step("sbt fixtures through the supervisor")
    val test = run.supervisor("sbt-test", Program.Sbt, checkout.sbtFixture, Seq("testFull"))
    run.check("sbt testFull in fixtures/sbt (supervisor)", test.ok, excerpt(test, if test.ok then "^\\[info\\] Passed"
      else "^\\[error\\]|^refused|Exception"))
    // A build with a dependency between projects: Ivy must take its lock file in the redirected home, or the build
    // dies while canonicalizing ~/.ivy2 (RunOnHostPrereqs.ivyHomeOf).
    val ivyVersion = "(?m)^sbt.version=(.*)$".r
      .findFirstMatchIn(Files.readString(checkout.ivyFixture / "project" / "build.properties")).map(_.group(1))
      .getOrElse("unread")
    val ivy = run.supervisor("sbt-ivy", Program.Sbt, checkout.ivyFixture, Seq("app/packageBin"))
    run.check(s"sbt $ivyVersion packageBin across dependsOn", ivy.ok, excerpt(ivy, if ivy.ok then "^\\[success\\]"
      else "^\\[error\\]|^refused|Exception"))
    // fixtures/deny's resolution reaches a refused host. The command must fail, and the supervisor's denied-host
    // report must say which host.
    val deny = run.supervisor("sbt-deny", Program.Sbt, checkout.denyFixture, Seq("update"))
    if deny.ok then run.fail("fetch unlisted host via proxy", "the command succeeded")
    else run.check("fetch unlisted host via proxy",
      deny.has("Command requested network access") && deny.has("denied.example.com"),
      if deny.has("denied.example.com") then "refused; supervisor named denied.example.com"
      else s"failed without the supervisor's diagnostic: ${excerpt(deny, "$^")}")

  /** Which CA bundle variables the curl and git that this macOS ships read (run-on-host-internals.md, "The command's
    * lifetime and environment"). Each fetches from the allowed host under the command's profile and environment,
    * first with every variable and then without one variable.
    *   - curl prints the status, 200 when it verified the proxy's leaf.
    *   - git asks for a path that is no repository. So "error: 403" is a verified handshake, because the proxy, having
    *     no git-fetch grant, refuses the discovery. An SSL error is an unverified handshake.
    *   - The probe script lies in the run's directory, inside the workspace, which the profile lets the command run. */
  private def caProbe(run: CheckRun): Unit =
    val script = run.out / "ca-probe.sh"
    val report = run.out / "ca-probe.out"
    Files.writeString(script,
      s"""#!/bin/sh
         |exec > ${shellQuoted(report)} 2>&1
         |curl_row() { # label env-arguments...
         |    label=$$1; shift
         |    printf 'curl, %s: ' "$$label"
         |    /usr/bin/env "$$@" /usr/bin/curl --max-time 30 -sS -o /dev/null -w '%{http_code}' \\
         |        https://repo1.maven.org/maven2/ 2>&1 | tr '\\n' ' '
         |    echo
         |}
         |git_row() { # label env-arguments...
         |    label=$$1; shift
         |    printf 'git, %s: ' "$$label"
         |    /usr/bin/env "$$@" GIT_TERMINAL_PROMPT=0 /usr/bin/git ls-remote \\
         |        https://repo1.maven.org/maven2/ko-agent-sandbox-run-on-host.git 2>&1 | tail -1 \\
         |        | sed "s/^fatal: unable to access '[^']*': //"
         |}
         |curl_row "every variable"
         |curl_row "no CURL_CA_BUNDLE" -u CURL_CA_BUNDLE
         |curl_row "no SSL_CERT_FILE" -u SSL_CERT_FILE
         |curl_row "neither" -u CURL_CA_BUNDLE -u SSL_CERT_FILE
         |git_row "every variable"
         |git_row "no GIT_SSL_CAINFO" -u GIT_SSL_CAINFO
         |git_row "no GIT_SSL_CAINFO, no CURL_CA_BUNDLE" -u GIT_SSL_CAINFO -u CURL_CA_BUNDLE
         |git_row "none of the three" -u GIT_SSL_CAINFO -u CURL_CA_BUNDLE -u SSL_CERT_FILE
         |""".stripMargin)
    run.supervisor("sbt-ca-probe", Program.Sbt, root,
      Seq(s"""eval scala.sys.process.Process(Seq("/bin/sh", "$script")).!"""))
    if Files.isRegularFile(report) && Files.size(report) > 0 then
      Files.readAllLines(report).forEach(line => run.info("CA bundle variables", line))
    else run.info("CA bundle variables", s"the probe wrote nothing; see ${run.out / "sbt-ca-probe.log"}")

  // --- mill -----------------------------------------------------------------------------------------------------

  def millRows(run: CheckRun, id: String): Unit =
    val transcript = run.transcript
    val profile = emitted(id)
    val workspace = profile.target.workspace
    val version = millVersionOf(workspace).getOrElse("unread")
    val runner = if millWithoutDaemon(version) then "build" else "daemon"
    transcript.step(s"mill $version builds through the supervisor")
    // Each supervisor row starts a daemon in the command's session, or, on a Mill without a daemon, runs the build in
    // the command itself. out/mill-daemon is Mill's: the supervisor neither clears it nor reads it for authority
    // (RunnerRuntimes, RunOnHostMillDaemons), beyond the `mill-daemon-classpath` file that a start deletes when the
    // file names paths that the profile denies (RunOnHostMillDaemons.discardForeignClasspath).
    for command <- Seq("__.compile", "__.test") do
      val built = run.supervisor(s"$id-${command.stripPrefix("__.")}", Program.Mill, workspace, Seq(command))
      run.check(s"./mill $command (supervisor)", built.ok,
        excerpt(built, if built.ok then "(?i)compiling|passed|mill" else "^refused|Exception|error"))
    run.check("no mill daemon survives its command", run.millDaemons(workspace).isEmpty,
      run.millDaemons(workspace).mkString(" "))
    pinnedRows(run, id, workspace, version, runner)
    // The one provisioned file, the JVM launcher, is executable. The row runs the launcher directly and without the
    // daemon, because it measures the grant, not the runtime; the builds above filled the run-on-host cache from which
    // the launcher resolves Mill's daemon.
    transcript.step(s"mill $version's launcher under the emitted profile")
    val launcher = run.sandboxed(profile, Seq(profile.executable.toString, "--no-daemon", "--version"), workspace)
    run.check("read and execute the mill launcher", launcher.ok, excerpt(launcher, if launcher.ok then "(?i)mill"
      else "Exception|error"))

  /**
   * A pinned and an unset mill-jvm-version (doc/run-on-host-internals.md, "A pinned JVM" and "An unset
   * `mill-jvm-version`"), in a copy of the target's workspace at a fixed path.
   *
   *   - `mill-jvm-index-version` makes the key of Mill's java-home file one that these rows can write; Mill's own
   *     default key is its release's. Mill runs whatever home that file names under the id's key
   *     (src/probe/mill-pinned-jvm.sh). So the rows name a JDK that is already in the Coursier cache, and nothing is
   *     fetched.
   *   - The rows name a JDK other than JAVA_HOME's when the cache holds one that Mill runs on, so that the grant is a
   *     second JDK's. That JDK must be Java 23 or later: for an id that names such a version, as `temurin:99` and
   *     `zulu:25` do, Mill passes the daemon `--sun-misc-unsafe-memory-access=allow`, which an older JDK rejects
   *     (`MillProcessLauncher.millLaunchJvmCommand`, 1.3.0).
   *   - The unset rows' key names the id built into the target's Mill, its `default-mill-jvm-version`. Under another
   *     id, Mill fetches, and the second unset row fails.
   */
  private def pinnedRows(run: CheckRun, id: String, workspace: Path, version: String, runner: String): Unit =
    run.transcript.step(s"mill $version's pinned and unset mill-jvm-version")
    val pinned = checkout.pinnedMill(id)
    run.cleanup.add(s"remove $pinned")(removeTree(pinned))
    removeTree(pinned)
    Files.createDirectories(pinned)
    Seq("mill", ".mill-version", "src", "test").map(workspace / _).filter(Files.exists(_))
      .foreach(entry => run.copyTree(entry, pinned / entry.getFileName.toString))
    Files.writeString(pinned / "build.mill.yaml", Files.readString(workspace / "build.mill.yaml")
      .replace("mill-jvm-version: system\n", "mill-jvm-version: temurin:99\nmill-jvm-index-version: acceptance\n"))
    val javaHomeFile = pinned / "out" / "mill-daemon" / "cache" / "java-home"
    def recordHome(home: Path, jvm: String = "temurin:99"): Unit =
      Files.createDirectories(javaHomeFile.getParent)
      Files.writeString(javaHomeFile, s"""["$jvm:acceptance:","$home"]""")
    def refused(label: String, log: String, wording: String): Unit =
      val result = run.supervisor(log, Program.Mill, pinned, Seq("version"))
      if result.ok then run.fail(label, "ran")
      else run.check(label, result.has(wording), excerpt(result, "$^"))
    def runsOn(label: String, log: String, home: Path, which: String): Unit =
      val result = run.supervisor(log, Program.Mill, pinned, Seq("--version"))
      run.check(label, result.ok && result.text.linesIterator.contains(s"java.home: $home"),
        if result.ok then which else s"$which; ${excerpt(result, "$^")}")
    val hostRun = s"MILL_VERSION=$version-jvm ./mill version"

    refused("a pinned JVM with no java-home file is refused, naming the host run", s"$id-pinned-absent", hostRun)
    val planted = pinned / "jdk" / "bin" / "java"
    Files.createDirectories(planted.getParent)
    Files.writeString(planted, "#!/bin/sh\nexit 0\n")
    planted.toFile.setExecutable(true)
    recordHome(pinned / "jdk")
    refused("a java-home file naming a directory outside the Coursier cache is refused", s"$id-pinned-planted",
      "no JDK inside the Coursier cache")
    val (home, which) = secondJdk()
    recordHome(home)
    runsOn(s"a pinned JVM's $runner runs on the JDK the java-home file records", s"$id-pinned", home, which)

    Files.writeString(pinned / "build.mill.yaml", Files.readString(pinned / "build.mill.yaml").linesIterator
      .filterNot(_.startsWith("mill-jvm-version: ")).mkString("", "\n", "\n"))
    Files.deleteIfExists(javaHomeFile)
    refused("an unset JVM with no java-home file is refused, naming the host run", s"$id-unset-absent", hostRun)
    val unsetLabel = s"an unset JVM's $runner runs on the JDK the java-home file records"
    val defaultJvm = version match
      case v if v.startsWith("1.1.") => Some("zulu:21")
      case "1.3.0" | "1.3.1" => Some("zulu:25")
      case _ => None
    defaultJvm match
      case None => run.skip(unsetLabel, s"the id built into mill $version is unread")
      case Some(jvm) =>
        recordHome(home, jvm)
        runsOn(unsetLabel, s"$id-unset", home, which)
    run.check("no mill daemon of the pinned or unset build survives its command", run.millDaemons(pinned).isEmpty,
      run.millDaemons(pinned).mkString(" "))

  /** A JDK of Java 23 or later in the Coursier cache other than JAVA_HOME's, or else JAVA_HOME's, with how the rows
    * describe it. */
  private def secondJdk(): (Path, String) =
    val javaHome = hostPaths.javaHome.toRealPath()
    val candidates =
      try
        scala.util.Using.resource(Files.find(hostPaths.userArc, 13, (path, attributes) =>
          attributes.isRegularFile && path.endsWith(Path.of("Contents", "Home", "bin", "java"))))(
          _.iterator.asScala.toVector.map(_.getParent.getParent.toRealPath()))
      catch case _: java.io.IOException => Vector.empty
    candidates.filter(_ != javaHome).iterator.flatMap: candidate =>
      val major = """version "(\d+)""".r.findFirstMatchIn(run.command((candidate / "bin" / "java").toString,
        "-version")).flatMap(_.group(1).toIntOption)
      major.filter(_ >= 23).map(found => candidate -> s"a second JDK, Java $found")
    .nextOption().getOrElse(javaHome -> "JAVA_HOME's, the only JDK 23 or later in the Coursier cache")

  // --- gradle and mvn -------------------------------------------------------------------------------------------

  def gradleRows(run: CheckRun, id: String): Unit =
    val workspace = emitted(id).target.workspace
    val release = wrapperRelease(workspace / "gradle" / "wrapper" / "gradle-wrapper.properties", "gradle")
      .getOrElse("unread")
    run.transcript.step(s"gradle $release builds through the supervisor")
    // Each supervisor row's client starts a daemon in the registry under the command's session. The daemon resolves
    // through the proxy into the run-on-host cache's Gradle user home. The supervisor records the daemon after the
    // command and ends it with the session (RunOnHostGradleDaemons).
    for task <- Seq("help", "build") do
      val built = run.supervisor(s"$id-$task", Program.Gradle, workspace, Seq(task))
      run.check(s"gradle $task (supervisor)", built.ok,
        excerpt(built, if built.ok then "BUILD SUCCESSFUL" else "FAILURE|^refused|Exception"))
    run.check("no gradle daemon survives its command", run.launchGradleDaemons.isEmpty,
      run.launchGradleDaemons.mkString(" "))

  def mvnRows(run: CheckRun): Unit =
    val workspace = emitted("mvn").target.workspace
    run.transcript.step("mvn builds through the supervisor")
    // Maven runs once with no daemon: each row is one Maven JVM under the profile. The JVM resolves plugins and the
    // test dependency from Central through the proxy into the run-on-host cache's local repository.
    for goal <- Seq("--version", "test") do
      val built = run.supervisor(s"mvn-${goal.dropWhile(_ == '-')}", Program.Mvn, workspace, Seq(goal))
      run.check(s"mvn $goal (supervisor)", built.ok,
        excerpt(built, if built.ok then "BUILD SUCCESS|^Apache Maven" else "^\\[ERROR\\]|^refused|Exception"))
