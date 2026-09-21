name := "ko-agent-sandbox"
version := "0.1.0"
scalaVersion := "3.9.0"

Compile / mainClass := Some("agentsandbox.launcher.AgentSandboxLauncher")

libraryDependencies ++= Seq(
  "org.scalameta" %% "munit" % "1.3.6" % Test,
)

scalacOptions ++= Seq(
  "-deprecation",
  "-feature",
  "-unchecked",
  "-Wunused:all",
  "-Werror",
)

// The container-launching suites share one podman, and each asserts on resources scoped to a
// project it created. Run in parallel they interleave — one suite's launch observing another's
// container, one suite's teardown racing another's `--reset`. The ordinary suites take seconds, so
// serial costs almost nothing and removes the whole class of interference.
Test / parallelExecution := false

// The container-launching suites run only under this command; `test` and `testFull` alone skip
// them, so no ordinary build starts a session. The command sets a system property the suites'
// condition reads (WithPodman.underTestWithPodman) for one run of testFull, or of testOnly with the
// patterns given, and clears it however the run ends. Not an environment variable: the tests run
// in the sbt server's JVM, whose environment is the one it was started with, so a variable on a
// thin client's command line never reaches them and the run passes with every session suite
// skipped. The task is run here rather than pushed as a command, so its failure is the command's
// failure and the clearing survives an interrupted run, which a test cleanup hook would not.
val TestWithPodmanProperty = "ko-agent-sandbox.testWithPodman"
commands += Command.args("testWithPodman", "<testOnly patterns>") { (state, patterns) =>
  val extracted = Project.extract(state)
  System.setProperty(TestWithPodmanProperty, "1")
  try
    if (patterns.isEmpty) extracted.runTask(Test / testFull, state)._1
    else extracted.runInputTask(Test / testOnly, patterns.mkString(" ", " ", ""), state)._1
  finally System.clearProperty(TestWithPodmanProperty)
}

// munit prints `==> s <test> skipped` without the clue its `assume` gave (doc/upstream-issues.md,
// "scalameta/munit"), and the clue is what tells one passing run from another:
//
// - A clue names a missing program, a command to use (`sbt testWithPodman`, for the
//   container-launching suites), or why the test cannot run in this environment.
// - A suite can skip whole: a host without wcwidth runs none of SandboxTextWidthTest.
// - A thin client attaches to whichever sbt server is running, so `sbt testFull` typed in a host
//   shell can run under the run-on-host profile. Its skips differ there, and the clues show which
//   environment ran the tests.
//
// The event sbt receives still carries the exception, so the clues of a run's skipped tests are
// printed before sbt's totals, grouped by clue, with each suite's count:
//
//     skipped 10: needs python3 with wcwidth (SandboxTextWidthTest: 10)
//
// A test event names its test as `<suite>.<test name>` and not its suite, so the suite is the
// started group that name begins with.
Test / testListeners += new TestsListener {
  private val suites = scala.collection.mutable.Set.empty[String]
  private val suitesByReason = scala.collection.mutable.LinkedHashMap.empty[String, Vector[String]]

  def doInit(): Unit = synchronized {
    suites.clear()
    suitesByReason.clear()
  }
  def startGroup(name: String): Unit = synchronized(suites += name)
  def testEvent(event: TestEvent): Unit = synchronized {
    for (detail <- event.detail if detail.status == sbt.testing.Status.Skipped) {
      val reason =
        if (detail.throwable.isDefined) Option(detail.throwable.get.getMessage).getOrElse("no reason given")
        else "no reason given"
      val test = detail.fullyQualifiedName
      val suite = suites.filter(name => test.startsWith(name + ".")).maxByOption(_.length).getOrElse(test)
      suitesByReason(reason) = suitesByReason.getOrElse(reason, Vector.empty) :+ suite
    }
  }
  def endGroup(name: String, thrown: Throwable): Unit = ()
  def endGroup(name: String, result: TestResult): Unit = ()
  def doComplete(finalResult: TestResult): Unit = synchronized {
    for ((reason, skipped) <- suitesByReason) {
      val counts = skipped.distinct.map(suite => s"${suite.split('.').last}: ${skipped.count(_ == suite)}")
      println(s"skipped ${skipped.size}: $reason (${counts.mkString(", ")})")
    }
  }
}

// --serve-proxy-on-host runs the proxy of the ko-agent-egress-proxy subproject, compiled into
// this jar from the same sources so an installed launcher carries it — the Scala sources, and the
// /defaults resources their class initialization loads eagerly. The subproject's own build still
// exists for the container image, which builds a native image from the bundled context; its
// tests run there.
Compile / unmanagedSourceDirectories +=
  baseDirectory.value / "container" / "ko-agent-egress-proxy" / "app" / "src" / "main" / "scala"
Compile / unmanagedResourceDirectories +=
  baseDirectory.value / "container" / "ko-agent-egress-proxy" / "app" / "src" / "main" / "resources"

// execvp is a restricted FFM method: without this, a warning per launch and refusal on a future JDK.
// The exports open the JDK's internal certificate builder to X509Helper.scala, which has why; the
// assembly manifest carries both for `java -jar`, the launcher's re-invocation of itself for the
// broker, wrapper and proxy it starts as `java -cp` (RunOnHostSandbox.CertificateBuilderExports),
// the native-image command in doc/TODO.md for the binary, and .jvmopts for the tests, which run in
// sbt's own JVM —
// a forked test JVM would need sbt's TCP listener to reach it, which the host command sandbox does
// not grant (doc/run-on-host.md, "Network").
Compile / run / javaOptions ++= Seq(
  "--enable-native-access=ALL-UNNAMED",
  "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
  "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
)
Compile / run / fork := true

// Extract --help from README.md’s Reference block so the published documentation and installed launcher
// cannot disagree. The block must run unbroken between headings; malformed input fails the build
// instead of silently truncating the help.
// Anchor on the heading so changing the invocation from java -jar to a Coursier command does not break extraction.
Compile / resourceGenerators += Def.task {
  val readme = IO.readLines(baseDirectory.value / "README.md")
  val start = readme.indexWhere(_.trim == "### Reference")
  if start < 0 then
    sys.error("README.md needs a '### Reference' heading for --help extraction")
  val rest = readme.drop(start + 1)
  val block = rest.takeWhile(line => line.trim.isEmpty || line.startsWith("    "))
  if !rest.drop(block.size).headOption.exists(_.matches("#{1,6}(\\s.*)?")) then
    sys.error("README.md's Reference block must run unbroken to the next heading")
  val text = block.map(_.stripPrefix("    "))
    .dropWhile(_.trim.isEmpty).reverse.dropWhile(_.trim.isEmpty).reverse
  if text.isEmpty then sys.error("README.md's Reference block is empty")
  val target = (Compile / resourceManaged).value / "agentsandbox" / "usage.txt"
  IO.write(target, text.mkString("\n"))
  Seq(target)
}.taskValue

// Bundle the build contexts into the jar so --build works with no checkout present
// (AgentSandboxLauncher.unpackBuildContext). INDEX lists every bundled path: a jar's resource tree cannot be enumerated
// at runtime.
// Native-image's resource discovery misses required files; the native-image command in doc/TODO.md must include
// sandbox-build/ (build contexts), defaults/ (proxy rules) and agentsandbox/ (--help and Seatbelt system paths).
Compile / resourceGenerators += Def.task {
  val log = streams.value.log
  val outputRoot = (Compile / resourceManaged).value / "sandbox-build"

  // (context root, the directories under it to bundle). Entries are stored relative to their context
  // root, so a jar entry — and the podman build path --build uses — stays a bare <image>/... whichever
  // tree the source is in. ko-agent-fs is under fuse/ rather than container/ because it runs in the
  // Podman machine, not in a container.
  val contexts = Seq(
    baseDirectory.value / "container" ->
      Seq(
        "debian-temurin", "debian-coursier",          // base images
        "ko-agent-sandbox", "ko-agent-egress-proxy",  // runtime images
        "ko-agent-self-test",                         // test image
      ),
    baseDirectory.value / "fuse" -> Seq("ko-agent-fs"),
  )

  // Build output and editor caches a worked-in checkout accumulates; keep in step with the .dockerignore files, which
  // exclude the same set from the podman build context. Two known divergences, neither reachable: "project/project" is
  // a substring test here but segment-anchored (**/) there, so a path like myproject/project would be dropped only
  // here, and no bundled directory is named that way; and ko-agent-fs's .dockerignore lists only target, doc and probe,
  // since no sbt or editor program creates the directories below inside a Rust crate — a stray .DS_Store there
  // would reach
  // a hand-run `podman build` that this task drops, costing a cache miss and nothing else (the source digest is
  // computed from the bundle, never from a checkout).
  //
  // ko-agent-fs/doc and ko-agent-fs/probe are excluded for a different reason: neither is a build input nor
  // distribution — probe/ holds the platform-verification probes a developer runs by hand, not under cargo — and
  // leaving them out keeps them out of AgentSandboxLauncher.koAgentFsSourceId too, so editing a design document or a
  // probe does not invalidate every installed filter binary. Its .dockerignore drops the same paths, so a direct
  // `podman build` from a checkout sees what a jar-built one does.
  // IO.relativize answers in the platform's separator, and everything downstream reads `/` — the
  // exclusion tests here, the jar's own entry names, and the INDEX the launcher resolves them by.
  // Unnormalized, a Windows build bundles the excluded directories and writes an INDEX no jar
  // lookup can serve.
  def bundlePath(root: File, file: File): Option[String] =
    IO.relativize(root, file).map(_.replace('\\', '/'))

  def included(root: File, file: File): Boolean =
    val relative = bundlePath(root, file).getOrElse("")
    val parts = relative.split("/").toSet
    file.isFile &&
      !relative.startsWith("ko-agent-fs/doc/") &&
      !relative.startsWith("ko-agent-fs/probe/") &&
      !parts.contains("target") &&
      !parts.contains(".scala-build") &&
      !parts.contains(".bsp") &&
      !parts.contains(".bloop") &&
      !parts.contains(".metals") &&
      !relative.contains("project/project") &&
      file.getName != ".DS_Store"

  IO.delete(outputRoot)

  val bundled =
    for
      (root, directories) <- contexts
      directory <- directories
      source <- (root / directory).allPaths.get()
      if included(root, source)
    yield
      val relative = bundlePath(root, source).get
      val target = outputRoot / relative
      IO.copyFile(source, target)
      relative -> target

  val index = outputRoot / "INDEX"
  IO.write(index, bundled.map(_._1).sorted.mkString("\n") + "\n")

  log.info(s"bundled ${bundled.size} build-context files into the jar")
  index +: bundled.map(_._2)
}.taskValue

assembly / assemblyJarName := "ko-agent-sandbox.jar"
assembly / assemblyOutputPath :=
  baseDirectory.value / "target" / "dist" / "ko-agent-sandbox.jar"

assembly / packageOptions += Package.ManifestAttributes(
  "Enable-Native-Access" -> "ALL-UNNAMED",
  "Add-Exports" -> "java.base/sun.security.x509 java.base/sun.security.util",
)

lazy val dist = taskKey[Unit]("Assemble one self-contained jar under target/dist")
// assembly is transient; caching this wrapper would exclude its only dependency from the cache key.
dist := Def.uncached {
  val jar = assembly.value
  streams.value.log.info(s"dist assembled: $jar")
}
