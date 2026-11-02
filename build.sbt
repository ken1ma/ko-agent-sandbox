name := "ko-agent-sandbox"
version := "0.1.0"
scalaVersion := "3.10.0"

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

// The container-launching suites share one podman, and each suite asserts on resources scoped to a workspace it
// created. Run in parallel, the suites interleave: one suite's launch observes another suite's container, and one
// suite's teardown races another suite's `--reset`. The ordinary suites take seconds, so a serial run costs almost
// nothing and removes the whole class of interference.
Test / parallelExecution := false

// The container-launching suites run only under this command. `test` and `testFull` alone skip them, so no ordinary
// build starts a session.
// - The command sets a system property for one run of testFull, or of testOnly with the given patterns, and clears the
//   property however the run ends. The suites' condition reads the property (WithPodman.underTestWithPodman).
// - The switch is a system property, not an environment variable. The tests run in the sbt server's JVM, which keeps
//   the environment it was started with. A variable on a thin client's command line never reaches the tests, and the
//   run passes with every session suite skipped.
// - The command runs the task itself rather than pushing the task as a command. The task's failure is then the
//   command's failure, and the property is cleared even after an interrupted run, which a test cleanup hook would not
//   survive.
val TestWithPodmanProperty = "ko-agent-sandbox.testWithPodman"
commands += Command.args("testWithPodman", "<testOnly patterns>") { (state, patterns) =>
  val extracted = Project.extract(state)
  System.setProperty(TestWithPodmanProperty, "1")
  try
    if (patterns.isEmpty) extracted.runTask(Test / testFull, state)._1
    else extracted.runInputTask(Test / testOnly, patterns.mkString(" ", " ", ""), state)._1
  finally System.clearProperty(TestWithPodmanProperty)
}

// munit prints `==> s <test> skipped` without the clue that its `assume` gave (doc/upstream-issues.md,
// "scalameta/munit"). The clue tells one passing run from another:
//
// - A clue names a missing program, a command to use (`sbt testWithPodman`, for the
//   container-launching suites), or the reason the test cannot run in this environment.
// - A whole suite can skip: a host without wcwidth runs none of SandboxTextWidthTest.
// - A thin client attaches to whichever sbt server is running, so `sbt testFull` typed in a host
//   shell can run under the run-on-host profile. The skips differ there, and the clues show which
//   environment ran the tests.
//
// The test event that sbt receives still carries the exception. This listener prints the clues of a run's skipped
// tests before sbt's totals, grouped by clue, with each suite's count:
//
//     skipped 10: needs python3 with wcwidth (SandboxTextWidthTest: 10)
//
// A test event names its test `<suite>.<test name>` and does not name its suite. The listener takes the suite to be
// the started group that begins the test's name.
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

// --serve-proxy-on-host runs the proxy of the ko-agent-egress-proxy subproject. This jar compiles the proxy from the
// same sources, so an installed launcher carries it: the Scala sources, and the /defaults resources that their class
// initialization loads eagerly. The subproject keeps its own build for the container image, which builds a native
// image from the bundled context. The subproject's tests run in that build.
Compile / unmanagedSourceDirectories +=
  baseDirectory.value / "container" / "ko-agent-egress-proxy" / "app" / "src" / "main" / "scala"
Compile / unmanagedResourceDirectories +=
  baseDirectory.value / "container" / "ko-agent-egress-proxy" / "app" / "src" / "main" / "resources"

// execvp is a restricted FFM method. Without --enable-native-access, every launch prints a warning, and a future JDK
// refuses the call. The exports open the JDK's internal certificate builder to X509Helper.scala, which records why.
// Besides `sbt run` here, these places carry both:
// - the assembly manifest, for `java -jar`;
// - the launcher's re-invocation of itself as `java -cp`, for the runner, supervisor and proxy that the launcher starts
//   (RunOnHostSandbox.CertificateBuilderExports);
// - the native-image command in doc/TODO.md, for the binary;
// - .jvmopts, for the tests, which run in sbt's own JVM. A forked test JVM would need sbt's TCP listener to reach it,
//   and the host command sandbox does not grant that listener (doc/run-on-host.md, "Network").
Compile / run / javaOptions ++= Seq(
  "--enable-native-access=ALL-UNNAMED",
  "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
  "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
)
Compile / run / fork := true

// Extract --help from README.md's Reference block, so the published documentation and the installed launcher cannot
// disagree. The block must run unbroken between headings. Malformed input fails the build instead of truncating the
// help silently. The extraction anchors on the heading, so changing the invocation from java -jar to a Coursier
// command does not break the extraction.
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

// The BPF backend's launcher suite (ko-agent-fs/bpf/test/podman/launcher/Launcher.scala) refuses a jar whose code
// differs from the checkout's. A compiled source leaves only classes in the jar, so the jar carries a copy of each one
// that the suite's sources.txt lists. The copies sit outside sandbox-build/, so they leave the bundle's source id as
// it is.
Compile / resourceGenerators += Def.task {
  val launcherSources = Seq("src/main/scala/KoAgentBpf.scala")
  launcherSources.map: path =>
    val target = (Compile / resourceManaged).value / "launcher-sources" / path
    IO.copyFile(baseDirectory.value / path, target)
    target
}.taskValue

// Bundle the build contexts into the jar, so --build works with no checkout present (ImageBuilds.unpackBuildContext).
// INDEX lists every bundled path, because a jar's resource tree cannot be enumerated at runtime.
// Native-image's resource discovery misses required files. The native-image command in doc/TODO.md must therefore
// include sandbox-build/ (build contexts), defaults/ (proxy rules) and agentsandbox/ (--help and Seatbelt system
// paths).
Compile / resourceGenerators += Def.task {
  val log = streams.value.log
  val outputRoot = (Compile / resourceManaged).value / "sandbox-build"

  // Each entry is (context root, the directories under it to bundle). Entries are stored relative to their context
  // root, so a jar entry stays a bare <image>/... whichever tree the source is in, and so does the podman build path
  // that --build uses. ko-agent-fs sits at the repository root rather than under container/, because ko-agent-fs runs
  // in the podman machine, not in a container.
  val contexts = Seq(
    baseDirectory.value / "container" ->
      Seq(
        "debian-temurin", "debian-coursier",          // base images
        "ko-agent-sandbox", "ko-agent-egress-proxy",  // runtime images
        "ko-agent-self-test",                         // test image
      ),
    // ko-agent-fs holds the workspace policy and the FUSE backend, which --build compiles (ko-agent-fs/Containerfile),
    // and the BPF backend (ko-agent-fs/bpf/Containerfile). The self-test image compiles the suites and the BPF
    // classifier's host build for policy/tests/bpf_equivalence.rs (ko-agent-self-test/Containerfile).
    baseDirectory.value -> Seq("ko-agent-fs"),
  )

  // The task excludes the build output and editor caches that accumulate in a worked-in checkout. Keep this set in step
  // with the .dockerignore files, which exclude the same set from the podman build context. Two known divergences
  // exist, and neither is reachable:
  // - "project/project" is a substring test here but segment-anchored (**/) there, so only this task would drop a path
  //   like myproject/project. No bundled directory has such a name.
  // - ko-agent-fs/.dockerignore lists only target and the directories of the next paragraph, because no sbt or editor
  //   program creates the other directories inside a Rust workspace. A stray .DS_Store there would reach a hand-run
  //   `podman build`, although this task drops the file. The stray file costs a cache miss and nothing else, because
  //   the source digest is computed from the bundle, never from a checkout.
  //
  // The task excludes ko-agent-fs's doc/ and probe/ directories and its bench/ for a different reason: none of them is
  // a build input or part of the distribution. The probes are the platform-verification probes that a developer runs
  // by hand. bench/ holds the benchmarks that the BPF backend's benchmark suite reruns. Cargo builds neither.
  // - Leaving these directories out also keeps them out of the source ids (KoAgentFs.koAgentFsSourceId,
  //   KoAgentBpf.sourceId), so editing a design document, a probe or a benchmark does not invalidate every installed
  //   binary.
  // - bpf/test holds the suites that measure the BPF backend. The task excludes bpf/test for the same reason, since
  //   the self-test image's id digests the whole bpf/ directory (LauncherImages.contextSourceId). bpf/test/host stays,
  //   because the self-test image compiles that host build.
  // - ko-agent-fs/.dockerignore drops the same paths, so a direct `podman build` from a checkout sees what a jar-built
  //   one does.
  //
  // IO.relativize answers in the platform's separator, and everything downstream reads `/`: the exclusion tests here,
  // the jar's own entry names, and the INDEX that the launcher resolves them by. Without the normalization, a Windows
  // build bundles the excluded directories and writes an INDEX that no jar lookup can serve.
  def bundlePath(root: File, file: File): Option[String] =
    IO.relativize(root, file).map(_.replace('\\', '/'))

  val unbundled = Seq("doc", "policy/doc", "bpf/doc", "fuse/doc", "policy/probe", "fuse/probe", "bench")

  def included(root: File, file: File): Boolean =
    val relative = bundlePath(root, file).getOrElse("")
    val parts = relative.split("/").toSet
    file.isFile &&
      !unbundled.exists(directory => relative.startsWith(s"ko-agent-fs/$directory/")) &&
      !(relative.startsWith("ko-agent-fs/bpf/test/") && !relative.startsWith("ko-agent-fs/bpf/test/host/")) &&
      !parts.contains("target") &&
      !parts.contains(".scala-build") &&
      !parts.contains(".bsp") &&
      !parts.contains(".bloop") &&
      !parts.contains(".metals") &&
      !relative.contains("project/project") &&
      file.getName != "metals.sbt" &&
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
  streams.value.log.info(s"dist: ${fileConverter.value.toPath(jar)}")  // expand `${BASE}` (virtual id)
}
