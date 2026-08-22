name := "ko-agent-sandbox"
version := "0.1.0"
scalaVersion := "3.8.4"

Compile / mainClass := Some("agentsandbox.launcher.AgentSandboxLauncher")

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcpkix-jdk18on" % "1.85",  // JCA cannot build X.509 certificates

  "org.scalameta" %% "munit" % "1.3.5" % Test
)

scalacOptions ++= Seq(
  "-deprecation",
  "-feature",
  "-unchecked",
  "-Wunused:all",
  "-Werror"
)

// The container-launching suites share one podman, and each asserts on resources scoped to a
// project it created. Run in parallel they interleave — one suite's launch observing another's
// container, one suite's teardown racing another's `--reset`. The ordinary suites take seconds, so
// serial costs almost nothing and removes the whole class of interference.
Test / parallelExecution := false

// execvp is a restricted FFM method: without this, a warning per launch and refusal on a future JDK.
Compile / run / javaOptions += "--enable-native-access=ALL-UNNAMED"
Compile / run / fork := true

// The --help text has one home: README.md's Reference block, the copy a reader browses before any
// jar exists. This task extracts it into the resource AgentSandboxLauncher.UsageText prints, so
// what --help shows cannot drift from what README shows. Anchored on the heading rather than on an
// invocation line, which would spell a launch channel (java -jar today, a cs-installed command
// later). Extraction fails the build rather than truncate: the block must follow the heading and
// run unbroken to the next one.
Compile / resourceGenerators += Def.task {
  val readme = IO.readLines(baseDirectory.value / "README.md")
  val start = readme.indexWhere(_.trim == "### Reference")
  if start < 0 then
    sys.error("README.md no longer has the '### Reference' heading the --help text is read from")
  val rest = readme.drop(start + 1)
  val block = rest.takeWhile(line => line.trim.isEmpty || line.startsWith("    "))
  if !rest.drop(block.size).headOption.exists(_.matches("#{1,6}(\\s.*)?")) then
    sys.error("README.md's Reference block no longer runs unbroken to the next heading")
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
Compile / resourceGenerators += Def.task {
  val log = streams.value.log
  val outputRoot = (Compile / resourceManaged).value / "sandbox-build"

  // (context root, the directories under it to bundle). Entries are stored relative to their context
  // root, so a jar entry — and the podman build path --build uses — stays a bare <image>/... whichever
  // tree the source lives in. ko-agent-fs is under fuse/ rather than container/ because it runs in the
  // Podman machine, not in a container.
  val contexts = Seq(
    baseDirectory.value / "container" ->
      Seq(
        "debian-temurin", "debian-coursier",          // base images
        "ko-agent-sandbox", "ko-agent-egress-proxy",  // runtime images
        "ko-agent-self-test",                         // test image
      ),
    baseDirectory.value / "fuse" -> Seq("ko-agent-fs")
  )

  // Build output and editor caches a worked-in checkout accumulates; keep in step with the .dockerignore files, which
  // exclude the same set from the podman build context. Two known divergences, neither reachable:
  // "project/project" is a substring test here but segment-anchored (**/) there, so a path like myproject/project
  // would be dropped only here, and no bundled directory is named that way; and ko-agent-fs's .dockerignore lists only
  // target, doc and probe, since a Rust crate grows none of the sbt and editor directories below — a stray .DS_Store
  // there would reach a hand-run `podman build` that this task drops, costing a cache miss and nothing else (the
  // source digest is computed from the bundle, never from a checkout).
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

// One self-contained jar: a single file is the unit of installation.
assembly / assemblyJarName := "ko-agent-sandbox.jar"
assembly / assemblyOutputPath :=
  baseDirectory.value / "target" / "dist" / "ko-agent-sandbox.jar"

// BouncyCastle drops: colliding module-info copies, and per-jar OSGi manifests. Signature files are already
// sbt-assembly's default discard.
assembly / assemblyMergeStrategy := {
  case path if path.endsWith("module-info.class")     => MergeStrategy.discard
  case path if path.endsWith("OSGI-INF/MANIFEST.MF")  => MergeStrategy.discard
  case path =>
    val default = (assembly / assemblyMergeStrategy).value
    default(path)
}

// Enable-Native-Access: the execvp downcall, warning-free and future-proof.
//
// Multi-Release is required, not an optimization: the assembled jar carries BouncyCastle's versioned
// trees, and 49 of those classes — the X25519 and Ed25519 key implementations among them — exist
// *only* under META-INF/versions, so without the attribute the JVM never looks there and they are
// missing rather than merely older. sbt-assembly copies the entries but does not set the flag; a fat
// jar built from multi-release inputs is not itself multi-release.
assembly / packageOptions += Package.ManifestAttributes(
  "Enable-Native-Access" -> "ALL-UNNAMED",
  "Multi-Release" -> "true"
)

lazy val dist = taskKey[Unit]("Assemble one self-contained jar under target/dist")
// assembly is transient; caching this wrapper would exclude its only dependency from the cache key.
dist := Def.uncached {
  val jar = assembly.value
  streams.value.log.info(s"dist assembled: $jar")
}
