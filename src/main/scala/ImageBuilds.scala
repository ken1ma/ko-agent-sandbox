// The image-producing actions — --build, --update and --self-test — with their podman build commands,
// the bundled build context they run in, and the lock and cleanup journal every image-producing action
// holds. What the images are called, how they are identified and which are removed is LauncherImages.scala.

package agentsandbox.launcher

import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.*

import AgentSandboxLauncher.*
import ContainerfileSources.*
import HostCommands.*
import FileHelper.*
import KoAgentFs.*
import LauncherImages.*
import LauncherState.*
import SandboxProject.*

object ImageBuilds:

  /** Both build actions run this after AgentSandboxLauncher.requirePodman: --update rebuilds the leaves through the
    * same `podman build` without a memory limit, so it shares --build's memory check. */
  def confirmMemoryForBuilds(os: Os): Unit =
    buildMemoryWarning(probedMachineAvailable(os)).foreach: message =>
      warn(message)
      Option(System.console()).foreach: console =>
        console.printf("Continue anyway? [y/N] ")
        if !consented(Option(console.readLine())) then fail("error: build not started")

  /**
   * The build context is bundled into the jar (build.sbt) so --build works
   * with no checkout present; unpacked to a temp directory, removed by
   * runBuilds on success.
   *
   * A new directory every time, and Files.write carries no mtime over from the
   * jar entry, so every file reaches podman freshly stamped. ko-agent-fs's
   * Containerfile leans on that: it is what stops a warm cargo cache from
   * reusing a build with an older source id compiled into it.
   */
  def unpackBuildContext(): Path =
    val root = Files.createTempDirectory("ko-agent-sandbox-build")

    bundleIndex().foreach: relative =>
      val target = root.resolve(relative)
      Files.createDirectories(target.getParent)
      Files.write(target, bundleResource(relative))

    System.err.println(s"build context: $root")
    root

  /** `--build` (README.md has what it builds and removes). */
  def build(os: Os): Nothing =
    withImageBuildLock(os): journal =>
      val context = unpackBuildContext()
      val fsSourceId = koAgentFsSourceId(context)
      val selfTestSourceId = contextSourceId(context, "ko-agent-self-test")
      val sandboxBundleId = contextSourceId(context, "ko-agent-sandbox")
      val proxyBundleId = contextSourceId(context, "ko-agent-egress-proxy")
      val readContainerfile = buildContextReader(context)
      val baseId = baseBundleId(
        contextSourceId(context, "debian-temurin"),
        contextSourceId(context, "debian-coursier"),
      )
      val commands =
        buildCommands(podman, ImgTagVersion, baseId, fsSourceId, sandboxBundleId, proxyBundleId)
      val remoteImages =
        remoteImagesForBuildCommands(commands, readContainerfile, managedImageTags(ImgTagVersion).toSet)
      val images = buildOutputImages(commands)
      val existingTags = existingImageTags(podman)
      val staleBaseTags = staleVersionedBaseImageTags(existingTags, buildImageTags(ImgTagVersion))
      val initialCandidates = prepareImageCleanupJournal(
        journal,
        imageIdsForTags(existingTags, images),
        staleBaseTags,
      )
      runBuilds(context, remoteImagePullCommands(podman, remoteImages) ++ commands)
      verifyBuiltBundleLabels(Seq(
        SandboxImage -> sandboxBundleId,
        ProxyImage -> proxyBundleId,
      ))
      verifyBuiltBundleLabels(Seq(coursierImage(ImgTagVersion) -> baseId), BaseBundleLabel)
      installKoAgentFs(podman, os, fsSourceId)
      val (candidates, staleTags) = includeStaleSelfTestCleanup(
        podman,
        journal,
        initialCandidates,
        staleBaseTags,
        fsSourceId,
        selfTestSourceId,
      )
      val remaining = removeSupersededImages(
        podman,
        candidates,
        managedImageTags(ImgTagVersion),
        staleTags,
      )
      writeImageCleanupJournal(journal, remaining)
    sys.exit(0)

  /** `--update` (README.md has what it rebuilds). */
  def update(os: Os): Nothing =
    withImageBuildLock(os): journal =>
      // Under the lock, so no other launcher replaces the base between this check and the build;
      // before the context is unpacked, so a refusal leaves nothing behind.
      requireBaseFromBundledSources(
        podman,
        coursierImage(ImgTagVersion),
        baseBundleId(bundledSourceId("debian-temurin"), bundledSourceId("debian-coursier")),
      )
      val context = unpackBuildContext()
      val fsSourceId = koAgentFsSourceId(context)
      val selfTestSourceId = contextSourceId(context, "ko-agent-self-test")
      val sandboxBundleId = contextSourceId(context, "ko-agent-sandbox")
      val readContainerfile = buildContextReader(context)
      val commands = updateCommands(podman, ImgTagVersion, sandboxBundleId)
      val remoteImages =
        remoteImagesForBuildCommands(commands, readContainerfile, managedImageTags(ImgTagVersion).toSet)
      val images = buildOutputImages(commands)
      val existingTags = existingImageTags(podman)
      val staleBaseTags = staleVersionedBaseImageTags(existingTags, buildImageTags(ImgTagVersion))
      val initialCandidates = prepareImageCleanupJournal(
        journal,
        imageIdsForTags(existingTags, images),
        staleBaseTags,
      )
      runBuilds(context, remoteImagePullCommands(podman, remoteImages) ++ commands)
      verifyBuiltBundleLabels(Seq(SandboxImage -> sandboxBundleId))
      val (candidates, staleTags) = includeStaleSelfTestCleanup(
        podman,
        journal,
        initialCandidates,
        staleBaseTags,
        fsSourceId,
        selfTestSourceId,
      )
      val remaining = removeSupersededImages(
        podman,
        candidates,
        managedImageTags(ImgTagVersion),
        staleTags,
      )
      writeImageCleanupJournal(journal, remaining)
    sys.exit(0)

  /**
   * Every launcher build passes this and reads its `FROM` images from local storage alone. The
   * launcher-built bases have short names (`debian-coursier:<version>`). Without the flag, podman
   * on Fedora, whose registries.conf lists several unqualified-search registries, asks the terminal
   * which registry holds such a base although the image is local. The registry-held images are in
   * storage before any build starts: --build and --update pull each one themselves
   * (remoteImagePullCommands), and selfTest refuses to start without the ones --build pulled.
   */
  val NoRegistryLookup = "--pull=never"

  /**
   * The product images and named build caches, in dependency order. Leaf images stay on
   * `latest`: a
   * rebuild there picks up new agent releases, which the base version says
   * nothing about; the base is an image label instead. debian-temurin does
   * not consume IMG_TAG_VER, and neither does ko-agent-fs — it builds on
   * rust:slim with its own pins, and its identity is the source digest.
   *
   * Each multi-stage compile stage is built first under a stable cache tag. The final build reuses
   * its ordinary local layer cache; naming the stage keeps one current cache image and lets the
   * successful build remove the previous one by the same exact-id rule as every final image.
   *
   * The bundle id travels twice: as BUNDLE_ID for the Containerfile's LABEL
   * (what a hand-run `podman build` from a checkout uses) and as `--label`
   * on the command line, which wins. The duplication is deliberate: podman's
   * layer cache does not key ARG-derived config instructions on the arg's
   * value (buildah #5501, #5095), so a cached LABEL step can commit a stale
   * digest; a command-line --label is applied at commit, outside that cache.
   * --build still verifies the committed label (verifyBuiltBundleLabels).
   *
   * debian-coursier's BaseBundleLabel travels as `--label` alone: only the launcher reads it
   * (requireBaseFromBundledSources), so a hand-run build has no use for the Containerfile LABEL.
   */
  def buildCommands(
    podman: String,
    version: String,
    baseBundleId: String,
    fsSourceId: String,
    sandboxBundleId: String,
    proxyBundleId: String,
  ): Vector[Vector[String]] =
    Vector(
      Vector(podman, "build", NoRegistryLookup, "-t", temurinImage(version), "debian-temurin"),
      Vector(
        podman, "build", NoRegistryLookup, "--build-arg", s"IMG_TAG_VER=$version",
        "--label", s"$BaseBundleLabel=$baseBundleId",
        "-t", coursierImage(version), "debian-coursier",
      ),
      Vector(
        podman, "build", NoRegistryLookup, "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$sandboxBundleId",
        "--label", s"$BundleLabel=$sandboxBundleId",
        "-t", SandboxImage, "ko-agent-sandbox",
      ),
      Vector(
        podman, "build", NoRegistryLookup, "--target", "build", "--build-arg", s"IMG_TAG_VER=$version",
        "-t", ProxyBuildImage, "ko-agent-egress-proxy",
      ),
      Vector(
        podman, "build", NoRegistryLookup, "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$proxyBundleId",
        "--label", s"$BundleLabel=$proxyBundleId",
        "-t", ProxyImage, "ko-agent-egress-proxy",
      ),
      Vector(
        podman, "build", NoRegistryLookup, "--target", "build",
        "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "-t", KoAgentFsBuildImage, "ko-agent-fs",
      ),
      Vector(
        podman, "build", NoRegistryLookup, "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "-t", KoAgentFsImage, "ko-agent-fs",
      ),
    )

  /**
   * The toolchain the filter ships, read from the image build that pins it rather than repeated
   * here. A second copy of the version is a self-test image that quietly stops exercising the
   * compiler that ships, and nothing else would notice — the same rule `probe/rig.sh` follows.
   */
  def pinnedRustVersion(context: Path): String =
    val containerfile = context.resolve("ko-agent-fs").resolve("Containerfile")
    val pinned = Files
      .readAllLines(containerfile)
      .asScala
      .collectFirst:
        case line if line.startsWith("ARG RUST_VERSION=") => line.stripPrefix("ARG RUST_VERSION=").trim
    pinned.filter(_.nonEmpty).getOrElse(
      fail(s"error: no 'ARG RUST_VERSION=' in $containerfile; there is no toolchain to build with"),
    )

  /**
   * `--self-test`'s image: the crate's suites compiled against the pinned toolchain, on top of the
   * sandbox image. Built on demand rather than by --build, so a user who only wants to run agents
   * never compiles a test suite; a rebuild is a cache hit whenever the bundled sources and the
   * Rust image --build pulled are unchanged (`fuse/ko-agent-fs/doc/testing.md`).
   *
   * `-f` with `.` as the context, not the directory: the crate this compiles is beside the
   * Containerfile in the unpacked bundle, not under it.
   */
  def selfTestBuildCommands(
    podman: String,
    rustVersion: String,
    fsSourceId: String,
    selfTestBundleId: String,
  ): Vector[Vector[String]] =
    Vector(
      Vector(
        podman, "build", NoRegistryLookup, "--target", "build",
        "--build-arg", s"RUST_VERSION=$rustVersion",
        "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "--label", s"$BundleLabel=$selfTestBundleId",
        "-f", "ko-agent-self-test/Containerfile",
        "-t", SelfTestBuildImage, ".",
      ),
      Vector(
        podman, "build", NoRegistryLookup,
        "--build-arg", s"RUST_VERSION=$rustVersion",
        "--build-arg", s"KO_AGENT_FS_SOURCE_ID=$fsSourceId",
        "--label", s"$BundleLabel=$selfTestBundleId",
        "-f", "ko-agent-self-test/Containerfile",
        "-t", SelfTestImage, ".",
      ),
    )

  /**
   * The verification container. Nothing is bound in or written out: the suites build their own
   * trees under the container's /tmp, and `--rm` takes the container with it. Image building and
   * replacement cleanup belong to selfTest, not this command.
   *
   * `--cap-add SYS_ADMIN` is the one place this project runs a container with more than a session
   * gets, and it is never a session's container. It is not redundant with the setuid fusermount3
   * the image installs: a setuid binary does not escape the container's capability bounding set,
   * measured rather than assumed (`fuse/ko-agent-fs/doc/verification-log.md`).
   *
   * `--network=none` because no case reaches a host, and nothing is fetched at this point.
   */
  def selfTestRunCommand(podman: String, filter: Option[String], asRoot: Boolean): Vector[String] =
    Vector(podman, "run", "--rm", "--pull=never", "--network=none", "--device", "/dev/fuse",
      "--cap-add", "SYS_ADMIN")
      ++ (if asRoot then Vector("--user", "0") else Vector.empty)
      ++ Vector(SelfTestImage)
      ++ filter.toVector

  /**
   * The exit code for a self-test that failed before its behavioral checks began, as against one
   * of those checks failing. The filter's own `--self-test` decides which, being the only party
   * that knows the stage it reached, and ko-agent-fs-suite passes the verdict up; its message says
   * what it can about the cause, which this launcher repeats without adding detail
   * (fuse/ko-agent-fs/src/main.rs, SelfTestFailure). Spelled there as SELF_TEST_SETUP_EXIT, and a
   * test holds the two together.
   */
  val SelfTestSetupExit = 3

  /**
   * `--no-cache`: new agent releases arrive through RUN steps whose inputs
   * look unchanged to the cache. Base images and the proxy are --build's.
   */
  def updateCommands(podman: String, version: String, sandboxBundleId: String): Vector[Vector[String]] =
    Vector(
      Vector(
        podman, "build", NoRegistryLookup, "--no-cache", "--build-arg", s"IMG_TAG_VER=$version",
        "--build-arg", s"BUNDLE_ID=$sandboxBundleId",
        "--label", s"$BundleLabel=$sandboxBundleId",
        "-t", SandboxImage, "ko-agent-sandbox",
      ),
    )

  /**
   * Each command echoed before it runs, so what follows is what podman prints for exactly that
   * line. A build's output says where its cache hit; a --quiet pull prints only the image id, so
   * the launcher reads the id before and after and says whether the image changed, as its own
   * `pull:` line.
   */
  def runBuilds(context: Path, commands: Vector[Vector[String]]): Unit =
    commands.foreach: command =>
      echoCommand(command)
      val pulled = if command.lift(1).contains("pull") then command.lift(2) else None
      val before = pulled.flatMap(imageId(command.head, _))
      val exit = ProcessBuilder(command*)
        .directory(context.toFile)
        .inheritIO()
        .start()
        .waitFor()
      if exit != 0 then
        if pulled.isDefined then
          deleteRecursively(context)
          fail(s"error: image refresh failed: ${command.mkString(" ")}", exit)
        else
          fail(
            s"error: build failed: ${command.mkString(" ")}\n" +
              s"build context retained at $context",
            exit,
          )
      pulled.foreach: image =>
        System.err.println("pull: " + pullVerdict(before, imageId(command.head, image)))
    deleteRecursively(context)

  private def imageId(podman: String, image: String): Option[String] =
    val inspected = run(podman, "image", "inspect", "--format", "{{.Id}}", image)
    Option.when(inspected.ok && inspected.text.nonEmpty)(inspected.text)

  def pullVerdict(before: Option[String], after: Option[String]): String =
    (before, after) match
      case (Some(old), Some(now)) if old == now => "up to date"
      case (Some(old), Some(_)) => s"tag updated; was ${shortId(old)}"
      case (None, Some(_)) => "tag added"
      case (_, None) => "no local image after the pull"

  private def buildContextReader(context: Path): String => String =
    relative => Files.readString(context.resolve(relative))

  def buildOutputImages(commands: Vector[Vector[String]]): Vector[String] =
    commands.flatMap: command =>
      command.sliding(2).collectFirst:
        case Seq("-t", image) => image

  /**
   * Image tags are workstation-wide, so every image-producing action shares one lock and journal.
   * The journal is written before the first build: if the process dies after a tag moves, the next
   * invocation still knows the exact old id. A global lock keeps two launcher versions from
   * retagging `latest` around each other's snapshots.
   */
  def withImageBuildLock[A](os: Os)(body: Path => A): A =
    requireStateRootOutside(os, workingDirectory())
    withFileLock(imageBuildLockFile(os)):
      body(imageCleanupJournal(os))

  /** The lock every image-producing action holds, and a mount of the filter too, since the action
    * replaces the filter binary the mount executes (KoAgentFs.mountKoAgentFs). */
  def imageBuildLockFile(os: Os): Path = stateRoot(os).resolve("image-build").resolve("lock")

  def imageCleanupJournal(os: Os): Path = stateRoot(os).resolve("image-build").resolve("cleanup.ids")

  /**
   * `--self-test`: build the self-test images, then run the crate's suites in a container with no
   * host bind mounts (`fuse/ko-agent-fs/doc/testing.md`). Unchanged inputs reuse the build cache.
   * No pull: its only remote source is the Rust image --build pulls to compile the filter that
   * ships (the test "self-test builds refresh no remote source of their own" holds that), and
   * verifying against that same image is the point. A successful run without a case filter also
   * measures the host share through SelfTestShare, which owns its scratch directory and cleanup.
   *
   * The sandbox image is a precondition rather than an artifact to build here: verifying is not the
   * command that decides which agent image a user runs.
   *
   * An unprivileged uid mounting through the setuid `fusermount3` is the route a session takes,
   * and the image runs as its `nonroot` user for exactly that reason. A machine where that cannot
   * work is retried once as root, so the run reports which of the two served rather than guessing.
   * What failed in the setup is the filter's to report and this launcher's to pass on
   * unchanged; only a setup failure reaches here, because a failed check exits with its own status.
   */
  def selfTest(os: Os, operands: List[String]): Nothing =
    if operands.sizeIs > 1 then
      fail("error: --self-test takes at most one operand, a test-name filter")
    val filter = operands.headOption.filter(_.nonEmpty)

    if !runOk(podman, "image", "exists", SandboxImage) then
      fail(
        """error: the sandbox image is not built, and --self-test does not build it
          |
          |Run --build first; --self-test then layers its suites on top of it.""".stripMargin
    )

    withImageBuildLock(os): journal =>
      val context = unpackBuildContext()
      val existingTags = existingImageTags(podman)
      val sandboxImageId = requiredImageId(existingTags, SandboxImage, "self-test did not start")
      val fsSourceId = koAgentFsSourceId(context)
      val rustVersion = pinnedRustVersion(context)
      val bundleId = selfTestBundleId(
        fsSourceId,
        contextSourceId(context, "ko-agent-self-test"),
        sandboxImageId,
      )
      val commands = selfTestBuildCommands(
        podman,
        rustVersion,
        fsSourceId,
        bundleId,
      )
      remoteImagesForBuildCommands(commands, buildContextReader(context), managedImageTags(ImgTagVersion).toSet)
        .filterNot(image => runOk(podman, "image", "exists", image))
        .foreach: image =>
          deleteRecursively(context)
          fail(
            s"""error: $image is not in local storage, and --self-test does not pull it
               |
               |Run --build first; it pulls the images the self-test suites compile with.""".stripMargin
          )
      val images = buildOutputImages(commands)
      val candidates = prepareImageCleanupJournal(
        journal,
        imageIdsForTags(existingTags, images),
        Vector.empty,
      )
      runBuilds(context, commands)
      verifyBuiltBundleLabels(SelfTestImageTags.map(_ -> bundleId))
      val remaining = removeSupersededImages(
        podman,
        candidates,
        managedImageTags(ImgTagVersion),
        Vector.empty,
      )
      writeImageCleanupJournal(journal, remaining)

    System.err.println(s"machine: ${os.toString.toLowerCase(java.util.Locale.ROOT)}, ${podmanVersion()}")
    // After the container suites, the share rows — what those suites cannot reach
    // (SelfTestShare). Skipped under a filter: it selects crate cases, and the one-case loop
    // stays fast.
    def finish(suiteExit: Int): Nothing =
      if suiteExit != 0 || filter.isDefined then sys.exit(suiteExit)
      sys.exit(SelfTestShare.shareRows(podman, os, resolveProjectDir(os)))

    val unprivileged = selfTestRunCommand(podman, filter, asRoot = false)
    echoCommand(unprivileged)
    val exit = ProcessBuilder(unprivileged*).inheritIO().start().waitFor()
    if exit != SelfTestSetupExit then finish(exit)

    System.err.println(
      "note: the filter's self-test failed in its setup rather than at a check; retrying as\n" +
        "  root. Its own message above is the report of what failed, and this launcher does not\n" +
        "  narrow it further. If root serves, this machine never exercises the setuid fusermount3\n" +
        "  route a session takes, which is worth recording with its machine\n" +
        "  (fuse/ko-agent-fs/doc/verification-log.md).",
    )
    val privileged = selfTestRunCommand(podman, filter, asRoot = true)
    echoCommand(privileged)
    finish(ProcessBuilder(privileged*).inheritIO().start().waitFor())
