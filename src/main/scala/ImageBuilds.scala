// The image-producing actions, --build, --update and --self-test, with:
// - their podman build commands;
// - the bundled build context they run in;
// - the lock and the cleanup journal that every image-producing action holds.
//
// LauncherImages.scala has what the images are called, how they are identified and which are removed.

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
import SandboxWorkspace.*

object ImageBuilds:

  /** Both build actions run this after AgentSandboxLauncher.requirePodman. --update rebuilds the leaves through the
    * same `podman build` without a memory limit, so it shares --build's memory check. */
  def confirmMemoryForBuilds(os: Os): Unit =
    buildMemoryWarning(probedMachineAvailable(os, podman)).foreach: message =>
      warn(message)
      terminalReader.foreach: reader =>
        reader.prompt("Continue anyway? [y/N] ")
        if !consented(reader.readLine()) then fail("error: build not started")

  /**
   * The build context is bundled into the jar (build.sbt), so --build works with no checkout present.
   * This method unpacks the context to a temp directory, which runBuilds removes on success.
   *
   * The directory is new every time, and Files.write carries no mtime over from the jar entry, so every
   * file reaches podman freshly stamped. ko-agent-fs's Containerfile relies on that: the fresh stamps
   * stop a warm cargo cache from reusing a build with an older source id compiled into it.
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
      val bpfSourceId = contextSourceId(context, KoAgentBpf.SourceDir)
      val sandboxBundleId = contextSourceId(context, "ko-agent-sandbox")
      val proxyBundleId = contextSourceId(context, "ko-agent-egress-proxy")
      val readContainerfile = buildContextReader(context)
      val baseId = baseBundleId(
        contextSourceId(context, "debian-temurin"),
        contextSourceId(context, "debian-coursier"),
      )
      // The BPF backend builds on the podman machines alone: native Linux keeps the filter (doc/TODO.md,
      // "The BPF backend's later versions"), and the build reads the machine's kernel BTF. A machine that
      // lacks what the backend needs gets the filter's build without the backend.
      val bpfBackendSourceId = KoAgentBpf.sourceId(context)
      val buildBpfBackend = os != Os.Linux && bpfBuildPossible(os)
      val bpfBackendCommands =
        if !buildBpfBackend then Vector.empty
        else KoAgentBpf.buildCommands(podman, KoAgentBpf.machineKernel(podman), bpfBackendSourceId)
      val commands = buildCommands(podman, ImgTagVersion, baseId, fsSourceId, sandboxBundleId, proxyBundleId)
      val remoteImages = remoteImagesForBuildCommands(
        commands ++ bpfBackendCommands,
        readContainerfile,
        managedImageTags(ImgTagVersion).toSet,
      )
      val images = buildOutputImages(commands ++ bpfBackendCommands)
      val existingTags = existingImageTags(podman)
      val staleBaseTags = staleVersionedBaseImageTags(existingTags, buildImageTags(ImgTagVersion))
      val initialCandidates = prepareImageCleanupJournal(
        journal,
        imageIdsForTags(existingTags, images),
        staleBaseTags,
      )
      // The backend builds after the rest, and its failure is not fatal. A kernel that the checks above
      // cannot tell apart, one lacking a BPF feature the program uses, fails the backend's build, and
      // `fuse`, the default, needs none of it.
      val bpfBuildFailure =
        runBuilds(context, remoteImagePullCommands(podman, remoteImages) ++ commands, optional = bpfBackendCommands)
      verifyBuiltBundleLabels(Seq(
        SandboxImage -> sandboxBundleId,
        ProxyImage -> proxyBundleId,
      ))
      verifyBuiltBundleLabels(Seq(coursierImage(ImgTagVersion) -> baseId), BaseBundleLabel)
      installKoAgentFs(podman, os, fsSourceId)
      // The profile installs before the backend, because the backend's launches need this build's
      // attribute rules (SeccompProfile.AttributeSyscalls).
      SeccompProfile.install(podman, os, SandboxImage)
      if buildBpfBackend then
        bpfBuildFailure.toLeft(()).flatMap(_ => KoAgentBpf.installKoAgentBpf(podman, os, bpfBackendSourceId))
          .left.foreach(reason => warn(KoAgentBpf.buildFailedNote(reason, os)))
      val (candidates, staleTags) = includeStaleSelfTestCleanup(
        podman,
        journal,
        initialCandidates,
        staleBaseTags,
        fsSourceId,
        selfTestSourceId,
        bpfSourceId,
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
   * Whether the machine can build the BPF backend, saying why not when it cannot. A probe that does not
   * answer fails the build, which needs the machine anyway.
   */
  private def bpfBuildPossible(os: Os): Boolean =
    val probed = run(koAgentFsScriptCommand(podman, os, KoAgentBpf.checksScript("/"))*)
    if !probed.ok then fail(s"error: the machine did not answer the BPF backend's checks\n${probed.err}")
    val failures = KoAgentBpf.buildFailures(KoAgentBpf.parseFacts(probed.text), os)
    if failures.nonEmpty then System.err.println(KoAgentBpf.buildSkippedNote(failures))
    failures.isEmpty

  /** `--update` (README.md has what it rebuilds). */
  def update(os: Os): Nothing =
    withImageBuildLock(os): journal =>
      // This check runs under the lock, so no other launcher replaces the base between the check and
      // the build. The check runs before the context is unpacked, so a refusal leaves nothing behind.
      requireBaseFromBundledSources(
        podman,
        coursierImage(ImgTagVersion),
        baseBundleId(bundledSourceId("debian-temurin"), bundledSourceId("debian-coursier")),
      )
      val context = unpackBuildContext()
      val fsSourceId = koAgentFsSourceId(context)
      val selfTestSourceId = contextSourceId(context, "ko-agent-self-test")
      val bpfSourceId = contextSourceId(context, KoAgentBpf.SourceDir)
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
      // The profile is derived again here, so a podman upgrade between two --build runs reaches the
      // sessions' profile.
      SeccompProfile.install(podman, os, SandboxImage)
      val (candidates, staleTags) = includeStaleSelfTestCleanup(
        podman,
        journal,
        initialCandidates,
        staleBaseTags,
        fsSourceId,
        selfTestSourceId,
        bpfSourceId,
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
   * Every launcher build passes this flag and reads its `FROM` images from local storage alone.
   * - The launcher-built bases have short names (`debian-coursier:<version>`). Without the flag,
   *   podman on Fedora, whose registries.conf lists several unqualified-search registries, asks the
   *   terminal which registry holds such a base although the image is local.
   * - The registry-held images are in storage before any build starts: --build and --update pull each
   *   one themselves (remoteImagePullCommands), and selfTest refuses to start without the ones --build
   *   pulled.
   */
  val NoRegistryLookup = "--pull=never"

  /**
   * The product images and named build caches, in dependency order.
   * - Leaf images stay on `latest`: a rebuild there picks up new agent releases, which the base
   *   version says nothing about. The base version is an image label instead.
   * - debian-temurin does not consume IMG_TAG_VER, and neither does ko-agent-fs: ko-agent-fs builds on
   *   rust:slim with its own pins, and its identity is the source digest.
   *
   * Each multi-stage compile stage is built first under a stable cache tag. The final build reuses its
   * ordinary local layer cache. Naming the stage keeps one current cache image, and it lets the
   * successful build remove the previous cache image by the same exact-id rule as every final image.
   *
   * The bundle id travels twice, and the duplication is deliberate:
   * - as BUNDLE_ID for the Containerfile's LABEL, which a hand-run `podman build` from a checkout uses;
   * - as `--label` on the command line, which wins. podman's layer cache does not key ARG-derived
   *   config instructions on the arg's value (buildah #5501, #5095), so a cached LABEL step can commit
   *   a stale digest. A command-line --label is applied at commit, outside that cache.
   *
   * --build still verifies the committed label (verifyBuiltBundleLabels).
   *
   * debian-coursier's BaseBundleLabel travels as `--label` alone. Only the launcher reads it
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
   * The toolchain the filter ships, read from the image build that pins it rather than repeated here.
   * A second copy of the version would let the self-test image quietly stop exercising the compiler
   * that ships, and nothing else would notice. `ko-agent-fs/fuse/probe/rig.sh` follows the same rule.
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
   * `--self-test`'s image: the ko-agent-fs workspace's suites compiled against the pinned toolchain, on
   * top of the sandbox image.
   * - The image is built on demand rather than by --build, so a user who only wants to run agents
   *   never compiles a test suite.
   * - A rebuild is a cache hit whenever the bundled sources and the Rust image --build pulled are
   *   unchanged (`ko-agent-fs/doc/testing.md`).
   *
   * The build passes `-f` with `.` as the context, not the directory: the workspace this image compiles
   * lies beside the Containerfile in the unpacked bundle, not under it.
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
   * The verification container. Nothing is bound in or written out: the suites build their own trees
   * under the container's /tmp, and `--rm` removes the container when it exits. Image building and
   * replacement cleanup belong to selfTest, not to this command.
   *
   * `--cap-add SYS_ADMIN` is the one place this project runs a container with more than a session
   * gets, and that container is never a session's. The capability is not redundant with the setuid
   * fusermount3 that the image installs: a setuid binary does not escape the container's capability
   * bounding set, which was measured rather than assumed (`ko-agent-fs/fuse/doc/verification-log.md`).
   *
   * `--network=none`, because no case reaches a host and nothing is fetched at this point.
   */
  def selfTestRunCommand(podman: String, filter: Option[String], asRoot: Boolean): Vector[String] =
    Vector(podman, "run", "--rm", "--pull=never", "--network=none", "--device", "/dev/fuse",
      "--cap-add", "SYS_ADMIN")
      ++ (if asRoot then Vector("--user", "0") else Vector.empty)
      ++ Vector(SelfTestImage)
      ++ filter.toVector

  /**
   * The exit code for a self-test that failed before its behavioral checks began, as against one of
   * those checks failing.
   * - The filter's own `--self-test` decides which, being the only party that knows the stage it
   *   reached, and ko-agent-fs-suite passes the verdict up.
   * - The filter's message says what it can about the cause, and this launcher repeats the message
   *   without adding detail (ko-agent-fs/fuse/src/main.rs, SelfTestFailure).
   * - main.rs spells the code SELF_TEST_SETUP_EXIT, and a test holds the two together.
   */
  val SelfTestSetupExit = 3

  /**
   * `--no-cache`, because new agent releases arrive through RUN steps whose inputs look unchanged to
   * the cache. Base images and the proxy belong to --build.
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
   * Runs the builds, each failure ending the launcher, then the optional builds, whose first failure is
   * returned instead. Once the required builds pass, the context is removed whether or not an optional
   * build fails.
   *
   * Each command is echoed before it runs, so what follows is what podman prints for exactly that
   * line. A build's output says where its cache hit. A --quiet pull prints only the image id, so the
   * launcher reads the id before and after and says whether the image changed, as its own `pull:`
   * line.
   */
  def runBuilds(
    context: Path,
    commands: Vector[Vector[String]],
    optional: Vector[Vector[String]] = Vector.empty,
    execute: (Path, Vector[String]) => Int = executeIn,
  ): Option[String] =
    commands.foreach: command =>
      echoCommand(command)
      val pulled = if command.lift(1).contains("pull") then command.lift(2) else None
      val before = pulled.flatMap(imageId(command.head, _))
      val exit = execute(context, command)
      if exit != 0 then
        if pulled.isDefined then
          deleteRecursively(context)
          fail(s"error: image refresh failed: ${shownCommand(command)}", exit)
        else
          fail(
            s"error: build failed: ${shownCommand(command)}\n" +
              s"build context retained at $context",
            exit,
          )
      pulled.foreach: image =>
        System.err.println("pull: " + pullVerdict(before, imageId(command.head, image)))
    val optionalFailure = optional.iterator
      .map: command =>
        echoCommand(command)
        command -> execute(context, command)
      .collectFirst { case (command, exit) if exit != 0 => s"build failed: ${shownCommand(command)}" }
    deleteRecursively(context)
    optionalFailure

  /** A build command run in the context, its output the user's, and its exit status. */
  private def executeIn(context: Path, command: Vector[String]): Int =
    ProcessBuilder(command*).directory(context.toFile).inheritIO().start().waitFor()

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
   * Image tags are workstation-wide, so every image-producing action shares one lock and one journal.
   * - The journal is written before the first build: if the process dies after a tag moves, the next
   *   invocation still knows the exact old id.
   * - A global lock keeps two launcher versions from retagging `latest` around each other's snapshots.
   */
  def withImageBuildLock[A](os: Os)(body: Path => A): A =
    requireStateRootOutside(os, workingDirectory())
    withFileLock(imageBuildLockFile(os)):
      body(imageCleanupJournal(os))

  /** The lock that every image-producing action holds, and that a mount of the filter holds too, since
    * the action replaces the filter binary the mount executes (KoAgentFs.mountKoAgentFs). */
  def imageBuildLockFile(os: Os): Path = stateRoot(os).resolve("image-build").resolve("lock")

  def imageCleanupJournal(os: Os): Path = stateRoot(os).resolve("image-build").resolve("cleanup.ids")

  /**
   * `--self-test`: builds the self-test images, then runs the workspace's suites in a container with no
   * host bind mounts (`ko-agent-fs/doc/testing.md`). Unchanged inputs reuse the build cache.
   * - The action pulls nothing. The action's only remote source is the Rust image that --build pulls to compile
   *   the filter that ships, and verifying against that same image is the point. The test "self-test
   *   builds refresh no remote source of their own" holds that.
   * - A successful run without a case filter also measures the host share through SelfTestShare,
   *   which owns its scratch directory and cleanup.
   * - The sandbox image is a precondition rather than an artifact to build here: verifying is not the
   *   command that decides which agent image a user runs.
   *
   * An unprivileged uid mounting through the setuid `fusermount3` is the route a session takes, and
   * the image runs as its `nonroot` user for exactly that reason.
   * - A machine where that route cannot work is retried once as root, so the run reports which of the
   *   two served rather than guessing.
   * - The filter reports what failed in the setup, and this launcher passes the report on unchanged.
   *   Only a setup failure reaches the retry, because a failed check exits with its own status.
   */
  def selfTest(os: Os, operands: List[String]): Nothing =
    if operands.sizeIs > 1 then
      fail("error: --self-test takes at most one operand, a test-name filter")
    val filter = operands.headOption.filter(_.nonEmpty)

    if !runOk(podman, "image", "exists", SandboxImage) then
      fail(
        """error: the sandbox image is not built, and --self-test does not build it
          |
          |Run --build first; --self-test then layers its suites on top of it.""".stripMargin,
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
        contextSourceId(context, KoAgentBpf.SourceDir),
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
               |Run --build first; it pulls the images the self-test suites compile with.""".stripMargin,
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
    // After the container suites come the share rows, which those suites cannot reach (SelfTestShare).
    // A filter skips the share rows: the filter selects crate cases, and the one-case loop stays fast.
    def finish(suiteExit: Int): Nothing =
      if suiteExit != 0 || filter.isDefined then sys.exit(suiteExit)
      sys.exit(SelfTestShare.shareRows(podman, os, resolveWorkspaceRoot(os)))

    val unprivileged = selfTestRunCommand(podman, filter, asRoot = false)
    echoCommand(unprivileged)
    val exit = ProcessBuilder(unprivileged*).inheritIO().start().waitFor()
    if exit != SelfTestSetupExit then finish(exit)

    System.err.println(
      "note: the filter's self-test failed in its setup rather than at a check; retrying as\n" +
        "  root. Its own message above is the report of what failed, and this launcher does not\n" +
        "  narrow it further. If root serves, this machine never exercises the setuid fusermount3\n" +
        "  route a session takes, which is worth recording with its machine\n" +
        "  (ko-agent-fs/fuse/doc/verification-log.md).",
    )
    val privileged = selfTestRunCommand(podman, filter, asRoot = true)
    echoCommand(privileged)
    finish(ProcessBuilder(privileged*).inheritIO().start().waitFor())
